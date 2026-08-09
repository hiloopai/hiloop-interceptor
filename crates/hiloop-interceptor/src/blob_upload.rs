//! Remote [`BlobUploader`]: ships captured payload blobs to a hiloop telemetry gateway's
//! `TelemetryBlobService` over tonic, using the same endpoint and Bearer auth as the gRPC event
//! exporter. The protocol is digest-first ([`BlobUploader::find_missing`] → `HasBlobs`, then
//! [`BlobUploader::upload`] → client-streaming `UploadBlob` for exactly the missing digests), so
//! already-present content is never re-sent and the backend re-hashes before storing.

use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream;
use hiloop_core::event::PayloadDigest;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Status};

use crate::blob::{BlobStoreError, BlobStoreErrorKind, BlobUploader, MAX_UPLOAD_BLOB_BYTES};
use crate::grpc_client::proto::telemetry_blob_service_client::TelemetryBlobServiceClient;
use crate::grpc_client::proto::{HasBlobsRequest, UploadBlobRequest};
use crate::grpc_client::{
    AuthInterceptor, GatewayCredential, GrpcClientError, build_channel, fold_status_message,
};

const STORE_NAME: &str = "grpc-blob";

/// One `UploadBlob` frame's content chunk (24 KiB) — below the gateway's bounded 64 KiB frame,
/// leaving room for digest and tenancy fields without coupling to exact protobuf overhead.
const UPLOAD_CHUNK_BYTES: usize = 24 * 1024;

/// Deadline on one `HasBlobs` probe. The channel itself has no timeout, and a black-holed
/// gateway would otherwise hang the run-end drain (and with it the wrapper's exit) forever.
pub const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Deadline on one `UploadBlob` stream — generous enough for a cap-sized (64 MiB) blob on a
/// slow link, small enough that a wedged transfer cannot hang the drain unbounded.
pub const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

type AuthedClient = TelemetryBlobServiceClient<InterceptedService<Channel, AuthInterceptor>>;

/// Uploads content-addressed payload blobs to a telemetry gateway.
pub struct GrpcBlobUploader {
    client: AuthedClient,
    credential: GatewayCredential,
    tenant_id: Option<String>,
}

impl GrpcBlobUploader {
    /// Build a lazily-connected uploader for `endpoint` (e.g.
    /// `https://telemetry.example.com:443`) — the same endpoint the gRPC event exporter ships
    /// events to. TLS (native + webpki trust roots) is used unless `insecure` is set (h2c, local
    /// dev only). The Bearer token is read from `HILOOP_API_KEY`; absent/empty means no auth
    /// header (an unauthenticated dev gateway). Pass `None` for `tenant_id` against an
    /// authenticated gateway (it derives the tenant from the token); pass `Some(tenant)` only
    /// against a no-auth local gateway.
    pub fn connect(
        endpoint: impl Into<String>,
        tenant_id: Option<String>,
        insecure: bool,
    ) -> Result<Self, BlobStoreError> {
        let credential = GatewayCredential::from_env().map_err(client_config_error)?;
        Self::with_credential(endpoint, tenant_id, insecure, credential)
    }

    /// Like [`connect`](Self::connect), but presenting an explicit (possibly refreshable)
    /// `credential` instead of reading `HILOOP_API_KEY`. Share one [`GatewayCredential`] across
    /// the event exporter and the blob uploader so a refresh triggered by either leg
    /// re-authenticates both.
    pub fn with_credential(
        endpoint: impl Into<String>,
        tenant_id: Option<String>,
        insecure: bool,
        credential: GatewayCredential,
    ) -> Result<Self, BlobStoreError> {
        let endpoint = endpoint.into();
        let channel = build_channel(&endpoint, insecure).map_err(client_config_error)?;
        let interceptor = AuthInterceptor::new(credential.clone());
        let client = TelemetryBlobServiceClient::with_interceptor(channel, interceptor);
        Ok(Self {
            client,
            credential,
            tenant_id,
        })
    }

    fn tenant_wire_value(&self) -> String {
        // proto3 has no optional scalar here: the empty string is the wire form of "absent",
        // which is exactly what an authenticated gateway expects (it derives the tenant from
        // the Bearer token).
        self.tenant_id.clone().unwrap_or_default()
    }

    /// Decide the fate of a failed RPC attempt, riding out an aged-out credential the same way
    /// the event exporter does: an `UNAUTHENTICATED` judgment of a refreshable bearer rotates it
    /// once (single-flight, shared with the event leg) and returns `Ok(())` so the caller
    /// retries the attempt; any other failure — or a rotation that is impossible, failed, or
    /// still in flight — is the final error (the blob drain retries every pass within its
    /// bounded budget anyway). `presented` is the bearer captured before the failed attempt.
    async fn refresh_or_fail(
        &self,
        failure: BlobCallFailure,
        presented: Option<&tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    ) -> Result<(), BlobStoreError> {
        let BlobCallFailure::Auth { message } = failure else {
            return Err(failure.into_error());
        };
        classify_refresh(self.credential.refresh_rejected(presented).await, message)
    }
}

fn classify_refresh(
    outcome: crate::grpc_client::RefreshOutcome,
    message: String,
) -> Result<(), BlobStoreError> {
    use crate::grpc_client::RefreshOutcome;

    match outcome {
        RefreshOutcome::Refreshed => Ok(()),
        RefreshOutcome::Unrefreshable => Err(BlobStoreError::rejected(STORE_NAME, message)),
        RefreshOutcome::Failed(reason) => Err(BlobStoreError::rejected(
            STORE_NAME,
            format!("{message}; refreshing the credential failed: {reason}"),
        )),
        RefreshOutcome::Pending => Err(BlobStoreError::unavailable(
            STORE_NAME,
            format!("{message}; a credential refresh is still in flight"),
        )),
    }
}

/// One failed blob RPC attempt, rendered but still distinguishing an `UNAUTHENTICATED`
/// judgment so [`GrpcBlobUploader::call_with_refresh`] can rotate the credential and retry.
enum BlobCallFailure {
    /// The gateway judged the credential unauthenticated.
    Auth { message: String },
    /// A non-auth failure with its retry disposition preserved.
    Classified {
        kind: BlobStoreErrorKind,
        message: String,
    },
}

impl BlobCallFailure {
    fn from_status(status: &Status, message: String) -> Self {
        if status.code() == tonic::Code::Unauthenticated {
            Self::Auth { message }
        } else {
            Self::Classified {
                kind: kind_for_status(status.code()),
                message,
            }
        }
    }

    fn into_error(self) -> BlobStoreError {
        match self {
            Self::Auth { message } => BlobStoreError::rejected(STORE_NAME, message),
            Self::Classified { kind, message } => match kind {
                BlobStoreErrorKind::Backpressure => {
                    BlobStoreError::backpressure(STORE_NAME, message)
                }
                BlobStoreErrorKind::Unavailable => BlobStoreError::unavailable(STORE_NAME, message),
                BlobStoreErrorKind::Rejected => BlobStoreError::rejected(STORE_NAME, message),
                BlobStoreErrorKind::Other => BlobStoreError::other(STORE_NAME, message),
            },
        }
    }
}

fn kind_for_status(code: tonic::Code) -> BlobStoreErrorKind {
    match code {
        tonic::Code::ResourceExhausted => BlobStoreErrorKind::Backpressure,
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => BlobStoreErrorKind::Unavailable,
        tonic::Code::InvalidArgument
        | tonic::Code::FailedPrecondition
        | tonic::Code::PermissionDenied
        | tonic::Code::Unauthenticated
        | tonic::Code::NotFound
        | tonic::Code::AlreadyExists
        | tonic::Code::OutOfRange => BlobStoreErrorKind::Rejected,
        _ => BlobStoreErrorKind::Other,
    }
}

impl GrpcBlobUploader {
    /// One deadline-bounded `HasBlobs` probe.
    async fn has_blobs_once(
        &self,
        digests: &[PayloadDigest],
    ) -> Result<Vec<String>, BlobCallFailure> {
        let mut client = self.client.clone();
        let request = Request::new(HasBlobsRequest {
            digests: digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect(),
            org_id: self.tenant_wire_value(),
        });
        let response = tokio::time::timeout(PROBE_TIMEOUT, client.has_blobs(request))
            .await
            .map_err(|_elapsed| BlobCallFailure::Classified {
                kind: BlobStoreErrorKind::Unavailable,
                message: format!("blob probe timed out after {}s", PROBE_TIMEOUT.as_secs()),
            })?
            .map_err(|status| {
                BlobCallFailure::from_status(
                    &status,
                    format!("blob probe rejected: {}", fold_status_message(&status)),
                )
            })?;
        Ok(response.into_inner().missing_digests)
    }

    /// One deadline-bounded client-streaming `UploadBlob`, returning the stored size.
    async fn upload_once(
        &self,
        digest: &PayloadDigest,
        bytes: Bytes,
    ) -> Result<u64, BlobCallFailure> {
        let frames = upload_frames(digest, &self.tenant_wire_value(), bytes);
        let mut client = self.client.clone();
        let response = tokio::time::timeout(UPLOAD_TIMEOUT, client.upload_blob(frames))
            .await
            .map_err(|_elapsed| BlobCallFailure::Classified {
                kind: BlobStoreErrorKind::Unavailable,
                message: format!(
                    "blob upload of {digest} timed out after {}s",
                    UPLOAD_TIMEOUT.as_secs()
                ),
            })?
            .map_err(|status| {
                BlobCallFailure::from_status(
                    &status,
                    format!(
                        "blob upload of {digest} rejected: {}",
                        fold_status_message(&status)
                    ),
                )
            })?;
        Ok(response.into_inner().size_bytes)
    }
}

#[async_trait]
impl BlobUploader for GrpcBlobUploader {
    async fn find_missing(
        &self,
        digests: &[PayloadDigest],
    ) -> Result<Vec<PayloadDigest>, BlobStoreError> {
        if digests.is_empty() {
            return Ok(Vec::new());
        }
        let presented = self.credential.bearer();
        let missing_digests = match self.has_blobs_once(digests).await {
            Ok(missing) => missing,
            Err(failure) => {
                self.refresh_or_fail(failure, presented.as_ref()).await?;
                self.has_blobs_once(digests)
                    .await
                    .map_err(BlobCallFailure::into_error)?
            }
        };

        // The gateway echoes missing digests verbatim as requested, so each echo must map back to
        // a digest we asked about; anything else is a contract violation, not data.
        let requested: HashMap<&str, &PayloadDigest> = digests
            .iter()
            .map(|digest| (digest.as_str(), digest))
            .collect();
        missing_digests
            .iter()
            .map(|raw| {
                requested
                    .get(raw.as_str())
                    .map(|&d| d.clone())
                    .ok_or_else(|| {
                        BlobStoreError::rejected(
                            STORE_NAME,
                            format!("gateway reported unrequested digest {raw:?} as missing"),
                        )
                    })
            })
            .collect()
    }

    async fn upload(&self, digest: &PayloadDigest, bytes: Bytes) -> Result<(), BlobStoreError> {
        let size = bytes.len() as u64;
        if size > MAX_UPLOAD_BLOB_BYTES {
            return Err(BlobStoreError::rejected(
                STORE_NAME,
                format!(
                    "blob {digest} is {size} bytes, over the {MAX_UPLOAD_BLOB_BYTES} byte upload cap"
                ),
            ));
        }
        let presented = self.credential.bearer();
        let stored = match self.upload_once(digest, bytes.clone()).await {
            Ok(stored) => stored,
            Err(failure) => {
                self.refresh_or_fail(failure, presented.as_ref()).await?;
                self.upload_once(digest, bytes)
                    .await
                    .map_err(BlobCallFailure::into_error)?
            }
        };
        if stored != size {
            return Err(BlobStoreError::rejected(
                STORE_NAME,
                format!("gateway stored {stored} bytes of {digest}, expected {size}"),
            ));
        }
        Ok(())
    }
}

fn client_config_error(error: GrpcClientError) -> BlobStoreError {
    BlobStoreError::with_source(STORE_NAME, "failed to configure the gateway client", error)
}

/// Chunk one blob into `UploadBlob` frames: the first frame declares the digest and tenancy (and
/// carries the first chunk — for an empty blob, no bytes), later frames carry content only.
fn upload_frames(
    digest: &PayloadDigest,
    org_id: &str,
    bytes: Bytes,
) -> impl futures_core::Stream<Item = UploadBlobRequest> + Send + 'static {
    stream::unfold(
        (
            bytes,
            0_usize,
            Some((digest.to_string(), org_id.to_owned())),
        ),
        |(bytes, offset, identity)| async move {
            if offset == bytes.len() && identity.is_none() {
                return None;
            }
            let end = offset.saturating_add(UPLOAD_CHUNK_BYTES).min(bytes.len());
            let (digest, org_id) = identity.unwrap_or_default();
            let frame = UploadBlobRequest {
                digest,
                data: bytes.slice(offset..end).to_vec(),
                org_id,
            };
            Some((frame, (bytes, end, None)))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt as _;

    fn digest_of(content: &[u8]) -> PayloadDigest {
        let hex = blake3::hash(content).to_hex().to_string();
        PayloadDigest::new(format!("blake3:{hex}")).expect("valid digest")
    }

    #[tokio::test]
    async fn frames_chunk_content_and_declare_identity_once() {
        let bytes = vec![7u8; UPLOAD_CHUNK_BYTES * 2 + 3];
        let digest = digest_of(&bytes);

        let frames: Vec<_> = upload_frames(&digest, "tenant-x", Bytes::from(bytes.clone()))
            .collect()
            .await;

        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].digest, digest.as_str());
        assert_eq!(frames[0].org_id, "tenant-x");
        assert_eq!(frames[0].data.len(), UPLOAD_CHUNK_BYTES);
        for frame in &frames[1..] {
            assert!(frame.digest.is_empty());
            assert!(frame.org_id.is_empty());
        }
        assert_eq!(frames[2].data.len(), 3);
        let assembled: Vec<u8> = frames.iter().flat_map(|f| f.data.clone()).collect();
        assert_eq!(assembled, bytes);
    }

    #[tokio::test]
    async fn empty_blob_is_a_single_identity_frame() {
        let digest = digest_of(b"");
        let frames: Vec<_> = upload_frames(&digest, "", Bytes::new()).collect().await;

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].digest, digest.as_str());
        assert!(frames[0].data.is_empty());
    }

    #[test]
    fn status_failures_preserve_retry_disposition() {
        assert_eq!(
            BlobCallFailure::from_status(&Status::resource_exhausted("full"), "full".to_owned(),)
                .into_error()
                .kind(),
            BlobStoreErrorKind::Backpressure
        );
        assert_eq!(
            BlobCallFailure::from_status(&Status::unavailable("offline"), "offline".to_owned())
                .into_error()
                .kind(),
            BlobStoreErrorKind::Unavailable
        );
        assert_eq!(
            BlobCallFailure::from_status(
                &Status::invalid_argument("bad digest"),
                "bad digest".to_owned(),
            )
            .into_error()
            .kind(),
            BlobStoreErrorKind::Rejected
        );
    }

    #[test]
    fn failed_credential_refresh_is_rejected() {
        let error = classify_refresh(
            crate::grpc_client::RefreshOutcome::Failed("session burned".to_owned()),
            "credential rejected".to_owned(),
        )
        .expect_err("a failed refresh is permanent");

        assert_eq!(error.kind(), BlobStoreErrorKind::Rejected);
        assert!(error.to_string().contains("session burned"));
    }

    #[tokio::test]
    async fn oversized_blob_is_rejected_client_side() {
        let uploader =
            GrpcBlobUploader::connect("http://127.0.0.1:9", None, true).expect("connect");
        let bytes = vec![0u8; usize::try_from(MAX_UPLOAD_BLOB_BYTES).expect("cap fits") + 1];

        // The endpoint above is unroutable: the rejection must happen before any RPC.
        let error = uploader
            .upload(&digest_of(&bytes), Bytes::from(bytes))
            .await
            .expect_err("over-cap blob must be rejected");
        assert_eq!(error.kind(), BlobStoreErrorKind::Rejected);
        assert!(error.to_string().contains("upload cap"));
    }

    #[tokio::test]
    async fn probe_with_no_digests_skips_the_rpc() {
        let uploader =
            GrpcBlobUploader::connect("http://127.0.0.1:9", None, true).expect("connect");

        // The endpoint above is unroutable: an empty probe must resolve without any RPC.
        let missing = uploader.find_missing(&[]).await.expect("empty probe");
        assert!(missing.is_empty());
    }
}
