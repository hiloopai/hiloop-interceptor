//! Remote [`BlobUploader`]: ships captured payload blobs to a hiloop telemetry gateway's
//! `TelemetryBlobService` over tonic, using the same endpoint and Bearer auth as the gRPC event
//! exporter. The protocol is digest-first ([`BlobUploader::find_missing`] → `HasBlobs`, then
//! [`BlobUploader::upload`] → client-streaming `UploadBlob` for exactly the missing digests), so
//! already-present content is never re-sent and the backend re-hashes before storing.

use std::collections::HashMap;

use async_trait::async_trait;
use hiloop_core::event::PayloadDigest;
use tonic::Request;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use crate::blob::{BlobStoreError, BlobUploader, MAX_UPLOAD_BLOB_BYTES};
use crate::grpc_client::proto::telemetry_blob_service_client::TelemetryBlobServiceClient;
use crate::grpc_client::proto::{HasBlobsRequest, UploadBlobRequest};
use crate::grpc_client::{AuthInterceptor, GrpcClientError, build_channel, fold_status_message};

const STORE_NAME: &str = "grpc-blob";

/// One `UploadBlob` frame's content chunk (1 MiB) — far below the gateway's raised 32 MiB
/// message cap and tonic's 4 MiB default, so a frame never trips a transport limit.
const UPLOAD_CHUNK_BYTES: usize = 1024 * 1024;

/// Deadline on one `HasBlobs` probe. The channel itself has no timeout, and a black-holed
/// gateway would otherwise hang the run-end drain (and with it the wrapper's exit) forever.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Deadline on one `UploadBlob` stream — generous enough for a cap-sized (64 MiB) blob on a
/// slow link, small enough that a wedged transfer cannot hang the drain unbounded.
const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

type AuthedClient = TelemetryBlobServiceClient<InterceptedService<Channel, AuthInterceptor>>;

/// Uploads content-addressed payload blobs to a telemetry gateway.
pub struct GrpcBlobUploader {
    client: AuthedClient,
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
        let endpoint = endpoint.into();
        let channel = build_channel(&endpoint, insecure).map_err(client_config_error)?;
        let interceptor = AuthInterceptor::from_env().map_err(client_config_error)?;
        let client = TelemetryBlobServiceClient::with_interceptor(channel, interceptor);
        Ok(Self { client, tenant_id })
    }

    fn tenant_wire_value(&self) -> String {
        // proto3 has no optional scalar here: the empty string is the wire form of "absent",
        // which is exactly what an authenticated gateway expects (it derives the tenant from
        // the Bearer token).
        self.tenant_id.clone().unwrap_or_default()
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
        let mut client = self.client.clone();
        let request = Request::new(HasBlobsRequest {
            digests: digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect(),
            tenant_id: self.tenant_wire_value(),
        });
        let response = tokio::time::timeout(PROBE_TIMEOUT, client.has_blobs(request))
            .await
            .map_err(|_elapsed| {
                BlobStoreError::other(
                    STORE_NAME,
                    format!("blob probe timed out after {}s", PROBE_TIMEOUT.as_secs()),
                )
            })?
            .map_err(|status| {
                BlobStoreError::other(
                    STORE_NAME,
                    format!("blob probe rejected: {}", fold_status_message(&status)),
                )
            })?
            .into_inner();

        // The gateway echoes missing digests verbatim as requested, so each echo must map back to
        // a digest we asked about; anything else is a contract violation, not data.
        let requested: HashMap<&str, &PayloadDigest> = digests
            .iter()
            .map(|digest| (digest.as_str(), digest))
            .collect();
        response
            .missing_digests
            .iter()
            .map(|raw| {
                requested
                    .get(raw.as_str())
                    .map(|&d| d.clone())
                    .ok_or_else(|| {
                        BlobStoreError::other(
                            STORE_NAME,
                            format!("gateway reported unrequested digest {raw:?} as missing"),
                        )
                    })
            })
            .collect()
    }

    async fn upload(&self, digest: &PayloadDigest, bytes: &[u8]) -> Result<(), BlobStoreError> {
        let size = bytes.len() as u64;
        if size > MAX_UPLOAD_BLOB_BYTES {
            return Err(BlobStoreError::other(
                STORE_NAME,
                format!(
                    "blob {digest} is {size} bytes, over the {MAX_UPLOAD_BLOB_BYTES} byte upload cap"
                ),
            ));
        }
        let frames = upload_frames(digest, &self.tenant_wire_value(), bytes);
        let mut client = self.client.clone();
        let stored = tokio::time::timeout(
            UPLOAD_TIMEOUT,
            client.upload_blob(tokio_stream::iter(frames)),
        )
        .await
        .map_err(|_elapsed| {
            BlobStoreError::other(
                STORE_NAME,
                format!(
                    "blob upload of {digest} timed out after {}s",
                    UPLOAD_TIMEOUT.as_secs()
                ),
            )
        })?
        .map_err(|status| {
            BlobStoreError::other(
                STORE_NAME,
                format!(
                    "blob upload of {digest} rejected: {}",
                    fold_status_message(&status)
                ),
            )
        })?
        .into_inner()
        .size_bytes;
        if stored != size {
            return Err(BlobStoreError::other(
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
fn upload_frames(digest: &PayloadDigest, tenant_id: &str, bytes: &[u8]) -> Vec<UploadBlobRequest> {
    let mut chunks = bytes.chunks(UPLOAD_CHUNK_BYTES);
    let first = UploadBlobRequest {
        digest: digest.as_str().to_owned(),
        data: chunks.next().unwrap_or_default().to_vec(),
        tenant_id: tenant_id.to_owned(),
    };
    std::iter::once(first)
        .chain(chunks.map(|chunk| UploadBlobRequest {
            digest: String::new(),
            data: chunk.to_vec(),
            tenant_id: String::new(),
        }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(content: &[u8]) -> PayloadDigest {
        let hex = blake3::hash(content).to_hex().to_string();
        PayloadDigest::new(format!("blake3:{hex}")).expect("valid digest")
    }

    #[test]
    fn frames_chunk_content_and_declare_identity_once() {
        let bytes = vec![7u8; UPLOAD_CHUNK_BYTES * 2 + 3];
        let digest = digest_of(&bytes);

        let frames = upload_frames(&digest, "tenant-x", &bytes);

        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].digest, digest.as_str());
        assert_eq!(frames[0].tenant_id, "tenant-x");
        assert_eq!(frames[0].data.len(), UPLOAD_CHUNK_BYTES);
        for frame in &frames[1..] {
            assert!(frame.digest.is_empty());
            assert!(frame.tenant_id.is_empty());
        }
        assert_eq!(frames[2].data.len(), 3);
        let assembled: Vec<u8> = frames.iter().flat_map(|f| f.data.clone()).collect();
        assert_eq!(assembled, bytes);
    }

    #[test]
    fn empty_blob_is_a_single_identity_frame() {
        let digest = digest_of(b"");
        let frames = upload_frames(&digest, "", b"");

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].digest, digest.as_str());
        assert!(frames[0].data.is_empty());
    }

    #[tokio::test]
    async fn oversized_blob_is_rejected_client_side() {
        let uploader =
            GrpcBlobUploader::connect("http://127.0.0.1:9", None, true).expect("connect");
        let bytes = vec![0u8; usize::try_from(MAX_UPLOAD_BLOB_BYTES).expect("cap fits") + 1];

        // The endpoint above is unroutable: the rejection must happen before any RPC.
        let error = uploader
            .upload(&digest_of(&bytes), &bytes)
            .await
            .expect_err("over-cap blob must be rejected");
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
