//! End-to-end round trip for the gRPC blob uploader: stand up an in-process
//! `TelemetryBlobService` that mirrors the gateway's production contract (digest-first `HasBlobs`,
//! client-streaming `UploadBlob` with first-frame identity and verify-before-store), then drive it
//! through `GrpcBlobUploader` and `BlobDrainer` — exercising the generated client, the chunked
//! frame protocol, and the dedup probe.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use hiloop_core::event::PayloadDigest;
use hiloop_interceptor::blob::{BlobStore, BlobUploader, DirBlobStore};
use hiloop_interceptor::blob_drain::{BlobDrainer, DrainRetryPolicy};
use hiloop_interceptor::blob_upload::GrpcBlobUploader;
use hiloop_interceptor::grpc_client::proto::telemetry_blob_service_server::{
    TelemetryBlobService, TelemetryBlobServiceServer,
};
use hiloop_interceptor::grpc_client::proto::{
    HasBlobsRequest, HasBlobsResponse, UploadBlobRequest, UploadBlobResponse,
};
use hiloop_interceptor::grpc_client::{GatewayCredential, RefreshBearer, RefreshFuture};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, Streaming};

/// One completed upload as the fake gateway observed it.
#[derive(Debug, Clone)]
struct RecordedUpload {
    digest: String,
    tenant_id: String,
    frames: usize,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Recorded {
    probes: Vec<(Vec<String>, String)>,
    uploads: Vec<RecordedUpload>,
}

/// In-process `TelemetryBlobService` mirroring the gateway contract: `HasBlobs` echoes the
/// requested spellings of digests it does not hold, `UploadBlob` takes identity from the first
/// frame, rejects a mid-stream identity switch, and verifies the assembled bytes hash to the
/// declared digest before "storing" (fail closed).
#[derive(Clone, Default)]
struct RecordingBlobService {
    have: Arc<HashSet<String>>,
    recorded: Arc<Mutex<Recorded>>,
    /// When set, report this stored size instead of the true one (to exercise mismatch handling).
    force_size: Option<u64>,
}

impl RecordingBlobService {
    fn with_existing(have: impl IntoIterator<Item = String>) -> Self {
        Self {
            have: Arc::new(have.into_iter().collect()),
            ..Self::default()
        }
    }

    fn recorded(&self) -> Arc<Mutex<Recorded>> {
        Arc::clone(&self.recorded)
    }
}

fn bare_hex(digest: &str) -> &str {
    digest.strip_prefix("blake3:").unwrap_or(digest)
}

#[tonic::async_trait]
impl TelemetryBlobService for RecordingBlobService {
    async fn has_blobs(
        &self,
        request: Request<HasBlobsRequest>,
    ) -> Result<Response<HasBlobsResponse>, Status> {
        let req = request.into_inner();
        self.recorded
            .lock()
            .expect("lock")
            .probes
            .push((req.digests.clone(), req.tenant_id.clone()));
        let missing_digests = req
            .digests
            .into_iter()
            .filter(|raw| !self.have.contains(bare_hex(raw)))
            .collect();
        Ok(Response::new(HasBlobsResponse { missing_digests }))
    }

    async fn upload_blob(
        &self,
        request: Request<Streaming<UploadBlobRequest>>,
    ) -> Result<Response<UploadBlobResponse>, Status> {
        let mut stream = request.into_inner();
        let Some(first) = stream.message().await? else {
            return Err(Status::invalid_argument("upload stream carried no frames"));
        };
        if first.digest.is_empty() {
            return Err(Status::invalid_argument(
                "first frame must declare the digest",
            ));
        }
        let digest = first.digest.clone();
        let tenant_id = first.tenant_id.clone();

        let mut bytes: Vec<u8> = Vec::new();
        let mut frames = 0usize;
        let mut frame = first;
        loop {
            frames += 1;
            if !frame.digest.is_empty() && frame.digest != digest {
                return Err(Status::invalid_argument(
                    "digest changed mid-upload; one UploadBlob stream carries one blob",
                ));
            }
            bytes.extend_from_slice(&frame.data);
            match stream.message().await? {
                Some(next) => frame = next,
                None => break,
            }
        }

        // The production gateway's CAS contract: verify before any write (fail closed).
        let hashed = blake3::hash(&bytes).to_hex().to_string();
        if hashed != bare_hex(&digest) {
            return Err(Status::invalid_argument(format!(
                "uploaded content does not hash to the declared digest {digest}"
            )));
        }

        let size_bytes = self.force_size.unwrap_or(bytes.len() as u64);
        self.recorded
            .lock()
            .expect("lock")
            .uploads
            .push(RecordedUpload {
                digest,
                tenant_id,
                frames,
                bytes,
            });
        Ok(Response::new(UploadBlobResponse { size_bytes }))
    }
}

async fn serve(service: RecordingBlobService) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TelemetryBlobServiceServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });
    format!("http://{addr}")
}

fn digest_of(content: &[u8]) -> PayloadDigest {
    let hex = blake3::hash(content).to_hex().to_string();
    PayloadDigest::new(format!("blake3:{hex}")).expect("valid digest")
}

#[tokio::test]
async fn probe_reports_only_gateway_missing_digests() {
    let have = digest_of(b"already there");
    let missing = digest_of(b"not yet");
    let service = RecordingBlobService::with_existing([bare_hex(have.as_str()).to_owned()]);
    let recorded = service.recorded();
    let endpoint = serve(service).await;

    let uploader =
        GrpcBlobUploader::connect(endpoint, Some("tenant-x".to_owned()), true).expect("connect");
    let reported = uploader
        .find_missing(&[have.clone(), missing.clone()])
        .await
        .expect("probe");

    assert_eq!(reported, vec![missing.clone()]);
    let rec = recorded.lock().expect("lock");
    assert_eq!(
        rec.probes,
        vec![(
            vec![have.as_str().to_owned(), missing.as_str().to_owned()],
            "tenant-x".to_owned()
        )]
    );
}

#[tokio::test]
async fn upload_chunks_large_blobs_and_declares_identity_once() {
    // 2 MiB + change: three 1 MiB frames on the wire.
    let bytes: Vec<u8> = (0..(2 * 1024 * 1024 + 512usize))
        .map(|i| (i % 251) as u8)
        .collect();
    let digest = digest_of(&bytes);
    let service = RecordingBlobService::default();
    let recorded = service.recorded();
    let endpoint = serve(service).await;

    let uploader =
        GrpcBlobUploader::connect(endpoint, Some("tenant-x".to_owned()), true).expect("connect");
    uploader.upload(&digest, &bytes).await.expect("upload");

    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.uploads.len(), 1);
    let upload = &rec.uploads[0];
    // The fake verified blake3(content) == the declared digest before recording, so getting here
    // means the chunked reassembly is byte-exact.
    assert_eq!(upload.digest, digest.as_str());
    assert_eq!(upload.tenant_id, "tenant-x");
    assert_eq!(upload.frames, 3);
    assert_eq!(upload.bytes, bytes);
}

#[tokio::test]
async fn empty_blob_uploads_as_a_single_identity_frame() {
    let digest = digest_of(b"");
    let service = RecordingBlobService::default();
    let recorded = service.recorded();
    let endpoint = serve(service).await;

    let uploader = GrpcBlobUploader::connect(endpoint, None, true).expect("connect");
    uploader.upload(&digest, b"").await.expect("upload");

    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.uploads.len(), 1);
    assert_eq!(rec.uploads[0].frames, 1);
    assert!(rec.uploads[0].bytes.is_empty());
    // `None` tenant (the authenticated-gateway path) collapses to proto3's empty-string "absent".
    assert_eq!(rec.uploads[0].tenant_id, "");
}

/// Blob service that mirrors an authenticated gateway: any request not presenting
/// `Bearer <expected>` is refused `UNAUTHENTICATED`; a correctly authenticated one delegates
/// to the recording contract fake.
#[derive(Clone)]
struct AuthGatedBlobService {
    expected_token: &'static str,
    inner: RecordingBlobService,
    rejections: Arc<std::sync::atomic::AtomicUsize>,
}

impl AuthGatedBlobService {
    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let presented = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        if presented == Some(&format!("Bearer {}", self.expected_token)) {
            return Ok(());
        }
        self.rejections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(Status::unauthenticated(
            "The request does not have valid authentication credentials",
        ))
    }
}

#[tonic::async_trait]
impl TelemetryBlobService for AuthGatedBlobService {
    async fn has_blobs(
        &self,
        request: Request<HasBlobsRequest>,
    ) -> Result<Response<HasBlobsResponse>, Status> {
        self.authorize(&request)?;
        self.inner.has_blobs(request).await
    }

    async fn upload_blob(
        &self,
        request: Request<Streaming<UploadBlobRequest>>,
    ) -> Result<Response<UploadBlobResponse>, Status> {
        self.authorize(&request)?;
        self.inner.upload_blob(request).await
    }
}

/// [`RefreshBearer`] fake yielding one fixed replacement token.
#[derive(Debug)]
struct FakeSessionRefresher {
    replacement: &'static str,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl RefreshBearer for FakeSessionRefresher {
    fn refresh<'a>(&'a self, _rejected: Option<&'a str>) -> RefreshFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.replacement.to_owned())
        })
    }
}

/// The blob leg of the mid-run token expiry (HIL-2129's stranded-blobs shape): the probe and the
/// upload must refresh a rejected session credential and retry, so the drain can complete
/// instead of stranding captured bodies locally.
#[tokio::test]
async fn an_unauthenticated_probe_refreshes_the_credential_and_retries() {
    let bytes = b"survives token expiry".to_vec();
    let digest = digest_of(&bytes);
    let service = AuthGatedBlobService {
        expected_token: "fresh-token",
        inner: RecordingBlobService::default(),
        rejections: Arc::default(),
    };
    let recorded = service.inner.recorded();
    let rejections = Arc::clone(&service.rejections);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TelemetryBlobServiceServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });

    let refresher = Arc::new(FakeSessionRefresher {
        replacement: "fresh-token",
        calls: Arc::default(),
    });
    let credential =
        GatewayCredential::new(Some("expired-token"), Some(Arc::clone(&refresher) as _))
            .expect("credential");
    let uploader =
        GrpcBlobUploader::with_credential(format!("http://{addr}"), None, true, credential)
            .expect("connect");

    let missing = uploader
        .find_missing(std::slice::from_ref(&digest))
        .await
        .expect("the probe must succeed under the refreshed credential");
    assert_eq!(missing, vec![digest.clone()]);

    uploader
        .upload(&digest, &bytes)
        .await
        .expect("the upload proceeds under the already-refreshed credential");

    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.uploads.len(), 1);
    assert_eq!(rec.uploads[0].bytes, bytes);
    assert_eq!(
        refresher.calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one rejection, one rotation, shared across the leg"
    );
    assert_eq!(rejections.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gateway_rejection_surfaces_as_a_readable_error() {
    let digest = digest_of(b"the real content");
    let service = RecordingBlobService::default();
    let endpoint = serve(service).await;

    let uploader = GrpcBlobUploader::connect(endpoint, None, true).expect("connect");
    // Mislabeled content: the gateway verifies before storing and must reject.
    let error = uploader
        .upload(&digest, b"other bytes")
        .await
        .expect_err("hash mismatch must be rejected");

    let message = error.to_string();
    assert!(message.contains("rejected"), "got: {message}");
    assert!(
        message.contains("does not hash to the declared digest"),
        "got: {message}"
    );
}

#[tokio::test]
async fn stored_size_mismatch_is_an_error() {
    let bytes = b"four".to_vec();
    let digest = digest_of(&bytes);
    let service = RecordingBlobService {
        force_size: Some(99),
        ..RecordingBlobService::default()
    };
    let endpoint = serve(service).await;

    let uploader = GrpcBlobUploader::connect(endpoint, None, true).expect("connect");
    let error = uploader
        .upload(&digest, &bytes)
        .await
        .expect_err("size mismatch must error");
    assert!(error.to_string().contains("stored 99 bytes"));
}

#[tokio::test]
async fn dir_store_drains_only_missing_blobs_to_the_gateway() {
    // The production shape end to end: bodies land in a DirBlobStore during capture, then
    // the drainer ships exactly what the gateway lacks.
    let temp = tempfile::tempdir().expect("tempdir");
    let store = DirBlobStore::create(temp.path())
        .await
        .expect("create store");
    let mut writer = store.writer();
    writer.write(b"present upstream").await.expect("write");
    let present = writer.finish().await.expect("finish").digest;
    let mut writer = store.writer();
    writer.write(b"new capture").await.expect("write");
    let fresh = writer.finish().await.expect("finish").digest;

    let service = RecordingBlobService::with_existing([bare_hex(present.as_str()).to_owned()]);
    let recorded = service.recorded();
    let endpoint = serve(service).await;
    let uploader = GrpcBlobUploader::connect(endpoint, None, true).expect("connect");

    let outcome = BlobDrainer::new(store, Arc::new(uploader))
        .finish(&DrainRetryPolicy::default())
        .await;

    assert!(outcome.is_complete(), "outcome: {outcome:?}");
    assert_eq!(outcome.report.found, 2);
    assert_eq!(outcome.report.landed, 2);
    assert_eq!(outcome.report.uploaded, 1);
    assert_eq!(outcome.report.oversize_skipped, 0);
    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.uploads.len(), 1);
    assert_eq!(rec.uploads[0].digest, fresh.as_str());
    assert_eq!(rec.uploads[0].bytes, b"new capture");
}
