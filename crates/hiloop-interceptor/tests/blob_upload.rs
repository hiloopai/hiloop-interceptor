//! End-to-end round trip for the gRPC blob uploader: stand up an in-process
//! `TelemetryBlobService` that mirrors the gateway's production contract (digest-first `HasBlobs`,
//! client-streaming `UploadBlob` with first-frame identity and verify-before-store), then drive it
//! through `GrpcBlobUploader` and `DirBlobStore::upload_missing` — exercising the generated client,
//! the chunked frame protocol, and the dedup probe.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use hiloop_core::event::PayloadDigest;
use hiloop_interceptor::blob::{BlobStore, BlobUploader, DirBlobStore};
use hiloop_interceptor::blob_upload::GrpcBlobUploader;
use hiloop_interceptor::grpc_client::proto::telemetry_blob_service_server::{
    TelemetryBlobService, TelemetryBlobServiceServer,
};
use hiloop_interceptor::grpc_client::proto::{
    HasBlobsRequest, HasBlobsResponse, UploadBlobRequest, UploadBlobResponse,
};
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
    // upload_missing ships exactly what the gateway lacks.
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

    let report = store.upload_missing(&uploader).await.expect("drain");

    assert_eq!(report.found, 2);
    assert_eq!(report.uploaded, 1);
    assert_eq!(report.oversize_skipped, 0);
    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.uploads.len(), 1);
    assert_eq!(rec.uploads[0].digest, fresh.as_str());
    assert_eq!(rec.uploads[0].bytes, b"new capture");
}
