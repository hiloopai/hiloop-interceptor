//! End-to-end round trip for the gRPC exporter: stand up an in-process `TelemetryIngestService`,
//! export real captured events through `GrpcIngestExporter`, and assert the server received them
//! 1:1 with the configured tenant/project — exercising the generated client + wire conversion.

use std::sync::{Arc, Mutex};

use hiloop_core::event::{AttributeKey, Event, EventName, SignalType};
use hiloop_core::identity::{Hlc, RunContext};
use hiloop_interceptor::grpc_client::proto::telemetry_ingest_service_server::{
    TelemetryIngestService, TelemetryIngestServiceServer,
};
use hiloop_interceptor::grpc_client::proto::{
    Event as ProtoEvent, IngestRequest, IngestResponse, IngestStreamRequest, IngestStreamResponse,
};
use hiloop_interceptor::grpc_client::{GatewayCredential, RefreshBearer, RefreshFuture};
use hiloop_interceptor::grpc_export::GrpcIngestExporter;
use hiloop_interceptor::seams::{ExportError, Exporter};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status, Streaming};

#[derive(Default)]
struct Recorded {
    events: Vec<ProtoEvent>,
    tenant_id: String,
    project_id: String,
}

#[derive(Clone, Default)]
struct RecordingService {
    recorded: Arc<Mutex<Recorded>>,
    /// When set, report this accepted count instead of the true one (to exercise mismatch handling).
    force_accepted: Option<u64>,
}

#[tonic::async_trait]
impl TelemetryIngestService for RecordingService {
    async fn ingest(
        &self,
        request: Request<IngestRequest>,
    ) -> Result<Response<IngestResponse>, Status> {
        let req = request.into_inner();
        let true_count = req.events.len() as u64;
        {
            let mut rec = self.recorded.lock().expect("lock");
            rec.tenant_id = req.tenant_id;
            rec.project_id = req.project_id;
            rec.events.extend(req.events);
        }
        Ok(Response::new(IngestResponse {
            accepted: self.force_accepted.unwrap_or(true_count),
        }))
    }

    async fn ingest_stream(
        &self,
        request: Request<Streaming<IngestStreamRequest>>,
    ) -> Result<Response<IngestStreamResponse>, Status> {
        let mut stream = request.into_inner();
        let mut accepted = 0;
        while let Some(batch) = stream.message().await? {
            accepted += batch.events.len() as u64;
        }
        Ok(Response::new(IngestStreamResponse { accepted }))
    }
}

async fn serve(service: RecordingService) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TelemetryIngestServiceServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });
    format!("http://{addr}")
}

fn log_event(message: &str) -> Event {
    Event::new(
        &RunContext::new_local_root(),
        Hlc {
            wall_ns: 1,
            logical: 0,
        },
        SignalType::Log,
        EventName::new("process.stdout").expect("event name"),
    )
    .with_attribute(AttributeKey::new("message").expect("key"), message)
}

#[tokio::test]
async fn exports_events_to_the_gateway_with_tenant_and_project() {
    let service = RecordingService::default();
    let recorded = Arc::clone(&service.recorded);
    let endpoint = serve(service).await;

    let exporter =
        GrpcIngestExporter::connect(endpoint, Some("tenant-x".to_owned()), "proj-y", true)
            .expect("connect");

    let events = vec![log_event("one"), log_event("two")];
    exporter.export(&events).await.expect("export");
    exporter.flush().await.expect("flush");

    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.events.len(), 2);
    assert_eq!(rec.tenant_id, "tenant-x");
    assert_eq!(rec.project_id, "proj-y");
    // event_id is minted and carried over the wire.
    assert!(!rec.events[0].event_id.is_empty());
    assert_eq!(rec.events[0].signal, "log");
}

#[tokio::test]
async fn empty_batch_is_a_noop() {
    let service = RecordingService::default();
    let recorded = Arc::clone(&service.recorded);
    let endpoint = serve(service).await;

    let exporter = GrpcIngestExporter::connect(endpoint, None, "default", true).expect("connect");
    exporter.export(&[]).await.expect("empty export");

    assert_eq!(recorded.lock().expect("lock").events.len(), 0);
}

#[tokio::test]
async fn omitted_tenant_is_empty_on_the_wire() {
    let service = RecordingService::default();
    let recorded = Arc::clone(&service.recorded);
    let endpoint = serve(service).await;

    // `None` tenant (the authenticated-gateway path) collapses to proto3's empty-string "absent".
    let exporter = GrpcIngestExporter::connect(endpoint, None, "proj-y", true).expect("connect");
    exporter.export(&[log_event("one")]).await.expect("export");

    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.tenant_id, "");
    assert_eq!(rec.project_id, "proj-y");
}

/// Ingest service that refuses every RPC with a fixed status code.
#[derive(Clone)]
struct RefusingService {
    code: Code,
}

#[tonic::async_trait]
impl TelemetryIngestService for RefusingService {
    async fn ingest(
        &self,
        _request: Request<IngestRequest>,
    ) -> Result<Response<IngestResponse>, Status> {
        Err(Status::new(self.code, "refused by test gateway"))
    }

    async fn ingest_stream(
        &self,
        _request: Request<Streaming<IngestStreamRequest>>,
    ) -> Result<Response<IngestStreamResponse>, Status> {
        Err(Status::new(self.code, "refused by test gateway"))
    }
}

async fn serve_refusing(code: Code) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TelemetryIngestServiceServer::new(RefusingService { code }))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });
    format!("http://{addr}")
}

/// One classification-matrix row: a status code, the variant check it must satisfy,
/// and the expected variant's name for the failure message.
type ClassificationCase = (Code, fn(&ExportError) -> bool, &'static str);

/// The classification matrix over the real wire: each gateway status code lands in
/// the `ExportError` retry-taxonomy variant the spooling wrapper dispatches on.
#[tokio::test]
async fn gateway_status_codes_classify_onto_the_export_error_taxonomy() {
    let cases: &[ClassificationCase] = &[
        (
            Code::ResourceExhausted,
            |e| matches!(e, ExportError::Backpressure { .. }),
            "Backpressure",
        ),
        (
            Code::Unavailable,
            |e| matches!(e, ExportError::Unavailable { .. }),
            "Unavailable",
        ),
        (
            Code::InvalidArgument,
            |e| matches!(e, ExportError::Rejected { .. }),
            "Rejected",
        ),
        (
            Code::PermissionDenied,
            |e| matches!(e, ExportError::Rejected { .. }),
            "Rejected",
        ),
        (
            Code::Unauthenticated,
            |e| matches!(e, ExportError::Rejected { .. }),
            "Rejected",
        ),
        (
            Code::Internal,
            |e| matches!(e, ExportError::Other { .. }),
            "Other",
        ),
    ];
    for (code, expected, expected_name) in cases {
        let endpoint = serve_refusing(*code).await;
        let exporter =
            GrpcIngestExporter::connect(endpoint, None, "proj-y", true).expect("connect");

        let error = exporter
            .export(&[log_event("one")])
            .await
            .expect_err("the refusing gateway must fail the export");

        assert!(
            expected(&error),
            "code {code:?} should classify as {expected_name}, got {error:?}"
        );
    }
}

/// A gateway that is not there at all (connection refused) classifies as the
/// transient `Unavailable`, so the spool retries instead of dropping.
#[tokio::test]
async fn unreachable_gateway_classifies_as_unavailable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let exporter = GrpcIngestExporter::connect(format!("http://{addr}"), None, "proj-y", true)
        .expect("connect");

    let error = exporter
        .export(&[log_event("one")])
        .await
        .expect_err("nothing listens on the dropped port");

    assert!(
        matches!(error, ExportError::Unavailable { .. }),
        "a transport failure classifies as Unavailable, got {error:?}"
    );
}

/// Ingest service that mirrors an authenticated gateway: any request not presenting
/// `Bearer <expected>` is refused `UNAUTHENTICATED` (the wire truth of an access token that
/// aged out mid-run); a correctly authenticated request records like [`RecordingService`].
#[derive(Clone)]
struct AuthGatedService {
    expected_token: &'static str,
    recorded: Arc<Mutex<Recorded>>,
    rejections: Arc<std::sync::atomic::AtomicUsize>,
}

impl AuthGatedService {
    fn expecting(token: &'static str) -> Self {
        Self {
            expected_token: token,
            recorded: Arc::default(),
            rejections: Arc::default(),
        }
    }

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
impl TelemetryIngestService for AuthGatedService {
    async fn ingest(
        &self,
        request: Request<IngestRequest>,
    ) -> Result<Response<IngestResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();
        let accepted = req.events.len() as u64;
        self.recorded
            .lock()
            .expect("lock")
            .events
            .extend(req.events);
        Ok(Response::new(IngestResponse { accepted }))
    }

    async fn ingest_stream(
        &self,
        request: Request<Streaming<IngestStreamRequest>>,
    ) -> Result<Response<IngestStreamResponse>, Status> {
        self.authorize(&request)?;
        let mut stream = request.into_inner();
        let mut accepted = 0;
        while let Some(batch) = stream.message().await? {
            accepted += batch.events.len() as u64;
        }
        Ok(Response::new(IngestStreamResponse { accepted }))
    }
}

async fn serve_auth_gated(service: AuthGatedService) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TelemetryIngestServiceServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });
    format!("http://{addr}")
}

/// [`RefreshBearer`] fake over a fixed replacement token (or a fixed failure), counting calls —
/// the seam a wrapping CLI fills with its login-session rotation.
#[derive(Debug)]
struct FakeSessionRefresher {
    replacement: Result<&'static str, &'static str>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl FakeSessionRefresher {
    fn returning(token: &'static str) -> Self {
        Self {
            replacement: Ok(token),
            calls: Arc::default(),
        }
    }

    fn failing(message: &'static str) -> Self {
        Self {
            replacement: Err(message),
            calls: Arc::default(),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl RefreshBearer for FakeSessionRefresher {
    fn refresh<'a>(&'a self, _rejected: Option<&'a str>) -> RefreshFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.replacement
                .map(str::to_owned)
                .map_err(|message| Box::from(message) as _)
        })
    }
}

/// The HIL-2111 defect shape: a login-session access token ages out mid-run and the gateway
/// starts answering `UNAUTHENTICATED`. With a refreshable credential the exporter must refresh
/// once and redeliver the same batch — never classify the rejection permanent and drop it.
#[tokio::test]
async fn an_unauthenticated_rejection_with_a_refreshable_credential_redelivers_after_refresh() {
    let service = AuthGatedService::expecting("fresh-token");
    let recorded = Arc::clone(&service.recorded);
    let rejections = Arc::clone(&service.rejections);
    let endpoint = serve_auth_gated(service).await;

    let refresher = Arc::new(FakeSessionRefresher::returning("fresh-token"));
    let credential =
        GatewayCredential::new(Some("expired-token"), Some(Arc::clone(&refresher) as _))
            .expect("credential");
    let exporter =
        GrpcIngestExporter::with_credential(endpoint, None, "proj-y", true, credential.clone())
            .expect("connect");

    exporter
        .export(&[log_event("one"), log_event("two")])
        .await
        .expect("the batch must be redelivered under the refreshed credential");

    let rec = recorded.lock().expect("lock");
    assert_eq!(rec.events.len(), 2, "the same batch lands exactly once");
    assert_eq!(rejections.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(refresher.calls(), 1, "one rejection, one rotation");
    assert_eq!(credential.refreshes(), 1);
}

/// Zero-loss end to end through the spool: the batch that trips the expired token and every
/// batch after it must land, with nothing dropped as permanently rejected.
#[tokio::test]
async fn spooled_batches_survive_a_mid_run_token_expiry_with_zero_loss() {
    use hiloop_interceptor::blob_drain::DrainRetryPolicy;
    use hiloop_interceptor::spool::{SpoolPolicy, SpoolingExporter};

    let service = AuthGatedService::expecting("fresh-token");
    let recorded = Arc::clone(&service.recorded);
    let endpoint = serve_auth_gated(service).await;

    let refresher = Arc::new(FakeSessionRefresher::returning("fresh-token"));
    let credential =
        GatewayCredential::new(Some("expired-token"), Some(Arc::clone(&refresher) as _))
            .expect("credential");
    let exporter = GrpcIngestExporter::with_credential(endpoint, None, "proj-y", true, credential)
        .expect("connect");
    let spool = SpoolingExporter::new(exporter, SpoolPolicy::default());

    spool.export(&[log_event("one")]).await.expect("export");
    spool.export(&[log_event("two")]).await.expect("export");
    let report = spool
        .drain(&DrainRetryPolicy {
            attempts: 3,
            initial_backoff: std::time::Duration::from_millis(1),
        })
        .await;

    assert!(report.is_clean(), "zero loss, zero backlog: {report:?}");
    assert_eq!(report.rejected_events, 0, "nothing was dropped as rejected");
    let delivered: Vec<String> = recorded
        .lock()
        .expect("lock")
        .events
        .iter()
        .map(|event| event.name.clone())
        .collect();
    assert_eq!(delivered.len(), 2, "every batch landed: {delivered:?}");
}

/// The bounded case: the refresh itself fails (a burned session), so the original
/// classification is preserved — the rejection stays permanent, attributed with both reasons.
#[tokio::test]
async fn a_failed_refresh_keeps_the_permanent_rejection() {
    let service = AuthGatedService::expecting("never-matched");
    let recorded = Arc::clone(&service.recorded);
    let endpoint = serve_auth_gated(service).await;

    let refresher = Arc::new(FakeSessionRefresher::failing("the refresh token is burned"));
    let credential =
        GatewayCredential::new(Some("expired-token"), Some(Arc::clone(&refresher) as _))
            .expect("credential");
    let exporter = GrpcIngestExporter::with_credential(endpoint, None, "proj-y", true, credential)
        .expect("connect");

    let error = exporter
        .export(&[log_event("one")])
        .await
        .expect_err("an unrefreshable rejection stays an error");

    assert!(
        matches!(error, ExportError::Rejected { .. }),
        "a failed refresh keeps the permanent classification, got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("authentication") && message.contains("the refresh token is burned"),
        "both the rejection and the refresh failure are attributed: {message}"
    );
    assert_eq!(refresher.calls(), 1);
    assert!(recorded.lock().expect("lock").events.is_empty());
}

/// A second `UNAUTHENTICATED` after a successful refresh is a judgment on the credential
/// itself, not a stale token: permanent, exactly one rotation attempted.
#[tokio::test]
async fn a_rejection_of_the_refreshed_credential_is_permanent() {
    let service = AuthGatedService::expecting("never-matched");
    let rejections = Arc::clone(&service.rejections);
    let endpoint = serve_auth_gated(service).await;

    let refresher = Arc::new(FakeSessionRefresher::returning("still-wrong"));
    let credential =
        GatewayCredential::new(Some("expired-token"), Some(Arc::clone(&refresher) as _))
            .expect("credential");
    let exporter = GrpcIngestExporter::with_credential(endpoint, None, "proj-y", true, credential)
        .expect("connect");

    let error = exporter
        .export(&[log_event("one")])
        .await
        .expect_err("a rejected refreshed credential stays an error");

    assert!(
        matches!(error, ExportError::Rejected { .. }),
        "got {error:?}"
    );
    assert_eq!(refresher.calls(), 1, "refresh once, never loop");
    assert_eq!(rejections.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn accepted_count_mismatch_is_an_error() {
    let service = RecordingService {
        force_accepted: Some(99),
        ..RecordingService::default()
    };
    let endpoint = serve(service).await;

    let exporter =
        GrpcIngestExporter::connect(endpoint, Some("tenant-x".to_owned()), "proj-y", true)
            .expect("connect");
    let error = exporter
        .export(&[log_event("one")])
        .await
        .expect_err("mismatch must error");
    assert!(error.to_string().contains("accepted 99 of 1"));
}
