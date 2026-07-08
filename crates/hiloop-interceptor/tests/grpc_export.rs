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
