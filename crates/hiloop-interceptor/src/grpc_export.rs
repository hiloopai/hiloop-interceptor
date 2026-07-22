//! Native gRPC exporter: streams normalized events to a hiloop telemetry gateway's
//! `TelemetryIngestService` over tonic. An authenticated gateway derives the tenant from the
//! request's Bearer token, so the client omits `tenant_id` (`None`) there; `project_id` selects the
//! project to record under. Against an unauthenticated local gateway, set `tenant_id` explicitly.

use crate::grpc_client::{AuthInterceptor, GatewayCredential, build_channel, fold_status_message};
use crate::seams::{ExportError, Exporter};
use async_trait::async_trait;
use hiloop_core::event::{AttributeValue, Event, PayloadRef, SignalType};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Status};

use crate::grpc_client::proto;
use proto::telemetry_ingest_service_client::TelemetryIngestServiceClient;

type AuthedClient = TelemetryIngestServiceClient<InterceptedService<Channel, AuthInterceptor>>;

/// Deadline on one `Ingest` RPC, covering the lazy (re)connect it may perform. The exporter is
/// exercised on the teardown drain after the child exits; without a deadline a black-holed gateway
/// stalls that drain — and the wrapper's exit — indefinitely. 10 s matches the export path's
/// per-attempt convention (the spool's `attempt_timeout`, the blob `HasBlobs` probe). A timed-out
/// call classifies as [`ExportError::Unavailable`] so a spooling wrapper parks and retries it.
const INGEST_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Ships events to the telemetry gateway over gRPC.
pub struct GrpcIngestExporter {
    client: AuthedClient,
    credential: GatewayCredential,
    tenant_id: Option<String>,
    project_id: String,
}

impl GrpcIngestExporter {
    /// Build a lazily-connected exporter for `endpoint` (e.g.
    /// `https://telemetry.example.com:443`). The channel connects on first export, not here,
    /// so a gateway that is briefly unreachable at startup doesn't abort the run (and any local
    /// JSONL sink keeps capturing). Every export is deadline-bounded (10 s per `Ingest` RPC,
    /// covering the lazy connect), so an unreachable gateway fails the export as
    /// [`ExportError::Unavailable`] instead of stalling the caller — the teardown drain must
    /// never outlive the child unboundedly. TLS (native + webpki trust roots) is used unless
    /// `insecure` is set (h2c, local dev only). The Bearer token is read from `HILOOP_API_KEY`;
    /// absent/empty means no auth header (an unauthenticated dev gateway). Pass `None` for
    /// `tenant_id` against an authenticated gateway (it derives the tenant from the token); pass
    /// `Some(tenant)` only against a no-auth local gateway. `project_id` selects the project.
    pub fn connect(
        endpoint: impl Into<String>,
        tenant_id: Option<String>,
        project_id: impl Into<String>,
        insecure: bool,
    ) -> Result<Self, ExportError> {
        let credential = GatewayCredential::from_env().map_err(client_config_error)?;
        Self::with_credential(endpoint, tenant_id, project_id, insecure, credential)
    }

    /// Like [`connect`](Self::connect), but presenting an explicit (possibly refreshable)
    /// `credential` instead of reading [`crate::grpc_client::TOKEN_ENV`]. Share one
    /// [`GatewayCredential`] across the event exporter and the blob uploader so a refresh
    /// triggered by either leg re-authenticates both.
    pub fn with_credential(
        endpoint: impl Into<String>,
        tenant_id: Option<String>,
        project_id: impl Into<String>,
        insecure: bool,
        credential: GatewayCredential,
    ) -> Result<Self, ExportError> {
        let endpoint = endpoint.into();
        let channel = build_channel(&endpoint, insecure).map_err(client_config_error)?;
        let interceptor = AuthInterceptor::new(credential.clone());
        let client = TelemetryIngestServiceClient::with_interceptor(channel, interceptor);
        Ok(Self {
            client,
            credential,
            tenant_id,
            project_id: project_id.into(),
        })
    }
}

/// How one `Ingest` RPC attempt failed, kept unmapped so the retry-after-refresh path can
/// inspect the raw gateway status before it is folded onto the [`ExportError`] taxonomy.
enum IngestFailure {
    Timeout(std::time::Duration),
    Rpc(Status),
    Mismatch { accepted: u64, expected: u64 },
}

impl IngestFailure {
    fn into_export_error(self) -> ExportError {
        match self {
            Self::Timeout(deadline) => ExportError::unavailable(
                "grpc",
                format!("ingest timed out after {}s", deadline.as_secs_f64()),
            ),
            Self::Rpc(status) => ingest_error(&status),
            Self::Mismatch { accepted, expected } => ExportError::other(
                "grpc",
                format!("gateway accepted {accepted} of {expected} events"),
            ),
        }
    }
}

impl GrpcIngestExporter {
    /// One deadline-bounded `Ingest` RPC. The deadline is a parameter so a regression test can
    /// exercise the timeout path against a stalling gateway without waiting out the production
    /// [`INGEST_RPC_TIMEOUT`].
    async fn ingest_once(
        &self,
        proto_events: &[proto::Event],
        deadline: std::time::Duration,
    ) -> Result<(), IngestFailure> {
        let expected = u64::try_from(proto_events.len()).unwrap_or(u64::MAX);
        let mut client = self.client.clone();
        let rpc = client.ingest(Request::new(proto::IngestRequest {
            events: proto_events.to_vec(),
            // proto3 has no optional scalar here: the empty string is the wire form of
            // "absent", which is exactly what an authenticated gateway expects (it derives
            // the tenant from the Bearer token).
            tenant_id: self.tenant_id.clone().unwrap_or_default(),
            project_id: self.project_id.clone(),
        }));
        let accepted = tokio::time::timeout(deadline, rpc)
            .await
            .map_err(|_elapsed| IngestFailure::Timeout(deadline))?
            .map_err(IngestFailure::Rpc)?
            .into_inner()
            .accepted;
        if accepted != expected {
            return Err(IngestFailure::Mismatch { accepted, expected });
        }
        Ok(())
    }

    /// Deliver one batch, riding out an aged-out credential: an `UNAUTHENTICATED` rejection of a
    /// refreshable bearer is retryable-after-refresh — rotate once (single-flight across legs)
    /// and redeliver the same batch before classifying anything permanent. A static credential,
    /// a failed rotation, or a rejection of the freshly rotated bearer keeps today's permanent
    /// [`ExportError::Rejected`]; a rotation still in flight past its wait bound classifies as
    /// transient so a spooling wrapper parks the batch and redelivers it later.
    async fn ingest_within(
        &self,
        events: &[Event],
        deadline: std::time::Duration,
    ) -> Result<(), ExportError> {
        use crate::grpc_client::RefreshOutcome;

        if events.is_empty() {
            return Ok(());
        }
        let proto_events: Vec<proto::Event> = events.iter().map(to_proto_event).collect();
        let presented = self.credential.bearer();
        let failure = match self.ingest_once(&proto_events, deadline).await {
            Ok(()) => return Ok(()),
            Err(failure) => failure,
        };
        let IngestFailure::Rpc(status) = &failure else {
            return Err(failure.into_export_error());
        };
        if status.code() != tonic::Code::Unauthenticated {
            return Err(failure.into_export_error());
        }
        match self.credential.refresh_rejected(presented.as_ref()).await {
            RefreshOutcome::Refreshed => self
                .ingest_once(&proto_events, deadline)
                .await
                .map_err(IngestFailure::into_export_error),
            RefreshOutcome::Unrefreshable => Err(failure.into_export_error()),
            RefreshOutcome::Failed(reason) => Err(ExportError::rejected(
                "grpc",
                format!(
                    "{}; refreshing the export credential failed: {reason}",
                    ingest_rejection_message(status)
                ),
            )),
            RefreshOutcome::Pending => Err(ExportError::unavailable(
                "grpc",
                format!(
                    "{}; a credential refresh is still in flight, so the batch parks for redelivery",
                    ingest_rejection_message(status)
                ),
            )),
        }
    }
}

#[async_trait]
impl Exporter for GrpcIngestExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        self.ingest_within(events, INGEST_RPC_TIMEOUT).await
    }
}

/// Wrap a gateway-client configuration failure as an export error.
fn client_config_error(error: crate::grpc_client::GrpcClientError) -> ExportError {
    ExportError::with_source("grpc", "failed to configure the gateway client", error)
}

/// Map a failed ingest RPC onto the [`ExportError`] retry taxonomy by `tonic::Code`,
/// so a spooling/retrying wrapper can tell a gateway outage from a judged rejection:
///
/// - `RESOURCE_EXHAUSTED` → [`ExportError::Backpressure`] (the gateway is shedding
///   load — a typed backlog shed deserves redelivery, not a warning);
/// - `UNAVAILABLE`, or any status caused by a transport failure → [`ExportError::Unavailable`];
/// - `INVALID_ARGUMENT` / `PERMISSION_DENIED` / `UNAUTHENTICATED` →
///   [`ExportError::Rejected`] (the batch or its credentials were judged and refused);
/// - anything else → the ambiguous [`ExportError::Other`].
fn ingest_error(status: &Status) -> ExportError {
    use tonic::Code;

    let message = ingest_rejection_message(status);
    match status.code() {
        Code::ResourceExhausted => ExportError::backpressure("grpc", message),
        Code::Unavailable => ExportError::unavailable("grpc", message),
        Code::InvalidArgument | Code::PermissionDenied | Code::Unauthenticated => {
            ExportError::rejected("grpc", message)
        }
        _ if is_transport_failure(status) => ExportError::unavailable("grpc", message),
        _ => ExportError::other("grpc", message),
    }
}

/// Whether the status was minted from a client-side transport failure (connect refused,
/// broken stream) rather than returned by the gateway. tonic stamps most of these
/// `UNAVAILABLE`, but some hops surface as `UNKNOWN` with the transport error as source.
fn is_transport_failure(status: &Status) -> bool {
    let mut source = std::error::Error::source(status);
    while let Some(error) = source {
        if error.is::<tonic::transport::Error>() {
            return true;
        }
        source = error.source();
    }
    false
}

/// Render a rejected ingest RPC as one human-readable line (see
/// [`fold_status_message`] for why the `Status` chain is folded rather than kept).
fn ingest_rejection_message(status: &Status) -> String {
    format!("ingest rejected: {}", fold_status_message(status))
}

fn to_proto_event(event: &Event) -> proto::Event {
    proto::Event {
        ts: Some(proto::Hlc {
            wall_ns: event.ts.wall_ns,
            logical: event.ts.logical,
        }),
        run_id: event.run_id.to_string(),
        signal: signal_str(event.signal).to_owned(),
        name: event.name.as_str().to_owned(),
        attributes: event
            .attributes
            .iter()
            .map(|(key, value)| (key.as_str().to_owned(), to_proto_attr(value)))
            .collect(),
        payload_ref: event.payload_ref.as_ref().map(to_proto_payload),
        event_id: event.event_id.to_string(),
        lineage_path: event.lineage_path.to_string(),
    }
}

fn to_proto_attr(value: &AttributeValue) -> proto::AttributeValue {
    use proto::attribute_value::Value;
    let inner = match value {
        AttributeValue::String(s) => Value::StringValue(s.clone()),
        AttributeValue::I64(i) => Value::IntValue(*i),
        AttributeValue::F64(f) => Value::DoubleValue(f.as_f64()),
        AttributeValue::Bool(b) => Value::BoolValue(*b),
    };
    proto::AttributeValue { value: Some(inner) }
}

fn to_proto_payload(payload: &PayloadRef) -> proto::PayloadRef {
    proto::PayloadRef {
        digest: payload.digest.to_string(),
        media_type: payload.media_type.as_ref().map(ToString::to_string),
        size_bytes: payload.size_bytes,
    }
}

const fn signal_str(signal: SignalType) -> &'static str {
    match signal {
        SignalType::Span => "span",
        SignalType::Log => "log",
        SignalType::Metric => "metric",
        SignalType::Net => "net",
        SignalType::Exec => "exec",
        SignalType::Llm => "llm",
        SignalType::Annotation => "annotation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::event::{AttributeKey, EventName, FiniteF64, MediaType, PayloadDigest};
    use hiloop_core::identity::{EventId, Hlc, LineagePath, RunContext, RunId};
    use std::str::FromStr;

    /// Golden fixture: a `hiloop_core::Event` with EVERY field populated to a distinct,
    /// deterministic, non-default value — including each `AttributeValue` variant and a fully
    /// populated `PayloadRef`. The companion test asserts the proto `Event` mirrors every field,
    /// so adding a field to either side without wiring the conversion fails the build. The
    /// `PayloadRef` carries `digest`, `media_type`, and `size_bytes` so all three wire fields are
    /// exercised.
    fn golden_event() -> Event {
        let root_run_id = RunId::from_str("00000000000000000000000001").expect("root run ulid");
        let run_id = RunId::from_str("00000000000000000000000002").expect("run ulid");
        let event_id = EventId::from_str("00000000000000000000000003").expect("event ulid");
        let lineage_path = LineagePath::root(root_run_id)
            .child(run_id)
            .expect("lineage path");

        let mut event = Event::new(
            &RunContext::new(run_id, lineage_path).expect("run context"),
            Hlc {
                wall_ns: 1_700_000_000_000_000_000,
                logical: 11,
            },
            SignalType::Llm,
            EventName::new("gen_ai.request").expect("name"),
        )
        .with_attribute(AttributeKey::new("model").expect("key"), "claude-opus")
        .with_attribute(AttributeKey::new("input_tokens").expect("key"), 128_i64)
        .with_attribute(
            AttributeKey::new("temperature").expect("key"),
            FiniteF64::new(0.5).expect("finite"),
        )
        .with_attribute(AttributeKey::new("stream").expect("key"), true)
        .with_payload_ref(
            PayloadRef::new(PayloadDigest::new("blake3:deadbeef").expect("digest"))
                .with_media_type(MediaType::new("application/json").expect("media type"))
                .with_size_bytes(4096),
        );
        // The minted event_id is overwritten with a fixed value so the fixture is fully golden.
        event.event_id = event_id;
        event
    }

    #[test]
    fn golden_fixture_maps_every_field_to_proto() {
        use proto::attribute_value::Value;

        let event = golden_event();
        let proto = to_proto_event(&event);

        // Spine identity.
        assert_eq!(proto.event_id, "00000000000000000000000003");
        assert_eq!(proto.run_id, "00000000000000000000000002");
        assert_eq!(
            proto.lineage_path,
            "00000000000000000000000001.00000000000000000000000002"
        );

        // Timestamp.
        assert_eq!(
            proto.ts,
            Some(proto::Hlc {
                wall_ns: 1_700_000_000_000_000_000,
                logical: 11,
            })
        );

        // Signal + name.
        assert_eq!(proto.signal, "llm");
        assert_eq!(proto.name, "gen_ai.request");

        // Every AttributeValue variant, one per key.
        assert_eq!(proto.attributes.len(), 4);
        assert_eq!(
            proto.attributes["model"].value,
            Some(Value::StringValue("claude-opus".to_owned()))
        );
        assert_eq!(
            proto.attributes["input_tokens"].value,
            Some(Value::IntValue(128))
        );
        assert_eq!(
            proto.attributes["temperature"].value,
            Some(Value::DoubleValue(0.5))
        );
        assert_eq!(
            proto.attributes["stream"].value,
            Some(Value::BoolValue(true))
        );

        // Fully populated payload reference (all three fields set).
        let payload = proto.payload_ref.as_ref().expect("payload ref");
        assert_eq!(payload.digest, "blake3:deadbeef");
        assert_eq!(payload.media_type.as_deref(), Some("application/json"));
        assert_eq!(payload.size_bytes, Some(4096));

        // Lockstep guard: a field added to either `proto::Event` or `hiloop_core::Event` without
        // updating the conversion makes this exhaustive reconstruction fail to compile, surfacing
        // the drift. `..` is deliberately NOT used.
        let expected = proto::Event {
            ts: proto.ts,
            run_id: proto.run_id.clone(),
            signal: proto.signal.clone(),
            name: proto.name.clone(),
            attributes: proto.attributes.clone(),
            payload_ref: proto.payload_ref.clone(),
            event_id: proto.event_id.clone(),
            lineage_path: proto.lineage_path.clone(),
        };
        let Event {
            event_id: _,
            ts: _,
            run_id: _,
            lineage_path: _,
            signal: _,
            name: _,
            attributes: _,
            payload_ref: _,
        } = event;
        assert_eq!(proto, expected);
    }

    fn sample_event() -> Event {
        Event::new(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 42,
                logical: 7,
            },
            SignalType::Llm,
            EventName::new("gen_ai.request").expect("name"),
        )
        .with_attribute(AttributeKey::new("model").expect("key"), "claude-opus")
        .with_attribute(AttributeKey::new("input_tokens").expect("key"), 128_i64)
        .with_attribute(
            AttributeKey::new("temperature").expect("key"),
            FiniteF64::new(0.5).expect("finite"),
        )
        .with_attribute(AttributeKey::new("stream").expect("key"), true)
    }

    #[test]
    fn converts_every_field_one_to_one() {
        use proto::attribute_value::Value;

        let event = sample_event();
        let proto = to_proto_event(&event);

        assert_eq!(proto.event_id, event.event_id.to_string());
        assert!(!proto.event_id.is_empty());
        assert_eq!(proto.run_id, event.run_id.to_string());
        assert_eq!(proto.lineage_path, event.lineage_path.to_string());
        assert_eq!(proto.signal, "llm");
        assert_eq!(proto.name, "gen_ai.request");
        assert_eq!(
            proto.ts,
            Some(proto::Hlc {
                wall_ns: 42,
                logical: 7
            })
        );

        assert_eq!(
            proto.attributes["model"].value,
            Some(Value::StringValue("claude-opus".to_owned()))
        );
        assert_eq!(
            proto.attributes["input_tokens"].value,
            Some(Value::IntValue(128))
        );
        assert_eq!(
            proto.attributes["temperature"].value,
            Some(Value::DoubleValue(0.5))
        );
        assert_eq!(
            proto.attributes["stream"].value,
            Some(Value::BoolValue(true))
        );
    }

    #[test]
    fn maps_payload_ref_and_signals() {
        assert_eq!(signal_str(SignalType::Span), "span");
        assert_eq!(signal_str(SignalType::Net), "net");
        assert_eq!(signal_str(SignalType::Annotation), "annotation");

        let event = sample_event().with_payload_ref(
            PayloadRef::new(PayloadDigest::new("blake3:abc").expect("digest")).with_size_bytes(9),
        );
        let proto = to_proto_event(&event);
        let payload = proto.payload_ref.expect("payload ref");
        assert_eq!(payload.digest, "blake3:abc");
        assert_eq!(payload.size_bytes, Some(9));
        assert_eq!(payload.media_type, None);
    }

    #[test]
    fn ingest_rejection_prefixes_the_folded_status() {
        let status = Status::unavailable("gateway draining");
        assert_eq!(
            ingest_rejection_message(&status),
            "ingest rejected: gateway draining"
        );
    }

    /// One classification-matrix row: a status code and the variant check it must satisfy.
    type ClassificationCase = (tonic::Code, fn(&ExportError) -> bool);

    /// The classification matrix: each `tonic::Code` lands in the retry-taxonomy
    /// variant the spooling wrapper dispatches on.
    #[test]
    fn ingest_error_classifies_status_codes() {
        use tonic::Code;

        let cases: &[ClassificationCase] = &[
            (Code::ResourceExhausted, |e| {
                matches!(e, ExportError::Backpressure { .. })
            }),
            (Code::Unavailable, |e| {
                matches!(e, ExportError::Unavailable { .. })
            }),
            (Code::InvalidArgument, |e| {
                matches!(e, ExportError::Rejected { .. })
            }),
            (Code::PermissionDenied, |e| {
                matches!(e, ExportError::Rejected { .. })
            }),
            (Code::Unauthenticated, |e| {
                matches!(e, ExportError::Rejected { .. })
            }),
            (Code::Internal, |e| matches!(e, ExportError::Other { .. })),
            (Code::Unknown, |e| matches!(e, ExportError::Other { .. })),
            (Code::DeadlineExceeded, |e| {
                matches!(e, ExportError::Other { .. })
            }),
        ];
        for (code, expected) in cases {
            let error = ingest_error(&Status::new(*code, "boom"));
            assert!(expected(&error), "code {code:?} classified as {error:?}");
        }
    }

    /// Regression test for the unbounded teardown stall: a gateway that accepts the TCP
    /// connection but never completes the HTTP/2 handshake (a black-holed/hung endpoint) must
    /// fail the export within the deadline as a transient `Unavailable` — never hang the
    /// caller's drain.
    #[tokio::test]
    async fn export_times_out_against_a_stalling_gateway() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Keep the listener alive so connects succeed, but never accept/answer: the
        // OS-level backlog holds the connection open and the h2 handshake stalls.
        let exporter = GrpcIngestExporter::connect(format!("http://{addr}"), None, "proj", true)
            .expect("exporter");

        let started = std::time::Instant::now();
        let error = exporter
            .ingest_within(&[sample_event()], std::time::Duration::from_millis(200))
            .await
            .expect_err("stalling gateway must time out");

        assert!(
            matches!(error, ExportError::Unavailable { .. }),
            "timeout classified as {error:?}"
        );
        assert!(
            error.to_string().contains("timed out"),
            "timeout attributed: {error}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "export returned within the deadline, not the kernel's"
        );
        drop(listener);
    }

    #[tokio::test]
    async fn ingest_error_treats_a_transport_sourced_status_as_unavailable() {
        // tonic stamps most client-side transport failures UNAVAILABLE, but some hops
        // surface as UNKNOWN with the transport error attached as source. Mint a real
        // transport error by connecting to a port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let transport_error = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect_err("nothing listens on the dropped port");

        let mut status = Status::new(tonic::Code::Unknown, "transport error");
        status.set_source(std::sync::Arc::new(transport_error));

        let error = ingest_error(&status);
        assert!(
            matches!(error, ExportError::Unavailable { .. }),
            "transport-sourced status classified as {error:?}"
        );
    }
}
