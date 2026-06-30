//! Native gRPC exporter: streams normalized events to a hiloop telemetry gateway's
//! `TelemetryIngestService` over tonic. An authenticated gateway derives the tenant from the
//! request's Bearer token, so the client omits `tenant_id` (`None`) there; `project_id` selects the
//! project to record under. Against an unauthenticated local gateway, set `tenant_id` explicitly.

use crate::seams::{ExportError, Exporter};
use async_trait::async_trait;
use hiloop_core::event::{AttributeValue, Event, PayloadRef, SignalType};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::{Request, Status};

/// Generated `hiloop.telemetry.v1` stubs (vendored proto, see `build.rs`).
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::allow_attributes_without_reason,
    reason = "tonic-prost-build generated code is not ours to lint (incl. its own bare #[allow]s)"
)]
pub mod proto {
    tonic::include_proto!("hiloop.telemetry.v1");
}

use proto::telemetry_ingest_service_client::TelemetryIngestServiceClient;

/// Env var holding the API key. Sourced from the environment only — never a CLI argument, so it
/// stays out of process provenance (`process.argv`).
pub const TOKEN_ENV: &str = "HILOOP_API_KEY";

/// Attaches `authorization: Bearer <token>` to every request when a token is configured.
#[derive(Clone)]
struct AuthInterceptor {
    bearer: Option<MetadataValue<Ascii>>,
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(bearer) = &self.bearer {
            request
                .metadata_mut()
                .insert("authorization", bearer.clone());
        }
        Ok(request)
    }
}

type AuthedClient = TelemetryIngestServiceClient<InterceptedService<Channel, AuthInterceptor>>;

/// Ships events to the telemetry gateway over gRPC.
pub struct GrpcIngestExporter {
    client: AuthedClient,
    tenant_id: Option<String>,
    project_id: String,
}

impl GrpcIngestExporter {
    /// Build a lazily-connected exporter for `endpoint` (e.g.
    /// `https://telemetry.example.com:443`). The channel connects on first export, not here,
    /// so a gateway that is briefly unreachable at startup doesn't abort the run (and any local
    /// JSONL sink keeps capturing). TLS (native trust roots) is used unless `insecure` is set (h2c,
    /// local dev only). The Bearer token is read from `HILOOP_API_KEY`; absent/empty means no auth
    /// header (an unauthenticated dev gateway). Pass `None` for `tenant_id` against an authenticated
    /// gateway (it derives the tenant from the token); pass `Some(tenant)` only against a no-auth
    /// local gateway. `project_id` selects the project.
    pub fn connect(
        endpoint: impl Into<String>,
        tenant_id: Option<String>,
        project_id: impl Into<String>,
        insecure: bool,
    ) -> Result<Self, ExportError> {
        let endpoint = endpoint.into();
        let mut builder = Channel::from_shared(endpoint.clone()).map_err(|e| {
            ExportError::with_source("grpc", format!("invalid endpoint `{endpoint}`"), e)
        })?;
        if !insecure {
            builder = builder
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|e| ExportError::with_source("grpc", "TLS configuration failed", e))?;
        }
        let channel = builder.connect_lazy();

        let bearer = match std::env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty()) {
            Some(token) => Some(
                format!("Bearer {token}")
                    .parse()
                    .map_err(|e| ExportError::with_source("grpc", "invalid API token", e))?,
            ),
            None => None,
        };
        let client =
            TelemetryIngestServiceClient::with_interceptor(channel, AuthInterceptor { bearer });
        Ok(Self {
            client,
            tenant_id,
            project_id: project_id.into(),
        })
    }
}

#[async_trait]
impl Exporter for GrpcIngestExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        if events.is_empty() {
            return Ok(());
        }
        let proto_events: Vec<proto::Event> = events.iter().map(to_proto_event).collect();
        let expected = u64::try_from(proto_events.len()).unwrap_or(u64::MAX);
        let mut client = self.client.clone();
        let accepted = client
            .ingest(Request::new(proto::IngestRequest {
                events: proto_events,
                // proto3 has no optional scalar here: the empty string is the wire form of
                // "absent", which is exactly what an authenticated gateway expects (it derives
                // the tenant from the Bearer token).
                tenant_id: self.tenant_id.clone().unwrap_or_default(),
                project_id: self.project_id.clone(),
            }))
            .await
            .map_err(|status| {
                ExportError::with_source(
                    "grpc",
                    format!("ingest rejected: {}", status.message()),
                    status,
                )
            })?
            .into_inner()
            .accepted;
        if accepted != expected {
            return Err(ExportError::other(
                "grpc",
                format!("gateway accepted {accepted} of {expected} events"),
            ));
        }
        Ok(())
    }
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
    fn auth_interceptor_attaches_bearer_when_token_present() {
        use tonic::service::Interceptor as _;

        let mut with_token = AuthInterceptor {
            bearer: Some("Bearer hil_secret".parse().expect("metadata value")),
        };
        let request = with_token.call(Request::new(())).expect("intercept");
        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .map(|v| v.to_str().expect("ascii")),
            Some("Bearer hil_secret")
        );
    }

    #[test]
    fn auth_interceptor_omits_header_when_no_token() {
        use tonic::service::Interceptor as _;

        let mut no_token = AuthInterceptor { bearer: None };
        let request = no_token.call(Request::new(())).expect("intercept");
        assert!(request.metadata().get("authorization").is_none());
    }
}
