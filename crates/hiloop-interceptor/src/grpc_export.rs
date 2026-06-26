//! gRPC exporter to the hiloop telemetry-gateway `Ingest` service (HIL-82).
//!
//! Sends normalized [`Event`]s to a hiloop telemetry gateway over gRPC/TLS, authenticated with a
//! Bearer API token (`hil_…`). The gateway derives the tenant from the token and stamps it on every
//! event (mesh-trust), so the client only supplies the `project_id`. Pairs with the local
//! [`crate::exporters::JsonlExporter`] via [`crate::exporters::FanoutExporter`]: a single wrap can
//! both keep a local JSONL trail and stream to the gateway.

use crate::seams::{ExportError, Exporter};
use async_trait::async_trait;
use hiloop_core::event::{AttributeValue, Event, SignalType};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig};

/// Generated `hiloop.telemetry.v1` client + messages (build.rs / tonic-prost-build).
pub mod proto {
    #![allow(clippy::doc_markdown, clippy::pedantic, clippy::nursery, missing_docs)]
    tonic::include_proto!("hiloop.telemetry.v1");
}

use proto::telemetry_ingest_service_client::TelemetryIngestServiceClient;

const SURFACE: &str = "grpc";

/// Exports events to a telemetry gateway's `TelemetryIngestService/Ingest`.
pub struct GrpcExporter {
    client: Mutex<TelemetryIngestServiceClient<Channel>>,
    project_id: String,
    bearer: MetadataValue<Ascii>,
}

impl GrpcExporter {
    /// Connects (lazily) to `endpoint` (e.g. `https://telemetry.example.com:443`; a bare host:port is
    /// upgraded to `https://`). `token` is the `hil_…` API key sent as `authorization: Bearer …`;
    /// `project_id` tags every ingested event (the tenant is derived from the token by the gateway).
    ///
    /// # Errors
    /// Fails if the endpoint URI or the Bearer header value is invalid, or TLS can't be configured.
    pub fn connect(endpoint: &str, token: &str, project_id: String) -> Result<Self, ExportError> {
        let uri = if endpoint.contains("://") {
            endpoint.to_owned()
        } else {
            format!("https://{endpoint}")
        };
        let channel = Channel::from_shared(uri)
            .map_err(|error| config_error("invalid telemetry endpoint URI", error))?
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .map_err(|error| config_error("failed to configure TLS for telemetry endpoint", error))?
            .connect_lazy();
        let bearer = format!("Bearer {token}")
            .parse::<MetadataValue<Ascii>>()
            .map_err(|error| config_error("invalid telemetry token (non-ASCII bearer)", error))?;
        Ok(Self {
            client: Mutex::new(TelemetryIngestServiceClient::new(channel)),
            project_id,
            bearer,
        })
    }
}

#[async_trait]
impl Exporter for GrpcExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        if events.is_empty() {
            return Ok(());
        }
        let mut request = tonic::Request::new(proto::IngestRequest {
            events: events.iter().map(to_proto_event).collect(),
            tenant_id: String::new(), // gateway assigns the tenant from the authenticated token
            project_id: self.project_id.clone(),
        });
        request
            .metadata_mut()
            .insert("authorization", self.bearer.clone());
        self.client
            .lock()
            .await
            .ingest(request)
            .await
            .map_err(|status| {
                ExportError::with_source(SURFACE, "telemetry ingest failed", status)
            })?;
        Ok(())
    }
}

fn config_error(
    message: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> ExportError {
    ExportError::with_source(SURFACE, message, error)
}

/// The wire `signal` string for a [`SignalType`] — matches the gateway's stored value and the
/// `hiloop-core` serde representation (`snake_case`).
fn signal_str(signal: SignalType) -> &'static str {
    match signal {
        SignalType::Span => "span",
        SignalType::Log => "log",
        SignalType::Metric => "metric",
        SignalType::Net => "net",
        SignalType::Exec => "exec",
        SignalType::Llm => "llm",
    }
}

fn to_proto_attr(value: &AttributeValue) -> proto::AttributeValue {
    use proto::attribute_value::Value;
    let value = match value {
        AttributeValue::String(s) => Value::StringValue(s.clone()),
        AttributeValue::I64(i) => Value::IntValue(*i),
        AttributeValue::F64(f) => Value::DoubleValue(f.as_f64()),
        AttributeValue::Bool(b) => Value::BoolValue(*b),
    };
    proto::AttributeValue { value: Some(value) }
}

/// Maps a normalized [`Event`] to the gateway wire `Event`. `event_id` is left empty — the
/// interceptor does not yet mint stable ids, so the gateway derives a deterministic blake3 fallback.
pub(crate) fn to_proto_event(event: &Event) -> proto::Event {
    let attributes: HashMap<String, proto::AttributeValue> = event
        .attributes
        .iter()
        .map(|(key, value)| (key.as_str().to_owned(), to_proto_attr(value)))
        .collect();
    proto::Event {
        ts: Some(proto::Hlc {
            wall_ns: event.ts.wall_ns,
            logical: event.ts.logical,
        }),
        run_id: event.run_id.to_string(),
        fork_node_id: event.fork_node_id.to_string(),
        fork_path: event.fork_path.to_string(),
        signal: signal_str(event.signal).to_owned(),
        name: event.name.as_str().to_owned(),
        attributes,
        payload_ref: event.payload_ref.as_ref().map(|payload| proto::PayloadRef {
            digest: payload.digest.as_str().to_owned(),
            media_type: payload.media_type.as_ref().map(|m| m.as_str().to_owned()),
            size_bytes: payload.size_bytes,
        }),
        event_id: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::event::{AttributeKey, EventName, MediaType, PayloadDigest, PayloadRef};
    use hiloop_core::identity::ForkContext;

    fn event_with(signal: SignalType, name: &str) -> Event {
        Event::new(
            &ForkContext::new_local_root(),
            hiloop_core::identity::Hlc {
                wall_ns: 42,
                logical: 7,
            },
            signal,
            EventName::new(name).expect("event name"),
        )
    }

    #[test]
    fn maps_signal_attrs_and_payload_ref() {
        let event = event_with(SignalType::Llm, "http.request")
            .with_attribute(
                AttributeKey::from_static("http.host"),
                AttributeValue::from("api.anthropic.com"),
            )
            .with_attribute(
                AttributeKey::from_static("http.size"),
                AttributeValue::from(467_i64),
            )
            .with_payload_ref(
                PayloadRef::new(PayloadDigest::new("blake3:abc").expect("digest"))
                    .with_media_type(MediaType::new("application/json").expect("media"))
                    .with_size_bytes(467),
            );

        let proto = to_proto_event(&event);

        assert_eq!(proto.signal, "llm");
        assert_eq!(proto.name, "http.request");
        assert_eq!(
            proto.ts,
            Some(proto::Hlc {
                wall_ns: 42,
                logical: 7
            })
        );
        assert!(
            proto.event_id.is_empty(),
            "interceptor does not mint event ids yet"
        );
        let host = proto
            .attributes
            .get("http.host")
            .and_then(|a| a.value.clone());
        assert_eq!(
            host,
            Some(proto::attribute_value::Value::StringValue(
                "api.anthropic.com".to_owned()
            ))
        );
        let size = proto
            .attributes
            .get("http.size")
            .and_then(|a| a.value.clone());
        assert_eq!(size, Some(proto::attribute_value::Value::IntValue(467)));
        let payload = proto.payload_ref.expect("payload ref mapped");
        assert_eq!(payload.digest, "blake3:abc");
        assert_eq!(payload.media_type.as_deref(), Some("application/json"));
        assert_eq!(payload.size_bytes, Some(467));
    }

    #[test]
    fn every_signal_has_a_wire_string() {
        for signal in [
            SignalType::Span,
            SignalType::Log,
            SignalType::Metric,
            SignalType::Net,
            SignalType::Exec,
            SignalType::Llm,
        ] {
            assert!(!signal_str(signal).is_empty());
        }
    }
}
