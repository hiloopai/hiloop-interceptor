//! OTLP receiver capture surface.
//!
//! The wrapper runs an embedded OTLP/HTTP receiver and injects
//! `OTEL_EXPORTER_OTLP_ENDPOINT` into the child, so the harness's own
//! OpenTelemetry export is captured and fork-stamped. Each trace export arrives
//! as one raw `traces` signal; [`OtlpTraceNormalizer`] decodes it into
//! fork-stamped events, with LLM spans (`gen_ai.*` / `llm.*` attributes) mapped
//! to [`SignalType::Llm`].
//!
//! Transport is OTLP/HTTP `http/protobuf`, not gRPC, to keep the shipped binary
//! lean — the wrapper controls the child env and forces that protocol. See
//! `docs/CAPTURE.md` for the dependency rationale.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prost::Message as _;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use hiloop_core::event::{AttributeKey, AttributeValue, Event, EventName, FiniteF64, SignalType};
use hiloop_core::identity::{Hlc, HlcClock};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::Span;

use crate::seams::{
    NormalizationContext, NormalizationOutcome, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerSupport, RawSignal, SourceError,
};

const OTLP_SOURCE: &str = "otlp";
const OTLP_TRACES_KIND: &str = "traces";
const TRACES_PATH: &str = "/v1/traces";
const MAX_OTLP_BODY_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
const DESCRIPTOR: NormalizerDescriptor =
    NormalizerDescriptor::new("otlp-trace", env!("CARGO_PKG_VERSION"), "hiloop.event.v1");

/// Embedded OTLP/HTTP receiver bound to an ephemeral localhost port.
pub struct OtlpReceiver {
    listener: TcpListener,
    clock: Arc<HlcClock>,
}

impl OtlpReceiver {
    /// Bind the receiver on `127.0.0.1:0`.
    pub async fn bind(clock: Arc<HlcClock>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        Ok(Self { listener, clock })
    }

    /// The bound address. Inject `OTEL_EXPORTER_OTLP_ENDPOINT=http://{addr}`.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept and serve OTLP exports until `shutdown` resolves.
    ///
    /// Each accepted export is forwarded as one raw `traces` signal on
    /// `signal_tx`; [`OtlpTraceNormalizer`] turns it into events downstream.
    /// In-flight connections after `shutdown` are dropped, not drained.
    pub async fn serve<S>(
        self,
        signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
        shutdown: S,
    ) where
        S: std::future::Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _peer) = match accepted {
                        Ok(conn) => conn,
                        Err(error) => {
                            eprintln!("hiloop-interceptor: OTLP receiver accept error: {error}");
                            continue;
                        }
                    };
                    let io = TokioIo::new(stream);
                    let signal_tx = signal_tx.clone();
                    let clock = Arc::clone(&self.clock);
                    tokio::spawn(async move {
                        let service = service_fn(move |request| {
                            handle_request(request, signal_tx.clone(), Arc::clone(&clock))
                        });
                        if let Err(error) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                        {
                            // Connection-level errors (client disconnect, malformed
                            // HTTP) are expected under normal operation and not
                            // fatal; log for diagnostics.
                            eprintln!("hiloop-interceptor: OTLP connection error: {error}");
                        }
                    });
                }
            }
        }
    }
}

async fn handle_request(
    request: Request<Incoming>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != Method::POST || request.uri().path() != TRACES_PATH {
        return Ok(empty_response(StatusCode::NOT_FOUND));
    }

    let body = match Limited::new(request.into_body(), MAX_OTLP_BODY_BYTES as usize)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            // A body exceeding the cap surfaces as `LengthLimitError`; report it
            // as 413 so the caller can distinguish it from a malformed request.
            if error.downcast_ref::<LengthLimitError>().is_some() {
                return Ok(empty_response(StatusCode::PAYLOAD_TOO_LARGE));
            }
            eprintln!("hiloop-interceptor: OTLP body read error: {error}");
            return Ok(empty_response(StatusCode::BAD_REQUEST));
        }
    };

    let raw = RawSignal::new(OTLP_SOURCE, OTLP_TRACES_KIND, clock.tick(), body)
        .with_attribute("otlp.path", TRACES_PATH);
    if signal_tx.send(Ok(raw)).await.is_err() {
        // The pipeline has gone away; the wrapper is shutting down.
        return Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE));
    }

    Ok(protobuf_response(
        ExportTraceServiceResponse::default().encode_to_vec(),
    ))
}

fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .expect("static empty response is valid")
}

fn protobuf_response(body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/x-protobuf")
        .body(Full::new(Bytes::from(body)))
        .expect("static protobuf response is valid")
}

/// Decodes OTLP trace exports into fork-stamped events.
#[derive(Debug, Default, Clone, Copy)]
pub struct OtlpTraceNormalizer;

#[async_trait]
impl Normalizer for OtlpTraceNormalizer {
    fn descriptor(&self) -> NormalizerDescriptor {
        DESCRIPTOR
    }

    fn supports(&self, raw: &RawSignal) -> NormalizerSupport {
        if raw.source == OTLP_SOURCE && raw.kind == OTLP_TRACES_KIND {
            NormalizerSupport::Exact
        } else {
            NormalizerSupport::Unsupported
        }
    }

    async fn normalize(
        &self,
        context: &NormalizationContext,
        raw: RawSignal,
    ) -> Result<NormalizationOutcome, NormalizeError> {
        let request = ExportTraceServiceRequest::decode(raw.body.as_ref()).map_err(|error| {
            NormalizeError::Decode {
                source_name: raw.source.clone(),
                kind: raw.kind.clone(),
                message: error.to_string(),
            }
        })?;

        let mut events = Vec::new();
        for resource_spans in &request.resource_spans {
            for scope_spans in &resource_spans.scope_spans {
                for span in &scope_spans.spans {
                    events.push(span_to_event(context, span)?);
                }
            }
        }

        Ok(NormalizationOutcome::from_events(events))
    }
}

fn span_to_event(context: &NormalizationContext, span: &Span) -> Result<Event, NormalizeError> {
    let signal = if span_is_llm(span) {
        SignalType::Llm
    } else {
        SignalType::Span
    };
    let name = EventName::new(span_name(span)).map_err(|error| NormalizeError::InvalidOutput {
        normalizer: DESCRIPTOR.name(),
        message: error.to_string(),
    })?;
    let ts = Hlc {
        wall_ns: span.start_time_unix_nano,
        logical: 0,
    };

    let mut event = Event::new(context.fork_context(), ts, signal, name);
    if !span.trace_id.is_empty() {
        event = event.with_attribute(
            AttributeKey::from_static("otel.trace_id"),
            hex(&span.trace_id),
        );
    }
    if !span.span_id.is_empty() {
        event = event.with_attribute(
            AttributeKey::from_static("otel.span_id"),
            hex(&span.span_id),
        );
    }
    if !span.parent_span_id.is_empty() {
        event = event.with_attribute(
            AttributeKey::from_static("otel.parent_span_id"),
            hex(&span.parent_span_id),
        );
    }

    for attribute in &span.attributes {
        let Ok(key) = AttributeKey::new(attribute.key.as_str()) else {
            continue;
        };
        if let Some(value) = attribute.value.as_ref().and_then(convert_any_value) {
            event = event.with_attribute(key, value);
        }
    }

    Ok(event)
}

fn span_name(span: &Span) -> &str {
    if span.name.trim().is_empty() {
        "otel.span"
    } else {
        span.name.as_str()
    }
}

fn span_is_llm(span: &Span) -> bool {
    span.attributes
        .iter()
        .any(|attribute| attribute.key.starts_with("gen_ai.") || attribute.key.starts_with("llm."))
}

/// Map an OTLP attribute value into the narrow scalar attribute set.
///
fn convert_any_value(value: &AnyValue) -> Option<AttributeValue> {
    // Wire enum designed to grow: map the scalars we model, drop the rest (bytes,
    // nested array/map, profiling strindex). The `_` is intentional — the OTLP spec
    // says receivers tolerate unknown value kinds.
    match value.value.as_ref()? {
        any_value::Value::StringValue(string) => Some(AttributeValue::String(string.clone())),
        any_value::Value::IntValue(int) => Some(AttributeValue::I64(*int)),
        any_value::Value::DoubleValue(double) => {
            FiniteF64::new(*double).ok().map(AttributeValue::F64)
        }
        any_value::Value::BoolValue(boolean) => Some(AttributeValue::Bool(*boolean)),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::identity::ForkContext;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn string_value(value: &str) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::StringValue(value.to_owned())),
        }
    }

    fn int_value(value: i64) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::IntValue(value)),
        }
    }

    fn span(name: &str, start: u64, attributes: Vec<(&str, AnyValue)>) -> Span {
        Span {
            name: name.to_owned(),
            start_time_unix_nano: start,
            trace_id: vec![0xab; 16],
            span_id: vec![0xcd; 8],
            attributes: attributes
                .into_iter()
                .map(|(key, value)| KeyValue {
                    key: key.to_owned(),
                    value: Some(value),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn request(spans: Vec<Span>) -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
    }

    #[tokio::test]
    async fn normalizes_spans_and_flags_llm_spans() {
        let body = request(vec![
            span(
                "chat completions",
                100,
                vec![
                    ("gen_ai.system", string_value("anthropic")),
                    ("gen_ai.usage.output_tokens", int_value(42)),
                ],
            ),
            span("db.query", 200, vec![("db.system", string_value("sqlite"))]),
        ])
        .encode_to_vec();
        let raw = RawSignal::new(
            OTLP_SOURCE,
            OTLP_TRACES_KIND,
            Hlc {
                wall_ns: 0,
                logical: 0,
            },
            body,
        );
        let context = NormalizationContext::new(ForkContext::new_local_root());

        let outcome = OtlpTraceNormalizer
            .normalize(&context, raw)
            .await
            .expect("normalize");
        let events = outcome.into_events();

        assert_eq!(events.len(), 2);

        let llm = &events[0];
        assert_eq!(llm.signal, SignalType::Llm);
        assert_eq!(llm.name.as_str(), "chat completions");
        assert_eq!(llm.ts.wall_ns, 100);
        assert_eq!(
            llm.attributes
                .get(&AttributeKey::new("gen_ai.system").expect("key")),
            Some(&AttributeValue::String("anthropic".to_owned()))
        );
        assert_eq!(
            llm.attributes
                .get(&AttributeKey::new("gen_ai.usage.output_tokens").expect("key")),
            Some(&AttributeValue::I64(42))
        );
        assert_eq!(
            llm.attributes
                .get(&AttributeKey::new("otel.trace_id").expect("key")),
            Some(&AttributeValue::String(
                "abababababababababababababababab".to_owned()
            ))
        );

        assert_eq!(events[1].signal, SignalType::Span);
        assert_eq!(events[1].name.as_str(), "db.query");
    }

    #[tokio::test]
    async fn rejects_unsupported_signals() {
        let normalizer = OtlpTraceNormalizer;
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 0,
                logical: 0,
            },
            Bytes::from_static(b"x"),
        );
        assert_eq!(normalizer.supports(&raw), NormalizerSupport::Unsupported);
    }

    #[tokio::test]
    async fn receiver_forwards_posted_traces_as_raw_signals() {
        let clock = Arc::new(HlcClock::new());
        let receiver = OtlpReceiver::bind(Arc::clone(&clock)).await.expect("bind");
        let addr = receiver.local_addr().expect("addr");
        let (tx, mut rx) = mpsc::channel(4);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(receiver.serve(tx, async move {
            let _ = shutdown_rx.await;
        }));

        let body = request(vec![span("op", 1, vec![])]).encode_to_vec();
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let head = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.expect("write head");
        stream.write_all(&body).await.expect("write body");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "unexpected response: {}",
            String::from_utf8_lossy(&response)
        );

        let signal = rx.recv().await.expect("signal").expect("raw signal");
        assert_eq!(signal.source, OTLP_SOURCE);
        assert_eq!(signal.kind, OTLP_TRACES_KIND);
        assert_eq!(signal.body.as_ref(), body.as_slice());

        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn rejects_body_exceeding_cap_with_413() {
        let clock = Arc::new(HlcClock::new());
        let receiver = OtlpReceiver::bind(Arc::clone(&clock)).await.expect("bind");
        let addr = receiver.local_addr().expect("addr");
        let (tx, mut rx) = mpsc::channel(4);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(receiver.serve(tx, async move {
            let _ = shutdown_rx.await;
        }));

        // One byte past the cap is enough to trip `Limited`.
        let oversize = MAX_OTLP_BODY_BYTES as usize + 1;
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let head = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {oversize}\r\nConnection: close\r\n\r\n",
        );
        stream.write_all(head.as_bytes()).await.expect("write head");
        // Stream the oversize body in chunks of arbitrary bytes; the receiver
        // must cut us off and answer 413 before draining the whole thing.
        let chunk = vec![0u8; 64 * 1024];
        let mut sent = 0usize;
        while sent < oversize {
            let remaining = oversize - sent;
            let n = remaining.min(chunk.len());
            // A short write here means the peer closed after responding — the
            // body cap is doing its job, so treat it as success.
            if stream.write_all(&chunk[..n]).await.is_err() {
                break;
            }
            sent += n;
        }

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 413"),
            "expected 413 Payload Too Large, got: {}",
            String::from_utf8_lossy(&response)
        );

        // No raw signal must be forwarded for a rejected oversize body.
        assert!(
            rx.try_recv().is_err(),
            "oversize body must not produce a raw signal"
        );

        let _ = shutdown_tx.send(());
        let _ = server.await;
    }
}
