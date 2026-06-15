//! MITM proxy capture surface.
//!
//! The wrapper runs a TLS-intercepting proxy ([`hudsucker`]) on an ephemeral
//! localhost port and injects `HTTPS_PROXY` plus a child-scoped CA bundle so the
//! harness's HTTPS traffic is decrypted, captured, and fork-stamped regardless
//! of whether the harness cooperates. Each request and response becomes one raw
//! signal; [`ProxyNormalizer`] turns it into a `net` event (or `llm` for known
//! LLM API hosts), and full bodies are offloaded to the bronze raw store via the
//! preserve-retention path. See `docs/CAPTURE.md`.
//!
//! Response bodies are forwarded as a streaming tee: each frame is passed
//! downstream the moment it arrives (so SSE/chunked responses are not blocked on
//! full-body buffering) while a capture copy accumulates in memory; the
//! `RawSignal` is emitted when the body stream ends. Request bodies are buffered
//! eagerly so a request signal is recorded even when the upstream never consumes
//! the body. Request and response events are linked by an `http.exchange_id`
//! attribute — see the `CaptureHandler` docs for the correlation mechanism and
//! its reliability limits.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::header::{CONTENT_TYPE, HOST};
use hudsucker::hyper::{Method, Request, Response};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use hiloop_core::event::{AttributeKey, Event, EventName, SignalType};
use hiloop_core::identity::HlcClock;
use thiserror::Error;

use crate::seams::{
    NormalizationContext, NormalizationOutcome, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerSupport, RawRetentionPolicy, RawSignal, SourceError,
};

const PROXY_SOURCE: &str = "proxy";
const REQUEST_KIND: &str = "http.request";
const RESPONSE_KIND: &str = "http.response";
const EXCHANGE_ID_ATTR: &str = "http.exchange_id";
const CA_CACHE_SIZE: u64 = 1_000;
const DESCRIPTOR: NormalizerDescriptor =
    NormalizerDescriptor::new("proxy-http", env!("CARGO_PKG_VERSION"), "hiloop.event.v1");

/// Process-global monotonic source of exchange ids. A plain counter (rather than
/// a ULID) keeps the proxy dependency-free; uniqueness only needs to hold within
/// a single wrapper run, and `u64` will not wrap in any realistic run.
static EXCHANGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Known LLM API hosts whose traffic is tagged as `llm` rather than `net`.
const LLM_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
];

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to generate proxy CA: {0}")]
    Ca(String),
    #[error("proxy server failed: {0}")]
    Server(String),
}

/// An ephemeral per-run certificate authority for TLS interception.
///
/// The CA private key stays in memory inside the [`RcgenAuthority`]; only the
/// public cert PEM is exposed, to be written to a child-scoped trust bundle.
pub struct ProxyCa {
    authority: RcgenAuthority,
    cert_pem: String,
}

impl ProxyCa {
    /// Mint a fresh ECDSA P-256 CA.
    pub fn generate() -> Result<Self, ProxyError> {
        let key_pair = KeyPair::generate().map_err(|error| ProxyError::Ca(error.to_string()))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "hiloop-interceptor proxy CA");
        params.distinguished_name = distinguished_name;

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|error| ProxyError::Ca(error.to_string()))?;
        let cert_pem = ca_cert.pem();

        // Issuer::from_ca_cert_pem consumes a KeyPair, so re-parse from PEM.
        let key_pem = key_pair.serialize_pem();
        let issuer_key =
            KeyPair::from_pem(&key_pem).map_err(|error| ProxyError::Ca(error.to_string()))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, issuer_key)
            .map_err(|error| ProxyError::Ca(error.to_string()))?;

        let authority = RcgenAuthority::new(issuer, CA_CACHE_SIZE, aws_lc_rs::default_provider());
        Ok(Self {
            authority,
            cert_pem,
        })
    }

    /// The CA certificate PEM to install as the child's trust anchor.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }
}

/// An intercepting proxy bound to an ephemeral localhost port.
pub struct ProxyServer {
    listener: TcpListener,
    clock: Arc<HlcClock>,
}

impl ProxyServer {
    /// Bind the proxy on `127.0.0.1:0`.
    pub async fn bind(clock: Arc<HlcClock>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        Ok(Self { listener, clock })
    }

    /// The bound address. Inject `HTTPS_PROXY=http://{addr}`.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the proxy until `shutdown` resolves, capturing traffic to `signal_tx`.
    pub async fn serve<F>(
        self,
        ca: ProxyCa,
        signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
        shutdown: F,
    ) -> Result<(), ProxyError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = CaptureHandler::new(signal_tx, self.clock);
        let proxy = Proxy::builder()
            .with_listener(self.listener)
            .with_ca(ca.authority)
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(handler)
            .with_graceful_shutdown(shutdown)
            .build()
            .map_err(|error| ProxyError::Server(error.to_string()))?;
        proxy
            .start()
            .await
            .map_err(|error| ProxyError::Server(error.to_string()))
    }
}

/// Captures decrypted request/response bodies and links the two by exchange id.
///
/// # Correlation
///
/// hudsucker clones the handler per HTTP request: `serve_stream` runs
/// `self.clone().proxy(req)` for each request, and that one clone calls both
/// `handle_request` and `handle_response` for that exchange (see hudsucker
/// `proxy/internal.rs`). So an id minted in `handle_request` and stashed in
/// `self.exchange_id` is readable in the matching `handle_response`, even when
/// HTTP/2 multiplexes several requests over one connection — each request still
/// gets its own clone and its own `proxy()` future.
///
/// # Reliability limits
///
/// The link is exact for any exchange that flows request → response through one
/// `proxy()` call. It is *absent* (no response event, hence nothing to mismatch)
/// when the upstream errors before a response — `handle_error` is invoked instead
/// of `handle_response`. It does not survive request/response *reordering* across
/// distinct exchanges because each exchange has an independent clone, which is the
/// correct behavior: there is no shared mutable handler that could cross-link two
/// in-flight exchanges.
#[derive(Clone)]
struct CaptureHandler {
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
    /// Exchange id for the request currently being handled by this clone,
    /// minted in `on_request` and read back in `on_response`.
    exchange_id: Option<String>,
}

impl CaptureHandler {
    fn new(signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>, clock: Arc<HlcClock>) -> Self {
        Self {
            signal_tx,
            clock,
            exchange_id: None,
        }
    }

    /// Capture a request, emit its raw signal, and rebuild it for forwarding. The
    /// exchange id is minted here and remembered so `on_response` can stamp the
    /// matching response. Split out of the trait impl so it is testable without an
    /// `HttpContext`.
    ///
    /// Unlike the response path, the request body is buffered eagerly rather than
    /// teed: a request signal must be emitted even when the upstream connection
    /// fails before consuming the body (a teed signal only fires once the body is
    /// drained downstream, which a failed upstream never does). Request bodies are
    /// the small side of an exchange (LLM prompts are JSON, not SSE), so this does
    /// not reintroduce the streaming-passthrough problem the response tee solves.
    async fn on_request(&mut self, request: Request<Body>) -> Request<Body> {
        // CONNECT only establishes the TLS tunnel; the real request arrives after
        // interception, so skip it to avoid noise authority-form signals.
        if request.method() == Method::CONNECT {
            return request;
        }

        let exchange_id = next_exchange_id();
        self.exchange_id = Some(exchange_id.clone());

        let (parts, body) = request.into_parts();
        let bytes = collect_body(body).await;

        let mut attributes = vec![
            (EXCHANGE_ID_ATTR, exchange_id),
            ("http.method", parts.method.as_str().to_owned()),
            ("http.target", parts.uri.to_string()),
        ];
        if let Some(host) = request_host(&parts.uri, &parts.headers) {
            attributes.push(("http.host", host));
        }
        if let Some(content_type) = header_str(&parts.headers, &CONTENT_TYPE) {
            attributes.push(("http.request.content_type", content_type));
        }

        emit_signal(
            &self.signal_tx,
            &self.clock,
            REQUEST_KIND,
            "http.request.body_size",
            attributes,
            bytes.clone(),
        )
        .await;

        Request::from_parts(parts, Body::from(bytes))
    }

    fn on_response(&mut self, response: Response<Body>) -> Response<Body> {
        let (parts, body) = response.into_parts();

        let mut attributes = vec![("http.status_code", parts.status.as_u16().to_string())];
        if let Some(exchange_id) = self.exchange_id.take() {
            attributes.push((EXCHANGE_ID_ATTR, exchange_id));
        }
        if let Some(content_type) = header_str(&parts.headers, &CONTENT_TYPE) {
            attributes.push(("http.response.content_type", content_type));
        }

        let teed = self.tee_body(RESPONSE_KIND, "http.response.body_size", attributes, body);
        Response::from_parts(parts, teed)
    }

    /// Build a forwarded [`Body`] that streams each frame downstream as it arrives
    /// while accumulating a capture copy; the `RawSignal` (with `attributes` plus
    /// the final body-size) is emitted once the upstream body ends.
    fn tee_body(
        &self,
        kind: &'static str,
        size_attr: &'static str,
        attributes: Vec<(&'static str, String)>,
        body: Body,
    ) -> Body {
        let signal_tx = self.signal_tx.clone();
        let clock = Arc::clone(&self.clock);
        let state = TeeState {
            upstream: Some(BodyStream::new(body)),
            captured: BytesMut::new(),
            attributes,
            signal_tx,
            clock,
            kind,
            size_attr,
        };

        // `async-stream` generators are unavailable, so drive the upstream body by
        // hand with `unfold`: each step forwards one frame downstream and copies
        // its data into the capture buffer. The first step that sees end-of-stream
        // (or an upstream error) emits the captured signal, then the stream ends.
        let teed = futures_util::stream::unfold(state, |mut state| async move {
            let upstream = state.upstream.as_mut()?;
            match upstream.next().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        state.captured.extend_from_slice(data);
                    }
                    Some((Ok(frame), state))
                }
                Some(Err(error)) => {
                    state.upstream = None;
                    state.emit().await;
                    Some((Err(error), state))
                }
                None => {
                    state.upstream = None;
                    state.emit().await;
                    None
                }
            }
        });

        Body::from(StreamBody::new(teed))
    }
}

/// Drives a single body's tee: forwards frames while accumulating `captured`,
/// then emits one `RawSignal` when the upstream ends.
struct TeeState {
    upstream: Option<BodyStream<Body>>,
    captured: BytesMut,
    attributes: Vec<(&'static str, String)>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
    kind: &'static str,
    size_attr: &'static str,
}

impl TeeState {
    async fn emit(&self) {
        emit_signal(
            &self.signal_tx,
            &self.clock,
            self.kind,
            self.size_attr,
            self.attributes.clone(),
            self.captured.clone().freeze(),
        )
        .await;
    }
}

async fn emit_signal(
    signal_tx: &mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: &HlcClock,
    kind: &'static str,
    size_attr: &'static str,
    attributes: Vec<(&'static str, String)>,
    body: Bytes,
) {
    let mut raw = RawSignal::new(PROXY_SOURCE, kind, clock.tick(), body.clone())
        .with_attribute(size_attr, body.len().to_string());
    for (key, value) in attributes {
        raw = raw.with_attribute(key, value);
    }
    let _ = signal_tx.send(Ok(raw)).await;
}

async fn collect_body(body: Body) -> Bytes {
    body.collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default()
}

fn next_exchange_id() -> String {
    let id = EXCHANGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("xchg-{id:016x}")
}

impl HttpHandler for CaptureHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        self.on_request(request).await.into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        self.on_response(response)
    }
}

fn request_host(
    uri: &hudsucker::hyper::Uri,
    headers: &hudsucker::hyper::HeaderMap,
) -> Option<String> {
    uri.host()
        .map(ToOwned::to_owned)
        .or_else(|| header_str(headers, &HOST))
}

fn header_str(
    headers: &hudsucker::hyper::HeaderMap,
    name: &hudsucker::hyper::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Turns captured proxy request/response signals into fork-stamped events.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProxyNormalizer;

#[async_trait]
impl Normalizer for ProxyNormalizer {
    fn descriptor(&self) -> NormalizerDescriptor {
        DESCRIPTOR
    }

    fn supports(&self, raw: &RawSignal) -> NormalizerSupport {
        if raw.source == PROXY_SOURCE && matches!(raw.kind.as_str(), REQUEST_KIND | RESPONSE_KIND) {
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
        let signal = match raw.attributes.get("http.host") {
            Some(host) if is_llm_host(host) => SignalType::Llm,
            _ => SignalType::Net,
        };
        let name = EventName::new(raw.kind.as_str()).map_err(|error| NormalizeError::Decode {
            source_name: raw.source.clone(),
            kind: raw.kind.clone(),
            message: error.to_string(),
        })?;

        let mut event = Event::new(context.fork_context(), raw.observed_at, signal, name);
        for (key, value) in &raw.attributes {
            let key = AttributeKey::new(key.as_str()).map_err(|error| NormalizeError::Decode {
                source_name: raw.source.clone(),
                kind: raw.kind.clone(),
                message: error.to_string(),
            })?;
            event = event.with_attribute(key, value.as_str());
        }

        // The full body lives in raw.body; preserve it to the bronze store so the
        // event stays small and the body is retrievable via raw.observation_id.
        Ok(NormalizationOutcome::from_events(vec![event])
            .with_raw_retention(RawRetentionPolicy::Preserve))
    }
}

fn is_llm_host(host: &str) -> bool {
    LLM_HOSTS
        .iter()
        .any(|known| host == *known || host.ends_with(&format!(".{known}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::event::AttributeValue;
    use hiloop_core::identity::{ForkContext, Hlc};
    use hudsucker::hyper::body::Frame;

    fn proxy_signal(kind: &str, attributes: &[(&str, &str)]) -> RawSignal {
        let mut raw = RawSignal::new(
            PROXY_SOURCE,
            kind,
            Hlc {
                wall_ns: 5,
                logical: 0,
            },
            Bytes::from_static(b"body"),
        );
        for (key, value) in attributes {
            raw = raw.with_attribute(*key, *value);
        }
        raw
    }

    #[tokio::test]
    async fn normalizes_request_as_net_event_and_preserves_body() {
        let raw = proxy_signal(
            REQUEST_KIND,
            &[
                ("http.method", "POST"),
                ("http.host", "example.com"),
                ("http.target", "/v1/thing"),
            ],
        );
        let context = NormalizationContext::new(ForkContext::new_local_root());

        let outcome = ProxyNormalizer
            .normalize(&context, raw)
            .await
            .expect("normalize");

        assert_eq!(outcome.raw_retention_policy(), RawRetentionPolicy::Preserve);
        let events = outcome.into_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signal, SignalType::Net);
        assert_eq!(events[0].name.as_str(), "http.request");
        assert_eq!(
            events[0]
                .attributes
                .get(&AttributeKey::new("http.method").expect("key")),
            Some(&AttributeValue::String("POST".to_owned()))
        );
    }

    #[tokio::test]
    async fn flags_known_llm_hosts() {
        let raw = proxy_signal(
            RESPONSE_KIND,
            &[
                ("http.host", "api.anthropic.com"),
                ("http.status_code", "200"),
            ],
        );
        let context = NormalizationContext::new(ForkContext::new_local_root());

        let outcome = ProxyNormalizer
            .normalize(&context, raw)
            .await
            .expect("normalize");
        let events = outcome.into_events();

        assert_eq!(events[0].signal, SignalType::Llm);
    }

    #[test]
    fn llm_host_matches_domain_and_subdomain() {
        assert!(is_llm_host("api.openai.com"));
        assert!(is_llm_host("eu.api.openai.com"));
        assert!(!is_llm_host("example.com"));
        assert!(!is_llm_host("notapi.openai.com.evil.com"));
    }

    /// Drive a forwarded body to completion, returning the frames the client
    /// would have received downstream. Capturing into a `RawSignal` only happens
    /// when the body is polled to its end, exactly as hudsucker forwards it.
    async fn drain_body(body: Body) -> Vec<Bytes> {
        let mut stream = BodyStream::new(body);
        let mut chunks = Vec::new();
        while let Some(frame) = stream.next().await {
            if let Ok(data) = frame.expect("frame").into_data() {
                chunks.push(data);
            }
        }
        chunks
    }

    fn streaming_body(chunks: &[&'static [u8]]) -> Body {
        let frames = chunks
            .iter()
            .map(|chunk| Ok::<_, hudsucker::Error>(Frame::data(Bytes::from_static(chunk))))
            .collect::<Vec<_>>();
        Body::from(StreamBody::new(futures_util::stream::iter(frames)))
    }

    #[tokio::test]
    async fn connect_requests_are_not_captured() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut handler = CaptureHandler::new(tx, Arc::new(HlcClock::new()));
        let request = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Body::empty())
            .expect("request");

        let _ = handler.on_request(request).await;

        assert!(rx.try_recv().is_err(), "CONNECT must not emit a signal");
    }

    #[test]
    fn ca_generation_produces_a_cert_pem() {
        let ca = ProxyCa::generate().expect("generate CA");
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn capture_handler_emits_request_signal() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut handler = CaptureHandler::new(tx, Arc::new(HlcClock::new()));
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/thing")
            .body(Body::from(Bytes::from_static(b"hello")))
            .expect("request");

        let forwarded = handler.on_request(request).await;
        let chunks = drain_body(forwarded.into_body()).await;
        assert_eq!(chunks.concat(), b"hello");

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.source, PROXY_SOURCE);
        assert_eq!(signal.kind, REQUEST_KIND);
        assert_eq!(signal.body.as_ref(), b"hello");
        assert_eq!(
            signal.attributes.get("http.method").map(String::as_str),
            Some("POST")
        );
        assert_eq!(
            signal.attributes.get("http.host").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            signal
                .attributes
                .get("http.request.body_size")
                .map(String::as_str),
            Some("5")
        );
    }

    #[tokio::test]
    async fn request_and_response_share_an_exchange_id() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut handler = CaptureHandler::new(tx, Arc::new(HlcClock::new()));

        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/thing")
            .body(Body::from(Bytes::from_static(b"req")))
            .expect("request");
        let forwarded = handler.on_request(request).await;
        drain_body(forwarded.into_body()).await;
        let request_signal = rx.recv().await.expect("request signal").expect("raw");

        let response = Response::builder()
            .status(200)
            .body(Body::from(Bytes::from_static(b"resp")))
            .expect("response");
        let forwarded = handler.on_response(response);
        drain_body(forwarded.into_body()).await;
        let response_signal = rx.recv().await.expect("response signal").expect("raw");

        let request_id = request_signal
            .attributes
            .get(EXCHANGE_ID_ATTR)
            .expect("request exchange id");
        let response_id = response_signal
            .attributes
            .get(EXCHANGE_ID_ATTR)
            .expect("response exchange id");
        assert_eq!(request_id, response_id, "exchange id must link the pair");
    }

    #[tokio::test]
    async fn streaming_response_is_forwarded_incrementally_and_captured() {
        let (tx, mut rx) = mpsc::channel(4);
        let handler = CaptureHandler::new(tx, Arc::new(HlcClock::new()));

        let body = streaming_body(&[b"event: a\n", b"data: 1\n\n", b"data: 2\n\n"]);
        let attributes = vec![("http.status_code", "200".to_owned())];
        let teed = handler.tee_body(RESPONSE_KIND, "http.response.body_size", attributes, body);

        // Three source frames must arrive downstream as three distinct frames,
        // proving frame boundaries are preserved rather than coalesced after a
        // full buffer.
        let mut stream = BodyStream::new(teed);
        let mut frames = Vec::new();
        // No signal may be emitted until the body has been fully drained.
        while let Some(frame) = stream.next().await {
            let data = frame.expect("frame").into_data().expect("data frame");
            assert!(
                rx.try_recv().is_err(),
                "signal must not fire before the body ends"
            );
            frames.push(data);
        }
        assert_eq!(
            frames.len(),
            3,
            "each upstream frame forwarded individually"
        );

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.kind, RESPONSE_KIND);
        assert_eq!(signal.body.as_ref(), b"event: a\ndata: 1\n\ndata: 2\n\n");
        assert_eq!(
            signal
                .attributes
                .get("http.response.body_size")
                .map(String::as_str),
            Some(signal.body.len().to_string().as_str())
        );
    }

    #[test]
    fn exchange_ids_are_unique() {
        let first = next_exchange_id();
        let second = next_exchange_id();
        assert_ne!(first, second);
    }
}
