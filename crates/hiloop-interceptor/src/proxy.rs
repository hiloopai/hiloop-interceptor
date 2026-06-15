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
//! First-slice limitations (tracked there): bodies are fully buffered before
//! forwarding (so streaming/SSE responses are not yet passed through
//! incrementally), and request/response events are not yet correlated.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
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
const CA_CACHE_SIZE: u64 = 1_000;
const DESCRIPTOR: NormalizerDescriptor =
    NormalizerDescriptor::new("proxy-http", env!("CARGO_PKG_VERSION"), "hiloop.event.v1");

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
        let handler = CaptureHandler {
            signal_tx,
            clock: self.clock,
        };
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

#[derive(Clone)]
struct CaptureHandler {
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
}

impl CaptureHandler {
    /// Capture a request, emit its raw signal, and rebuild it for forwarding.
    /// Split out of the trait impl so it is testable without an `HttpContext`.
    async fn on_request(&self, request: Request<Body>) -> Request<Body> {
        // CONNECT only establishes the TLS tunnel; the real request arrives after
        // interception, so skip it to avoid noise authority-form signals.
        if request.method() == Method::CONNECT {
            return request;
        }

        let (parts, body) = request.into_parts();
        let bytes = collect_body(body).await;

        let mut attributes = vec![
            ("http.method", parts.method.as_str().to_owned()),
            ("http.target", parts.uri.to_string()),
            ("http.request.body_size", bytes.len().to_string()),
        ];
        if let Some(host) = request_host(&parts.uri, &parts.headers) {
            attributes.push(("http.host", host));
        }
        if let Some(content_type) = header_str(&parts.headers, &CONTENT_TYPE) {
            attributes.push(("http.request.content_type", content_type));
        }
        self.capture(REQUEST_KIND, attributes, bytes.clone()).await;

        Request::from_parts(parts, Body::from(Full::new(bytes)))
    }

    async fn on_response(&self, response: Response<Body>) -> Response<Body> {
        let (parts, body) = response.into_parts();
        let bytes = collect_body(body).await;

        let mut attributes = vec![
            ("http.status_code", parts.status.as_u16().to_string()),
            ("http.response.body_size", bytes.len().to_string()),
        ];
        if let Some(content_type) = header_str(&parts.headers, &CONTENT_TYPE) {
            attributes.push(("http.response.content_type", content_type));
        }
        self.capture(RESPONSE_KIND, attributes, bytes.clone()).await;

        Response::from_parts(parts, Body::from(Full::new(bytes)))
    }

    async fn capture(
        &self,
        kind: &'static str,
        attributes: Vec<(&'static str, String)>,
        body: Bytes,
    ) {
        let mut raw = RawSignal::new(PROXY_SOURCE, kind, self.clock.tick(), body);
        for (key, value) in attributes {
            raw = raw.with_attribute(key, value);
        }
        let _ = self.signal_tx.send(Ok(raw)).await;
    }
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
        self.on_response(response).await
    }
}

async fn collect_body(body: Body) -> Bytes {
    body.collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default()
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

    #[tokio::test]
    async fn connect_requests_are_not_captured() {
        let (tx, mut rx) = mpsc::channel(4);
        let handler = CaptureHandler {
            signal_tx: tx,
            clock: Arc::new(HlcClock::new()),
        };
        let request = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Body::from(Full::new(Bytes::new())))
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
        let handler = CaptureHandler {
            signal_tx: tx,
            clock: Arc::new(HlcClock::new()),
        };
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/thing")
            .body(Body::from(Full::new(Bytes::from_static(b"hello"))))
            .expect("request");

        let _ = handler.on_request(request).await;

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
    }
}
