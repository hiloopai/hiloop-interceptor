//! MITM proxy capture surface.
//!
//! The wrapper runs a TLS-intercepting proxy ([`hudsucker`]) on an ephemeral
//! localhost port and injects `HTTPS_PROXY` plus a child-scoped CA bundle so the
//! harness's HTTPS traffic is decrypted, captured, and fork-stamped regardless
//! of whether the harness cooperates. Each request and response becomes one raw
//! signal; [`ProxyNormalizer`] turns it into a `net` event (or `llm` for known
//! LLM API hosts), and full bodies are streamed to a content-addressed blob store
//! (the [`crate::blob`] seam) so the event carries only a `payload_ref`. See
//! `docs/CAPTURE.md`.
//!
//! Response bodies are forwarded as a streaming tee: each frame is passed
//! downstream the moment it arrives (so SSE/chunked responses are not blocked on
//! full-body buffering) and simultaneously written to the blob store, bounding
//! memory to one frame; the `RawSignal` (empty `body` + `payload_ref`) is emitted
//! when the body stream ends. Request bodies are buffered eagerly so a request
//! signal is recorded even when the upstream never consumes the body, then
//! offloaded to the store too. Request and response events are linked by an
//! `http.exchange_id` attribute — see the `CaptureHandler` docs for the
//! correlation mechanism and its reliability limits.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
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

use hiloop_core::event::{AttributeKey, Event, EventName, MediaType, PayloadRef, SignalType};
use hiloop_core::identity::HlcClock;
use thiserror::Error;

use crate::blob::{BlobStore, BlobWriter};
use crate::seams::{
    NormalizationContext, NormalizationOutcome, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerSupport, RawSignal, SourceError,
};

const PROXY_SOURCE: &str = "proxy";
const REQUEST_KIND: &str = "http.request";
const RESPONSE_KIND: &str = "http.response";
const EXCHANGE_ID_ATTR: &str = "http.exchange_id";
const TRUNCATED_ATTR: &str = "http.capture.truncated";
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

    /// Run the proxy until `shutdown` resolves, capturing traffic to `signal_tx`
    /// and streaming bodies to `blob_store`.
    pub async fn serve<F>(
        self,
        ca: ProxyCa,
        signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
        blob_store: Arc<dyn BlobStore>,
        max_capture_bytes: Option<u64>,
        shutdown: F,
    ) -> Result<(), ProxyError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = CaptureHandler::new(signal_tx, self.clock, blob_store, max_capture_bytes);
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
    blob_store: Arc<dyn BlobStore>,
    /// Cap on captured body bytes (blob + reported size); `None` is unlimited.
    /// Never bounds what is forwarded to the client/upstream.
    max_capture_bytes: Option<u64>,
    /// Exchange id for the request currently being handled by this clone,
    /// minted in `on_request` and read back in `on_response`.
    exchange_id: Option<String>,
}

impl CaptureHandler {
    fn new(
        signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
        clock: Arc<HlcClock>,
        blob_store: Arc<dyn BlobStore>,
        max_capture_bytes: Option<u64>,
    ) -> Self {
        Self {
            signal_tx,
            clock,
            blob_store,
            max_capture_bytes,
            exchange_id: None,
        }
    }

    /// The request body is buffered eagerly, not teed like the response: a teed
    /// signal only fires once the body drains downstream, which a failed upstream
    /// never does. Inherent (not the trait method) to stay testable without an
    /// `HttpContext`.
    async fn on_request(&mut self, request: Request<Body>) -> Request<Body> {
        // CONNECT only establishes the TLS tunnel; the real request arrives after
        // interception, so skip it to avoid noisy authority-form signals.
        if request.method() == Method::CONNECT {
            return request;
        }

        let exchange_id = next_exchange_id();
        self.exchange_id = Some(exchange_id.clone());

        let (parts, body) = request.into_parts();
        let (bytes, mut truncated) = collect_body(body).await;

        // Capture at most `cap` bytes, but always forward the full body upstream.
        let captured = match self.max_capture_bytes {
            Some(cap) if bytes.len() as u64 > cap => {
                truncated = true;
                bytes.slice(..usize::try_from(cap).unwrap_or(usize::MAX))
            }
            _ => bytes.clone(),
        };

        let content_type = header_str(&parts.headers, &CONTENT_TYPE);
        let mut attributes = vec![
            (EXCHANGE_ID_ATTR, exchange_id),
            ("http.method", parts.method.as_str().to_owned()),
            ("http.target", parts.uri.to_string()),
        ];
        if let Some(host) = request_host(&parts.uri, &parts.headers) {
            attributes.push(("http.host", host));
        }
        if let Some(content_type) = &content_type {
            attributes.push(("http.request.content_type", content_type.clone()));
        }

        // Offload the buffered body to the blob store; on any failure fall back to
        // an inline body so the capture is never lost. The forwarded request keeps
        // the buffered bytes either way.
        let payload_ref =
            match offload_bytes(self.blob_store.as_ref(), &captured, content_type.as_deref()).await
            {
                Ok(payload_ref) => Some(payload_ref),
                Err(error) => {
                    eprintln!("hiloop-interceptor: proxy request blob offload failed: {error}");
                    None
                }
            };
        let raw = build_raw(
            &self.clock,
            REQUEST_KIND,
            "http.request.body_size",
            attributes,
            captured,
            truncated,
            payload_ref,
        );
        let _ = self.signal_tx.send(Ok(raw)).await;

        Request::from_parts(parts, Body::from(bytes))
    }

    fn on_response(&mut self, response: Response<Body>) -> Response<Body> {
        let (parts, body) = response.into_parts();

        let content_type = header_str(&parts.headers, &CONTENT_TYPE);
        let mut attributes = vec![("http.status_code", parts.status.as_u16().to_string())];
        if let Some(exchange_id) = self.exchange_id.take() {
            attributes.push((EXCHANGE_ID_ATTR, exchange_id));
        }
        if let Some(content_type) = &content_type {
            attributes.push(("http.response.content_type", content_type.clone()));
        }

        let teed = self.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            attributes,
            content_type,
            body,
        );
        Response::from_parts(parts, teed)
    }

    /// Build a forwarded [`Body`] that streams each frame downstream as it arrives
    /// while writing the same bytes to the blob store; the `RawSignal` (empty body
    /// plus a `payload_ref`) is emitted once the upstream body ends.
    fn tee_body(
        &self,
        kind: &'static str,
        size_attr: &'static str,
        attributes: Vec<(&'static str, String)>,
        media_type: Option<String>,
        body: Body,
    ) -> Body {
        let state = TeeState {
            upstream: Some(BodyStream::new(body)),
            writer: Some(self.blob_store.writer()),
            size: 0,
            max_capture_bytes: self.max_capture_bytes,
            capped: false,
            media_type,
            attributes,
            signal_tx: self.signal_tx.clone(),
            clock: Arc::clone(&self.clock),
            kind,
            size_attr,
            emitted: false,
        };

        // Streaming tee: forward each frame as it arrives and write it to the blob
        // store; never collect() the whole body. Mid-stream client disconnect is
        // handled by TeeState's Drop.
        let teed = futures_util::stream::unfold(state, |mut state| async move {
            let upstream = state.upstream.as_mut()?;
            match upstream.next().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        state.write(data).await;
                    }
                    Some((Ok(frame), state))
                }
                Some(Err(error)) => {
                    state.upstream = None;
                    state.emit(true).await;
                    Some((Err(error), state))
                }
                None => {
                    state.upstream = None;
                    state.emit(false).await;
                    None
                }
            }
        });

        Body::from(StreamBody::new(teed))
    }
}

/// State for one streaming body tee. `Drop` finalizes a partial (truncated) blob
/// and emits its signal if the client disconnects before the body ends.
struct TeeState {
    upstream: Option<BodyStream<Body>>,
    writer: Option<Box<dyn BlobWriter>>,
    size: u64,
    /// Cap on captured bytes; `None` is unlimited. Forwarding is unaffected.
    max_capture_bytes: Option<u64>,
    /// Set once the cap is hit and further frames stop being captured.
    capped: bool,
    media_type: Option<String>,
    attributes: Vec<(&'static str, String)>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
    kind: &'static str,
    size_attr: &'static str,
    emitted: bool,
}

impl TeeState {
    async fn write(&mut self, data: &[u8]) {
        if self.capped {
            return;
        }
        // Capture only up to the cap; the writer is kept (not dropped) so the
        // capped prefix still finalizes into a blob. Forwarding is untouched.
        let data = match self.max_capture_bytes {
            Some(cap) => {
                let remaining = cap.saturating_sub(self.size);
                let take = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(data.len());
                if take < data.len() {
                    self.capped = true;
                }
                &data[..take]
            }
            None => data,
        };
        if data.is_empty() {
            return;
        }
        if let Some(writer) = self.writer.as_mut() {
            // On write failure the writer is dropped; the streamed frames aren't
            // buffered, so the response signal degrades to metadata only (no
            // payload_ref). Unlike the request path, there is no inline fallback.
            if let Err(error) = writer.write(data).await {
                eprintln!("hiloop-interceptor: proxy response blob write failed: {error}");
                self.writer = None;
            } else {
                self.size += data.len() as u64;
            }
        }
    }

    /// Idempotent so the end-of-stream emit and the Drop fallback can't double-send.
    async fn emit(&mut self, truncated: bool) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        let raw = finalize_tee(
            &self.clock,
            self.kind,
            self.size_attr,
            std::mem::take(&mut self.attributes),
            self.writer.take(),
            self.size,
            self.media_type.take(),
            truncated || self.capped,
        )
        .await;
        let _ = self.signal_tx.send(Ok(raw)).await;
    }
}

impl Drop for TeeState {
    fn drop(&mut self) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        // Drop can't await, so finalize the partial blob on a detached task.
        // TeeState is always dropped inside the proxy's tokio runtime, so spawn is
        // safe here.
        let clock = Arc::clone(&self.clock);
        let kind = self.kind;
        let size_attr = self.size_attr;
        let attributes = std::mem::take(&mut self.attributes);
        let writer = self.writer.take();
        let size = self.size;
        let media_type = self.media_type.take();
        let signal_tx = self.signal_tx.clone();
        tokio::spawn(async move {
            let raw = finalize_tee(
                &clock, kind, size_attr, attributes, writer, size, media_type, true,
            )
            .await;
            let _ = signal_tx.send(Ok(raw)).await;
        });
    }
}

/// Finalize a teed body's blob and build its offloaded (or fallback) signal.
/// `size` is the byte count tracked across frames, so the size attribute is
/// correct even when the blob finalize fails and no `payload_ref` is produced.
#[expect(
    clippy::too_many_arguments,
    reason = "threads the per-frame tee capture state (clock/kind/attrs/writer/size/media_type/truncated) needed to finalize one body; grouping into a struct is deferred"
)]
async fn finalize_tee(
    clock: &HlcClock,
    kind: &'static str,
    size_attr: &'static str,
    attributes: Vec<(&'static str, String)>,
    writer: Option<Box<dyn BlobWriter>>,
    size: u64,
    media_type: Option<String>,
    truncated: bool,
) -> RawSignal {
    let payload_ref = match writer {
        Some(writer) => match writer.finish().await {
            Ok(payload_ref) => Some(apply_media_type(payload_ref, media_type.as_deref())),
            Err(error) => {
                eprintln!("hiloop-interceptor: proxy blob finalize failed: {error}");
                None
            }
        },
        None => None,
    };
    let mut raw = RawSignal::new(PROXY_SOURCE, kind, clock.tick(), Bytes::new())
        .with_attribute(size_attr, size.to_string());
    if truncated {
        raw = raw.with_attribute(TRUNCATED_ATTR, "true");
    }
    for (key, value) in attributes {
        raw = raw.with_attribute(key, value);
    }
    if let Some(payload_ref) = payload_ref {
        raw = raw.with_payload_ref(payload_ref);
    }
    raw
}

/// Builds a request signal: offloaded (empty body + `payload_ref`) when the blob
/// store succeeded, else an inline-body fallback so the capture is not lost.
fn build_raw(
    clock: &HlcClock,
    kind: &'static str,
    size_attr: &'static str,
    attributes: Vec<(&'static str, String)>,
    body: Bytes,
    truncated: bool,
    payload_ref: Option<PayloadRef>,
) -> RawSignal {
    let size = body.len();
    let body = if payload_ref.is_some() {
        Bytes::new()
    } else {
        body
    };
    let mut raw = RawSignal::new(PROXY_SOURCE, kind, clock.tick(), body)
        .with_attribute(size_attr, size.to_string());
    if truncated {
        raw = raw.with_attribute(TRUNCATED_ATTR, "true");
    }
    for (key, value) in attributes {
        raw = raw.with_attribute(key, value);
    }
    if let Some(payload_ref) = payload_ref {
        raw = raw.with_payload_ref(payload_ref);
    }
    raw
}

fn apply_media_type(payload_ref: PayloadRef, media_type: Option<&str>) -> PayloadRef {
    match media_type.and_then(|value| MediaType::new(value).ok()) {
        Some(media_type) => payload_ref.with_media_type(media_type),
        None => payload_ref,
    }
}

/// Offload `bytes` to `store`, returning a `payload_ref` with media-type applied.
async fn offload_bytes(
    store: &dyn BlobStore,
    bytes: &[u8],
    media_type: Option<&str>,
) -> Result<PayloadRef, crate::blob::BlobStoreError> {
    let mut writer = store.writer();
    writer.write(bytes).await?;
    let payload_ref = writer.finish().await?;
    Ok(apply_media_type(payload_ref, media_type))
}

/// The bool is whether an upstream error truncated collection — so an error-emptied
/// body isn't mistaken for a genuinely empty one.
async fn collect_body(body: Body) -> (Bytes, bool) {
    match body.collect().await {
        Ok(collected) => (collected.to_bytes(), false),
        Err(error) => {
            eprintln!("hiloop-interceptor: proxy request body read error: {error}");
            (Bytes::new(), true)
        }
    }
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

        // The body already lives in the blob store; carry its reference onto the
        // event and let the raw observation be discarded (default retention).
        if let Some(payload_ref) = raw.payload_ref() {
            event = event.with_payload_ref(payload_ref.clone());
        }

        Ok(NormalizationOutcome::from_events(vec![event]))
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
    use crate::blob::testing::MemoryBlobStore;
    use hiloop_core::event::{AttributeValue, PayloadDigest};
    use hiloop_core::identity::{ForkContext, Hlc};
    use hudsucker::hyper::body::Frame;

    fn handler() -> (
        CaptureHandler,
        mpsc::Receiver<Result<RawSignal, SourceError>>,
        Arc<MemoryBlobStore>,
    ) {
        handler_with_cap(None)
    }

    fn handler_with_cap(
        max_capture_bytes: Option<u64>,
    ) -> (
        CaptureHandler,
        mpsc::Receiver<Result<RawSignal, SourceError>>,
        Arc<MemoryBlobStore>,
    ) {
        let (tx, rx) = mpsc::channel(4);
        let store = Arc::new(MemoryBlobStore::default());
        let handler = CaptureHandler::new(
            tx,
            Arc::new(HlcClock::new()),
            store.clone(),
            max_capture_bytes,
        );
        (handler, rx, store)
    }

    fn expected_digest(body: &[u8]) -> String {
        format!("blake3:{}", blake3::hash(body).to_hex())
    }

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
    async fn normalizes_request_as_net_event_and_carries_payload_ref() {
        use crate::seams::RawRetentionPolicy;
        let digest = PayloadDigest::new("sha256:abc").expect("digest");
        let raw = proxy_signal(
            REQUEST_KIND,
            &[
                ("http.method", "POST"),
                ("http.host", "example.com"),
                ("http.target", "/v1/thing"),
            ],
        )
        .with_payload_ref(PayloadRef::new(digest));
        let context = NormalizationContext::new(ForkContext::new_local_root());

        let outcome = ProxyNormalizer
            .normalize(&context, raw)
            .await
            .expect("normalize");

        // The body lives in the blob store now, so nothing is retained in bronze.
        assert_eq!(
            outcome.raw_retention_policy(),
            RawRetentionPolicy::DiscardAfterNormalize
        );
        let events = outcome.into_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signal, SignalType::Net);
        assert_eq!(events[0].name.as_str(), "http.request");
        assert_eq!(
            events[0].payload_ref.as_ref().map(|p| p.digest.as_str()),
            Some("sha256:abc")
        );
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
    async fn response_partial_is_captured_when_client_disconnects() {
        let (mut handler, mut rx, store) = handler();
        let response = Response::builder()
            .status(200)
            .body(streaming_body(&[b"chunk-1", b"chunk-2", b"chunk-3"]))
            .expect("response");

        let teed = handler.on_response(response);
        let mut stream = BodyStream::new(teed.into_body());
        let first = stream
            .next()
            .await
            .expect("frame")
            .expect("ok")
            .into_data()
            .expect("data");
        assert_eq!(first.as_ref(), b"chunk-1");
        drop(stream);

        // Drop finalizes the partial blob on a detached task; recv awaits it.
        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.kind, RESPONSE_KIND);
        assert!(signal.body.is_empty(), "offloaded body must be empty");
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(b"chunk-1").as_str())
        );
        assert_eq!(signal.payload_ref().and_then(|p| p.size_bytes), Some(7));
        assert_eq!(
            signal.attributes.get(TRUNCATED_ATTR).map(String::as_str),
            Some("true")
        );
        assert_eq!(store.blobs().len(), 1);
    }

    #[tokio::test]
    async fn connect_requests_are_not_captured() {
        let (mut handler, mut rx, _store) = handler();
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
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/thing")
            .body(Body::from(Bytes::from_static(b"hello")))
            .expect("request");

        // The forwarded request still carries the buffered bytes upstream.
        let forwarded = handler.on_request(request).await;
        let chunks = drain_body(forwarded.into_body()).await;
        assert_eq!(chunks.concat(), b"hello");

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.source, PROXY_SOURCE);
        assert_eq!(signal.kind, REQUEST_KIND);
        assert!(signal.body.is_empty(), "offloaded body must be empty");
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(b"hello").as_str())
        );
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
        let (mut handler, mut rx, _store) = handler();

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
    async fn streaming_response_is_forwarded_incrementally_and_offloaded() {
        let (handler, mut rx, _store) = handler();

        let body = streaming_body(&[b"event: a\n", b"data: 1\n\n", b"data: 2\n\n"]);
        let attributes = vec![("http.status_code", "200".to_owned())];
        let teed = handler.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            attributes,
            None,
            body,
        );

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

        let full = b"event: a\ndata: 1\n\ndata: 2\n\n";
        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.kind, RESPONSE_KIND);
        assert!(signal.body.is_empty(), "offloaded body must be empty");
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(full).as_str())
        );
        assert_eq!(
            signal.payload_ref().and_then(|p| p.size_bytes),
            Some(full.len() as u64)
        );
        assert_eq!(
            signal
                .attributes
                .get("http.response.body_size")
                .map(String::as_str),
            Some(full.len().to_string().as_str())
        );
    }

    #[tokio::test]
    async fn response_over_cap_is_truncated_but_fully_forwarded() {
        // Cap 10 bytes splits mid second frame (7 + 7 = 14 > 10).
        let (handler, mut rx, store) = handler_with_cap(Some(10));
        let teed = handler.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            vec![("http.status_code", "200".to_owned())],
            None,
            streaming_body(&[b"chunk-1", b"chunk-2", b"chunk-3"]),
        );

        // The client still receives every frame in full.
        let chunks = drain_body(teed).await;
        assert_eq!(chunks.concat(), b"chunk-1chunk-2chunk-3");

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.attributes.get(TRUNCATED_ATTR).map(String::as_str),
            Some("true")
        );
        assert_eq!(
            signal
                .attributes
                .get("http.response.body_size")
                .map(String::as_str),
            Some("10")
        );
        assert_eq!(
            signal.payload_ref().and_then(|p| p.size_bytes),
            Some(10),
            "blob holds exactly the cap"
        );
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(b"chunk-1chu").as_str())
        );
        assert_eq!(store.blobs().len(), 1);
    }

    #[tokio::test]
    async fn response_under_cap_is_not_truncated() {
        let (handler, mut rx, _store) = handler_with_cap(Some(1024));
        let teed = handler.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            vec![("http.status_code", "200".to_owned())],
            None,
            streaming_body(&[b"chunk-1", b"chunk-2"]),
        );
        drain_body(teed).await;

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert!(!signal.attributes.contains_key(TRUNCATED_ATTR));
        assert_eq!(
            signal
                .attributes
                .get("http.response.body_size")
                .map(String::as_str),
            Some("14")
        );
    }

    #[tokio::test]
    async fn request_over_cap_is_truncated_but_forwards_full_body() {
        let (mut handler, mut rx, _store) = handler_with_cap(Some(3));
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/thing")
            .body(Body::from(Bytes::from_static(b"hello")))
            .expect("request");

        let forwarded = handler.on_request(request).await;
        let chunks = drain_body(forwarded.into_body()).await;
        assert_eq!(chunks.concat(), b"hello", "upstream gets the full body");

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.attributes.get(TRUNCATED_ATTR).map(String::as_str),
            Some("true")
        );
        assert_eq!(
            signal.payload_ref().and_then(|p| p.size_bytes),
            Some(3),
            "offloaded prefix equals the cap"
        );
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(b"hel").as_str())
        );
        assert_eq!(
            signal
                .attributes
                .get("http.request.body_size")
                .map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn exchange_ids_are_unique() {
        let first = next_exchange_id();
        let second = next_exchange_id();
        assert_ne!(first, second);
    }
}
