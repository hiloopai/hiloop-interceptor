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
//! full-body buffering) while the *captured copy* is accumulated separately, bounded
//! by the capture cap ([`DEFAULT_MAX_CAPTURE_BYTES`] by default, `--max-capture-bytes`
//! to override; this finite default bounds interceptor memory). When the stream ends
//! the captured copy is redacted once (see [`crate::redact`] — so a secret straddling
//! two frames is still caught) and offloaded to the blob store, and the `RawSignal`
//! (empty `body` + `payload_ref`) is emitted. Request bodies are buffered eagerly so
//! a request signal is recorded even when the upstream never consumes the body, then
//! capped to the same limit, redacted, and offloaded. The cap bounds only the captured
//! copy; the bytes forwarded to the origin are always complete and never capped.
//! Request and response events are linked by an `http.exchange_id` attribute; an
//! exchange that ends without a response (upstream failure, client abort, policy
//! block) is closed by a terminal `http.abort` event sharing the same id — see the
//! `CaptureHandler` docs for the correlation mechanism and its reliability limits.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hudsucker::certificate_authority::CertificateAuthority;
use hudsucker::hyper::header::{CONTENT_ENCODING, CONTENT_TYPE, HOST};
use hudsucker::hyper::http::uri::Authority;
use hudsucker::hyper::{Method, Request, Response, StatusCode};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, string::Ia5String,
};
use hudsucker::rustls::{
    ServerConfig,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};

use hiloop_core::event::{AttributeKey, Event, EventName, MediaType, PayloadRef, SignalType};
use hiloop_core::identity::HlcClock;
use thiserror::Error;

use crate::anomaly::{AnomalyConfig, AnomalyFlag};
use crate::blob::BlobStore;
use crate::egress::{CanonicalHost, Destination, EgressPolicy, canonicalize_host};
use crate::redact::RedactionPolicy;
use crate::seams::{
    NormalizationContext, NormalizationOutcome, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerSupport, RawSignal, SourceError,
};
use crate::secret::SecretInjector;

/// Default cap on captured body bytes per request/response, applied when the cap is
/// left unspecified. Capture is buffered in memory before redaction/offload, so a
/// finite default bounds interceptor memory; 8 MiB captures essentially all real API
/// bodies in full. Only the *captured copy* is bounded — the bytes forwarded to the
/// client/upstream are never capped. A cap of `0` at the CLI means unlimited.
pub const DEFAULT_MAX_CAPTURE_BYTES: u64 = 8 * 1024 * 1024;

const PROXY_SOURCE: &str = "proxy";
const REQUEST_KIND: &str = "http.request";
const RESPONSE_KIND: &str = "http.response";
const EGRESS_DENIED_KIND: &str = "egress.denied";
/// Terminal event for an exchange that ended without a response: it shares the
/// request's `http.exchange_id` and names why the exchange never completed
/// ([`ABORT_REASON_ATTR`]), so a captured request can never dangle ambiguously.
const ABORT_KIND: &str = "http.abort";
/// Why the exchange aborted: `upstream_connect_error` (the origin was unreachable),
/// `upstream_error` (the forward leg failed after connecting), `blocked` (a policy
/// short-circuit ended the exchange after its request event), or `incomplete` (the
/// exchange was still open when its handler was dropped — client abort or capture end).
const ABORT_REASON_ATTR: &str = "http.abort.reason";
/// Human-readable detail for an aborted exchange (the folded upstream error chain).
const ABORT_DETAIL_ATTR: &str = "http.abort.detail";
const EXCHANGE_ID_ATTR: &str = "http.exchange_id";
const GEN_AI_REQUEST_MODEL_ATTR: &str = "gen_ai.request.model";
const GEN_AI_RESPONSE_MODEL_ATTR: &str = "gen_ai.response.model";
const TOOL_CALL_ATTR: &str = "tool_call";
const TRUNCATED_ATTR: &str = "http.capture.truncated";
/// Body bytes observed on the wire for the request leg — pre-cap, pre-redaction —
/// so a truncated capture still records the true transfer size. (The `body_size`
/// attributes report the *stored* captured copy: post-cap, post-redaction.)
const REQUEST_WIRE_SIZE_ATTR: &str = "http.request.wire_size";
/// Body bytes observed on the wire for the response leg; on a mid-stream abort it
/// counts what was seen before the stream ended. See [`REQUEST_WIRE_SIZE_ATTR`].
const RESPONSE_WIRE_SIZE_ATTR: &str = "http.response.wire_size";
/// The request's `Content-Encoding` header, recorded (like content-type) because the
/// stored bytes are byte-exact wire bytes: without it a gzip body is semantically
/// opaque against its decoded media type.
const REQUEST_CONTENT_ENCODING_ATTR: &str = "http.request.content_encoding";
/// The response's `Content-Encoding` header. See [`REQUEST_CONTENT_ENCODING_ATTR`].
const RESPONSE_CONTENT_ENCODING_ATTR: &str = "http.response.content_encoding";
/// Attribute stamped with a comma-separated list of matched anomaly rule names when a
/// captured request trips one or more [`AnomalyConfig`] rules.
const FLAGGED_ATTR: &str = "anomaly.flagged";
/// Attribute stamped with `true` when a flagged request was rejected (block mode).
const BLOCKED_ATTR: &str = "anomaly.blocked";
const CA_CACHE_SIZE: u64 = 1_000;
const DESCRIPTOR: NormalizerDescriptor =
    NormalizerDescriptor::new("proxy-http", env!("CARGO_PKG_VERSION"), "hiloop.event.v1");

static CERT_SERIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Known LLM API hosts whose traffic is tagged as `llm` rather than `net`.
const LLM_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
];
const MAX_LLM_METADATA_VALUE_BYTES: usize = 128;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to generate proxy CA: {0}")]
    Ca(String),
    #[error("proxy server failed: {0}")]
    Server(String),
}

/// An ephemeral per-run certificate authority for TLS interception.
///
/// The CA private key stays in memory inside the proxy authority; only the
/// public cert PEM is exposed, to be written to a child-scoped trust bundle.
pub struct ProxyCa {
    authority: ProxyAuthority,
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

        let authority = ProxyAuthority::new(issuer, aws_lc_rs::default_provider());
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

struct ProxyAuthority {
    issuer: Issuer<'static, KeyPair>,
    private_key: PrivateKeyDer<'static>,
    cache: Mutex<HashMap<Authority, Arc<ServerConfig>>>,
    provider: Arc<CryptoProvider>,
}

impl ProxyAuthority {
    fn new(issuer: Issuer<'static, KeyPair>, provider: CryptoProvider) -> Self {
        let private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(issuer.key().serialize_der()));

        Self {
            issuer,
            private_key,
            cache: Mutex::new(HashMap::new()),
            provider: Arc::new(provider),
        }
    }

    fn gen_cert(&self, authority: &Authority) -> CertificateDer<'static> {
        let mut params = CertificateParams::default();
        params.serial_number = Some(CERT_SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed).into());
        params.use_authority_key_identifier_extension = true;

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, authority.host());
        params.distinguished_name = distinguished_name;

        params
            .subject_alt_names
            .push(subject_alt_name(authority.host()));

        params
            .signed_by(self.issuer.key(), &self.issuer)
            .expect("sign proxy certificate")
            .into()
    }

    fn server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        let certs = vec![self.gen_cert(authority)];

        let mut server_cfg = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .expect("specify TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key.clone_key())
            .expect("build proxy ServerConfig");

        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Arc::new(server_cfg)
    }
}

fn subject_alt_name(host: &str) -> SanType {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return SanType::IpAddress(ip);
    }

    if let Some(bracketed_host) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        && let Ok(ip) = bracketed_host.parse::<IpAddr>()
    {
        return SanType::IpAddress(ip);
    }

    SanType::DnsName(Ia5String::try_from(host).expect("create Ia5String"))
}

impl CertificateAuthority for ProxyAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        if let Some(server_cfg) = self.cache.lock().await.get(authority).cloned() {
            return server_cfg;
        }

        let server_cfg = self.server_config(authority);
        let mut cache = self.cache.lock().await;
        if cache.len() >= CA_CACHE_SIZE as usize {
            cache.clear();
        }
        cache.insert(authority.clone(), Arc::clone(&server_cfg));
        server_cfg
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
    ///
    /// `egress` enforces the run's egress policy (default allow-all is a no-op),
    /// `anomaly` inspects original request bodies (default disabled is a no-op), and
    /// `injector`, when set, injects bound credentials into matching requests.
    #[expect(
        clippy::too_many_arguments,
        reason = "the proxy's capture, redaction, egress, anomaly, and injection seams are all configured per run; a config struct is deferred while there is a single in-tree caller (the supervisor)"
    )]
    pub async fn serve<F>(
        self,
        ca: ProxyCa,
        signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
        blob_store: Arc<dyn BlobStore>,
        max_capture_bytes: Option<u64>,
        redaction: RedactionPolicy,
        egress: Arc<EgressPolicy>,
        anomaly: Arc<AnomalyConfig>,
        injector: Option<SecretInjector>,
        shutdown: F,
    ) -> Result<(), ProxyError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = CaptureHandler::new(
            signal_tx,
            self.clock,
            blob_store,
            max_capture_bytes,
            redaction,
            egress,
            anomaly,
            injector,
        );
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
/// `proxy()` call. When no response ever arrives the exchange is closed by a
/// terminal `http.abort` event sharing the same id: `handle_error` (invoked
/// instead of `handle_response` when the upstream leg fails) emits it with the
/// upstream failure as reason/detail, and a clone dropped with its exchange still
/// open (client abort, capture end, policy short-circuit) emits it from `Drop` —
/// so a captured request never dangles with an ambiguous fate. The link does not
/// survive request/response *reordering* across distinct exchanges because each
/// exchange has an independent clone, which is the correct behavior: there is no
/// shared mutable handler that could cross-link two in-flight exchanges.
#[derive(Clone)]
struct CaptureHandler {
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
    blob_store: Arc<dyn BlobStore>,
    /// Cap on captured body bytes (blob + reported size); `None` is unlimited.
    /// Never bounds what is forwarded to the client/upstream.
    max_capture_bytes: Option<u64>,
    /// Scrubs secrets from the captured copy before it is persisted; never the
    /// bytes forwarded to the client/upstream.
    redaction: RedactionPolicy,
    /// Egress policy enforced at CONNECT and at the decrypted request. Allow-all by
    /// default (a no-op).
    egress: Arc<EgressPolicy>,
    /// Request-body anomaly detection run over the original request body (not the
    /// truncated/redacted captured copy). Disabled by default (a no-op).
    anomaly: Arc<AnomalyConfig>,
    /// Credential injector, when the run binds secrets to hosts.
    injector: Option<SecretInjector>,
    /// The canonicalized host from this clone's CONNECT (the SNI host), stashed so the
    /// decrypted request can reject a `Host`/`:authority` that disagrees with it.
    connect_host: Option<CanonicalHost>,
    /// The credential values injected into the current request (one per binding on
    /// the host), retained only long enough to scrub them from this exchange's
    /// captured request/response copies. Zeroized when the handler clone is dropped
    /// at end of exchange.
    injected_secrets: Vec<zeroize::Zeroizing<String>>,
    /// Exchange id for the request currently being handled by this clone,
    /// minted in `on_request` and read back in `on_response`.
    exchange_id: Option<String>,
    /// Request host for the current exchange, carried onto the matching response so
    /// response telemetry can be classified and queried by the same host dimension.
    exchange_host: Option<String>,
    /// Method of the current exchange's request, carried onto a terminal
    /// `http.abort` so an aborted exchange still records what was actually sent.
    exchange_method: Option<String>,
    /// Normalized target of the current exchange's request, for the same purpose.
    exchange_target: Option<String>,
    /// Set when a policy short-circuit (anomaly block) ends the exchange after its
    /// request event, so the Drop-emitted terminal abort names the real reason.
    abort_reason: Option<&'static str>,
}

impl CaptureHandler {
    #[expect(
        clippy::too_many_arguments,
        reason = "the handler's capture, redaction, egress, anomaly, and injection seams are each configured per run; a config struct is deferred while the only caller is the supervisor via ProxyServer::serve"
    )]
    fn new(
        signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
        clock: Arc<HlcClock>,
        blob_store: Arc<dyn BlobStore>,
        max_capture_bytes: Option<u64>,
        redaction: RedactionPolicy,
        egress: Arc<EgressPolicy>,
        anomaly: Arc<AnomalyConfig>,
        injector: Option<SecretInjector>,
    ) -> Self {
        Self {
            signal_tx,
            clock,
            blob_store,
            max_capture_bytes,
            redaction,
            egress,
            anomaly,
            injector,
            connect_host: None,
            injected_secrets: Vec::new(),
            exchange_id: None,
            exchange_host: None,
            exchange_method: None,
            exchange_target: None,
            abort_reason: None,
        }
    }

    /// The request body is buffered eagerly, not teed like the response: a teed
    /// signal only fires once the body drains downstream, which a failed upstream
    /// never does. Inherent (not the trait method) to stay testable without an
    /// `HttpContext`.
    ///
    /// Enforces egress and (on a match) credential injection before capture: a CONNECT
    /// to a denied host short-circuits with `403` before any tunnel is established; a
    /// decrypted request to a denied host (or one whose `Host` disagrees with the
    /// CONNECT's SNI host) also short-circuits with `403`; a broker failure on an
    /// injected request fails closed with `502` so the request is never forwarded
    /// without its credential.
    async fn on_request(&mut self, request: Request<Body>) -> RequestOrResponse {
        // CONNECT only establishes the TLS tunnel; the real request arrives after
        // interception. Capture nothing here, but enforce egress on the SNI host and
        // stash it so the decrypted request can detect a Host/SNI mismatch.
        if request.method() == Method::CONNECT {
            match canonical_authority(&request) {
                Some(destination) => {
                    if let Some(denied) = self.enforce_egress(&destination, "connect") {
                        return denied.into();
                    }
                    self.connect_host = Some(destination.host().clone());
                }
                None => {
                    // An un-parseable CONNECT authority can't be policed; under a
                    // non-allow-all policy, fail closed rather than tunnel an unknown
                    // destination.
                    if !self.egress.is_allow_all() {
                        self.emit_egress_unparseable("connect");
                        return forbidden().into();
                    }
                }
            }
            return request.into();
        }

        let destination = canonical_authority(&request);

        // Fail closed under a non-allow-all policy: a host that can't be canonicalized
        // (missing, or crafted to defeat the parser) must be DENIED, never forwarded —
        // otherwise an unparseable host would skip the deny-by-default policy entirely.
        let Some(destination) = destination else {
            if self.egress.is_allow_all() {
                // No policy to enforce; capture and forward as before.
                return self.capture_request(request).await;
            }
            self.emit_egress_unparseable("request");
            return forbidden().into();
        };

        // Reject a decrypted Host that disagrees with the CONNECT's SNI host *before*
        // the policy check: a mismatch means the request would reach a host the
        // CONNECT-time egress check never saw, regardless of whether the decrypted host
        // would itself pass the policy. Skipped under allow-all (no SNI was policed).
        if !self.egress.is_allow_all()
            && let Some(connect_host) = &self.connect_host
            && connect_host != destination.host()
        {
            self.emit_egress_denied(&destination, "host-mismatch", "request", None);
            return forbidden().into();
        }
        // Authoritative egress check on the decrypted Host/:authority.
        if let Some(denied) = self.enforce_egress(&destination, "request") {
            return denied.into();
        }

        // Inject the bound credentials, if any; fail the request closed on broker error.
        // `inject` borrows the injector (no per-request HashMap clone); the borrow ends
        // before `capture_request`/`injected_secrets` take `&mut self`.
        if self.injector.is_some() {
            let mut request = request;
            let injected = {
                let injector = self.injector.as_ref().expect("checked is_some");
                injector.inject(destination.host(), &mut request).await
            };
            match injected {
                Ok(values) => self.injected_secrets = values,
                Err(error) => {
                    eprintln!(
                        "hiloop-interceptor: credential broker resolve failed; failing request closed: {error}"
                    );
                    return bad_gateway().into();
                }
            }
            return self.capture_request(request).await;
        }

        self.capture_request(request).await
    }

    /// Buffer, capture, and forward a (post-egress, post-injection) request.
    ///
    /// Anomaly detection runs over the original request body (so a capture cap cannot
    /// truncate an upload out of detection); matches are flagged onto the request signal,
    /// while only the truncated+redacted copy is captured/offloaded. Under
    /// [`AnomalyConfig::blocks_on_match`] a match short-circuits with a `403` and the
    /// request is never forwarded (the signal still records the flagged, blocked
    /// exchange).
    async fn capture_request(&mut self, request: Request<Body>) -> RequestOrResponse {
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
        // Only the captured copy is redacted; the forwarded `bytes` are never touched.
        // An injected credential is scrubbed as an exact literal even if redaction is
        // off, so the placeholder — not the secret — is all that reaches telemetry.
        let captured = self.redact_capture(captured);

        let content_type = header_str(&parts.headers, &CONTENT_TYPE);

        // Inspect the ORIGINAL body (full pre-truncation length, unredacted bytes) for
        // exfiltration-shaped anomalies, so a capture cap below a threshold cannot
        // truncate a large upload out of detection. Inspection is read-only; only the
        // truncated+redacted `captured` copy is ever emitted or offloaded. The flags
        // carry only rule names and sizes (never body content), safe to stamp onto
        // telemetry.
        let flags = self
            .anomaly
            .inspect(parts.method.as_str(), content_type.as_deref(), &bytes);
        let blocked = !flags.is_empty() && self.anomaly.blocks_on_match();

        let method = parts.method.as_str().to_owned();
        let target = telemetry_target(&parts.uri);
        self.exchange_method = Some(method.clone());
        self.exchange_target = Some(target.clone());
        let mut attributes = vec![
            (EXCHANGE_ID_ATTR, exchange_id),
            ("http.method", method),
            ("http.target", target),
            // The true transfer size, distinct from the stored (capped + redacted)
            // `body_size`: reconstruction and traffic accounting survive truncation.
            (REQUEST_WIRE_SIZE_ATTR, bytes.len().to_string()),
        ];
        if let Some(encoding) = header_str(&parts.headers, &CONTENT_ENCODING) {
            attributes.push((REQUEST_CONTENT_ENCODING_ATTR, encoding));
        }
        let host = request_host(&parts.uri, &parts.headers).map(|host| telemetry_host(&host));
        self.exchange_host.clone_from(&host);
        if let Some(host) = &host {
            attributes.push(("http.host", host.clone()));
        }
        if let Some(content_type) = &content_type {
            attributes.push(("http.request.content_type", content_type.clone()));
        }
        append_llm_capture_attributes(
            &mut attributes,
            host.as_deref(),
            content_type.as_deref(),
            &captured,
            LlmCaptureDirection::Request,
        );
        if !flags.is_empty() {
            attributes.push((FLAGGED_ATTR, join_flag_names(&flags)));
        }
        if blocked {
            attributes.push((BLOCKED_ATTR, "true".to_owned()));
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

        if blocked {
            // The 403 short-circuit never reaches `on_response`, so the exchange's
            // terminal record is the Drop-emitted abort; name its reason honestly.
            self.abort_reason = Some("blocked");
            return forbidden().into();
        }
        Request::from_parts(parts, Body::from(bytes)).into()
    }

    /// Build the terminal `http.abort` signal for the currently open exchange (if
    /// any), consuming the exchange state so the terminal is emitted exactly once.
    fn take_abort_signal(&mut self, reason: &str, detail: Option<String>) -> Option<RawSignal> {
        let exchange_id = self.exchange_id.take()?;
        let mut raw = RawSignal::new(PROXY_SOURCE, ABORT_KIND, self.clock.tick(), Bytes::new())
            .with_attribute(EXCHANGE_ID_ATTR, exchange_id)
            .with_attribute(ABORT_REASON_ATTR, reason);
        if let Some(host) = self.exchange_host.take() {
            raw = raw.with_attribute("http.host", host);
        }
        if let Some(method) = self.exchange_method.take() {
            raw = raw.with_attribute("http.method", method);
        }
        if let Some(target) = self.exchange_target.take() {
            raw = raw.with_attribute("http.target", target);
        }
        if let Some(detail) = detail {
            raw = raw.with_attribute(ABORT_DETAIL_ATTR, detail);
        }
        Some(raw)
    }

    /// Record the terminal abort for an exchange whose upstream leg failed:
    /// hudsucker calls `handle_error` instead of `handle_response` there, so
    /// without this the request event would dangle with no terminal record.
    /// Inherent (not the trait method) to stay testable without an `HttpContext`.
    async fn on_upstream_error(&mut self, reason: &'static str, detail: String) {
        if let Some(raw) = self.take_abort_signal(reason, Some(detail)) {
            let _ = self.signal_tx.send(Ok(raw)).await;
        }
    }

    /// Evaluate `destination` against the egress policy at `layer`; on a deny, emit the
    /// `egress.denied` event and return the `403` to short-circuit. `None` ⇒ allowed.
    fn enforce_egress(
        &self,
        destination: &Destination,
        layer: &'static str,
    ) -> Option<Response<Body>> {
        if self.egress.is_allow_all() {
            return None;
        }
        let decision = self.egress.evaluate(destination);
        if decision.allowed() {
            return None;
        }
        self.emit_egress_denied(destination, "policy", layer, decision.rule_matched());
        Some(forbidden())
    }

    /// Emit a structured `egress.denied` event. Carries only low-cardinality decision
    /// metadata — the canonicalized host, the matched rule, the layer, the mode, and
    /// the port — never a URL, body, or secret.
    fn emit_egress_denied(
        &self,
        destination: &Destination,
        decision: &'static str,
        layer: &'static str,
        rule_matched: Option<&str>,
    ) {
        let mut raw = RawSignal::new(
            PROXY_SOURCE,
            EGRESS_DENIED_KIND,
            self.clock.tick(),
            Bytes::new(),
        )
        .with_attribute("egress.decision", decision)
        .with_attribute("http.host", destination.host_str())
        .with_attribute("egress.layer", layer)
        .with_attribute("egress.mode", self.egress.mode().to_string());
        if let Some(rule) = rule_matched {
            raw = raw.with_attribute("egress.rule_matched", rule);
        }
        if let Some(port) = destination.port() {
            raw = raw.with_attribute("net.peer.port", port.to_string());
        }
        // The pipeline channel is bounded; an egress-deny event is best-effort like the
        // capture signals and must never block request handling.
        let _ = self.signal_tx.try_send(Ok(raw));
    }

    /// Emit an `egress.denied` event for a destination that failed canonicalization and
    /// so was failed closed. No host is reported (there is no canonical host to name);
    /// the decision is `unparseable_host`.
    fn emit_egress_unparseable(&self, layer: &'static str) {
        let raw = RawSignal::new(
            PROXY_SOURCE,
            EGRESS_DENIED_KIND,
            self.clock.tick(),
            Bytes::new(),
        )
        .with_attribute("egress.decision", "unparseable_host")
        .with_attribute("egress.layer", layer)
        .with_attribute("egress.mode", self.egress.mode().to_string());
        let _ = self.signal_tx.try_send(Ok(raw));
    }

    /// Redact a captured body: the configured pattern policy plus any credentials this
    /// exchange injected (scrubbed as exact literals so they never reach telemetry,
    /// even when pattern redaction is disabled).
    fn redact_capture(&self, body: Bytes) -> Bytes {
        redact_with_injected(self.redaction, body, &self.injected_secrets)
    }

    fn on_response(&mut self, response: Response<Body>) -> Response<Body> {
        let (parts, body) = response.into_parts();

        let content_type = header_str(&parts.headers, &CONTENT_TYPE);
        let mut attributes = vec![("http.status_code", parts.status.as_u16().to_string())];
        if let Some(exchange_id) = self.exchange_id.take() {
            attributes.push((EXCHANGE_ID_ATTR, exchange_id));
        }
        if let Some(host) = self.exchange_host.take() {
            attributes.push(("http.host", host));
        }
        if let Some(content_type) = &content_type {
            attributes.push(("http.response.content_type", content_type.clone()));
        }
        if let Some(encoding) = header_str(&parts.headers, &CONTENT_ENCODING) {
            attributes.push((RESPONSE_CONTENT_ENCODING_ATTR, encoding));
        }

        let teed = self.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            RESPONSE_WIRE_SIZE_ATTR,
            attributes,
            content_type,
            body,
        );
        Response::from_parts(parts, teed)
    }

    /// Build a forwarded [`Body`] that streams each frame downstream as it arrives
    /// while buffering the captured copy; once the upstream body ends the buffer is
    /// redacted, offloaded to the blob store, and the `RawSignal` (empty body plus a
    /// `payload_ref`) is emitted.
    fn tee_body(
        &self,
        kind: &'static str,
        size_attr: &'static str,
        wire_size_attr: &'static str,
        attributes: Vec<(&'static str, String)>,
        media_type: Option<String>,
        body: Body,
    ) -> Body {
        let state = TeeState {
            upstream: Some(BodyStream::new(body)),
            blob_store: Arc::clone(&self.blob_store),
            captured: Vec::new(),
            max_capture_bytes: self.max_capture_bytes,
            truncated: false,
            redaction: self.redaction,
            injected_secrets: self.injected_secrets.clone(),
            capped: false,
            media_type,
            attributes,
            signal_tx: self.signal_tx.clone(),
            clock: Arc::clone(&self.clock),
            kind,
            size_attr,
            wire_size_attr,
            wire_bytes: 0,
            emitted: false,
        };

        // Streaming tee: forward each frame downstream as it arrives while buffering
        // the captured copy; never block forwarding on capture. The buffer is redacted
        // once at finalize (so a secret split across frames is still caught) before it
        // is written to the blob store. Mid-stream client disconnect is handled by
        // TeeState's Drop.
        let teed = futures_util::stream::unfold(state, |mut state| async move {
            let upstream = state.upstream.as_mut()?;
            match upstream.next().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        state.capture(data);
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

impl Drop for CaptureHandler {
    /// A clone dropped with its exchange still open (no response, no upstream-error
    /// terminal) means the exchange ended without a terminal record — the client
    /// aborted, capture ended mid-flight, or a policy short-circuit closed it after
    /// its request event. Emit the terminal `http.abort` so no captured request
    /// dangles ambiguously. `try_send`, since Drop cannot await: losing this
    /// best-effort marker under backpressure is acceptable; blocking Drop is not.
    fn drop(&mut self) {
        let reason = self.abort_reason.take().unwrap_or("incomplete");
        if let Some(raw) = self.take_abort_signal(reason, None) {
            let _ = self.signal_tx.try_send(Ok(raw));
        }
    }
}

/// State for one streaming body tee. The captured copy is buffered (bounded by
/// `max_capture_bytes`) and redacted as a whole at finalize, so a secret straddling
/// two DATA frames is still caught. `Drop` finalizes a partial blob and emits its
/// signal if the client disconnects before the body ends.
struct TeeState {
    upstream: Option<BodyStream<Body>>,
    blob_store: Arc<dyn BlobStore>,
    /// Captured response bytes, bounded by `max_capture_bytes`. Redacted once at
    /// finalize; never the bytes forwarded downstream.
    captured: Vec<u8>,
    /// Cap on captured bytes; `None` is unlimited. Forwarding is unaffected.
    max_capture_bytes: Option<u64>,
    /// Set when capture was cut short (cap hit or upstream error).
    truncated: bool,
    /// Scrubs secrets from the buffered capture before it reaches the blob; the
    /// bytes forwarded downstream are never touched.
    redaction: RedactionPolicy,
    /// Credentials injected into this exchange, scrubbed as exact literals from the
    /// captured copy so they never reach telemetry (even if pattern redaction is off).
    injected_secrets: Vec<zeroize::Zeroizing<String>>,
    /// Set once the cap is hit and further bytes stop being captured.
    capped: bool,
    media_type: Option<String>,
    attributes: Vec<(&'static str, String)>,
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
    kind: &'static str,
    size_attr: &'static str,
    /// Attribute name for the observed wire size ([`RESPONSE_WIRE_SIZE_ATTR`]).
    wire_size_attr: &'static str,
    /// Body bytes observed on the wire so far — counted past the capture cap, so a
    /// truncated capture still records the true transfer size.
    wire_bytes: u64,
    emitted: bool,
}

impl TeeState {
    fn capture(&mut self, data: &[u8]) {
        // The wire count keeps running past the capture cap: the stored copy is
        // bounded, the true transfer size is not.
        self.wire_bytes = self.wire_bytes.saturating_add(data.len() as u64);
        if self.capped {
            return;
        }
        let data = match self.max_capture_bytes {
            Some(cap) => {
                let remaining = cap.saturating_sub(self.captured.len() as u64);
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
        self.captured.extend_from_slice(data);
    }

    /// Idempotent so the end-of-stream emit and the Drop fallback can't double-send.
    async fn emit(&mut self, truncated: bool) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        let raw = finalize_tee(FinalizeTee {
            clock: &self.clock,
            kind: self.kind,
            size_attr: self.size_attr,
            attributes: std::mem::take(&mut self.attributes),
            blob_store: self.blob_store.as_ref(),
            captured: std::mem::take(&mut self.captured),
            redaction: self.redaction,
            injected_secrets: std::mem::take(&mut self.injected_secrets),
            media_type: self.media_type.take(),
            truncated: truncated || self.truncated || self.capped,
            wire_size_attr: self.wire_size_attr,
            wire_bytes: self.wire_bytes,
        })
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
        let wire_size_attr = self.wire_size_attr;
        let wire_bytes = self.wire_bytes;
        let attributes = std::mem::take(&mut self.attributes);
        let blob_store = Arc::clone(&self.blob_store);
        let captured = std::mem::take(&mut self.captured);
        let redaction = self.redaction;
        let injected_secrets = std::mem::take(&mut self.injected_secrets);
        let media_type = self.media_type.take();
        let signal_tx = self.signal_tx.clone();
        tokio::spawn(async move {
            let raw = finalize_tee(FinalizeTee {
                clock: &clock,
                kind,
                size_attr,
                attributes,
                blob_store: blob_store.as_ref(),
                captured,
                redaction,
                injected_secrets,
                media_type,
                truncated: true,
                wire_size_attr,
                wire_bytes,
            })
            .await;
            let _ = signal_tx.send(Ok(raw)).await;
        });
    }
}

/// Inputs to [`finalize_tee`]: the buffered capture plus the metadata needed to
/// redact, offload, and stamp one response body's signal.
struct FinalizeTee<'a> {
    clock: &'a HlcClock,
    kind: &'static str,
    size_attr: &'static str,
    attributes: Vec<(&'static str, String)>,
    blob_store: &'a dyn BlobStore,
    captured: Vec<u8>,
    redaction: RedactionPolicy,
    injected_secrets: Vec<zeroize::Zeroizing<String>>,
    media_type: Option<String>,
    truncated: bool,
    /// Attribute name for the observed wire size ([`RESPONSE_WIRE_SIZE_ATTR`]).
    wire_size_attr: &'static str,
    /// Body bytes observed on the wire (counted past the capture cap); on a
    /// mid-stream abort, what was seen before the stream ended.
    wire_bytes: u64,
}

/// Redact `body` with the configured pattern policy plus the exchange's injected
/// credentials as exact literals (scrubbed even when pattern redaction is disabled,
/// so an injected secret can never reach telemetry).
fn redact_with_injected(
    redaction: RedactionPolicy,
    body: Bytes,
    secrets: &[zeroize::Zeroizing<String>],
) -> Bytes {
    if secrets.is_empty() {
        return redaction.redact_body(body);
    }
    let literals: Vec<&[u8]> = secrets.iter().map(|secret| secret.as_bytes()).collect();
    redaction.redact_body_with_literals(body, &literals)
}

/// Redact the buffered capture once, offload it to the blob store, and build the
/// offloaded (or metadata-only) signal. The size attribute reports the stored
/// (post-redaction) byte count, consistent with the truncation path; the wire-size
/// attribute reports the bytes actually observed on the wire (pre-cap,
/// pre-redaction), so truncation never loses the true transfer size.
async fn finalize_tee(args: FinalizeTee<'_>) -> RawSignal {
    let FinalizeTee {
        clock,
        kind,
        size_attr,
        mut attributes,
        blob_store,
        captured,
        redaction,
        injected_secrets,
        media_type,
        truncated,
        wire_size_attr,
        wire_bytes,
    } = args;

    let captured = Bytes::from(captured);
    let stored = redact_with_injected(redaction, captured, &injected_secrets);
    let host = attributes
        .iter()
        .find_map(|(key, value)| (*key == "http.host").then(|| value.clone()));
    append_llm_capture_attributes(
        &mut attributes,
        host.as_deref(),
        media_type.as_deref(),
        &stored,
        LlmCaptureDirection::Response,
    );
    let size = stored.len() as u64;
    let payload_ref = match offload_bytes(blob_store, &stored, media_type.as_deref()).await {
        Ok(payload_ref) => Some(payload_ref),
        Err(error) => {
            eprintln!("hiloop-interceptor: proxy response blob offload failed: {error}");
            None
        }
    };

    let mut raw = RawSignal::new(PROXY_SOURCE, kind, clock.tick(), Bytes::new())
        .with_attribute(size_attr, size.to_string())
        .with_attribute(wire_size_attr, wire_bytes.to_string());
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

/// Render matched anomaly flags as a stable, comma-separated list of rule names for the
/// `anomaly.flagged` attribute.
fn join_flag_names(flags: &[AnomalyFlag]) -> String {
    flags
        .iter()
        .map(|flag| flag.rule.name())
        .collect::<Vec<_>>()
        .join(",")
}

/// Mint a globally unique exchange id. A ULID rather than a process-local
/// counter: several wrapper invocations can emit into one run (sibling
/// commands sharing the same run identity), and a per-process counter would
/// restart at zero in each, colliding their exchanges under one id.
fn next_exchange_id() -> String {
    ulid::Ulid::new().to_string()
}

/// A `403 Forbidden` short-circuit returned for an egress-denied destination.
fn forbidden() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::empty())
        .expect("static 403 response builds")
}

/// A `502 Bad Gateway` short-circuit returned when an injected credential could not be
/// resolved — the request is failed closed rather than forwarded without it.
fn bad_gateway() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::empty())
        .expect("static 502 response builds")
}

impl HttpHandler for CaptureHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        self.on_request(request).await
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        self.on_response(response)
    }

    /// An upstream forwarding failure fails closed with `502` (hudsucker's default),
    /// so a request whose origin connection broke never leaks downstream as success —
    /// and the exchange reaches its terminal record: an `http.abort` event naming
    /// whether the origin was unreachable or the forward leg broke mid-exchange.
    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        error: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        eprintln!("hiloop-interceptor: proxy upstream request failed: {error}");
        let reason = if error.is_connect() {
            "upstream_connect_error"
        } else {
            "upstream_error"
        };
        self.on_upstream_error(reason, error_chain_message(&error))
            .await;
        bad_gateway()
    }
}

/// Fold an error and its source chain into one `: `-separated line. hyper's legacy
/// client `Display` names only the failing phase (e.g. `client error (Connect)`);
/// the actionable cause lives down the chain.
fn error_chain_message(error: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    while let Some(hop) = source {
        parts.push(hop.to_string());
        source = hop.source();
    }
    parts.join(": ")
}

/// Render a request target for telemetry with the scheme-default port stripped
/// (`https://host:443/x` → `https://host/x`). hudsucker rebuilds an intercepted
/// HTTP/1.1 request's URI from the CONNECT authority (which carries an explicit
/// `:443`), while an HTTP/2 request keeps its port-less `:authority` — without
/// normalization the same endpoint splits into two target values.
fn telemetry_target(uri: &hudsucker::hyper::Uri) -> String {
    let default_port: u16 = match uri.scheme_str() {
        Some("https") => 443,
        Some("http") => 80,
        _ => return uri.to_string(),
    };
    let (Some(port), Some(authority)) = (uri.port_u16(), uri.authority()) else {
        return uri.to_string();
    };
    if port != default_port {
        return uri.to_string();
    }
    let scheme = uri.scheme_str().unwrap_or_default();
    let host = authority
        .as_str()
        .strip_suffix(&format!(":{port}"))
        .unwrap_or(authority.as_str());
    let path = uri.path_and_query().map_or("", |pq| pq.as_str());
    format!("{scheme}://{host}{path}")
}

/// Canonicalize a request's destination authority — the CONNECT authority for a
/// CONNECT, otherwise the URI host or `Host` header. `None` when no host is present or
/// it fails canonicalization.
fn canonical_authority(request: &Request<Body>) -> Option<Destination> {
    let raw = if request.method() == Method::CONNECT {
        request
            .uri()
            .authority()
            .map(ToString::to_string)
            .or_else(|| request.uri().host().map(ToOwned::to_owned))
    } else {
        request_host(request.uri(), request.headers())
    }?;
    canonicalize_host(&raw).ok()
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

fn telemetry_host(host: &str) -> String {
    canonicalize_host(host).map_or_else(|_| host.to_owned(), |destination| destination.host_str())
}

#[derive(Clone, Copy)]
enum LlmCaptureDirection {
    Request,
    Response,
}

#[derive(Default)]
struct LlmCaptureMetadata {
    model: Option<String>,
    tool_call: Option<String>,
}

impl LlmCaptureMetadata {
    fn is_complete(&self) -> bool {
        self.model.is_some() && self.tool_call.is_some()
    }

    fn merge(&mut self, other: LlmCaptureMetadata) {
        if self.model.is_none() {
            self.model = other.model;
        }
        if self.tool_call.is_none() {
            self.tool_call = other.tool_call;
        }
    }
}

fn append_llm_capture_attributes(
    attributes: &mut Vec<(&'static str, String)>,
    host: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
    direction: LlmCaptureDirection,
) {
    let Some(host) = host else {
        return;
    };
    if !is_llm_host(host) {
        return;
    }

    let metadata = llm_capture_metadata(content_type, body, direction);
    let model_attr = match direction {
        LlmCaptureDirection::Request => GEN_AI_REQUEST_MODEL_ATTR,
        LlmCaptureDirection::Response => GEN_AI_RESPONSE_MODEL_ATTR,
    };
    if let Some(model) = metadata.model {
        push_attribute_once(attributes, model_attr, model);
    }
    if let Some(tool_call) = metadata.tool_call {
        push_attribute_once(attributes, TOOL_CALL_ATTR, tool_call);
    }
}

fn push_attribute_once(
    attributes: &mut Vec<(&'static str, String)>,
    key: &'static str,
    value: String,
) {
    if attributes.iter().any(|(existing, _)| *existing == key) {
        return;
    }
    attributes.push((key, value));
}

fn llm_capture_metadata(
    content_type: Option<&str>,
    body: &[u8],
    direction: LlmCaptureDirection,
) -> LlmCaptureMetadata {
    if body.is_empty() {
        return LlmCaptureMetadata::default();
    }
    if is_event_stream_media_type(content_type) {
        return llm_metadata_from_event_stream(body, direction);
    }
    if is_json_media_type(content_type) || body_looks_json(body) {
        return llm_metadata_from_json_bytes(body, direction);
    }
    LlmCaptureMetadata::default()
}

fn llm_metadata_from_event_stream(
    body: &[u8],
    direction: LlmCaptureDirection,
) -> LlmCaptureMetadata {
    let mut metadata = LlmCaptureMetadata::default();
    for line in body.split(|byte| *byte == b'\n') {
        let line = trim_ascii(line);
        let Some(data) = line.strip_prefix(b"data:") else {
            continue;
        };
        let data = trim_ascii(data);
        if data.is_empty() || data == b"[DONE]" {
            continue;
        }
        metadata.merge(llm_metadata_from_json_bytes(data, direction));
        if metadata.is_complete() {
            break;
        }
    }
    metadata
}

fn llm_metadata_from_json_bytes(body: &[u8], direction: LlmCaptureDirection) -> LlmCaptureMetadata {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return LlmCaptureMetadata::default();
    };
    llm_metadata_from_json_value(&value, direction)
}

fn llm_metadata_from_json_value(
    value: &Value,
    direction: LlmCaptureDirection,
) -> LlmCaptureMetadata {
    let tool_count = match direction {
        LlmCaptureDirection::Request => 0,
        LlmCaptureDirection::Response => count_tool_calls(value, 0),
    };
    LlmCaptureMetadata {
        model: value
            .get("model")
            .and_then(Value::as_str)
            .and_then(safe_llm_metadata_value),
        tool_call: (tool_count > 0).then(|| tool_count.min(999).to_string()),
    }
}

fn count_tool_calls(value: &Value, depth: usize) -> usize {
    if depth > 8 {
        return 0;
    }
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| count_tool_calls(item, depth + 1))
            .sum(),
        Value::Object(map) => {
            let mut count = 0;
            if let Some(child) = map.get("tool_calls") {
                count += count_actual_tool_call_entries(child);
            }
            if matches!(map.get("function_call"), Some(child) if !child.is_null()) {
                count += 1;
            }
            if matches!(
                map.get("type").and_then(Value::as_str),
                Some("function_call" | "tool_use")
            ) {
                count += 1;
            }
            for key in [
                "choices", "message", "messages", "content", "output", "delta", "item", "response",
            ] {
                if let Some(child) = map.get(key) {
                    count += count_tool_calls(child, depth + 1);
                }
            }
            count
        }
        _ => 0,
    }
}

fn count_actual_tool_call_entries(value: &Value) -> usize {
    match value {
        Value::Array(items) => items.len(),
        Value::Object(map) if !map.is_empty() => 1,
        _ => 0,
    }
}

fn safe_llm_metadata_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_LLM_METADATA_VALUE_BYTES {
        return None;
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
    }) {
        Some(value.to_owned())
    } else {
        None
    }
}

fn is_json_media_type(content_type: Option<&str>) -> bool {
    media_type(content_type)
        .is_some_and(|value| value == "application/json" || value.ends_with("+json"))
}

fn is_event_stream_media_type(content_type: Option<&str>) -> bool {
    media_type(content_type).is_some_and(|value| value == "text/event-stream")
}

fn media_type(content_type: Option<&str>) -> Option<String> {
    content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn body_looks_json(body: &[u8]) -> bool {
    matches!(trim_ascii(body).first().copied(), Some(b'{' | b'['))
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first()
        && first.is_ascii_whitespace()
    {
        value = rest;
    }
    while let Some((last, rest)) = value.split_last()
        && last.is_ascii_whitespace()
    {
        value = rest;
    }
    value
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
        if raw.source == PROXY_SOURCE
            && matches!(
                raw.kind.as_str(),
                REQUEST_KIND | RESPONSE_KIND | ABORT_KIND | EGRESS_DENIED_KIND
            )
        {
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

        let mut event = Event::new(context.run_context(), raw.observed_at, signal, name);
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
    let host = telemetry_host(host);
    LLM_HOSTS
        .iter()
        .any(|known| host == *known || host.ends_with(&format!(".{known}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::testing::MemoryBlobStore;
    use hiloop_core::event::{AttributeValue, PayloadDigest};
    use hiloop_core::identity::{Hlc, RunContext};
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
        handler_with(max_capture_bytes, RedactionPolicy::default())
    }

    fn handler_with(
        max_capture_bytes: Option<u64>,
        redaction: RedactionPolicy,
    ) -> (
        CaptureHandler,
        mpsc::Receiver<Result<RawSignal, SourceError>>,
        Arc<MemoryBlobStore>,
    ) {
        handler_with_egress(
            max_capture_bytes,
            redaction,
            Arc::new(EgressPolicy::default()),
            None,
        )
    }

    fn handler_with_egress(
        max_capture_bytes: Option<u64>,
        redaction: RedactionPolicy,
        egress: Arc<EgressPolicy>,
        injector: Option<SecretInjector>,
    ) -> (
        CaptureHandler,
        mpsc::Receiver<Result<RawSignal, SourceError>>,
        Arc<MemoryBlobStore>,
    ) {
        handler_with_anomaly(
            max_capture_bytes,
            redaction,
            egress,
            Arc::new(AnomalyConfig::default()),
            injector,
        )
    }

    fn handler_with_anomaly(
        max_capture_bytes: Option<u64>,
        redaction: RedactionPolicy,
        egress: Arc<EgressPolicy>,
        anomaly: Arc<AnomalyConfig>,
        injector: Option<SecretInjector>,
    ) -> (
        CaptureHandler,
        mpsc::Receiver<Result<RawSignal, SourceError>>,
        Arc<MemoryBlobStore>,
    ) {
        let (tx, rx) = mpsc::channel(8);
        let store = Arc::new(MemoryBlobStore::default());
        let handler = CaptureHandler::new(
            tx,
            Arc::new(HlcClock::new()),
            store.clone(),
            max_capture_bytes,
            redaction,
            egress,
            anomaly,
            injector,
        );
        (handler, rx, store)
    }

    fn expected_digest(body: &[u8]) -> String {
        format!("blake3:{}", blake3::hash(body).to_hex())
    }

    /// Unwrap an `on_request` outcome that should have been forwarded (not denied).
    fn expect_forwarded(outcome: RequestOrResponse) -> Request<Body> {
        match outcome {
            RequestOrResponse::Request(request) => request,
            RequestOrResponse::Response(response) => {
                panic!(
                    "expected a forwarded request, got a {} response",
                    response.status()
                )
            }
        }
    }

    /// Unwrap an `on_request` outcome that should have been short-circuited (denied).
    fn expect_response(outcome: RequestOrResponse) -> Response<Body> {
        match outcome {
            RequestOrResponse::Response(response) => response,
            RequestOrResponse::Request(_) => panic!("expected a short-circuit response"),
        }
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
        let digest = PayloadDigest::new("blake3:abc").expect("digest");
        let raw = proxy_signal(
            REQUEST_KIND,
            &[
                ("http.method", "POST"),
                ("http.host", "example.com"),
                ("http.target", "/v1/thing"),
            ],
        )
        .with_payload_ref(PayloadRef::new(digest));
        let context = NormalizationContext::new(RunContext::new_local_root());

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
            Some("blake3:abc")
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
        let context = NormalizationContext::new(RunContext::new_local_root());

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
        assert!(is_llm_host("api.openai.com:443"));
        assert!(is_llm_host("eu.api.openai.com"));
        assert!(is_llm_host("eu.api.openai.com:443"));
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

    #[test]
    fn generated_server_cert_contains_authority_key_identifier() {
        let ca = ProxyCa::generate().expect("generate CA");
        let cert = ca
            .authority
            .gen_cert(&Authority::from_static("api.openai.com"));
        let (_, parsed) =
            x509_parser::parse_x509_certificate(cert.as_ref()).expect("parse generated cert");

        let authority_key_identifier = parsed.extensions().iter().find_map(|extension| {
            if let x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(identifier) =
                extension.parsed_extension()
            {
                Some(identifier)
            } else {
                None
            }
        });

        assert!(
            authority_key_identifier
                .and_then(|identifier| identifier.key_identifier.as_ref())
                .is_some(),
            "generated server cert must include Authority Key Identifier"
        );
    }

    #[test]
    fn generated_server_cert_uses_ip_san_for_ip_literal_authorities() {
        let ca = ProxyCa::generate().expect("generate CA");
        let cert = ca.authority.gen_cert(&Authority::from_static("127.0.0.1"));
        let (_, parsed) =
            x509_parser::parse_x509_certificate(cert.as_ref()).expect("parse generated cert");

        let subject_alt_names = parsed
            .extensions()
            .iter()
            .find_map(|extension| {
                if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                    extension.parsed_extension()
                {
                    Some(&san.general_names)
                } else {
                    None
                }
            })
            .expect("generated server cert has SAN extension");

        let has_ip_san = subject_alt_names.iter().any(|name| {
            matches!(
                name,
                x509_parser::extensions::GeneralName::IPAddress(bytes)
                    if *bytes == [127, 0, 0, 1].as_slice()
            )
        });
        let has_dns_ip_san = subject_alt_names.iter().any(|name| {
            matches!(
                name,
                x509_parser::extensions::GeneralName::DNSName(value) if *value == "127.0.0.1"
            )
        });

        assert!(
            has_ip_san,
            "generated server cert must encode IP literals as iPAddress SANs"
        );
        assert!(
            !has_dns_ip_san,
            "generated server cert must not encode IP literals as dNSName SANs"
        );
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
        let forwarded = expect_forwarded(handler.on_request(request).await);
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
        let forwarded = expect_forwarded(handler.on_request(request).await);
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
            RESPONSE_WIRE_SIZE_ATTR,
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
            RESPONSE_WIRE_SIZE_ATTR,
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
            signal
                .attributes
                .get(RESPONSE_WIRE_SIZE_ATTR)
                .map(String::as_str),
            Some("21"),
            "truncation must not lose the true transfer size"
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
            RESPONSE_WIRE_SIZE_ATTR,
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
        assert_eq!(
            signal
                .attributes
                .get(RESPONSE_WIRE_SIZE_ATTR)
                .map(String::as_str),
            Some("14"),
            "wire size equals the stored size when nothing is cut"
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

        let forwarded = expect_forwarded(handler.on_request(request).await);
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
        assert_eq!(
            signal
                .attributes
                .get(REQUEST_WIRE_SIZE_ATTR)
                .map(String::as_str),
            Some("5"),
            "truncation must not lose the true transfer size"
        );
    }

    #[tokio::test]
    async fn content_encoding_rides_along_on_both_directions() {
        // Stored bytes are byte-exact wire bytes — often content-encoded — while the
        // content-type names the *decoded* media type; without the encoding attribute
        // a gzip body is semantically opaque.
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/upload")
            .header(CONTENT_ENCODING, "gzip")
            .body(Body::from(Bytes::from_static(b"\x1f\x8b\x08fake")))
            .expect("request");
        let _forwarded = expect_forwarded(handler.on_request(request).await);
        let request_signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            request_signal
                .attributes
                .get(REQUEST_CONTENT_ENCODING_ATTR)
                .map(String::as_str),
            Some("gzip")
        );

        let response = Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
            .header(CONTENT_ENCODING, "gzip")
            .body(streaming_body(&[b"\x1f\x8b\x08fake"]))
            .expect("response");
        let teed = handler.on_response(response);
        drain_body(teed.into_body()).await;
        let response_signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            response_signal
                .attributes
                .get(RESPONSE_CONTENT_ENCODING_ATTR)
                .map(String::as_str),
            Some("gzip")
        );
        assert_eq!(
            response_signal
                .attributes
                .get("http.response.content_type")
                .map(String::as_str),
            Some("application/vnd.pypi.simple.v1+json"),
            "the decoded media type still rides along unchanged"
        );
    }

    #[tokio::test]
    async fn content_encoding_attribute_is_absent_for_identity_bodies() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/plain")
            .body(Body::empty())
            .expect("request");
        let _forwarded = expect_forwarded(handler.on_request(request).await);
        let signal = rx.recv().await.expect("signal").expect("raw");
        assert!(
            !signal
                .attributes
                .contains_key(REQUEST_CONTENT_ENCODING_ATTR),
            "no header, no attribute — never a synthesized `identity`"
        );
    }

    #[tokio::test]
    async fn anomalous_request_is_flagged_but_forwarded_in_audit_mode() {
        let anomaly = Arc::new(
            AnomalyConfig::enabled()
                .with_suspicious_content_types(["application/octet-stream".to_owned()]),
        );
        let (mut handler, mut rx, _store) = handler_with_anomaly(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            anomaly,
            None,
        );
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/upload")
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(Bytes::from_static(b"payload")))
            .expect("request");

        // Audit mode: the request is still forwarded with its full body.
        let forwarded = expect_forwarded(handler.on_request(request).await);
        let chunks = drain_body(forwarded.into_body()).await;
        assert_eq!(chunks.concat(), b"payload");

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.attributes.get(FLAGGED_ATTR).map(String::as_str),
            Some("suspicious_content_type")
        );
        assert!(
            !signal.attributes.contains_key(BLOCKED_ATTR),
            "audit mode must not mark the exchange blocked"
        );
    }

    #[tokio::test]
    async fn anomalous_request_is_blocked_in_block_mode() {
        let anomaly = Arc::new(
            AnomalyConfig::enabled()
                .with_suspicious_content_types(["application/octet-stream".to_owned()])
                .with_block_on_match(true),
        );
        let (mut handler, mut rx, _store) = handler_with_anomaly(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            anomaly,
            None,
        );
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/upload")
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(Bytes::from_static(b"payload")))
            .expect("request");

        // Block mode: the request is rejected with a 403 and never forwarded.
        let response = expect_response(handler.on_request(request).await);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // The flagged, blocked exchange is still recorded.
        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.attributes.get(FLAGGED_ATTR).map(String::as_str),
            Some("suspicious_content_type")
        );
        assert_eq!(
            signal.attributes.get(BLOCKED_ATTR).map(String::as_str),
            Some("true")
        );

        // The 403 short-circuit never reaches `on_response`, so the exchange's
        // terminal record is the Drop-emitted abort, named with the real reason.
        drop(handler);
        let abort = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(abort.kind, ABORT_KIND);
        assert_eq!(
            abort.attributes.get(EXCHANGE_ID_ATTR),
            signal.attributes.get(EXCHANGE_ID_ATTR),
            "the abort closes the blocked exchange"
        );
        assert_eq!(
            abort.attributes.get(ABORT_REASON_ATTR).map(String::as_str),
            Some("blocked")
        );
    }

    /// Regression test for dangling aborted exchanges: an upstream failure must
    /// produce a terminal `http.abort` sharing the request's exchange id and
    /// carrying the method/target actually sent (was: no terminal event at all —
    /// hudsucker calls `handle_error`, which only logged).
    #[tokio::test]
    async fn upstream_error_emits_terminal_abort_with_exchange_context() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("POST")
            .uri("https://api.openai.com:443/v1/responses")
            .body(Body::from(Bytes::from_static(b"{}")))
            .expect("request");
        let _forwarded = expect_forwarded(handler.on_request(request).await);
        let request_signal = rx.recv().await.expect("signal").expect("raw");
        let exchange_id = request_signal
            .attributes
            .get(EXCHANGE_ID_ATTR)
            .cloned()
            .expect("exchange id");

        handler
            .on_upstream_error(
                "upstream_connect_error",
                "client error (Connect): tcp connect error: Connection refused".to_owned(),
            )
            .await;

        let abort = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(abort.kind, ABORT_KIND);
        assert_eq!(
            abort.attributes.get(EXCHANGE_ID_ATTR),
            Some(&exchange_id),
            "the abort joins the dangling request"
        );
        assert_eq!(
            abort.attributes.get(ABORT_REASON_ATTR).map(String::as_str),
            Some("upstream_connect_error")
        );
        assert_eq!(
            abort.attributes.get("http.method").map(String::as_str),
            Some("POST"),
            "the method actually sent is recorded, never a placeholder"
        );
        assert_eq!(
            abort.attributes.get("http.target").map(String::as_str),
            Some("https://api.openai.com/v1/responses")
        );
        assert_eq!(
            abort.attributes.get("http.host").map(String::as_str),
            Some("api.openai.com")
        );
        assert!(
            abort
                .attributes
                .get(ABORT_DETAIL_ATTR)
                .expect("detail")
                .contains("Connection refused")
        );

        // The terminal is emitted exactly once: dropping the handler afterwards
        // must not mint a second abort for the same exchange.
        drop(handler);
        assert!(rx.recv().await.is_none(), "no duplicate terminal event");
    }

    #[tokio::test]
    async fn dropped_open_exchange_emits_incomplete_abort() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/stream")
            .body(Body::empty())
            .expect("request");
        let _forwarded = expect_forwarded(handler.on_request(request).await);
        let request_signal = rx.recv().await.expect("signal").expect("raw");

        // Client abort / capture end: the clone is dropped before any response.
        drop(handler);

        let abort = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(abort.kind, ABORT_KIND);
        assert_eq!(
            abort.attributes.get(EXCHANGE_ID_ATTR),
            request_signal.attributes.get(EXCHANGE_ID_ATTR)
        );
        assert_eq!(
            abort.attributes.get(ABORT_REASON_ATTR).map(String::as_str),
            Some("incomplete")
        );
    }

    #[tokio::test]
    async fn completed_exchange_emits_no_abort() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/ok")
            .body(Body::empty())
            .expect("request");
        let _forwarded = expect_forwarded(handler.on_request(request).await);
        let response = Response::builder()
            .status(200)
            .body(streaming_body(&[b"done"]))
            .expect("response");
        let teed = handler.on_response(response);
        drain_body(teed.into_body()).await;
        drop(handler);

        let kinds: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|signal| signal.expect("raw").kind)
            .collect();
        assert_eq!(
            kinds,
            [REQUEST_KIND, RESPONSE_KIND],
            "a request → response exchange must not grow a terminal abort"
        );
    }

    #[tokio::test]
    async fn captured_target_strips_the_scheme_default_port() {
        // hudsucker rebuilds an intercepted HTTP/1.1 URI from the CONNECT authority
        // (`host:443`) while HTTP/2 keeps the port-less `:authority`; the captured
        // target must not split one endpoint into two values.
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("GET")
            .uri("https://api.openai.com:443/v1/responses")
            .body(Body::empty())
            .expect("request");
        let _forwarded = expect_forwarded(handler.on_request(request).await);
        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.attributes.get("http.target").map(String::as_str),
            Some("https://api.openai.com/v1/responses")
        );
    }

    #[test]
    fn telemetry_target_strips_only_the_scheme_default_port() {
        let cases: &[(&str, &str)] = &[
            (
                "https://api.openai.com:443/v1/responses",
                "https://api.openai.com/v1/responses",
            ),
            ("http://example.com:80/x", "http://example.com/x"),
            ("https://example.com:8443/x", "https://example.com:8443/x"),
            ("http://example.com:8080/x", "http://example.com:8080/x"),
            ("https://example.com/x", "https://example.com/x"),
            ("https://[::1]:443/x", "https://[::1]/x"),
            ("/origin-form-only", "/origin-form-only"),
        ];
        for (input, expected) in cases {
            let uri: hudsucker::hyper::Uri = input.parse().expect("uri");
            assert_eq!(telemetry_target(&uri), *expected, "for {input}");
        }
    }

    #[tokio::test]
    async fn normalizes_abort_as_a_terminal_event() {
        let raw = proxy_signal(
            ABORT_KIND,
            &[
                ("http.host", "api.openai.com"),
                (ABORT_REASON_ATTR, "upstream_connect_error"),
            ],
        );
        let context = NormalizationContext::new(RunContext::new_local_root());
        let outcome = ProxyNormalizer
            .normalize(&context, raw)
            .await
            .expect("normalize");
        let events = outcome.into_events();
        assert_eq!(events[0].name.as_str(), "http.abort");
        assert_eq!(events[0].signal, SignalType::Llm);
    }

    #[tokio::test]
    async fn clean_request_is_not_flagged_when_anomaly_enabled() {
        let anomaly = Arc::new(AnomalyConfig::enabled().with_block_on_match(true));
        let (mut handler, mut rx, _store) = handler_with_anomaly(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            anomaly,
            None,
        );
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/chat")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(Bytes::from_static(b"{\"prompt\":\"hi\"}")))
            .expect("request");

        let forwarded = expect_forwarded(handler.on_request(request).await);
        drain_body(forwarded.into_body()).await;

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert!(
            !signal.attributes.contains_key(FLAGGED_ATTR),
            "an ordinary JSON request must not be flagged"
        );
    }

    #[tokio::test]
    async fn anomaly_inspects_original_body_not_the_truncated_capture() {
        // A capture cap set BELOW both the upload threshold and the base64 floor must not
        // truncate a large upload out of detection: inspection runs on the original body.
        let upload_threshold: u64 = 4096;
        let base64_floor: u64 = 4096;
        let anomaly = Arc::new(
            AnomalyConfig::enabled()
                .with_max_upload_bytes(upload_threshold)
                .with_min_base64_bytes(base64_floor),
        );
        // Cap capture at 64 bytes — far below both thresholds.
        let (mut handler, mut rx, store) = handler_with_anomaly(
            Some(64),
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            anomaly,
            None,
        );
        // A large, all-base64-alphabet body: without inspecting the original it would be
        // truncated to 64 bytes and evade both the upload and base64 rules.
        let original_len = 8192usize;
        let payload = Bytes::from(vec![b'A'; original_len]);
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/upload")
            .body(Body::from(payload.clone()))
            .expect("request");

        // The full body is still forwarded upstream untouched.
        let forwarded = expect_forwarded(handler.on_request(request).await);
        let chunks = drain_body(forwarded.into_body()).await;
        assert_eq!(chunks.concat().len(), original_len);

        let signal = rx.recv().await.expect("signal").expect("raw");
        let flagged = signal
            .attributes
            .get(FLAGGED_ATTR)
            .map(String::as_str)
            .expect("a large upload must still be flagged despite the tiny capture cap");
        assert!(
            flagged.contains("upload_shaped_request"),
            "upload rule must evaluate the original length, got: {flagged}"
        );
        assert!(
            flagged.contains("large_base64_blob"),
            "base64 floor must evaluate the original body, got: {flagged}"
        );

        // The captured/offloaded copy stays truncated to the cap — inspection is
        // read-only and never widens what reaches telemetry.
        let stored = store.blobs();
        assert_eq!(
            stored.len(),
            1,
            "exactly one request body should be offloaded"
        );
        assert_eq!(
            stored[0].1.len(),
            64,
            "the captured copy stays truncated to max_capture_bytes"
        );
    }

    #[test]
    fn normalizer_rejects_unsupported_source() {
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(b"hello"),
        );
        assert_eq!(
            ProxyNormalizer.supports(&raw),
            NormalizerSupport::Unsupported
        );
    }

    #[test]
    fn normalizer_accepts_response_kind() {
        let raw = proxy_signal(RESPONSE_KIND, &[("http.status_code", "200")]);
        assert_eq!(ProxyNormalizer.supports(&raw), NormalizerSupport::Exact);
    }

    #[tokio::test]
    async fn normalizer_carries_all_raw_attributes() {
        let raw = proxy_signal(
            REQUEST_KIND,
            &[
                ("http.method", "GET"),
                ("http.target", "/api"),
                ("custom.attr", "value"),
            ],
        );
        let context = NormalizationContext::new(RunContext::new_local_root());

        let outcome = ProxyNormalizer
            .normalize(&context, raw)
            .await
            .expect("normalize");
        let events = outcome.into_events();

        assert_eq!(
            events[0]
                .attributes
                .get(&AttributeKey::new("custom.attr").expect("key")),
            Some(&AttributeValue::String("value".to_owned()))
        );
    }

    #[test]
    fn proxy_normalizer_descriptor_is_stable() {
        let n = ProxyNormalizer;
        assert_eq!(n.descriptor().name(), "proxy-http");
        assert_eq!(n.descriptor().output_schema_version(), "hiloop.event.v1");
    }

    #[tokio::test]
    async fn request_with_content_type_records_it() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .header("content-type", "application/json")
            .body(Body::from(Bytes::from_static(b"{}")))
            .expect("request");

        let forwarded = expect_forwarded(handler.on_request(request).await);
        drain_body(forwarded.into_body()).await;

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal
                .attributes
                .get("http.request.content_type")
                .map(String::as_str),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn request_host_falls_back_to_header() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("GET")
            .uri("/path-only")
            .header("host", "fallback.example.com")
            .body(Body::empty())
            .expect("request");

        let forwarded = expect_forwarded(handler.on_request(request).await);
        drain_body(forwarded.into_body()).await;

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.attributes.get("http.host").map(String::as_str),
            Some("fallback.example.com")
        );
    }

    #[tokio::test]
    async fn brokered_llm_request_records_safe_model_without_tool_definition_metadata() {
        let url = stub_broker("sk-real-secret-value").await;
        let injector = injector_for(&url, "api.openai.com");
        let (mut handler, mut rx, store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            Some(injector),
        );
        let body = Bytes::from_static(
            br#"{"model":"gpt-5-codex","messages":[{"role":"user","content":"do not leak this prompt"}],"tools":[{"type":"function","function":{"name":"run_shell","description":"do not leak this description"}}],"metadata":{"echo":"sk-real-secret-value"}}"#,
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header(CONTENT_TYPE, "application/json")
            .header(HOST, "api.openai.com:443")
            .header("authorization", "Bearer hil-secret://openai-prod")
            .body(Body::from(body.clone()))
            .expect("request");

        let forwarded = expect_forwarded(handler.on_request(request).await);
        assert_eq!(
            forwarded
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer sk-real-secret-value")
        );
        assert_eq!(drain_body(forwarded.into_body()).await.concat(), body);

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.attributes.get("http.host").map(String::as_str),
            Some("api.openai.com")
        );
        assert_eq!(
            signal
                .attributes
                .get(GEN_AI_REQUEST_MODEL_ATTR)
                .map(String::as_str),
            Some("gpt-5-codex")
        );
        assert!(!signal.attributes.contains_key(TOOL_CALL_ATTR));
        for forbidden in [
            "do not leak this prompt",
            "do not leak this description",
            "run_shell",
            "sk-real-secret-value",
        ] {
            assert!(
                signal
                    .attributes
                    .values()
                    .all(|value| !value.contains(forbidden)),
                "attributes must not include {forbidden}"
            );
        }
        let blob = &store.blobs()[0].1;
        assert!(
            !blob
                .windows(20)
                .any(|window| window == b"sk-real-secret-value"),
            "captured blob must redact the brokered credential"
        );
    }

    #[tokio::test]
    async fn llm_metadata_is_not_extracted_for_non_llm_hosts() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/responses")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(Bytes::from_static(
                br#"{"model":"gpt-5-codex","tools":[{"type":"function","function":{"name":"run_shell"}}]}"#,
            )))
            .expect("request");

        let forwarded = expect_forwarded(handler.on_request(request).await);
        drain_body(forwarded.into_body()).await;

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert!(!signal.attributes.contains_key(GEN_AI_REQUEST_MODEL_ATTR));
        assert!(!signal.attributes.contains_key(TOOL_CALL_ATTR));
    }

    #[tokio::test]
    async fn llm_response_records_safe_metadata_and_normalizes_as_llm() {
        let (mut handler, mut rx, _store) = handler();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header(HOST, "api.openai.com:443")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(Bytes::from_static(
                br#"{"model":"gpt-5-codex","input":"hi"}"#,
            )))
            .expect("request");
        drain_body(expect_forwarded(handler.on_request(request).await).into_body()).await;
        let _request_signal = rx.recv().await.expect("request signal").expect("raw");

        let response = Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(Bytes::from_static(
                br#"{"model":"gpt-5-codex","choices":[{"message":{"tool_calls":[{"function":{"name":"run_shell","arguments":"{\"prompt\":\"do not leak\"}"}}]}}]}"#,
            )))
            .expect("response");
        let forwarded = handler.on_response(response);
        drain_body(forwarded.into_body()).await;

        let signal = rx.recv().await.expect("response signal").expect("raw");
        assert_eq!(
            signal.attributes.get("http.host").map(String::as_str),
            Some("api.openai.com")
        );
        assert_eq!(
            signal
                .attributes
                .get(GEN_AI_RESPONSE_MODEL_ATTR)
                .map(String::as_str),
            Some("gpt-5-codex")
        );
        assert_eq!(
            signal.attributes.get(TOOL_CALL_ATTR).map(String::as_str),
            Some("1")
        );
        for forbidden in ["run_shell", "do not leak"] {
            assert!(
                signal
                    .attributes
                    .values()
                    .all(|value| !value.contains(forbidden)),
                "attributes must not include {forbidden}"
            );
        }

        let context = NormalizationContext::new(RunContext::new_local_root());
        let outcome = ProxyNormalizer
            .normalize(&context, signal)
            .await
            .expect("normalize");
        let events = outcome.into_events();
        assert_eq!(events[0].signal, SignalType::Llm);
        assert_eq!(
            events[0]
                .attributes
                .get(&AttributeKey::new(GEN_AI_RESPONSE_MODEL_ATTR).expect("key")),
            Some(&AttributeValue::String("gpt-5-codex".to_owned()))
        );
    }

    #[test]
    fn count_tool_calls_walks_openai_responses_streaming_envelopes() {
        for body in [
            br#"data: {"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_1","name":"run_shell","arguments":"{}"}}"#.as_slice(),
            br#"data: {"type":"response.completed","response":{"output":[{"type":"function_call","call_id":"call_1","name":"run_shell","arguments":"{}"}]}}"#.as_slice(),
        ] {
            let metadata = llm_metadata_from_event_stream(body, LlmCaptureDirection::Response);
            assert_eq!(metadata.tool_call.as_deref(), Some("1"));
        }
    }

    #[test]
    fn is_llm_host_rejects_partial_prefix_match() {
        assert!(!is_llm_host("notapi.anthropic.com"));
        assert!(!is_llm_host("api.anthropic.com.evil.com"));
    }

    #[test]
    fn exchange_ids_are_unique_minted_ulids() {
        let first = next_exchange_id();
        let second = next_exchange_id();
        assert_ne!(first, second);
        for id in [&first, &second] {
            ulid::Ulid::from_string(id).expect("exchange id is a valid ULID");
        }
    }

    #[tokio::test]
    async fn request_body_secret_is_redacted_in_capture_but_forwarded_intact() {
        let (mut handler, mut rx, store) = handler_with(None, RedactionPolicy::enabled());
        let secret = b"Authorization: Bearer supersecret";
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/thing")
            .body(Body::from(Bytes::from_static(secret)))
            .expect("request");

        // The forwarded request must still carry the real credential upstream.
        let forwarded = expect_forwarded(handler.on_request(request).await);
        let chunks = drain_body(forwarded.into_body()).await;
        assert_eq!(
            chunks.concat(),
            secret,
            "forwarded body must be byte-for-byte intact"
        );

        // The persisted blob (the captured copy) must be scrubbed.
        let signal = rx.recv().await.expect("signal").expect("raw");
        let scrubbed = b"Authorization: [REDACTED]";
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(scrubbed).as_str())
        );
        let blobs = store.blobs();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].1, scrubbed);
    }

    #[tokio::test]
    async fn request_body_secret_is_persisted_verbatim_when_redaction_disabled() {
        let (mut handler, mut rx, store) = handler_with(None, RedactionPolicy::disabled());
        let secret = b"Bearer supersecret";
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/thing")
            .body(Body::from(Bytes::from_static(secret)))
            .expect("request");

        drain_body(expect_forwarded(handler.on_request(request).await).into_body()).await;

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(secret).as_str())
        );
        assert_eq!(store.blobs()[0].1, secret);
    }

    #[tokio::test]
    async fn response_body_secret_is_redacted_in_capture_but_forwarded_intact() {
        let (handler, mut rx, store) = handler_with(None, RedactionPolicy::enabled());
        let teed = handler.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            RESPONSE_WIRE_SIZE_ATTR,
            vec![("http.status_code", "200".to_owned())],
            None,
            streaming_body(&[b"token=sk-abc123 ", b"and AKIA0123456789ABCDEF"]),
        );

        // The client still receives the original, unredacted bytes.
        let chunks = drain_body(teed).await;
        assert_eq!(chunks.concat(), b"token=sk-abc123 and AKIA0123456789ABCDEF");

        let signal = rx.recv().await.expect("signal").expect("raw");
        let scrubbed = b"token=[REDACTED] and [REDACTED]";
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(scrubbed).as_str())
        );
        assert_eq!(store.blobs()[0].1, scrubbed);
    }

    #[tokio::test]
    async fn response_secret_split_across_frames_is_redacted_in_capture() {
        // Regression: per-frame redaction leaked a secret straddling two DATA frames.
        // The capture is buffered and redacted once at finalize, so the split token is
        // still caught; the forwarded frames stay byte-for-byte intact.
        let (handler, mut rx, store) = handler_with(None, RedactionPolicy::enabled());
        let teed = handler.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            RESPONSE_WIRE_SIZE_ATTR,
            vec![("http.status_code", "200".to_owned())],
            None,
            streaming_body(&[b"Bearer super", b"secret-token-here"]),
        );

        let chunks = drain_body(teed).await;
        assert_eq!(
            chunks.concat(),
            b"Bearer supersecret-token-here",
            "forwarded frames must be untouched"
        );

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(
            signal.payload_ref().map(|p| p.digest.as_str()),
            Some(expected_digest(b"[REDACTED]").as_str())
        );
        assert_eq!(store.blobs()[0].1, b"[REDACTED]");
    }

    #[tokio::test]
    async fn response_disabled_redaction_does_not_buffer_copy_for_forwarding() {
        // The disabled path still captures verbatim and forwards untouched; this guards
        // the zero-extra-copy disabled branch behaviorally.
        let (handler, mut rx, store) = handler_with(None, RedactionPolicy::disabled());
        let teed = handler.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            RESPONSE_WIRE_SIZE_ATTR,
            vec![("http.status_code", "200".to_owned())],
            None,
            streaming_body(&[b"Bearer super", b"secret"]),
        );
        let chunks = drain_body(teed).await;
        assert_eq!(chunks.concat(), b"Bearer supersecret");

        let _signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(store.blobs()[0].1, b"Bearer supersecret");
    }

    #[tokio::test]
    async fn response_body_is_persisted_verbatim_when_redaction_disabled() {
        let (handler, mut rx, store) = handler_with(None, RedactionPolicy::disabled());
        let teed = handler.tee_body(
            RESPONSE_KIND,
            "http.response.body_size",
            RESPONSE_WIRE_SIZE_ATTR,
            vec![("http.status_code", "200".to_owned())],
            None,
            streaming_body(&[b"Bearer supersecret"]),
        );
        drain_body(teed).await;

        let _signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(store.blobs()[0].1, b"Bearer supersecret");
    }

    // --- egress enforcement ---

    use crate::egress::EgressMode;

    fn deny_policy(domains: &[&str], cidrs: &[&str]) -> Arc<EgressPolicy> {
        Arc::new(
            EgressPolicy::new(
                EgressMode::Deny,
                domains.iter().map(|s| (*s).to_owned()),
                cidrs.iter().map(|s| (*s).to_owned()),
            )
            .expect("policy"),
        )
    }

    fn allow_block_policy(domains: &[&str]) -> Arc<EgressPolicy> {
        Arc::new(
            EgressPolicy::new(
                EgressMode::Allow,
                domains.iter().map(|s| (*s).to_owned()),
                [],
            )
            .expect("policy"),
        )
    }

    fn connect_request(authority: &str) -> Request<Body> {
        Request::builder()
            .method("CONNECT")
            .uri(authority)
            .body(Body::empty())
            .expect("connect request")
    }

    #[tokio::test]
    async fn allow_all_egress_is_a_no_op() {
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            None,
        );
        let request = Request::builder()
            .method("GET")
            .uri("http://anywhere.example.com/")
            .body(Body::empty())
            .expect("request");
        let outcome = handler.on_request(request).await;
        // Forwarded, and a capture signal is emitted (not an egress.denied).
        let _forwarded = expect_forwarded(outcome);
        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.kind, REQUEST_KIND);
    }

    #[tokio::test]
    async fn connect_to_denied_host_short_circuits_with_403() {
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            deny_policy(&["api.anthropic.com"], &[]),
            None,
        );
        let response =
            expect_response(handler.on_request(connect_request("example.com:443")).await);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let signal = rx.recv().await.expect("egress signal").expect("raw");
        assert_eq!(signal.kind, EGRESS_DENIED_KIND);
        assert_eq!(
            signal.attributes.get("egress.layer").map(String::as_str),
            Some("connect")
        );
        assert_eq!(
            signal.attributes.get("egress.mode").map(String::as_str),
            Some("deny")
        );
        assert_eq!(
            signal.attributes.get("http.host").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            signal.attributes.get("net.peer.port").map(String::as_str),
            Some("443")
        );
        assert_eq!(
            signal.attributes.get("egress.decision").map(String::as_str),
            Some("policy")
        );
    }

    #[tokio::test]
    async fn connect_to_allowed_host_proceeds_and_stashes_sni() {
        let (mut handler, _rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            deny_policy(&["api.anthropic.com"], &[]),
            None,
        );
        let _forwarded = expect_forwarded(
            handler
                .on_request(connect_request("api.anthropic.com:443"))
                .await,
        );
        assert_eq!(
            handler.connect_host,
            Some(CanonicalHost::Domain("api.anthropic.com".to_owned()))
        );
    }

    #[tokio::test]
    async fn decrypted_request_to_denied_host_is_403() {
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            allow_block_policy(&["blocked.example.com"]),
            None,
        );
        let request = Request::builder()
            .method("POST")
            .uri("http://blocked.example.com/v1/thing")
            .body(Body::from(Bytes::from_static(b"payload")))
            .expect("request");
        let response = expect_response(handler.on_request(request).await);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let signal = rx.recv().await.expect("egress signal").expect("raw");
        assert_eq!(signal.kind, EGRESS_DENIED_KIND);
        assert_eq!(
            signal.attributes.get("egress.layer").map(String::as_str),
            Some("request")
        );
        assert_eq!(
            signal
                .attributes
                .get("egress.rule_matched")
                .map(String::as_str),
            Some("blocked.example.com")
        );
        // No capture signal for a denied request.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn sni_host_mismatch_is_rejected() {
        // CONNECT to an allowed host, then a decrypted request whose Host disagrees.
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            deny_policy(&["allowed.example.com"], &[]),
            None,
        );
        let _ = expect_forwarded(
            handler
                .on_request(connect_request("allowed.example.com:443"))
                .await,
        );
        let request = Request::builder()
            .method("GET")
            .uri("/path")
            .header("host", "different.example.com")
            .body(Body::empty())
            .expect("request");
        let response = expect_response(handler.on_request(request).await);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let signal = rx.recv().await.expect("egress signal").expect("raw");
        assert_eq!(signal.kind, EGRESS_DENIED_KIND);
        assert_eq!(
            signal.attributes.get("egress.decision").map(String::as_str),
            Some("host-mismatch")
        );
    }

    #[tokio::test]
    async fn ip_literal_host_is_enforced_via_cidr() {
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            deny_policy(&[], &["10.0.0.0/8"]),
            None,
        );
        // Decimal-notation IP for a denied address — must be canonicalized and denied.
        let response = expect_response(handler.on_request(connect_request("2130706433:443")).await);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let signal = rx.recv().await.expect("egress signal").expect("raw");
        assert_eq!(
            signal.attributes.get("http.host").map(String::as_str),
            Some("127.0.0.1")
        );
    }

    #[tokio::test]
    async fn unparseable_host_under_deny_fails_closed() {
        // A request whose host fails canonicalization must be DENIED (not forwarded)
        // under a non-allow-all policy — otherwise it would bypass deny-by-default.
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            deny_policy(&["allowed.example.com"], &[]),
            None,
        );
        // A Host header carrying whitespace is a valid header value but fails
        // canonicalization (which rejects whitespace, percent, control chars, etc.).
        let request = Request::builder()
            .method("GET")
            .uri("/path")
            .header("host", "evil example.com")
            .body(Body::empty())
            .expect("request");
        let response = expect_response(handler.on_request(request).await);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let signal = rx.recv().await.expect("egress signal").expect("raw");
        assert_eq!(signal.kind, EGRESS_DENIED_KIND);
        assert_eq!(
            signal.attributes.get("egress.decision").map(String::as_str),
            Some("unparseable_host")
        );
        assert_eq!(
            signal.attributes.get("egress.layer").map(String::as_str),
            Some("request")
        );
        // No host is reported (none could be canonicalized).
        assert!(!signal.attributes.contains_key("http.host"));
    }

    #[tokio::test]
    async fn missing_host_under_deny_fails_closed() {
        // A request with neither a URI host nor a Host header cannot be policed.
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            deny_policy(&["allowed.example.com"], &[]),
            None,
        );
        let request = Request::builder()
            .method("GET")
            .uri("/just-a-path")
            .body(Body::empty())
            .expect("request");
        let response = expect_response(handler.on_request(request).await);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let signal = rx.recv().await.expect("egress signal").expect("raw");
        assert_eq!(
            signal.attributes.get("egress.decision").map(String::as_str),
            Some("unparseable_host")
        );
    }

    #[tokio::test]
    async fn unparseable_host_under_allow_all_is_forwarded() {
        // Allow-all has no policy to enforce, so an unparseable host is still captured
        // and forwarded (no false denial when egress is off).
        let (mut handler, mut rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            None,
        );
        let request = Request::builder()
            .method("GET")
            .uri("/just-a-path")
            .body(Body::empty())
            .expect("request");
        let _forwarded = expect_forwarded(handler.on_request(request).await);
        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.kind, REQUEST_KIND);
    }

    // --- credential injection through the handler ---

    use crate::secret::{BrokerConfig, SecretBinding};
    use hyper::server::conn::http1 as broker_http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    /// Spin a stub broker that always returns `{"value": <value>}` with 200.
    async fn stub_broker(value: &'static str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = service_fn(move |_req| async move {
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(200)
                                .body(http_body_util::Full::new(Bytes::from_static(
                                    format!("{{\"value\":\"{value}\"}}").leak().as_bytes(),
                                )))
                                .expect("response"),
                        )
                    });
                    let _ = broker_http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        format!("http://{addr}/resolve")
    }

    fn injector_for(url: &str, host: &str) -> SecretInjector {
        SecretInjector::new(
            [SecretBinding {
                name: "openai-prod".to_owned(),
                env_placeholder: "hil-secret://openai-prod".to_owned(),
                host: host.to_owned(),
                header: "authorization".to_owned(),
                scheme: "Bearer".to_owned(),
            }],
            &BrokerConfig {
                url: url.to_owned(),
                token: "broker-token".to_owned(),
            },
        )
        .expect("injector")
    }

    #[tokio::test]
    async fn injected_credential_is_redacted_from_captured_body() {
        // The credential value the broker returns is echoed into the request body here
        // to prove the capture path scrubs it (real injection is into a header, which
        // the proxy never captures; this guards the literal-redaction wiring).
        let url = stub_broker("sk-real-secret-value").await;
        let injector = injector_for(&url, "api.openai.com");
        let (mut handler, mut rx, store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            Some(injector),
        );
        let request = Request::builder()
            .method("POST")
            .uri("http://api.openai.com/v1/chat")
            .header("authorization", "Bearer hil-secret://openai-prod")
            .body(Body::from(Bytes::from_static(
                b"echo sk-real-secret-value here",
            )))
            .expect("request");

        let forwarded = expect_forwarded(handler.on_request(request).await);
        // The forwarded request carries the real credential in the header.
        assert_eq!(
            forwarded
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer sk-real-secret-value")
        );
        drain_body(forwarded.into_body()).await;

        let signal = rx.recv().await.expect("signal").expect("raw");
        assert_eq!(signal.kind, REQUEST_KIND);
        // The captured copy must not contain the secret value.
        let blob = &store.blobs()[0].1;
        assert!(
            !blob.windows(20).any(|w| w == b"sk-real-secret-value"),
            "captured body must not leak the injected credential"
        );
        assert_eq!(blob, b"echo [REDACTED] here");
    }

    #[tokio::test]
    async fn credential_not_injected_on_unbound_host() {
        let url = stub_broker("sk-real-secret-value").await;
        let injector = injector_for(&url, "api.openai.com");
        let (mut handler, _rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            Some(injector),
        );
        let request = Request::builder()
            .method("GET")
            .uri("http://other.example.com/")
            .body(Body::empty())
            .expect("request");
        let forwarded = expect_forwarded(handler.on_request(request).await);
        assert!(
            forwarded.headers().get("authorization").is_none(),
            "an unbound host must not receive a credential"
        );
    }

    #[tokio::test]
    async fn broker_failure_fails_request_closed() {
        // Point at a closed port so the broker call fails; the request must be blocked.
        let injector = injector_for("http://127.0.0.1:1/resolve", "api.openai.com");
        let (mut handler, _rx, _store) = handler_with_egress(
            None,
            RedactionPolicy::default(),
            Arc::new(EgressPolicy::default()),
            Some(injector),
        );
        let request = Request::builder()
            .method("POST")
            .uri("http://api.openai.com/v1/chat")
            .body(Body::empty())
            .expect("request");
        let response = expect_response(handler.on_request(request).await);
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "a broker failure must fail the request closed, not forward it"
        );
    }
}
