//! Credential injection for intercepted HTTP(S) requests.
//!
//! A run can bind a named secret to a destination host and a request header: when
//! the wrapped harness sends a request to that host, the proxy resolves the secret's
//! plaintext from a [broker](BrokerConfig) and replaces a user-authored
//! *placeholder* (e.g. `hil-secret://openai-prod`) in the bound header with the real
//! credential (`{scheme} {value}`), or injects the header when it is absent.
//!
//! # Why a placeholder, and what the user sees
//!
//! The harness only ever holds the placeholder, never the credential. The real value
//! is fetched at request time, spliced into the *forwarded* header, and then zeroized.
//! The captured/telemetry copy is scrubbed of the value (it is
//! threaded through the [redaction](crate::redact) path as an exact literal), so a
//! capture shows only the placeholder — the secret never lands in an event or a blob.
//!
//! # Host scoping and fail-closed
//!
//! Injection is scoped to the bound host: a request to any other destination is
//! forwarded untouched, so a secret bound to `api.openai.com` can never leak to a
//! request the harness sends elsewhere. If the broker call fails, the request is
//! **failed closed** — the proxy returns an error response rather than forwarding a
//! request without (or with a stale placeholder for) the credential.
//!
//! # Threat model
//!
//! Like the [egress filter](crate::egress), this is a cooperative control over
//! traffic that flows through the proxy. Hostile in-guest code that bypasses the
//! proxy never reaches this layer; the placeholder simply never resolves and the
//! request fails wherever the harness sent it. This keeps the *credential* out of the
//! guest, which is its purpose, but it is not a sandbox boundary.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use zeroize::Zeroizing;

use crate::egress::{CanonicalHost, canonicalize_host};

/// Maximum broker response body the client will read, bounding memory against a
/// misbehaving broker.
const MAX_BROKER_RESPONSE_BYTES: usize = 64 * 1024;

/// Binds a named secret to a destination host and the request header it scopes to.
///
/// `env_placeholder` is the opaque token the harness carries in place of the
/// credential (e.g. `hil-secret://openai-prod`); the proxy replaces it (or injects
/// the header) only on a request whose canonicalized host matches `host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBinding {
    /// The broker-side secret name to resolve.
    pub name: String,
    /// The placeholder the harness holds in place of the credential.
    pub env_placeholder: String,
    /// The destination host this binding is scoped to (canonicalized at build time).
    pub host: String,
    /// The request header the credential is written into (e.g. `authorization`).
    pub header: String,
    /// The credential scheme prefix (e.g. `Bearer`); empty for a bare value.
    pub scheme: String,
}

/// How to reach the credential broker (the server-side `ResolveSandboxSecret`).
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// The broker endpoint the client POSTs resolve requests to.
    pub url: String,
    /// Bearer token authenticating the proxy to the broker.
    pub token: String,
}

/// A validated, host-keyed view of the secret bindings plus the broker.
///
/// Built once per run; the proxy consults it on every request. `None` host-match is
/// the common case (no binding for the destination) and returns immediately.
#[derive(Clone, Debug)]
pub struct SecretInjector {
    /// Bindings keyed by canonicalized host (one binding per host for v1).
    bindings: HashMap<String, ResolvedBinding>,
    broker: Arc<BrokerClient>,
}

/// A binding with its host already canonicalized.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedBinding {
    name: String,
    placeholder: String,
    header: HeaderName,
    scheme: String,
}

/// Why building a [`SecretInjector`] failed.
#[derive(Debug, thiserror::Error)]
pub enum SecretConfigError {
    #[error("invalid secret binding host `{host}`: {source}")]
    Host {
        host: String,
        source: crate::egress::CanonicalizeError,
    },
    #[error("secret binding host `{host}` must be a domain or IP, not empty")]
    EmptyHost { host: String },
    #[error("invalid secret binding header `{header}`")]
    Header { header: String },
    #[error("broker URL `{url}` is not a valid http(s) URI")]
    BrokerUrl { url: String },
    #[error("two secret bindings target the same host `{host}`")]
    DuplicateHost { host: String },
    #[error("broker TLS configuration failed: {0}")]
    Tls(String),
}

/// Why resolving an injected credential failed (request is failed closed).
#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("broker request failed: {0}")]
    Transport(String),
    #[error("broker returned status {0}")]
    Status(u16),
    #[error("broker response was not valid JSON `{{\"value\": ...}}`")]
    MalformedResponse,
    #[error("resolved secret value is not a valid header value")]
    InvalidHeaderValue,
}

impl SecretInjector {
    /// Build an injector from the bindings and broker config, canonicalizing and
    /// validating each binding's host and header up front.
    pub fn new(
        bindings: impl IntoIterator<Item = SecretBinding>,
        broker: &BrokerConfig,
    ) -> Result<Self, SecretConfigError> {
        let client = BrokerClient::new(broker)?;
        let mut map = HashMap::new();
        for binding in bindings {
            let destination =
                canonicalize_host(&binding.host).map_err(|source| SecretConfigError::Host {
                    host: binding.host.clone(),
                    source,
                })?;
            let host_key = match destination.host() {
                CanonicalHost::Domain(domain) => domain.clone(),
                CanonicalHost::Ip(ip) => ip.to_string(),
            };
            let header = HeaderName::try_from(binding.header.as_str()).map_err(|_| {
                SecretConfigError::Header {
                    header: binding.header.clone(),
                }
            })?;
            let resolved = ResolvedBinding {
                name: binding.name,
                placeholder: binding.env_placeholder,
                header,
                scheme: binding.scheme,
            };
            if map.insert(host_key.clone(), resolved).is_some() {
                return Err(SecretConfigError::DuplicateHost { host: host_key });
            }
        }
        Ok(Self {
            bindings: map,
            broker: Arc::new(client),
        })
    }

    /// The binding for `host`, if one is bound to it.
    fn binding_for(&self, host: &CanonicalHost) -> Option<&ResolvedBinding> {
        let key = match host {
            CanonicalHost::Domain(domain) => domain.clone(),
            CanonicalHost::Ip(ip) => ip.to_string(),
        };
        self.bindings.get(&key)
    }

    /// Inject the bound credential into `request` when its host matches a binding.
    ///
    /// On a match the broker resolves the secret value, and the bound header is written
    /// to respect the agent's intent:
    ///
    /// - If the header is **present and contains the placeholder token**, the token is
    ///   replaced in place by the resolved `value` (the agent already authored the rest
    ///   of the header — e.g. the `Bearer ` scheme prefix — around the placeholder, so
    ///   only the placeholder is substituted, not the whole header).
    /// - Otherwise (header absent, or present without the placeholder) the header is
    ///   **set** to `{scheme} {value}` (or just `{value}` when `scheme` is empty).
    ///
    /// The resolved value is returned in [`Zeroizing`] so the caller can scrub it from
    /// any captured copy and so it is wiped when dropped. A non-matching host returns
    /// `Ok(None)` and leaves the request untouched; a broker failure returns `Err`, and
    /// the caller must fail the request closed.
    pub async fn inject<B>(
        &self,
        host: &CanonicalHost,
        request: &mut Request<B>,
    ) -> Result<Option<Zeroizing<String>>, InjectError> {
        let Some(binding) = self.binding_for(host) else {
            return Ok(None);
        };

        let value = self.broker.resolve(&binding.name).await?;

        // Substitute the placeholder in the existing header value when present; this
        // preserves the agent-authored scheme/structure around the placeholder.
        let existing = request
            .headers()
            .get(&binding.header)
            .and_then(|v| v.to_str().ok());
        let rendered = match existing {
            Some(existing)
                if !binding.placeholder.is_empty() && existing.contains(&binding.placeholder) =>
            {
                existing.replace(&binding.placeholder, value.as_str())
            }
            // Header absent or no placeholder to replace: set the full credential.
            _ if binding.scheme.is_empty() => value.to_string(),
            _ => format!("{} {}", binding.scheme, value.as_str()),
        };
        // Keep the rendered header value in `Zeroizing` so the secret it carries is
        // wiped from this scratch buffer once it has been copied into the HeaderValue.
        let rendered = Zeroizing::new(rendered);
        let header_value = HeaderValue::try_from(rendered.as_str())
            .map_err(|_| InjectError::InvalidHeaderValue)?;
        request
            .headers_mut()
            .insert(binding.header.clone(), header_value);

        Ok(Some(value))
    }
}

/// HTTP client for the credential broker (`ResolveSandboxSecret`).
///
/// The client POSTs `{"name": <binding.name>}` with `Authorization: Bearer <token>`
/// and expects `{"value": <plaintext>}`. The broker endpoint scheme is
/// deployment-dependent — a plaintext in-cluster service (`http://…`) or the public
/// API edge (`https://…`) — so the connector speaks HTTPS **or** HTTP. A plaintext-only
/// connector would reject an `https://` URL before connecting (surfacing as a
/// `client error (Connect)`), which is why TLS is wired here. Trust anchors come from
/// the compiled-in webpki bundle: native roots are empty in the minimal sandbox base
/// where the interceptor runs, so the webpki bundle is what anchors the public chain.
struct BrokerClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    uri: Uri,
    /// Bearer token, kept in `Zeroizing` so it is wiped from memory on drop.
    token: Zeroizing<String>,
}

impl std::fmt::Debug for BrokerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the broker token.
        f.debug_struct("BrokerClient")
            .field("client", &self.client)
            .field("uri", &self.uri)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Build the rustls client config the broker connector uses: the compiled-in webpki
/// trust anchors and an explicit `aws-lc-rs` provider (matching the proxy's crypto
/// backend, so no process-wide default provider need be installed).
fn broker_tls_config() -> Result<rustls::ClientConfig, SecretConfigError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| SecretConfigError::Tls(error.to_string()))
    .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

impl BrokerClient {
    fn new(config: &BrokerConfig) -> Result<Self, SecretConfigError> {
        Self::with_tls_config(config, broker_tls_config()?)
    }

    /// Construct the client from a specific rustls config. The connector accepts both
    /// `https://` and `http://` broker URLs so the same build works against the public
    /// API edge and a plaintext in-cluster broker.
    fn with_tls_config(
        config: &BrokerConfig,
        tls: rustls::ClientConfig,
    ) -> Result<Self, SecretConfigError> {
        let uri: Uri = config
            .url
            .parse()
            .map_err(|_| SecretConfigError::BrokerUrl {
                url: config.url.clone(),
            })?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            client,
            uri,
            token: Zeroizing::new(config.token.clone()),
        })
    }

    /// Resolve `name` to its plaintext value via the broker. The value is returned in
    /// [`Zeroizing`] so it is wiped from memory when the caller drops it.
    async fn resolve(&self, name: &str) -> Result<Zeroizing<String>, InjectError> {
        // serde_json builds the request body so the name is correctly escaped.
        let payload = serde_json::json!({ "name": name }).to_string();
        // Keep the bearer header in `Zeroizing` so the token-bearing scratch string is
        // wiped once it has been copied into the request's HeaderValue.
        let bearer = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let request = Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, bearer.as_str())
            .body(Full::new(Bytes::from(payload)))
            .map_err(|error| InjectError::Transport(error.to_string()))?;

        let response = self
            .client
            .request(request)
            .await
            .map_err(|error| InjectError::Transport(error.to_string()))?;

        if response.status() != StatusCode::OK {
            return Err(InjectError::Status(response.status().as_u16()));
        }

        let body = http_body_util::Limited::new(response.into_body(), MAX_BROKER_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| InjectError::MalformedResponse)?
            .to_bytes();
        parse_broker_value(&body)
    }
}

/// Parse `{"value": <plaintext>}` out of the broker response body.
fn parse_broker_value(body: &[u8]) -> Result<Zeroizing<String>, InjectError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| InjectError::MalformedResponse)?;
    parsed
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(|value| Zeroizing::new(value.to_owned()))
        .ok_or(InjectError::MalformedResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Response, server::conn::http1};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    fn binding(host: &str) -> SecretBinding {
        SecretBinding {
            name: "openai-prod".to_owned(),
            env_placeholder: "hil-secret://openai-prod".to_owned(),
            host: host.to_owned(),
            header: "authorization".to_owned(),
            scheme: "Bearer".to_owned(),
        }
    }

    /// What a stub broker request recorded, so a test can assert the auth header and
    /// body the proxy sent.
    #[derive(Default)]
    struct BrokerLog {
        auth: Mutex<Option<String>>,
        body: Mutex<Option<String>>,
    }

    /// Spin a stub broker that returns `response` (status 200 unless `status` is set)
    /// and records the inbound auth header + body. Returns the URL and the log.
    async fn stub_broker(
        response: &'static str,
        status: StatusCode,
    ) -> (String, Arc<BrokerLog>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        let log = Arc::new(BrokerLog::default());
        let log_for_task = Arc::clone(&log);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let log = Arc::clone(&log_for_task);
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let log = Arc::clone(&log);
                        async move {
                            *log.auth.lock().expect("lock") = req
                                .headers()
                                .get(AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .map(ToOwned::to_owned);
                            let body = req.into_body().collect().await.expect("body").to_bytes();
                            *log.body.lock().expect("lock") =
                                Some(String::from_utf8_lossy(&body).into_owned());
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from_static(response.as_bytes())))
                                    .expect("response"),
                            )
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        });
        (format!("http://{addr}/resolve"), log, handle)
    }

    /// Spin a stub broker behind TLS with a self-signed cert for `localhost`, returning the
    /// `https://` URL and the trust anchor a client must add to reach it. This exercises the
    /// broker client's TLS path — the plaintext connector regression (an `https://` broker URL
    /// rejected before connecting) is caught here.
    async fn stub_broker_tls(
        response: &'static str,
    ) -> (
        String,
        rustls::pki_types::CertificateDer<'static>,
        tokio::task::JoinHandle<()>,
    ) {
        use hudsucker::rcgen::{CertificateParams, KeyPair};
        use tokio_rustls::TlsAcceptor;

        let key_pair = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        let cert = params.self_signed(&key_pair).expect("self-signed");
        let cert_der = cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server cert");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(response.as_bytes())))
                                .expect("response"),
                        )
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        // `localhost` (not `127.0.0.1`) so the URL host matches the cert SAN.
        (
            format!("https://localhost:{port}/resolve"),
            cert_der,
            handle,
        )
    }

    #[tokio::test]
    async fn resolves_over_https_broker() {
        let (url, cert_der, _task) = stub_broker_tls(r#"{"value":"sk-https-secret"}"#).await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust the stub cert");
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        let client = BrokerClient::with_tls_config(
            &BrokerConfig {
                url,
                token: "broker-token".to_owned(),
            },
            tls,
        )
        .expect("broker client");

        let value = client
            .resolve("openai-prod")
            .await
            .expect("resolve over https");
        assert_eq!(value.as_str(), "sk-https-secret");
    }

    fn injector(url: &str, host: &str) -> SecretInjector {
        SecretInjector::new(
            [binding(host)],
            &BrokerConfig {
                url: url.to_owned(),
                token: "broker-token".to_owned(),
            },
        )
        .expect("injector")
    }

    fn canon(host: &str) -> CanonicalHost {
        canonicalize_host(host).expect("canon").host().clone()
    }

    #[tokio::test]
    async fn injects_credential_on_bound_host() {
        let (url, log, _task) = stub_broker(r#"{"value":"sk-real-secret"}"#, StatusCode::OK).await;
        let injector = injector(&url, "api.openai.com");

        let mut request = Request::builder()
            .uri("https://api.openai.com/v1/chat")
            .header("authorization", "Bearer hil-secret://openai-prod")
            .body(())
            .expect("request");

        let value = injector
            .inject(&canon("api.openai.com"), &mut request)
            .await
            .expect("inject")
            .expect("a value on the bound host");

        assert_eq!(value.as_str(), "sk-real-secret");
        assert_eq!(
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer sk-real-secret"),
            "placeholder replaced by the resolved credential"
        );
        // The broker saw the proxy's bearer auth and the name payload.
        assert_eq!(
            log.auth.lock().expect("lock").as_deref(),
            Some("Bearer broker-token")
        );
        assert_eq!(
            log.body.lock().expect("lock").as_deref(),
            Some(r#"{"name":"openai-prod"}"#)
        );
    }

    #[tokio::test]
    async fn placeholder_is_substituted_in_place_preserving_surrounding_text() {
        // The agent authored a header with the placeholder embedded in a larger value;
        // only the placeholder token is replaced, the rest is preserved.
        let (url, _log, _task) = stub_broker(r#"{"value":"sk-real"}"#, StatusCode::OK).await;
        let injector = injector(&url, "api.openai.com");
        let mut request = Request::builder()
            .uri("https://api.openai.com/")
            .header(
                "authorization",
                "Bearer hil-secret://openai-prod, extra=keep",
            )
            .body(())
            .expect("request");
        injector
            .inject(&canon("api.openai.com"), &mut request)
            .await
            .expect("inject")
            .expect("value");
        assert_eq!(
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer sk-real, extra=keep"),
            "only the placeholder token is substituted"
        );
    }

    #[tokio::test]
    async fn header_present_without_placeholder_is_set_to_full_credential() {
        // A bound header present but NOT containing the placeholder is replaced with the
        // full `{scheme} {value}` credential (the documented fallback).
        let (url, _log, _task) = stub_broker(r#"{"value":"sk-real"}"#, StatusCode::OK).await;
        let injector = injector(&url, "api.openai.com");
        let mut request = Request::builder()
            .uri("https://api.openai.com/")
            .header("authorization", "Bearer stale-token")
            .body(())
            .expect("request");
        injector
            .inject(&canon("api.openai.com"), &mut request)
            .await
            .expect("inject")
            .expect("value");
        assert_eq!(
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer sk-real")
        );
    }

    #[tokio::test]
    async fn does_not_inject_on_unbound_host() {
        let (url, _log, _task) = stub_broker(r#"{"value":"sk-real-secret"}"#, StatusCode::OK).await;
        let injector = injector(&url, "api.openai.com");

        let mut request = Request::builder()
            .uri("https://evil.example.com/v1/chat")
            .body(())
            .expect("request");

        let value = injector
            .inject(&canon("evil.example.com"), &mut request)
            .await
            .expect("inject");

        assert!(value.is_none(), "no binding for the host");
        assert!(
            request.headers().get("authorization").is_none(),
            "unbound host must not have a credential injected"
        );
    }

    #[tokio::test]
    async fn broker_failure_returns_error_so_caller_fails_closed() {
        let (url, _log, _task) = stub_broker("nope", StatusCode::INTERNAL_SERVER_ERROR).await;
        let injector = injector(&url, "api.openai.com");

        let mut request = Request::builder()
            .uri("https://api.openai.com/v1/chat")
            .body(())
            .expect("request");

        let error = injector
            .inject(&canon("api.openai.com"), &mut request)
            .await
            .expect_err("broker 500 must error");
        assert!(matches!(error, InjectError::Status(500)));
    }

    #[tokio::test]
    async fn malformed_broker_response_errors() {
        let (url, _log, _task) = stub_broker("not json", StatusCode::OK).await;
        let injector = injector(&url, "api.openai.com");
        let mut request = Request::builder()
            .uri("https://api.openai.com/")
            .body(())
            .expect("request");
        let error = injector
            .inject(&canon("api.openai.com"), &mut request)
            .await
            .expect_err("malformed response must error");
        assert!(matches!(error, InjectError::MalformedResponse));
    }

    #[tokio::test]
    async fn injects_header_when_absent() {
        let (url, _log, _task) = stub_broker(r#"{"value":"sk-real"}"#, StatusCode::OK).await;
        let injector = injector(&url, "api.openai.com");
        // No authorization header on the inbound request.
        let mut request = Request::builder()
            .uri("https://api.openai.com/")
            .body(())
            .expect("request");
        injector
            .inject(&canon("api.openai.com"), &mut request)
            .await
            .expect("inject")
            .expect("value");
        assert_eq!(
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer sk-real")
        );
    }

    #[test]
    fn duplicate_host_binding_is_rejected() {
        let error = SecretInjector::new(
            [binding("api.openai.com"), binding("api.openai.com")],
            &BrokerConfig {
                url: "http://localhost:9/resolve".to_owned(),
                token: "t".to_owned(),
            },
        )
        .expect_err("duplicate host");
        assert!(matches!(error, SecretConfigError::DuplicateHost { .. }));
    }

    #[test]
    fn invalid_broker_url_is_rejected() {
        let error = SecretInjector::new(
            [binding("api.openai.com")],
            &BrokerConfig {
                url: "not a uri".to_owned(),
                token: "t".to_owned(),
            },
        )
        .expect_err("bad url");
        assert!(matches!(error, SecretConfigError::BrokerUrl { .. }));
    }

    #[test]
    fn parse_broker_value_extracts_plaintext() {
        let value = parse_broker_value(br#"{"value":"abc"}"#).expect("value");
        assert_eq!(value.as_str(), "abc");
        assert!(parse_broker_value(br#"{"other":"abc"}"#).is_err());
    }

    #[test]
    fn bare_scheme_injects_value_without_prefix() {
        // An empty scheme injects the raw value (e.g. for an `x-api-key` header).
        let injector = SecretInjector::new(
            [SecretBinding {
                scheme: String::new(),
                header: "x-api-key".to_owned(),
                ..binding("api.openai.com")
            }],
            &BrokerConfig {
                url: "http://localhost:9/resolve".to_owned(),
                token: "t".to_owned(),
            },
        )
        .expect("injector");
        let resolved = injector
            .binding_for(&canon("api.openai.com"))
            .expect("binding");
        assert_eq!(resolved.scheme, "");
        assert_eq!(resolved.header.as_str(), "x-api-key");
    }
}
