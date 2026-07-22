//! Shared plumbing for gRPC clients of a hiloop telemetry gateway: channel construction with the
//! interceptor's TLS trust policy, Bearer auth sourced from the environment, and compact rendering
//! of rejection `Status` chains. Used by the event exporter ([`crate::grpc_export`]) and the blob
//! uploader ([`crate::blob_upload`]) so the two clients can never drift on endpoint, trust, or
//! credential handling.

use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::{Request, Status};

/// Generated `hiloop.telemetry.v1` stubs (vendored protos, see `build.rs`): the ingest service the
/// exporter speaks and the blob service the uploader speaks.
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

/// Env var holding the API key. Sourced from the environment only — never a CLI argument, so it
/// stays out of process provenance (`process.command_args`).
pub const TOKEN_ENV: &str = "HILOOP_API_KEY";

/// Bound on establishing the gateway connection (DNS + TCP + TLS). The channel is lazy, so the
/// connect happens inside the first RPC after an outage; without this bound a black-holed gateway
/// (unroutable address, dropped SYNs) holds that RPC — and the teardown drain awaiting it — at the
/// mercy of kernel TCP timeouts. 10 s matches the export path's per-attempt convention (the spool's
/// `attempt_timeout`, the blob `HasBlobs` probe).
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Errors building a gateway client (invalid endpoint, TLS setup, malformed token).
#[derive(Debug, Error)]
pub enum GrpcClientError {
    #[error("invalid endpoint `{endpoint}`")]
    InvalidEndpoint {
        endpoint: String,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("TLS configuration failed")]
    Tls(#[source] Box<dyn StdError + Send + Sync>),
    #[error("invalid API token")]
    InvalidToken(#[source] Box<dyn StdError + Send + Sync>),
}

/// Build a lazily-connecting channel to `endpoint` (e.g. `https://telemetry.example.com:443`).
///
/// The channel connects on first use, not here, so a gateway that is briefly unreachable at
/// startup doesn't abort the run. TLS is used unless `insecure` is set (h2c, local dev only).
//
// `with_enabled_roots()` trusts BOTH the OS store (native roots — for an on-prem gateway behind a
// private CA) AND the compiled-in webpki/Mozilla bundle. Native roots alone fail to auto-discover
// the trust store in a minimal container (the sandbox base, where `hiloop run` embeds this
// interceptor: `with_native_roots()` yielded an empty set → `UnknownIssuer` even though the public
// chain's anchor was installed); the webpki bundle anchors the public chain regardless. This
// matches the HTTP capture path's rustls trust.
pub(crate) fn build_channel(endpoint: &str, insecure: bool) -> Result<Channel, GrpcClientError> {
    let mut builder = Channel::from_shared(endpoint.to_owned()).map_err(|error| {
        GrpcClientError::InvalidEndpoint {
            endpoint: endpoint.to_owned(),
            source: Box::new(error),
        }
    })?;
    if !insecure {
        builder = builder
            .tls_config(ClientTlsConfig::new().with_enabled_roots())
            .map_err(|error| GrpcClientError::Tls(Box::new(error)))?;
    }
    Ok(builder.connect_timeout(CONNECT_TIMEOUT).connect_lazy())
}

/// Read the Bearer token from [`TOKEN_ENV`]. Absent/empty means no auth header (an
/// unauthenticated dev gateway).
fn token_from_env() -> Option<String> {
    std::env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty())
}

fn bearer_value(token: &str) -> Result<MetadataValue<Ascii>, GrpcClientError> {
    format!("Bearer {token}").parse().map_err(
        |error: tonic::metadata::errors::InvalidMetadataValue| {
            GrpcClientError::InvalidToken(Box::new(error))
        },
    )
}

/// Bound on waiting for an in-flight credential refresh. The refresh itself runs detached (a
/// half-done rotation must never be cancelled mid-flight — it may have already burned the old
/// token server-side), so a waiter that times out classifies the failed delivery as transient and
/// the spooled batch redelivers once the refresh lands. 10 s matches the export path's
/// per-attempt convention.
const REFRESH_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Boxed future returned by [`RefreshBearer::refresh`].
pub type RefreshFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, Box<dyn StdError + Send + Sync>>> + Send + 'a>>;

/// Exchanges a bearer the gateway rejected as unauthenticated for a fresh one.
///
/// Installed on a [`GatewayCredential`] only when the credential is renewable (e.g. a wrapping
/// CLI's cached login session — never a static API key). Implementations must be safe to call
/// concurrently and should serialize their own rotation (the credential handle serializes the
/// common path, but a cancelled waiter can admit a second call while a rotation is in flight).
pub trait RefreshBearer: Send + Sync + std::fmt::Debug {
    /// Return a bearer token that replaces `rejected` (`None` when no token was presented) —
    /// either one a concurrent rotation already produced, or a freshly minted one.
    ///
    /// # Errors
    /// The refresh credential itself is dead or the refresh could not be performed; the caller
    /// then treats the original rejection as permanent.
    fn refresh<'a>(&'a self, rejected: Option<&'a str>) -> RefreshFuture<'a>;
}

/// How a [`GatewayCredential::refresh_rejected`] call resolved, for classifying the delivery
/// failure that triggered it.
#[derive(Debug)]
pub(crate) enum RefreshOutcome {
    /// A replacement bearer is installed — redeliver the rejected payload.
    Refreshed,
    /// The credential has no refresher (a static key): the rejection stands as permanent.
    Unrefreshable,
    /// The refresher failed: the rejection stands as permanent, with this reason attached.
    Failed(String),
    /// A refresh is still in flight past the wait bound: transient — park and redeliver later.
    Pending,
}

/// Shared, refreshable bearer credential for the telemetry-gateway clients.
///
/// One handle is shared by the event exporter and the blob uploader so a refresh triggered by
/// either leg re-authenticates both. Refreshes are serialized (single-flight): concurrent
/// rejections trigger one rotation, and a caller whose presented bearer is already stale simply
/// retries with the current one.
#[derive(Clone)]
pub struct GatewayCredential {
    inner: Arc<CredentialState>,
}

struct CredentialState {
    bearer: std::sync::RwLock<Option<MetadataValue<Ascii>>>,
    refresher: Option<Arc<dyn RefreshBearer>>,
    /// Serializes rotations; held across the refresh await so concurrent rejections coalesce.
    refresh_gate: tokio::sync::Mutex<()>,
    /// Successful rotations, reported on the run's `capture.drain` health record.
    refreshes: AtomicU64,
}

impl std::fmt::Debug for GatewayCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bearer is a live credential: name its presence, never its value.
        f.debug_struct("GatewayCredential")
            .field("bearer", &self.bearer().map(|_| "<redacted>"))
            .field("refresher", &self.inner.refresher)
            .field("refreshes", &self.refreshes())
            .finish()
    }
}

impl GatewayCredential {
    /// Build from an explicit `token` (`None` → no auth header), refreshable through `refresher`
    /// when one is given.
    ///
    /// # Errors
    /// The token is not a valid HTTP header value.
    pub fn new(
        token: Option<&str>,
        refresher: Option<Arc<dyn RefreshBearer>>,
    ) -> Result<Self, GrpcClientError> {
        let bearer = token.map(bearer_value).transpose()?;
        Ok(Self {
            inner: Arc::new(CredentialState {
                bearer: std::sync::RwLock::new(bearer),
                refresher,
                refresh_gate: tokio::sync::Mutex::new(()),
                refreshes: AtomicU64::new(0),
            }),
        })
    }

    /// Build from the token in [`TOKEN_ENV`] (absent/empty → no auth header), with no refresher:
    /// a rejected bearer stays rejected.
    ///
    /// # Errors
    /// The environment token is not a valid HTTP header value.
    pub fn from_env() -> Result<Self, GrpcClientError> {
        Self::from_env_with_refresher(None)
    }

    /// Build from the token in [`TOKEN_ENV`], refreshable through `refresher` when one is given.
    ///
    /// # Errors
    /// The environment token is not a valid HTTP header value.
    pub fn from_env_with_refresher(
        refresher: Option<Arc<dyn RefreshBearer>>,
    ) -> Result<Self, GrpcClientError> {
        Self::new(token_from_env().as_deref(), refresher)
    }

    /// The current bearer header value, if a token is configured.
    pub(crate) fn bearer(&self) -> Option<MetadataValue<Ascii>> {
        self.inner
            .bearer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Successful mid-run credential rotations, for the run's capture-health accounting.
    #[must_use]
    pub fn refreshes(&self) -> u64 {
        self.inner.refreshes.load(Ordering::SeqCst)
    }

    /// React to the gateway rejecting `presented` as unauthenticated: rotate the bearer through
    /// the refresher (single-flight — concurrent rejections coalesce into one rotation) and
    /// report how the caller should classify the failed delivery.
    ///
    /// The rotation itself runs on a detached task: cancelling the waiter (a caller-imposed
    /// delivery deadline) must never strand a rotation that may already have burned the previous
    /// token server-side. A waiter that times out gets [`RefreshOutcome::Pending`]; the rotation
    /// still installs the fresh bearer when it lands, so parked payloads redeliver.
    pub(crate) async fn refresh_rejected(
        &self,
        presented: Option<&MetadataValue<Ascii>>,
    ) -> RefreshOutcome {
        if self.inner.refresher.is_none() {
            return RefreshOutcome::Unrefreshable;
        }
        let _gate = self.inner.refresh_gate.lock().await;
        if self.bearer().as_ref() != presented {
            // Another leg already rotated past the rejected bearer: just retry with the
            // current one.
            return RefreshOutcome::Refreshed;
        }
        let rejected_token = presented.and_then(|bearer| {
            bearer
                .to_str()
                .ok()
                .and_then(|header| header.strip_prefix("Bearer "))
                .map(str::to_owned)
        });
        let inner = Arc::clone(&self.inner);
        let rotation = tokio::spawn(async move {
            let refresher = inner
                .refresher
                .as_ref()
                .expect("refresh_rejected checked the refresher above");
            match refresher.refresh(rejected_token.as_deref()).await {
                Ok(token) => match bearer_value(&token) {
                    Ok(bearer) => {
                        *inner
                            .bearer
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bearer);
                        inner.refreshes.fetch_add(1, Ordering::SeqCst);
                        eprintln!(
                            "hiloop-interceptor: the telemetry gateway rejected the export credential as unauthenticated; refreshed it and retrying delivery"
                        );
                        Ok(())
                    }
                    Err(error) => Err(format!(
                        "the refreshed token is not a valid header: {error}"
                    )),
                },
                Err(error) => Err(format!("{error}")),
            }
        });
        match tokio::time::timeout(REFRESH_WAIT_TIMEOUT, rotation).await {
            Ok(Ok(Ok(()))) => RefreshOutcome::Refreshed,
            Ok(Ok(Err(message))) => RefreshOutcome::Failed(message),
            Ok(Err(join_error)) => {
                RefreshOutcome::Failed(format!("the credential refresh task failed: {join_error}"))
            }
            Err(_elapsed) => RefreshOutcome::Pending,
        }
    }
}

/// Attaches `authorization: Bearer <token>` from the shared [`GatewayCredential`] to every
/// request, so a mid-run rotation re-authenticates every later RPC without reconnecting.
#[derive(Clone)]
pub(crate) struct AuthInterceptor {
    credential: GatewayCredential,
}

impl AuthInterceptor {
    pub(crate) fn new(credential: GatewayCredential) -> Self {
        Self { credential }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(bearer) = self.credential.bearer() {
            request.metadata_mut().insert("authorization", bearer);
        }
        Ok(request)
    }
}

/// Fold a rejected RPC's `Status` into one human-readable line.
///
/// `tonic::Status` can carry an empty gRPC message and noisy sources — its own `Display` embeds
/// the `Debug` of its transport source (`tonic::transport::Error(Transport, hyper::Error(..))`),
/// which would leak internals into a wrapping CLI's stderr. Fold the readable pieces into one
/// compact diagnostic instead: the status message (or the code description when the message is
/// empty) followed by each source's `Display`. Hops in the chain routinely restate each other
/// (tonic stamps the root cause into the status message), so a hop that appears verbatim inside
/// another hop is dropped rather than repeated. The `Status` is deliberately not kept as a
/// structured `source` — any wrapper that renders an error chain (`anyhow`'s `{err:#}`) would
/// hit `Status`'s leaky `Display` again.
pub(crate) fn fold_status_message(status: &Status) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut push = |part: &str| {
        let part = part.trim();
        if !part.is_empty() {
            parts.push(part.to_owned());
        }
    };
    if status.message().is_empty() {
        push(status.code().description());
    } else {
        push(status.message());
    }
    let mut source = StdError::source(status);
    while let Some(error) = source {
        push(&error.to_string());
        source = error.source();
    }

    // Keep a hop only if no other hop subsumes it: a strictly longer hop that contains it, or an
    // identical earlier hop (so exact repeats keep their first occurrence).
    let kept: Vec<&str> = parts
        .iter()
        .enumerate()
        .filter(|(i, part)| {
            !parts.iter().enumerate().any(|(j, other)| {
                j != *i && other.contains(part.as_str()) && (other.len() > part.len() || j < *i)
            })
        })
        .map(|(_, part)| part.as_str())
        .collect();

    kept.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(token: Option<&str>) -> GatewayCredential {
        GatewayCredential::new(token, None).expect("credential")
    }

    #[test]
    fn auth_interceptor_attaches_bearer_when_token_present() {
        use tonic::service::Interceptor as _;

        let mut with_token = AuthInterceptor::new(credential(Some("hil_secret")));
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

        let mut no_token = AuthInterceptor::new(credential(None));
        let request = no_token.call(Request::new(())).expect("intercept");
        assert!(request.metadata().get("authorization").is_none());
    }

    /// Scripted [`RefreshBearer`]: pops one response per call and counts invocations.
    #[derive(Debug, Default)]
    struct ScriptedRefresher {
        responses: std::sync::Mutex<std::collections::VecDeque<Result<String, String>>>,
        calls: AtomicU64,
        seen_rejected: std::sync::Mutex<Vec<Option<String>>>,
    }

    impl ScriptedRefresher {
        fn returning(token: &str) -> Self {
            Self {
                responses: std::sync::Mutex::new([Ok(token.to_owned())].into_iter().collect()),
                ..Self::default()
            }
        }

        fn failing(message: &str) -> Self {
            Self {
                responses: std::sync::Mutex::new([Err(message.to_owned())].into_iter().collect()),
                ..Self::default()
            }
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl RefreshBearer for ScriptedRefresher {
        fn refresh<'a>(&'a self, rejected: Option<&'a str>) -> RefreshFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.seen_rejected
                    .lock()
                    .expect("lock")
                    .push(rejected.map(str::to_owned));
                self.responses
                    .lock()
                    .expect("lock")
                    .pop_front()
                    .unwrap_or_else(|| Err("script exhausted".to_owned()))
                    .map_err(|message| Box::from(message) as Box<dyn StdError + Send + Sync>)
            })
        }
    }

    #[tokio::test]
    async fn refresh_installs_the_fresh_bearer_and_counts_the_rotation() {
        let refresher = Arc::new(ScriptedRefresher::returning("fresh"));
        let credential = GatewayCredential::new(Some("stale"), Some(Arc::clone(&refresher) as _))
            .expect("credential");

        let presented = credential.bearer();
        let outcome = credential.refresh_rejected(presented.as_ref()).await;

        assert!(matches!(outcome, RefreshOutcome::Refreshed), "{outcome:?}");
        assert_eq!(
            credential
                .bearer()
                .map(|b| b.to_str().expect("ascii").to_owned()),
            Some("Bearer fresh".to_owned())
        );
        assert_eq!(credential.refreshes(), 1);
        assert_eq!(refresher.calls(), 1);
        assert_eq!(
            *refresher.seen_rejected.lock().expect("lock"),
            vec![Some("stale".to_owned())],
            "the refresher is told which token was rejected, without the header scheme"
        );
    }

    #[tokio::test]
    async fn refresh_without_a_refresher_reports_unrefreshable() {
        let credential = credential(Some("static-key"));
        let presented = credential.bearer();

        let outcome = credential.refresh_rejected(presented.as_ref()).await;

        assert!(
            matches!(outcome, RefreshOutcome::Unrefreshable),
            "{outcome:?}"
        );
        assert_eq!(credential.refreshes(), 0);
    }

    #[tokio::test]
    async fn refresh_failure_reports_the_reason_and_keeps_the_bearer() {
        let refresher = Arc::new(ScriptedRefresher::failing("session burned"));
        let credential = GatewayCredential::new(Some("stale"), Some(Arc::clone(&refresher) as _))
            .expect("credential");
        let presented = credential.bearer();

        let outcome = credential.refresh_rejected(presented.as_ref()).await;

        let RefreshOutcome::Failed(message) = outcome else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert!(message.contains("session burned"), "{message}");
        assert_eq!(
            credential.bearer(),
            presented,
            "a failed refresh must not clobber the current bearer"
        );
        assert_eq!(credential.refreshes(), 0);
    }

    /// Single-flight: a rejection that arrives after another leg already rotated must not burn a
    /// second refresh — the stale presented bearer short-circuits to "retry with the current one".
    #[tokio::test]
    async fn a_stale_presented_bearer_skips_the_refresher() {
        let refresher = Arc::new(ScriptedRefresher::returning("fresh"));
        let credential = GatewayCredential::new(Some("stale"), Some(Arc::clone(&refresher) as _))
            .expect("credential");
        let presented = credential.bearer();

        let first = credential.refresh_rejected(presented.as_ref()).await;
        assert!(matches!(first, RefreshOutcome::Refreshed), "{first:?}");

        // The same stale bearer rejected again (a concurrent leg's 401 landing late).
        let second = credential.refresh_rejected(presented.as_ref()).await;

        assert!(matches!(second, RefreshOutcome::Refreshed), "{second:?}");
        assert_eq!(refresher.calls(), 1, "one rotation serves both rejections");
        assert_eq!(credential.refreshes(), 1);
    }

    #[test]
    fn fold_uses_the_status_message() {
        let status = Status::unavailable("gateway draining");
        assert_eq!(fold_status_message(&status), "gateway draining");
    }

    #[test]
    fn fold_falls_back_to_the_code_description_for_an_empty_message() {
        let status = Status::new(tonic::Code::Unavailable, "");
        assert_eq!(
            fold_status_message(&status),
            tonic::Code::Unavailable.description()
        );
    }

    /// A `Display`-only error chain fake: each hop renders its text and points at the next.
    #[derive(Debug)]
    struct ChainError(&'static str, Option<Box<ChainError>>);

    impl std::fmt::Display for ChainError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl StdError for ChainError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.1
                .as_deref()
                .map(|error| error as &(dyn StdError + 'static))
        }
    }

    #[test]
    fn fold_collapses_the_source_chain_without_debug_noise() {
        let mut status = Status::new(tonic::Code::Unknown, "transport error");
        status.set_source(std::sync::Arc::new(ChainError(
            "transport error",
            Some(Box::new(ChainError("connection refused", None))),
        )));

        // The repeated "transport error" hop collapses and the chain stays `Display`-only —
        // no `tonic::transport::Error(..)` debug internals.
        assert_eq!(
            fold_status_message(&status),
            "transport error: connection refused"
        );
    }

    #[test]
    fn fold_drops_hops_subsumed_by_a_more_specific_hop() {
        // Real-world shape: tonic stamps the root cause ("tcp connect error") into the status
        // message, and the deepest hop restates it with the OS detail.
        let mut status = Status::new(tonic::Code::Unavailable, "tcp connect error");
        status.set_source(std::sync::Arc::new(ChainError(
            "transport error",
            Some(Box::new(ChainError(
                "tcp connect error: Connection refused (os error 61)",
                None,
            ))),
        )));

        assert_eq!(
            fold_status_message(&status),
            "transport error: tcp connect error: Connection refused (os error 61)"
        );
    }

    #[test]
    fn build_channel_rejects_a_malformed_endpoint() {
        let error = build_channel("not a uri", true).expect_err("malformed endpoint");
        assert!(error.to_string().contains("invalid endpoint"));
    }
}
