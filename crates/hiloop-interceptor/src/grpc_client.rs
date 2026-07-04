//! Shared plumbing for gRPC clients of a hiloop telemetry gateway: channel construction with the
//! interceptor's TLS trust policy, Bearer auth sourced from the environment, and compact rendering
//! of rejection `Status` chains. Used by the event exporter ([`crate::grpc_export`]) and the blob
//! uploader ([`crate::blob_upload`]) so the two clients can never drift on endpoint, trust, or
//! credential handling.

use std::error::Error as StdError;

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
/// stays out of process provenance (`process.argv`).
pub const TOKEN_ENV: &str = "HILOOP_API_KEY";

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
    Ok(builder.connect_lazy())
}

/// Read the Bearer token from [`TOKEN_ENV`]. Absent/empty means no auth header (an
/// unauthenticated dev gateway).
pub(crate) fn bearer_from_env() -> Result<Option<MetadataValue<Ascii>>, GrpcClientError> {
    match std::env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty()) {
        Some(token) => format!("Bearer {token}").parse().map(Some).map_err(
            |error: tonic::metadata::errors::InvalidMetadataValue| {
                GrpcClientError::InvalidToken(Box::new(error))
            },
        ),
        None => Ok(None),
    }
}

/// Attaches `authorization: Bearer <token>` to every request when a token is configured.
#[derive(Clone)]
pub(crate) struct AuthInterceptor {
    bearer: Option<MetadataValue<Ascii>>,
}

impl AuthInterceptor {
    /// Build from the token in [`TOKEN_ENV`] (absent/empty → no auth header).
    pub(crate) fn from_env() -> Result<Self, GrpcClientError> {
        Ok(Self {
            bearer: bearer_from_env()?,
        })
    }
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
