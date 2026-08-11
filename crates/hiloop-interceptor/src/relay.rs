//! Fixed, proof-bound relay configuration for exact HTTPS destinations.

use std::{
    collections::BTreeSet,
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::StreamExt as _;
use http_body_util::{BodyStream, StreamBody};
use hudsucker::{
    Body,
    hyper::{
        Request, Uri,
        body::Frame,
        header::{AUTHORIZATION, CONNECTION, HOST, HeaderValue, UPGRADE},
    },
    hyper_util::client::legacy::connect::HttpConnector,
    rustls::{
        ClientConfig, RootCertStore,
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, ServerName},
    },
};
use hyper_rustls::{FixedServerNameResolver, HttpsConnectorBuilder};
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tower_service::Service;

use crate::egress::{CanonicalHost, Destination, canonicalize_host};

pub(crate) const SECRET_PROOF_HEADER: &str = "x-hiloop-secret-proof";
const HILOOP_PRIVATE_HEADER_PREFIX: &str = "x-hiloop-";
const SEC_WEBSOCKET_KEY_HEADER: &str = "sec-websocket-key";
const SEC_WEBSOCKET_VERSION_HEADER: &str = "sec-websocket-version";
const MAX_PROOF_BYTES: usize = 16 * 1024;
const PROOF_IO_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const RELAY_CONNECT_TLS_TIMEOUT: Duration = Duration::from_secs(3);

/// An exact DNS destination whose HTTPS port is always 443.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundHttpsSelector {
    host: String,
}

impl BoundHttpsSelector {
    /// Validate and canonicalize an exact DNS host.
    ///
    /// # Errors
    ///
    /// Returns [`RelayConfigError::Selector`] unless `host` is one exact DNS name
    /// without a port, wildcard, IP literal, or single-label spelling.
    pub fn new(host: impl Into<String>) -> Result<Self, RelayConfigError> {
        let host = host.into();
        let destination = canonicalize_host(&host).map_err(|_| RelayConfigError::Selector {
            value: host.clone(),
        })?;
        match (destination.host(), destination.port()) {
            (CanonicalHost::Domain(host), None) if host.contains('.') && !host.contains('*') => {
                Ok(Self { host: host.clone() })
            }
            _ => Err(RelayConfigError::Selector { value: host }),
        }
    }

    /// The canonical ASCII DNS host.
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// One fixed TLS next hop for an immutable set of exact public HTTPS selectors.
#[derive(Clone)]
pub struct FixedTlsRelayConfig {
    endpoint: SocketAddr,
    server_name: ServerName<'static>,
    trust_anchors: Arc<[CertificateDer<'static>]>,
    proof_file: PathBuf,
    selectors: Arc<BTreeSet<BoundHttpsSelector>>,
    bound_port: u16,
}

type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;
type ConnectorResponse = <HttpsConnector as Service<Uri>>::Response;
type ConnectorError = <HttpsConnector as Service<Uri>>::Error;

#[derive(Clone)]
pub(crate) struct RelayRoutingConnector {
    direct: HttpsConnector,
    relay: Option<RelayUpstream>,
}

#[derive(Clone)]
struct RelayUpstream {
    connector: HttpsConnector,
    transport_uri: Uri,
    config: FixedTlsRelayConfig,
}

impl FixedTlsRelayConfig {
    /// Build the closed relay capability used by one capture sidecar.
    ///
    /// # Errors
    ///
    /// Returns [`RelayConfigError`] when the endpoint, TLS identity or roots, proof
    /// path, or exact selector set violates the closed relay contract.
    pub fn new(
        endpoint: SocketAddr,
        server_name: impl Into<String>,
        trust_anchors: Vec<CertificateDer<'static>>,
        proof_file: PathBuf,
        selectors: impl IntoIterator<Item = BoundHttpsSelector>,
    ) -> Result<Self, RelayConfigError> {
        if endpoint.port() == 0 {
            return Err(RelayConfigError::Endpoint);
        }
        let server_name = server_name.into();
        let server_name = ServerName::try_from(server_name.clone())
            .map_err(|_| RelayConfigError::ServerName { value: server_name })?;
        if trust_anchors.is_empty() || trust_anchors.iter().any(|cert| !is_ca_certificate(cert)) {
            return Err(RelayConfigError::TrustAnchors);
        }
        if !proof_file.is_absolute() {
            return Err(RelayConfigError::ProofPath);
        }
        let mut exact = BTreeSet::new();
        for selector in selectors {
            if !exact.insert(selector.clone()) {
                return Err(RelayConfigError::DuplicateSelector {
                    host: selector.host,
                });
            }
        }
        if exact.is_empty() {
            return Err(RelayConfigError::EmptySelectors);
        }
        Ok(Self {
            endpoint,
            server_name,
            trust_anchors: trust_anchors.into(),
            proof_file,
            selectors: Arc::new(exact),
            bound_port: 443,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_bound_port_for_test(mut self, port: u16) -> Self {
        self.bound_port = port;
        self
    }

    const fn bound_port(&self) -> u16 {
        self.bound_port
    }

    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub(crate) fn server_name(&self) -> ServerName<'static> {
        self.server_name.clone()
    }

    pub(crate) fn route_uri(&self, uri: &Uri) -> RelayRoute {
        let Some(authority) = uri.authority() else {
            return RelayRoute::Direct;
        };
        let Ok(destination) = canonicalize_host(authority.as_str()) else {
            return RelayRoute::Direct;
        };
        self.route_destination(uri.scheme_str(), &destination)
    }

    pub(crate) fn route_destination(
        &self,
        scheme: Option<&str>,
        destination: &Destination,
    ) -> RelayRoute {
        if !self.contains_host(destination.host()) {
            return RelayRoute::Direct;
        }
        if scheme == Some("https") && destination.port().unwrap_or(443) == self.bound_port() {
            RelayRoute::Bound
        } else {
            RelayRoute::Denied
        }
    }

    pub(crate) fn route_connect(&self, destination: &Destination) -> RelayRoute {
        if !self.contains_host(destination.host()) {
            return RelayRoute::Direct;
        }
        if destination.port() == Some(self.bound_port()) {
            RelayRoute::Bound
        } else {
            RelayRoute::Denied
        }
    }

    pub(crate) fn contains_host(&self, host: &CanonicalHost) -> bool {
        let CanonicalHost::Domain(host) = host else {
            return false;
        };
        self.selectors
            .contains(&BoundHttpsSelector { host: host.clone() })
    }

    pub(crate) fn tls_client_config(&self) -> Result<ClientConfig, RelayConfigError> {
        let mut roots = RootCertStore::empty();
        for anchor in self.trust_anchors.iter() {
            roots
                .add(anchor.clone())
                .map_err(|_| RelayConfigError::TrustAnchors)?;
        }
        ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| RelayConfigError::Tls)
            .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
    }

    pub(crate) fn validate_connector(&self) -> Result<(), RelayConfigError> {
        self.transport_uri()?;
        self.tls_client_config().map(drop)
    }

    fn transport_uri(&self) -> Result<Uri, RelayConfigError> {
        format!("https://{}/", self.endpoint())
            .parse()
            .map_err(|_| RelayConfigError::Tls)
    }

    pub(crate) async fn read_proof(&self) -> Result<HeaderValue, RelayProofError> {
        let path = self.proof_file.clone();
        let mut bytes = tokio::time::timeout(PROOF_IO_TIMEOUT, async move {
            let file = tokio::task::spawn_blocking(move || {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.custom_flags(nix::libc::O_NONBLOCK);
                }
                let file = options.open(path)?;
                if !file.metadata()?.file_type().is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "proof path is not a regular file",
                    ));
                }
                Ok::<_, io::Error>(file)
            })
            .await
            .map_err(|_| RelayProofError::Unavailable)?
            .map_err(|_| RelayProofError::Unavailable)?;
            let mut bytes = Vec::with_capacity(MAX_PROOF_BYTES + 1);
            tokio::fs::File::from_std(file)
                .take((MAX_PROOF_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| RelayProofError::Unavailable)?;
            Ok::<_, RelayProofError>(bytes)
        })
        .await
        .map_err(|_| RelayProofError::Unavailable)??;
        while matches!(bytes.last(), Some(b'\r' | b'\n')) {
            bytes.pop();
        }
        if bytes.is_empty() || bytes.len() > MAX_PROOF_BYTES {
            return Err(RelayProofError::Invalid);
        }
        let mut value = HeaderValue::from_bytes(&bytes).map_err(|_| RelayProofError::Invalid)?;
        value.set_sensitive(true);
        Ok(value)
    }

    pub(crate) fn request_mentions_bound_host<B>(&self, request: &Request<B>) -> bool {
        request.headers().get_all(HOST).iter().any(|value| {
            value
                .to_str()
                .ok()
                .and_then(|host| canonicalize_host(host).ok())
                .is_some_and(|destination| self.contains_host(destination.host()))
        })
    }

    pub(crate) async fn prepare_request<B>(
        &self,
        request: &mut Request<B>,
        connect_destination: Option<&Destination>,
        destination: &Destination,
    ) -> Result<(), SecretEgressDenial> {
        if connect_destination
            .is_none_or(|connect| self.route_connect(connect) != RelayRoute::Bound)
            || request_has_ambiguous_authority(request, destination)
            || is_websocket_request(request)
        {
            return Err(SecretEgressDenial::AuthorityOrProtocolMismatch);
        }
        let proof = self
            .read_proof()
            .await
            .map_err(|_| SecretEgressDenial::ProofUnavailable)?;
        scrub_private_headers(request.headers_mut());
        request.headers_mut().insert(SECRET_PROOF_HEADER, proof);
        Ok(())
    }
}

pub(crate) fn scrub_private_trailers(body: Body) -> Body {
    let frames = BodyStream::new(body).map(|result| {
        result.map(|frame| match frame.into_trailers() {
            Ok(mut trailers) => {
                scrub_private_headers(&mut trailers);
                Frame::trailers(trailers)
            }
            Err(frame) => frame,
        })
    });
    Body::from(StreamBody::new(frames))
}

fn scrub_private_headers(headers: &mut hudsucker::hyper::HeaderMap) {
    headers.remove(AUTHORIZATION);
    let private_headers = headers
        .keys()
        .filter(|name| name.as_str().starts_with(HILOOP_PRIVATE_HEADER_PREFIX))
        .cloned()
        .collect::<Vec<_>>();
    for name in private_headers {
        headers.remove(name);
    }
}

impl RelayRoutingConnector {
    pub(crate) fn new(
        direct_tls: ClientConfig,
        relay: Option<FixedTlsRelayConfig>,
    ) -> Result<Self, RelayConfigError> {
        let direct = HttpsConnectorBuilder::new()
            .with_tls_config(direct_tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let relay = relay.map(RelayUpstream::new).transpose()?;
        Ok(Self { direct, relay })
    }
}

impl RelayUpstream {
    fn new(config: FixedTlsRelayConfig) -> Result<Self, RelayConfigError> {
        let transport_uri = config.transport_uri()?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(config.tls_client_config()?)
            .https_only()
            .with_server_name_resolver(FixedServerNameResolver::new(config.server_name()))
            .enable_http1()
            .enable_http2()
            .build();
        Ok(Self {
            connector,
            transport_uri,
            config,
        })
    }
}

impl Service<Uri> for RelayRoutingConnector {
    type Response = ConnectorResponse;
    type Error = ConnectorError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Poll::Ready(result) = self.direct.poll_ready(context) {
            result?;
        } else {
            return Poll::Pending;
        }
        if let Some(relay) = &mut self.relay {
            relay.connector.poll_ready(context)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        match self
            .relay
            .as_mut()
            .map(|relay| relay.config.route_uri(&destination))
        {
            Some(RelayRoute::Bound) => {
                let Some(relay) = self.relay.as_mut() else {
                    return Box::pin(async {
                        Err(io::Error::other("fixed relay configuration disappeared").into())
                    });
                };
                let connect = relay.connector.call(relay.transport_uri.clone());
                Box::pin(async move {
                    tokio::time::timeout(RELAY_CONNECT_TLS_TIMEOUT, connect)
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "fixed relay connect timed out")
                        })?
                })
            }
            Some(RelayRoute::Denied) => Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bound secret destination requires exact HTTPS port 443",
                )
                .into())
            }),
            Some(RelayRoute::Direct) | None => self.direct.call(destination),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayRoute {
    Direct,
    Bound,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretEgressDenial {
    NestedConnect,
    InvalidConnectAuthority,
    AmbiguousAuthority,
    InvalidDestination,
    AuthorityOrProtocolMismatch,
    ProofUnavailable,
}

impl SecretEgressDenial {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NestedConnect => "nested_connect",
            Self::InvalidConnectAuthority => "invalid_connect_authority",
            Self::AmbiguousAuthority => "ambiguous_authority",
            Self::InvalidDestination => "invalid_destination",
            Self::AuthorityOrProtocolMismatch => "authority_or_protocol_mismatch",
            Self::ProofUnavailable => "proof_unavailable",
        }
    }

    pub(crate) const fn proof_unavailable(self) -> bool {
        matches!(self, Self::ProofUnavailable)
    }
}

/// Invalid fixed-relay configuration.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum RelayConfigError {
    #[error("bound HTTPS selector must be one exact DNS host without a port: `{value}`")]
    Selector { value: String },
    #[error("fixed TLS relay endpoint must use a nonzero port")]
    Endpoint,
    #[error("invalid fixed TLS relay server name `{value}`")]
    ServerName { value: String },
    #[error("fixed TLS relay requires only valid CA trust anchors")]
    TrustAnchors,
    #[error("fixed TLS relay proof path must be absolute")]
    ProofPath,
    #[error("fixed TLS relay requires at least one selector")]
    EmptySelectors,
    #[error("duplicate fixed TLS relay selector `{host}`")]
    DuplicateSelector { host: String },
    #[error("fixed TLS relay client configuration failed")]
    Tls,
}

/// A per-request proof could not be safely loaded.
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum RelayProofError {
    #[error("secret-egress proof is unavailable")]
    Unavailable,
    #[error("secret-egress proof is invalid")]
    Invalid,
}

pub(crate) fn is_ca_certificate(anchor: &CertificateDer<'_>) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(anchor.as_ref()) else {
        return false;
    };
    let key_cert_sign = match cert.key_usage() {
        Ok(Some(key_usage)) => key_usage.value.key_cert_sign(),
        Ok(None) => true,
        Err(_) => false,
    };
    cert.is_ca() && key_cert_sign
}

fn request_has_ambiguous_authority<B>(request: &Request<B>, destination: &Destination) -> bool {
    if request.uri().scheme_str() != Some("https") || request.uri().authority().is_none() {
        return true;
    }
    header_authority_mismatch(request, destination)
}

pub(crate) fn connect_has_ambiguous_authority<B>(
    request: &Request<B>,
    destination: &Destination,
) -> bool {
    header_authority_mismatch(request, destination)
}

fn header_authority_mismatch<B>(request: &Request<B>, destination: &Destination) -> bool {
    let mut hosts = request.headers().get_all(HOST).iter();
    let Some(host) = hosts.next() else {
        return false;
    };
    if hosts.next().is_some() {
        return true;
    }
    let Ok(host) = host.to_str() else {
        return true;
    };
    let Ok(header_destination) = canonicalize_host(host) else {
        return true;
    };
    header_destination.host() != destination.host()
        || header_destination.port().unwrap_or(443) != 443
}

fn is_websocket_request<B>(request: &Request<B>) -> bool {
    request.headers().contains_key(UPGRADE)
        || request.headers().contains_key(SEC_WEBSOCKET_KEY_HEADER)
        || request.headers().contains_key(SEC_WEBSOCKET_VERSION_HEADER)
        || request.headers().get_all(CONNECTION).iter().any(|value| {
            value.to_str().ok().is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use hudsucker::rustls::pki_types::pem::PemObject as _;

    fn ca() -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("CA");
        CertificateDer::from_pem_slice(cert.pem().as_bytes()).expect("DER")
    }

    fn config(proof_file: PathBuf) -> FixedTlsRelayConfig {
        FixedTlsRelayConfig::new(
            "127.0.0.1:8443".parse().expect("endpoint"),
            "secret-egress.test",
            vec![ca()],
            proof_file,
            [BoundHttpsSelector::new("API.Example.COM.").expect("selector")],
        )
        .expect("config")
    }

    #[test]
    fn selector_is_exact_canonical_dns_without_port_or_ip() {
        assert_eq!(
            BoundHttpsSelector::new("API.Example.COM.")
                .expect("selector")
                .host(),
            "api.example.com"
        );
        for invalid in [
            "localhost",
            "api.example.com:443",
            "*.example.com",
            "127.0.0.1",
            "[::1]",
        ] {
            assert!(BoundHttpsSelector::new(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn route_is_exact_https_443_and_same_host_other_shapes_deny() {
        let relay = config(PathBuf::from("/proof"));
        for bound in [
            "https://api.example.com/v1",
            "https://api.example.com:443/v1",
        ] {
            assert_eq!(
                relay.route_uri(&bound.parse().expect("URI")),
                RelayRoute::Bound
            );
        }
        for denied in [
            "http://api.example.com/v1",
            "https://api.example.com:444/v1",
        ] {
            assert_eq!(
                relay.route_uri(&denied.parse().expect("URI")),
                RelayRoute::Denied
            );
        }
        assert_eq!(
            relay.route_uri(&"https://other.example.com/v1".parse().expect("URI")),
            RelayRoute::Direct
        );
    }

    #[test]
    fn relay_config_rejects_ambiguous_or_open_capabilities() {
        let selector = BoundHttpsSelector::new("api.example.com").expect("selector");
        let endpoint = "127.0.0.1:8443".parse().expect("endpoint");
        let proof = PathBuf::from("/proof");

        assert!(matches!(
            FixedTlsRelayConfig::new(
                "127.0.0.1:0".parse().expect("zero-port endpoint"),
                "secret-egress.test",
                vec![ca()],
                proof.clone(),
                [selector.clone()],
            ),
            Err(RelayConfigError::Endpoint)
        ));
        assert!(matches!(
            FixedTlsRelayConfig::new(
                endpoint,
                "invalid server name",
                vec![ca()],
                proof.clone(),
                [selector.clone()],
            ),
            Err(RelayConfigError::ServerName { .. })
        ));
        assert!(matches!(
            FixedTlsRelayConfig::new(
                endpoint,
                "secret-egress.test",
                Vec::new(),
                proof.clone(),
                [selector.clone()],
            ),
            Err(RelayConfigError::TrustAnchors)
        ));
        assert!(matches!(
            FixedTlsRelayConfig::new(
                endpoint,
                "secret-egress.test",
                vec![ca()],
                PathBuf::from("relative-proof"),
                [selector.clone()],
            ),
            Err(RelayConfigError::ProofPath)
        ));
        assert!(matches!(
            FixedTlsRelayConfig::new(
                endpoint,
                "secret-egress.test",
                vec![ca()],
                proof.clone(),
                [],
            ),
            Err(RelayConfigError::EmptySelectors)
        ));
        assert!(matches!(
            FixedTlsRelayConfig::new(
                endpoint,
                "secret-egress.test",
                vec![ca()],
                proof,
                [selector.clone(), selector],
            ),
            Err(RelayConfigError::DuplicateSelector { .. })
        ));
    }

    #[test]
    fn secret_egress_denial_codes_are_stable() {
        assert_eq!(
            [
                SecretEgressDenial::NestedConnect,
                SecretEgressDenial::InvalidConnectAuthority,
                SecretEgressDenial::AmbiguousAuthority,
                SecretEgressDenial::InvalidDestination,
                SecretEgressDenial::AuthorityOrProtocolMismatch,
                SecretEgressDenial::ProofUnavailable,
            ]
            .map(SecretEgressDenial::as_str),
            [
                "nested_connect",
                "invalid_connect_authority",
                "ambiguous_authority",
                "invalid_destination",
                "authority_or_protocol_mismatch",
                "proof_unavailable",
            ]
        );
    }

    #[tokio::test]
    async fn proof_is_read_fresh_bounded_and_marked_sensitive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("proof");
        tokio::fs::write(&path, b"first\n").await.expect("write");
        let relay = config(path.clone());

        let first = relay.read_proof().await.expect("first proof");
        assert_eq!(first.as_bytes(), b"first");
        assert!(first.is_sensitive());

        tokio::fs::write(&path, b"second").await.expect("rotate");
        assert_eq!(
            relay.read_proof().await.expect("rotated").as_bytes(),
            b"second"
        );

        tokio::fs::write(&path, vec![b'x'; MAX_PROOF_BYTES + 1])
            .await
            .expect("oversized");
        assert_eq!(relay.read_proof().await, Err(RelayProofError::Invalid));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proof_rejects_devices_and_fifos_without_blocking() {
        let device = config(PathBuf::from("/dev/zero"));
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(250), device.read_proof())
                .await
                .expect("device rejection is prompt"),
            Err(RelayProofError::Unavailable)
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("proof.fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("run mkfifo")
                .success()
        );
        let fifo = config(fifo);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(250), fifo.read_proof())
                .await
                .expect("FIFO rejection is prompt"),
            Err(RelayProofError::Unavailable)
        );
    }
}
