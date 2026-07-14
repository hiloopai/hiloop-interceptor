//! Dual-stack transparent TCP acceptance and fail-closed upstream opening.

use std::{io, net::SocketAddr, time::Duration};

use async_trait::async_trait;
use hiloop_core::capture::{CaptureContractError, OriginalDestination, TlsFlowIdentity};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    time::Instant,
};

use crate::egress::EgressPolicy;

use super::{
    AuthorizedRoute, ClassificationError, ClassificationProgress, DnsAnswerEvidence, RouteDenial,
    TcpProtocol, authorize_route, classifier::MAX_CLASSIFICATION_BYTES, classify_tcp_prefix,
};

const CLASSIFICATION_TIMEOUT: Duration = Duration::from_secs(5);
const CLASSIFICATION_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Dual-stack listener pair inherited from the rootless network provisioner.
#[derive(Debug)]
pub struct TransparentTcpIngress {
    ipv4: TcpListener,
    ipv6: TcpListener,
}

impl TransparentTcpIngress {
    /// Convert the W2 listener descriptors into one asynchronous acceptor.
    pub fn from_std(ipv4: std::net::TcpListener, ipv6: std::net::TcpListener) -> io::Result<Self> {
        if !ipv4.local_addr()?.is_ipv4() || !ipv6.local_addr()?.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transparent ingress requires IPv4 then IPv6 listeners",
            ));
        }
        ipv4.set_nonblocking(true)?;
        ipv6.set_nonblocking(true)?;
        Ok(Self {
            ipv4: TcpListener::from_std(ipv4)?,
            ipv6: TcpListener::from_std(ipv6)?,
        })
    }

    /// Accept, classify, and authorize one flow without opening an upstream socket.
    pub async fn accept(
        &self,
        policy: &EgressPolicy,
        dns: &dyn DnsAnswerEvidence,
    ) -> Result<AdmittedTcpFlow, IngressError> {
        let (client, _) = tokio::select! {
            result = self.ipv4.accept() => result,
            result = self.ipv6.accept() => result,
        }
        .map_err(IngressError::Socket)?;
        let original_destination =
            recover_original_destination(&client).map_err(IngressError::Socket)?;
        let protocol = classify_stream(&client).await?;
        let route = authorize_route(policy, dns, original_destination, &protocol)?;
        Ok(AdmittedTcpFlow {
            client,
            route,
            protocol,
        })
    }

    /// Accept and authorize before asking the connector to open the upstream socket.
    pub async fn accept_and_connect<C: TcpUpstreamConnector>(
        &self,
        policy: &EgressPolicy,
        dns: &dyn DnsAnswerEvidence,
        connector: &C,
    ) -> Result<ConnectedTcpFlow<C::Stream>, IngressError> {
        let flow = self.accept(policy, dns).await?;
        connect_authorized(flow, connector)
            .await
            .map_err(IngressError::Upstream)
    }
}

/// A classified flow whose route passed egress policy and destination reconciliation.
#[derive(Debug)]
pub struct AdmittedTcpFlow {
    client: TcpStream,
    route: AuthorizedRoute,
    protocol: TcpProtocol,
}

impl AdmittedTcpFlow {
    /// Authorized routing decision.
    pub fn route(&self) -> &AuthorizedRoute {
        &self.route
    }

    /// Application protocol metadata parsed from the untouched client prefix.
    pub fn protocol(&self) -> &TcpProtocol {
        &self.protocol
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn into_test_parts(self) -> (TcpStream, AuthorizedRoute, TcpProtocol) {
        (self.client, self.route, self.protocol)
    }

    /// Build the W1 TLS event identity without defining a second event shape.
    pub fn tls_flow_identity(&self) -> Result<Option<TlsFlowIdentity>, CaptureContractError> {
        let TcpProtocol::TlsClientHello(hello) = &self.protocol else {
            return Ok(None);
        };
        let mut identity = TlsFlowIdentity::new(self.route.original_destination())
            .with_client_hello_fingerprint(hello.fingerprint())?;
        if let Some(server_name) = hello.server_name() {
            identity = identity.with_server_name(server_name)?;
        }
        Ok(Some(identity))
    }
}

/// Connector seam invoked only after an [`AdmittedTcpFlow`] exists.
#[async_trait]
pub trait TcpUpstreamConnector: Send + Sync {
    /// Stream returned for an admitted original destination.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// Open the authorized upstream transport without sending application bytes.
    async fn connect(&self, route: &AuthorizedRoute) -> io::Result<Self::Stream>;
}

/// Gateway-namespace connector for the admitted original destination.
#[derive(Debug, Default, Clone, Copy)]
pub struct DirectTcpConnector;

#[async_trait]
impl TcpUpstreamConnector for DirectTcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, route: &AuthorizedRoute) -> io::Result<Self::Stream> {
        // W2 intercepts only prerouting traffic arriving on the workload veth. A socket created
        // by this gateway follows the pasta-facing route and cannot re-enter that nftables hook.
        let destination = route.original_destination();
        TcpStream::connect(SocketAddr::new(destination.ip(), destination.port())).await
    }
}

/// Client and upstream streams after policy admission, with no bytes copied yet.
#[derive(Debug)]
pub struct ConnectedTcpFlow<S> {
    client: TcpStream,
    upstream: S,
    route: AuthorizedRoute,
    protocol: TcpProtocol,
}

impl<S> ConnectedTcpFlow<S> {
    /// Split the connected flow for the W4 TLS/capture decision.
    pub fn into_parts(self) -> (TcpStream, S, AuthorizedRoute, TcpProtocol) {
        (self.client, self.upstream, self.route, self.protocol)
    }
}

/// Open an upstream socket only for a previously authorized flow.
pub async fn connect_authorized<C: TcpUpstreamConnector>(
    flow: AdmittedTcpFlow,
    connector: &C,
) -> io::Result<ConnectedTcpFlow<C::Stream>> {
    let upstream = connector.connect(&flow.route).await?;
    Ok(ConnectedTcpFlow {
        client: flow.client,
        upstream,
        route: flow.route,
        protocol: flow.protocol,
    })
}

/// Recover the authoritative TPROXY destination from an accepted socket.
pub fn recover_original_destination(stream: &TcpStream) -> io::Result<OriginalDestination> {
    let destination = stream.local_addr()?;
    OriginalDestination::new(destination.ip(), destination.port())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

async fn classify_stream(stream: &TcpStream) -> Result<TcpProtocol, IngressError> {
    let deadline = Instant::now() + CLASSIFICATION_TIMEOUT;
    let mut prefix = vec![0; MAX_CLASSIFICATION_BYTES];
    loop {
        let available = tokio::time::timeout_at(deadline, stream.peek(&mut prefix))
            .await
            .map_err(|_| IngressError::ClassificationTimeout)?
            .map_err(IngressError::Socket)?;
        if available == 0 {
            return Err(IngressError::Socket(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before TCP classification completed",
            )));
        }
        match classify_tcp_prefix(&prefix[..available])? {
            ClassificationProgress::Classified(protocol) => return Ok(protocol),
            ClassificationProgress::NeedMore => {
                if Instant::now() >= deadline {
                    return Err(IngressError::ClassificationTimeout);
                }
                tokio::time::sleep(CLASSIFICATION_POLL_INTERVAL).await;
            }
        }
    }
}

/// Transparent ingress failure before application bytes can leave the gateway.
#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    /// Accepting or inspecting the client socket failed.
    #[error("transparent TCP socket failed: {0}")]
    Socket(#[source] io::Error),
    /// The prefix did not contain a supported, well-formed classification.
    #[error("transparent TCP classification failed: {0}")]
    Classification(#[from] ClassificationError),
    /// The client did not finish its routing prefix within the bounded deadline.
    #[error("transparent TCP classification timed out")]
    ClassificationTimeout,
    /// Egress policy or destination reconciliation denied the flow.
    #[error("transparent TCP route denied: {0}")]
    Denied(#[from] RouteDenial),
    /// Opening the admitted upstream transport failed before any application write.
    #[error("transparent TCP upstream connect failed: {0}")]
    Upstream(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

    use super::*;
    use crate::{
        egress::{EgressMode, EgressPolicy},
        netns::{NoDnsAnswerEvidence, RoutingIdentitySource, authorize_route},
    };

    #[tokio::test]
    async fn recovers_ipv4_and_ipv6_original_destinations() {
        for (ipv4, expected_ipv6) in [(true, false), (false, true)] {
            let (ingress, ipv4_address, ipv6_address) = ingress().expect("dual-stack ingress");
            let destination = if ipv4 { ipv4_address } else { ipv6_address };
            let client = tokio::spawn(async move {
                let mut stream = TcpStream::connect(destination).await.expect("connect");
                stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    .await
                    .expect("write request");
            });
            let flow = ingress
                .accept(&EgressPolicy::default(), &NoDnsAnswerEvidence)
                .await
                .expect("accepted flow");
            assert_eq!(
                flow.route().original_destination().ip().is_ipv6(),
                expected_ipv6
            );
            assert_eq!(
                flow.route().original_destination().port(),
                destination.port()
            );
            client.await.expect("client task");
        }
    }

    #[tokio::test]
    async fn policy_denial_happens_before_upstream_connect_or_bytes() {
        let (ingress, ipv4, _) = ingress().expect("dual-stack ingress");
        let connector = FakeConnector::default();
        let policy = EgressPolicy::new(EgressMode::Allow, ["blocked.example.com".to_owned()], [])
            .expect("policy");
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(ipv4).await.expect("connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\nsecret")
                .await
                .expect("write request");
        });

        assert!(matches!(
            ingress
                .accept_and_connect(&policy, &NoDnsAnswerEvidence, &connector)
                .await,
            Err(IngressError::Denied(RouteDenial::PolicyDenied { .. }))
        ));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        assert!(connector.peer.lock().expect("peer lock").is_none());
        client.await.expect("client task");
    }

    #[tokio::test]
    async fn admission_peeks_without_consuming_or_forwarding_prefix() {
        let (ingress, ipv4, _) = ingress().expect("dual-stack ingress");
        let connector = FakeConnector::default();
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(ipv4).await.expect("connect");
            stream.write_all(request).await.expect("write request");
        });
        let connected = ingress
            .accept_and_connect(&EgressPolicy::default(), &NoDnsAnswerEvidence, &connector)
            .await
            .expect("connected flow");
        let (mut accepted, _upstream, route, _) = connected.into_parts();
        assert_eq!(route.identity_source(), RoutingIdentitySource::HttpHost);
        let mut actual = vec![0; request.len()];
        accepted
            .read_exact(&mut actual)
            .await
            .expect("client prefix");
        assert_eq!(actual, request);

        let mut peer = connector
            .peer
            .lock()
            .expect("peer lock")
            .take()
            .expect("fake upstream peer");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.read_u8())
                .await
                .is_err(),
            "connector must not receive application bytes"
        );
        client.await.expect("client task");
    }

    #[tokio::test]
    async fn direct_connector_opens_once_without_writing_and_routing_is_ingress_only() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("upstream");
        let destination = upstream.local_addr().expect("upstream address");
        let original = OriginalDestination::new(destination.ip(), destination.port())
            .expect("original destination");
        let protocol = TcpProtocol::OtherTcp;
        let route = authorize_route(
            &EgressPolicy::default(),
            &NoDnsAnswerEvidence,
            original,
            &protocol,
        )
        .expect("authorized route");
        let client_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("client listener");
        let client_address = client_listener.local_addr().expect("client address");
        let client = tokio::spawn(TcpStream::connect(client_address));
        let (accepted, _) = client_listener.accept().await.expect("client accept");
        let _client = client.await.expect("client task").expect("client connect");
        let flow = AdmittedTcpFlow {
            client: accepted,
            route,
            protocol,
        };

        let connect = connect_authorized(flow, &DirectTcpConnector);
        let (connected, accepted) = tokio::join!(connect, upstream.accept());
        let _connected = connected.expect("direct connect");
        let (mut upstream_flow, _) = accepted.expect("upstream accept");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), upstream_flow.read_u8())
                .await
                .is_err(),
            "opening the admitted socket must not send application bytes"
        );
    }

    fn ingress() -> io::Result<(TransparentTcpIngress, SocketAddr, SocketAddr)> {
        let ipv4 = std::net::TcpListener::bind("127.0.0.1:0")?;
        let ipv6 = std::net::TcpListener::bind("[::1]:0")?;
        let ipv4_address = ipv4.local_addr()?;
        let ipv6_address = ipv6.local_addr()?;
        Ok((
            TransparentTcpIngress::from_std(ipv4, ipv6)?,
            ipv4_address,
            ipv6_address,
        ))
    }

    #[derive(Default)]
    struct FakeConnector {
        calls: AtomicUsize,
        peer: Arc<Mutex<Option<DuplexStream>>>,
    }

    #[async_trait]
    impl TcpUpstreamConnector for FakeConnector {
        type Stream = DuplexStream;

        async fn connect(&self, _route: &AuthorizedRoute) -> io::Result<Self::Stream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (gateway, peer) = tokio::io::duplex(1024);
            *self.peer.lock().expect("peer lock") = Some(peer);
            Ok(gateway)
        }
    }
}
