use std::{
    ffi::OsString,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
    sync::Mutex,
};

use super::{
    DnsAnswerTracker,
    resolver::{DnsTransport, HostResolver},
};

const DNS_PORT: u16 = 53;
const RELAY_PROTOCOL_VERSION: u8 = 1;
const RELAY_STATUS_OK: u8 = 0;
const RELAY_STATUS_ERROR: u8 = 1;
const MAX_ERROR_BYTES: usize = 1024;

/// Gateway-worker environment variable naming the private host DNS relay socket.
pub const DNS_RELAY_SOCKET_ENV: &str = "HILOOP_DNS_RELAY_SOCKET";

/// DNS transport selected by the workload resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryTransport {
    /// A DNS datagram query.
    Udp,
    /// A length-prefixed DNS stream query, including truncated-response fallback.
    Tcp,
}

impl From<DnsQueryTransport> for DnsTransport {
    fn from(transport: DnsQueryTransport) -> Self {
        match transport {
            DnsQueryTransport::Udp => Self::Udp,
            DnsQueryTransport::Tcp => Self::Tcp,
        }
    }
}

/// Serialized private-channel client used by the gateway namespace.
#[derive(Debug)]
pub struct DnsRelayClient {
    stream: UnixStream,
}

impl DnsRelayClient {
    /// Connect to the host-namespace relay path supplied by the substrate.
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            stream: UnixStream::connect(path).await?,
        })
    }

    /// Connect using [`DNS_RELAY_SOCKET_ENV`].
    pub async fn connect_from_environment() -> io::Result<Self> {
        let path = std::env::var_os(DNS_RELAY_SOCKET_ENV).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{DNS_RELAY_SOCKET_ENV} is not set"),
            )
        })?;
        Self::connect(PathBuf::from(path)).await
    }

    /// Relay one unmodified DNS message through the host network namespace.
    pub async fn query(
        &mut self,
        transport: DnsQueryTransport,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let length = u16::try_from(query.len()).map_err(invalid_input)?;
        self.stream.write_u8(RELAY_PROTOCOL_VERSION).await?;
        self.stream
            .write_u8(match transport {
                DnsQueryTransport::Udp => 0,
                DnsQueryTransport::Tcp => 1,
            })
            .await?;
        self.stream.write_u16(length).await?;
        self.stream.write_all(query).await?;
        self.stream.flush().await?;

        let status = self.stream.read_u8().await?;
        let response_length = usize::from(self.stream.read_u16().await?);
        let mut response = vec![0_u8; response_length];
        self.stream.read_exact(&mut response).await?;
        match status {
            RELAY_STATUS_OK => Ok(response),
            RELAY_STATUS_ERROR => Err(io::Error::other(
                String::from_utf8_lossy(&response).into_owned(),
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host DNS relay returned an unknown status",
            )),
        }
    }
}

pub(super) struct HostDnsRelay {
    listener: UnixListener,
    resolver: HostResolver,
}

impl HostDnsRelay {
    pub(super) fn bind(path: &Path, resolver: HostResolver) -> io::Result<Self> {
        Ok(Self {
            listener: UnixListener::bind(path)?,
            resolver,
        })
    }

    pub(super) async fn serve(self) -> io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            serve_host_connection(stream, &self.resolver).await?;
        }
    }
}

async fn serve_host_connection(mut stream: UnixStream, resolver: &HostResolver) -> io::Result<()> {
    loop {
        let mut version = [0_u8; 1];
        if stream.read(&mut version).await? == 0 {
            return Ok(());
        }
        if version[0] != RELAY_PROTOCOL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported host DNS relay protocol version",
            ));
        }
        let transport = match stream.read_u8().await? {
            0 => DnsTransport::Udp,
            1 => DnsTransport::Tcp,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "host DNS relay received an unknown transport",
                ));
            }
        };
        let query_length = usize::from(stream.read_u16().await?);
        if query_length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host DNS relay received an empty query",
            ));
        }
        let mut query = vec![0_u8; query_length];
        stream.read_exact(&mut query).await?;
        match resolver.query(transport, &query).await {
            Ok(response) => write_relay_response(&mut stream, RELAY_STATUS_OK, &response).await?,
            Err(error) => {
                let mut diagnostic = error.to_string().into_bytes();
                diagnostic.truncate(MAX_ERROR_BYTES);
                write_relay_response(&mut stream, RELAY_STATUS_ERROR, &diagnostic).await?;
            }
        }
    }
}

async fn write_relay_response(
    stream: &mut UnixStream,
    status: u8,
    payload: &[u8],
) -> io::Result<()> {
    let length = u16::try_from(payload.len()).map_err(invalid_input)?;
    stream.write_u8(status).await?;
    stream.write_u16(length).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Dedicated dual-stack DNS listener in the gateway namespace.
pub struct GatewayDnsRelay {
    udp_ipv4: UdpSocket,
    udp_ipv6: UdpSocket,
    tcp_ipv4: TcpListener,
    tcp_ipv6: TcpListener,
    client: Arc<Mutex<DnsRelayClient>>,
    tracker: Arc<DnsAnswerTracker>,
}

impl std::fmt::Debug for GatewayDnsRelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayDnsRelay")
            .finish_non_exhaustive()
    }
}

impl GatewayDnsRelay {
    /// Bind the reserved UDP and TCP port 53 listeners on both gateway addresses.
    pub async fn bind(
        gateway_ipv4: Ipv4Addr,
        gateway_ipv6: Ipv6Addr,
        client: DnsRelayClient,
        tracker: Arc<DnsAnswerTracker>,
    ) -> io::Result<Self> {
        Self::bind_on(
            SocketAddr::new(gateway_ipv4.into(), DNS_PORT),
            SocketAddr::new(gateway_ipv6.into(), DNS_PORT),
            client,
            tracker,
        )
        .await
    }

    async fn bind_on(
        ipv4: SocketAddr,
        ipv6: SocketAddr,
        client: DnsRelayClient,
        tracker: Arc<DnsAnswerTracker>,
    ) -> io::Result<Self> {
        if !ipv4.is_ipv4() || !ipv6.is_ipv6() || ipv4.port() != ipv6.port() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway DNS listeners require matching IPv4 and IPv6 ports",
            ));
        }
        Ok(Self {
            udp_ipv4: UdpSocket::bind(ipv4).await?,
            udp_ipv6: UdpSocket::bind(ipv6).await?,
            tcp_ipv4: TcpListener::bind(ipv4).await?,
            tcp_ipv6: TcpListener::bind(ipv6).await?,
            client: Arc::new(Mutex::new(client)),
            tracker,
        })
    }

    /// Serve all four reserved listener surfaces until one encounters a dataplane error.
    pub async fn serve(self) -> io::Result<()> {
        let Self {
            udp_ipv4,
            udp_ipv6,
            tcp_ipv4,
            tcp_ipv6,
            client,
            tracker,
        } = self;
        tokio::try_join!(
            serve_gateway_udp(udp_ipv4, Arc::clone(&client), Arc::clone(&tracker)),
            serve_gateway_udp(udp_ipv6, Arc::clone(&client), Arc::clone(&tracker)),
            serve_gateway_tcp(tcp_ipv4, Arc::clone(&client), Arc::clone(&tracker)),
            serve_gateway_tcp(tcp_ipv6, client, tracker),
        )?;
        Ok(())
    }
}

async fn serve_gateway_udp(
    socket: UdpSocket,
    client: Arc<Mutex<DnsRelayClient>>,
    tracker: Arc<DnsAnswerTracker>,
) -> io::Result<()> {
    let mut query = vec![0_u8; usize::from(u16::MAX)];
    loop {
        let (length, peer) = socket.recv_from(&mut query).await?;
        let query = &query[..length];
        let response = match client
            .lock()
            .await
            .query(DnsQueryTransport::Udp, query)
            .await
        {
            Ok(response) => response,
            Err(_) => servfail(query),
        };
        if socket.send_to(&response, peer).await? != response.len() {
            return Err(io::Error::other("gateway DNS response was partially sent"));
        }
        tracker.record_response(query, &response);
    }
}

async fn serve_gateway_tcp(
    listener: TcpListener,
    client: Arc<Mutex<DnsRelayClient>>,
    tracker: Arc<DnsAnswerTracker>,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let client = Arc::clone(&client);
        let tracker = Arc::clone(&tracker);
        tokio::spawn(async move {
            let _ = serve_gateway_tcp_connection(stream, client, tracker).await;
        });
    }
}

async fn serve_gateway_tcp_connection(
    mut stream: TcpStream,
    client: Arc<Mutex<DnsRelayClient>>,
    tracker: Arc<DnsAnswerTracker>,
) -> io::Result<()> {
    loop {
        let length = match stream.read_u16().await {
            Ok(length) => usize::from(length),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gateway DNS listener received an empty TCP query",
            ));
        }
        let mut query = vec![0_u8; length];
        stream.read_exact(&mut query).await?;
        let response = match client
            .lock()
            .await
            .query(DnsQueryTransport::Tcp, &query)
            .await
        {
            Ok(response) => response,
            Err(_) => servfail(&query),
        };
        let response_length = u16::try_from(response.len()).map_err(invalid_input)?;
        stream.write_u16(response_length).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        tracker.record_response(&query, &response);
    }
}

fn servfail(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    if response.len() >= 12 {
        let request_flags = u16::from_be_bytes([response[2], response[3]]);
        let flags = 0x8000 | (request_flags & 0x7900) | 0x0080 | 0x0002;
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[6..12].fill(0);
    }
    response
}

pub(super) fn relay_socket_environment(path: &Path) -> (OsString, OsString) {
    (DNS_RELAY_SOCKET_ENV.into(), path.as_os_str().to_owned())
}

fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn host_namespace_relay_preserves_udp_and_tcp_queries() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("UDP fixture");
        let address = udp.local_addr().expect("UDP fixture address");
        let tcp = TcpListener::bind(address).await.expect("TCP fixture");
        let udp_fixture = tokio::spawn(async move {
            let mut query = [0_u8; 512];
            let (length, peer) = udp.recv_from(&mut query).await.expect("fixture receive");
            let response = response(&query[..length]);
            udp.send_to(&response, peer).await.expect("fixture send");
        });
        let tcp_fixture = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.expect("fixture accept");
            let length = stream.read_u16().await.expect("fixture length");
            let mut query = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut query).await.expect("fixture query");
            let response = response(&query);
            stream
                .write_u16(u16::try_from(response.len()).expect("fixture response length"))
                .await
                .expect("fixture response length");
            stream.write_all(&response).await.expect("fixture response");
        });

        let directory = tempfile::tempdir().expect("relay directory");
        let path = directory.path().join("dns.sock");
        let resolver =
            HostResolver::new(vec![address], Duration::from_secs(1)).expect("host resolver");
        let relay = HostDnsRelay::bind(&path, resolver).expect("host relay");
        let relay_task = tokio::spawn(relay.serve());
        let mut client = DnsRelayClient::connect(&path).await.expect("relay client");
        let query = query();

        for transport in [DnsQueryTransport::Udp, DnsQueryTransport::Tcp] {
            let relayed = client.query(transport, &query).await.expect("relay query");
            assert_eq!(relayed, response(&query));
        }

        udp_fixture.await.expect("UDP fixture task");
        tcp_fixture.await.expect("TCP fixture task");
        relay_task.abort();
    }

    #[tokio::test]
    async fn gateway_reserves_dual_stack_udp_and_tcp_listeners() {
        let upstream_udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("upstream UDP fixture");
        let upstream = upstream_udp.local_addr().expect("upstream address");
        let upstream_tcp = TcpListener::bind(upstream)
            .await
            .expect("upstream TCP fixture");
        let udp_fixture = tokio::spawn(async move {
            let mut query = [0_u8; 512];
            let (length, peer) = upstream_udp
                .recv_from(&mut query)
                .await
                .expect("upstream UDP receive");
            upstream_udp
                .send_to(&response(&query[..length]), peer)
                .await
                .expect("upstream UDP response");
        });
        let tcp_fixture = tokio::spawn(async move {
            let (mut stream, _) = upstream_tcp.accept().await.expect("upstream TCP accept");
            let length = stream.read_u16().await.expect("upstream TCP length");
            let mut query = vec![0_u8; usize::from(length)];
            stream
                .read_exact(&mut query)
                .await
                .expect("upstream TCP query");
            let response = response(&query);
            stream
                .write_u16(u16::try_from(response.len()).expect("response length"))
                .await
                .expect("upstream response length");
            stream
                .write_all(&response)
                .await
                .expect("upstream TCP response");
        });

        let directory = tempfile::tempdir().expect("relay directory");
        let relay_path = directory.path().join("dns.sock");
        let host_relay = HostDnsRelay::bind(
            &relay_path,
            HostResolver::new(vec![upstream], Duration::from_secs(1)).expect("host resolver"),
        )
        .expect("host relay");
        let host_task = tokio::spawn(host_relay.serve());
        let client = DnsRelayClient::connect(&relay_path)
            .await
            .expect("relay client");

        let reservation =
            std::net::TcpListener::bind("127.0.0.1:0").expect("gateway port reservation");
        let port = reservation.local_addr().expect("reserved address").port();
        drop(reservation);
        let gateway = GatewayDnsRelay::bind_on(
            format!("127.0.0.1:{port}").parse().expect("gateway IPv4"),
            format!("[::1]:{port}").parse().expect("gateway IPv6"),
            client,
            Arc::new(DnsAnswerTracker::default()),
        )
        .await
        .expect("gateway DNS relay");
        let gateway_task = tokio::spawn(gateway.serve());
        let query = query();

        let udp_client = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("gateway UDP client");
        udp_client
            .send_to(&query, format!("127.0.0.1:{port}"))
            .await
            .expect("gateway UDP query");
        let mut udp_response = [0_u8; 512];
        let (length, _) = udp_client
            .recv_from(&mut udp_response)
            .await
            .expect("gateway UDP response");
        assert_eq!(&udp_response[..length], response(&query));

        let mut tcp_client = TcpStream::connect(format!("[::1]:{port}"))
            .await
            .expect("gateway TCP client");
        tcp_client
            .write_u16(u16::try_from(query.len()).expect("query length"))
            .await
            .expect("gateway TCP length");
        tcp_client
            .write_all(&query)
            .await
            .expect("gateway TCP query");
        let length = tcp_client
            .read_u16()
            .await
            .expect("gateway TCP response length");
        let mut tcp_response = vec![0_u8; usize::from(length)];
        tcp_client
            .read_exact(&mut tcp_response)
            .await
            .expect("gateway TCP response");
        assert_eq!(tcp_response, response(&query));

        udp_fixture.await.expect("UDP fixture task");
        tcp_fixture.await.expect("TCP fixture task");
        gateway_task.abort();
        host_task.abort();
    }

    #[test]
    fn servfail_retains_the_query_and_clears_all_answer_sections() {
        let query = query();
        let response = servfail(&query);
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x800f,
            0x8002
        );
        assert_eq!(&response[6..12], &[0; 6]);
        assert_eq!(&response[12..], &query[12..]);
    }

    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    fn response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response
    }
}
