use std::{io, net::SocketAddr, path::Path, time::Duration};

use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpStream, UdpSocket},
    time,
};

const DNS_QUERY_ID: u16 = 0x6869;
const DNS_PORT: u16 = 53;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone)]
pub(super) struct ResolverConfig {
    resolvers: Vec<SocketAddr>,
    workload_contents: Vec<u8>,
}

impl ResolverConfig {
    pub(super) fn parse(contents: &str) -> io::Result<Self> {
        Ok(Self {
            resolvers: parse_nameservers(contents)?,
            workload_contents: workload_resolv_conf(contents),
        })
    }

    pub(super) fn workload_contents(&self) -> &[u8] {
        &self.workload_contents
    }
}

#[derive(Debug, Clone)]
pub(super) struct HostResolver {
    resolvers: Vec<SocketAddr>,
    timeout: Duration,
}

impl HostResolver {
    #[cfg(test)]
    pub(super) fn new(resolvers: Vec<SocketAddr>, timeout: Duration) -> io::Result<Self> {
        if resolvers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS relay requires at least one host resolver",
            ));
        }
        Ok(Self { resolvers, timeout })
    }

    pub(super) fn from_config(config: &ResolverConfig, timeout: Duration) -> Self {
        Self {
            resolvers: config.resolvers.clone(),
            timeout,
        }
    }

    pub(super) async fn query(&self, transport: DnsTransport, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut diagnostics = Vec::new();
        for resolver in &self.resolvers {
            let result = match transport {
                DnsTransport::Udp => query_udp(*resolver, query, self.timeout).await,
                DnsTransport::Tcp => query_tcp(*resolver, query, self.timeout).await,
            };
            match result {
                Ok(response) => return Ok(response),
                Err(error) => diagnostics.push(format!("{resolver}: {error}")),
            }
        }
        Err(io::Error::other(format!(
            "no configured resolver answered the DNS relay query ({})",
            diagnostics.join("; ")
        )))
    }
}

pub(super) async fn probe_resolver(path: &Path, timeout: Duration) -> io::Result<()> {
    let contents = fs::read_to_string(path).await?;
    let resolvers = parse_nameservers(&contents)?;
    let query = dns_query();
    let mut diagnostics = Vec::new();
    for resolver in resolvers {
        let udp = probe_udp(resolver, &query, timeout).await;
        let tcp = probe_tcp(resolver, &query, timeout).await;
        if udp.is_ok() && tcp.is_ok() {
            return Ok(());
        }
        diagnostics.push(format!(
            "{resolver}: udp={}, tcp={}",
            display_result(&udp),
            display_result(&tcp)
        ));
    }
    Err(io::Error::other(format!(
        "no configured resolver answered both UDP and TCP probes ({})",
        diagnostics.join("; ")
    )))
}

fn parse_nameservers(contents: &str) -> io::Result<Vec<SocketAddr>> {
    let mut resolvers = Vec::new();
    for line in contents.lines() {
        let line = line.split_once('#').map_or(line, |(value, _)| value).trim();
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = fields.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resolv.conf nameserver is missing its address",
            ));
        };
        if fields.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resolv.conf nameserver contains trailing fields",
            ));
        }
        let address = address.parse().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid resolv.conf nameserver `{address}`: {error}"),
            )
        })?;
        resolvers.push(SocketAddr::new(address, DNS_PORT));
    }
    if resolvers.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resolv.conf contains no nameserver",
        ))
    } else {
        Ok(resolvers)
    }
}

async fn probe_udp(resolver: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<()> {
    let response = query_udp(resolver, query, timeout).await?;
    validate_response(&response)
}

async fn probe_tcp(resolver: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<()> {
    let response = query_tcp(resolver, query, timeout).await?;
    validate_response(&response)
}

async fn query_udp(resolver: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    time::timeout(timeout, async {
        let bind = if resolver.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(resolver).await?;
        if socket.send(query).await? != query.len() {
            return Err(io::Error::other("UDP DNS query was partially sent"));
        }
        let mut response = vec![0_u8; usize::from(u16::MAX)];
        let length = socket.recv(&mut response).await?;
        response.truncate(length);
        validate_transaction(query, &response)?;
        Ok(response)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP DNS relay timed out"))?
}

async fn query_tcp(resolver: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    time::timeout(timeout, async {
        let mut stream = TcpStream::connect(resolver).await?;
        let length = u16::try_from(query.len())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(query).await?;
        let response_length = stream.read_u16().await?;
        let mut response = vec![0_u8; usize::from(response_length)];
        stream.read_exact(&mut response).await?;
        validate_transaction(query, &response)?;
        Ok(response)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP DNS relay timed out"))?
}

fn dns_query() -> Vec<u8> {
    let mut query = Vec::with_capacity(29);
    query.extend_from_slice(&DNS_QUERY_ID.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    for label in ["example", "com"] {
        query.push(u8::try_from(label.len()).expect("static DNS label fits u8"));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

fn validate_response(response: &[u8]) -> io::Result<()> {
    if response.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response is shorter than its header",
        ));
    }
    if u16::from_be_bytes([response[0], response[1]]) != DNS_QUERY_ID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response transaction id does not match",
        ));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS resolver returned a query instead of a response",
        ));
    }
    Ok(())
}

fn validate_transaction(query: &[u8], response: &[u8]) -> io::Result<()> {
    if query.len() < 2 || response.len() < 2 || query[..2] != response[..2] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response transaction id does not match the relayed query",
        ));
    }
    if response.len() < 4 || u16::from_be_bytes([response[2], response[3]]) & 0x8000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS relay received a query instead of a response",
        ));
    }
    Ok(())
}

fn workload_resolv_conf(contents: &str) -> Vec<u8> {
    let mut generated = format!(
        "# generated by hiloop-interceptor\nnameserver {}\nnameserver {}\n",
        super::routing::GATEWAY_IPV4,
        super::routing::GATEWAY_IPV6,
    )
    .into_bytes();
    for line in contents.lines() {
        let directive = line.split_once('#').map_or(line, |(value, _)| value).trim();
        let keyword = directive.split_ascii_whitespace().next();
        if matches!(keyword, Some("search" | "domain" | "options")) {
            generated.extend_from_slice(directive.as_bytes());
            generated.push(b'\n');
        }
    }
    generated
}

fn display_result(result: &io::Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_config_preserves_loopback_and_dual_stack_addresses() {
        assert_eq!(
            parse_nameservers(
                "# generated\nnameserver 127.0.0.53\nnameserver 2001:db8::53 # vpn\noptions edns0\n"
            )
            .expect("valid resolver config"),
            [
                "127.0.0.53:53".parse().expect("test resolver"),
                "[2001:db8::53]:53".parse().expect("test resolver"),
            ]
        );
    }

    #[test]
    fn workload_resolver_reserves_gateway_and_preserves_search_and_options() {
        let config = ResolverConfig::parse(
            "nameserver 127.0.0.53\nsearch corp.example svc.example\noptions ndots:5 timeout:2 attempts:3 rotate\ndomain ignored.example # preserved too\n",
        )
        .expect("valid resolver config");

        assert_eq!(
            String::from_utf8(config.workload_contents().to_vec()).expect("UTF-8 config"),
            "# generated by hiloop-interceptor\nnameserver 169.254.254.1\nnameserver fd00:6869:6c6f:6f70::1\nsearch corp.example svc.example\noptions ndots:5 timeout:2 attempts:3 rotate\ndomain ignored.example\n"
        );
    }

    #[test]
    fn resolver_config_rejects_absent_or_malformed_nameservers() {
        for contents in [
            "search example.com\n",
            "nameserver\n",
            "nameserver not-an-ip\n",
            "nameserver 1.1.1.1 trailing\n",
        ] {
            assert!(parse_nameservers(contents).is_err());
        }
    }

    #[test]
    fn dns_probe_requires_matching_response_header() {
        let mut response = [0_u8; 12];
        response[..2].copy_from_slice(&DNS_QUERY_ID.to_be_bytes());
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        validate_response(&response).expect("valid response header");
        response[0] ^= 1;
        assert!(validate_response(&response).is_err());
        assert!(validate_response(&response[..8]).is_err());
    }
}
