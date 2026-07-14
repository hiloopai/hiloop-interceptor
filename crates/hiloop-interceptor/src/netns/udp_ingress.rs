use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
        unix::net::UnixDatagram,
    },
};

use async_trait::async_trait;
use nix::{
    cmsg_space, libc,
    sys::socket::{
        ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage, recvmsg,
    },
};
use tokio::{io::unix::AsyncFd, sync::Mutex};

use super::{
    UdpChildDatagram, UdpChildSink, UdpFlowDisposition, UdpFlowKey, UdpFlowRelay, UdpRelayError,
    udp_broker::{BROKER_STATUS_OK, encode_request},
};

/// One datagram received through nft TPROXY with its authoritative original destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptedUdpDatagram {
    key: UdpFlowKey,
    payload: Vec<u8>,
}

impl InterceptedUdpDatagram {
    /// Flow identity recovered before any policy or upstream operation.
    pub fn key(&self) -> UdpFlowKey {
        self.key
    }

    /// Exact opaque datagram bytes; QUIC receives no partial classification.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Dual-stack transparent UDP ingress backed by the substrate's pre-opened sockets.
#[derive(Debug)]
pub struct TransparentUdpIngress {
    ipv4: AsyncFd<UdpSocket>,
    ipv6: AsyncFd<UdpSocket>,
}

/// Cap-free downstream sender backed by the namespace manager's narrow socket broker.
#[derive(Debug)]
pub struct TransparentUdpChildSink {
    state: Mutex<BrokerState>,
}

#[derive(Debug)]
struct BrokerState {
    broker: AsyncFd<UnixDatagram>,
    sockets: HashMap<UdpFlowKey, tokio::net::UdpSocket>,
}

impl TransparentUdpChildSink {
    /// Adopt the connected broker descriptor returned by [`super::GatewayListeners`].
    pub fn new(broker: UnixDatagram) -> io::Result<Self> {
        broker.set_nonblocking(true)?;
        Ok(Self {
            state: Mutex::new(BrokerState {
                broker: AsyncFd::new(broker)?,
                sockets: HashMap::new(),
            }),
        })
    }
}

#[async_trait]
impl UdpChildSink for TransparentUdpChildSink {
    async fn send(&self, datagram: UdpChildDatagram) -> io::Result<()> {
        let mut state = self.state.lock().await;
        if !state.sockets.contains_key(&datagram.key()) {
            let descriptor = request_reply_socket(&state.broker, datagram.key()).await?;
            let socket = UdpSocket::from(descriptor);
            socket.set_nonblocking(true)?;
            state
                .sockets
                .insert(datagram.key(), tokio::net::UdpSocket::from_std(socket)?);
        }
        let socket = state
            .sockets
            .get(&datagram.key())
            .ok_or_else(|| io::Error::other("UDP reply socket was not cached"))?;
        if socket.send(datagram.payload()).await? != datagram.payload().len() {
            return Err(io::Error::other(
                "UDP downstream datagram was partially sent",
            ));
        }
        Ok(())
    }

    async fn close(&self, key: UdpFlowKey) {
        self.state.lock().await.sockets.remove(&key);
    }
}

impl TransparentUdpIngress {
    /// Adopt the two cap-free listener descriptors transferred by [`super::GatewayListeners`].
    pub fn from_std(ipv4: UdpSocket, ipv6: UdpSocket) -> io::Result<Self> {
        let ipv4_address = ipv4.local_addr()?;
        let ipv6_address = ipv6.local_addr()?;
        if !ipv4_address.is_ipv4()
            || !ipv6_address.is_ipv6()
            || ipv4_address.port() != ipv6_address.port()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transparent UDP ingress requires matching IPv4 and IPv6 listener ports",
            ));
        }
        ipv4.set_nonblocking(true)?;
        ipv6.set_nonblocking(true)?;
        Ok(Self {
            ipv4: AsyncFd::new(ipv4)?,
            ipv6: AsyncFd::new(ipv6)?,
        })
    }

    /// Receive the next IPv4 or IPv6 datagram with source and original destination identity.
    pub async fn receive(&self) -> io::Result<InterceptedUdpDatagram> {
        tokio::select! {
            datagram = receive_one(&self.ipv4, AddressFamily::Ipv4) => datagram,
            datagram = receive_one(&self.ipv6, AddressFamily::Ipv6) => datagram,
        }
    }

    /// Dispatch datagrams until transparent ingress or a binding-fatal relay decision stops it.
    pub async fn serve(&self, relay: &UdpFlowRelay) -> Result<(), UdpIngressError> {
        loop {
            let datagram = self.receive().await?;
            match relay.forward(datagram.key, &datagram.payload).await {
                Ok(()) => {}
                Err(error)
                    if error.disposition() == Some(UdpFlowDisposition::DenyIdentityUnavailable) => {
                }
                Err(error) => return Err(UdpIngressError::Relay(error)),
            }
        }
    }
}

async fn receive_one(
    socket: &AsyncFd<UdpSocket>,
    family: AddressFamily,
) -> io::Result<InterceptedUdpDatagram> {
    loop {
        let mut readiness = socket.readable().await?;
        if let Ok(result) = readiness.try_io(|inner| receive_now(inner.get_ref(), family)) {
            return result;
        }
    }
}

fn receive_now(socket: &UdpSocket, family: AddressFamily) -> io::Result<InterceptedUdpDatagram> {
    let mut payload = vec![0_u8; usize::from(u16::MAX)];
    let mut iovec = [IoSliceMut::new(&mut payload)];
    let mut control = cmsg_space!(libc::sockaddr_in6);
    let message = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iovec,
        Some(&mut control),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(errno)?;
    if message
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transparent UDP datagram or destination metadata was truncated",
        ));
    }
    let client = message
        .address
        .as_ref()
        .and_then(socket_address)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "UDP source address is absent")
        })?;
    let mut destination = None;
    for control in message.cmsgs().map_err(errno)? {
        let candidate = match control {
            ControlMessageOwned::Ipv4OrigDstAddr(address) if family == AddressFamily::Ipv4 => {
                Some(SocketAddr::from(SockaddrIn::from(address)))
            }
            ControlMessageOwned::Ipv6OrigDstAddr(address) if family == AddressFamily::Ipv6 => {
                Some(SocketAddr::from(SockaddrIn6::from(address)))
            }
            _ => None,
        };
        if let Some(candidate) = candidate
            && destination.replace(candidate).is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram carried duplicate original destinations",
            ));
        }
    }
    let destination = destination.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP datagram omitted its original destination",
        )
    })?;
    let length = message.bytes;
    payload.truncate(length);
    let key = UdpFlowKey::new(client, destination).map_err(io::Error::other)?;
    Ok(InterceptedUdpDatagram { key, payload })
}

fn socket_address(address: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(ipv4) = address.as_sockaddr_in() {
        Some(SocketAddr::from(*ipv4))
    } else {
        address
            .as_sockaddr_in6()
            .map(|ipv6| SocketAddr::from(*ipv6))
    }
}

fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

async fn request_reply_socket(
    broker: &AsyncFd<UnixDatagram>,
    key: UdpFlowKey,
) -> io::Result<OwnedFd> {
    let request = encode_request(key);
    loop {
        let mut readiness = broker.writable().await?;
        match readiness.try_io(|inner| inner.get_ref().send(&request)) {
            Ok(Ok(length)) if length == request.len() => break,
            Ok(Ok(_)) => {
                return Err(io::Error::other("UDP broker request was partially sent"));
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => {}
        }
    }
    loop {
        let mut readiness = broker.readable().await?;
        if let Ok(result) = readiness.try_io(|inner| receive_reply_socket(inner.get_ref())) {
            return result;
        }
    }
}

fn receive_reply_socket(broker: &UnixDatagram) -> io::Result<OwnedFd> {
    let mut status = [0_u8; 1];
    let mut iovec = [IoSliceMut::new(&mut status)];
    let mut control = cmsg_space!([RawFd; 1]);
    let message = recvmsg::<()>(
        broker.as_raw_fd(),
        &mut iovec,
        Some(&mut control),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(errno)?;
    let mut descriptors = Vec::new();
    for message in message.cmsgs().map_err(errno)? {
        if let ControlMessageOwned::ScmRights(raw_descriptors) = message {
            for descriptor in raw_descriptors {
                // SAFETY: SCM_RIGHTS installs a fresh descriptor in this process; adopting every
                // received descriptor immediately ensures malformed responses cannot leak one.
                #[expect(
                    unsafe_code,
                    reason = "SCM_RIGHTS transfers ownership of each returned descriptor; see SAFETY"
                )]
                descriptors.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
            }
        }
    }
    if message.bytes != 1 || status[0] != BROKER_STATUS_OK || descriptors.len() != 1 {
        return Err(io::Error::other(
            "namespace manager could not open a transparent UDP reply socket",
        ));
    }
    descriptors
        .pop()
        .ok_or_else(|| io::Error::other("UDP broker returned no descriptor"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// Transparent UDP ingress or relay failure.
#[derive(Debug, thiserror::Error)]
pub enum UdpIngressError {
    /// Reading a transparent listener failed.
    #[error("receive transparent UDP datagram: {0}")]
    Receive(#[from] io::Error),
    /// The flow relay closed or made a strict-run fatal decision.
    #[error(transparent)]
    Relay(#[from] UdpRelayError),
}

#[cfg(test)]
mod tests {
    use nix::sys::socket::{setsockopt, sockopt};

    use super::*;

    #[tokio::test]
    async fn ingress_recovers_dual_stack_destination_metadata() {
        let ipv4 = UdpSocket::bind("127.0.0.1:0").expect("IPv4 listener");
        let port = ipv4.local_addr().expect("IPv4 address").port();
        let ipv6 = UdpSocket::bind(("::1", port)).expect("IPv6 listener");
        setsockopt(&ipv4, sockopt::Ipv4OrigDstAddr, &true).expect("IPv4 destination metadata");
        setsockopt(&ipv6, sockopt::Ipv6OrigDstAddr, &true).expect("IPv6 destination metadata");
        let ipv4_destination = ipv4.local_addr().expect("IPv4 destination");
        let ipv6_destination = ipv6.local_addr().expect("IPv6 destination");
        let ingress = TransparentUdpIngress::from_std(ipv4, ipv6).expect("UDP ingress");

        for destination in [ipv4_destination, ipv6_destination] {
            let sender = tokio::net::UdpSocket::bind(if destination.is_ipv4() {
                "127.0.0.1:0"
            } else {
                "[::1]:0"
            })
            .await
            .expect("sender");
            sender
                .send_to(b"opaque", destination)
                .await
                .expect("send test datagram");
            let received = ingress.receive().await.expect("receive test datagram");
            assert_eq!(
                received.key().client(),
                sender.local_addr().expect("sender address")
            );
            assert_eq!(received.key().destination(), destination);
            assert_eq!(received.payload(), b"opaque");
        }
    }
}
