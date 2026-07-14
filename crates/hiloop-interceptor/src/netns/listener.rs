use std::{
    io, mem,
    net::{TcpListener, UdpSocket},
    num::NonZeroU16,
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
    os::unix::net::UnixDatagram,
};

use nix::libc;

use super::UdpFlowKey;
use super::security::deny_process_inspection;

const IPV4_LISTENER_FD: RawFd = 3;
const IPV6_LISTENER_FD: RawFd = 4;
const IPV4_UDP_FD: RawFd = 5;
const IPV6_UDP_FD: RawFd = 6;
const READY_FD: RawFd = 7;
const IPV6_TRANSPARENT: libc::c_int = 75;

/// Transparent listeners inherited by a cap-free gateway worker.
#[derive(Debug)]
pub struct GatewayListeners {
    tcp_ipv4: TcpListener,
    tcp_ipv6: TcpListener,
    udp_ipv4: UdpSocket,
    udp_ipv6: UdpSocket,
    broker: UnixDatagram,
}

impl GatewayListeners {
    /// Consume the listener set for independent async conversion.
    pub fn into_parts(self) -> (TcpListener, TcpListener, UdpSocket, UdpSocket, UnixDatagram) {
        (
            self.tcp_ipv4,
            self.tcp_ipv6,
            self.udp_ipv4,
            self.udp_ipv6,
            self.broker,
        )
    }
}

/// Gateway-worker bootstrap contract used before its async runtime starts.
#[derive(Debug)]
pub struct GatewayWorkerBootstrap {
    listeners: GatewayListeners,
}

impl GatewayWorkerBootstrap {
    /// Take ownership of the fixed descriptors installed by the namespace manager.
    ///
    /// # Errors
    ///
    /// Returns an OS error when an inherited descriptor is not a valid listener or
    /// readiness channel.
    #[expect(
        unsafe_code,
        reason = "the namespace manager transfers ownership of three documented inherited descriptors; see SAFETY"
    )]
    pub fn from_inherited_fds() -> io::Result<Self> {
        let ipv4_flags = validate_listener_descriptor(IPV4_LISTENER_FD, libc::AF_INET)?;
        let ipv6_flags = validate_listener_descriptor(IPV6_LISTENER_FD, libc::AF_INET6)?;
        let udp_ipv4_flags = validate_datagram_descriptor(IPV4_UDP_FD, libc::AF_INET)?;
        let udp_ipv6_flags = validate_datagram_descriptor(IPV6_UDP_FD, libc::AF_INET6)?;
        let ready_flags = validate_connected_unix_descriptor(READY_FD)?;
        set_descriptor_close_on_exec(IPV4_LISTENER_FD, ipv4_flags)?;
        set_descriptor_close_on_exec(IPV6_LISTENER_FD, ipv6_flags)?;
        set_descriptor_close_on_exec(IPV4_UDP_FD, udp_ipv4_flags)?;
        set_descriptor_close_on_exec(IPV6_UDP_FD, udp_ipv6_flags)?;
        set_descriptor_close_on_exec(READY_FD, ready_flags)?;
        deny_process_inspection()?;

        // SAFETY: the manager duplicates one owned descriptor onto each fixed number and then
        // execs the worker with no other owner in this process. The checks above proved all five
        // descriptors open, validated their socket contracts, and restored close-on-exec.
        let ipv4 = TcpListener::from(unsafe { OwnedFd::from_raw_fd(IPV4_LISTENER_FD) });
        // SAFETY: same transfer contract as the IPv4 descriptor, for the IPv6 listener.
        let ipv6 = TcpListener::from(unsafe { OwnedFd::from_raw_fd(IPV6_LISTENER_FD) });
        // SAFETY: same transfer contract as the TCP descriptors, for the IPv4 UDP listener.
        let udp_ipv4 = UdpSocket::from(unsafe { OwnedFd::from_raw_fd(IPV4_UDP_FD) });
        // SAFETY: same transfer contract as the TCP descriptors, for the IPv6 UDP listener.
        let udp_ipv6 = UdpSocket::from(unsafe { OwnedFd::from_raw_fd(IPV6_UDP_FD) });
        // SAFETY: same transfer contract, for one connected Unix readiness socket.
        let broker = UnixDatagram::from(unsafe { OwnedFd::from_raw_fd(READY_FD) });
        ipv4.local_addr()?;
        ipv6.local_addr()?;
        udp_ipv4.local_addr()?;
        udp_ipv6.local_addr()?;
        broker.peer_addr()?;
        Ok(Self {
            listeners: GatewayListeners {
                tcp_ipv4: ipv4,
                tcp_ipv6: ipv6,
                udp_ipv4,
                udp_ipv6,
                broker,
            },
        })
    }

    /// Acknowledge steady-state readiness after all worker initialization succeeds.
    pub fn notify_ready(self) -> io::Result<GatewayListeners> {
        if self.listeners.broker.send(&[1])? != 1 {
            return Err(io::Error::other("gateway readiness was partially sent"));
        }
        Ok(self.listeners)
    }
}

fn validate_datagram_descriptor(fd: RawFd, family: libc::c_int) -> io::Result<libc::c_int> {
    let flags = descriptor_flags(fd)?;
    require_socket_option(fd, libc::SO_TYPE, libc::SOCK_DGRAM, "socket type")?;
    require_socket_option(fd, libc::SO_DOMAIN, family, "socket family")?;
    require_socket_option(fd, libc::SO_ACCEPTCONN, 0, "listener state")?;
    Ok(flags)
}

fn validate_listener_descriptor(fd: RawFd, family: libc::c_int) -> io::Result<libc::c_int> {
    let flags = descriptor_flags(fd)?;
    require_socket_option(fd, libc::SO_TYPE, libc::SOCK_STREAM, "socket type")?;
    require_socket_option(fd, libc::SO_DOMAIN, family, "socket family")?;
    require_socket_option(fd, libc::SO_ACCEPTCONN, 1, "listener state")?;
    Ok(flags)
}

fn validate_connected_unix_descriptor(fd: RawFd) -> io::Result<libc::c_int> {
    let flags = descriptor_flags(fd)?;
    require_socket_option(fd, libc::SO_TYPE, libc::SOCK_DGRAM, "socket type")?;
    require_socket_option(fd, libc::SO_DOMAIN, libc::AF_UNIX, "socket family")?;
    let peer_family = peer_socket_family(fd)?;
    if peer_family != libc::AF_UNIX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("readiness descriptor peer family was {peer_family}, expected AF_UNIX"),
        ));
    }
    Ok(flags)
}

#[expect(
    unsafe_code,
    reason = "fcntl validates one scalar descriptor without pointer arguments; see SAFETY"
)]
fn descriptor_flags(fd: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: `F_GETFD` takes only the scalar descriptor and command.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

#[expect(
    unsafe_code,
    reason = "fcntl sets close-on-exec on one validated scalar descriptor; see SAFETY"
)]
fn set_descriptor_close_on_exec(fd: RawFd, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` was validated by `descriptor_flags`; `F_SETFD` consumes the integer flags.
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) })
}

fn require_socket_option(
    fd: RawFd,
    option: libc::c_int,
    expected: libc::c_int,
    description: &str,
) -> io::Result<()> {
    let actual = socket_option(fd, option)?;
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("inherited descriptor {description} was {actual}, expected {expected}"),
        ))
    }
}

#[expect(
    unsafe_code,
    reason = "getsockopt writes one integer option through a valid pointer; see SAFETY"
)]
fn socket_option(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value = 0;
    let expected_length =
        libc::socklen_t::try_from(mem::size_of_val(&value)).map_err(invalid_input)?;
    let mut length = expected_length;
    // SAFETY: `value` and `length` are writable initialized storage of the advertised size, and
    // the kernel retains neither pointer after the call.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast(),
            std::ptr::from_mut(&mut length),
        )
    };
    cvt(result)?;
    if length != expected_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket option returned an unexpected length",
        ));
    }
    Ok(value)
}

#[expect(
    unsafe_code,
    reason = "getpeername initializes one sockaddr storage value and length; see SAFETY"
)]
fn peer_socket_family(fd: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: an all-zero `sockaddr_storage` is a valid initialized output buffer.
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length =
        libc::socklen_t::try_from(mem::size_of_val(&address)).map_err(invalid_input)?;
    // SAFETY: both pointers reference writable initialized storage for the duration of the call.
    let result = unsafe {
        libc::getpeername(
            fd,
            std::ptr::from_mut(&mut address).cast(),
            std::ptr::from_mut(&mut length),
        )
    };
    cvt(result)?;
    let family_length =
        libc::socklen_t::try_from(mem::size_of::<libc::sa_family_t>()).map_err(invalid_input)?;
    if length < family_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer address omitted its socket family",
        ));
    }
    Ok(libc::c_int::from(address.ss_family))
}

#[derive(Debug)]
pub(super) struct TransparentListeners {
    tcp_ipv4: OwnedFd,
    tcp_ipv6: OwnedFd,
    udp_ipv4: OwnedFd,
    udp_ipv6: OwnedFd,
    port: NonZeroU16,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum TransparentListenerError {
    #[error("create IPv4 transparent listener: {0}")]
    Ipv4(#[source] io::Error),
    #[error("create IPv6 transparent listener: {0}")]
    Ipv6(#[source] io::Error),
    #[error("create IPv4 transparent UDP listener: {0}")]
    UdpIpv4(#[source] io::Error),
    #[error("create IPv6 transparent UDP listener: {0}")]
    UdpIpv6(#[source] io::Error),
}

impl TransparentListeners {
    pub(super) fn bind(requested: Option<NonZeroU16>) -> Result<Self, TransparentListenerError> {
        let (tcp_ipv4, port) =
            create_ipv4_listener(requested).map_err(TransparentListenerError::Ipv4)?;
        let tcp_ipv6 = create_ipv6_listener(port).map_err(TransparentListenerError::Ipv6)?;
        let udp_ipv4 = create_ipv4_udp_listener(port).map_err(TransparentListenerError::UdpIpv4)?;
        let udp_ipv6 = create_ipv6_udp_listener(port).map_err(TransparentListenerError::UdpIpv6)?;

        Ok(Self {
            tcp_ipv4,
            tcp_ipv6,
            udp_ipv4,
            udp_ipv6,
            port,
        })
    }

    pub(super) fn port(&self) -> NonZeroU16 {
        self.port
    }

    pub(super) fn raw_fds(&self) -> [RawFd; 4] {
        [
            self.tcp_ipv4.as_raw_fd(),
            self.tcp_ipv6.as_raw_fd(),
            self.udp_ipv4.as_raw_fd(),
            self.udp_ipv6.as_raw_fd(),
        ]
    }
}

fn create_ipv4_listener(requested: Option<NonZeroU16>) -> io::Result<(OwnedFd, NonZeroU16)> {
    let ipv4 = create_socket(libc::AF_INET, libc::SOCK_STREAM)?;
    set_socket_option(ipv4.as_raw_fd(), libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
    set_socket_option(ipv4.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    bind_ipv4(ipv4.as_raw_fd(), requested.map_or(0, NonZeroU16::get))?;
    listen(ipv4.as_raw_fd())?;
    let port = local_port_ipv4(ipv4.as_raw_fd())?;
    Ok((ipv4, port))
}

fn create_ipv6_listener(port: NonZeroU16) -> io::Result<OwnedFd> {
    let ipv6 = create_socket(libc::AF_INET6, libc::SOCK_STREAM)?;
    set_socket_option(ipv6.as_raw_fd(), libc::IPPROTO_IPV6, IPV6_TRANSPARENT, 1)?;
    set_socket_option(ipv6.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    set_socket_option(ipv6.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    bind_ipv6(ipv6.as_raw_fd(), port.get())?;
    listen(ipv6.as_raw_fd())?;
    Ok(ipv6)
}

fn create_ipv4_udp_listener(port: NonZeroU16) -> io::Result<OwnedFd> {
    let socket = create_socket(libc::AF_INET, libc::SOCK_DGRAM)?;
    set_socket_option(socket.as_raw_fd(), libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
    set_socket_option(
        socket.as_raw_fd(),
        libc::SOL_IP,
        libc::IP_RECVORIGDSTADDR,
        1,
    )?;
    set_socket_option(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    bind_ipv4(socket.as_raw_fd(), port.get())?;
    Ok(socket)
}

fn create_ipv6_udp_listener(port: NonZeroU16) -> io::Result<OwnedFd> {
    let socket = create_socket(libc::AF_INET6, libc::SOCK_DGRAM)?;
    set_socket_option(socket.as_raw_fd(), libc::IPPROTO_IPV6, IPV6_TRANSPARENT, 1)?;
    set_socket_option(
        socket.as_raw_fd(),
        libc::IPPROTO_IPV6,
        libc::IPV6_RECVORIGDSTADDR,
        1,
    )?;
    set_socket_option(socket.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    set_socket_option(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    bind_ipv6(socket.as_raw_fd(), port.get())?;
    Ok(socket)
}

pub(super) fn create_transparent_reply_socket(key: UdpFlowKey) -> io::Result<OwnedFd> {
    let (family, transparent_level, transparent_name) = if key.destination().is_ipv4() {
        (libc::AF_INET, libc::SOL_IP, libc::IP_TRANSPARENT)
    } else {
        (libc::AF_INET6, libc::IPPROTO_IPV6, IPV6_TRANSPARENT)
    };
    let socket = create_socket(family, libc::SOCK_DGRAM)?;
    set_socket_option(socket.as_raw_fd(), transparent_level, transparent_name, 1)?;
    set_socket_option(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    set_socket_option(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
    match key.destination() {
        std::net::SocketAddr::V4(address) => {
            bind_specific_ipv4(socket.as_raw_fd(), *address.ip(), address.port())?;
        }
        std::net::SocketAddr::V6(address) => {
            bind_specific_ipv6(socket.as_raw_fd(), *address.ip(), address.port())?;
        }
    }
    connect_socket(socket.as_raw_fd(), key.client())?;
    Ok(socket)
}

fn create_socket(family: libc::c_int, kind: libc::c_int) -> io::Result<OwnedFd> {
    #[expect(
        unsafe_code,
        reason = "socket returns a new owned descriptor and takes only scalar arguments; see SAFETY"
    )]
    // SAFETY: the call takes scalar constants and returns a fresh descriptor on success.
    let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd == -1 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful socket call returned this uniquely owned descriptor.
        #[expect(
            unsafe_code,
            reason = "successful socket return transfers one new descriptor; see SAFETY"
        )]
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn set_socket_option(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "setsockopt reads one initialized integer through a valid pointer; see SAFETY"
    )]
    // SAFETY: `value` is initialized and the supplied length matches exactly one `c_int`.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            libc::socklen_t::try_from(mem::size_of_val(&value)).map_err(invalid_input)?,
        )
    };
    cvt(result)
}

fn bind_ipv4(fd: RawFd, port: u16) -> io::Result<()> {
    bind_specific_ipv4(fd, std::net::Ipv4Addr::UNSPECIFIED, port)
}

fn bind_specific_ipv4(fd: RawFd, ip: std::net::Ipv4Addr, port: u16) -> io::Result<()> {
    let address = libc::sockaddr_in {
        sin_family: libc::sa_family_t::try_from(libc::AF_INET).map_err(invalid_input)?,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    bind_address(fd, &address)
}

fn bind_ipv6(fd: RawFd, port: u16) -> io::Result<()> {
    bind_specific_ipv6(fd, std::net::Ipv6Addr::UNSPECIFIED, port)
}

fn bind_specific_ipv6(fd: RawFd, ip: std::net::Ipv6Addr, port: u16) -> io::Result<()> {
    let address = libc::sockaddr_in6 {
        sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).map_err(invalid_input)?,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: ip.octets(),
        },
        sin6_scope_id: 0,
    };
    bind_address(fd, &address)
}

fn connect_socket(fd: RawFd, address: std::net::SocketAddr) -> io::Result<()> {
    match address {
        std::net::SocketAddr::V4(address) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET).map_err(invalid_input)?,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            connect_address(fd, &raw)
        }
        std::net::SocketAddr::V6(address) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).map_err(invalid_input)?,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            connect_address(fd, &raw)
        }
    }
}

fn connect_address<T>(fd: RawFd, address: &T) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "connect reads one initialized sockaddr value for the duration of the call; see SAFETY"
    )]
    // SAFETY: `address` is a fully initialized sockaddr variant and the length is exact.
    cvt(unsafe {
        libc::connect(
            fd,
            std::ptr::from_ref(address).cast(),
            libc::socklen_t::try_from(mem::size_of::<T>()).map_err(invalid_input)?,
        )
    })
}

fn bind_address<T>(fd: RawFd, address: &T) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "bind reads one initialized sockaddr value for the duration of the call; see SAFETY"
    )]
    // SAFETY: `address` is a fully initialized sockaddr variant and the length is exact.
    let result = unsafe {
        libc::bind(
            fd,
            std::ptr::from_ref(address).cast(),
            libc::socklen_t::try_from(mem::size_of::<T>()).map_err(invalid_input)?,
        )
    };
    cvt(result)
}

fn listen(fd: RawFd) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "listen takes one valid socket descriptor and a scalar backlog; see SAFETY"
    )]
    // SAFETY: `fd` remains owned by the caller and is a bound stream socket.
    cvt(unsafe { libc::listen(fd, 128) })
}

fn local_port_ipv4(fd: RawFd) -> io::Result<NonZeroU16> {
    let mut address = libc::sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut length =
        libc::socklen_t::try_from(mem::size_of_val(&address)).map_err(invalid_input)?;
    #[expect(
        unsafe_code,
        reason = "getsockname initializes the provided sockaddr and length values; see SAFETY"
    )]
    // SAFETY: both pointers reference writable initialized storage of the advertised size.
    let result = unsafe {
        libc::getsockname(
            fd,
            std::ptr::from_mut(&mut address).cast(),
            std::ptr::from_mut(&mut length),
        )
    };
    cvt(result)?;
    NonZeroU16::new(u16::from_be(address.sin_port))
        .ok_or_else(|| io::Error::other("kernel returned transparent listener port zero"))
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        net::UdpSocket, os::fd::AsRawFd as _, os::unix::net::UnixDatagram as StdUnixDatagram,
    };

    use super::*;

    #[test]
    fn inherited_descriptor_contract_is_fixed_and_non_overlapping() {
        assert_eq!(IPV4_LISTENER_FD, 3);
        assert_eq!(IPV6_LISTENER_FD, 4);
        assert_eq!(IPV4_UDP_FD, 5);
        assert_eq!(IPV6_UDP_FD, 6);
        assert_eq!(READY_FD, 7);
    }

    #[test]
    fn listener_validation_requires_stream_listener_and_exact_family() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("IPv4 listener");
        let flags = validate_listener_descriptor(listener.as_raw_fd(), libc::AF_INET)
            .expect("valid IPv4 listener");
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        assert!(validate_listener_descriptor(listener.as_raw_fd(), libc::AF_INET6).is_err());

        let datagram = UdpSocket::bind("127.0.0.1:0").expect("IPv4 datagram socket");
        assert!(validate_listener_descriptor(datagram.as_raw_fd(), libc::AF_INET).is_err());
        validate_datagram_descriptor(datagram.as_raw_fd(), libc::AF_INET)
            .expect("valid IPv4 datagram socket");
    }

    #[test]
    fn readiness_validation_requires_a_connected_unix_datagram() {
        let (ready, _peer) = StdUnixDatagram::pair().expect("Unix readiness pair");
        validate_connected_unix_descriptor(ready.as_raw_fd()).expect("connected Unix datagram");

        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP listener");
        assert!(validate_connected_unix_descriptor(listener.as_raw_fd()).is_err());
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "the test clears close-on-exec on its owned descriptor before exercising restoration; see SAFETY"
    )]
    fn inherited_descriptor_close_on_exec_is_restored() {
        let (ready, _peer) = StdUnixDatagram::pair().expect("Unix readiness pair");
        let fd = ready.as_raw_fd();
        let flags = descriptor_flags(fd).expect("descriptor flags");
        // SAFETY: `fd` remains owned by `ready`; this only updates its descriptor flags.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            -1
        );
        let flags = validate_connected_unix_descriptor(fd).expect("connected Unix datagram");
        set_descriptor_close_on_exec(fd, flags).expect("restore close-on-exec");
        assert_ne!(
            descriptor_flags(fd).expect("restored descriptor flags") & libc::FD_CLOEXEC,
            0
        );
    }
}
