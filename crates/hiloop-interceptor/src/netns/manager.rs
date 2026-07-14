use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs,
    io::{self, IoSlice, Read as _, Write as _},
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
        unix::{
            ffi::{OsStrExt as _, OsStringExt as _},
            net::{UnixDatagram, UnixStream},
            process::CommandExt as _,
        },
    },
    path::{Path, PathBuf},
    process::{Command, ExitCode, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use hiloop_core::capture::CaptureTransportDegradationReason;
use nix::libc;
use tempfile::NamedTempFile;

use super::{
    FatalReport, FragmentedUdpBehavior, NamespaceCommand, StartupStage, SubstrateExit,
    SubstrateInfo,
    listener::{
        GatewayWorkerBootstrap, TransparentListenerError, TransparentListeners,
        create_transparent_reply_socket,
    },
    pasta::{HOST_LOOPBACK_IPV4, HOST_LOOPBACK_IPV6, PASTA_INTERFACE},
    protocol::{
        MAX_GATEWAY_CONTROL_BYTES, ManagerMessage, SupervisorMessage, WireCommand,
        WireDegradationReason, WireExecCommand, WireExit, WireFatalReport, WireProvisionRequest,
        WireStartupStage, WireSubstrateInfo, WorkloadMessage, WorkloadReply, decode_gateway_fatal,
        receive_sync, send_sync,
    },
    routing::{
        GATEWAY_IPV4, GATEWAY_IPV6, IPV4_FRAGMENT_COUNTER, IPV6_FRAGMENT_COUNTER, IpFamily,
        LINK_MTU, NFT_TABLE, NamespacedCommand, NetworkNamespace, RoutingPlan,
        parse_counter_packets,
    },
    security::{
        CapabilityStatus, ChildLockdown, close_descriptors_except, deny_process_inspection,
    },
    udp_broker::{BROKER_STATUS_ERROR, BROKER_STATUS_OK, decode_request},
};

pub(super) const MANAGER_ROLE: &str = "__hiloop-netns-manager";
pub(super) const WORKLOAD_ROLE: &str = "__hiloop-netns-workload";
pub(super) const WORKER_PROBE_ROLE: &str = "__hiloop-netns-worker-probe";
pub(super) const WORKLOAD_PROBE_ROLE: &str = "__hiloop-netns-workload-probe";
#[cfg(feature = "test-support")]
pub(super) const DATAPLANE_WORKER_PROBE_ROLE: &str = "__hiloop-netns-dataplane-worker-probe";
#[cfg(feature = "test-support")]
pub(super) const DATAPLANE_WORKLOAD_PROBE_ROLE: &str = "__hiloop-netns-dataplane-workload-probe";
#[cfg(feature = "test-support")]
pub(super) const LOOPBACK_DESCENDANT_PROBE_ROLE: &str = "__hiloop-netns-loopback-descendant-probe";
#[cfg(feature = "test-support")]
pub(super) const CRASHING_WORKER_PROBE_ROLE: &str = "__hiloop-netns-crashing-worker-probe";
#[cfg(feature = "test-support")]
pub(super) const DETACHED_WORKLOAD_PROBE_ROLE: &str = "__hiloop-netns-detached-workload-probe";
#[cfg(feature = "test-support")]
pub(super) const FATAL_WORKER_PROBE_ROLE: &str = "__hiloop-netns-fatal-worker-probe";

const CONTROL_FD: RawFd = 3;
const IPV4_LISTENER_FD: RawFd = 3;
const IPV6_LISTENER_FD: RawFd = 4;
const IPV4_UDP_FD: RawFd = 5;
const IPV6_UDP_FD: RawFd = 6;
const WORKER_READY_FD: RawFd = 7;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(20);
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn dispatch_from_args() -> Option<io::Result<ExitCode>> {
    let role = std::env::args_os().nth(1)?;
    match role.to_str() {
        Some(MANAGER_ROLE) => Some(manager_entrypoint()),
        Some(WORKLOAD_ROLE) => Some(workload_entrypoint()),
        Some(WORKER_PROBE_ROLE) => Some(worker_probe_entrypoint()),
        Some(WORKLOAD_PROBE_ROLE) => Some(workload_probe_entrypoint()),
        #[cfg(feature = "test-support")]
        Some(DATAPLANE_WORKER_PROBE_ROLE) => Some(dataplane_worker_probe_entrypoint()),
        #[cfg(feature = "test-support")]
        Some(DATAPLANE_WORKLOAD_PROBE_ROLE) => Some(dataplane_workload_probe_entrypoint()),
        #[cfg(feature = "test-support")]
        Some(LOOPBACK_DESCENDANT_PROBE_ROLE) => Some(loopback_descendant_probe_entrypoint()),
        #[cfg(feature = "test-support")]
        Some(CRASHING_WORKER_PROBE_ROLE) => Some(crashing_worker_probe_entrypoint()),
        #[cfg(feature = "test-support")]
        Some(DETACHED_WORKLOAD_PROBE_ROLE) => Some(detached_workload_probe_entrypoint()),
        #[cfg(feature = "test-support")]
        Some(FATAL_WORKER_PROBE_ROLE) => Some(fatal_worker_probe_entrypoint()),
        _ => None,
    }
}

fn manager_entrypoint() -> io::Result<ExitCode> {
    close_descriptors_except(&[CONTROL_FD])?;
    let mut control = inherited_control_stream()?;
    if let Err(error) = arm_parent_death_signal().and_then(|()| create_user_namespace()) {
        send_startup_failure(
            &mut control,
            StartupStage::Namespace,
            CaptureTransportDegradationReason::UserNamespaceDenied,
            &error,
        );
        return Err(error);
    }
    send_sync(&mut control, &ManagerMessage::UserNamespaceReady)?;
    match receive_sync(&mut control)? {
        SupervisorMessage::IdMapsInstalled => {}
        SupervisorMessage::Shutdown => return Ok(ExitCode::SUCCESS),
        _ => return Err(protocol_order("expected uid/gid maps")),
    }
    if let Err(error) = enter_mapped_identity()
        .and_then(|()| arm_parent_death_signal())
        .and_then(|()| create_gateway_namespaces())
    {
        send_startup_failure(
            &mut control,
            StartupStage::Namespace,
            CaptureTransportDegradationReason::NetnsStartupFailed,
            &error,
        );
        return Err(error);
    }
    let mut failure_control = control.try_clone()?;
    match fork_gateway_init(control) {
        Ok(exit) => Ok(exit),
        Err(error) => {
            send_startup_failure(
                &mut failure_control,
                StartupStage::Namespace,
                CaptureTransportDegradationReason::NetnsStartupFailed,
                &error,
            );
            Err(error)
        }
    }
}

fn send_startup_failure(
    control: &mut UnixStream,
    stage: StartupStage,
    reason: CaptureTransportDegradationReason,
    error: &io::Error,
) {
    let _ = send_sync(
        control,
        &ManagerMessage::Failed {
            stage: WireStartupStage::from(stage),
            reason: WireDegradationReason::from(reason),
            diagnostic: error.to_string(),
        },
    );
}

#[expect(
    unsafe_code,
    reason = "the fixed control descriptor is uniquely transferred across exec; see SAFETY"
)]
fn inherited_control_stream() -> io::Result<UnixStream> {
    validate_inherited_stream(CONTROL_FD)?;
    // SAFETY: the supervisor duplicates one connected Unix stream onto `CONTROL_FD` immediately
    // before exec and gives this helper sole ownership of that descriptor.
    let stream = unsafe { UnixStream::from_raw_fd(CONTROL_FD) };
    stream.peer_addr()?;
    Ok(stream)
}

#[expect(
    unsafe_code,
    reason = "fcntl and getsockopt validate a fixed inherited descriptor before ownership; see SAFETY"
)]
fn validate_inherited_stream(fd: RawFd) -> io::Result<()> {
    // SAFETY: all calls take a scalar candidate descriptor. getsockopt writes exactly one c_int
    // and its initialized socklen; successful F_GETFD proves the descriptor is open first.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        let mut socket_type = 0;
        let mut length = libc::socklen_t::try_from(std::mem::size_of_val(&socket_type))
            .map_err(invalid_input)?;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::from_mut(&mut socket_type).cast(),
            std::ptr::from_mut(&mut length),
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        if socket_type != libc::SOCK_STREAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inherited control descriptor is not a stream socket",
            ));
        }
        if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn arm_parent_death_signal() -> io::Result<()> {
    let expected_parent = parent_pid();
    raw_prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL)?;
    if parent_pid() != expected_parent || expected_parent <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "namespace supervisor exited during helper startup",
        ));
    }
    Ok(())
}

fn create_user_namespace() -> io::Result<()> {
    raw_unshare(libc::CLONE_NEWUSER)
}

fn enter_mapped_identity() -> io::Result<()> {
    cvt(unsafe_setresgid(0, 0, 0))?;
    cvt(unsafe_setresuid(0, 0, 0))
}

fn create_gateway_namespaces() -> io::Result<()> {
    raw_unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID | libc::CLONE_NEWUTS)?;
    mount_private_root()
}

#[expect(
    unsafe_code,
    reason = "fork is performed by the single-threaded re-exec helper before any runtime exists; see SAFETY"
)]
fn fork_gateway_init(mut control: UnixStream) -> io::Result<ExitCode> {
    let (parent_liveness, child_liveness) = create_liveness_pipe()?;
    // SAFETY: this helper is single-threaded, holds no library locks, and both branches restrict
    // themselves to owned descriptors and async-signal-safe syscalls until ordinary Rust resumes.
    let child = unsafe { libc::fork() };
    if child == -1 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        drop(parent_liveness);
        arm_parent_death_signal_without_pid_check()?;
        require_parent_liveness(&child_liveness)?;
        drop(child_liveness);
        mount_private_proc()?;
        return gateway_init(control);
    }
    drop(child_liveness);

    let child_pid =
        u32::try_from(child).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    send_sync(
        &mut control,
        &ManagerMessage::GatewayNamespaceReady { pid: child_pid },
    )?;
    drop(control);
    let _parent_liveness = parent_liveness;
    wait_for_gateway_init(child)
}

fn arm_parent_death_signal_without_pid_check() -> io::Result<()> {
    raw_prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL)
}

#[expect(
    unsafe_code,
    reason = "pipe2 creates two fresh descriptors in caller-provided integer storage; see SAFETY"
)]
fn create_liveness_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: `descriptors` is valid writable storage for exactly two fds. On success pipe2
    // transfers one fresh descriptor into each slot; both are immediately adopted below.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 returned two distinct, newly owned descriptors.
    #[expect(
        unsafe_code,
        reason = "successful pipe2 transfers ownership of both returned descriptors; see SAFETY"
    )]
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[1]),
            OwnedFd::from_raw_fd(descriptors[0]),
        )
    })
}

fn require_parent_liveness(descriptor: &OwnedFd) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    // SAFETY: poll receives one initialized descriptor and may update only its revents field.
    #[expect(
        unsafe_code,
        reason = "poll receives one valid pollfd for the duration of the call; see SAFETY"
    )]
    let result = unsafe { libc::poll(std::ptr::from_mut(&mut poll), 1, 0) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "namespace manager exited during gateway startup",
        ))
    }
}

fn wait_for_gateway_init(child: libc::pid_t) -> io::Result<ExitCode> {
    loop {
        let mut status = 0;
        let result = raw_waitpid(child, &mut status, 0);
        if result == child {
            return Ok(exit_code_from_wait_status(status));
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

fn gateway_init(mut control: UnixStream) -> io::Result<ExitCode> {
    match receive_sync(&mut control)? {
        SupervisorMessage::PastaReady => deny_process_inspection()?,
        SupervisorMessage::Shutdown => return Ok(ExitCode::SUCCESS),
        _ => return Err(protocol_order("expected pasta readiness")),
    }
    let request = match receive_sync(&mut control)? {
        SupervisorMessage::Configure(request) => *request,
        SupervisorMessage::Shutdown => return Ok(ExitCode::SUCCESS),
        _ => return Err(protocol_order("expected provision request")),
    };

    match start_gateway(&mut control, request) {
        Ok(exit) => Ok(exit_code_for_substrate(exit)),
        Err(failure) => {
            let _ = send_sync(
                &mut control,
                &ManagerMessage::Failed {
                    stage: WireStartupStage::from(failure.stage),
                    reason: WireDegradationReason::from(failure.reason),
                    diagnostic: failure.error.to_string(),
                },
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

#[derive(Debug)]
struct ManagerFailure {
    stage: StartupStage,
    reason: CaptureTransportDegradationReason,
    error: io::Error,
}

impl ManagerFailure {
    fn new(stage: StartupStage, error: impl Into<io::Error>) -> Self {
        Self {
            stage,
            reason: CaptureTransportDegradationReason::NetnsStartupFailed,
            error: error.into(),
        }
    }

    fn classified(
        stage: StartupStage,
        reason: CaptureTransportDegradationReason,
        error: impl Into<io::Error>,
    ) -> Self {
        Self {
            stage,
            reason,
            error: error.into(),
        }
    }
}

struct RunningGateway {
    workload_pid: libc::pid_t,
    worker_pid: Option<libc::pid_t>,
    routing: RoutingPlan,
    listeners: Option<TransparentListeners>,
    broker: Option<UnixDatagram>,
}

fn start_gateway(
    control: &mut UnixStream,
    request: WireProvisionRequest,
) -> Result<SubstrateExit, ManagerFailure> {
    let parts = request
        .into_parts()
        .map_err(|error| ManagerFailure::new(StartupStage::Workload, error))?;
    let workload = parts.workload;
    let gateway_worker = parts.gateway_worker;
    let requested_port = parts.port;
    let require_ipv6 = parts.require_ipv6;
    let validate_dataplane = parts.validate_dataplane;
    let resolv_conf = parts.resolv_conf;
    validate_carrier(require_ipv6)?;
    configure_gateway_sysctls()
        .map_err(|error| ManagerFailure::new(StartupStage::Routing, error))?;
    let listeners = TransparentListeners::bind(requested_port).map_err(|error| {
        let reason = match &error {
            TransparentListenerError::Ipv4(_) | TransparentListenerError::UdpIpv4(_) => {
                CaptureTransportDegradationReason::TproxyUnavailable
            }
            TransparentListenerError::Ipv6(_) | TransparentListenerError::UdpIpv6(_) => {
                CaptureTransportDegradationReason::Ipv6Unavailable
            }
        };
        ManagerFailure::classified(StartupStage::Routing, reason, io::Error::other(error))
    })?;
    let port = listeners.port();
    let hosts_file = generated_hosts_file()
        .map_err(|error| ManagerFailure::new(StartupStage::Workload, error))?;
    let resolv_file = generated_resolv_file(&resolv_conf).map_err(|error| {
        ManagerFailure::classified(
            StartupStage::Workload,
            CaptureTransportDegradationReason::ResolverUnavailable,
            error,
        )
    })?;
    let (workload_pid, mut workload_control) = spawn_workload_helper()
        .map_err(|error| ManagerFailure::new(StartupStage::Namespace, error))?;
    let routing = RoutingPlan::new(pid_u32(workload_pid)?, port);

    if let Err(failure) = execute_gateway_setup(&routing) {
        let mut running = RunningGateway {
            workload_pid,
            worker_pid: None,
            routing,
            listeners: Some(listeners),
            broker: None,
        };
        let _ = cleanup_gateway(&mut running);
        return Err(failure);
    }
    if let Err(failure) = configure_workload(
        &mut workload_control,
        &routing,
        hosts_file.path(),
        resolv_file.path(),
    ) {
        let mut running = RunningGateway {
            workload_pid,
            worker_pid: None,
            routing,
            listeners: Some(listeners),
            broker: None,
        };
        let _ = cleanup_gateway(&mut running);
        return Err(failure);
    }
    if let Err(error) = hosts_file.close() {
        let mut running = RunningGateway {
            workload_pid,
            worker_pid: None,
            routing,
            listeners: Some(listeners),
            broker: None,
        };
        let _ = cleanup_gateway(&mut running);
        return Err(ManagerFailure::new(StartupStage::Workload, error));
    }
    if let Err(error) = resolv_file.close() {
        let mut running = RunningGateway {
            workload_pid,
            worker_pid: None,
            routing,
            listeners: Some(listeners),
            broker: None,
        };
        let _ = cleanup_gateway(&mut running);
        return Err(ManagerFailure::new(StartupStage::Workload, error));
    }

    let (worker_pid, broker) = match spawn_gateway_worker(gateway_worker, &listeners) {
        Ok(worker) => worker,
        Err(error) => {
            let mut running = RunningGateway {
                workload_pid,
                worker_pid: None,
                routing,
                listeners: Some(listeners),
                broker: None,
            };
            let _ = cleanup_gateway(&mut running);
            return Err(ManagerFailure::new(StartupStage::GatewayWorker, error));
        }
    };
    drop(listeners);

    let mut running = RunningGateway {
        workload_pid,
        worker_pid: Some(worker_pid),
        routing,
        listeners: None,
        broker: Some(broker),
    };
    if let Err(error) = start_workload(&mut workload_control, workload) {
        let _ = cleanup_gateway(&mut running);
        return Err(ManagerFailure::new(StartupStage::Workload, error));
    }
    drop(workload_control);

    let info = match substrate_info(port) {
        Ok(info) => info,
        Err(failure) => {
            let _ = cleanup_gateway(&mut running);
            return Err(failure);
        }
    };
    if let Err(error) = send_sync(
        control,
        &ManagerMessage::Ready(WireSubstrateInfo::from(&info)),
    ) {
        let _ = cleanup_gateway(&mut running);
        return Err(ManagerFailure::new(StartupStage::Namespace, error));
    }

    let terminal = supervise_children(control, &running);
    let validation_failure = if validate_dataplane
        && matches!(&terminal, TerminalState::Workload(SubstrateExit::Code(0)))
    {
        thread::sleep(CHILD_POLL_INTERVAL);
        validate_fragment_counters().err()
    } else {
        None
    };
    let cleanup_failures = cleanup_gateway(&mut running);

    if let Some(error) = validation_failure {
        send_sync(
            control,
            &ManagerMessage::Failed {
                stage: WireStartupStage::Routing,
                reason: WireDegradationReason::TproxyUnavailable,
                diagnostic: error.to_string(),
            },
        )
        .map_err(|send_error| ManagerFailure::new(StartupStage::Routing, send_error))?;
        send_sync(
            control,
            &ManagerMessage::CleanupComplete {
                failures: cleanup_failures,
            },
        )
        .map_err(|send_error| ManagerFailure::new(StartupStage::Namespace, send_error))?;
        return Ok(SubstrateExit::Code(1));
    }
    match terminal {
        TerminalState::Workload(exit) => {
            send_sync(
                control,
                &ManagerMessage::WorkloadExited(WireExit::from(exit)),
            )
            .map_err(|error| ManagerFailure::new(StartupStage::Workload, error))?;
            send_sync(
                control,
                &ManagerMessage::CleanupComplete {
                    failures: cleanup_failures,
                },
            )
            .map_err(|error| ManagerFailure::new(StartupStage::Namespace, error))?;
            Ok(exit)
        }
        TerminalState::Shutdown | TerminalState::ControlClosed => {
            if matches!(terminal, TerminalState::Shutdown) {
                send_sync(
                    control,
                    &ManagerMessage::CleanupComplete {
                        failures: cleanup_failures,
                    },
                )
                .map_err(|error| ManagerFailure::new(StartupStage::Namespace, error))?;
            }
            Ok(SubstrateExit::Code(0))
        }
        TerminalState::WorkerFailed(exit) => {
            let diagnostic = format!("gateway worker exited {exit:?}");
            send_sync(
                control,
                &ManagerMessage::Failed {
                    stage: WireStartupStage::GatewayWorker,
                    reason: WireDegradationReason::NetnsStartupFailed,
                    diagnostic: diagnostic.clone(),
                },
            )
            .map_err(|error| ManagerFailure::new(StartupStage::GatewayWorker, error))?;
            send_sync(
                control,
                &ManagerMessage::CleanupComplete {
                    failures: cleanup_failures,
                },
            )
            .map_err(|error| ManagerFailure::new(StartupStage::Namespace, error))?;
            Ok(SubstrateExit::Code(1))
        }
        TerminalState::Fatal(report) => {
            send_sync(
                control,
                &ManagerMessage::Fatal(WireFatalReport::from(&report)),
            )
            .map_err(|error| ManagerFailure::new(StartupStage::GatewayWorker, error))?;
            send_sync(
                control,
                &ManagerMessage::CleanupComplete {
                    failures: cleanup_failures,
                },
            )
            .map_err(|error| ManagerFailure::new(StartupStage::Namespace, error))?;
            Ok(SubstrateExit::Code(1))
        }
    }
}

fn validate_fragment_counters() -> io::Result<()> {
    for (family, counter) in [
        ("IPv4", IPV4_FRAGMENT_COUNTER),
        ("IPv6", IPV6_FRAGMENT_COUNTER),
    ] {
        let output = Command::new("nft")
            .args(["list", "counter", "inet", NFT_TABLE, counter])
            .output()?;
        require_success(
            "inspect fragmented UDP counter",
            output.status,
            &output.stderr,
        )?;
        let packets = parse_counter_packets(&String::from_utf8_lossy(&output.stdout))?;
        if packets == 0 {
            return Err(io::Error::other(format!(
                "{family} fragmented UDP did not hit the fail-closed nft rule"
            )));
        }
    }
    Ok(())
}

fn substrate_info(port: NonZeroU16) -> Result<SubstrateInfo, ManagerFailure> {
    SubstrateInfo::new(
        port,
        LINK_MTU,
        GATEWAY_IPV4,
        GATEWAY_IPV6,
        parse_ipv4(HOST_LOOPBACK_IPV4)?,
        parse_ipv6(HOST_LOOPBACK_IPV6)?,
        FragmentedUdpBehavior::Drop,
    )
    .map_err(|error| ManagerFailure::new(StartupStage::Routing, io::Error::other(error)))
}

fn validate_carrier(require_ipv6: bool) -> Result<(), ManagerFailure> {
    let output = Command::new("ip")
        .args(["-details", "link", "show", "dev", PASTA_INTERFACE])
        .output()
        .map_err(tun_failure)?;
    require_success("inspect pasta interface", output.status, &output.stderr)
        .map_err(tun_failure)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains(&format!("mtu {LINK_MTU}")) {
        return Err(tun_failure(io::Error::other(format!(
            "pasta interface did not report MTU {LINK_MTU}"
        ))));
    }
    let route = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .map_err(tun_failure)?;
    require_success("inspect pasta IPv4 route", route.status, &route.stderr)
        .map_err(tun_failure)?;
    if route.stdout.is_empty() {
        return Err(tun_failure(io::Error::other(
            "pasta installed no IPv4 default route",
        )));
    }
    if require_ipv6 {
        let route = Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .map_err(ipv6_failure)?;
        require_success("inspect pasta IPv6 route", route.status, &route.stderr)
            .map_err(ipv6_failure)?;
        if route.stdout.is_empty() {
            return Err(ipv6_failure(io::Error::other(
                "pasta installed no IPv6 default route",
            )));
        }
    }
    Ok(())
}

fn tun_failure(error: io::Error) -> ManagerFailure {
    ManagerFailure::classified(
        StartupStage::Pasta,
        CaptureTransportDegradationReason::TunUnavailable,
        error,
    )
}

fn ipv6_failure(error: io::Error) -> ManagerFailure {
    ManagerFailure::classified(
        StartupStage::Pasta,
        CaptureTransportDegradationReason::Ipv6Unavailable,
        error,
    )
}

fn configure_gateway_sysctls() -> io::Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", b"0")?;
    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", b"0")?;
    fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", b"0")?;
    for path in [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv6/conf/all/forwarding",
    ] {
        if fs::read_to_string(path)?.trim() != "0" {
            return Err(io::Error::other(format!(
                "namespace forwarding remained enabled at {path}"
            )));
        }
    }
    if fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")?.trim() != "0" {
        return Err(io::Error::other(
            "gateway namespace did not reserve cap-free DNS port binding",
        ));
    }
    Ok(())
}

fn generated_hosts_file() -> io::Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    let existing = fs::read("/etc/hosts")?;
    file.write_all(&generated_hosts(&existing))?;
    file.flush()?;
    Ok(file)
}

fn generated_resolv_file(contents: &[u8]) -> io::Result<NamedTempFile> {
    if contents.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "generated resolver configuration is empty",
        ));
    }
    let mut file = NamedTempFile::new()?;
    file.write_all(contents)?;
    file.flush()?;
    Ok(file)
}

fn generated_hosts(existing: &[u8]) -> Vec<u8> {
    const RESERVED_HOST: &[u8] = b"host.hiloop.internal";

    let mut generated = Vec::with_capacity(existing.len().saturating_add(128));
    for line in existing.split_inclusive(|byte| *byte == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let comment_at = content.iter().position(|byte| *byte == b'#');
        let address_fields = &content[..comment_at.unwrap_or(content.len())];
        let fields = address_fields
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.iter().skip(1).any(|field| *field == RESERVED_HOST) {
            let retained = fields
                .into_iter()
                .enumerate()
                .filter_map(|(index, field)| {
                    (index == 0 || field != RESERVED_HOST).then_some(field)
                })
                .collect::<Vec<_>>();
            if retained.len() > 1 {
                for (index, field) in retained.into_iter().enumerate() {
                    if index > 0 {
                        generated.push(b' ');
                    }
                    generated.extend_from_slice(field);
                }
                if let Some(comment_at) = comment_at {
                    generated.push(b' ');
                    generated.extend_from_slice(&content[comment_at..]);
                }
                generated.push(b'\n');
            }
        } else {
            generated.extend_from_slice(line);
        }
    }
    if !generated.ends_with(b"\n") {
        generated.push(b'\n');
    }
    generated.extend_from_slice(HOST_LOOPBACK_IPV4.as_bytes());
    generated.extend_from_slice(b" host.hiloop.internal\n");
    generated.extend_from_slice(HOST_LOOPBACK_IPV6.as_bytes());
    generated.extend_from_slice(b" host.hiloop.internal\n");
    generated
}

fn spawn_workload_helper() -> io::Result<(libc::pid_t, UnixStream)> {
    let (manager, child) = UnixStream::pair()?;
    let child_fd = child.as_raw_fd();
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg(WORKLOAD_ROLE)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    set_workload_pre_exec(&mut command, child_fd);
    let child_process = command.spawn()?;
    let pid = libc::pid_t::try_from(child_process.id())
        .ok()
        .ok_or_else(|| io::Error::other("workload helper returned no PID"))?;
    drop(child_process);
    drop(child);
    Ok((pid, manager))
}

#[expect(
    unsafe_code,
    reason = "pre_exec performs only scalar Linux syscalls before exec; see SAFETY"
)]
fn set_workload_pre_exec(command: &mut Command, control_fd: RawFd) {
    let expected_parent = current_pid();
    // SAFETY: the closure calls only async-signal-safe syscalls, captures integers only, and
    // returns any errno to `Command` so the child aborts instead of continuing partially set up.
    unsafe {
        command.pre_exec(move || {
            duplicate_to(control_fd, CONTROL_FD)?;
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "gateway exited during workload startup",
                ));
            }
            if libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) == -1 {
                return Err(io::Error::last_os_error());
            }
            mount_private_root()?;
            Ok(())
        });
    }
}

fn configure_workload(
    control: &mut UnixStream,
    routing: &RoutingPlan,
    hosts_path: &Path,
    resolv_path: &Path,
) -> Result<(), ManagerFailure> {
    let commands = routing
        .setup_commands()
        .iter()
        .filter(|command| command.namespace() == NetworkNamespace::Workload)
        .map(wire_routing_command)
        .collect();
    send_sync(
        control,
        &WorkloadMessage::Configure {
            commands,
            hosts_path: hosts_path.as_os_str().as_bytes().to_vec(),
            resolv_path: resolv_path.as_os_str().as_bytes().to_vec(),
        },
    )
    .map_err(|error| ManagerFailure::new(StartupStage::Workload, error))?;
    match receive_sync(control)
        .map_err(|error| ManagerFailure::new(StartupStage::Workload, error))?
    {
        WorkloadReply::Ready => Ok(()),
        WorkloadReply::Failed { reason, diagnostic } => Err(ManagerFailure::classified(
            StartupStage::Workload,
            reason.into(),
            io::Error::other(diagnostic),
        )),
        WorkloadReply::ExecFailed { .. } => Err(ManagerFailure::new(
            StartupStage::Workload,
            protocol_order("workload exec preceded start"),
        )),
    }
}

fn start_workload(control: &mut UnixStream, workload: WireCommand) -> io::Result<()> {
    send_sync(control, &WorkloadMessage::Start(workload))?;
    match receive_sync::<WorkloadReply>(control) {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Ok(WorkloadReply::ExecFailed { diagnostic }) => Err(io::Error::other(diagnostic)),
        Ok(WorkloadReply::Ready | WorkloadReply::Failed { .. }) => Err(protocol_order(
            "workload sent an invalid exec acknowledgement",
        )),
        Err(error) => Err(error),
    }
}

fn wire_routing_command(command: &NamespacedCommand) -> WireExecCommand {
    WireExecCommand::new(
        OsStr::new(command.command().program()),
        command.command().arguments().iter().map(OsString::from),
    )
}

fn execute_gateway_setup(routing: &RoutingPlan) -> Result<(), ManagerFailure> {
    for (index, command) in routing
        .setup_commands()
        .iter()
        .filter(|command| command.namespace() == NetworkNamespace::Gateway)
        .enumerate()
    {
        execute_routing_command(command, Some(routing.nft_script())).map_err(|error| {
            let (stage, reason) = gateway_setup_failure(index, command);
            ManagerFailure::classified(stage, reason, error)
        })?;
    }
    Ok(())
}

fn gateway_setup_failure(
    index: usize,
    command: &NamespacedCommand,
) -> (StartupStage, CaptureTransportDegradationReason) {
    if command.command().arguments().first().map(String::as_str) == Some("-6") {
        return (
            StartupStage::Routing,
            CaptureTransportDegradationReason::Ipv6Unavailable,
        );
    }
    if index < 4 {
        (
            StartupStage::Veth,
            CaptureTransportDegradationReason::NetnsStartupFailed,
        )
    } else {
        (
            StartupStage::Routing,
            CaptureTransportDegradationReason::TproxyUnavailable,
        )
    }
}

fn execute_routing_command(
    command: &NamespacedCommand,
    nft_script: Option<&str>,
) -> io::Result<()> {
    let mut process = Command::new(command.command().program());
    process.args(command.command().arguments());
    if command.command().program() == "nft" && command.command().arguments() == ["-f", "-"] {
        process.stdin(Stdio::piped());
    }
    process.stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = process.spawn()?;
    if let Some(script) = nft_script
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(script.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    require_success(command.command().program(), output.status, &output.stderr)
}

fn spawn_gateway_worker(
    worker: WireCommand,
    listeners: &TransparentListeners,
) -> io::Result<(libc::pid_t, UnixDatagram)> {
    let command_spec = worker.into_command();
    let (ready_parent, ready_child) = UnixDatagram::pair()?;
    ready_parent.set_read_timeout(Some(WORKER_READY_TIMEOUT))?;
    let listener_fds = listeners.raw_fds();
    let ready_fd = ready_child.as_raw_fd();
    let lockdown = ChildLockdown::prepare(&[
        IPV4_LISTENER_FD,
        IPV6_LISTENER_FD,
        IPV4_UDP_FD,
        IPV6_UDP_FD,
        WORKER_READY_FD,
    ])?;
    let mut command = command_from_spec(&command_spec);
    set_worker_pre_exec(&mut command, listener_fds, ready_fd, lockdown);
    let child = command.spawn()?;
    let pid = libc::pid_t::try_from(child.id())
        .ok()
        .ok_or_else(|| io::Error::other("gateway worker returned no PID"))?;
    drop(child);
    drop(ready_child);
    let mut readiness = [0_u8; 1];
    if ready_parent.recv(&mut readiness)? != readiness.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway worker sent partial readiness",
        ));
    }
    if readiness != [1] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway worker sent invalid readiness byte",
        ));
    }
    ready_parent.set_nonblocking(true)?;
    Ok((pid, ready_parent))
}

#[expect(
    unsafe_code,
    reason = "pre_exec duplicates owned descriptors and applies a prepared syscall-only lockdown; see SAFETY"
)]
fn set_worker_pre_exec(
    command: &mut Command,
    listeners: [RawFd; 4],
    ready_fd: RawFd,
    lockdown: ChildLockdown,
) {
    let expected_parent = current_pid();
    // SAFETY: all allocations and descriptor discovery happened in `prepare`; the closure calls
    // only dup/fcntl/prctl/capset/close syscalls and aborts the child on the first failure.
    unsafe {
        command.pre_exec(move || {
            duplicate_to(listeners[0], IPV4_LISTENER_FD)?;
            duplicate_to(listeners[1], IPV6_LISTENER_FD)?;
            duplicate_to(listeners[2], IPV4_UDP_FD)?;
            duplicate_to(listeners[3], IPV6_UDP_FD)?;
            duplicate_to(ready_fd, WORKER_READY_FD)?;
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "gateway exited during worker startup",
                ));
            }
            lockdown.apply_in_pre_exec()
        });
    }
}

fn command_from_spec(spec: &NamespaceCommand) -> Command {
    let mut command = Command::new(spec.program());
    command.args(spec.arguments());
    for (name, value) in spec.environment() {
        match value {
            Some(value) => {
                command.env(name, value);
            }
            None => {
                command.env_remove(name);
            }
        }
    }
    if let Some(directory) = spec.working_directory() {
        command.current_dir(directory);
    }
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TerminalState {
    Workload(SubstrateExit),
    WorkerFailed(SubstrateExit),
    Shutdown,
    ControlClosed,
    Fatal(FatalReport),
}

fn supervise_children(control: &mut UnixStream, running: &RunningGateway) -> TerminalState {
    loop {
        let exits = reap_available_children();
        if let Some(terminal) =
            terminal_from_reaped(&exits, running.workload_pid, running.worker_pid)
        {
            return terminal;
        }
        if let Some(broker) = &running.broker {
            match service_gateway_control(broker) {
                Ok(Some(report)) => return TerminalState::Fatal(report),
                Ok(None) => {}
                Err(_) => return TerminalState::WorkerFailed(SubstrateExit::Code(1)),
            }
        }
        match control_readable(control.as_raw_fd(), CHILD_POLL_INTERVAL) {
            Ok(false) => {}
            Ok(true) => match receive_sync::<SupervisorMessage>(control) {
                Ok(SupervisorMessage::Shutdown) => return TerminalState::Shutdown,
                Ok(_) | Err(_) => return TerminalState::ControlClosed,
            },
            Err(_) => return TerminalState::ControlClosed,
        }
    }
}

fn service_gateway_control(broker: &UnixDatagram) -> io::Result<Option<FatalReport>> {
    loop {
        let mut request = [0_u8; MAX_GATEWAY_CONTROL_BYTES];
        let length = match broker.recv(&mut request) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        if let Some(report) = decode_gateway_fatal(&request[..length])? {
            return Ok(Some(report));
        }
        let Some(key) = decode_request(&request[..length]) else {
            send_broker_error(broker)?;
            continue;
        };
        let Ok(socket) = create_transparent_reply_socket(key) else {
            send_broker_error(broker)?;
            continue;
        };
        let status = [BROKER_STATUS_OK];
        let iovec = [IoSlice::new(&status)];
        let descriptors = [socket.as_raw_fd()];
        let control = [nix::sys::socket::ControlMessage::ScmRights(&descriptors)];
        let sent = nix::sys::socket::sendmsg::<()>(
            broker.as_raw_fd(),
            &iovec,
            &control,
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .map_err(errno_io)?;
        if sent != status.len() {
            return Err(io::Error::other("UDP broker response was partially sent"));
        }
    }
}

fn send_broker_error(broker: &UnixDatagram) -> io::Result<()> {
    if broker.send(&[BROKER_STATUS_ERROR])? == 1 {
        Ok(())
    } else {
        Err(io::Error::other(
            "UDP broker error response was partially sent",
        ))
    }
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn terminal_from_reaped(
    exits: &[(libc::pid_t, SubstrateExit)],
    workload_pid: libc::pid_t,
    worker_pid: Option<libc::pid_t>,
) -> Option<TerminalState> {
    exits
        .iter()
        .find(|(pid, _)| worker_pid == Some(*pid))
        .map(|(_, exit)| TerminalState::WorkerFailed(*exit))
        .or_else(|| {
            exits
                .iter()
                .find(|(pid, _)| *pid == workload_pid)
                .map(|(_, exit)| TerminalState::Workload(*exit))
        })
}

fn control_readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    let milliseconds = libc::c_int::try_from(timeout.as_millis()).map_err(invalid_input)?;
    #[expect(
        unsafe_code,
        reason = "poll receives one initialized descriptor and writes only its revents field; see SAFETY"
    )]
    // SAFETY: `descriptor` is valid writable storage for one `pollfd` and the call retains no
    // pointer after returning.
    let result = unsafe { libc::poll(std::ptr::from_mut(&mut descriptor), 1, milliseconds) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result > 0)
    }
}

fn cleanup_gateway(running: &mut RunningGateway) -> Vec<String> {
    running.listeners.take();
    running.broker.take();
    let mut failures = Vec::new();
    let teardown = running.routing.teardown_commands();
    if let Some(veth) = teardown.first()
        && let Err(error) = execute_routing_command(veth, None)
    {
        failures.push(format!("delete workload veth: {error}"));
    }
    kill_namespace_descendants();
    for command in teardown.iter().skip(1) {
        if let Err(error) = execute_routing_command(command, None) {
            failures.push(format!(
                "{} {}: {error}",
                command.command().program(),
                command.command().arguments().join(" ")
            ));
        }
    }
    if let Err(error) = reap_descendants() {
        failures.push(format!("reap PID-namespace descendants: {error}"));
    }
    failures
}

fn kill_namespace_descendants() {
    #[expect(
        unsafe_code,
        reason = "kill(-1) is the Linux PID-namespace operation that excludes PID 1 itself; see SAFETY"
    )]
    // SAFETY: scalar PID -1 targets every signalable process except this PID-namespace init.
    let _ = unsafe { libc::kill(-1, libc::SIGKILL) };
}

fn reap_descendants() -> io::Result<()> {
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        let reaped = reap_available_children();
        if reaped.is_empty() {
            let mut status = 0;
            let result = raw_waitpid(-1, &mut status, libc::WNOHANG);
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    return Ok(());
                }
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PID-namespace descendants did not exit after SIGKILL",
            ));
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

fn reap_available_children() -> Vec<(libc::pid_t, SubstrateExit)> {
    let mut exits = Vec::new();
    loop {
        let mut status = 0;
        let pid = raw_waitpid(-1, &mut status, libc::WNOHANG);
        if pid <= 0 {
            return exits;
        }
        exits.push((pid, substrate_exit_from_wait_status(status)));
    }
}

fn workload_entrypoint() -> io::Result<ExitCode> {
    close_descriptors_except(&[CONTROL_FD])?;
    let mut control = inherited_control_stream()?;
    let (commands, hosts_path, resolv_path) = match receive_sync(&mut control)? {
        WorkloadMessage::Configure {
            commands,
            hosts_path,
            resolv_path,
        } => (
            commands,
            PathBuf::from(OsString::from_vec(hosts_path)),
            PathBuf::from(OsString::from_vec(resolv_path)),
        ),
        WorkloadMessage::Shutdown => return Ok(ExitCode::SUCCESS),
        WorkloadMessage::Start(_) => return Err(protocol_order("workload start preceded setup")),
    };
    let setup = configure_workload_namespace(commands, &hosts_path, &resolv_path);
    match setup {
        Ok(()) => send_sync(&mut control, &WorkloadReply::Ready)?,
        Err(failure) => {
            let _ = send_sync(
                &mut control,
                &WorkloadReply::Failed {
                    reason: WireDegradationReason::from(failure.reason),
                    diagnostic: failure.error.to_string(),
                },
            );
            return Err(failure.error);
        }
    }
    let command = match receive_sync(&mut control)? {
        WorkloadMessage::Start(command) => command.into_command(),
        WorkloadMessage::Shutdown => return Ok(ExitCode::SUCCESS),
        WorkloadMessage::Configure { .. } => {
            return Err(protocol_order("workload configured twice"));
        }
    };
    let lockdown = ChildLockdown::prepare(&[CONTROL_FD])?;
    exec_locked_down(&command, &lockdown, &mut control)
}

fn configure_workload_namespace(
    commands: Vec<WireExecCommand>,
    hosts_path: &Path,
    resolv_path: &Path,
) -> Result<(), WorkloadSetupFailure> {
    for command in commands {
        let (program, args) = command.into_parts();
        let reason = workload_setup_reason(&program, &args);
        let output = Command::new(&program)
            .args(&args)
            .output()
            .map_err(|error| WorkloadSetupFailure { reason, error })?;
        require_success(&program.to_string_lossy(), output.status, &output.stderr)
            .map_err(|error| WorkloadSetupFailure { reason, error })?;
    }
    bind_mount_read_only(hosts_path, Path::new("/etc/hosts")).map_err(|error| {
        WorkloadSetupFailure {
            reason: CaptureTransportDegradationReason::NetnsStartupFailed,
            error,
        }
    })?;
    bind_mount_read_only(resolv_path, Path::new("/etc/resolv.conf")).map_err(|error| {
        WorkloadSetupFailure {
            reason: CaptureTransportDegradationReason::ResolverUnavailable,
            error,
        }
    })
}

struct WorkloadSetupFailure {
    reason: CaptureTransportDegradationReason,
    error: io::Error,
}

fn workload_setup_reason(
    program: &OsStr,
    arguments: &[OsString],
) -> CaptureTransportDegradationReason {
    if program == OsStr::new("ip")
        && arguments.first().and_then(|argument| argument.to_str()) == Some("-6")
    {
        CaptureTransportDegradationReason::Ipv6Unavailable
    } else {
        CaptureTransportDegradationReason::NetnsStartupFailed
    }
}

fn exec_locked_down(
    command: &NamespaceCommand,
    lockdown: &ChildLockdown,
    control: &mut UnixStream,
) -> io::Result<ExitCode> {
    let mut process = command_from_spec(command);
    lockdown.apply()?;
    set_close_on_exec(CONTROL_FD)?;
    let error = process.exec();
    let _ = send_sync(
        control,
        &WorkloadReply::ExecFailed {
            diagnostic: error.to_string(),
        },
    );
    Err(error)
}

#[expect(
    unsafe_code,
    reason = "fcntl marks one validated inherited descriptor close-on-exec; see SAFETY"
)]
fn set_close_on_exec(fd: RawFd) -> io::Result<()> {
    // SAFETY: both fcntl operations accept only a scalar descriptor and flags.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn worker_probe_entrypoint() -> io::Result<ExitCode> {
    let bootstrap = GatewayWorkerBootstrap::from_inherited_fds()?;
    require_empty_capabilities()?;
    let listeners = bootstrap.notify_ready()?;
    require_only_open_fds(&[
        IPV4_LISTENER_FD,
        IPV6_LISTENER_FD,
        IPV4_UDP_FD,
        IPV6_UDP_FD,
        WORKER_READY_FD,
    ])?;
    validate_transparent_listener_probe(listeners)?;
    loop {
        raw_pause();
    }
}

#[cfg(feature = "test-support")]
fn crashing_worker_probe_entrypoint() -> io::Result<ExitCode> {
    let bootstrap = GatewayWorkerBootstrap::from_inherited_fds()?;
    require_empty_capabilities()?;
    let _listeners = bootstrap.notify_ready()?;
    require_only_open_fds(&[
        IPV4_LISTENER_FD,
        IPV6_LISTENER_FD,
        IPV4_UDP_FD,
        IPV6_UDP_FD,
        WORKER_READY_FD,
    ])?;
    thread::sleep(Duration::from_millis(100));
    Ok(ExitCode::from(23))
}

fn workload_probe_entrypoint() -> io::Result<ExitCode> {
    require_empty_capabilities()?;
    require_only_open_fds(&[])?;
    let status = fs::read_to_string("/proc/self/status")?;
    if !status.lines().any(|line| line == "NoNewPrivs:\t1") {
        return Err(io::Error::other(
            "workload probe did not retain no_new_privs",
        ));
    }
    require_ptrace_denied(1, MANAGER_ROLE)?;
    require_process_inspection_denied(WORKER_PROBE_ROLE)?;
    validate_udp_mtu_and_fragments()?;
    validate_transparent_workload_probe()?;
    Ok(ExitCode::SUCCESS)
}

fn validate_transparent_listener_probe(
    listeners: crate::netns::listener::GatewayListeners,
) -> io::Result<()> {
    let (ipv4, ipv6, _udp_ipv4, _udp_ipv6, _broker) = listeners.into_parts();
    ipv4.set_nonblocking(false)?;
    ipv6.set_nonblocking(false)?;
    for (listener, expected, response) in [
        (&ipv4, "198.51.100.42:443", 1_u8),
        (&ipv6, "[2001:db8::42]:443", 2_u8),
    ] {
        let (mut connection, _) = listener.accept()?;
        require_probe_destination(
            connection.local_addr()?,
            expected.parse().map_err(invalid_input)?,
        )?;
        connection.write_all(&[response])?;
    }
    Ok(())
}

fn validate_transparent_workload_probe() -> io::Result<()> {
    use std::net::TcpStream;

    let timeout = Duration::from_secs(5);
    for (destination, expected) in [("198.51.100.42:443", 1_u8), ("[2001:db8::42]:443", 2_u8)] {
        let address = destination.parse().map_err(invalid_input)?;
        let mut stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        let mut response = [0_u8; 1];
        stream.read_exact(&mut response)?;
        if response != [expected] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("transparent preflight returned {response:?} for {destination}"),
            ));
        }
    }
    Ok(())
}

fn require_only_open_fds(allowed: &[RawFd]) -> io::Result<()> {
    let candidates = fs::read_dir("/proc/self/fd")?
        .map(|entry| {
            let name = entry?.file_name();
            name.to_string_lossy()
                .parse::<RawFd>()
                .map_err(invalid_input)
        })
        .collect::<io::Result<Vec<_>>>()?;
    for fd in candidates {
        if fd < 3 || allowed.contains(&fd) {
            continue;
        }
        // SAFETY: F_GETFD takes only a scalar candidate descriptor and does not mutate it.
        #[expect(
            unsafe_code,
            reason = "fcntl probes scalar descriptor numbers without pointer arguments; see SAFETY"
        )]
        let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if result != -1 {
            return Err(io::Error::other(format!(
                "helper inherited unexpected file descriptor {fd}"
            )));
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn require_process_inspection_denied(role: &str) -> io::Result<()> {
    let pid = find_process_by_role(role)?;
    require_ptrace_denied(pid, role)
}

fn require_ptrace_denied(pid: libc::pid_t, role: &str) -> io::Result<()> {
    // SAFETY: ptrace receives only the target PID and null address/data for ATTACH/DETACH.
    #[expect(
        unsafe_code,
        reason = "the security probe attempts and, only on unexpected success, detaches ptrace; see SAFETY"
    )]
    unsafe {
        if libc::ptrace(
            libc::PTRACE_ATTACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ) == -1
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPERM) {
                return Ok(());
            }
            return Err(error);
        }
        let mut status = 0;
        let _ = libc::waitpid(pid, std::ptr::from_mut(&mut status), libc::__WALL);
        let _ = libc::ptrace(
            libc::PTRACE_DETACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("workload could ptrace protected process role {role}"),
    ))
}

fn find_process_by_role(role: &str) -> io::Result<libc::pid_t> {
    let role = role.as_bytes();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse().ok())
        else {
            continue;
        };
        let command = match fs::read(entry.path().join("cmdline")) {
            Ok(command) => command,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if command
            .split(|byte| *byte == 0)
            .any(|argument| argument == role)
        {
            return Ok(pid);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "could not find protected process role {}",
            String::from_utf8_lossy(role)
        ),
    ))
}

fn validate_udp_mtu_and_fragments() -> io::Result<()> {
    validate_udp_family(
        IpFamily::Ipv4,
        "0.0.0.0:0",
        "198.51.100.42:443",
        libc::IPPROTO_IP,
        libc::IP_MTU_DISCOVER,
    )?;
    validate_udp_family(
        IpFamily::Ipv6,
        "[::]:0",
        "[2001:db8::42]:443",
        libc::IPPROTO_IPV6,
        libc::IPV6_MTU_DISCOVER,
    )
}

fn validate_udp_family(
    family: IpFamily,
    bind: &str,
    destination: &str,
    option_level: libc::c_int,
    option_name: libc::c_int,
) -> io::Result<()> {
    use std::net::UdpSocket;

    let socket = UdpSocket::bind(bind)?;
    socket.connect(destination)?;
    set_socket_integer_option(&socket, option_level, option_name, libc::IP_PMTUDISC_DO)?;
    let maximum = family.max_udp_payload();
    let boundary = vec![0x5a; maximum];
    if socket.send(&boundary)? != maximum {
        return Err(io::Error::other(format!(
            "{family:?} boundary UDP datagram was partially sent"
        )));
    }
    let oversized = vec![0xa5; maximum + 1];
    match socket.send(&oversized) {
        Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(io::Error::other(format!(
                "{family:?} PMTU did not reject an oversized UDP datagram"
            )));
        }
    }
    set_socket_integer_option(&socket, option_level, option_name, libc::IP_PMTUDISC_DONT)?;
    if socket.send(&oversized)? != oversized.len() {
        return Err(io::Error::other(format!(
            "{family:?} fragmented UDP probe was partially sent"
        )));
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "setsockopt reads one initialized integer for a valid UDP socket; see SAFETY"
)]
fn set_socket_integer_option(
    socket: &std::net::UdpSocket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: the socket remains owned by the caller; value is initialized and its length exact.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            libc::socklen_t::try_from(std::mem::size_of_val(&value)).map_err(invalid_input)?,
        )
    };
    cvt(result)
}

#[cfg(feature = "test-support")]
fn dataplane_worker_probe_entrypoint() -> io::Result<ExitCode> {
    use std::sync::Arc;

    use crate::netns::{
        TransparentTcpIngress, TransparentUdpChildSink, TransparentUdpIngress, UdpFlowRelay,
    };

    let evidence_path = std::env::args_os()
        .nth(2)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing evidence path"))?;
    let host_ipv4_port = parse_probe_port(3)?;
    let host_ipv6_port = parse_probe_port(4)?;
    let _host_udp_ipv4_port = parse_probe_port(5)?;
    let _host_udp_ipv6_port = parse_probe_port(6)?;
    let bootstrap = GatewayWorkerBootstrap::from_inherited_fds()?;
    require_empty_capabilities()?;
    let listeners = bootstrap.notify_ready()?;
    let (ipv4, ipv6, udp_ipv4, udp_ipv6, broker) = listeners.into_parts();
    require_only_open_fds(&[
        IPV4_LISTENER_FD,
        IPV6_LISTENER_FD,
        IPV4_UDP_FD,
        IPV6_UDP_FD,
        WORKER_READY_FD,
    ])?;
    let ingress = TransparentTcpIngress::from_std(ipv4, ipv6)?;
    let udp_ingress = TransparentUdpIngress::from_std(udp_ipv4, udp_ipv6)?;
    let udp_sink = Arc::new(TransparentUdpChildSink::new(broker)?);
    let (summary_tx, mut summary_rx) = tokio::sync::mpsc::channel(8);
    let udp_relay = Arc::new(UdpFlowRelay::new(
        false,
        &crate::egress::EgressPolicy::default(),
        Duration::from_secs(5),
        udp_sink,
        summary_tx,
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    let (
        (first_destination, first_address),
        (second_destination, second_address),
        (host_ipv4_destination, host_ipv4_peer),
        (host_ipv6_destination, host_ipv6_peer),
    ) = runtime.block_on(async {
        let relay = Arc::clone(&udp_relay);
        let _udp_task = tokio::spawn(async move { udp_ingress.serve(&relay).await });
        let first = accept_transparent_probe(
            &ingress,
            "198.51.100.42:443".parse().map_err(invalid_input)?,
            1,
        )
        .await?;
        let second = accept_transparent_probe(
            &ingress,
            "[2001:db8::42]:443".parse().map_err(invalid_input)?,
            2,
        )
        .await?;
        let host_ipv4 = proxy_host_loopback(
            &ingress,
            std::net::SocketAddr::new(parse_ipv4_address(HOST_LOOPBACK_IPV4)?, host_ipv4_port),
        )
        .await?;
        let host_ipv6_destination = format!("[{HOST_LOOPBACK_IPV6}]:{host_ipv6_port}")
            .parse()
            .map_err(invalid_input)?;
        let host_ipv6 = proxy_host_loopback(&ingress, host_ipv6_destination).await?;
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(10), summary_rx.recv())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP flow did not idle"))?
                .ok_or_else(|| io::Error::other("UDP flow summary channel closed"))?;
        }
        Ok::<_, io::Error>((first, second, host_ipv4, host_ipv6))
    })?;

    fs::write(
        evidence_path,
        format!(
            "ipv4={first_destination} peer={first_address}\nipv6={second_destination} peer={second_address}\nhost_ipv4={host_ipv4_destination} peer={host_ipv4_peer}\nhost_ipv6={host_ipv6_destination} peer={host_ipv6_peer}\n"
        ),
    )?;
    loop {
        raw_pause();
    }
}

#[cfg(feature = "test-support")]
fn fatal_worker_probe_entrypoint() -> io::Result<ExitCode> {
    use hiloop_core::capture::{CaptureFatalReason, OriginalDestination, TlsFlowIdentity};

    use crate::netns::{DataplaneLatch, FatalReport, GatewayFatalController};

    let bootstrap = GatewayWorkerBootstrap::from_inherited_fds()?;
    require_empty_capabilities()?;
    let listeners = bootstrap.notify_ready()?;
    let (_, _, _, _, broker) = listeners.into_parts();
    let destination = OriginalDestination::new("203.0.113.10".parse().map_err(invalid_input)?, 443)
        .map_err(invalid_input)?;
    let flow = TlsFlowIdentity::new(destination)
        .with_server_name("api.example.com")
        .map_err(invalid_input)?
        .with_client_hello_fingerprint("ja4:fatal-probe")
        .map_err(invalid_input)?;
    thread::sleep(Duration::from_millis(200));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(async {
        let controller = GatewayFatalController::new(DataplaneLatch::new(), &broker)?;
        controller
            .trigger(&FatalReport::tls(
                CaptureFatalReason::SecretBindUnterminatable,
                flow,
            ))
            .await
            .map_err(io::Error::other)
    })?;
    loop {
        raw_pause();
    }
}

#[cfg(feature = "test-support")]
async fn accept_transparent_probe(
    ingress: &crate::netns::TransparentTcpIngress,
    expected_destination: std::net::SocketAddr,
    response: u8,
) -> io::Result<(std::net::SocketAddr, std::net::SocketAddr)> {
    use tokio::io::AsyncWriteExt as _;

    let admitted = ingress
        .accept(
            &crate::egress::EgressPolicy::default(),
            &crate::netns::NoDnsAnswerEvidence,
        )
        .await
        .map_err(io::Error::other)?;
    let destination = std::net::SocketAddr::new(
        admitted.route().original_destination().ip(),
        admitted.route().original_destination().port(),
    );
    require_probe_destination(destination, expected_destination)?;
    let (mut flow, _, _) = admitted.into_test_parts();
    let peer = flow.peer_addr()?;
    flow.write_all(&[response]).await?;
    Ok((destination, peer))
}

#[cfg(feature = "test-support")]
async fn proxy_host_loopback(
    ingress: &crate::netns::TransparentTcpIngress,
    expected_destination: std::net::SocketAddr,
) -> io::Result<(std::net::SocketAddr, std::net::SocketAddr)> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let connected = ingress
        .accept_and_connect(
            &crate::egress::EgressPolicy::default(),
            &crate::netns::NoDnsAnswerEvidence,
            &crate::netns::DirectTcpConnector,
        )
        .await
        .map_err(io::Error::other)?;
    let (mut flow, mut upstream, route, _) = connected.into_parts();
    let destination = std::net::SocketAddr::new(
        route.original_destination().ip(),
        route.original_destination().port(),
    );
    require_probe_destination(destination, expected_destination)?;
    let peer = flow.peer_addr()?;
    let mut request = [0_u8; 4];
    flow.read_exact(&mut request).await?;
    upstream.write_all(&request).await?;
    let mut response = [0_u8; 4];
    upstream.read_exact(&mut response).await?;
    flow.write_all(&response).await?;
    Ok((destination, peer))
}

#[cfg(feature = "test-support")]
fn dataplane_workload_probe_entrypoint() -> io::Result<ExitCode> {
    use std::net::{TcpStream, ToSocketAddrs as _, UdpSocket};

    require_empty_capabilities()?;
    require_only_open_fds(&[])?;
    validate_private_workload_loopback()?;
    validate_udp_mtu_and_fragments()?;
    let host_ipv4_port = parse_probe_port(2)?;
    let host_ipv6_port = parse_probe_port(3)?;
    let host_udp_ipv4_port = parse_probe_port(4)?;
    let host_udp_ipv6_port = parse_probe_port(5)?;
    let timeout = Duration::from_secs(5);
    for (destination, expected) in [("198.51.100.42:443", 1_u8), ("[2001:db8::42]:443", 2_u8)] {
        let address = destination.parse().map_err(invalid_input)?;
        let mut stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.write_all(b"GET / HTTP/1.1\r\nHost: transparent.test\r\n\r\n")?;
        let mut actual = [0_u8; 1];
        stream.read_exact(&mut actual)?;
        if actual != [expected] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("transparent probe returned {actual:?} for {destination}"),
            ));
        }
    }

    for (port, family, family_name) in [
        (host_ipv4_port, IpFamily::Ipv4, "IPv4"),
        (host_ipv6_port, IpFamily::Ipv6, "IPv6"),
    ] {
        let destination = ("host.hiloop.internal", port)
            .to_socket_addrs()?
            .find(|address| match family {
                IpFamily::Ipv4 => address.is_ipv4(),
                IpFamily::Ipv6 => address.is_ipv6(),
            })
            .ok_or_else(|| {
                io::Error::other(format!("host.hiloop.internal has no {family_name} mapping"))
            })?;
        let mut stream = TcpStream::connect_timeout(&destination, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.write_all(b"ping")?;
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response)?;
        if response != *b"pong" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{family_name} host loopback fixture returned an unexpected payload"),
            ));
        }
    }
    for (bind, destination, family_name) in [
        (
            "0.0.0.0:0",
            format!("{HOST_LOOPBACK_IPV4}:{host_udp_ipv4_port}"),
            "IPv4",
        ),
        (
            "[::]:0",
            format!("[{HOST_LOOPBACK_IPV6}]:{host_udp_ipv6_port}"),
            "IPv6",
        ),
    ] {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.connect(destination)?;
        if socket.send(b"ping")? != 4 {
            return Err(io::Error::other(format!(
                "{family_name} UDP request was partially sent"
            )));
        }
        let mut response = [0_u8; 4];
        if socket.recv(&mut response)? != response.len() || response != *b"pong" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{family_name} UDP relay returned an unexpected payload"),
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "test-support")]
fn validate_private_workload_loopback() -> io::Result<()> {
    use std::net::TcpListener;

    let ipv4 = TcpListener::bind("127.0.0.1:0")?;
    let ipv6 = TcpListener::bind("[::1]:0")?;
    let mut descendant = Command::new(std::env::current_exe()?)
        .arg(LOOPBACK_DESCENDANT_PROBE_ROLE)
        .arg(ipv4.local_addr()?.port().to_string())
        .arg(ipv6.local_addr()?.port().to_string())
        .spawn()?;
    for (listener, expected) in [(&ipv4, *b"ipv4"), (&ipv6, *b"ipv6")] {
        let (mut connection, _) = listener.accept()?;
        let mut payload = [0_u8; 4];
        connection.read_exact(&mut payload)?;
        if payload != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "workload descendant returned an invalid loopback probe",
            ));
        }
    }
    let status = descendant.wait()?;
    require_success("workload loopback descendant", status, &[])
}

#[cfg(feature = "test-support")]
fn loopback_descendant_probe_entrypoint() -> io::Result<ExitCode> {
    use std::net::TcpStream;

    require_empty_capabilities()?;
    require_only_open_fds(&[])?;
    let ipv4_port = parse_probe_port(2)?;
    let ipv6_port = parse_probe_port(3)?;
    let mut ipv4 = TcpStream::connect((Ipv4Addr::LOCALHOST, ipv4_port))?;
    ipv4.write_all(b"ipv4")?;
    let mut ipv6 = TcpStream::connect((Ipv6Addr::LOCALHOST, ipv6_port))?;
    ipv6.write_all(b"ipv6")?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "test-support")]
#[expect(
    unsafe_code,
    reason = "the single-threaded workload probe forks a detached descendant to test PID-namespace teardown; see SAFETY"
)]
fn detached_workload_probe_entrypoint() -> io::Result<ExitCode> {
    require_empty_capabilities()?;
    require_only_open_fds(&[])?;
    let pid_path = std::env::args_os()
        .nth(2)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing descendant PID path")
        })?;

    // SAFETY: this helper is single-threaded. The descendant performs only isolated test setup;
    // every process remains inside the owned PID namespace and is killed by gateway teardown.
    let first = unsafe { libc::fork() };
    if first == -1 {
        return Err(io::Error::last_os_error());
    }
    if first == 0 {
        if unsafe { libc::setsid() } == -1 {
            unsafe { libc::_exit(111) };
        }
        let second = unsafe { libc::fork() };
        if second == -1 {
            unsafe { libc::_exit(112) };
        }
        if second > 0 {
            unsafe { libc::_exit(0) };
        }
        if fs::write(&pid_path, current_pid().to_string()).is_err() {
            unsafe { libc::_exit(113) };
        }
        loop {
            raw_pause();
        }
    }

    let mut status = 0;
    if raw_waitpid(first, &mut status, 0) != first
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
    {
        return Err(io::Error::other("detached descendant launcher failed"));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !pid_path.exists() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "detached descendant did not record its PID",
            ));
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }
    loop {
        raw_pause();
    }
}

#[cfg(feature = "test-support")]
fn parse_probe_port(index: usize) -> io::Result<u16> {
    let value = std::env::args_os()
        .nth(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing probe port"))?;
    value
        .to_string_lossy()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn require_probe_destination(
    actual: std::net::SocketAddr,
    expected: std::net::SocketAddr,
) -> io::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("transparent destination was {actual}, expected {expected}"),
        ))
    }
}

#[cfg(feature = "test-support")]
fn parse_ipv4_address(value: &str) -> io::Result<std::net::IpAddr> {
    value
        .parse::<Ipv4Addr>()
        .map(std::net::IpAddr::V4)
        .map_err(invalid_input)
}

fn require_empty_capabilities() -> io::Result<()> {
    let capabilities = CapabilityStatus::read_current()?;
    if capabilities.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "helper retained capabilities: effective={:#x} permitted={:#x} inheritable={:#x} bounding={:#x} ambient={:#x}",
            capabilities.effective(),
            capabilities.permitted(),
            capabilities.inheritable(),
            capabilities.bounding(),
            capabilities.ambient()
        )))
    }
}

fn bind_mount_read_only(source: &Path, target: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes()).map_err(invalid_input)?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(invalid_input)?;
    raw_mount(
        Some(&source),
        &target,
        None,
        libc::MS_BIND,
        std::ptr::null(),
    )?;
    raw_mount(
        None,
        &target,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
        std::ptr::null(),
    )
}

fn mount_private_root() -> io::Result<()> {
    raw_mount(
        None,
        c"/",
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    )
}

fn mount_private_proc() -> io::Result<()> {
    raw_mount(Some(c"proc"), c"/proc", Some(c"proc"), 0, std::ptr::null())
}

fn duplicate_to(source: RawFd, target: RawFd) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "dup2/fcntl operate on validated scalar descriptors during child setup; see SAFETY"
    )]
    // SAFETY: both values are descriptor numbers. `dup2` atomically replaces the target and
    // `fcntl` clears CLOEXEC when source already equals target.
    unsafe {
        if source == target {
            let flags = libc::fcntl(target, libc::F_GETFD);
            if flags == -1 || libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(io::Error::last_os_error());
            }
        } else if libc::dup2(source, target) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "unshare takes one scalar namespace flag mask; see SAFETY"
)]
fn raw_unshare(flags: libc::c_int) -> io::Result<()> {
    // SAFETY: no pointer arguments; the helper is single-threaded when changing namespaces.
    cvt(unsafe { libc::unshare(flags) })
}

#[expect(
    unsafe_code,
    reason = "mount receives valid C strings and a null data pointer for fixed Linux mounts; see SAFETY"
)]
fn raw_mount(
    source: Option<&CStr>,
    target: &CStr,
    filesystem: Option<&CStr>,
    flags: libc::c_ulong,
    data: *const libc::c_void,
) -> io::Result<()> {
    // SAFETY: optional strings are NUL-terminated and live through the call; target is valid;
    // these operations pass no mount data, represented by a null pointer.
    cvt(unsafe {
        libc::mount(
            source.map_or(std::ptr::null(), CStr::as_ptr),
            target.as_ptr(),
            filesystem.map_or(std::ptr::null(), CStr::as_ptr),
            flags,
            data,
        )
    })
}

#[expect(
    unsafe_code,
    reason = "prctl is called with scalar parent-death controls only; see SAFETY"
)]
fn raw_prctl(option: libc::c_int, argument: libc::c_int) -> io::Result<()> {
    // SAFETY: both selected prctl operations use scalar integer arguments and no pointers.
    cvt(unsafe { libc::prctl(option, argument, 0, 0, 0) })
}

#[expect(
    unsafe_code,
    reason = "waitpid writes one status integer through a valid pointer; see SAFETY"
)]
fn raw_waitpid(pid: libc::pid_t, status: &mut libc::c_int, options: libc::c_int) -> libc::pid_t {
    // SAFETY: `status` is valid writable storage and the pointer is retained only for the call.
    unsafe { libc::waitpid(pid, std::ptr::from_mut(status), options) }
}

#[expect(
    unsafe_code,
    reason = "setresuid changes only the single-threaded helper's mapped credentials; see SAFETY"
)]
fn unsafe_setresuid(real: libc::uid_t, effective: libc::uid_t, saved: libc::uid_t) -> libc::c_int {
    // SAFETY: scalar mapped IDs; this helper has no other threads.
    unsafe { libc::setresuid(real, effective, saved) }
}

#[expect(
    unsafe_code,
    reason = "setresgid changes only the single-threaded helper's mapped credentials; see SAFETY"
)]
fn unsafe_setresgid(real: libc::gid_t, effective: libc::gid_t, saved: libc::gid_t) -> libc::c_int {
    // SAFETY: scalar mapped IDs; this helper has no other threads.
    unsafe { libc::setresgid(real, effective, saved) }
}

#[expect(
    unsafe_code,
    reason = "pause blocks the capability probe until the manager terminates it; see SAFETY"
)]
fn raw_pause() {
    // SAFETY: no arguments or memory access; EINTR simply resumes the loop.
    let _ = unsafe { libc::pause() };
}

#[expect(
    unsafe_code,
    reason = "getppid returns one scalar process identifier; see SAFETY"
)]
fn parent_pid() -> libc::pid_t {
    // SAFETY: no arguments or memory access.
    unsafe { libc::getppid() }
}

#[expect(
    unsafe_code,
    reason = "getpid returns one scalar process identifier; see SAFETY"
)]
fn current_pid() -> libc::pid_t {
    // SAFETY: no arguments or memory access.
    unsafe { libc::getpid() }
}

fn require_success(operation: &str, status: ExitStatus, stderr: &[u8]) -> io::Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation} exited {status}: {}",
            String::from_utf8_lossy(stderr).trim()
        )))
    }
}

fn substrate_exit_from_wait_status(status: libc::c_int) -> SubstrateExit {
    if libc::WIFEXITED(status) {
        SubstrateExit::Code(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        SubstrateExit::Signal(
            crate::netns::LinuxSignal::new(libc::WTERMSIG(status))
                .expect("Linux wait status contains a valid signal number"),
        )
    } else {
        SubstrateExit::Code(1)
    }
}

fn exit_code_from_wait_status(status: libc::c_int) -> ExitCode {
    exit_code_for_substrate(substrate_exit_from_wait_status(status))
}

fn exit_code_for_substrate(exit: SubstrateExit) -> ExitCode {
    let code = match exit {
        SubstrateExit::Code(code) => code.clamp(0, 255),
        SubstrateExit::Signal(signal) => (128 + signal.get()).clamp(0, 255),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn pid_u32(pid: libc::pid_t) -> Result<u32, ManagerFailure> {
    u32::try_from(pid).map_err(|error| {
        ManagerFailure::new(
            StartupStage::Namespace,
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })
}

fn parse_ipv4(value: &str) -> Result<Ipv4Addr, ManagerFailure> {
    value.parse().map_err(|error| {
        ManagerFailure::new(
            StartupStage::Namespace,
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })
}

fn parse_ipv6(value: &str) -> Result<Ipv6Addr, ManagerFailure> {
    value.parse().map_err(|error| {
        ManagerFailure::new(
            StartupStage::Namespace,
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })
}

fn protocol_order(expected: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, expected)
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
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;

    #[test]
    fn generated_hosts_replaces_conflicts_and_preserves_unrelated_aliases() {
        let contents = generated_hosts(
            b"127.0.0.1 localhost\n192.0.2.1 old host.hiloop.internal # conflict\n::1 host.hiloop.internal\n",
        );
        let contents = String::from_utf8(contents).expect("generated hosts is UTF-8");
        assert!(contents.contains("127.0.0.1 localhost\n"));
        assert!(contents.contains("192.0.2.1 old # conflict\n"));
        assert!(!contents.contains("192.0.2.1 old host.hiloop.internal"));
        assert!(!contents.contains("::1 host.hiloop.internal"));
        assert_eq!(
            contents.matches("host.hiloop.internal").count(),
            2,
            "only canonical v4/v6 aliases remain"
        );
    }

    #[test]
    fn wait_status_preserves_codes_and_signals() {
        let normal = ExitStatus::from_raw(23 << 8);
        assert_eq!(
            substrate_exit_from_wait_status(normal.into_raw()),
            SubstrateExit::Code(23)
        );
        let signaled = ExitStatus::from_raw(libc::SIGTERM);
        assert_eq!(
            substrate_exit_from_wait_status(signaled.into_raw()),
            SubstrateExit::Signal(
                crate::netns::LinuxSignal::new(libc::SIGTERM).expect("valid test signal")
            )
        );
    }

    #[test]
    fn teardown_plan_closes_veth_before_any_other_resource() {
        let plan = RoutingPlan::new(9, NonZeroU16::new(15_001).expect("test port is nonzero"));
        let first = plan.teardown_commands().first().expect("teardown command");
        assert_eq!(first.command().program(), "ip");
        assert_eq!(
            first.command().arguments(),
            ["link", "delete", "dev", "hlgate0"]
        );
    }

    #[test]
    fn worker_failure_wins_when_worker_and_workload_exit_together() {
        let exits = [(10, SubstrateExit::Code(0)), (11, SubstrateExit::Code(23))];
        assert_eq!(
            terminal_from_reaped(&exits, 10, Some(11)),
            Some(TerminalState::WorkerFailed(SubstrateExit::Code(23)))
        );
    }

    #[test]
    fn udp_socket_broker_rejects_malformed_requests_without_opening_a_socket() {
        let (manager, worker) = UnixDatagram::pair().expect("broker pair");
        manager.set_nonblocking(true).expect("nonblocking manager");
        worker.send(b"malformed").expect("broker request");

        assert_eq!(
            service_gateway_control(&manager).expect("service malformed request"),
            None
        );

        let mut status = [0_u8; 1];
        assert_eq!(worker.recv(&mut status).expect("broker response"), 1);
        assert_eq!(status, [BROKER_STATUS_ERROR]);
    }

    #[test]
    fn gateway_fatal_report_preempts_further_broker_service() {
        use hiloop_core::capture::{CaptureFatalReason, OriginalDestination};

        let (manager, worker) = UnixDatagram::pair().expect("broker pair");
        manager.set_nonblocking(true).expect("nonblocking manager");
        let report = FatalReport::destination(
            CaptureFatalReason::SecretTransportUnsupported,
            OriginalDestination::new("203.0.113.10".parse().expect("test destination"), 443)
                .expect("valid destination"),
        );
        let frame =
            crate::netns::protocol::encode_gateway_fatal(&report).expect("encode gateway fatal");
        worker.send(&frame).expect("send gateway fatal");

        assert_eq!(
            service_gateway_control(&manager).expect("service gateway fatal"),
            Some(report)
        );
    }

    #[test]
    fn ipv6_gateway_setup_failures_keep_the_closed_ipv6_reason() {
        let plan = RoutingPlan::new(9, NonZeroU16::new(15_001).expect("test port is nonzero"));
        let (index, command) = plan
            .setup_commands()
            .iter()
            .filter(|command| command.namespace() == NetworkNamespace::Gateway)
            .enumerate()
            .find(|(_, command)| {
                command.command().arguments().first().map(String::as_str) == Some("-6")
            })
            .expect("IPv6 gateway command");

        assert_eq!(
            gateway_setup_failure(index, command),
            (
                StartupStage::Routing,
                CaptureTransportDegradationReason::Ipv6Unavailable,
            )
        );
    }

    #[test]
    fn ipv6_workload_setup_failures_keep_the_closed_ipv6_reason() {
        assert_eq!(
            workload_setup_reason(
                OsStr::new("ip"),
                &[OsString::from("-6"), OsString::from("route")]
            ),
            CaptureTransportDegradationReason::Ipv6Unavailable
        );
        assert_eq!(
            workload_setup_reason(
                OsStr::new("ip"),
                &[OsString::from("link"), OsString::from("set")]
            ),
            CaptureTransportDegradationReason::NetnsStartupFailed
        );
    }
}
