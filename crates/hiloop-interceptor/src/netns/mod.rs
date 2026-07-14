//! Rootless transparent-capture network substrate.

use std::{
    collections::BTreeMap,
    error::Error as StdError,
    ffi::{OsStr, OsString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use hiloop_core::capture::{CapturePreflight, CaptureTransportDegradationReason};
use thiserror::Error;

mod classifier;
mod dns;
mod dns_relay;
mod event_relay;
mod fatal;
#[cfg(target_os = "linux")]
mod gateway;
mod ingress;
#[cfg(target_os = "linux")]
mod listener;
#[cfg(target_os = "linux")]
mod manager;
#[cfg(target_os = "linux")]
mod pasta;
#[cfg(target_os = "linux")]
mod protocol;
#[cfg(target_os = "linux")]
mod resolver;
mod route;
#[cfg(target_os = "linux")]
mod routing;
mod run;
#[cfg(target_os = "linux")]
mod security;
mod system;
mod tls_policy;
mod tls_transport;
mod udp;
#[cfg(target_os = "linux")]
mod udp_broker;
#[cfg(target_os = "linux")]
mod udp_ingress;

pub use classifier::{
    ClassificationError, ClassificationProgress, ClientHelloIdentity, HttpIdentity, TcpProtocol,
    classify_tcp_prefix,
};
pub use dns::DnsAnswerTracker;
pub use dns_relay::{DNS_RELAY_SOCKET_ENV, DnsQueryTransport, DnsRelayClient, GatewayDnsRelay};
pub use fatal::{
    DataplaneClosed, DataplaneLatch, FatalReport, FatalRunError, FatalRunResult,
    FatalRunSupervisor, SupervisedRunError,
};
#[cfg(target_os = "linux")]
pub use fatal::{GatewayFatalController, GatewayFatalError};
pub use ingress::{
    AdmittedTcpFlow, ConnectedTcpFlow, DirectTcpConnector, IngressError, TcpUpstreamConnector,
    TransparentTcpIngress, connect_authorized, recover_original_destination,
};
#[cfg(target_os = "linux")]
pub use listener::{GatewayListeners, GatewayWorkerBootstrap};
pub use route::{
    AuthorizedRoute, DnsAnswerEvidence, NoDnsAnswerEvidence, RouteDenial, RoutingIdentitySource,
    authorize_route,
};
pub use run::{NetnsRun, NetworkCapture};
pub use system::SystemNetworkProvisioner;
pub use tls_policy::{
    HandshakeFailure, HandshakeFailureDecision, RequestAuthorityRejection, SecretRoute,
    TlsPolicyEngine, TlsPolicyFlow, TlsTransportDecision, TrustAlert,
};
pub use tls_transport::{
    TlsTransportError, classify_client_handshake_error, emit_interception_failure, raw_tcp_splice,
    raw_tls_splice,
};
pub use udp::{
    UdpChildDatagram, UdpChildSink, UdpFlowDisposition, UdpFlowKey, UdpFlowRelay, UdpFlowSummary,
    UdpRelayError, udp_flow_disposition,
};
#[cfg(target_os = "linux")]
pub use udp_ingress::{
    InterceptedUdpDatagram, TransparentUdpChildSink, TransparentUdpIngress, UdpIngressError,
};

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

/// Exact upstream pasta release accepted by the substrate.
pub const PINNED_PASTA_VERSION: &str = "2026_06_11.a9c61ff";

/// Result of exercising every transparent-capture primitive required by this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    result: CapturePreflight,
    ipv4_available: bool,
    ipv6_available: bool,
    degradation_reason: Option<CaptureTransportDegradationReason>,
    diagnostic: Option<String>,
}

impl PreflightReport {
    /// Report that every required primitive completed an actual-operation probe.
    ///
    /// IPv4 is a required substrate invariant and is therefore always available in a passing
    /// report; `ipv6_available` records whether the optional host IPv6 path was preserved.
    pub fn passed(ipv6_available: bool) -> Self {
        Self {
            result: CapturePreflight::Passed,
            ipv4_available: true,
            ipv6_available,
            degradation_reason: None,
            diagnostic: None,
        }
    }

    /// Report a closed startup reason without selecting a transport.
    pub fn failed(
        reason: CaptureTransportDegradationReason,
        diagnostic: impl Into<String>,
        ipv4_available: bool,
        ipv6_available: bool,
    ) -> Self {
        Self {
            result: CapturePreflight::Failed,
            ipv4_available,
            ipv6_available,
            degradation_reason: Some(reason),
            diagnostic: Some(diagnostic.into()),
        }
    }

    /// Typed preflight state for the `capture.transport` event.
    pub fn result(&self) -> CapturePreflight {
        self.result
    }

    /// Whether the host and isolated carrier both preserve IPv4 connectivity.
    pub fn ipv4_available(&self) -> bool {
        self.ipv4_available
    }

    /// Whether the host and isolated carrier both preserve IPv6 connectivity.
    pub fn ipv6_available(&self) -> bool {
        self.ipv6_available
    }

    /// Closed transport degradation reason when preflight failed.
    pub fn degradation_reason(&self) -> Option<CaptureTransportDegradationReason> {
        self.degradation_reason
    }

    /// Actionable local detail that must not be copied into telemetry attributes.
    pub fn diagnostic(&self) -> Option<&str> {
        self.diagnostic.as_deref()
    }
}

/// An argv-preserving command executed inside an isolated namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceCommand {
    program: OsString,
    args: Vec<OsString>,
    environment: BTreeMap<OsString, Option<OsString>>,
    current_dir: Option<PathBuf>,
}

impl NamespaceCommand {
    /// Create a command without invoking a shell.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            environment: BTreeMap::new(),
            current_dir: None,
        }
    }

    /// Append one literal argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append literal arguments in order.
    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set one child-only environment override.
    #[must_use]
    pub fn env(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.insert(name.into(), Some(value.into()));
        self
    }

    /// Remove one inherited environment variable from the child.
    #[must_use]
    pub fn env_remove(mut self, name: impl Into<OsString>) -> Self {
        self.environment.insert(name.into(), None);
        self
    }

    /// Select the child's working directory.
    #[must_use]
    pub fn current_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(path.into());
        self
    }

    /// Executable passed directly to `exec`.
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Literal argv entries after argv zero.
    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }

    /// Environment overrides, where `None` removes an inherited value.
    pub fn environment(&self) -> &BTreeMap<OsString, Option<OsString>> {
        &self.environment
    }

    /// Working directory override, if any.
    pub fn working_directory(&self) -> Option<&Path> {
        self.current_dir.as_deref()
    }
}

/// Everything needed to start one isolated transparent-capture substrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionRequest {
    workload: NamespaceCommand,
    gateway_worker: NamespaceCommand,
    intercept_port: Option<NonZeroU16>,
}

impl ProvisionRequest {
    /// Create a request whose required transparent worker receives an unused listener port.
    pub fn new(workload: NamespaceCommand, gateway_worker: NamespaceCommand) -> Self {
        Self {
            workload,
            gateway_worker,
            intercept_port: None,
        }
    }

    /// Request a fixed transparent-listener port, primarily for deterministic fixtures.
    #[must_use]
    pub fn with_intercept_port(mut self, port: NonZeroU16) -> Self {
        self.intercept_port = Some(port);
        self
    }

    /// Command executed in the workload network and mount namespaces.
    pub fn workload(&self) -> &NamespaceCommand {
        &self.workload
    }

    /// Required cap-free steady-state gateway process.
    pub fn gateway_worker(&self) -> &NamespaceCommand {
        &self.gateway_worker
    }

    /// Requested listener port, or `None` to allocate one inside the gateway namespace.
    pub fn intercept_port(&self) -> Option<NonZeroU16> {
        self.intercept_port
    }
}

/// Stable network facts handed from W2 to the gateway and later transport layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateInfo {
    intercept_port: NonZeroU16,
    mtu: u16,
    gateway_ipv4: Ipv4Addr,
    gateway_ipv6: Ipv6Addr,
    host_loopback_ipv4: Ipv4Addr,
    host_loopback_ipv6: Ipv6Addr,
    fragmented_udp: FragmentedUdpBehavior,
}

/// Carrier behavior for IP-fragmented UDP arriving from the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentedUdpBehavior {
    /// Fragments are rejected before pasta because the pinned carrier cannot forward them.
    Drop,
}

/// Minimum link MTU that can carry every valid IPv6 packet without invalid configuration.
pub const MIN_SUBSTRATE_MTU: u16 = 1_280;

/// Invalid stable network facts returned by a provisioner.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SubstrateInfoError {
    /// The configured link cannot satisfy IPv6's minimum MTU.
    #[error("substrate MTU {mtu} is smaller than the required minimum {MIN_SUBSTRATE_MTU}")]
    MtuTooSmall {
        /// Rejected link MTU.
        mtu: u16,
    },
    /// An infrastructure address cannot identify a routable endpoint.
    #[error("{field} address {address} must not be unspecified, loopback, or multicast")]
    InvalidAddress {
        /// Field containing the rejected address.
        field: &'static str,
        /// Rejected address.
        address: IpAddr,
    },
    /// Two infrastructure roles were assigned the same address.
    #[error("{first} and {second} must use distinct addresses, both were {address}")]
    DuplicateAddress {
        /// First conflicting field.
        first: &'static str,
        /// Second conflicting field.
        second: &'static str,
        /// Duplicated address.
        address: IpAddr,
    },
}

impl SubstrateInfo {
    /// Construct the validated facts returned by a provisioner implementation.
    pub fn new(
        intercept_port: NonZeroU16,
        mtu: u16,
        gateway_ipv4: Ipv4Addr,
        gateway_ipv6: Ipv6Addr,
        host_loopback_ipv4: Ipv4Addr,
        host_loopback_ipv6: Ipv6Addr,
        fragmented_udp: FragmentedUdpBehavior,
    ) -> Result<Self, SubstrateInfoError> {
        if mtu < MIN_SUBSTRATE_MTU {
            return Err(SubstrateInfoError::MtuTooSmall { mtu });
        }
        validate_substrate_address("gateway_ipv4", gateway_ipv4.into())?;
        validate_substrate_address("gateway_ipv6", gateway_ipv6.into())?;
        validate_substrate_address("host_loopback_ipv4", host_loopback_ipv4.into())?;
        validate_substrate_address("host_loopback_ipv6", host_loopback_ipv6.into())?;
        require_distinct_addresses(
            "gateway_ipv4",
            gateway_ipv4.into(),
            "host_loopback_ipv4",
            host_loopback_ipv4.into(),
        )?;
        require_distinct_addresses(
            "gateway_ipv6",
            gateway_ipv6.into(),
            "host_loopback_ipv6",
            host_loopback_ipv6.into(),
        )?;
        Ok(Self {
            intercept_port,
            mtu,
            gateway_ipv4,
            gateway_ipv6,
            host_loopback_ipv4,
            host_loopback_ipv6,
            fragmented_udp,
        })
    }

    /// Port receiving transparently redirected TCP for both address families.
    pub fn intercept_port(&self) -> NonZeroU16 {
        self.intercept_port
    }

    /// End-to-end carrier MTU enforced on the workload, veth, and pasta links.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Reserved gateway address visible to the workload over IPv4.
    pub fn gateway_ipv4(&self) -> Ipv4Addr {
        self.gateway_ipv4
    }

    /// Reserved gateway address visible to the workload over IPv6.
    pub fn gateway_ipv6(&self) -> Ipv6Addr {
        self.gateway_ipv6
    }

    /// Address mapped by pasta to host loopback over IPv4.
    pub fn host_loopback_ipv4(&self) -> Ipv4Addr {
        self.host_loopback_ipv4
    }

    /// Address mapped by pasta to host loopback over IPv6.
    pub fn host_loopback_ipv6(&self) -> Ipv6Addr {
        self.host_loopback_ipv6
    }

    /// Explicit fragmented-UDP posture consumed by the W6 relay and event layer.
    pub fn fragmented_udp_behavior(&self) -> FragmentedUdpBehavior {
        self.fragmented_udp
    }
}

fn validate_substrate_address(
    field: &'static str,
    address: IpAddr,
) -> Result<(), SubstrateInfoError> {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        Err(SubstrateInfoError::InvalidAddress { field, address })
    } else {
        Ok(())
    }
}

fn require_distinct_addresses(
    first: &'static str,
    first_address: IpAddr,
    second: &'static str,
    second_address: IpAddr,
) -> Result<(), SubstrateInfoError> {
    if first_address == second_address {
        Err(SubstrateInfoError::DuplicateAddress {
            first,
            second,
            address: first_address,
        })
    } else {
        Ok(())
    }
}

mod linux_signal {
    use thiserror::Error;

    const MAX_LINUX_SIGNAL: i32 = 64;

    /// Valid Linux signal number reported for an isolated workload.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxSignal(i32);

    impl LinuxSignal {
        /// Validate a raw Linux signal number.
        pub fn new(value: i32) -> Result<Self, InvalidLinuxSignal> {
            if (1..=MAX_LINUX_SIGNAL).contains(&value) {
                Ok(Self(value))
            } else {
                Err(InvalidLinuxSignal { value })
            }
        }

        /// Raw Linux signal number.
        pub fn get(self) -> i32 {
            self.0
        }
    }

    impl TryFrom<i32> for LinuxSignal {
        type Error = InvalidLinuxSignal;

        fn try_from(value: i32) -> Result<Self, Self::Error> {
            Self::new(value)
        }
    }

    impl From<LinuxSignal> for i32 {
        fn from(signal: LinuxSignal) -> Self {
            signal.get()
        }
    }

    /// A raw integer was not a Linux signal number.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
    #[error("invalid Linux signal number {value}; expected 1..={MAX_LINUX_SIGNAL}")]
    pub struct InvalidLinuxSignal {
        value: i32,
    }

    impl InvalidLinuxSignal {
        /// Rejected raw signal number.
        pub fn value(self) -> i32 {
            self.value
        }
    }
}

pub use linux_signal::{InvalidLinuxSignal, LinuxSignal};

/// Observable completion of the isolated workload PID namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstrateExit {
    /// The workload returned an ordinary process exit code.
    Code(i32),
    /// The workload was terminated by a Unix signal.
    Signal(LinuxSignal),
}

/// Lifecycle stage that failed before a usable substrate was returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupStage {
    /// Rootless carrier discovery or version validation.
    Pasta,
    /// Private namespace creation.
    Namespace,
    /// Workload-to-gateway link setup.
    Veth,
    /// Transparent listener, nftables, or policy routing.
    Routing,
    /// Gateway worker startup and readiness.
    GatewayWorker,
    /// Workload setup and execution.
    Workload,
}

impl std::fmt::Display for StartupStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Pasta => "pasta",
            Self::Namespace => "namespace",
            Self::Veth => "veth",
            Self::Routing => "routing",
            Self::GatewayWorker => "gateway_worker",
            Self::Workload => "workload",
        })
    }
}

/// Typed substrate startup, runtime, and cleanup failure.
#[derive(Debug, Error)]
pub enum ProvisionError {
    /// The host cannot provide the required transparent transport.
    #[error("transparent network substrate unavailable: {reason}: {diagnostic}")]
    Unavailable {
        /// Closed reason shared with `capture.transport`.
        reason: CaptureTransportDegradationReason,
        /// Local actionable context that is not an event attribute.
        diagnostic: String,
        /// Underlying local failure, when it remains available in this process.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
    /// A concrete startup stage failed after launch began.
    #[error("transparent network substrate {stage} startup failed ({reason}): {diagnostic}")]
    Startup {
        /// Stage whose partial state was torn down.
        stage: StartupStage,
        /// Closed preflight reason represented by this stage failure.
        reason: CaptureTransportDegradationReason,
        /// Actionable local context.
        diagnostic: String,
        /// Underlying local failure, when it remains available in this process.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
    /// A required helper exited after readiness.
    #[error("transparent network substrate dataplane failed: {component}: {diagnostic}")]
    Dataplane {
        /// Low-cardinality failing component name.
        component: &'static str,
        /// Actionable local context.
        diagnostic: String,
        /// Underlying local failure, when it remains available in this process.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
    /// Ordered teardown did not remove every owned resource.
    #[error("transparent network substrate cleanup failed: {diagnostic}")]
    Cleanup {
        /// Combined cleanup failures in execution order.
        diagnostic: String,
        /// Underlying local failure, when one primary failure remains available.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
    /// The gateway latched closed and completed namespace teardown for a typed fatal route.
    #[error("transparent network substrate failed fatally: {report:?}")]
    Fatal {
        /// Safe route metadata and the closed fatal reason.
        report: FatalReport,
        /// Ordered teardown failures reported after the fatal latch, when present.
        cleanup_diagnostic: Option<String>,
    },
}

impl ProvisionError {
    /// Preserve a gateway fatal report after its close-first teardown completes.
    pub fn fatal(report: FatalReport) -> Self {
        Self::Fatal {
            report,
            cleanup_diagnostic: None,
        }
    }

    /// Report that the host cannot provide the required transparent transport.
    pub fn unavailable(
        reason: CaptureTransportDegradationReason,
        diagnostic: impl Into<String>,
    ) -> Self {
        Self::Unavailable {
            reason,
            diagnostic: diagnostic.into(),
            source: None,
        }
    }

    /// Preserve a local source while reporting unavailable transparent transport.
    pub fn unavailable_with_source(
        reason: CaptureTransportDegradationReason,
        diagnostic: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Unavailable {
            reason,
            diagnostic: diagnostic.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Report a typed startup-stage failure after launch began.
    pub fn startup(
        stage: StartupStage,
        reason: CaptureTransportDegradationReason,
        diagnostic: impl Into<String>,
    ) -> Self {
        Self::Startup {
            stage,
            reason,
            diagnostic: diagnostic.into(),
            source: None,
        }
    }

    /// Preserve a local source while reporting a typed startup-stage failure.
    pub fn startup_with_source(
        stage: StartupStage,
        reason: CaptureTransportDegradationReason,
        diagnostic: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Startup {
            stage,
            reason,
            diagnostic: diagnostic.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Report failure of a required steady-state dataplane component.
    pub fn dataplane(component: &'static str, diagnostic: impl Into<String>) -> Self {
        Self::Dataplane {
            component,
            diagnostic: diagnostic.into(),
            source: None,
        }
    }

    /// Preserve a local source while reporting a steady-state dataplane failure.
    pub fn dataplane_with_source(
        component: &'static str,
        diagnostic: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Dataplane {
            component,
            diagnostic: diagnostic.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Report that ordered teardown could not remove every owned resource.
    pub fn cleanup(diagnostic: impl Into<String>) -> Self {
        Self::Cleanup {
            diagnostic: diagnostic.into(),
            source: None,
        }
    }

    /// Preserve one primary local source while reporting ordered teardown failure.
    pub fn cleanup_with_source(
        diagnostic: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Cleanup {
            diagnostic: diagnostic.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Live isolated topology supporting cancellation-safe wait followed by ordered shutdown.
#[async_trait]
pub trait NetworkSession: Send {
    /// Network facts needed by transparent ingress and DNS/UDP layers.
    fn info(&self) -> &SubstrateInfo;

    /// Wait for workload completion, then close the dataplane and reap helpers.
    ///
    /// Cancelling this future leaves the session available for [`Self::shutdown`].
    async fn wait(&mut self) -> Result<SubstrateExit, ProvisionError>;

    /// Close the dataplane, terminate the private PID namespace, and reap helpers.
    async fn shutdown(&mut self) -> Result<(), ProvisionError>;
}

/// Production seam shared by the real rootless substrate and its deterministic fake.
#[async_trait]
pub trait NetworkProvisioner: Send + Sync {
    /// Exercise and tear down every primitive needed by [`Self::provision`].
    async fn preflight(&self) -> PreflightReport;

    /// Start an isolated topology after a successful preflight.
    async fn provision(
        &self,
        request: ProvisionRequest,
    ) -> Result<Box<dyn NetworkSession>, ProvisionError>;
}

/// Run an internal namespace helper before an embedding binary constructs an async runtime.
///
/// Product binaries that use [`NetworkProvisioner`] must call this at process entry and return
/// the supplied result when it is `Some`. Ordinary invocations return `None`.
#[cfg(target_os = "linux")]
pub fn dispatch_internal_helper() -> Option<std::io::Result<std::process::ExitCode>> {
    manager::dispatch_from_args()
}

/// Transparent namespace helpers do not exist on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn dispatch_internal_helper() -> Option<std::io::Result<std::process::ExitCode>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_constructors_cannot_silently_degrade() {
        let passed = PreflightReport::passed(true);
        assert_eq!(passed.result(), CapturePreflight::Passed);
        assert!(passed.ipv4_available());
        assert!(passed.ipv6_available());
        assert_eq!(passed.degradation_reason(), None);
        assert_eq!(passed.diagnostic(), None);

        let failed = PreflightReport::failed(
            CaptureTransportDegradationReason::TunUnavailable,
            "/dev/net/tun could not create a TAP device",
            true,
            false,
        );
        assert_eq!(failed.result(), CapturePreflight::Failed);
        assert_eq!(
            failed.degradation_reason(),
            Some(CaptureTransportDegradationReason::TunUnavailable)
        );
        assert_eq!(
            failed.diagnostic(),
            Some("/dev/net/tun could not create a TAP device")
        );
    }

    #[test]
    fn namespace_command_preserves_argv_and_environment_intent() {
        let command = NamespaceCommand::new("sh")
            .args(["-c", "printf '%s' \"$VALUE\""])
            .env("VALUE", "literal value")
            .env_remove("HTTP_PROXY")
            .current_dir("/tmp");

        assert_eq!(command.program(), OsStr::new("sh"));
        assert_eq!(
            command.arguments(),
            [
                OsString::from("-c"),
                OsString::from("printf '%s' \"$VALUE\"")
            ]
        );
        assert_eq!(
            command.environment().get(OsStr::new("VALUE")),
            Some(&Some(OsString::from("literal value")))
        );
        assert_eq!(
            command.environment().get(OsStr::new("HTTP_PROXY")),
            Some(&None)
        );
        assert_eq!(command.working_directory(), Some(Path::new("/tmp")));
    }
}
