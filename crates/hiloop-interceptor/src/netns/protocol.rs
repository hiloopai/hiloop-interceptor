use std::{
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
    os::unix::ffi::{OsStrExt as _, OsStringExt as _},
    path::PathBuf,
};

use hiloop_core::capture::{
    CaptureFatalReason, CaptureTransportDegradationReason, OriginalDestination, TlsFlowIdentity,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::{
    FatalReport, FragmentedUdpBehavior, NamespaceCommand, ProvisionRequest, StartupStage,
    SubstrateExit, SubstrateInfo, fatal::FatalRoute,
};

const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub(super) const MAX_GATEWAY_CONTROL_BYTES: usize = 4 * 1024;
const GATEWAY_FATAL_VERSION: u8 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum SupervisorMessage {
    IdMapsInstalled,
    PastaReady,
    Configure(Box<WireProvisionRequest>),
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum ManagerMessage {
    UserNamespaceReady,
    GatewayNamespaceReady {
        pid: u32,
    },
    Ready(WireSubstrateInfo),
    WorkloadExited(WireExit),
    Failed {
        stage: WireStartupStage,
        reason: WireDegradationReason,
        diagnostic: String,
    },
    Fatal(WireFatalReport),
    CleanupComplete {
        failures: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireFatalReport {
    reason: WireFatalReason,
    route: WireFatalRoute,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum WireFatalReason {
    SecretBindUnterminatable,
    SecretRouteAmbiguous,
    SecretDestinationMismatch,
    SecretPassthroughForbidden,
    SecretRouteIdentityMismatch,
    SecretTransportInsecure,
    SecretTransportUnsupported,
    DataplaneFailed,
}

#[derive(Debug, Serialize, Deserialize)]
enum WireFatalRoute {
    None,
    Tls {
        destination: WireDestination,
        server_name: Option<String>,
        client_hello_fingerprint: Option<String>,
    },
    Destination(WireDestination),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct WireDestination {
    ip: IpAddr,
    port: u16,
}

impl From<&FatalReport> for WireFatalReport {
    fn from(report: &FatalReport) -> Self {
        let route = match report.route() {
            FatalRoute::None => WireFatalRoute::None,
            FatalRoute::Tls(flow) => WireFatalRoute::Tls {
                destination: WireDestination::from(flow.destination()),
                server_name: flow.server_name().map(str::to_owned),
                client_hello_fingerprint: flow.client_hello_fingerprint().map(str::to_owned),
            },
            FatalRoute::Destination(destination) => {
                WireFatalRoute::Destination(WireDestination::from(*destination))
            }
        };
        Self {
            reason: WireFatalReason::from(report.reason()),
            route,
        }
    }
}

impl TryFrom<WireFatalReport> for FatalReport {
    type Error = io::Error;

    fn try_from(report: WireFatalReport) -> Result<Self, Self::Error> {
        let reason = CaptureFatalReason::from(report.reason);
        let route = match report.route {
            WireFatalRoute::None => FatalRoute::None,
            WireFatalRoute::Destination(destination) => {
                FatalRoute::Destination(destination.try_into()?)
            }
            WireFatalRoute::Tls {
                destination,
                server_name,
                client_hello_fingerprint,
            } => {
                let mut flow = TlsFlowIdentity::new(destination.try_into()?);
                if let Some(server_name) = server_name {
                    flow = flow.with_server_name(server_name).map_err(invalid_data)?;
                }
                if let Some(fingerprint) = client_hello_fingerprint {
                    flow = flow
                        .with_client_hello_fingerprint(fingerprint)
                        .map_err(invalid_data)?;
                }
                FatalRoute::Tls(flow)
            }
        };
        Ok(FatalReport::from_route(reason, route))
    }
}

impl From<OriginalDestination> for WireDestination {
    fn from(destination: OriginalDestination) -> Self {
        Self {
            ip: destination.ip(),
            port: destination.port(),
        }
    }
}

impl TryFrom<WireDestination> for OriginalDestination {
    type Error = io::Error;

    fn try_from(destination: WireDestination) -> Result<Self, Self::Error> {
        Self::new(destination.ip, destination.port).map_err(invalid_data)
    }
}

impl From<CaptureFatalReason> for WireFatalReason {
    fn from(reason: CaptureFatalReason) -> Self {
        match reason {
            CaptureFatalReason::SecretBindUnterminatable => Self::SecretBindUnterminatable,
            CaptureFatalReason::SecretRouteAmbiguous => Self::SecretRouteAmbiguous,
            CaptureFatalReason::SecretDestinationMismatch => Self::SecretDestinationMismatch,
            CaptureFatalReason::SecretPassthroughForbidden => Self::SecretPassthroughForbidden,
            CaptureFatalReason::SecretRouteIdentityMismatch => Self::SecretRouteIdentityMismatch,
            CaptureFatalReason::SecretTransportInsecure => Self::SecretTransportInsecure,
            CaptureFatalReason::SecretTransportUnsupported => Self::SecretTransportUnsupported,
            CaptureFatalReason::DataplaneFailed => Self::DataplaneFailed,
        }
    }
}

impl From<WireFatalReason> for CaptureFatalReason {
    fn from(reason: WireFatalReason) -> Self {
        match reason {
            WireFatalReason::SecretBindUnterminatable => Self::SecretBindUnterminatable,
            WireFatalReason::SecretRouteAmbiguous => Self::SecretRouteAmbiguous,
            WireFatalReason::SecretDestinationMismatch => Self::SecretDestinationMismatch,
            WireFatalReason::SecretPassthroughForbidden => Self::SecretPassthroughForbidden,
            WireFatalReason::SecretRouteIdentityMismatch => Self::SecretRouteIdentityMismatch,
            WireFatalReason::SecretTransportInsecure => Self::SecretTransportInsecure,
            WireFatalReason::SecretTransportUnsupported => Self::SecretTransportUnsupported,
            WireFatalReason::DataplaneFailed => Self::DataplaneFailed,
        }
    }
}

pub(super) fn encode_gateway_fatal(report: &FatalReport) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(&WireFatalReport::from(report)).map_err(invalid_data)?;
    let mut frame = Vec::with_capacity(payload.len() + 1);
    frame.push(GATEWAY_FATAL_VERSION);
    frame.extend_from_slice(&payload);
    if frame.len() > MAX_GATEWAY_CONTROL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway fatal report exceeds the private control datagram limit",
        ));
    }
    Ok(frame)
}

pub(super) fn decode_gateway_fatal(frame: &[u8]) -> io::Result<Option<FatalReport>> {
    let Some((&version, payload)) = frame.split_first() else {
        return Ok(None);
    };
    if version != GATEWAY_FATAL_VERSION {
        return Ok(None);
    }
    let report = serde_json::from_slice::<WireFatalReport>(payload).map_err(invalid_data)?;
    report.try_into().map(Some)
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum WorkloadMessage {
    Configure {
        commands: Vec<WireExecCommand>,
        hosts_path: Vec<u8>,
        resolv_path: Vec<u8>,
    },
    Start(WireCommand),
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireExecCommand {
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
}

impl WireExecCommand {
    pub(super) fn new(program: &OsStr, args: impl IntoIterator<Item = OsString>) -> Self {
        Self {
            program: program.as_bytes().to_vec(),
            args: args
                .into_iter()
                .map(std::os::unix::ffi::OsStringExt::into_vec)
                .collect(),
        }
    }

    pub(super) fn into_parts(self) -> (OsString, Vec<OsString>) {
        (
            OsString::from_vec(self.program),
            self.args.into_iter().map(OsString::from_vec).collect(),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum WorkloadReply {
    Ready,
    ExecFailed {
        diagnostic: String,
    },
    Failed {
        reason: WireDegradationReason,
        diagnostic: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) enum WireDegradationReason {
    UnsupportedPlatform,
    UserNamespaceDenied,
    TproxyUnavailable,
    TunUnavailable,
    PastaMissing,
    Ipv6Unavailable,
    ResolverUnavailable,
    NetnsStartupFailed,
}

impl From<CaptureTransportDegradationReason> for WireDegradationReason {
    fn from(reason: CaptureTransportDegradationReason) -> Self {
        match reason {
            CaptureTransportDegradationReason::UnsupportedPlatform => Self::UnsupportedPlatform,
            CaptureTransportDegradationReason::UserNamespaceDenied => Self::UserNamespaceDenied,
            CaptureTransportDegradationReason::TproxyUnavailable => Self::TproxyUnavailable,
            CaptureTransportDegradationReason::TunUnavailable => Self::TunUnavailable,
            CaptureTransportDegradationReason::PastaMissing => Self::PastaMissing,
            CaptureTransportDegradationReason::Ipv6Unavailable => Self::Ipv6Unavailable,
            CaptureTransportDegradationReason::ResolverUnavailable => Self::ResolverUnavailable,
            CaptureTransportDegradationReason::NetnsStartupFailed => Self::NetnsStartupFailed,
        }
    }
}

impl From<WireDegradationReason> for CaptureTransportDegradationReason {
    fn from(reason: WireDegradationReason) -> Self {
        match reason {
            WireDegradationReason::UnsupportedPlatform => Self::UnsupportedPlatform,
            WireDegradationReason::UserNamespaceDenied => Self::UserNamespaceDenied,
            WireDegradationReason::TproxyUnavailable => Self::TproxyUnavailable,
            WireDegradationReason::TunUnavailable => Self::TunUnavailable,
            WireDegradationReason::PastaMissing => Self::PastaMissing,
            WireDegradationReason::Ipv6Unavailable => Self::Ipv6Unavailable,
            WireDegradationReason::ResolverUnavailable => Self::ResolverUnavailable,
            WireDegradationReason::NetnsStartupFailed => Self::NetnsStartupFailed,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireProvisionRequest {
    workload: WireCommand,
    gateway_worker: WireCommand,
    intercept_port: Option<u16>,
    require_ipv6: bool,
    validate_dataplane: bool,
    resolv_conf: Vec<u8>,
}

impl WireProvisionRequest {
    pub(super) fn from_request(
        request: &ProvisionRequest,
        require_ipv6: bool,
        validate_dataplane: bool,
        resolv_conf: &[u8],
    ) -> Self {
        Self {
            workload: WireCommand::from(request.workload()),
            gateway_worker: WireCommand::from(request.gateway_worker()),
            intercept_port: request.intercept_port().map(NonZeroU16::get),
            require_ipv6,
            validate_dataplane,
            resolv_conf: resolv_conf.to_vec(),
        }
    }

    pub(super) fn into_parts(self) -> io::Result<WireProvisionParts> {
        let port = self
            .intercept_port
            .map(|port| {
                NonZeroU16::new(port).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "intercept port must be nonzero")
                })
            })
            .transpose()?;
        Ok(WireProvisionParts {
            workload: self.workload,
            gateway_worker: self.gateway_worker,
            port,
            require_ipv6: self.require_ipv6,
            validate_dataplane: self.validate_dataplane,
            resolv_conf: self.resolv_conf,
        })
    }
}

pub(super) struct WireProvisionParts {
    pub(super) workload: WireCommand,
    pub(super) gateway_worker: WireCommand,
    pub(super) port: Option<NonZeroU16>,
    pub(super) require_ipv6: bool,
    pub(super) validate_dataplane: bool,
    pub(super) resolv_conf: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireCommand {
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
    environment: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    current_dir: Option<Vec<u8>>,
}

impl From<&NamespaceCommand> for WireCommand {
    fn from(command: &NamespaceCommand) -> Self {
        Self {
            program: command.program().as_bytes().to_vec(),
            args: command
                .arguments()
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
            environment: command
                .environment()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_bytes().to_vec(),
                        value.as_ref().map(|value| value.as_bytes().to_vec()),
                    )
                })
                .collect(),
            current_dir: command
                .working_directory()
                .map(|path| path.as_os_str().as_bytes().to_vec()),
        }
    }
}

impl WireCommand {
    pub(super) fn into_command(self) -> NamespaceCommand {
        let mut command = NamespaceCommand::new(OsString::from_vec(self.program));
        command = command.args(self.args.into_iter().map(OsString::from_vec));
        for (name, value) in self.environment {
            let name = OsString::from_vec(name);
            command = match value {
                Some(value) => command.env(name, OsString::from_vec(value)),
                None => command.env_remove(name),
            };
        }
        if let Some(current_dir) = self.current_dir {
            command = command.current_dir(PathBuf::from(OsString::from_vec(current_dir)));
        }
        command
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireSubstrateInfo {
    intercept_port: u16,
    mtu: u16,
    gateway_ipv4: Ipv4Addr,
    gateway_ipv6: Ipv6Addr,
    host_loopback_ipv4: Ipv4Addr,
    host_loopback_ipv6: Ipv6Addr,
}

impl From<&SubstrateInfo> for WireSubstrateInfo {
    fn from(info: &SubstrateInfo) -> Self {
        Self {
            intercept_port: info.intercept_port().get(),
            mtu: info.mtu(),
            gateway_ipv4: info.gateway_ipv4(),
            gateway_ipv6: info.gateway_ipv6(),
            host_loopback_ipv4: info.host_loopback_ipv4(),
            host_loopback_ipv6: info.host_loopback_ipv6(),
        }
    }
}

impl TryFrom<WireSubstrateInfo> for SubstrateInfo {
    type Error = io::Error;

    fn try_from(info: WireSubstrateInfo) -> Result<Self, Self::Error> {
        let intercept_port = NonZeroU16::new(info.intercept_port).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "manager returned port zero")
        })?;
        Self::new(
            intercept_port,
            info.mtu,
            info.gateway_ipv4,
            info.gateway_ipv6,
            info.host_loopback_ipv4,
            info.host_loopback_ipv6,
            FragmentedUdpBehavior::Drop,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum WireExit {
    Code(i32),
    Signal(i32),
}

impl From<SubstrateExit> for WireExit {
    fn from(exit: SubstrateExit) -> Self {
        match exit {
            SubstrateExit::Code(code) => Self::Code(code),
            SubstrateExit::Signal(signal) => Self::Signal(signal.get()),
        }
    }
}

impl TryFrom<WireExit> for SubstrateExit {
    type Error = io::Error;

    fn try_from(exit: WireExit) -> Result<Self, Self::Error> {
        match exit {
            WireExit::Code(code) => Ok(Self::Code(code)),
            WireExit::Signal(signal) => crate::netns::LinuxSignal::new(signal)
                .map(Self::Signal)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum WireStartupStage {
    Pasta,
    Namespace,
    Veth,
    Routing,
    GatewayWorker,
    Workload,
}

impl From<StartupStage> for WireStartupStage {
    fn from(stage: StartupStage) -> Self {
        match stage {
            StartupStage::Pasta => Self::Pasta,
            StartupStage::Namespace => Self::Namespace,
            StartupStage::Veth => Self::Veth,
            StartupStage::Routing => Self::Routing,
            StartupStage::GatewayWorker => Self::GatewayWorker,
            StartupStage::Workload => Self::Workload,
        }
    }
}

impl From<WireStartupStage> for StartupStage {
    fn from(stage: WireStartupStage) -> Self {
        match stage {
            WireStartupStage::Pasta => Self::Pasta,
            WireStartupStage::Namespace => Self::Namespace,
            WireStartupStage::Veth => Self::Veth,
            WireStartupStage::Routing => Self::Routing,
            WireStartupStage::GatewayWorker => Self::GatewayWorker,
            WireStartupStage::Workload => Self::Workload,
        }
    }
}

pub(super) fn send_sync<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(invalid_data)?;
    let length = checked_length(payload.len())?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

pub(super) fn receive_sync<T: DeserializeOwned>(reader: &mut impl Read) -> io::Result<T> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = frame_length(length)?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(invalid_data)
}

pub(super) async fn send_async<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(invalid_data)?;
    let length = checked_length(payload.len())?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

pub(super) async fn receive_async<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<T> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let length = frame_length(length)?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(invalid_data)
}

fn checked_length(length: usize) -> io::Result<u32> {
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "namespace control frame exceeds 1 MiB",
        ));
    }
    u32::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "control frame is too large"))
}

fn frame_length(bytes: [u8; 4]) -> io::Result<usize> {
    let length = usize::try_from(u32::from_be_bytes(bytes)).map_err(invalid_data)?;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "namespace control frame exceeds 1 MiB",
        ));
    }
    Ok(length)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_round_trip_preserves_non_utf8_argv() {
        let command = NamespaceCommand::new(OsString::from_vec(vec![b'f', 0x80]))
            .arg(OsString::from_vec(vec![b'a', 0xff]))
            .env(
                OsString::from_vec(vec![b'K', 0xfe]),
                OsString::from_vec(vec![0xfd]),
            )
            .env_remove("REMOVE_ME")
            .current_dir(PathBuf::from(OsString::from_vec(vec![b'/', b't', 0xfc])));
        let wire = WireCommand::from(&command);
        let bytes = serde_json::to_vec(&wire).expect("serialize command");
        let decoded: WireCommand = serde_json::from_slice(&bytes).expect("deserialize command");

        assert_eq!(decoded.into_command(), command);
    }

    #[test]
    fn sync_framing_round_trips_and_rejects_oversize_input() {
        let message = ManagerMessage::GatewayNamespaceReady { pid: 42 };
        let mut bytes = Vec::new();
        send_sync(&mut bytes, &message).expect("frame message");
        let decoded: ManagerMessage = receive_sync(&mut bytes.as_slice()).expect("read message");
        assert!(matches!(
            decoded,
            ManagerMessage::GatewayNamespaceReady { pid: 42 }
        ));

        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .expect("test limit fits u32")
            .to_be_bytes();
        let error = receive_sync::<ManagerMessage>(&mut oversized.as_slice())
            .expect_err("oversized frame must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn manager_failure_preserves_closed_degradation_reason_on_the_wire() {
        let message = ManagerMessage::Failed {
            stage: WireStartupStage::Pasta,
            reason: WireDegradationReason::Ipv6Unavailable,
            diagnostic: "carrier installed no IPv6 route".to_owned(),
        };
        let mut bytes = Vec::new();
        send_sync(&mut bytes, &message).expect("frame typed failure");
        let decoded: ManagerMessage =
            receive_sync(&mut bytes.as_slice()).expect("read typed failure");
        assert!(matches!(
            decoded,
            ManagerMessage::Failed {
                stage: WireStartupStage::Pasta,
                reason: WireDegradationReason::Ipv6Unavailable,
                ..
            }
        ));
    }

    #[test]
    fn gateway_fatal_wire_round_trips_every_closed_reason_and_route_shape() {
        let destination =
            OriginalDestination::new("203.0.113.10".parse().expect("test destination"), 443)
                .expect("valid destination");
        let flow = TlsFlowIdentity::new(destination)
            .with_server_name("api.example.com")
            .expect("test SNI")
            .with_client_hello_fingerprint("ja4:test")
            .expect("test fingerprint");
        for reason in [
            CaptureFatalReason::SecretBindUnterminatable,
            CaptureFatalReason::SecretRouteAmbiguous,
            CaptureFatalReason::SecretDestinationMismatch,
            CaptureFatalReason::SecretPassthroughForbidden,
            CaptureFatalReason::SecretRouteIdentityMismatch,
            CaptureFatalReason::SecretTransportInsecure,
            CaptureFatalReason::SecretTransportUnsupported,
            CaptureFatalReason::DataplaneFailed,
        ] {
            for report in [
                FatalReport::without_route(reason),
                FatalReport::destination(reason, destination),
                FatalReport::tls(reason, flow.clone()),
            ] {
                let encoded = encode_gateway_fatal(&report).expect("encode fatal report");
                assert!(encoded.len() <= MAX_GATEWAY_CONTROL_BYTES);
                assert_eq!(
                    decode_gateway_fatal(&encoded).expect("decode fatal report"),
                    Some(report)
                );
            }
        }
    }
}
