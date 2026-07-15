use std::{path::PathBuf, time::Duration};

use async_trait::async_trait;
#[cfg(not(target_os = "linux"))]
use hiloop_core::capture::CaptureTransportDegradationReason;

use super::{
    NetworkProvisioner, NetworkSession, PreflightReport, ProvisionError, ProvisionRequest,
};

/// Host-backed transparent network provisioner.
#[derive(Debug, Clone)]
pub struct SystemNetworkProvisioner {
    pasta_path: PathBuf,
    helper_path: PathBuf,
    startup_timeout: Duration,
    resolver_timeout: Duration,
    #[cfg(feature = "test-support")]
    forced_host_ip_families: Option<(bool, bool)>,
}

impl SystemNetworkProvisioner {
    /// Use an explicit version-pinned pasta executable and the current binary as helper.
    pub fn new(pasta_path: impl Into<PathBuf>) -> std::io::Result<Self> {
        Ok(Self {
            pasta_path: pasta_path.into(),
            helper_path: std::env::current_exe()?,
            startup_timeout: Duration::from_secs(10),
            resolver_timeout: Duration::from_secs(2),
            #[cfg(feature = "test-support")]
            forced_host_ip_families: None,
        })
    }

    /// Select a binary that dispatches [`super::dispatch_internal_helper`] at process entry.
    #[must_use]
    pub fn with_helper_executable(mut self, helper_path: impl Into<PathBuf>) -> Self {
        self.helper_path = helper_path.into();
        self
    }

    /// Bound startup and resolver probes independently.
    #[must_use]
    pub fn with_timeouts(mut self, startup: Duration, resolver: Duration) -> Self {
        self.startup_timeout = startup;
        self.resolver_timeout = resolver;
        self
    }

    /// Version-pinned carrier executable used for every run.
    pub fn pasta_path(&self) -> &std::path::Path {
        &self.pasta_path
    }

    /// Re-exec helper used to create namespace-scoped processes.
    pub fn helper_path(&self) -> &std::path::Path {
        &self.helper_path
    }

    #[cfg(feature = "test-support")]
    pub(super) fn force_ipv4_only(mut self) -> Self {
        self.forced_host_ip_families = Some((true, false));
        self
    }

    #[cfg(feature = "test-support")]
    pub(super) fn force_dual_stack(mut self) -> Self {
        self.forced_host_ip_families = Some((true, true));
        self
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl NetworkProvisioner for SystemNetworkProvisioner {
    async fn preflight(&self) -> PreflightReport {
        linux::preflight(self).await
    }

    async fn provision(
        &self,
        request: ProvisionRequest,
    ) -> Result<Box<dyn NetworkSession>, ProvisionError> {
        linux::provision(self, request).await
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl NetworkProvisioner for SystemNetworkProvisioner {
    async fn preflight(&self) -> PreflightReport {
        PreflightReport::failed(
            CaptureTransportDegradationReason::UnsupportedPlatform,
            "transparent network namespaces are available only on Linux",
            false,
            false,
        )
    }

    async fn provision(
        &self,
        _request: ProvisionRequest,
    ) -> Result<Box<dyn NetworkSession>, ProvisionError> {
        Err(ProvisionError::unavailable(
            CaptureTransportDegradationReason::UnsupportedPlatform,
            "transparent network namespaces are available only on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs, io,
        net::UdpSocket,
        os::{
            fd::AsRawFd as _,
            unix::{fs::PermissionsExt as _, net::UnixStream as StdUnixStream},
        },
        path::{Path, PathBuf},
        process::{ExitStatus, Stdio},
        time::{Duration, Instant},
    };

    use async_trait::async_trait;
    use hiloop_core::capture::CaptureTransportDegradationReason;
    use nix::libc;
    use tokio::{
        io::{AsyncRead, AsyncReadExt as _},
        net::{
            UnixStream,
            unix::{OwnedReadHalf, OwnedWriteHalf},
        },
        process::{Child, Command},
        sync::mpsc,
        task::JoinHandle,
        time,
    };

    use super::SystemNetworkProvisioner;
    use crate::netns::{
        NetworkSession, PreflightReport, ProvisionError, ProvisionRequest, StartupStage,
        SubstrateExit, SubstrateInfo,
        dns_relay::{HostDnsRelay, relay_socket_environment},
        manager::{IPV4_ONLY_PROBE_ARG, MANAGER_ROLE, WORKER_PROBE_ROLE, WORKLOAD_PROBE_ROLE},
        pasta::{
            PastaCommand, PastaStartupFailure, classify_startup_stderr, verify_version,
            wait_until_ready,
        },
        protocol::{
            ManagerMessage, SupervisorMessage, WireProvisionRequest, receive_async, send_async,
        },
        resolver::{HostResolver, ResolverConfig, probe_resolver},
        security::PreExecDescriptorSanitizer,
    };

    const CONTROL_FD: libc::c_int = 3;
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
    const EXIT_MESSAGE_GRACE: Duration = Duration::from_secs(2);
    const DROP_REAP_INTERVAL: Duration = Duration::from_millis(10);
    const STDERR_CAPTURE_LIMIT: usize = 64 * 1024;

    pub(super) async fn preflight(provisioner: &SystemNetworkProvisioner) -> PreflightReport {
        let connectivity = host_connectivity(provisioner);
        if !connectivity.ipv4 {
            return PreflightReport::failed(
                CaptureTransportDegradationReason::NetnsStartupFailed,
                "the host has no usable IPv4 route",
                false,
                connectivity.ipv6,
            );
        }
        if let Err(report) = preflight_dependencies(provisioner, connectivity).await {
            return report;
        }

        let mut workload =
            crate::netns::NamespaceCommand::new(&provisioner.helper_path).arg(WORKLOAD_PROBE_ROLE);
        let mut worker =
            crate::netns::NamespaceCommand::new(&provisioner.helper_path).arg(WORKER_PROBE_ROLE);
        if !connectivity.ipv6 {
            workload = workload.arg(IPV4_ONLY_PROBE_ARG);
            worker = worker.arg(IPV4_ONLY_PROBE_ARG);
        }
        let request = ProvisionRequest::new(workload, worker);
        match launch(provisioner, request, connectivity.ipv6, true).await {
            Ok(mut session) => {
                match time::timeout(provisioner.startup_timeout, session.wait()).await {
                    Ok(Ok(SubstrateExit::Code(0))) => PreflightReport::passed(connectivity.ipv6),
                    Ok(Ok(exit)) => PreflightReport::failed(
                        CaptureTransportDegradationReason::NetnsStartupFailed,
                        format!("namespace security probe exited {exit:?}"),
                        connectivity.ipv4,
                        connectivity.ipv6,
                    ),
                    Ok(Err(error)) => report_for_error(error, connectivity),
                    Err(_) => {
                        let diagnostic = match session.shutdown().await {
                            Ok(()) => "namespace security probe timed out".to_owned(),
                            Err(error) => format!(
                                "namespace security probe timed out; ordered shutdown failed: {error}"
                            ),
                        };
                        PreflightReport::failed(
                            CaptureTransportDegradationReason::NetnsStartupFailed,
                            diagnostic,
                            connectivity.ipv4,
                            connectivity.ipv6,
                        )
                    }
                }
            }
            Err(error) => report_for_error(error, connectivity),
        }
    }

    pub(super) async fn provision(
        provisioner: &SystemNetworkProvisioner,
        request: ProvisionRequest,
    ) -> Result<Box<dyn NetworkSession>, ProvisionError> {
        let connectivity = host_connectivity(provisioner);
        if !connectivity.ipv4 {
            return Err(ProvisionError::unavailable(
                CaptureTransportDegradationReason::NetnsStartupFailed,
                "the host has no usable IPv4 route",
            ));
        }
        verify_dependencies(provisioner).await?;
        Ok(Box::new(
            launch(provisioner, request, connectivity.ipv6, false).await?,
        ))
    }

    async fn preflight_dependencies(
        provisioner: &SystemNetworkProvisioner,
        connectivity: HostConnectivity,
    ) -> Result<(), PreflightReport> {
        if let Err(error) =
            verify_version(&provisioner.pasta_path, provisioner.startup_timeout).await
        {
            return Err(PreflightReport::failed(
                CaptureTransportDegradationReason::PastaMissing,
                error.to_string(),
                connectivity.ipv4,
                connectivity.ipv6,
            ));
        }
        if let Err(error) = require_tools() {
            return Err(PreflightReport::failed(
                CaptureTransportDegradationReason::TproxyUnavailable,
                error.to_string(),
                connectivity.ipv4,
                connectivity.ipv6,
            ));
        }
        if let Err(error) =
            probe_resolver(Path::new("/etc/resolv.conf"), provisioner.resolver_timeout).await
        {
            return Err(PreflightReport::failed(
                CaptureTransportDegradationReason::ResolverUnavailable,
                error.to_string(),
                connectivity.ipv4,
                connectivity.ipv6,
            ));
        }
        Ok(())
    }

    async fn verify_dependencies(
        provisioner: &SystemNetworkProvisioner,
    ) -> Result<(), ProvisionError> {
        verify_version(&provisioner.pasta_path, provisioner.startup_timeout)
            .await
            .map_err(|error| {
                unavailable_from_io(
                    CaptureTransportDegradationReason::PastaMissing,
                    "verify the pinned pasta executable",
                    error,
                )
            })?;
        require_tools().map_err(|error| {
            unavailable_from_io(
                CaptureTransportDegradationReason::TproxyUnavailable,
                "locate required Linux networking tools",
                error,
            )
        })
    }

    fn require_tools() -> io::Result<()> {
        for tool in ["ip", "nft"] {
            find_executable(tool).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("required Linux networking tool `{tool}` was not found on PATH"),
                )
            })?;
        }
        Ok(())
    }

    fn find_executable(name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| {
                fs::metadata(candidate).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
    }

    #[derive(Debug, Clone, Copy)]
    struct HostConnectivity {
        ipv4: bool,
        ipv6: bool,
    }

    impl HostConnectivity {
        fn probe() -> Self {
            Self {
                ipv4: route_available("0.0.0.0:0", "1.1.1.1:53"),
                ipv6: route_available("[::]:0", "[2606:4700:4700::1111]:53"),
            }
        }
    }

    fn host_connectivity(provisioner: &SystemNetworkProvisioner) -> HostConnectivity {
        #[cfg(feature = "test-support")]
        if let Some((ipv4, ipv6)) = provisioner.forced_host_ip_families {
            return HostConnectivity { ipv4, ipv6 };
        }
        HostConnectivity::probe()
    }

    fn route_available(bind: &str, destination: &str) -> bool {
        UdpSocket::bind(bind)
            .and_then(|socket| socket.connect(destination))
            .is_ok()
    }

    async fn launch(
        provisioner: &SystemNetworkProvisioner,
        mut request: ProvisionRequest,
        require_ipv6: bool,
        validate_dataplane: bool,
    ) -> Result<RealNetworkSession, ProvisionError> {
        let dns_relay = DnsRelayResources::start(provisioner)?;
        let (name, value) = relay_socket_environment(dns_relay.socket_path());
        request.gateway_worker = request.gateway_worker.clone().env(name, value);
        let (parent_control, child_control) = StdUnixStream::pair().map_err(|error| {
            namespace_startup_from_io("create namespace-manager control channel", error)
        })?;
        parent_control.set_nonblocking(true).map_err(|error| {
            namespace_startup_from_io("configure namespace-manager control channel", error)
        })?;
        let control = UnixStream::from_std(parent_control).map_err(|error| {
            namespace_startup_from_io("adopt namespace-manager control channel", error)
        })?;
        let sanitizer = PreExecDescriptorSanitizer::prepare(&[CONTROL_FD]).map_err(|error| {
            namespace_startup_from_io("prepare namespace-manager descriptor isolation", error)
        })?;
        let child_fd = child_control.as_raw_fd();
        let mut command = Command::new(&provisioner.helper_path);
        command
            .arg(MANAGER_ROLE)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        set_control_pre_exec(&mut command, child_fd, sanitizer);
        let bootstrap = command
            .spawn()
            .map_err(|error| namespace_startup_from_io("spawn namespace-manager helper", error))?;
        drop(child_control);

        let mut resources = LaunchResources::new(control, bootstrap, dns_relay);
        let result = launch_inner(
            &mut resources,
            provisioner,
            &request,
            require_ipv6,
            validate_dataplane,
        )
        .await;
        match result {
            Ok(info) => match resources.promote(info) {
                Ok(session) => Ok(session),
                Err(error) => Err(fail_launch(&mut resources, LaunchFailure::Error(error)).await),
            },
            Err(error) => Err(fail_launch(&mut resources, error).await),
        }
    }

    async fn launch_inner(
        resources: &mut LaunchResources,
        provisioner: &SystemNetworkProvisioner,
        request: &ProvisionRequest,
        require_ipv6: bool,
        validate_dataplane: bool,
    ) -> Result<SubstrateInfo, LaunchFailure> {
        let bootstrap_pid = resources.bootstrap_id().ok_or_else(|| {
            LaunchFailure::Error(namespace_startup(io::Error::other(
                "namespace manager returned no PID",
            )))
        })?;

        let first = resources
            .receive_manager_before_pasta(provisioner.startup_timeout)
            .await
            .map_err(LaunchFailure::Error)?;
        match first {
            ManagerMessage::UserNamespaceReady => {}
            ManagerMessage::Failed {
                stage,
                reason,
                diagnostic,
            } => {
                return Err(LaunchFailure::Error(ProvisionError::startup(
                    StartupStage::from(stage),
                    reason.into(),
                    diagnostic,
                )));
            }
            message => {
                return Err(LaunchFailure::Error(protocol_startup(format!(
                    "manager sent unexpected startup message {message:?}"
                ))));
            }
        }

        install_id_maps(bootstrap_pid).map_err(|error| {
            LaunchFailure::Error(unavailable_from_io(
                CaptureTransportDegradationReason::UserNamespaceDenied,
                "install namespace uid/gid maps",
                error,
            ))
        })?;
        resources
            .send(&SupervisorMessage::IdMapsInstalled)
            .await
            .map_err(|error| {
                LaunchFailure::Error(namespace_startup_from_io(
                    "send uid/gid-map readiness to namespace manager",
                    error,
                ))
            })?;

        let gateway_pid = match resources
            .receive_manager_before_pasta(provisioner.startup_timeout)
            .await
            .map_err(LaunchFailure::Error)?
        {
            ManagerMessage::GatewayNamespaceReady { pid } => pid,
            ManagerMessage::Failed {
                stage,
                reason,
                diagnostic,
            } => {
                return Err(LaunchFailure::Error(ProvisionError::startup(
                    StartupStage::from(stage),
                    reason.into(),
                    diagnostic,
                )));
            }
            message => {
                return Err(LaunchFailure::Error(protocol_startup(format!(
                    "manager sent unexpected namespace message {message:?}"
                ))));
            }
        };

        resources.start_pasta(provisioner, gateway_pid, require_ipv6)?;
        resources
            .wait_for_pasta_ready(provisioner.startup_timeout, require_ipv6)
            .await?;
        resources.release_readiness_artifact();

        resources
            .send(&SupervisorMessage::PastaReady)
            .await
            .map_err(|error| {
                LaunchFailure::Error(pasta_startup_from_io(
                    CaptureTransportDegradationReason::NetnsStartupFailed,
                    "send pasta readiness to namespace manager",
                    error,
                ))
            })?;
        resources
            .send(&SupervisorMessage::Configure(Box::new(
                WireProvisionRequest::from_request(
                    request,
                    require_ipv6,
                    validate_dataplane,
                    resources.workload_resolv_conf(),
                ),
            )))
            .await
            .map_err(|error| {
                LaunchFailure::Error(namespace_startup_from_io(
                    "send provision request to namespace manager",
                    error,
                ))
            })?;

        match resources
            .receive_manager_with_pasta(provisioner.startup_timeout, require_ipv6)
            .await?
        {
            ManagerMessage::Ready(info) => SubstrateInfo::try_from(info).map_err(|error| {
                LaunchFailure::Error(namespace_startup_from_io(
                    "validate namespace-manager substrate information",
                    error,
                ))
            }),
            ManagerMessage::Failed {
                stage,
                reason,
                diagnostic,
            } => Err(LaunchFailure::Error(ProvisionError::startup(
                StartupStage::from(stage),
                reason.into(),
                diagnostic,
            ))),
            message => Err(LaunchFailure::Error(protocol_startup(format!(
                "manager sent unexpected ready message {message:?}"
            )))),
        }
    }

    enum LaunchFailure {
        Error(ProvisionError),
        Pasta {
            source: io::Error,
            require_ipv6: bool,
        },
    }

    enum StartupManagerEvent {
        Message(Option<io::Result<ManagerMessage>>),
        Bootstrap(io::Result<ExitStatus>),
        Timeout,
    }

    enum PastaReadinessEvent {
        Ready(io::Result<()>),
        Pasta(io::Result<ExitStatus>),
        Bootstrap(io::Result<ExitStatus>),
    }

    enum ManagerReadyEvent {
        Message(Option<io::Result<ManagerMessage>>),
        Pasta(io::Result<ExitStatus>),
        Bootstrap(io::Result<ExitStatus>),
        Timeout,
    }

    fn decode_startup_message(
        message: Option<io::Result<ManagerMessage>>,
    ) -> Result<ManagerMessage, ProvisionError> {
        match message {
            Some(Ok(message)) => Ok(message),
            Some(Err(error)) => Err(namespace_startup_from_io(
                "receive namespace-manager readiness",
                error,
            )),
            None => Err(namespace_startup(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "namespace-manager message reader stopped",
            ))),
        }
    }

    fn error_from_early_manager_message(
        message: ManagerMessage,
        readiness: &str,
    ) -> ProvisionError {
        match message {
            ManagerMessage::Failed {
                stage,
                reason,
                diagnostic,
            } => ProvisionError::startup(StartupStage::from(stage), reason.into(), diagnostic),
            message => protocol_startup(format!(
                "manager sent unexpected message before {readiness}: {message:?}"
            )),
        }
    }

    async fn fail_launch(
        resources: &mut LaunchResources,
        failure: LaunchFailure,
    ) -> ProvisionError {
        let report = resources.abort().await;
        let error = match failure {
            LaunchFailure::Error(error) => error,
            LaunchFailure::Pasta {
                source,
                require_ipv6,
            } => pasta_error(source, &report.stderr, require_ipv6),
        };
        attach_cleanup(error, report.cleanup)
    }

    struct LaunchResources {
        control_writer: Option<OwnedWriteHalf>,
        messages: Option<mpsc::Receiver<io::Result<ManagerMessage>>>,
        manager_reader: Option<JoinHandle<()>>,
        bootstrap: Option<Child>,
        pasta: Option<Child>,
        pasta_stderr: Option<JoinHandle<io::Result<String>>>,
        pid_file: Option<fs::File>,
        pid_file_path: Option<PathBuf>,
        dns_relay: Option<DnsRelayResources>,
    }

    impl LaunchResources {
        fn new(control: UnixStream, bootstrap: Child, dns_relay: DnsRelayResources) -> Self {
            let (reader, writer) = control.into_split();
            let (message_sender, messages) = mpsc::channel(8);
            let manager_reader = tokio::spawn(read_manager_messages(reader, message_sender));
            Self {
                control_writer: Some(writer),
                messages: Some(messages),
                manager_reader: Some(manager_reader),
                bootstrap: Some(bootstrap),
                pasta: None,
                pasta_stderr: None,
                pid_file: None,
                pid_file_path: None,
                dns_relay: Some(dns_relay),
            }
        }

        fn workload_resolv_conf(&self) -> &[u8] {
            self.dns_relay
                .as_ref()
                .map_or(&[], DnsRelayResources::workload_resolv_conf)
        }

        fn bootstrap_id(&self) -> Option<u32> {
            self.bootstrap.as_ref().and_then(Child::id)
        }

        async fn send(&mut self, message: &SupervisorMessage) -> io::Result<()> {
            let control = self.control_writer.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "namespace-manager control channel is closed",
                )
            })?;
            send_async(control, message).await
        }

        async fn receive_manager_before_pasta(
            &mut self,
            timeout: Duration,
        ) -> Result<ManagerMessage, ProvisionError> {
            let messages = self
                .messages
                .as_mut()
                .ok_or_else(|| ProvisionError::dataplane("manager", "message reader is closed"))?;
            let bootstrap = self.bootstrap.as_mut().ok_or_else(|| {
                ProvisionError::dataplane("manager", "namespace manager is not running")
            })?;
            let event = tokio::select! {
                biased;
                message = messages.recv() => StartupManagerEvent::Message(message),
                status = bootstrap.wait() => StartupManagerEvent::Bootstrap(status),
                () = time::sleep(timeout) => StartupManagerEvent::Timeout,
            };
            match event {
                StartupManagerEvent::Message(message) => decode_startup_message(message),
                StartupManagerEvent::Bootstrap(status) => {
                    self.message_after_bootstrap_exit(status).await
                }
                StartupManagerEvent::Timeout => Err(namespace_startup(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "namespace manager timed out",
                ))),
            }
        }

        fn start_pasta(
            &mut self,
            provisioner: &SystemNetworkProvisioner,
            gateway_pid: u32,
            enable_ipv6: bool,
        ) -> Result<(), LaunchFailure> {
            let (pid_file, pid_file_path) = anonymous_readiness_file().map_err(|error| {
                LaunchFailure::Error(pasta_startup_from_io(
                    CaptureTransportDegradationReason::NetnsStartupFailed,
                    "create anonymous pasta readiness file",
                    error,
                ))
            })?;
            let mut command = PastaCommand::attach(
                &provisioner.pasta_path,
                gateway_pid,
                &pid_file_path,
                enable_ipv6,
            )
            .into_tokio_command();
            let sanitizer = PreExecDescriptorSanitizer::prepare(&[]).map_err(|error| {
                LaunchFailure::Error(pasta_startup_from_io(
                    CaptureTransportDegradationReason::NetnsStartupFailed,
                    "prepare pasta descriptor isolation",
                    error,
                ))
            })?;
            set_pasta_pre_exec(&mut command, sanitizer);
            self.pid_file = Some(pid_file);
            self.pid_file_path = Some(pid_file_path);

            let mut pasta = command.spawn().map_err(|error| {
                LaunchFailure::Error(unavailable_from_io(
                    CaptureTransportDegradationReason::PastaMissing,
                    "spawn the pinned pasta executable",
                    error,
                ))
            })?;
            if pasta.id().is_none() {
                self.pasta = Some(pasta);
                return Err(LaunchFailure::Pasta {
                    source: io::Error::other("pasta returned no PID"),
                    require_ipv6: false,
                });
            }
            let Some(stderr) = pasta.stderr.take() else {
                self.pasta = Some(pasta);
                return Err(LaunchFailure::Pasta {
                    source: io::Error::other("pasta stderr was not piped"),
                    require_ipv6: false,
                });
            };
            self.pasta_stderr = Some(tokio::spawn(read_bounded_to_eof(stderr)));
            self.pasta = Some(pasta);
            Ok(())
        }

        async fn wait_for_pasta_ready(
            &mut self,
            timeout: Duration,
            require_ipv6: bool,
        ) -> Result<(), LaunchFailure> {
            let pid_file_path = self.pid_file_path.as_ref().ok_or_else(|| {
                LaunchFailure::Error(pasta_startup(io::Error::other(
                    "pasta readiness path is unavailable",
                )))
            })?;
            let pasta = self.pasta.as_mut().ok_or_else(|| {
                LaunchFailure::Error(pasta_startup(io::Error::other("pasta is not running")))
            })?;
            let pasta_pid = pasta.id().ok_or_else(|| LaunchFailure::Pasta {
                source: io::Error::other("pasta returned no PID"),
                require_ipv6,
            })?;
            let bootstrap = self.bootstrap.as_mut().ok_or_else(|| {
                LaunchFailure::Error(namespace_startup(io::Error::other(
                    "namespace manager is not running",
                )))
            })?;
            let event = tokio::select! {
                biased;
                result = wait_until_ready(pid_file_path, pasta_pid, timeout) => {
                    PastaReadinessEvent::Ready(result)
                },
                status = pasta.wait() => PastaReadinessEvent::Pasta(status),
                status = bootstrap.wait() => PastaReadinessEvent::Bootstrap(status),
            };
            match event {
                PastaReadinessEvent::Ready(result) => {
                    result.map_err(|source| LaunchFailure::Pasta {
                        source,
                        require_ipv6,
                    })
                }
                PastaReadinessEvent::Pasta(status) => Err(LaunchFailure::Pasta {
                    source: child_exit_error("pasta exited before readiness", status),
                    require_ipv6,
                }),
                PastaReadinessEvent::Bootstrap(status) => {
                    match self.message_after_bootstrap_exit(status).await {
                        Ok(message) => Err(LaunchFailure::Error(error_from_early_manager_message(
                            message,
                            "pasta readiness",
                        ))),
                        Err(error) => Err(LaunchFailure::Error(error)),
                    }
                }
            }
        }

        async fn receive_manager_with_pasta(
            &mut self,
            timeout: Duration,
            require_ipv6: bool,
        ) -> Result<ManagerMessage, LaunchFailure> {
            let messages = self.messages.as_mut().ok_or_else(|| {
                LaunchFailure::Error(namespace_startup(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "namespace-manager message reader is closed",
                )))
            })?;
            let pasta = self.pasta.as_mut().ok_or_else(|| {
                LaunchFailure::Error(pasta_startup(io::Error::other("pasta is not running")))
            })?;
            let bootstrap = self.bootstrap.as_mut().ok_or_else(|| {
                LaunchFailure::Error(namespace_startup(io::Error::other(
                    "namespace manager is not running",
                )))
            })?;
            let event = tokio::select! {
                biased;
                message = messages.recv() => ManagerReadyEvent::Message(message),
                status = pasta.wait() => ManagerReadyEvent::Pasta(status),
                status = bootstrap.wait() => ManagerReadyEvent::Bootstrap(status),
                () = time::sleep(timeout) => ManagerReadyEvent::Timeout,
            };
            match event {
                ManagerReadyEvent::Message(message) => {
                    decode_startup_message(message).map_err(LaunchFailure::Error)
                }
                ManagerReadyEvent::Pasta(status) => Err(LaunchFailure::Pasta {
                    source: child_exit_error("pasta exited before manager readiness", status),
                    require_ipv6,
                }),
                ManagerReadyEvent::Bootstrap(status) => self
                    .message_after_bootstrap_exit(status)
                    .await
                    .map_err(LaunchFailure::Error),
                ManagerReadyEvent::Timeout => Err(LaunchFailure::Error(namespace_startup(
                    io::Error::new(io::ErrorKind::TimedOut, "namespace manager timed out"),
                ))),
            }
        }

        async fn message_after_bootstrap_exit(
            &mut self,
            status: io::Result<ExitStatus>,
        ) -> Result<ManagerMessage, ProvisionError> {
            let message = match self.messages.as_mut() {
                Some(messages) => time::timeout(EXIT_MESSAGE_GRACE, messages.recv())
                    .await
                    .ok(),
                None => None,
            };
            match message.flatten() {
                Some(Ok(message)) => Ok(message),
                Some(Err(error)) => Err(namespace_startup_from_io(
                    "read final namespace-manager message",
                    error,
                )),
                None => Err(manager_startup_exit(status)),
            }
        }

        fn release_readiness_artifact(&mut self) {
            self.pid_file_path.take();
            self.pid_file.take();
        }

        fn promote(&mut self, info: SubstrateInfo) -> Result<RealNetworkSession, ProvisionError> {
            let writer = self
                .control_writer
                .take()
                .ok_or_else(|| ProvisionError::dataplane("manager", "control channel is closed"))?;
            let messages = self
                .messages
                .take()
                .ok_or_else(|| ProvisionError::dataplane("manager", "message reader is closed"))?;
            let manager_reader = self.manager_reader.take().ok_or_else(|| {
                ProvisionError::dataplane("manager", "message-reader task is not running")
            })?;
            let bootstrap = self.bootstrap.take().ok_or_else(|| {
                ProvisionError::dataplane("manager", "namespace manager is not running")
            })?;
            let pasta = self
                .pasta
                .take()
                .ok_or_else(|| ProvisionError::dataplane("pasta", "pasta is not running"))?;
            let pasta_stderr = self.pasta_stderr.take().ok_or_else(|| {
                ProvisionError::dataplane("pasta", "pasta stderr reader is not running")
            })?;
            let dns_relay = self.dns_relay.take().ok_or_else(|| {
                ProvisionError::dataplane("dns_relay", "host DNS relay is not running")
            })?;
            Ok(RealNetworkSession {
                info,
                control_writer: Some(writer),
                messages,
                manager_reader: Some(manager_reader),
                shutdown_task: None,
                bootstrap: Some(bootstrap),
                pasta: Some(pasta),
                pasta_stderr: Some(pasta_stderr),
                exit: None,
                failure: None,
                cleanup: CleanupFailures::default(),
                shutdown_requested: false,
                terminal: false,
                finished: false,
                dns_relay: Some(dns_relay),
            })
        }

        async fn abort(&mut self) -> AbortReport {
            let mut cleanup = CleanupFailures::default();
            if let Some(control) = self.control_writer.as_mut() {
                match time::timeout(
                    SHUTDOWN_TIMEOUT,
                    send_async(control, &SupervisorMessage::Shutdown),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        cleanup.record_io("send launch-abort shutdown to namespace manager", error);
                    }
                    Err(_) => {
                        cleanup.record_message(
                            "send launch-abort shutdown to namespace manager timed out",
                        );
                    }
                }
            }
            self.control_writer.take();

            if let Some(bootstrap) = self.bootstrap.as_mut() {
                wait_or_kill(
                    bootstrap,
                    "namespace manager",
                    SHUTDOWN_TIMEOUT,
                    &mut cleanup,
                )
                .await;
            }
            self.bootstrap.take();

            if let Some(pasta) = self.pasta.as_mut() {
                if let Err(error) = terminate(pasta) {
                    cleanup.record_io("terminate pasta", error);
                }
                wait_or_kill(pasta, "pasta", SHUTDOWN_TIMEOUT, &mut cleanup).await;
            }
            self.pasta.take();

            finish_task(
                &mut self.manager_reader,
                "namespace-manager message reader",
                &mut cleanup,
            )
            .await;
            self.messages.take();
            let stderr = finish_stderr(&mut self.pasta_stderr, &mut cleanup).await;
            self.pid_file.take();
            self.pid_file_path.take();
            self.dns_relay.take();
            AbortReport { stderr, cleanup }
        }
    }

    impl Drop for LaunchResources {
        fn drop(&mut self) {
            self.control_writer.take();
            self.messages.take();
            if let Some(task) = self.manager_reader.as_mut() {
                task.abort();
            }
            if let Some(task) = self.pasta_stderr.as_mut() {
                task.abort();
            }
            if let Some(pasta) = self.pasta.as_mut() {
                let _ = pasta.start_kill();
            }
            if let Some(bootstrap) = self.bootstrap.as_mut() {
                let _ = bootstrap.start_kill();
            }
            let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
            if let Some(bootstrap) = self.bootstrap.as_mut() {
                reap_synchronously(bootstrap, deadline);
            }
            if let Some(pasta) = self.pasta.as_mut() {
                reap_synchronously(pasta, deadline);
            }
            self.pid_file.take();
            self.pid_file_path.take();
            self.dns_relay.take();
        }
    }

    struct DnsRelayResources {
        _directory: tempfile::TempDir,
        socket_path: PathBuf,
        workload_resolv_conf: Vec<u8>,
        task: JoinHandle<io::Result<()>>,
    }

    impl DnsRelayResources {
        fn start(provisioner: &SystemNetworkProvisioner) -> Result<Self, ProvisionError> {
            let contents = fs::read_to_string("/etc/resolv.conf").map_err(|error| {
                unavailable_from_io(
                    CaptureTransportDegradationReason::ResolverUnavailable,
                    "read the host resolver configuration",
                    error,
                )
            })?;
            let config = ResolverConfig::parse(&contents).map_err(|error| {
                unavailable_from_io(
                    CaptureTransportDegradationReason::ResolverUnavailable,
                    "parse the host resolver configuration",
                    error,
                )
            })?;
            let directory = tempfile::tempdir().map_err(|error| {
                unavailable_from_io(
                    CaptureTransportDegradationReason::ResolverUnavailable,
                    "create the private DNS relay directory",
                    error,
                )
            })?;
            let socket_path = directory.path().join("dns.sock");
            let resolver = HostResolver::from_config(&config, provisioner.resolver_timeout);
            let relay = HostDnsRelay::bind(&socket_path, resolver).map_err(|error| {
                unavailable_from_io(
                    CaptureTransportDegradationReason::ResolverUnavailable,
                    "bind the private host DNS relay",
                    error,
                )
            })?;
            let workload_resolv_conf = config.workload_contents().to_vec();
            Ok(Self {
                _directory: directory,
                socket_path,
                workload_resolv_conf,
                task: tokio::spawn(relay.serve()),
            })
        }

        fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        fn workload_resolv_conf(&self) -> &[u8] {
            &self.workload_resolv_conf
        }
    }

    impl Drop for DnsRelayResources {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct AbortReport {
        stderr: String,
        cleanup: CleanupFailures,
    }

    async fn read_manager_messages(
        mut reader: OwnedReadHalf,
        sender: mpsc::Sender<io::Result<ManagerMessage>>,
    ) {
        loop {
            let message = receive_async(&mut reader).await;
            let failed = message.is_err();
            if sender.send(message).await.is_err() || failed {
                return;
            }
        }
    }

    #[async_trait]
    impl NetworkSession for RealNetworkSession {
        fn info(&self) -> &SubstrateInfo {
            &self.info
        }

        async fn wait(&mut self) -> Result<SubstrateExit, ProvisionError> {
            self.wait_inner(false).await
        }

        async fn shutdown(&mut self) -> Result<(), ProvisionError> {
            self.wait_inner(true).await.map(|_| ())
        }
    }

    struct RealNetworkSession {
        info: SubstrateInfo,
        control_writer: Option<OwnedWriteHalf>,
        messages: mpsc::Receiver<io::Result<ManagerMessage>>,
        manager_reader: Option<JoinHandle<()>>,
        shutdown_task: Option<JoinHandle<io::Result<()>>>,
        bootstrap: Option<Child>,
        pasta: Option<Child>,
        pasta_stderr: Option<JoinHandle<io::Result<String>>>,
        exit: Option<SubstrateExit>,
        failure: Option<ProvisionError>,
        cleanup: CleanupFailures,
        shutdown_requested: bool,
        terminal: bool,
        finished: bool,
        dns_relay: Option<DnsRelayResources>,
    }

    impl RealNetworkSession {
        async fn wait_inner(&mut self, shutdown: bool) -> Result<SubstrateExit, ProvisionError> {
            if self.finished {
                return Err(ProvisionError::dataplane(
                    "manager",
                    "network session has already completed",
                ));
            }
            if shutdown {
                self.begin_shutdown();
                self.finish_shutdown_request().await;
            }

            while !self.terminal {
                let event = self.next_terminal_event().await;
                self.handle_terminal_event(event);
            }
            self.finish_processes().await;
            self.finished = true;

            let fallback_exit = self.shutdown_requested.then_some(SubstrateExit::Code(0));
            let result = if let Some(error) = self.failure.take() {
                Err(error)
            } else {
                self.exit.or(fallback_exit).ok_or_else(|| {
                    ProvisionError::dataplane(
                        "workload",
                        "manager completed without a workload exit",
                    )
                })
            };
            match result {
                Ok(exit) if self.cleanup.is_empty() => Ok(exit),
                Ok(_) => Err(std::mem::take(&mut self.cleanup).into_error()),
                Err(error) => Err(attach_cleanup(error, std::mem::take(&mut self.cleanup))),
            }
        }

        fn begin_shutdown(&mut self) {
            if self.shutdown_requested {
                return;
            }
            self.shutdown_requested = true;
            if self.terminal {
                return;
            }
            match self.control_writer.take() {
                Some(mut writer) => {
                    self.shutdown_task = Some(tokio::spawn(async move {
                        send_async(&mut writer, &SupervisorMessage::Shutdown).await
                    }));
                }
                None => self.record_failure(ProvisionError::dataplane(
                    "manager",
                    "control channel was already closed before shutdown",
                )),
            }
        }

        async fn finish_shutdown_request(&mut self) {
            let Some(task) = self.shutdown_task.as_mut() else {
                return;
            };
            let result = (&mut *task).await;
            self.shutdown_task.take();
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => self.record_failure(dataplane_manager(
                    "send shutdown to namespace manager",
                    error,
                )),
                Err(error) => self.record_failure(ProvisionError::dataplane_with_source(
                    "manager",
                    format!("namespace-manager shutdown task failed: {error}"),
                    error,
                )),
            }
        }

        async fn next_terminal_event(&mut self) -> TerminalEvent {
            let Some(pasta) = self.pasta.as_mut() else {
                return TerminalEvent::Missing("pasta");
            };
            let Some(bootstrap) = self.bootstrap.as_mut() else {
                return TerminalEvent::Missing("namespace manager");
            };
            let event = tokio::select! {
                biased;
                message = self.messages.recv() => TerminalEvent::Manager(message),
                status = pasta.wait() => TerminalEvent::Pasta(status),
                status = bootstrap.wait() => TerminalEvent::Bootstrap(status),
            };
            match event {
                event @ (TerminalEvent::Pasta(_) | TerminalEvent::Bootstrap(_)) => {
                    match time::timeout(EXIT_MESSAGE_GRACE, self.messages.recv()).await {
                        Ok(message) => TerminalEvent::Manager(message),
                        Err(_) => event,
                    }
                }
                _ => event,
            }
        }

        fn handle_terminal_event(&mut self, event: TerminalEvent) {
            match event {
                TerminalEvent::Manager(Some(Ok(ManagerMessage::WorkloadExited(value)))) => {
                    match SubstrateExit::try_from(value) {
                        Ok(exit) => self.exit = Some(exit),
                        Err(error) => {
                            self.record_failure(dataplane_manager(
                                "decode workload exit from namespace manager",
                                error,
                            ));
                            self.terminal = true;
                        }
                    }
                }
                TerminalEvent::Manager(Some(Ok(ManagerMessage::Failed {
                    stage,
                    reason,
                    diagnostic,
                }))) => {
                    let stage = StartupStage::from(stage);
                    let error = if stage == StartupStage::GatewayWorker {
                        ProvisionError::dataplane("gateway_worker", diagnostic)
                    } else {
                        ProvisionError::startup(stage, reason.into(), diagnostic)
                    };
                    self.record_failure(error);
                }
                TerminalEvent::Manager(Some(Ok(ManagerMessage::Fatal(report)))) => {
                    match report.try_into() {
                        Ok(report) => self.record_failure(ProvisionError::fatal(report)),
                        Err(error) => self.record_failure(dataplane_manager(
                            "decode fatal report from namespace manager",
                            error,
                        )),
                    }
                }
                TerminalEvent::Manager(Some(Ok(ManagerMessage::CleanupComplete { failures }))) => {
                    self.cleanup.extend_messages(failures);
                    self.terminal = true;
                }
                TerminalEvent::Manager(Some(Ok(message))) => {
                    self.record_failure(ProvisionError::dataplane(
                        "manager",
                        format!("unexpected manager message {message:?}"),
                    ));
                    self.terminal = true;
                }
                TerminalEvent::Manager(Some(Err(error))) => {
                    self.record_failure(dataplane_manager(
                        "receive terminal namespace-manager message",
                        error,
                    ));
                    self.terminal = true;
                }
                TerminalEvent::Manager(None) => {
                    self.record_failure(ProvisionError::dataplane(
                        "manager",
                        "namespace-manager message reader stopped",
                    ));
                    self.terminal = true;
                }
                TerminalEvent::Pasta(status) => {
                    self.record_failure(child_dataplane_error(
                        "pasta",
                        "pasta exited before namespace teardown",
                        status,
                    ));
                    self.terminal = true;
                }
                TerminalEvent::Bootstrap(status) => {
                    self.record_failure(child_dataplane_error(
                        "manager",
                        "namespace manager exited before reporting cleanup",
                        status,
                    ));
                    self.terminal = true;
                }
                TerminalEvent::Missing(component) => {
                    self.record_failure(ProvisionError::dataplane(
                        component,
                        "required process handle is missing",
                    ));
                    self.terminal = true;
                }
            }
        }

        fn record_failure(&mut self, error: ProvisionError) {
            if self.failure.is_none() {
                self.failure = Some(error);
            }
        }

        async fn finish_processes(&mut self) {
            self.control_writer.take();
            if let Some(task) = self.shutdown_task.as_mut() {
                task.abort();
            }
            self.shutdown_task.take();

            if let Some(bootstrap) = self.bootstrap.as_mut() {
                wait_or_kill(
                    bootstrap,
                    "namespace manager",
                    SHUTDOWN_TIMEOUT,
                    &mut self.cleanup,
                )
                .await;
            }
            self.bootstrap.take();

            if let Some(pasta) = self.pasta.as_mut() {
                if let Err(error) = terminate(pasta) {
                    self.cleanup.record_io("terminate pasta", error);
                }
                wait_or_kill(pasta, "pasta", SHUTDOWN_TIMEOUT, &mut self.cleanup).await;
            }
            self.pasta.take();

            finish_task(
                &mut self.manager_reader,
                "namespace-manager message reader",
                &mut self.cleanup,
            )
            .await;
            let _ = finish_stderr(&mut self.pasta_stderr, &mut self.cleanup).await;
            self.dns_relay.take();
        }
    }

    impl Drop for RealNetworkSession {
        fn drop(&mut self) {
            self.control_writer.take();
            if let Some(task) = self.shutdown_task.as_mut() {
                task.abort();
            }
            if let Some(task) = self.manager_reader.as_mut() {
                task.abort();
            }
            if let Some(task) = self.pasta_stderr.as_mut() {
                task.abort();
            }
            self.dns_relay.take();

            if let Some(pasta) = self.pasta.as_mut() {
                let _ = pasta.start_kill();
            }
            if let Some(bootstrap) = self.bootstrap.as_mut() {
                let _ = bootstrap.start_kill();
            }
            let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
            if let Some(bootstrap) = self.bootstrap.as_mut() {
                reap_synchronously(bootstrap, deadline);
            }
            if let Some(pasta) = self.pasta.as_mut() {
                reap_synchronously(pasta, deadline);
            }
        }
    }

    enum TerminalEvent {
        Manager(Option<io::Result<ManagerMessage>>),
        Pasta(io::Result<ExitStatus>),
        Bootstrap(io::Result<ExitStatus>),
        Missing(&'static str),
    }

    #[derive(Default)]
    struct CleanupFailures {
        diagnostics: Vec<String>,
        source: Option<io::Error>,
    }

    impl CleanupFailures {
        fn record_io(&mut self, operation: &str, error: io::Error) {
            self.diagnostics.push(format!("{operation}: {error}"));
            if self.source.is_none() {
                self.source = Some(error);
            }
        }

        fn record_message(&mut self, diagnostic: impl Into<String>) {
            self.diagnostics.push(diagnostic.into());
        }

        fn extend_messages(&mut self, diagnostics: impl IntoIterator<Item = String>) {
            self.diagnostics.extend(diagnostics);
        }

        fn is_empty(&self) -> bool {
            self.diagnostics.is_empty()
        }

        fn diagnostic(&self) -> String {
            self.diagnostics.join("; ")
        }

        fn into_error(mut self) -> ProvisionError {
            let diagnostic = self.diagnostic();
            match self.source.take() {
                Some(source) => ProvisionError::cleanup_with_source(diagnostic, source),
                None => ProvisionError::cleanup(diagnostic),
            }
        }
    }

    fn attach_cleanup(mut error: ProvisionError, mut cleanup: CleanupFailures) -> ProvisionError {
        if cleanup.is_empty() {
            return error;
        }
        let cleanup_diagnostic = cleanup.diagnostic();
        match &mut error {
            ProvisionError::Unavailable {
                diagnostic, source, ..
            }
            | ProvisionError::Startup {
                diagnostic, source, ..
            }
            | ProvisionError::Dataplane {
                diagnostic, source, ..
            }
            | ProvisionError::Cleanup { diagnostic, source } => {
                diagnostic.push_str("; cleanup failed: ");
                diagnostic.push_str(&cleanup_diagnostic);
                if source.is_none() {
                    *source = cleanup
                        .source
                        .take()
                        .map(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>);
                }
            }
            ProvisionError::Fatal {
                cleanup_diagnostic: fatal_cleanup,
                ..
            } => match fatal_cleanup {
                Some(diagnostic) => {
                    diagnostic.push_str("; ");
                    diagnostic.push_str(&cleanup_diagnostic);
                }
                None => *fatal_cleanup = Some(cleanup_diagnostic),
            },
        }
        error
    }

    async fn wait_or_kill(
        child: &mut Child,
        name: &str,
        timeout: Duration,
        cleanup: &mut CleanupFailures,
    ) {
        match time::timeout(timeout, child.wait()).await {
            Ok(Ok(_)) => return,
            Ok(Err(error)) => cleanup.record_io(&format!("wait for {name}"), error),
            Err(_) => cleanup.record_message(format!("wait for {name} timed out")),
        }

        if let Err(error) = child.start_kill()
            && error.kind() != io::ErrorKind::InvalidInput
            && error.raw_os_error() != Some(libc::ESRCH)
        {
            cleanup.record_io(&format!("kill {name}"), error);
        }
        match time::timeout(timeout, child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => cleanup.record_io(&format!("reap {name} after kill"), error),
            Err(_) => cleanup.record_message(format!("reap {name} after kill timed out")),
        }
    }

    fn terminate(child: &mut Child) -> io::Result<()> {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        let Some(pid) = child.id() else {
            return Ok(());
        };
        let pid = libc::pid_t::try_from(pid).map_err(io::Error::other)?;
        // SAFETY: `pid` came from this owned child; kill reads no caller memory.
        #[expect(
            unsafe_code,
            reason = "kill sends SIGTERM to one owned child process; see SAFETY"
        )]
        if unsafe { libc::kill(pid, libc::SIGTERM) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn reap_synchronously(child: &mut Child, deadline: Instant) {
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            std::thread::sleep(DROP_REAP_INTERVAL.min(deadline.saturating_duration_since(now)));
        }
    }

    async fn finish_task(
        task: &mut Option<JoinHandle<()>>,
        name: &str,
        cleanup: &mut CleanupFailures,
    ) {
        let Some(handle) = task.as_mut() else {
            return;
        };
        match time::timeout(SHUTDOWN_TIMEOUT, &mut *handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup.record_io(&format!("join {name}"), io::Error::other(error)),
            Err(_) => {
                cleanup.record_message(format!("join {name} timed out"));
                handle.abort();
            }
        }
        task.take();
    }

    async fn finish_stderr(
        task: &mut Option<JoinHandle<io::Result<String>>>,
        cleanup: &mut CleanupFailures,
    ) -> String {
        let Some(handle) = task.as_mut() else {
            return String::new();
        };
        let output = match time::timeout(SHUTDOWN_TIMEOUT, &mut *handle).await {
            Ok(Ok(Ok(stderr))) => stderr,
            Ok(Ok(Err(error))) => {
                cleanup.record_io("read pasta stderr", error);
                String::new()
            }
            Ok(Err(error)) => {
                cleanup.record_io("join pasta stderr reader", io::Error::other(error));
                String::new()
            }
            Err(_) => {
                cleanup.record_message("join pasta stderr reader timed out");
                handle.abort();
                String::new()
            }
        };
        task.take();
        output
    }

    async fn read_bounded_to_eof(mut reader: impl AsyncRead + Unpin) -> io::Result<String> {
        let mut captured = Vec::new();
        let mut chunk = [0_u8; 8 * 1024];
        loop {
            let read = reader.read(&mut chunk).await?;
            if read == 0 {
                return Ok(String::from_utf8_lossy(&captured).into_owned());
            }
            let remaining = STDERR_CAPTURE_LIMIT.saturating_sub(captured.len());
            captured.extend_from_slice(&chunk[..read.min(remaining)]);
        }
    }

    fn anonymous_readiness_file() -> io::Result<(fs::File, PathBuf)> {
        let file = tempfile::tempfile()?;
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            file.as_raw_fd()
        ));
        Ok((file, path))
    }

    fn install_id_maps(pid: u32) -> io::Result<()> {
        let uid = effective_uid();
        let gid = effective_gid();
        let base = PathBuf::from(format!("/proc/{pid}"));
        fs::write(base.join("setgroups"), b"deny")?;
        fs::write(base.join("uid_map"), format!("0 {uid} 1"))?;
        fs::write(base.join("gid_map"), format!("0 {gid} 1"))?;
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "pre_exec duplicates one owned control descriptor using scalar fd syscalls; see SAFETY"
    )]
    fn set_control_pre_exec(
        command: &mut Command,
        control_fd: libc::c_int,
        sanitizer: PreExecDescriptorSanitizer,
    ) {
        // SAFETY: the closure captures descriptor integers and an allocation-owning plan prepared
        // in the parent, then performs only scalar syscalls before exec.
        unsafe {
            command.pre_exec(move || {
                if control_fd != CONTROL_FD && libc::dup2(control_fd, CONTROL_FD) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if control_fd == CONTROL_FD {
                    let flags = libc::fcntl(CONTROL_FD, libc::F_GETFD);
                    if flags == -1
                        || libc::fcntl(CONTROL_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                sanitizer.apply_in_pre_exec()
            });
        }
    }

    #[expect(
        unsafe_code,
        reason = "pre_exec arms pasta's parent-death signal and applies a prepared descriptor plan; see SAFETY"
    )]
    fn set_pasta_pre_exec(command: &mut Command, sanitizer: PreExecDescriptorSanitizer) {
        // SAFETY: the closure captures scalar state and an allocation-owning plan prepared in the
        // parent, then performs only prctl/getppid and descriptor syscalls before exec.
        let expected_parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != expected_parent {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "network supervisor exited during pasta startup",
                    ));
                }
                sanitizer.apply_in_pre_exec()
            });
        }
    }

    fn report_for_error(error: ProvisionError, connectivity: HostConnectivity) -> PreflightReport {
        let (reason, diagnostic) = match error {
            ProvisionError::Unavailable {
                reason, diagnostic, ..
            }
            | ProvisionError::Startup {
                reason, diagnostic, ..
            } => (reason, diagnostic),
            ProvisionError::Dataplane {
                component,
                diagnostic,
                ..
            } => (
                CaptureTransportDegradationReason::NetnsStartupFailed,
                format!("{component}: {diagnostic}"),
            ),
            ProvisionError::Cleanup { diagnostic, .. } => (
                CaptureTransportDegradationReason::NetnsStartupFailed,
                diagnostic,
            ),
            ProvisionError::Fatal { report, .. } => (
                CaptureTransportDegradationReason::NetnsStartupFailed,
                format!("preflight failed fatally: {}", report.reason()),
            ),
        };
        PreflightReport::failed(reason, diagnostic, connectivity.ipv4, connectivity.ipv6)
    }

    fn pasta_error(source: io::Error, stderr: &str, require_ipv6: bool) -> ProvisionError {
        let reason = match classify_startup_stderr(stderr) {
            PastaStartupFailure::UserNamespace => {
                CaptureTransportDegradationReason::UserNamespaceDenied
            }
            PastaStartupFailure::Tun => CaptureTransportDegradationReason::TunUnavailable,
            PastaStartupFailure::Ipv6 if require_ipv6 => {
                CaptureTransportDegradationReason::Ipv6Unavailable
            }
            PastaStartupFailure::Ipv6 | PastaStartupFailure::Other => {
                CaptureTransportDegradationReason::NetnsStartupFailed
            }
        };
        let diagnostic = if stderr.trim().is_empty() {
            source.to_string()
        } else {
            format!("{source}: {}", stderr.trim())
        };
        ProvisionError::unavailable_with_source(reason, diagnostic, source)
    }

    fn unavailable_from_io(
        reason: CaptureTransportDegradationReason,
        operation: &str,
        source: io::Error,
    ) -> ProvisionError {
        ProvisionError::unavailable_with_source(reason, format!("{operation}: {source}"), source)
    }

    fn namespace_startup(source: io::Error) -> ProvisionError {
        namespace_startup_from_io("start namespace manager", source)
    }

    fn namespace_startup_from_io(operation: &str, source: io::Error) -> ProvisionError {
        ProvisionError::startup_with_source(
            StartupStage::Namespace,
            CaptureTransportDegradationReason::NetnsStartupFailed,
            format!("{operation}: {source}"),
            source,
        )
    }

    fn pasta_startup(source: io::Error) -> ProvisionError {
        pasta_startup_from_io(
            CaptureTransportDegradationReason::NetnsStartupFailed,
            "start pasta",
            source,
        )
    }

    fn pasta_startup_from_io(
        reason: CaptureTransportDegradationReason,
        operation: &str,
        source: io::Error,
    ) -> ProvisionError {
        ProvisionError::startup_with_source(
            StartupStage::Pasta,
            reason,
            format!("{operation}: {source}"),
            source,
        )
    }

    fn protocol_startup(diagnostic: String) -> ProvisionError {
        ProvisionError::startup(
            StartupStage::Namespace,
            CaptureTransportDegradationReason::NetnsStartupFailed,
            diagnostic,
        )
    }

    fn manager_startup_exit(status: io::Result<ExitStatus>) -> ProvisionError {
        match status {
            Ok(status) => ProvisionError::startup(
                StartupStage::Namespace,
                CaptureTransportDegradationReason::NetnsStartupFailed,
                format!("namespace manager exited before readiness: {status}"),
            ),
            Err(error) => namespace_startup_from_io("wait for namespace-manager readiness", error),
        }
    }

    fn child_exit_error(operation: &str, status: io::Result<ExitStatus>) -> io::Error {
        match status {
            Ok(status) => io::Error::other(format!("{operation}: {status}")),
            Err(error) => io::Error::new(error.kind(), error),
        }
    }

    fn child_dataplane_error(
        component: &'static str,
        operation: &str,
        status: io::Result<ExitStatus>,
    ) -> ProvisionError {
        match status {
            Ok(status) => ProvisionError::dataplane(component, format!("{operation}: {status}")),
            Err(error) => ProvisionError::dataplane_with_source(
                component,
                format!("{operation}: {error}"),
                error,
            ),
        }
    }

    fn dataplane_manager(operation: &str, source: io::Error) -> ProvisionError {
        ProvisionError::dataplane_with_source("manager", format!("{operation}: {source}"), source)
    }

    #[expect(
        unsafe_code,
        reason = "geteuid returns scalar process credentials without memory access; see SAFETY"
    )]
    fn effective_uid() -> libc::uid_t {
        // SAFETY: no arguments or memory access.
        unsafe { libc::geteuid() }
    }

    #[expect(
        unsafe_code,
        reason = "getegid returns scalar process credentials without memory access; see SAFETY"
    )]
    fn effective_gid() -> libc::gid_t {
        // SAFETY: no arguments or memory access.
        unsafe { libc::getegid() }
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write as _;

        use super::*;

        #[test]
        fn host_route_probe_is_an_actual_socket_operation() {
            assert!(route_available("0.0.0.0:0", "127.0.0.1:9"));
        }

        #[test]
        fn path_lookup_requires_an_executable_regular_file() {
            assert!(find_executable("ip").is_some());
            assert!(find_executable("hiloop-definitely-not-a-tool").is_none());
        }

        #[test]
        fn preflight_preserves_manager_degradation_reason() {
            let report = report_for_error(
                ProvisionError::startup(
                    StartupStage::Pasta,
                    CaptureTransportDegradationReason::Ipv6Unavailable,
                    "pasta installed no IPv6 route",
                ),
                HostConnectivity {
                    ipv4: true,
                    ipv6: true,
                },
            );
            assert_eq!(
                report.degradation_reason(),
                Some(CaptureTransportDegradationReason::Ipv6Unavailable)
            );
        }

        #[tokio::test]
        async fn stderr_capture_drains_past_its_storage_limit() {
            let bytes = vec![b'x'; STDERR_CAPTURE_LIMIT + 1_024];
            let captured = read_bounded_to_eof(bytes.as_slice())
                .await
                .expect("read in-memory stderr");
            assert_eq!(captured.len(), STDERR_CAPTURE_LIMIT);
        }

        #[test]
        fn cleanup_context_keeps_the_primary_typed_reason() {
            let mut cleanup = CleanupFailures::default();
            cleanup.record_message("pasta reap timed out");
            let error = attach_cleanup(
                ProvisionError::startup(
                    StartupStage::Pasta,
                    CaptureTransportDegradationReason::Ipv6Unavailable,
                    "IPv6 route missing",
                ),
                cleanup,
            );
            assert!(matches!(
                error,
                ProvisionError::Startup {
                    reason: CaptureTransportDegradationReason::Ipv6Unavailable,
                    ..
                }
            ));
        }

        #[test]
        fn anonymous_pid_file_is_addressed_through_the_supervisor_proc_fd() {
            let (_file, path) = anonymous_readiness_file().expect("anonymous readiness file");
            assert!(path.starts_with(format!("/proc/{}/fd", std::process::id())));
            let mut writer = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .expect("open anonymous file through supervisor proc fd");
            writer.write_all(b"123\n").expect("write readiness file");
            drop(writer);
            assert_eq!(fs::read_to_string(&path).expect("read proc fd"), "123\n");
            assert!(
                fs::read_link(&path)
                    .expect("read anonymous fd link")
                    .to_string_lossy()
                    .contains("(deleted)")
            );
        }
    }
}
