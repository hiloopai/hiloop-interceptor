//! Deterministic rootless-substrate fake for dataplane and policy tests.

use std::{
    process::ExitCode,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use hiloop_core::capture::CaptureTransportDegradationReason;

use super::{
    FatalReport, NetnsRun, NetworkProvisioner, NetworkSession, PreflightReport, ProvisionError,
    ProvisionRequest, StartupStage, SubstrateExit, SubstrateInfo, SystemNetworkProvisioner,
};
use crate::supervisor::RunOptions;

/// Force the real provisioner to expose only IPv4 host egress in substrate tests.
#[must_use]
pub fn force_ipv4_only(provisioner: SystemNetworkProvisioner) -> SystemNetworkProvisioner {
    provisioner.force_ipv4_only()
}

/// Force both host IP families for real dual-stack substrate tests.
#[must_use]
pub fn force_dual_stack(provisioner: SystemNetworkProvisioner) -> SystemNetworkProvisioner {
    provisioner.force_dual_stack()
}

/// One observable call through the composed netns-run port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeNetnsRunCall {
    /// Host preflight was requested without starting a child.
    Preflight,
    /// The composed transparent run was invoked.
    Run,
}

/// Cloneable inspection handle for [`FakeNetnsRun`].
#[derive(Debug, Clone)]
pub struct FakeNetnsRunHandle {
    calls: Arc<Mutex<Vec<FakeNetnsRunCall>>>,
}

impl FakeNetnsRunHandle {
    /// Snapshot calls in execution order.
    pub fn calls(&self) -> Vec<FakeNetnsRunCall> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Deterministic implementation of the exact production [`NetnsRun`] port.
#[derive(Debug, Clone)]
pub struct FakeNetnsRun {
    preflight: PreflightReport,
    result: Result<u8, String>,
    calls: Arc<Mutex<Vec<FakeNetnsRunCall>>>,
}

impl FakeNetnsRun {
    /// Script a preflight report and successful process exit byte.
    pub fn exiting(preflight: PreflightReport, exit_code: u8) -> (Self, FakeNetnsRunHandle) {
        Self::new(preflight, Ok(exit_code))
    }

    /// Script a preflight report and composed-run failure.
    pub fn failing(
        preflight: PreflightReport,
        diagnostic: impl Into<String>,
    ) -> (Self, FakeNetnsRunHandle) {
        Self::new(preflight, Err(diagnostic.into()))
    }

    fn new(preflight: PreflightReport, result: Result<u8, String>) -> (Self, FakeNetnsRunHandle) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                preflight,
                result,
                calls: Arc::clone(&calls),
            },
            FakeNetnsRunHandle { calls },
        )
    }

    fn record(&self, call: FakeNetnsRunCall) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(call);
    }
}

#[async_trait]
impl NetnsRun for FakeNetnsRun {
    async fn preflight(&self) -> PreflightReport {
        self.record(FakeNetnsRunCall::Preflight);
        self.preflight.clone()
    }

    async fn run(&self, _options: &RunOptions) -> anyhow::Result<ExitCode> {
        self.record(FakeNetnsRunCall::Run);
        match &self.result {
            Ok(code) => Ok(ExitCode::from(*code)),
            Err(diagnostic) => Err(anyhow::anyhow!(diagnostic.clone())),
        }
    }
}

/// One observable call across the fake provisioner and its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeProvisionerCall {
    /// Actual-operation preflight was requested.
    Preflight,
    /// A topology was requested with the recorded production request.
    Provision(ProvisionRequest),
    /// The caller waited for workload completion.
    Wait,
    /// The caller explicitly shut the topology down.
    Shutdown,
    /// A live fake session was dropped without completing a terminal operation.
    Dropped,
    /// Stop accepting or forwarding traffic before process teardown.
    CloseDataplane,
    /// Terminate the private PID namespace and all of its descendants.
    TerminateNamespace,
    /// Reap the carrier, namespace manager, worker, and workload helpers.
    ReapHelpers,
}

#[derive(Debug, Clone)]
enum FakeProvisionOutcome {
    Session {
        info: SubstrateInfo,
        outcome: FakeSessionOutcome,
    },
    Unavailable {
        reason: CaptureTransportDegradationReason,
        diagnostic: String,
    },
    StartupFailure {
        stage: StartupStage,
        reason: CaptureTransportDegradationReason,
        diagnostic: String,
    },
}

/// Scripted terminal behavior of a fake network session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeSessionOutcome {
    /// The isolated workload completes normally or by signal.
    Exit(SubstrateExit),
    /// A required gateway or carrier process fails after readiness.
    DataplaneFailure {
        /// Low-cardinality component used by the production error contract.
        component: &'static str,
        /// Deterministic test diagnostic.
        diagnostic: String,
    },
    /// Ordered teardown reaches one or more failures after attempting every step.
    CleanupFailure {
        /// Deterministic combined cleanup diagnostic.
        diagnostic: String,
    },
    /// A gateway fatal signal whose ordered cleanup completes before it reaches the supervisor.
    Fatal(FatalReport),
}

/// Cloneable inspection handle for a [`FakeNetworkProvisioner`].
#[derive(Debug, Clone)]
pub struct FakeProvisionerHandle {
    calls: Arc<Mutex<Vec<FakeProvisionerCall>>>,
}

impl FakeProvisionerHandle {
    /// Snapshot calls in execution order.
    pub fn calls(&self) -> Vec<FakeProvisionerCall> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Scriptable implementation of the exact production [`NetworkProvisioner`] port.
#[derive(Debug, Clone)]
pub struct FakeNetworkProvisioner {
    preflight: PreflightReport,
    provision: FakeProvisionOutcome,
    calls: Arc<Mutex<Vec<FakeProvisionerCall>>>,
}

impl FakeNetworkProvisioner {
    /// Return a passing fake that completes with the scripted workload exit.
    pub fn passing(
        preflight: PreflightReport,
        info: SubstrateInfo,
        exit: SubstrateExit,
    ) -> (Self, FakeProvisionerHandle) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                preflight,
                provision: FakeProvisionOutcome::Session {
                    info,
                    outcome: FakeSessionOutcome::Exit(exit),
                },
                calls: Arc::clone(&calls),
            },
            FakeProvisionerHandle { calls },
        )
    }

    /// Return a passing preflight with a scripted runtime or cleanup outcome.
    pub fn scripted(
        preflight: PreflightReport,
        info: SubstrateInfo,
        outcome: FakeSessionOutcome,
    ) -> (Self, FakeProvisionerHandle) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                preflight,
                provision: FakeProvisionOutcome::Session { info, outcome },
                calls: Arc::clone(&calls),
            },
            FakeProvisionerHandle { calls },
        )
    }

    /// Return a fake whose provision operation fails with a closed preflight reason.
    pub fn unavailable(
        preflight: PreflightReport,
        reason: CaptureTransportDegradationReason,
        diagnostic: impl Into<String>,
    ) -> (Self, FakeProvisionerHandle) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                preflight,
                provision: FakeProvisionOutcome::Unavailable {
                    reason,
                    diagnostic: diagnostic.into(),
                },
                calls: Arc::clone(&calls),
            },
            FakeProvisionerHandle { calls },
        )
    }

    /// Return a fake whose provision operation fails after ordered partial-state cleanup.
    pub fn startup_failure(
        preflight: PreflightReport,
        stage: StartupStage,
        reason: CaptureTransportDegradationReason,
        diagnostic: impl Into<String>,
    ) -> (Self, FakeProvisionerHandle) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                preflight,
                provision: FakeProvisionOutcome::StartupFailure {
                    stage,
                    reason,
                    diagnostic: diagnostic.into(),
                },
                calls: Arc::clone(&calls),
            },
            FakeProvisionerHandle { calls },
        )
    }

    fn record(&self, call: FakeProvisionerCall) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(call);
    }

    fn record_cleanup(&self) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend([
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]);
    }
}

#[async_trait]
impl NetworkProvisioner for FakeNetworkProvisioner {
    async fn preflight(&self) -> PreflightReport {
        self.record(FakeProvisionerCall::Preflight);
        self.preflight.clone()
    }

    async fn provision(
        &self,
        request: ProvisionRequest,
    ) -> Result<Box<dyn NetworkSession>, ProvisionError> {
        self.record(FakeProvisionerCall::Provision(request));
        match &self.provision {
            FakeProvisionOutcome::Session { info, outcome } => Ok(Box::new(FakeNetworkSession {
                info: info.clone(),
                outcome: outcome.clone(),
                calls: Arc::clone(&self.calls),
                closed: false,
            })),
            FakeProvisionOutcome::Unavailable { reason, diagnostic } => {
                Err(ProvisionError::unavailable(*reason, diagnostic.clone()))
            }
            FakeProvisionOutcome::StartupFailure {
                stage,
                reason,
                diagnostic,
            } => {
                self.record_cleanup();
                Err(ProvisionError::startup(*stage, *reason, diagnostic.clone()))
            }
        }
    }
}

#[derive(Debug)]
struct FakeNetworkSession {
    info: SubstrateInfo,
    outcome: FakeSessionOutcome,
    calls: Arc<Mutex<Vec<FakeProvisionerCall>>>,
    closed: bool,
}

impl FakeNetworkSession {
    fn record(&self, call: FakeProvisionerCall) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(call);
    }

    fn begin_terminal_operation(&self) -> Result<(), ProvisionError> {
        if self.closed {
            Err(ProvisionError::dataplane(
                "session",
                "fake network session already completed teardown",
            ))
        } else {
            Ok(())
        }
    }

    fn complete_cleanup(&mut self) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend([
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]);
        self.closed = true;
    }
}

#[async_trait]
impl NetworkSession for FakeNetworkSession {
    fn info(&self) -> &SubstrateInfo {
        &self.info
    }

    async fn wait(&mut self) -> Result<SubstrateExit, ProvisionError> {
        self.begin_terminal_operation()?;
        self.record(FakeProvisionerCall::Wait);
        tokio::task::yield_now().await;
        let outcome = self.outcome.clone();
        self.complete_cleanup();
        match outcome {
            FakeSessionOutcome::Exit(exit) => Ok(exit),
            FakeSessionOutcome::Fatal(report) => Err(ProvisionError::fatal(report)),
            FakeSessionOutcome::DataplaneFailure {
                component,
                diagnostic,
            } => Err(ProvisionError::dataplane(component, diagnostic)),
            FakeSessionOutcome::CleanupFailure { diagnostic } => {
                Err(ProvisionError::cleanup(diagnostic))
            }
        }
    }

    async fn shutdown(&mut self) -> Result<(), ProvisionError> {
        self.begin_terminal_operation()?;
        self.record(FakeProvisionerCall::Shutdown);
        let outcome = self.outcome.clone();
        self.complete_cleanup();
        match outcome {
            FakeSessionOutcome::Exit(_) => Ok(()),
            FakeSessionOutcome::Fatal(report) => Err(ProvisionError::fatal(report)),
            FakeSessionOutcome::DataplaneFailure {
                component,
                diagnostic,
            } => Err(ProvisionError::dataplane(component, diagnostic)),
            FakeSessionOutcome::CleanupFailure { diagnostic } => {
                Err(ProvisionError::cleanup(diagnostic))
            }
        }
    }
}

impl Drop for FakeNetworkSession {
    fn drop(&mut self) {
        if !self.closed {
            self.record(FakeProvisionerCall::Dropped);
            self.complete_cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, net::Ipv6Addr, num::NonZeroU16};

    use super::*;
    use crate::netns::{
        FragmentedUdpBehavior, LinuxSignal, MIN_SUBSTRATE_MTU, NamespaceCommand, SubstrateInfoError,
    };

    fn info() -> SubstrateInfo {
        SubstrateInfo::new(
            NonZeroU16::new(15_001).expect("test port is nonzero"),
            1_500,
            "169.254.254.1".parse().expect("test IPv4"),
            "fd00:6869:6c6f:6f70::1".parse().expect("test IPv6"),
            "169.254.2.2".parse().expect("test host IPv4"),
            "fd00:6869:6c6f:6f71::2"
                .parse::<Ipv6Addr>()
                .expect("test host IPv6"),
            FragmentedUdpBehavior::Drop,
        )
        .expect("valid test substrate info")
    }

    fn request() -> ProvisionRequest {
        ProvisionRequest::new(
            NamespaceCommand::new("workload-fixture"),
            NamespaceCommand::new("worker-fixture"),
        )
    }

    #[tokio::test]
    async fn fake_implements_preflight_provision_and_wait_port() {
        let (fake, handle) = FakeNetworkProvisioner::passing(
            PreflightReport::passed(true),
            info(),
            SubstrateExit::Code(23),
        );
        let request = request();

        assert_eq!(fake.preflight().await, PreflightReport::passed(true));
        let mut session = fake
            .provision(request.clone())
            .await
            .expect("fake provision");
        assert_eq!(session.info(), &info());
        assert_eq!(
            session.wait().await.expect("fake wait"),
            SubstrateExit::Code(23)
        );
        assert_eq!(
            handle.calls(),
            [
                FakeProvisionerCall::Preflight,
                FakeProvisionerCall::Provision(request),
                FakeProvisionerCall::Wait,
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]
        );
    }

    #[tokio::test]
    async fn dropping_a_live_fake_session_is_observable() {
        let (fake, handle) = FakeNetworkProvisioner::passing(
            PreflightReport::passed(false),
            info(),
            SubstrateExit::Code(0),
        );
        let session = fake.provision(request()).await.expect("fake provision");
        drop(session);

        assert_eq!(
            &handle.calls()[1..],
            [
                FakeProvisionerCall::Dropped,
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]
        );
    }

    #[tokio::test]
    async fn fake_scripts_worker_crashes_and_cleanup_failures() {
        let (worker_crash, _) = FakeNetworkProvisioner::scripted(
            PreflightReport::passed(true),
            info(),
            FakeSessionOutcome::DataplaneFailure {
                component: "gateway_worker",
                diagnostic: "fixture crash".to_owned(),
            },
        );
        let mut session = worker_crash
            .provision(request())
            .await
            .expect("fake provision");
        assert!(matches!(
            session.wait().await,
            Err(ProvisionError::Dataplane {
                component: "gateway_worker",
                ..
            })
        ));

        let (cleanup_failure, _) = FakeNetworkProvisioner::scripted(
            PreflightReport::passed(true),
            info(),
            FakeSessionOutcome::CleanupFailure {
                diagnostic: "fixture cleanup".to_owned(),
            },
        );
        let mut session = cleanup_failure
            .provision(request())
            .await
            .expect("fake provision");
        assert!(matches!(
            session.shutdown().await,
            Err(ProvisionError::Cleanup { .. })
        ));
    }

    #[tokio::test]
    async fn cancelled_wait_can_be_followed_by_ordered_shutdown() {
        let (fake, handle) = FakeNetworkProvisioner::passing(
            PreflightReport::passed(true),
            info(),
            SubstrateExit::Code(0),
        );
        let requested = request();
        let mut session = fake
            .provision(requested.clone())
            .await
            .expect("fake provision");

        let mut wait = Box::pin(session.wait());
        let mut cancellation = Box::pin(tokio::task::yield_now());
        tokio::select! {
            biased;
            () = &mut cancellation => {}
            result = &mut wait => panic!("wait completed before cancellation: {result:?}"),
        }
        drop(wait);
        session
            .shutdown()
            .await
            .expect("shutdown after cancellation");

        assert_eq!(
            handle.calls(),
            [
                FakeProvisionerCall::Provision(requested),
                FakeProvisionerCall::Wait,
                FakeProvisionerCall::Shutdown,
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]
        );
    }

    #[tokio::test]
    async fn startup_failure_and_shutdown_crash_preserve_typed_outcomes_and_cleanup_order() {
        let (startup, startup_handle) = FakeNetworkProvisioner::startup_failure(
            PreflightReport::passed(true),
            StartupStage::GatewayWorker,
            CaptureTransportDegradationReason::NetnsStartupFailed,
            "worker readiness failed",
        );
        let requested = request();
        let error = startup
            .provision(requested.clone())
            .await
            .err()
            .expect("startup must fail");
        assert!(matches!(
            error,
            ProvisionError::Startup {
                stage: StartupStage::GatewayWorker,
                ..
            }
        ));
        assert_eq!(
            startup_handle.calls(),
            [
                FakeProvisionerCall::Provision(requested),
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]
        );

        let (crash, crash_handle) = FakeNetworkProvisioner::scripted(
            PreflightReport::passed(true),
            info(),
            FakeSessionOutcome::DataplaneFailure {
                component: "pasta",
                diagnostic: "fixture crash".to_owned(),
            },
        );
        let requested = request();
        let mut session = crash
            .provision(requested.clone())
            .await
            .expect("fake provision");
        assert!(matches!(
            session.shutdown().await,
            Err(ProvisionError::Dataplane {
                component: "pasta",
                ..
            })
        ));
        assert_eq!(
            crash_handle.calls(),
            [
                FakeProvisionerCall::Provision(requested),
                FakeProvisionerCall::Shutdown,
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]
        );
    }

    #[test]
    fn preflight_and_substrate_facts_exclude_invalid_states() {
        let passed = PreflightReport::passed(false);
        assert!(passed.ipv4_available());
        assert!(!passed.ipv6_available());

        let valid = info();
        let error = SubstrateInfo::new(
            valid.intercept_port(),
            MIN_SUBSTRATE_MTU - 1,
            valid.gateway_ipv4(),
            valid.gateway_ipv6(),
            valid.host_loopback_ipv4(),
            valid.host_loopback_ipv6(),
            valid.fragmented_udp_behavior(),
        )
        .expect_err("undersized MTU must fail");
        assert_eq!(
            error,
            SubstrateInfoError::MtuTooSmall {
                mtu: MIN_SUBSTRATE_MTU - 1
            }
        );

        for (field, gateway_ipv4, gateway_ipv6, host_ipv4, host_ipv6) in [
            (
                "gateway_ipv4",
                "0.0.0.0",
                "fd00:6869:6c6f:6f70::1",
                "169.254.2.2",
                "fd00:6869:6c6f:6f71::2",
            ),
            (
                "gateway_ipv6",
                "169.254.254.1",
                "ff02::1",
                "169.254.2.2",
                "fd00:6869:6c6f:6f71::2",
            ),
            (
                "host_loopback_ipv4",
                "169.254.254.1",
                "fd00:6869:6c6f:6f70::1",
                "127.0.0.1",
                "fd00:6869:6c6f:6f71::2",
            ),
        ] {
            let error = SubstrateInfo::new(
                valid.intercept_port(),
                valid.mtu(),
                gateway_ipv4.parse().expect("test IPv4"),
                gateway_ipv6.parse().expect("test IPv6"),
                host_ipv4.parse().expect("test host IPv4"),
                host_ipv6.parse().expect("test host IPv6"),
                valid.fragmented_udp_behavior(),
            )
            .expect_err("invalid address must fail");
            assert!(matches!(
                error,
                SubstrateInfoError::InvalidAddress {
                    field: actual,
                    ..
                } if actual == field
            ));
        }

        let error = SubstrateInfo::new(
            valid.intercept_port(),
            valid.mtu(),
            valid.gateway_ipv4(),
            valid.gateway_ipv6(),
            valid.gateway_ipv4(),
            valid.host_loopback_ipv6(),
            valid.fragmented_udp_behavior(),
        )
        .expect_err("duplicate IPv4 roles must fail");
        assert!(matches!(error, SubstrateInfoError::DuplicateAddress { .. }));
    }

    #[test]
    fn signals_and_provision_sources_are_validated_and_preserved() {
        for value in [1, 9, 64] {
            assert_eq!(LinuxSignal::new(value).expect("valid signal").get(), value);
        }
        for value in [i32::MIN, -1, 0, 65, i32::MAX] {
            assert_eq!(
                LinuxSignal::new(value).expect_err("invalid signal").value(),
                value
            );
        }

        let error = ProvisionError::cleanup_with_source(
            "fixture cleanup",
            std::io::Error::other("fixture source"),
        );
        assert_eq!(
            error.source().expect("source chain").to_string(),
            "fixture source"
        );
    }
}
