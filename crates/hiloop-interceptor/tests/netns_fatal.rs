#![cfg(feature = "test-support")]

use std::{
    net::Ipv6Addr,
    num::{NonZeroU8, NonZeroU16},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use hiloop_core::{
    capture::{CaptureFatalReason, OriginalDestination, TlsFlowIdentity},
    event::Event,
    identity::RunContext,
};
use hiloop_interceptor::{
    netns::{
        DataplaneLatch, FatalReport, FatalRunSupervisor, FragmentedUdpBehavior, NamespaceCommand,
        NetworkProvisioner, ProvisionRequest, SubstrateExit, SubstrateInfo,
        testing::{
            FakeNetworkProvisioner, FakeProvisionerCall, FakeProvisionerHandle, FakeSessionOutcome,
        },
    },
    seams::{ExportError, Exporter},
};
use tokio::sync::{Notify, oneshot};

#[cfg(target_os = "linux")]
use hiloop_interceptor::netns::GatewayFatalController;

fn info() -> SubstrateInfo {
    SubstrateInfo::new(
        NonZeroU16::new(15_001).expect("test port is nonzero"),
        1_500,
        "169.254.254.1".parse().expect("test IPv4"),
        "fd00:6869:6c6f:6f70::1".parse().expect("test IPv6"),
        "169.254.2.2".parse().expect("test host IPv4"),
        "fd00:6869:6c6f:6f70:1::2"
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

fn tls_report(reason: CaptureFatalReason) -> FatalReport {
    let destination =
        OriginalDestination::new("203.0.113.10".parse().expect("test destination"), 443)
            .expect("valid destination");
    let flow = TlsFlowIdentity::new(destination)
        .with_server_name("api.example.com")
        .expect("test SNI")
        .with_client_hello_fingerprint("ja4:test")
        .expect("test fingerprint");
    FatalReport::tls(reason, flow)
}

fn teardown_calls(handle: &FakeProvisionerHandle) -> Vec<FakeProvisionerCall> {
    handle
        .calls()
        .into_iter()
        .filter(|call| {
            matches!(
                call,
                FakeProvisionerCall::Shutdown
                    | FakeProvisionerCall::CloseDataplane
                    | FakeProvisionerCall::TerminateNamespace
                    | FakeProvisionerCall::ReapHelpers
            )
        })
        .collect()
}

#[derive(Debug)]
struct OrderingExporter {
    provisioner: FakeProvisionerHandle,
    events: Mutex<Vec<Event>>,
    calls_at_export: Mutex<Vec<FakeProvisionerCall>>,
    flushes: AtomicUsize,
}

impl OrderingExporter {
    fn new(provisioner: FakeProvisionerHandle) -> Self {
        Self {
            provisioner,
            events: Mutex::new(Vec::new()),
            calls_at_export: Mutex::new(Vec::new()),
            flushes: AtomicUsize::new(0),
        }
    }

    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn calls_at_export(&self) -> Vec<FakeProvisionerCall> {
        self.calls_at_export
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn flushes(&self) -> usize {
        self.flushes.load(Ordering::Acquire)
    }
}

#[async_trait]
impl Exporter for OrderingExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        *self
            .calls_at_export
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.provisioner.calls();
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(events);
        Ok(())
    }

    async fn flush(&self) -> Result<(), ExportError> {
        self.flushes.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[tokio::test]
async fn every_secret_fatal_closes_and_reaps_before_durable_nonzero_result() {
    for reason in [
        CaptureFatalReason::SecretBindUnterminatable,
        CaptureFatalReason::SecretRouteAmbiguous,
        CaptureFatalReason::SecretDestinationMismatch,
        CaptureFatalReason::SecretPassthroughForbidden,
        CaptureFatalReason::SecretRouteIdentityMismatch,
        CaptureFatalReason::SecretTransportInsecure,
        CaptureFatalReason::SecretTransportUnsupported,
    ] {
        let (fake, handle) = FakeNetworkProvisioner::passing(
            hiloop_interceptor::netns::PreflightReport::passed(true),
            info(),
            SubstrateExit::Code(0),
        );
        let mut session = fake.provision(request()).await.expect("fake provision");
        let exporter = Arc::new(OrderingExporter::new(handle.clone()));
        let supervisor = FatalRunSupervisor::new(
            RunContext::new_local_root(),
            Arc::<OrderingExporter>::clone(&exporter),
        );

        let fatal = supervisor
            .terminate(session.as_mut(), tls_report(reason))
            .await;

        assert_eq!(fatal.reason(), reason);
        assert_eq!(
            fatal.exit_code(),
            NonZeroU8::new(1).expect("one is nonzero")
        );
        assert!(fatal.event_persisted(), "{reason}");
        assert_eq!(exporter.flushes(), 1, "{reason}");
        assert_eq!(
            teardown_calls(&handle),
            [
                FakeProvisionerCall::Shutdown,
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ],
            "{reason}"
        );
        assert!(
            exporter.calls_at_export().ends_with(&[
                FakeProvisionerCall::CloseDataplane,
                FakeProvisionerCall::TerminateNamespace,
                FakeProvisionerCall::ReapHelpers,
            ]),
            "persistence began before teardown for {reason}"
        );
        let event = serde_json::to_value(&exporter.events()[0]).expect("fatal event JSON");
        assert_eq!(event["name"], "capture.fatal");
        assert_eq!(event["attributes"]["reason"], reason.to_string());
        assert!(event["attributes"].get("secret").is_none());
        assert!(event["attributes"].get("secret.name").is_none());
        assert!(event["attributes"].get("secret.value").is_none());
    }
}

#[tokio::test]
async fn worker_crash_becomes_dataplane_fatal_after_ordered_teardown() {
    let (fake, handle) = FakeNetworkProvisioner::scripted(
        hiloop_interceptor::netns::PreflightReport::passed(true),
        info(),
        FakeSessionOutcome::DataplaneFailure {
            component: "gateway_worker",
            diagnostic: "fixture crash".to_owned(),
        },
    );
    let mut session = fake.provision(request()).await.expect("fake provision");
    let exporter = Arc::new(OrderingExporter::new(handle.clone()));
    let supervisor = FatalRunSupervisor::new(
        RunContext::new_local_root(),
        Arc::<OrderingExporter>::clone(&exporter),
    );

    let error = supervisor
        .wait(session.as_mut())
        .await
        .expect_err("worker crash must fail the run");
    let fatal = error.into_fatal().expect("typed dataplane fatal");

    assert_eq!(fatal.reason(), CaptureFatalReason::DataplaneFailed);
    assert!(fatal.event_persisted());
    assert_eq!(
        &handle.calls()[1..],
        [
            FakeProvisionerCall::Wait,
            FakeProvisionerCall::CloseDataplane,
            FakeProvisionerCall::TerminateNamespace,
            FakeProvisionerCall::ReapHelpers,
        ]
    );
    assert!(
        exporter
            .calls_at_export()
            .ends_with(&[FakeProvisionerCall::ReapHelpers])
    );
}

#[tokio::test]
async fn gateway_fatal_signal_reaches_the_supervisor_only_after_fake_teardown() {
    let report = tls_report(CaptureFatalReason::SecretDestinationMismatch);
    let (fake, handle) = FakeNetworkProvisioner::scripted(
        hiloop_interceptor::netns::PreflightReport::passed(true),
        info(),
        FakeSessionOutcome::Fatal(report),
    );
    let mut session = fake.provision(request()).await.expect("fake provision");
    let exporter = Arc::new(OrderingExporter::new(handle.clone()));
    let supervisor = FatalRunSupervisor::new(
        RunContext::new_local_root(),
        Arc::<OrderingExporter>::clone(&exporter),
    );

    let fatal = supervisor
        .wait(session.as_mut())
        .await
        .expect_err("fatal report must fail the run")
        .into_fatal()
        .expect("typed fatal result");

    assert_eq!(
        fatal.reason(),
        CaptureFatalReason::SecretDestinationMismatch
    );
    assert!(fatal.event_persisted());
    assert!(
        exporter
            .calls_at_export()
            .ends_with(&[FakeProvisionerCall::ReapHelpers])
    );
}

#[derive(Debug)]
struct BlockingExporter {
    provisioner: FakeProvisionerHandle,
    started: Mutex<Option<oneshot::Sender<Vec<FakeProvisionerCall>>>>,
    release: Notify,
}

#[async_trait]
impl Exporter for BlockingExporter {
    async fn export(&self, _events: &[Event]) -> Result<(), ExportError> {
        if let Some(started) = self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = started.send(self.provisioner.calls());
        }
        self.release.notified().await;
        Ok(())
    }
}

#[tokio::test]
async fn event_backpressure_starts_only_after_the_retry_window_is_closed() {
    let (fake, handle) = FakeNetworkProvisioner::passing(
        hiloop_interceptor::netns::PreflightReport::passed(true),
        info(),
        SubstrateExit::Code(0),
    );
    let mut session = fake.provision(request()).await.expect("fake provision");
    let (started_tx, started_rx) = oneshot::channel();
    let exporter = Arc::new(BlockingExporter {
        provisioner: handle,
        started: Mutex::new(Some(started_tx)),
        release: Notify::new(),
    });
    let supervisor = FatalRunSupervisor::new(
        RunContext::new_local_root(),
        Arc::<BlockingExporter>::clone(&exporter),
    );
    let transition = tokio::spawn(async move {
        supervisor
            .terminate(
                session.as_mut(),
                FatalReport::destination(
                    CaptureFatalReason::SecretTransportUnsupported,
                    OriginalDestination::new(
                        "203.0.113.10".parse().expect("test destination"),
                        443,
                    )
                    .expect("valid destination"),
                ),
            )
            .await
    });

    let calls = started_rx.await.expect("export started");
    assert!(calls.ends_with(&[
        FakeProvisionerCall::CloseDataplane,
        FakeProvisionerCall::TerminateNamespace,
        FakeProvisionerCall::ReapHelpers,
    ]));
    assert!(
        !transition.is_finished(),
        "exporter is deliberately blocked"
    );

    exporter.release.notify_one();
    assert!(transition.await.expect("transition task").event_persisted());
}

#[tokio::test]
async fn atomic_latch_cancels_active_flows_and_rejects_later_admission() {
    let latch = DataplaneLatch::new();
    let active = latch.clone();
    let (started_tx, started_rx) = oneshot::channel();
    let flow = tokio::spawn(async move {
        active
            .run(async move {
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
            .await
    });
    started_rx.await.expect("flow started");

    latch.close().await;

    assert!(latch.is_closed());
    assert!(flow.await.expect("flow task").is_err());
    assert!(latch.run(async {}).await.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn gateway_controller_drains_the_latch_before_reporting_fatality() {
    use std::os::unix::net::UnixDatagram;

    let (manager, worker) = UnixDatagram::pair().expect("private control pair");
    manager.set_nonblocking(true).expect("nonblocking manager");
    let manager = tokio::net::UnixDatagram::from_std(manager).expect("async manager");
    let latch = DataplaneLatch::new();
    let controller = GatewayFatalController::new(latch.clone(), &worker).expect("fatal controller");
    let active = latch.clone();
    let (started_tx, started_rx) = oneshot::channel();
    let flow = tokio::spawn(async move {
        active
            .run(async move {
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
            .await
    });
    started_rx.await.expect("flow started");

    controller
        .trigger(&tls_report(CaptureFatalReason::SecretBindUnterminatable))
        .await
        .expect("report fatal");

    assert!(latch.is_closed());
    assert!(flow.await.expect("flow task").is_err());
    let mut frame = [0_u8; 4 * 1024];
    assert!(manager.recv(&mut frame).await.expect("manager report") > 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancelling_a_trigger_waiter_cannot_strand_the_closed_dataplane() {
    use std::os::unix::net::UnixDatagram;

    let (manager, worker) = UnixDatagram::pair().expect("private control pair");
    manager.set_nonblocking(true).expect("nonblocking manager");
    let manager = tokio::net::UnixDatagram::from_std(manager).expect("async manager");
    let controller =
        GatewayFatalController::new(DataplaneLatch::new(), &worker).expect("fatal controller");
    let waiter = {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .trigger(&tls_report(CaptureFatalReason::SecretRouteAmbiguous))
                .await
        })
    };
    tokio::task::yield_now().await;
    waiter.abort();

    let mut frame = [0_u8; 4 * 1024];
    let received =
        tokio::time::timeout(std::time::Duration::from_secs(1), manager.recv(&mut frame))
            .await
            .expect("internally owned report task timed out")
            .expect("manager report");
    assert!(received > 1);
    assert!(controller.latch().is_closed());
}
