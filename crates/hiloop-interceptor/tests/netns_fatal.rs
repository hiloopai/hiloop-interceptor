#![cfg(feature = "test-support")]

use std::{
    net::Ipv6Addr,
    num::NonZeroU16,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use hiloop_core::{
    capture::CaptureFatalReason,
    event::{AttributeValue, Event},
    identity::RunContext,
};
use hiloop_interceptor::{
    netns::{
        FatalRunSupervisor, FragmentedUdpBehavior, NamespaceCommand, NetworkProvisioner,
        ProvisionRequest, SubstrateInfo,
        testing::{
            FakeNetworkProvisioner, FakeProvisionerCall, FakeProvisionerHandle, FakeSessionOutcome,
        },
    },
    seams::{ExportError, Exporter},
};
use tokio::sync::{Notify, oneshot};

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

#[derive(Debug)]
struct OrderingExporter {
    provisioner: FakeProvisionerHandle,
    calls_at_export: Mutex<Vec<FakeProvisionerCall>>,
    events: Mutex<Vec<Event>>,
    flushes: AtomicUsize,
}

impl OrderingExporter {
    fn new(provisioner: FakeProvisionerHandle) -> Self {
        Self {
            provisioner,
            calls_at_export: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            flushes: AtomicUsize::new(0),
        }
    }

    fn calls_at_export(&self) -> Vec<FakeProvisionerCall> {
        self.calls_at_export
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
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
    let events = exporter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].name.as_str(), "capture.fatal");
    assert_eq!(
        events[0]
            .attributes
            .iter()
            .find(|(key, _)| key.as_str() == "reason")
            .map(|(_, value)| value),
        Some(&AttributeValue::String("dataplane_failed".to_owned()))
    );
    assert_eq!(exporter.flushes.load(Ordering::SeqCst), 1);
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
    let (fake, handle) = FakeNetworkProvisioner::scripted(
        hiloop_interceptor::netns::PreflightReport::passed(true),
        info(),
        FakeSessionOutcome::DataplaneFailure {
            component: "gateway_worker",
            diagnostic: "fixture crash".to_owned(),
        },
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
    let transition = tokio::spawn(async move { supervisor.wait(session.as_mut()).await });

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
    let fatal = transition
        .await
        .expect("transition task")
        .expect_err("worker crash")
        .into_fatal()
        .expect("typed dataplane fatal");
    assert!(fatal.event_persisted());
}
