use std::{future::Future, num::NonZeroU8, sync::Arc};

#[cfg(target_os = "linux")]
use std::os::unix::net::UnixDatagram;

use hiloop_core::{
    capture::{CaptureFatalReason, OriginalDestination, TlsFlowIdentity},
    event::Event,
    identity::{Hlc, HlcClock, RunContext},
};
use thiserror::Error;
use tokio::sync::watch;

use crate::seams::{ExportError, Exporter};

#[cfg(target_os = "linux")]
use super::protocol::encode_gateway_fatal;
use super::{NetworkSession, ProvisionError, SubstrateExit};

/// Route metadata safe to carry from the gateway into a fatal event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FatalRoute {
    None,
    Tls(TlsFlowIdentity),
    Destination(OriginalDestination),
}

/// Typed fatal cause sent by the dataplane after it has stopped application traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatalReport {
    reason: CaptureFatalReason,
    route: FatalRoute,
}

impl FatalReport {
    /// Report a fatal TLS route with its pre-request routing identity.
    pub fn tls(reason: CaptureFatalReason, flow: TlsFlowIdentity) -> Self {
        Self {
            reason,
            route: FatalRoute::Tls(flow),
        }
    }

    /// Report a fatal opaque transport using only its original destination.
    pub fn destination(reason: CaptureFatalReason, destination: OriginalDestination) -> Self {
        Self {
            reason,
            route: FatalRoute::Destination(destination),
        }
    }

    /// Report a run-level dataplane failure for which no safe route identity exists.
    pub fn without_route(reason: CaptureFatalReason) -> Self {
        Self {
            reason,
            route: FatalRoute::None,
        }
    }

    /// Closed reason returned as the run's terminal result.
    pub fn reason(&self) -> CaptureFatalReason {
        self.reason
    }

    pub(super) fn from_route(reason: CaptureFatalReason, route: FatalRoute) -> Self {
        Self { reason, route }
    }

    pub(super) fn route(&self) -> &FatalRoute {
        &self.route
    }

    pub(super) fn event(&self, context: &RunContext, timestamp: Hlc) -> Event {
        match &self.route {
            FatalRoute::None => Event::capture_fatal(context, timestamp, self.reason, None),
            FatalRoute::Tls(flow) => {
                Event::capture_fatal(context, timestamp, self.reason, Some(flow.clone()))
            }
            FatalRoute::Destination(destination) => {
                Event::capture_fatal_for_destination(context, timestamp, self.reason, *destination)
            }
        }
    }
}

#[derive(Debug, Default)]
struct LatchState {
    closed: bool,
    active: usize,
}

#[derive(Debug)]
struct LatchInner {
    state: std::sync::Mutex<LatchState>,
    closed_tx: watch::Sender<bool>,
    active_tx: watch::Sender<usize>,
}

/// Run-wide close barrier shared by accept loops and every active application flow.
///
/// Work admitted with [`Self::run`] is cancelled when the latch closes. Closing waits until every
/// admitted future has been dropped, so the caller can acknowledge a drained dataplane before
/// namespace teardown begins.
#[derive(Debug, Clone)]
pub struct DataplaneLatch {
    inner: Arc<LatchInner>,
}

impl Default for DataplaneLatch {
    fn default() -> Self {
        Self::new()
    }
}

impl DataplaneLatch {
    /// Create an open latch with no active flows.
    pub fn new() -> Self {
        let (closed_tx, _) = watch::channel(false);
        let (active_tx, _) = watch::channel(0);
        Self {
            inner: Arc::new(LatchInner {
                state: std::sync::Mutex::new(LatchState::default()),
                closed_tx,
                active_tx,
            }),
        }
    }

    /// Whether the run-wide dataplane has irreversibly transitioned closed.
    pub fn is_closed(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
    }

    /// Admit one flow while open and cancel it during the close transition.
    pub async fn run<F>(&self, future: F) -> Result<F::Output, DataplaneClosed>
    where
        F: Future,
    {
        let mut closed_rx = self.inner.closed_tx.subscribe();
        let guard = self.enter()?;
        tokio::pin!(future);
        let result = tokio::select! {
            biased;
            changed = closed_rx.changed() => {
                let _ = changed;
                Err(DataplaneClosed)
            }
            output = &mut future => Ok(output),
        };
        drop(guard);
        result
    }

    /// Irreversibly stop admission, cancel active work, and await the drained acknowledgement.
    pub async fn close(&self) {
        let mut active_rx = self.inner.active_tx.subscribe();
        let changed = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let changed = !state.closed;
            state.closed = true;
            changed
        };
        if changed {
            self.inner.closed_tx.send_replace(true);
        }
        loop {
            if self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active
                == 0
            {
                return;
            }
            if active_rx.changed().await.is_err() {
                return;
            }
        }
    }

    fn enter(&self) -> Result<ActiveFlow, DataplaneClosed> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(DataplaneClosed);
        }
        state.active += 1;
        Ok(ActiveFlow {
            inner: Arc::clone(&self.inner),
        })
    }
}

#[derive(Debug)]
struct ActiveFlow {
    inner: Arc<LatchInner>,
}

impl Drop for ActiveFlow {
    fn drop(&mut self) {
        let drained = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active = state.active.saturating_sub(1);
            state.active == 0
        };
        if drained {
            self.inner.active_tx.send_replace(0);
        } else {
            self.inner.active_tx.send_replace(
                self.inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .active,
            );
        }
    }
}

/// A flow tried to enter or continue after the fatal close transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("transparent capture dataplane is closed")]
pub struct DataplaneClosed;

/// Gateway-side fatal sender that reports only after the shared dataplane has drained.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct GatewayFatalController {
    latch: DataplaneLatch,
    control: tokio::net::UnixDatagram,
    reported: std::sync::atomic::AtomicBool,
}

#[cfg(target_os = "linux")]
impl GatewayFatalController {
    /// Clone the namespace-manager broker without taking it away from the UDP reply seam.
    pub fn new(latch: DataplaneLatch, broker: &UnixDatagram) -> std::io::Result<Self> {
        let control = broker.try_clone()?;
        control.set_nonblocking(true)?;
        Ok(Self {
            latch,
            control: tokio::net::UnixDatagram::from_std(control)?,
            reported: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Latch and drain all application work, then send the first fatal report to the manager.
    pub async fn trigger(&self, report: &FatalReport) -> Result<(), GatewayFatalError> {
        let first = !self
            .reported
            .swap(true, std::sync::atomic::Ordering::AcqRel);
        self.latch.close().await;
        if !first {
            return Ok(());
        }
        let frame = encode_gateway_fatal(report)?;
        let sent = self.control.send(&frame).await?;
        if sent != frame.len() {
            return Err(GatewayFatalError::PartialDatagram {
                expected: frame.len(),
                actual: sent,
            });
        }
        Ok(())
    }

    /// Shared latch that accept loops and active flows must use for admission.
    pub fn latch(&self) -> &DataplaneLatch {
        &self.latch
    }
}

/// Failure to report a fatal cause after the local dataplane was already closed.
#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
pub enum GatewayFatalError {
    /// The private manager channel failed after the latch closed.
    #[error("send gateway fatal report: {0}")]
    Io(#[from] std::io::Error),
    /// A Unix datagram did not preserve its required atomic write.
    #[error("gateway fatal datagram was partially sent: {actual}/{expected} bytes")]
    PartialDatagram {
        /// Complete encoded report length.
        expected: usize,
        /// Bytes accepted by the socket.
        actual: usize,
    },
}

/// Terminal nonzero result preserved independently of capture-event delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatalRunResult {
    reason: CaptureFatalReason,
}

impl FatalRunResult {
    /// Closed fatal reason matching the persisted `capture.fatal` event.
    pub fn reason(self) -> CaptureFatalReason {
        self.reason
    }

    /// Stable nonzero process result for a supervised fatal transition.
    pub fn exit_code(self) -> NonZeroU8 {
        NonZeroU8::MIN
    }
}

/// Completed fatal transition, including any loud teardown or durability failure.
#[derive(Debug, Error)]
#[error("transparent capture run failed fatally: {result_reason}")]
pub struct FatalRunError {
    result: FatalRunResult,
    result_reason: CaptureFatalReason,
    teardown_error: Option<ProvisionError>,
    persistence_error: Option<ExportError>,
}

impl FatalRunError {
    /// Fatal reason returned to the run caller.
    pub fn reason(&self) -> CaptureFatalReason {
        self.result.reason()
    }

    /// Matching nonzero run result.
    pub fn exit_code(&self) -> NonZeroU8 {
        self.result.exit_code()
    }

    /// True only after direct export and flush both completed successfully.
    pub fn event_persisted(&self) -> bool {
        self.persistence_error.is_none()
    }

    /// Ordered substrate teardown failure, if cleanup could not remove every resource.
    pub fn teardown_error(&self) -> Option<&ProvisionError> {
        self.teardown_error.as_ref()
    }

    /// Fatal-event export or flush failure, if durability could not be established.
    pub fn persistence_error(&self) -> Option<&ExportError> {
        self.persistence_error.as_ref()
    }
}

/// A supervised network session failed before producing a normal workload exit.
#[derive(Debug, Error)]
pub enum SupervisedRunError {
    /// The close-first fatal invariant completed and returned a nonzero result.
    #[error(transparent)]
    Fatal(#[from] FatalRunError),
    /// A non-fatal substrate operation failed.
    #[error(transparent)]
    Provision(#[from] ProvisionError),
}

impl SupervisedRunError {
    /// Consume the wrapper error when it represents a typed fatal transition.
    pub fn into_fatal(self) -> Option<FatalRunError> {
        match self {
            Self::Fatal(error) => Some(error),
            Self::Provision(_) => None,
        }
    }
}

/// Outer supervisor that tears transport down before directly persisting a fatal result.
pub struct FatalRunSupervisor {
    context: RunContext,
    clock: HlcClock,
    exporter: Arc<dyn Exporter>,
}

impl std::fmt::Debug for FatalRunSupervisor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FatalRunSupervisor")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl FatalRunSupervisor {
    /// Bind one run context to the durability sink used for fatal events.
    pub fn new(context: RunContext, exporter: Arc<dyn Exporter>) -> Self {
        Self {
            context,
            clock: HlcClock::new(),
            exporter,
        }
    }

    /// Wait for a normal exit or convert a post-cleanup dataplane failure into a typed fatal.
    pub async fn wait(
        &self,
        session: &mut dyn NetworkSession,
    ) -> Result<SubstrateExit, SupervisedRunError> {
        match session.wait().await {
            Ok(exit) => Ok(exit),
            Err(ProvisionError::Fatal {
                report,
                cleanup_diagnostic,
            }) => {
                let teardown_error = cleanup_diagnostic.map(ProvisionError::cleanup);
                Err(self.persist(report, teardown_error).await.into())
            }
            Err(error @ ProvisionError::Dataplane { .. }) => Err(self
                .persist(
                    FatalReport::without_route(CaptureFatalReason::DataplaneFailed),
                    Some(error),
                )
                .await
                .into()),
            Err(error) => Err(error.into()),
        }
    }

    /// Close the veth and PID namespace before persisting an already-latched fatal report.
    pub async fn terminate(
        &self,
        session: &mut dyn NetworkSession,
        report: FatalReport,
    ) -> FatalRunError {
        let teardown_error = session.shutdown().await.err();
        self.persist(report, teardown_error).await
    }

    async fn persist(
        &self,
        report: FatalReport,
        teardown_error: Option<ProvisionError>,
    ) -> FatalRunError {
        let result = FatalRunResult {
            reason: report.reason(),
        };
        let event = report.event(&self.context, self.clock.tick());
        let persistence_error = match self.exporter.export(&[event]).await {
            Ok(()) => self.exporter.flush().await.err(),
            Err(error) => Some(error),
        };
        FatalRunError {
            result,
            result_reason: result.reason(),
            teardown_error,
            persistence_error,
        }
    }
}
