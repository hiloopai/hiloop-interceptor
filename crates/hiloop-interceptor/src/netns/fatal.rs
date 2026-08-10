use std::{num::NonZeroU8, sync::Arc};

use crate::seams::{ExportError, Exporter};
use hiloop_core::{
    capture::{CaptureEventDelivery, CaptureFatalReason},
    event::Event,
    identity::{HlcClock, RunContext},
};
use thiserror::Error;

use super::{NetworkSession, ProvisionError, SubstrateExit};

/// Terminal nonzero result preserved independently of capture-event delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatalRunResult {
    reason: CaptureFatalReason,
}

impl std::fmt::Display for FatalRunResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(formatter)
    }
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
#[derive(Debug)]
pub struct FatalRunError {
    result: FatalRunResult,
    substrate_error: Option<ProvisionError>,
    persistence: FatalPersistence,
}

impl std::fmt::Display for FatalRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "transparent capture run failed fatally: {}",
            self.result
        )
    }
}

impl std::error::Error for FatalRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.persistence_failure()
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.substrate_error()
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
    }
}

#[derive(Debug)]
enum FatalPersistence {
    Pending,
    Persisted,
    Failed(FatalPersistenceFailure),
}

#[derive(Debug, Default)]
struct FatalPersistenceFailure {
    export: Option<Arc<ExportError>>,
    flush: Option<Arc<ExportError>>,
}

impl std::fmt::Display for FatalPersistenceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.export, &self.flush) {
            (Some(export), Some(flush)) => {
                write!(
                    formatter,
                    "{export}; final exporter flush also failed: {flush}"
                )
            }
            (Some(error), None) | (None, Some(error)) => error.fmt(formatter),
            (None, None) => formatter.write_str("fatal event persistence failed"),
        }
    }
}

impl std::error::Error for FatalPersistenceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.export
            .as_deref()
            .or(self.flush.as_deref())
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
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
        matches!(self.persistence, FatalPersistence::Persisted)
    }

    fn event_delivery(&self) -> CaptureEventDelivery {
        let mut delivery = CaptureEventDelivery {
            observed: 1,
            ..CaptureEventDelivery::default()
        };
        match &self.persistence {
            FatalPersistence::Pending | FatalPersistence::Persisted => delivery.landed = 1,
            FatalPersistence::Failed(FatalPersistenceFailure {
                export: Some(error),
                ..
            }) if matches!(error.as_ref(), ExportError::Rejected { .. }) => {
                delivery.rejected = 1;
            }
            FatalPersistence::Failed(FatalPersistenceFailure {
                export: Some(_), ..
            }) => {
                delivery.dropped = 1;
            }
            FatalPersistence::Failed(FatalPersistenceFailure { export: None, .. }) => {
                delivery.landed = 1;
            }
        }
        delivery
    }

    /// Underlying worker failure or ordered-cleanup failure, when present.
    pub fn substrate_error(&self) -> Option<&ProvisionError> {
        self.substrate_error.as_ref()
    }

    /// Fatal-event export or flush failure, if durability could not be established.
    pub fn persistence_error(&self) -> Option<&ExportError> {
        match &self.persistence {
            FatalPersistence::Failed(failure) => {
                failure.export.as_deref().or(failure.flush.as_deref())
            }
            FatalPersistence::Pending | FatalPersistence::Persisted => None,
        }
    }

    fn persistence_failure(&self) -> Option<&FatalPersistenceFailure> {
        match &self.persistence {
            FatalPersistence::Failed(failure) => Some(failure),
            FatalPersistence::Pending | FatalPersistence::Persisted => None,
        }
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
    pub(crate) fn fatal_event_delivery(&self) -> CaptureEventDelivery {
        match self {
            Self::Fatal(error) => error.event_delivery(),
            Self::Provision(_) => CaptureEventDelivery::default(),
        }
    }

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
        let mut result = self.finish_wait(session.wait().await).await;
        if matches!(result, Err(SupervisedRunError::Fatal(_))) {
            let _ = Self::record_flush(&mut result, self.exporter.flush().await);
        }
        result
    }

    /// Convert a completed session wait into a supervised result without flushing its exporter.
    pub(crate) async fn finish_wait(
        &self,
        result: Result<SubstrateExit, ProvisionError>,
    ) -> Result<SubstrateExit, SupervisedRunError> {
        match result {
            Ok(exit) => Ok(exit),
            Err(error @ ProvisionError::Dataplane { .. }) => Err(self
                .persist(CaptureFatalReason::DataplaneFailed, Some(error))
                .await
                .into()),
            Err(error) => Err(error.into()),
        }
    }

    /// Attach the composing boundary's final flush result to a pending fatal transition.
    pub(crate) fn record_flush(
        result: &mut Result<SubstrateExit, SupervisedRunError>,
        flush: Result<(), ExportError>,
    ) -> Result<(), Arc<ExportError>> {
        let flush = flush.map_err(Arc::new);
        let Err(SupervisedRunError::Fatal(error)) = result else {
            return flush;
        };
        error.persistence = match (&error.persistence, &flush) {
            (FatalPersistence::Pending, Ok(())) | (FatalPersistence::Persisted, _) => {
                FatalPersistence::Persisted
            }
            (FatalPersistence::Pending, Err(flush)) => {
                FatalPersistence::Failed(FatalPersistenceFailure {
                    export: None,
                    flush: Some(Arc::clone(flush)),
                })
            }
            (FatalPersistence::Failed(failure), Err(flush)) => {
                FatalPersistence::Failed(FatalPersistenceFailure {
                    export: failure.export.clone(),
                    flush: Some(Arc::clone(flush)),
                })
            }
            (FatalPersistence::Failed(failure), Ok(())) => {
                FatalPersistence::Failed(FatalPersistenceFailure {
                    export: failure.export.clone(),
                    flush: failure.flush.clone(),
                })
            }
        };
        flush
    }

    async fn persist(
        &self,
        reason: CaptureFatalReason,
        substrate_error: Option<ProvisionError>,
    ) -> FatalRunError {
        let result = FatalRunResult { reason };
        let event = Event::capture_fatal(&self.context, self.clock.tick(), reason);
        let persistence = match self.exporter.export(&[event]).await {
            Ok(()) => FatalPersistence::Pending,
            Err(error) => FatalPersistence::Failed(FatalPersistenceFailure {
                export: Some(Arc::new(error)),
                flush: None,
            }),
        };
        FatalRunError {
            result,
            substrate_error,
            persistence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_fatal_delivery(error: ExportError) -> CaptureEventDelivery {
        FatalRunError {
            result: FatalRunResult {
                reason: CaptureFatalReason::DataplaneFailed,
            },
            substrate_error: None,
            persistence: FatalPersistence::Failed(FatalPersistenceFailure {
                export: Some(Arc::new(error)),
                flush: None,
            }),
        }
        .event_delivery()
    }

    #[test]
    fn generated_fatal_events_remain_observed_when_delivery_fails() {
        assert_eq!(
            failed_fatal_delivery(ExportError::unavailable("fixture", "down")),
            CaptureEventDelivery {
                observed: 1,
                dropped: 1,
                ..CaptureEventDelivery::default()
            }
        );
        assert_eq!(
            failed_fatal_delivery(ExportError::rejected("fixture", "invalid")),
            CaptureEventDelivery {
                observed: 1,
                rejected: 1,
                ..CaptureEventDelivery::default()
            }
        );
    }
}
