use std::{num::NonZeroU8, sync::Arc};

use crate::seams::{ExportError, Exporter};
use hiloop_core::{
    capture::CaptureFatalReason,
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
#[derive(Debug, Error)]
#[error("transparent capture run failed fatally: {result}")]
pub struct FatalRunError {
    result: FatalRunResult,
    substrate_error: Option<ProvisionError>,
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

    /// Underlying worker failure or ordered-cleanup failure, when present.
    pub fn substrate_error(&self) -> Option<&ProvisionError> {
        self.substrate_error.as_ref()
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
            Err(error @ ProvisionError::Dataplane { .. }) => Err(self
                .persist(CaptureFatalReason::DataplaneFailed, Some(error))
                .await
                .into()),
            Err(error) => Err(error.into()),
        }
    }

    async fn persist(
        &self,
        reason: CaptureFatalReason,
        substrate_error: Option<ProvisionError>,
    ) -> FatalRunError {
        let result = FatalRunResult { reason };
        let event = Event::capture_fatal(&self.context, self.clock.tick(), reason);
        let persistence_error = match self.exporter.export(&[event]).await {
            Ok(()) => self.exporter.flush().await.err(),
            Err(error) => Some(error),
        };
        FatalRunError {
            result,
            substrate_error,
            persistence_error,
        }
    }
}
