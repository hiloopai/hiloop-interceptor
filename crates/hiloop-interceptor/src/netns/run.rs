//! Embeddable transparent-network run composition.

use std::{fmt, process::ExitCode, sync::Arc};

use async_trait::async_trait;
use hiloop_core::{
    capture::{CapturePolicy, CapturePreflight, NetCaptureMode, SelectedNetCaptureMode},
    event::Event,
    identity::{Hlc, RunContext},
};

use crate::supervisor::RunOptions;

use super::PreflightReport;

/// Network transport selected by an embedding CLI after policy and preflight evaluation.
#[derive(Clone)]
pub enum NetworkCapture {
    /// Run without network capture.
    Off,
    /// Run the cooperative environment-proxy transport.
    Proxy {
        requested: NetCaptureMode,
        preflight: Option<PreflightReport>,
    },
    /// Run the production transparent-network composition.
    Netns {
        requested: NetCaptureMode,
        preflight: PreflightReport,
        runner: Arc<dyn NetnsRun>,
    },
}

impl fmt::Debug for NetworkCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => formatter.write_str("Off"),
            Self::Proxy {
                requested,
                preflight,
            } => formatter
                .debug_struct("Proxy")
                .field("requested", requested)
                .field("preflight", preflight)
                .finish(),
            Self::Netns {
                requested,
                preflight,
                ..
            } => formatter
                .debug_struct("Netns")
                .field("requested", requested)
                .field("preflight", preflight)
                .finish_non_exhaustive(),
        }
    }
}

impl NetworkCapture {
    /// Explicitly disable network capture.
    pub const fn off() -> Self {
        Self::Off
    }

    /// Select the cooperative proxy directly, without transparent preflight.
    pub const fn proxy() -> Self {
        Self::Proxy {
            requested: NetCaptureMode::Proxy,
            preflight: None,
        }
    }

    /// Select the cooperative proxy after an observation-only `auto` preflight failed.
    pub fn proxy_fallback(preflight: PreflightReport) -> Self {
        Self::Proxy {
            requested: NetCaptureMode::Auto,
            preflight: Some(preflight),
        }
    }

    /// Select transparent capture with the exact report used by the caller's decision.
    pub fn netns(
        requested: NetCaptureMode,
        preflight: PreflightReport,
        runner: Arc<dyn NetnsRun>,
    ) -> Self {
        Self::Netns {
            requested,
            preflight,
            runner,
        }
    }

    pub(crate) const fn uses_proxy(&self) -> bool {
        matches!(self, Self::Proxy { .. })
    }

    pub(crate) fn netns_runner(&self) -> Option<(&PreflightReport, &Arc<dyn NetnsRun>)> {
        match self {
            Self::Netns {
                preflight, runner, ..
            } => Some((preflight, runner)),
            Self::Off | Self::Proxy { .. } => None,
        }
    }

    /// Build the once-per-run transport event from the exact selection inputs.
    pub fn transport_event(
        &self,
        context: &RunContext,
        timestamp: Hlc,
        capture_policy: CapturePolicy,
    ) -> Event {
        let (requested, selected, report) = match self {
            Self::Off => (NetCaptureMode::Off, SelectedNetCaptureMode::Off, None),
            Self::Proxy {
                requested,
                preflight,
            } => (
                *requested,
                SelectedNetCaptureMode::Proxy,
                preflight.as_ref(),
            ),
            Self::Netns {
                requested,
                preflight,
                ..
            } => (
                *requested,
                if preflight.result() == CapturePreflight::Passed {
                    SelectedNetCaptureMode::Netns
                } else {
                    SelectedNetCaptureMode::None
                },
                Some(preflight),
            ),
        };
        Event::capture_transport(
            context,
            timestamp,
            requested,
            selected,
            capture_policy,
            report.map_or(CapturePreflight::NotApplicable, PreflightReport::result),
            report.is_none_or(PreflightReport::ipv4_available),
            report.is_some_and(PreflightReport::ipv6_available),
            report.and_then(PreflightReport::degradation_reason),
        )
    }
}

/// Production composition port shared by the host-backed runner and deterministic fake.
#[async_trait]
pub trait NetnsRun: Send + Sync {
    /// Exercise every host primitive without starting the requested workload.
    async fn preflight(&self) -> PreflightReport;

    /// Run the wrapped command through the transparent gateway and fatal supervisor.
    async fn run(&self, options: &RunOptions) -> anyhow::Result<ExitCode>;
}
