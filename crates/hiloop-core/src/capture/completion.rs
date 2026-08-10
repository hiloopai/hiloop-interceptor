//! Capture-process completion truth and its canonical Event-v1 projection.

use std::fmt;

use crate::{
    event::{AttributeKey, Event, EventName, SignalType},
    identity::{Hlc, RunContext},
};

string_enum! {
    /// Authority class for one source's capture evidence.
    pub enum CaptureEvidenceTrust {
        /// The capture runtime observed the source independently of workload instrumentation.
        PlatformObserved => "platform_observed",
        /// The workload or one of its SDKs reported the source to capture.
        WorkloadReported => "workload_reported",
    }
}

string_enum! {
    /// Closed degradation reasons carried by the capture-completion summary.
    pub enum CaptureSourceDegradation {
        /// The source failed while it was being attached.
        StartupFailed => "startup_failed",
        /// The attached source failed before capture completed.
        RuntimeFailed => "runtime_failed",
        /// Network traffic was observable only as transport metadata.
        OpaqueNetworkTraffic => "opaque_network_traffic",
    }
}

/// Final state of one configured capture source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureSourceState {
    /// Capture was deliberately disabled by policy/configuration.
    OffByPolicy,
    /// Capture was requested but the source could not remain attached.
    ConfiguredUnavailable {
        /// Typed reason the source was unavailable.
        reason: CaptureSourceDegradation,
    },
    /// The source remained attached and observed no data.
    AttachedNoData,
    /// Every observation carried the source's full supported fidelity.
    AttachedFull {
        /// Observations accepted from the source.
        observations: u64,
    },
    /// Every observation was limited to metadata.
    AttachedMetadataOnly {
        /// Metadata-only observations accepted from the source.
        observations: u64,
        /// Typed reason payload/content capture was unavailable.
        reason: CaptureSourceDegradation,
    },
    /// The source observed both full-fidelity and metadata-only traffic.
    AttachedMixed {
        /// Full-fidelity observations.
        full_observations: u64,
        /// Metadata-only observations.
        metadata_only_observations: u64,
        /// Typed reason some observations were metadata-only.
        reason: CaptureSourceDegradation,
    },
}

impl CaptureSourceState {
    fn name(&self) -> &'static str {
        match self {
            Self::OffByPolicy => "off_by_policy",
            Self::ConfiguredUnavailable { .. } => "configured_unavailable",
            Self::AttachedNoData => "attached_no_data",
            Self::AttachedFull { .. } => "attached_full",
            Self::AttachedMetadataOnly { .. } => "attached_metadata_only",
            Self::AttachedMixed { .. } => "attached_mixed",
        }
    }

    fn is_unavailable(&self) -> bool {
        matches!(self, Self::ConfiguredUnavailable { .. })
    }
}

/// Trust and final fidelity for one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSourceReport {
    /// Authority class for this source's evidence.
    pub trust: CaptureEvidenceTrust,
    /// Final source state.
    pub state: CaptureSourceState,
}

impl CaptureSourceReport {
    /// Report a deliberately disabled source.
    pub const fn off_by_policy(trust: CaptureEvidenceTrust) -> Self {
        Self {
            trust,
            state: CaptureSourceState::OffByPolicy,
        }
    }

    /// Report a configured source that could not remain attached.
    pub const fn configured_unavailable(
        trust: CaptureEvidenceTrust,
        reason: CaptureSourceDegradation,
    ) -> Self {
        Self {
            trust,
            state: CaptureSourceState::ConfiguredUnavailable { reason },
        }
    }

    /// Report an attached source with no observations.
    pub const fn attached_no_data(trust: CaptureEvidenceTrust) -> Self {
        Self {
            trust,
            state: CaptureSourceState::AttachedNoData,
        }
    }

    /// Report an attached source whose observations had full supported fidelity.
    pub const fn attached_full(trust: CaptureEvidenceTrust, observations: u64) -> Self {
        Self {
            trust,
            state: CaptureSourceState::AttachedFull { observations },
        }
    }

    /// Report an attached source whose observations were metadata-only.
    pub const fn attached_metadata_only(
        trust: CaptureEvidenceTrust,
        observations: u64,
        reason: CaptureSourceDegradation,
    ) -> Self {
        Self {
            trust,
            state: CaptureSourceState::AttachedMetadataOnly {
                observations,
                reason,
            },
        }
    }

    /// Report an attached source with mixed full and metadata-only observations.
    pub const fn attached_mixed(
        trust: CaptureEvidenceTrust,
        full_observations: u64,
        metadata_only_observations: u64,
        reason: CaptureSourceDegradation,
    ) -> Self {
        Self {
            trust,
            state: CaptureSourceState::AttachedMixed {
                full_observations,
                metadata_only_observations,
                reason,
            },
        }
    }
}

/// Fixed source coverage for one capture process session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSourcesReport {
    /// Process lifecycle source.
    pub process: CaptureSourceReport,
    /// Standard input/output source.
    pub stdio: CaptureSourceReport,
    /// Network source.
    pub network: CaptureSourceReport,
    /// Workload OTLP source.
    pub otlp: CaptureSourceReport,
}

impl CaptureSourcesReport {
    fn has_unavailable_source(&self) -> bool {
        [&self.process, &self.stdio, &self.network, &self.otlp]
            .into_iter()
            .any(|source| source.state.is_unavailable())
    }
}

/// Event delivery accounting at completion-record mint time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CaptureEventDelivery {
    /// Events normalized by the capture pipeline.
    pub observed: u64,
    /// Events that entered retry spooling at least once.
    pub spooled: u64,
    /// Events confirmed durable or ordered ahead of this durable completion record.
    pub landed: u64,
    /// Events evicted when the bounded spool filled.
    pub dropped: u64,
    /// Events permanently rejected by the sink.
    pub rejected: u64,
    /// Events awaiting ordered redelivery when the record was minted.
    pub pending: u64,
}

/// Payload-blob delivery accounting at completion-record mint time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CaptureBlobDelivery {
    /// Finalized blobs found by the capture process.
    pub found: u64,
    /// Blobs confirmed durable at the sink.
    pub landed: u64,
    /// Uploadable blobs not confirmed durable.
    pub missing: u64,
    /// Blobs rejected because they exceeded the upload cap.
    pub oversize: u64,
    /// Bytes represented by missing blobs.
    pub missing_bytes: u64,
}

/// Typed, unconditional completion report shared by local and managed capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureCompletionReport {
    /// Final source coverage and fidelity.
    pub sources: CaptureSourcesReport,
    /// Event delivery outcome.
    pub events: CaptureEventDelivery,
    /// Blob delivery outcome when capture used an out-of-row blob store.
    pub blobs: Option<CaptureBlobDelivery>,
    /// Mid-session gateway credential refreshes, when applicable.
    pub auth_refreshes: Option<u64>,
    /// Terminal capture error, if any.
    pub error: Option<String>,
}

impl CaptureCompletionReport {
    /// True only when every configured source stayed available and no event/blob was lost.
    ///
    /// Pending events do not count as loss for the local ordered-spool projection: this record
    /// queues behind them, so its own durable arrival certifies that backlog. Managed capture
    /// emits completion only after its final drain and therefore reports zero pending events.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.error.is_none()
            && !self.sources.has_unavailable_source()
            && self.events.dropped == 0
            && self.events.rejected == 0
            && self
                .blobs
                .is_none_or(|blobs| blobs.missing == 0 && blobs.oversize == 0)
    }

    /// Build the canonical Event-v1 projection of this report.
    #[must_use]
    pub fn to_event(&self, context: &RunContext, ts: Hlc) -> Event {
        let mut event = Event::new(
            context,
            ts,
            SignalType::Log,
            EventName::from_static("capture.drain"),
        );
        event = with_source_report(event, "process", &self.sources.process);
        event = with_source_report(event, "stdio", &self.sources.stdio);
        event = with_source_report(event, "network", &self.sources.network);
        event = with_source_report(event, "otlp", &self.sources.otlp);
        event = event
            .with_attribute(
                AttributeKey::from_static("capture.events.observed"),
                event_count(self.events.observed),
            )
            .with_attribute(
                AttributeKey::from_static("capture.events.spooled"),
                event_count(self.events.spooled),
            )
            .with_attribute(
                AttributeKey::from_static("capture.events.landed"),
                event_count(self.events.landed),
            )
            .with_attribute(
                AttributeKey::from_static("capture.events.dropped"),
                event_count(self.events.dropped),
            )
            .with_attribute(
                AttributeKey::from_static("capture.events.rejected"),
                event_count(self.events.rejected),
            )
            .with_attribute(
                AttributeKey::from_static("capture.events.pending"),
                event_count(self.events.pending),
            );
        if let Some(blobs) = self.blobs {
            event = event
                .with_attribute(
                    AttributeKey::from_static("capture.blobs.found"),
                    event_count(blobs.found),
                )
                .with_attribute(
                    AttributeKey::from_static("capture.blobs.landed"),
                    event_count(blobs.landed),
                )
                .with_attribute(
                    AttributeKey::from_static("capture.blobs.missing"),
                    event_count(blobs.missing),
                )
                .with_attribute(
                    AttributeKey::from_static("capture.blobs.oversize"),
                    event_count(blobs.oversize),
                )
                .with_attribute(
                    AttributeKey::from_static("capture.blobs.missing_bytes"),
                    event_count(blobs.missing_bytes),
                );
        }
        if let Some(refreshes) = self.auth_refreshes {
            event = event.with_attribute(
                AttributeKey::from_static("capture.auth.refreshes"),
                event_count(refreshes),
            );
        }
        if let Some(error) = &self.error {
            event =
                event.with_attribute(AttributeKey::from_static("capture.error"), error.as_str());
        }
        event.with_attribute(
            AttributeKey::from_static("capture.complete"),
            self.is_complete(),
        )
    }
}

fn event_count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn source_key(source: &'static str, field: &'static str) -> AttributeKey {
    AttributeKey::new(format!("capture.source.{source}.{field}"))
        .expect("fixed capture source attribute key")
}

fn with_source_report(
    mut event: Event,
    source: &'static str,
    report: &CaptureSourceReport,
) -> Event {
    event = event
        .with_attribute(source_key(source, "trust"), report.trust.to_string())
        .with_attribute(source_key(source, "state"), report.state.name());
    match report.state {
        CaptureSourceState::OffByPolicy | CaptureSourceState::AttachedNoData => event,
        CaptureSourceState::ConfiguredUnavailable { reason } => {
            event.with_attribute(source_key(source, "degradation"), reason.to_string())
        }
        CaptureSourceState::AttachedFull { observations } => event.with_attribute(
            source_key(source, "observations"),
            event_count(observations),
        ),
        CaptureSourceState::AttachedMetadataOnly {
            observations,
            reason,
        } => event
            .with_attribute(
                source_key(source, "observations"),
                event_count(observations),
            )
            .with_attribute(source_key(source, "degradation"), reason.to_string()),
        CaptureSourceState::AttachedMixed {
            full_observations,
            metadata_only_observations,
            reason,
        } => event
            .with_attribute(
                source_key(source, "full_observations"),
                event_count(full_observations),
            )
            .with_attribute(
                source_key(source, "metadata_only_observations"),
                event_count(metadata_only_observations),
            )
            .with_attribute(source_key(source, "degradation"), reason.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AttributeValue;

    fn attr<'a>(event: &'a Event, key: &'static str) -> &'a AttributeValue {
        event
            .attributes
            .get(&AttributeKey::from_static(key))
            .expect("capture completion attribute")
    }

    #[test]
    fn zero_activity_is_explicit_without_claiming_missing_capture() {
        let report = CaptureCompletionReport {
            sources: CaptureSourcesReport {
                process: CaptureSourceReport::attached_full(
                    CaptureEvidenceTrust::PlatformObserved,
                    2,
                ),
                stdio: CaptureSourceReport::attached_no_data(
                    CaptureEvidenceTrust::PlatformObserved,
                ),
                network: CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                otlp: CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::WorkloadReported),
            },
            events: CaptureEventDelivery {
                observed: 2,
                landed: 2,
                ..CaptureEventDelivery::default()
            },
            blobs: None,
            auth_refreshes: None,
            error: None,
        };

        let event = report.to_event(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 7,
                logical: 0,
            },
        );

        assert_eq!(event.name.as_str(), "capture.drain");
        assert_eq!(
            attr(&event, "capture.complete"),
            &AttributeValue::Bool(true)
        );
        assert_eq!(
            attr(&event, "capture.source.otlp.state"),
            &AttributeValue::String("attached_no_data".to_owned())
        );
        assert_eq!(
            attr(&event, "capture.source.otlp.trust"),
            &AttributeValue::String("workload_reported".to_owned())
        );
    }

    #[test]
    fn metadata_only_network_capture_is_truthful_but_delivery_complete() {
        let report = CaptureCompletionReport {
            sources: CaptureSourcesReport {
                process: CaptureSourceReport::attached_no_data(
                    CaptureEvidenceTrust::PlatformObserved,
                ),
                stdio: CaptureSourceReport::attached_no_data(
                    CaptureEvidenceTrust::PlatformObserved,
                ),
                network: CaptureSourceReport::attached_metadata_only(
                    CaptureEvidenceTrust::PlatformObserved,
                    3,
                    CaptureSourceDegradation::OpaqueNetworkTraffic,
                ),
                otlp: CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            },
            events: CaptureEventDelivery::default(),
            blobs: None,
            auth_refreshes: None,
            error: None,
        };

        let event = report.to_event(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 8,
                logical: 0,
            },
        );

        assert_eq!(
            attr(&event, "capture.complete"),
            &AttributeValue::Bool(true)
        );
        assert_eq!(
            attr(&event, "capture.source.network.state"),
            &AttributeValue::String("attached_metadata_only".to_owned())
        );
        assert_eq!(
            attr(&event, "capture.source.network.degradation"),
            &AttributeValue::String("opaque_network_traffic".to_owned())
        );
    }

    #[test]
    fn loss_and_unavailable_sources_make_completion_false() {
        let report = CaptureCompletionReport {
            sources: CaptureSourcesReport {
                process: CaptureSourceReport::configured_unavailable(
                    CaptureEvidenceTrust::PlatformObserved,
                    CaptureSourceDegradation::RuntimeFailed,
                ),
                stdio: CaptureSourceReport::attached_no_data(
                    CaptureEvidenceTrust::PlatformObserved,
                ),
                network: CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                otlp: CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            },
            events: CaptureEventDelivery {
                observed: 4,
                spooled: 4,
                landed: 2,
                dropped: 1,
                rejected: 1,
                pending: 0,
            },
            blobs: Some(CaptureBlobDelivery {
                found: 2,
                landed: 1,
                missing: 0,
                oversize: 1,
                missing_bytes: 0,
            }),
            auth_refreshes: Some(2),
            error: Some("capture source stopped".to_owned()),
        };

        let event = report.to_event(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 9,
                logical: 0,
            },
        );

        assert_eq!(
            attr(&event, "capture.complete"),
            &AttributeValue::Bool(false)
        );
        assert_eq!(
            attr(&event, "capture.events.spooled"),
            &AttributeValue::I64(4)
        );
        assert_eq!(
            attr(&event, "capture.blobs.oversize"),
            &AttributeValue::I64(1)
        );
        assert_eq!(
            attr(&event, "capture.auth.refreshes"),
            &AttributeValue::I64(2)
        );
    }
}
