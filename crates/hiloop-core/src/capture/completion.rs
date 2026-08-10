//! Capture-process completion truth and its canonical Event-v1 projection.

use std::{fmt, num::NonZeroU64};

use crate::{
    event::{AttributeKey, Event, EventName, SignalType},
    identity::{Hlc, RunContext},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

string_enum! {
    /// Authority class for one source's capture evidence.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum CaptureEvidenceTrust {
        /// The capture runtime observed the source independently of workload instrumentation.
        PlatformObserved => "platform_observed",
        /// The workload or one of its SDKs reported the source to capture.
        WorkloadReported => "workload_reported",
    }
}

string_enum! {
    /// Closed degradation reasons carried by the capture-completion summary.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
        /// Normalized events accepted from the source.
        events: NonZeroU64,
    },
    /// Every observation was limited to metadata.
    AttachedMetadataOnly {
        /// Metadata-only normalized events accepted from the source.
        events: NonZeroU64,
        /// Typed reason payload/content capture was unavailable.
        reason: CaptureSourceDegradation,
    },
    /// The source observed both full-fidelity and metadata-only traffic.
    AttachedMixed {
        /// Full-fidelity normalized events.
        full_events: NonZeroU64,
        /// Metadata-only normalized events.
        metadata_only_events: NonZeroU64,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn attached_full(trust: CaptureEvidenceTrust, events: u64) -> Self {
        let Some(events) = NonZeroU64::new(events) else {
            return Self::attached_no_data(trust);
        };
        Self {
            trust,
            state: CaptureSourceState::AttachedFull { events },
        }
    }

    /// Report an attached source whose observations were metadata-only.
    pub fn attached_metadata_only(
        trust: CaptureEvidenceTrust,
        events: u64,
        reason: CaptureSourceDegradation,
    ) -> Self {
        let Some(events) = NonZeroU64::new(events) else {
            return Self::attached_no_data(trust);
        };
        Self {
            trust,
            state: CaptureSourceState::AttachedMetadataOnly { events, reason },
        }
    }

    /// Report an attached source with mixed full and metadata-only observations.
    pub fn attached_mixed(
        trust: CaptureEvidenceTrust,
        full_events: u64,
        metadata_only_events: u64,
        reason: CaptureSourceDegradation,
    ) -> Self {
        let Some(full_events) = NonZeroU64::new(full_events) else {
            return Self::attached_metadata_only(trust, metadata_only_events, reason);
        };
        let Some(metadata_only_events) = NonZeroU64::new(metadata_only_events) else {
            return Self::attached_full(trust, full_events.get());
        };
        Self {
            trust,
            state: CaptureSourceState::AttachedMixed {
                full_events,
                metadata_only_events,
                reason,
            },
        }
    }

    /// Report source fidelity from normalized event counts.
    pub fn from_event_counts(
        trust: CaptureEvidenceTrust,
        full_events: u64,
        metadata_only_events: u64,
        degradation: CaptureSourceDegradation,
    ) -> Self {
        match (full_events, metadata_only_events) {
            (0, 0) => Self::attached_no_data(trust),
            (full, 0) => Self::attached_full(trust, full),
            (0, metadata_only) => Self::attached_metadata_only(trust, metadata_only, degradation),
            (full, metadata_only) => Self::attached_mixed(trust, full, metadata_only, degradation),
        }
    }
}

/// Fixed source coverage for one capture process session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSourcesReport {
    /// Process lifecycle source.
    process: CaptureSourceReport,
    /// Standard input/output source.
    stdio: CaptureSourceReport,
    /// Network source.
    network: CaptureSourceReport,
    /// Workload OTLP source.
    otlp: CaptureSourceReport,
}

impl CaptureSourcesReport {
    /// Build the fixed four-source coverage report.
    pub const fn new(
        process: CaptureSourceReport,
        stdio: CaptureSourceReport,
        network: CaptureSourceReport,
        otlp: CaptureSourceReport,
    ) -> Self {
        Self {
            process,
            stdio,
            network,
            otlp,
        }
    }

    /// Process lifecycle source.
    pub const fn process(&self) -> &CaptureSourceReport {
        &self.process
    }

    /// Standard input/output source.
    pub const fn stdio(&self) -> &CaptureSourceReport {
        &self.stdio
    }

    /// Network source.
    pub const fn network(&self) -> &CaptureSourceReport {
        &self.network
    }

    /// Workload OTLP source.
    pub const fn otlp(&self) -> &CaptureSourceReport {
        &self.otlp
    }

    fn has_unavailable_source(&self) -> bool {
        [&self.process, &self.stdio, &self.network, &self.otlp]
            .into_iter()
            .any(|source| source.state.is_unavailable())
    }
}

/// Event delivery accounting at completion-record mint time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureCompletionReport {
    /// Final source coverage and fidelity.
    sources: CaptureSourcesReport,
    /// Event delivery outcome.
    events: CaptureEventDelivery,
    /// Blob delivery outcome when capture used an out-of-row blob store.
    blobs: Option<CaptureBlobDelivery>,
    /// Mid-session gateway credential refreshes, when applicable.
    auth_refreshes: Option<u64>,
    /// Terminal capture error, if any.
    error: Option<String>,
}

#[derive(Deserialize)]
struct CaptureCompletionReportWire {
    sources: CaptureSourcesReport,
    events: CaptureEventDelivery,
    blobs: Option<CaptureBlobDelivery>,
    auth_refreshes: Option<u64>,
    error: Option<String>,
}

impl<'de> Deserialize<'de> for CaptureCompletionReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CaptureCompletionReportWire::deserialize(deserializer)?;
        Self::new(
            wire.sources,
            wire.events,
            wire.blobs,
            wire.auth_refreshes,
            wire.error,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Invalid completion accounting rejected before it can become capture authority.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaptureCompletionError {
    /// Event terminal buckets do not account for every observed event.
    #[error("capture event accounting is inconsistent")]
    EventAccounting,
    /// More events entered the spool than were observed.
    #[error("capture spool accounting is inconsistent")]
    SpoolAccounting,
    /// Blob terminal buckets do not account for every found blob.
    #[error("capture blob accounting is inconsistent")]
    BlobAccounting,
}

impl CaptureCompletionReport {
    /// Build a validated capture completion report.
    pub fn new(
        sources: CaptureSourcesReport,
        events: CaptureEventDelivery,
        blobs: Option<CaptureBlobDelivery>,
        auth_refreshes: Option<u64>,
        error: Option<String>,
    ) -> Result<Self, CaptureCompletionError> {
        let accounted_events = events
            .landed
            .checked_add(events.dropped)
            .and_then(|value| value.checked_add(events.rejected))
            .and_then(|value| value.checked_add(events.pending))
            .ok_or(CaptureCompletionError::EventAccounting)?;
        if accounted_events != events.observed {
            return Err(CaptureCompletionError::EventAccounting);
        }
        if events.spooled > events.observed {
            return Err(CaptureCompletionError::SpoolAccounting);
        }
        let accounted_spooled = events
            .pending
            .checked_add(events.dropped)
            .ok_or(CaptureCompletionError::SpoolAccounting)?;
        if accounted_spooled > events.spooled {
            return Err(CaptureCompletionError::SpoolAccounting);
        }
        if let Some(blobs) = blobs {
            let accounted_blobs = blobs
                .landed
                .checked_add(blobs.missing)
                .and_then(|value| value.checked_add(blobs.oversize))
                .ok_or(CaptureCompletionError::BlobAccounting)?;
            if accounted_blobs != blobs.found {
                return Err(CaptureCompletionError::BlobAccounting);
            }
            if blobs.missing == 0 && blobs.missing_bytes != 0 {
                return Err(CaptureCompletionError::BlobAccounting);
            }
        }
        Ok(Self {
            sources,
            events,
            blobs,
            auth_refreshes,
            error,
        })
    }

    /// Final source coverage.
    pub const fn sources(&self) -> &CaptureSourcesReport {
        &self.sources
    }

    /// Event delivery outcome.
    pub const fn events(&self) -> CaptureEventDelivery {
        self.events
    }

    /// Payload delivery outcome.
    pub const fn blobs(&self) -> Option<CaptureBlobDelivery> {
        self.blobs
    }

    /// Mid-session credential refresh count.
    pub const fn auth_refreshes(&self) -> Option<u64> {
        self.auth_refreshes
    }

    /// Terminal capture error.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Replace event-delivery accounting while retaining source and blob truth.
    pub fn with_event_delivery(
        &self,
        events: CaptureEventDelivery,
    ) -> Result<Self, CaptureCompletionError> {
        Self::new(
            self.sources.clone(),
            events,
            self.blobs,
            self.auth_refreshes,
            self.error.clone(),
        )
    }

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

    /// True only when completion is lossless and no event remains pending.
    #[must_use]
    pub fn is_settled_complete(&self) -> bool {
        self.events.pending == 0 && self.is_complete()
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
        CaptureSourceState::AttachedFull { events } => {
            event.with_attribute(source_key(source, "events"), event_count(events.get()))
        }
        CaptureSourceState::AttachedMetadataOnly { events, reason } => event
            .with_attribute(source_key(source, "events"), event_count(events.get()))
            .with_attribute(source_key(source, "degradation"), reason.to_string()),
        CaptureSourceState::AttachedMixed {
            full_events,
            metadata_only_events,
            reason,
        } => event
            .with_attribute(
                source_key(source, "full_events"),
                event_count(full_events.get()),
            )
            .with_attribute(
                source_key(source, "metadata_only_events"),
                event_count(metadata_only_events.get()),
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

    #[test]
    fn completion_validation_rejects_impossible_accounting() {
        let sources = CaptureSourcesReport::new(
            CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
            CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
            CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
            CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
        );
        assert_eq!(
            CaptureCompletionReport::new(
                sources.clone(),
                CaptureEventDelivery {
                    observed: 1,
                    landed: 2,
                    ..CaptureEventDelivery::default()
                },
                None,
                None,
                None,
            ),
            Err(CaptureCompletionError::EventAccounting)
        );
        assert_eq!(
            CaptureCompletionReport::new(
                sources,
                CaptureEventDelivery::default(),
                Some(CaptureBlobDelivery {
                    found: 1,
                    landed: 1,
                    missing: 1,
                    ..CaptureBlobDelivery::default()
                }),
                None,
                None,
            ),
            Err(CaptureCompletionError::BlobAccounting)
        );
        assert_eq!(
            CaptureCompletionReport::new(
                CaptureSourcesReport::new(
                    CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved,),
                    CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved,),
                    CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                    CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
                ),
                CaptureEventDelivery {
                    observed: 1,
                    pending: 1,
                    ..CaptureEventDelivery::default()
                },
                None,
                None,
                None,
            ),
            Err(CaptureCompletionError::SpoolAccounting)
        );
        assert_eq!(
            CaptureCompletionReport::new(
                CaptureSourcesReport::new(
                    CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved,),
                    CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved,),
                    CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                    CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
                ),
                CaptureEventDelivery::default(),
                Some(CaptureBlobDelivery {
                    missing_bytes: 1,
                    ..CaptureBlobDelivery::default()
                }),
                None,
                None,
            ),
            Err(CaptureCompletionError::BlobAccounting)
        );
    }

    #[test]
    fn managed_completion_requires_a_settled_event_delivery() {
        let report = CaptureCompletionReport::new(
            CaptureSourcesReport::new(
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            ),
            CaptureEventDelivery {
                observed: 1,
                spooled: 1,
                pending: 1,
                ..CaptureEventDelivery::default()
            },
            None,
            None,
            None,
        )
        .expect("valid ordered local completion");

        assert!(report.is_complete());
        assert!(!report.is_settled_complete());
        let mut value = serde_json::to_value(&report).expect("completion json");
        value["events"]["landed"] = 2.into();
        assert!(serde_json::from_value::<CaptureCompletionReport>(value).is_err());
    }
}
