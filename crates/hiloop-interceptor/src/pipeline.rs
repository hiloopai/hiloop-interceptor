//! Tokio pipeline for source, normalization, and export stages.

use crate::seams::{
    ExportError, Exporter, NormalizationContext, NormalizeError, Normalizer, NormalizerDescriptor,
    RawRetentionPolicy, RawSignal, Source, SourceError, provenance_keys,
};
use futures_util::StreamExt;
use hiloop_core::{
    event::{AttributeKey, Event},
    identity::ForkContext,
};
use thiserror::Error;
use tokio::sync::mpsc;

/// Bounded queue and batching settings for one pipeline run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineOptions {
    raw_queue_capacity: usize,
    event_queue_capacity: usize,
    export_batch_size: usize,
}

impl PipelineOptions {
    /// Rejects zero capacities, which would make Tokio bounded channels panic.
    pub fn new(
        raw_queue_capacity: usize,
        event_queue_capacity: usize,
        export_batch_size: usize,
    ) -> Result<Self, PipelineOptionsError> {
        if raw_queue_capacity == 0 {
            return Err(PipelineOptionsError::ZeroCapacity {
                field: "raw_queue_capacity",
            });
        }
        if event_queue_capacity == 0 {
            return Err(PipelineOptionsError::ZeroCapacity {
                field: "event_queue_capacity",
            });
        }
        if export_batch_size == 0 {
            return Err(PipelineOptionsError::ZeroCapacity {
                field: "export_batch_size",
            });
        }

        Ok(Self {
            raw_queue_capacity,
            event_queue_capacity,
            export_batch_size,
        })
    }

    pub fn raw_queue_capacity(self) -> usize {
        self.raw_queue_capacity
    }

    pub fn event_queue_capacity(self) -> usize {
        self.event_queue_capacity
    }

    pub fn export_batch_size(self) -> usize {
        self.export_batch_size
    }
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            raw_queue_capacity: 1024,
            event_queue_capacity: 1024,
            export_batch_size: 128,
        }
    }
}

/// Invalid pipeline configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PipelineOptionsError {
    #[error("{field} must be greater than zero")]
    ZeroCapacity { field: &'static str },
}

/// Counts emitted by a completed pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineReport {
    pub raw_signals: usize,
    pub events: usize,
    pub export_batches: usize,
}

/// Pipeline failure with the stage that produced it.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error(transparent)]
    Normalize(#[from] NormalizeError),
    #[error(transparent)]
    Export(#[from] ExportError),
    #[error("pipeline channel closed while sending {stage}")]
    ChannelClosed { stage: &'static str },
}

/// Runs until the source is exhausted and the exporter has flushed.
pub async fn run_source<S, N, E>(
    context: &ForkContext,
    source: &S,
    normalizer: &N,
    exporter: &E,
    options: PipelineOptions,
) -> Result<PipelineReport, PipelineError>
where
    S: Source,
    N: Normalizer,
    E: Exporter,
{
    run_stream(context, source.signals(), normalizer, exporter, options).await
}

/// Accepts any raw-signal stream, including producer-backed Tokio channels.
pub async fn run_stream<S, N, E>(
    context: &ForkContext,
    stream: S,
    normalizer: &N,
    exporter: &E,
    options: PipelineOptions,
) -> Result<PipelineReport, PipelineError>
where
    S: futures_core::Stream<Item = Result<RawSignal, SourceError>> + Unpin,
    N: Normalizer,
    E: Exporter,
{
    let normalization_context = NormalizationContext::new(context.clone());
    run_stream_with_context(
        &normalization_context,
        stream,
        normalizer,
        exporter,
        options,
    )
    .await
}

pub async fn run_stream_with_context<S, N, E>(
    context: &NormalizationContext,
    mut stream: S,
    normalizer: &N,
    exporter: &E,
    options: PipelineOptions,
) -> Result<PipelineReport, PipelineError>
where
    S: futures_core::Stream<Item = Result<RawSignal, SourceError>> + Unpin,
    N: Normalizer,
    E: Exporter,
{
    let (raw_tx, mut raw_rx) = mpsc::channel(options.raw_queue_capacity());
    let (event_tx, mut event_rx) = mpsc::channel(options.event_queue_capacity());
    let context = context.clone();
    let descriptor = normalizer.descriptor();

    let source_stage = async move {
        let mut raw_signals = 0;
        while let Some(raw) = stream.next().await {
            let raw = raw?;
            raw_tx
                .send(raw)
                .await
                .map_err(|_| PipelineError::ChannelClosed {
                    stage: "raw signal",
                })?;
            raw_signals += 1;
        }
        Ok::<_, PipelineError>(raw_signals)
    };

    let normalize_stage = async move {
        let mut events = 0;
        while let Some(raw) = raw_rx.recv().await {
            if !normalizer.supports(&raw).is_supported() {
                return Err(PipelineError::Normalize(NormalizeError::Unsupported {
                    normalizer: descriptor.name(),
                    source_name: raw.source,
                    kind: raw.kind,
                }));
            }

            let source = raw.source.clone();
            let kind = raw.kind.clone();
            let outcome = normalizer.normalize(&context, raw).await?;
            let retention = outcome.raw_retention_policy();

            for event in outcome.into_events() {
                let event =
                    stamp_normalization_metadata(event, descriptor, retention, &source, &kind)?;
                event_tx
                    .send(event)
                    .await
                    .map_err(|_| PipelineError::ChannelClosed { stage: "event" })?;
                events += 1;
            }
        }
        Ok::<_, PipelineError>(events)
    };

    let export_stage = async {
        let mut batches = 0;
        let mut batch = Vec::with_capacity(options.export_batch_size());

        while let Some(event) = event_rx.recv().await {
            batch.push(event);
            if batch.len() >= options.export_batch_size() {
                exporter.export(&batch).await?;
                batch.clear();
                batches += 1;
            }
        }

        if !batch.is_empty() {
            exporter.export(&batch).await?;
            batches += 1;
        }
        exporter.flush().await?;

        Ok::<_, PipelineError>(batches)
    };

    let (raw_signals, events, export_batches) =
        tokio::join!(source_stage, normalize_stage, export_stage);

    let export_batches = export_batches?;
    let events = events?;
    let raw_signals = raw_signals?;

    Ok(PipelineReport {
        raw_signals,
        events,
        export_batches,
    })
}

fn stamp_normalization_metadata(
    event: Event,
    descriptor: NormalizerDescriptor,
    retention: RawRetentionPolicy,
    source: &str,
    kind: &str,
) -> Result<Event, PipelineError> {
    Ok(event
        .with_attribute(
            normalizer_key(provenance_keys::NORMALIZER_NAME, descriptor)?,
            descriptor.name(),
        )
        .with_attribute(
            normalizer_key(provenance_keys::NORMALIZER_VERSION, descriptor)?,
            descriptor.version(),
        )
        .with_attribute(
            normalizer_key(
                provenance_keys::NORMALIZER_OUTPUT_SCHEMA_VERSION,
                descriptor,
            )?,
            descriptor.output_schema_version(),
        )
        .with_attribute(
            normalizer_key(provenance_keys::RAW_SOURCE, descriptor)?,
            source,
        )
        .with_attribute(normalizer_key(provenance_keys::RAW_KIND, descriptor)?, kind)
        .with_attribute(
            normalizer_key(provenance_keys::RAW_RETENTION, descriptor)?,
            retention.as_str(),
        ))
}

fn normalizer_key(
    value: &'static str,
    descriptor: NormalizerDescriptor,
) -> Result<AttributeKey, PipelineError> {
    AttributeKey::new(value)
        .map_err(|error| NormalizeError::InvalidOutput {
            normalizer: descriptor.name(),
            message: error.to_string(),
        })
        .map_err(PipelineError::Normalize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        exporters::testing::sample_log_event,
        seams::{ExportError, RawSignal},
        stdio::StdioLogNormalizer,
    };
    use async_trait::async_trait;
    use bytes::Bytes;
    use hiloop_core::{
        event::Event,
        identity::{ForkContext, Hlc},
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Debug, Default)]
    struct RecordingExporter {
        events: Mutex<Vec<Event>>,
        flushed: AtomicBool,
    }

    impl RecordingExporter {
        fn events(&self) -> Vec<Event> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn flushed(&self) -> bool {
            self.flushed.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Exporter for RecordingExporter {
        async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(events);
            Ok(())
        }

        async fn flush(&self) -> Result<(), ExportError> {
            self.flushed.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn pipeline_exports_and_flushes_final_batch() {
        let context = ForkContext::new_local_root();
        let normalizer = StdioLogNormalizer;
        let exporter = RecordingExporter::default();
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(b"hello"),
        );
        let stream = futures_util::stream::iter([Ok(raw)]);

        let report = run_stream(
            &context,
            stream,
            &normalizer,
            &exporter,
            PipelineOptions::new(1, 1, 8).expect("pipeline options"),
        )
        .await
        .expect("pipeline should run");

        assert_eq!(
            report,
            PipelineReport {
                raw_signals: 1,
                events: 1,
                export_batches: 1,
            }
        );
        let events = exporter.events();
        assert_eq!(events.len(), 1);
        let value = serde_json::to_value(&events[0]).expect("serialize event");
        assert_eq!(
            value["attributes"][provenance_keys::NORMALIZER_NAME],
            "stdio-log"
        );
        assert_eq!(
            value["attributes"][provenance_keys::NORMALIZER_VERSION],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            value["attributes"][provenance_keys::NORMALIZER_OUTPUT_SCHEMA_VERSION],
            "hiloop.event.v1"
        );
        assert_eq!(value["attributes"][provenance_keys::RAW_SOURCE], "stdio");
        assert_eq!(value["attributes"][provenance_keys::RAW_KIND], "stdout");
        assert_eq!(
            value["attributes"][provenance_keys::RAW_RETENTION],
            "preserve"
        );
        assert!(exporter.flushed());
    }

    #[test]
    fn pipeline_options_reject_zero_capacity() {
        assert!(PipelineOptions::new(0, 1, 1).is_err());
        assert!(PipelineOptions::new(1, 0, 1).is_err());
        assert!(PipelineOptions::new(1, 1, 0).is_err());
    }

    #[tokio::test]
    async fn pipeline_accepts_empty_stream_and_still_flushes() {
        let context = ForkContext::new_local_root();
        let normalizer = StdioLogNormalizer;
        let exporter = RecordingExporter::default();
        let stream = futures_util::stream::iter([]);

        let report = run_stream(
            &context,
            stream,
            &normalizer,
            &exporter,
            PipelineOptions::default(),
        )
        .await
        .expect("pipeline should run");

        assert_eq!(
            report,
            PipelineReport {
                raw_signals: 0,
                events: 0,
                export_batches: 0,
            }
        );
        assert!(exporter.flushed());
    }

    #[tokio::test]
    async fn exporter_contract_helper_uses_shared_sample_event() {
        let exporter = RecordingExporter::default();
        exporter
            .export(&[sample_log_event()])
            .await
            .expect("export should succeed");
        exporter.flush().await.expect("flush should succeed");

        assert_eq!(exporter.events().len(), 1);
        assert!(exporter.flushed());
    }
}
