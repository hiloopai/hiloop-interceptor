//! Tokio pipeline for source, normalization, and export stages.

use crate::seams::{
    ExportError, Exporter, NormalizationContext, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerRouter, RawObservationRef, RawRetentionPolicy, RawSignal, RawStore, RawStoreError,
    Source, SourceError, provenance_keys,
};
use futures_util::{FutureExt, StreamExt};
use hiloop_core::event::{AttributeKey, Event};
use thiserror::Error;
use tokio::sync::mpsc;

/// Bounded queue and batching settings for one pipeline run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineOptions {
    raw_queue_capacity: usize,
    event_queue_capacity: usize,
    export_batch_size: usize,
    raw_retention_override: Option<RawRetentionPolicy>,
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
            raw_retention_override: None,
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

    #[must_use]
    pub fn with_raw_retention_override(mut self, policy: RawRetentionPolicy) -> Self {
        self.raw_retention_override = Some(policy);
        self
    }

    pub fn raw_retention_override(self) -> Option<RawRetentionPolicy> {
        self.raw_retention_override
    }
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            raw_queue_capacity: 1024,
            event_queue_capacity: 1024,
            export_batch_size: 128,
            raw_retention_override: None,
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
    pub diagnostics: usize,
    pub raw_observations: usize,
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
    #[error(transparent)]
    RawStore(#[from] RawStoreError),
    #[error(
        "normalizer `{normalizer}` requested raw preservation for `{kind}` signal from `{source_name}`, but no raw store is configured"
    )]
    RawRetentionUnavailable {
        normalizer: &'static str,
        source_name: String,
        kind: String,
    },
    #[error("pipeline channel closed while sending {stage}")]
    ChannelClosed { stage: &'static str },
}

/// Builder for a `source → normalize → export` pipeline run.
///
/// This is the single entry point for running the pipeline. Configure the
/// optional pieces (normalizer router, raw store, queue/batch options) with
/// chained methods, then finish with [`Pipeline::run`] for any raw-signal
/// stream or [`Pipeline::run_source`] for a [`Source`].
///
/// ```ignore
/// Pipeline::new(fork_context, &normalizer, &exporter)
///     .options(options)
///     .run(stream)
///     .await?;
/// ```
pub struct Pipeline<'a, E> {
    context: NormalizationContext,
    router: NormalizerRouter<'a>,
    exporter: &'a E,
    raw_store: Option<&'a dyn RawStore>,
    options: PipelineOptions,
}

impl<'a, E> Pipeline<'a, E>
where
    E: Exporter,
{
    /// Start a pipeline that routes every signal through one normalizer.
    ///
    /// `context` accepts either a bare [`ForkContext`](hiloop_core::identity::ForkContext)
    /// or a fully built [`NormalizationContext`].
    pub fn new(
        context: impl Into<NormalizationContext>,
        normalizer: &'a dyn Normalizer,
        exporter: &'a E,
    ) -> Self {
        Self::with_router(context, NormalizerRouter::single(normalizer), exporter)
    }

    /// Start a pipeline with a preconfigured normalizer router.
    pub fn with_router(
        context: impl Into<NormalizationContext>,
        router: NormalizerRouter<'a>,
        exporter: &'a E,
    ) -> Self {
        Self {
            context: context.into(),
            router,
            exporter,
            raw_store: None,
            options: PipelineOptions::default(),
        }
    }

    /// Attach a raw store so normalizers may request raw preservation.
    #[must_use]
    pub fn raw_store(mut self, raw_store: &'a dyn RawStore) -> Self {
        self.raw_store = Some(raw_store);
        self
    }

    /// Override the default queue and batch options.
    #[must_use]
    pub fn options(mut self, options: PipelineOptions) -> Self {
        self.options = options;
        self
    }

    /// Run until the stream is exhausted and the exporter has flushed.
    pub async fn run<S>(self, stream: S) -> Result<PipelineReport, PipelineError>
    where
        S: futures_core::Stream<Item = Result<RawSignal, SourceError>> + Unpin,
    {
        run_pipeline(
            &self.context,
            stream,
            &self.router,
            self.exporter,
            self.raw_store,
            self.options,
        )
        .await
    }

    /// Run directly from a [`Source`], consuming its raw-signal stream.
    pub async fn run_source<S>(self, source: &S) -> Result<PipelineReport, PipelineError>
    where
        S: Source,
    {
        let signals = source.signals();
        self.run(signals).await
    }
}

async fn run_pipeline<S, E>(
    context: &NormalizationContext,
    mut stream: S,
    router: &NormalizerRouter<'_>,
    exporter: &E,
    raw_store: Option<&dyn RawStore>,
    options: PipelineOptions,
) -> Result<PipelineReport, PipelineError>
where
    S: futures_core::Stream<Item = Result<RawSignal, SourceError>> + Unpin,
    E: Exporter,
{
    let (raw_tx, mut raw_rx) = mpsc::channel(options.raw_queue_capacity());
    let (event_tx, mut event_rx) = mpsc::channel(options.event_queue_capacity());
    let context = context.clone();

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
        let mut diagnostics = 0;
        let mut raw_observations = 0;
        while let Some(raw) = raw_rx.recv().await {
            let selections = router.select_all(&raw);
            if selections.is_empty() {
                return Err(PipelineError::Normalize(NormalizeError::Unsupported {
                    normalizer: "normalizer-router",
                    source_name: raw.source.clone(),
                    kind: raw.kind.clone(),
                }));
            }

            let source = raw.source.clone();
            let kind = raw.kind.clone();
            let mut normalized = Vec::with_capacity(selections.len());
            let mut requested_retention = RawRetentionPolicy::DiscardAfterNormalize;
            let mut retention_requester = "pipeline";

            for selection in selections {
                let descriptor = selection.descriptor();
                let outcome = selection
                    .normalizer()
                    .normalize(&context, raw.clone())
                    .await?;
                if outcome.raw_retention_policy() == RawRetentionPolicy::Preserve {
                    requested_retention = RawRetentionPolicy::Preserve;
                    retention_requester = descriptor.name();
                }
                diagnostics += outcome.diagnostics().len();
                normalized.push((descriptor, outcome));
            }

            let retention = options
                .raw_retention_override()
                .unwrap_or(requested_retention);
            let raw_observation = if retention == RawRetentionPolicy::Preserve {
                let store = raw_store.ok_or_else(|| PipelineError::RawRetentionUnavailable {
                    normalizer: retention_requester,
                    source_name: source.clone(),
                    kind: kind.clone(),
                })?;
                raw_observations += 1;
                Some(store.store(&context, &raw).await?)
            } else {
                None
            };

            for (descriptor, outcome) in normalized {
                for event in outcome.into_events() {
                    let event = stamp_normalization_metadata(
                        event,
                        &context,
                        descriptor,
                        retention,
                        &source,
                        &kind,
                        raw_observation.as_ref(),
                    )?;
                    event_tx
                        .send(event)
                        .await
                        .map_err(|_| PipelineError::ChannelClosed { stage: "event" })?;
                    events += 1;
                }
            }
        }
        Ok::<_, PipelineError>((events, diagnostics, raw_observations))
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

    let source_stage = source_stage.fuse();
    let normalize_stage = normalize_stage.fuse();
    let export_stage = export_stage.fuse();
    tokio::pin!(source_stage);
    tokio::pin!(normalize_stage);
    tokio::pin!(export_stage);

    let mut raw_signals = None;
    let mut normalize_report = None;
    let mut export_batches = None;

    loop {
        if raw_signals.is_some() && normalize_report.is_some() && export_batches.is_some() {
            break;
        }

        tokio::select! {
            result = &mut source_stage, if raw_signals.is_none() => {
                raw_signals = Some(result?);
            }
            result = &mut normalize_stage, if normalize_report.is_none() => {
                normalize_report = Some(result?);
            }
            result = &mut export_stage, if export_batches.is_none() => {
                export_batches = Some(result?);
            }
        }
    }

    if let Some(raw_store) = raw_store {
        raw_store.flush().await?;
    }
    let (events, diagnostics, raw_observations) =
        normalize_report.expect("normalize stage completed");

    Ok(PipelineReport {
        raw_signals: raw_signals.expect("source stage completed"),
        events,
        diagnostics,
        raw_observations,
        export_batches: export_batches.expect("export stage completed"),
    })
}

fn stamp_normalization_metadata(
    event: Event,
    context: &NormalizationContext,
    descriptor: NormalizerDescriptor,
    retention: RawRetentionPolicy,
    source: &str,
    kind: &str,
    raw_observation: Option<&RawObservationRef>,
) -> Result<Event, PipelineError> {
    use provenance_keys as keys;

    let mut event = event
        .with_attribute(
            AttributeKey::from_static(keys::NORMALIZER_NAME),
            descriptor.name(),
        )
        .with_attribute(
            AttributeKey::from_static(keys::NORMALIZER_VERSION),
            descriptor.version(),
        )
        .with_attribute(
            AttributeKey::from_static(keys::NORMALIZER_OUTPUT_SCHEMA_VERSION),
            descriptor.output_schema_version(),
        )
        .with_attribute(AttributeKey::from_static(keys::RAW_SOURCE), source)
        .with_attribute(AttributeKey::from_static(keys::RAW_KIND), kind)
        .with_attribute(
            AttributeKey::from_static(keys::RAW_RETENTION),
            retention.as_str(),
        )
        .with_attribute(
            AttributeKey::from_static(keys::WRAPPER_NAME),
            context.wrapper.name,
        )
        .with_attribute(
            AttributeKey::from_static(keys::WRAPPER_VERSION),
            context.wrapper.version,
        );

    if let Some(process) = &context.process {
        if let Some(pid) = process.pid {
            event =
                event.with_attribute(AttributeKey::from_static(keys::PROCESS_PID), i64::from(pid));
        }
        if let Some(command) = &process.command
            && !command.as_os_str().is_empty()
        {
            event = event.with_attribute(
                AttributeKey::from_static(keys::PROCESS_COMMAND),
                command.display().to_string(),
            );
        }
        if !process.argv.is_empty() {
            let argv = serde_json::to_string(&process.argv).map_err(|error| {
                PipelineError::Normalize(NormalizeError::InvalidOutput {
                    normalizer: descriptor.name(),
                    message: error.to_string(),
                })
            })?;
            event = event.with_attribute(AttributeKey::from_static(keys::PROCESS_ARGV), argv);
        }
        if let Some(cwd) = &process.cwd
            && !cwd.as_os_str().is_empty()
        {
            event = event.with_attribute(
                AttributeKey::from_static(keys::PROCESS_CWD),
                cwd.display().to_string(),
            );
        }
    }

    if let Some(raw_observation) = raw_observation {
        event = event.with_attribute(
            AttributeKey::from_static(keys::RAW_OBSERVATION_ID),
            raw_observation.id(),
        );
    }

    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        exporters::testing::sample_log_event,
        seams::{
            ExportError, NormalizationOutcome, ProcessContext, RawSignal, testing::MemoryRawStore,
        },
        stdio::StdioLogNormalizer,
    };
    use async_trait::async_trait;
    use bytes::Bytes;
    use hiloop_core::{
        event::{AttributeKey, Event, EventName, SignalType},
        identity::{ForkContext, Hlc},
    };
    use std::path::PathBuf;
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

    #[derive(Debug)]
    struct FailingExporter;

    #[async_trait]
    impl Exporter for FailingExporter {
        async fn export(&self, _events: &[Event]) -> Result<(), ExportError> {
            Err(ExportError::other("failing", "intentional failure"))
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct PreserveStdioNormalizer;

    #[async_trait]
    impl Normalizer for PreserveStdioNormalizer {
        fn descriptor(&self) -> NormalizerDescriptor {
            StdioLogNormalizer.descriptor()
        }

        fn supports(&self, raw: &RawSignal) -> crate::seams::NormalizerSupport {
            StdioLogNormalizer.supports(raw)
        }

        async fn normalize(
            &self,
            context: &NormalizationContext,
            raw: RawSignal,
        ) -> Result<NormalizationOutcome, NormalizeError> {
            StdioLogNormalizer
                .normalize(context, raw)
                .await
                .map(|outcome| outcome.with_raw_retention(RawRetentionPolicy::Preserve))
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FallbackNormalizer;

    #[async_trait]
    impl Normalizer for FallbackNormalizer {
        fn descriptor(&self) -> NormalizerDescriptor {
            NormalizerDescriptor::new("fallback-log", "1", "hiloop.event.v1")
        }

        fn supports(&self, raw: &RawSignal) -> crate::seams::NormalizerSupport {
            if raw.source == "stdio" {
                crate::seams::NormalizerSupport::Fallback
            } else {
                crate::seams::NormalizerSupport::Unsupported
            }
        }

        async fn normalize(
            &self,
            context: &NormalizationContext,
            raw: RawSignal,
        ) -> Result<NormalizationOutcome, NormalizeError> {
            let event = Event::new(
                context.fork_context(),
                raw.observed_at,
                SignalType::Log,
                EventName::new("fallback.log").map_err(|error| NormalizeError::Decode {
                    source_name: raw.source.clone(),
                    kind: raw.kind.clone(),
                    message: error.to_string(),
                })?,
            )
            .with_attribute(
                AttributeKey::new("fallback").map_err(|error| NormalizeError::Decode {
                    source_name: raw.source,
                    kind: raw.kind,
                    message: error.to_string(),
                })?,
                true,
            );

            Ok(NormalizationOutcome::from_events(vec![event]))
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

        let report = Pipeline::new(context, &normalizer, &exporter)
            .options(PipelineOptions::new(1, 1, 8).expect("pipeline options"))
            .run(stream)
            .await
            .expect("pipeline should run");

        assert_eq!(
            report,
            PipelineReport {
                raw_signals: 1,
                events: 1,
                diagnostics: 0,
                raw_observations: 0,
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
            "discard_after_normalize"
        );
        assert!(exporter.flushed());
    }

    #[tokio::test]
    async fn pipeline_stamps_process_and_wrapper_provenance() {
        let context =
            NormalizationContext::new(ForkContext::new_local_root()).with_process(ProcessContext {
                pid: Some(42),
                command: Some(PathBuf::from("example")),
                argv: vec!["example".to_owned(), "--flag".to_owned()],
                cwd: Some(PathBuf::from("/tmp/hiloop")),
            });
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

        Pipeline::new(context, &normalizer, &exporter)
            .options(PipelineOptions::new(1, 1, 8).expect("pipeline options"))
            .run(stream)
            .await
            .expect("pipeline should run");

        let events = exporter.events();
        let value = serde_json::to_value(&events[0]).expect("serialize event");

        assert_eq!(value["attributes"][provenance_keys::PROCESS_PID], 42);
        assert_eq!(
            value["attributes"][provenance_keys::PROCESS_COMMAND],
            "example"
        );
        assert_eq!(
            value["attributes"][provenance_keys::PROCESS_ARGV],
            r#"["example","--flag"]"#
        );
        assert_eq!(
            value["attributes"][provenance_keys::PROCESS_CWD],
            "/tmp/hiloop"
        );
        assert_eq!(
            value["attributes"][provenance_keys::WRAPPER_NAME],
            env!("CARGO_PKG_NAME")
        );
        assert_eq!(
            value["attributes"][provenance_keys::WRAPPER_VERSION],
            env!("CARGO_PKG_VERSION")
        );
    }

    #[tokio::test]
    async fn pipeline_preserves_raw_when_store_is_configured() {
        let context = NormalizationContext::new(ForkContext::new_local_root());
        let router = NormalizerRouter::single(&PreserveStdioNormalizer);
        let exporter = RecordingExporter::default();
        let raw_store = MemoryRawStore::default();
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

        let report = Pipeline::with_router(context, router, &exporter)
            .raw_store(&raw_store)
            .options(PipelineOptions::new(1, 1, 8).expect("pipeline options"))
            .run(stream)
            .await
            .expect("pipeline should run");

        assert_eq!(report.raw_observations, 1);
        let raw_refs = raw_store.raws();
        assert_eq!(raw_refs.len(), 1);
        assert_eq!(raw_refs[0].0.id(), "raw-1");

        let events = exporter.events();
        let value = serde_json::to_value(&events[0]).expect("serialize event");
        assert_eq!(
            value["attributes"][provenance_keys::RAW_RETENTION],
            "preserve"
        );
        assert_eq!(
            value["attributes"][provenance_keys::RAW_OBSERVATION_ID],
            "raw-1"
        );
    }

    #[tokio::test]
    async fn pipeline_rejects_preserve_without_raw_store() {
        let context = ForkContext::new_local_root();
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

        let error = Pipeline::new(context, &PreserveStdioNormalizer, &exporter)
            .options(PipelineOptions::new(1, 1, 8).expect("pipeline options"))
            .run(stream)
            .await
            .expect_err("pipeline should reject unsupported raw preservation");

        assert!(matches!(
            error,
            PipelineError::RawRetentionUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn pipeline_runs_all_supported_normalizers() {
        let context = NormalizationContext::new(ForkContext::new_local_root());
        let stdio = StdioLogNormalizer;
        let fallback = FallbackNormalizer;
        let normalizers: [&dyn Normalizer; 2] = [&fallback, &stdio];
        let router = NormalizerRouter::new(normalizers).expect("router");
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

        let report = Pipeline::with_router(context, router, &exporter)
            .options(PipelineOptions::new(1, 2, 8).expect("pipeline options"))
            .run(stream)
            .await
            .expect("pipeline should run");

        assert_eq!(report.events, 2);
        let mut names = exporter
            .events()
            .iter()
            .map(|event| event.name.to_string())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["fallback.log", "process.stdout"]);
    }

    #[tokio::test]
    async fn pipeline_returns_export_error_while_source_is_still_open() {
        let context = ForkContext::new_local_root();
        let normalizer = StdioLogNormalizer;
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok(RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(b"hello"),
        )))
        .await
        .expect("send raw");
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            Pipeline::new(context, &normalizer, &FailingExporter)
                .options(PipelineOptions::new(1, 1, 1).expect("pipeline options"))
                .run(stream),
        )
        .await
        .expect("pipeline should fail fast");

        assert!(matches!(result, Err(PipelineError::Export(_))));
        drop(tx);
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

        let report = Pipeline::new(context, &normalizer, &exporter)
            .options(PipelineOptions::default())
            .run(stream)
            .await
            .expect("pipeline should run");

        assert_eq!(
            report,
            PipelineReport {
                raw_signals: 0,
                events: 0,
                diagnostics: 0,
                raw_observations: 0,
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
