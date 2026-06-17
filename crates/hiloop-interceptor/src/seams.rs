//! Wrapper-local seam traits.
//!
//! These traits are extension points for the interceptor binary/library. They
//! intentionally live here instead of `hiloop-core`: private-only system seams
//! belong in the private monorepo, and wrapper-only seams belong with the wrapper.

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use hiloop_core::{
    event::{Event, PayloadRef},
    identity::{ForkContext, Hlc},
};
use std::{
    collections::BTreeMap, error::Error as StdError, future::Future, path::PathBuf, pin::Pin,
};
use thiserror::Error;

/// Normalized attribute keys reserved for interceptor provenance.
pub mod provenance_keys {
    pub const NORMALIZER_NAME: &str = "normalizer.name";
    pub const NORMALIZER_VERSION: &str = "normalizer.version";
    pub const NORMALIZER_OUTPUT_SCHEMA_VERSION: &str = "normalizer.output_schema_version";
    pub const PROCESS_ARGV: &str = "process.argv";
    pub const PROCESS_COMMAND: &str = "process.command";
    pub const PROCESS_CWD: &str = "process.cwd";
    pub const PROCESS_PID: &str = "process.pid";
    pub const RAW_OBSERVATION_ID: &str = "raw.observation_id";
    pub const RAW_SOURCE: &str = "raw.source";
    pub const RAW_KIND: &str = "raw.kind";
    pub const RAW_RETENTION: &str = "raw.retention";
    pub const WRAPPER_NAME: &str = "wrapper.name";
    pub const WRAPPER_VERSION: &str = "wrapper.version";
}

/// Boxed stream of raw signals produced by a [`Source`].
pub type RawSignalStream = Pin<Box<dyn Stream<Item = Result<RawSignal, SourceError>> + Send>>;

/// Captured signal before schema normalization.
///
/// `source`, `kind`, and attributes stay stringly typed at this boundary because
/// source adapters ingest heterogeneous data before a stable taxonomy exists.
/// [`Normalizer`] implementations must convert this loose shape into the narrow
/// [`Event`] contract. Revisit these raw fields once source/kind categories
/// stabilize.
///
/// A source with a large payload may set an out-of-line [`PayloadRef`] via
/// [`with_payload_ref`](RawSignal::with_payload_ref) and leave `body` empty, so the
/// bytes travel by reference rather than through every pipeline channel.
/// **Authority rule:** when `payload_ref` is `Some` it is where the body lives and
/// `body` may be empty; when it is `None`, `body` holds the bytes inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSignal {
    pub source: String,
    pub kind: String,
    pub observed_at: Hlc,
    pub attributes: BTreeMap<String, String>,
    pub body: Bytes,
    /// Optional out-of-line reference to the body for payloads too large to inline.
    pub payload_ref: Option<PayloadRef>,
}

impl RawSignal {
    /// Raw signals start with an empty attribute map and an inline body.
    pub fn new(
        source: impl Into<String>,
        kind: impl Into<String>,
        observed_at: Hlc,
        body: impl Into<Bytes>,
    ) -> Self {
        Self {
            source: source.into(),
            kind: kind.into(),
            observed_at,
            attributes: BTreeMap::new(),
            body: body.into(),
            payload_ref: None,
        }
    }

    /// Add one source-specific attribute.
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Attach an out-of-line payload reference. Does not touch `body`; a source
    /// offloading its bytes should pass an empty `body` to `new`.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: PayloadRef) -> Self {
        self.payload_ref = Some(payload_ref);
        self
    }

    /// The out-of-line payload reference, when the source offloaded the body.
    pub fn payload_ref(&self) -> Option<&PayloadRef> {
        self.payload_ref.as_ref()
    }
}

/// Back-pressure behavior for bounded producer/consumer boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backpressure {
    /// Wait until capacity is available.
    Block,
    /// Drop the oldest queued signal to make room for the new one.
    DropOldest,
    /// Drop the new signal when no capacity is available.
    DropNewest,
}

/// Outcome of pushing one signal into a [`RawSignalSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkSend {
    /// The signal was accepted by the downstream pipeline.
    Delivered,
    /// The pipeline closed its receiver; the source should stop producing.
    Closed,
}

impl SinkSend {
    /// Whether the downstream pipeline is still accepting signals.
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Delivered)
    }
}

/// Where a [`Source`] hands its raw signals during [`Source::run`].
///
/// This is the only channel a source needs: it hides the concrete transport
/// (today a bounded Tokio channel into the pipeline) so push sources (an OTLP or
/// proxy server accepting connections) and pull sources (reading process stdio)
/// share one delivery surface. Sends apply back-pressure by awaiting capacity;
/// once the pipeline closes its end, [`RawSignalSink::send`] reports
/// [`SinkSend::Closed`] and the source should wind down.
#[derive(Clone)]
pub struct RawSignalSink {
    inner: tokio::sync::mpsc::Sender<Result<RawSignal, SourceError>>,
}

impl RawSignalSink {
    /// Wrap a pipeline channel sender as a sink.
    pub fn new(inner: tokio::sync::mpsc::Sender<Result<RawSignal, SourceError>>) -> Self {
        Self { inner }
    }

    /// Deliver one raw signal, awaiting capacity for back-pressure.
    pub async fn send(&self, raw: RawSignal) -> SinkSend {
        self.send_result(Ok(raw)).await
    }

    /// Report a source-level error to the pipeline (e.g. a fatal read failure).
    ///
    /// The pipeline treats this as terminal, so prefer it over silently dropping
    /// signals when a source cannot continue.
    pub async fn send_error(&self, error: SourceError) -> SinkSend {
        self.send_result(Err(error)).await
    }

    async fn send_result(&self, item: Result<RawSignal, SourceError>) -> SinkSend {
        if self.inner.send(item).await.is_ok() {
            SinkSend::Delivered
        } else {
            SinkSend::Closed
        }
    }
}

/// Signal a [`Source`] to stop producing and return.
///
/// The future resolves once the supervisor wants the source to wind down (the
/// child process exited, the run was cancelled, …). Server-style sources select
/// on it against their accept loop; pull sources may ignore it and simply run to
/// end-of-input. Sources should treat shutdown as cooperative: stop accepting new
/// work, flush anything already buffered into the sink, then return.
pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Produces ordered raw signals from one input: stdio, an OTLP/proxy server, a
/// file, or a future harness integration.
///
/// # Lifecycle
///
/// A source is *constructed and configured* by its own constructor (binding a
/// socket, opening a reader, holding credentials), then *driven* exactly once by
/// [`run`](Source::run):
///
/// 1. construct the source with whatever config it needs;
/// 2. the pipeline calls `run(sink, shutdown)`, handing it the delivery sink and
///    a cooperative shutdown signal;
/// 3. the source pushes [`RawSignal`]s into `sink`, applying back-pressure by
///    awaiting each [`RawSignalSink::send`];
/// 4. the source returns `Ok(())` when its input is exhausted, `shutdown`
///    resolved, or the sink reported [`SinkSend::Closed`]; it returns
///    `Err(SourceError)` only for a genuine capture failure.
///
/// This shape deliberately covers both producer styles with one method:
///
/// - **push** (OTLP receiver, MITM proxy): `run` is an accept loop that selects
///   on `shutdown`; each request becomes a signal sent into the sink.
/// - **pull** (stdio): `run` is a read loop that frames bytes into records and
///   sends them, returning at end-of-input.
///
/// `run` takes `self` by value so a source can own non-`Sync` capture state and
/// move it into the driving task. Construction-time config stays on the concrete
/// type; the trait intentionally does not prescribe a config shape.
///
/// # Contract
///
/// - Preserve raw bytes, timestamps, source identity, and source-local metadata;
///   never infer semantic meaning that belongs to a [`Normalizer`].
/// - Keep buffering bounded; rely on the sink's back-pressure instead of
///   accumulating unbounded internal queues.
/// - Honor `shutdown` rather than hiding teardown failures.
/// - Large bodies may travel out-of-line via [`RawSignal::with_payload_ref`].
#[async_trait]
pub trait Source: Send {
    /// Stable source name, used for diagnostics and error attribution.
    fn name(&self) -> &'static str;

    /// Drive the source to completion, delivering signals into `sink`.
    ///
    /// Returns once the input is exhausted, `shutdown` resolves, or `sink`
    /// closes. Returns [`SourceError`] only on an unrecoverable capture failure.
    async fn run(
        self: Box<Self>,
        sink: RawSignalSink,
        shutdown: ShutdownSignal,
    ) -> Result<(), SourceError>;
}

/// Stable identity and output schema of a normalizer implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizerDescriptor {
    name: &'static str,
    version: &'static str,
    output_schema_version: &'static str,
}

impl NormalizerDescriptor {
    pub const fn new(
        name: &'static str,
        version: &'static str,
        output_schema_version: &'static str,
    ) -> Self {
        Self {
            name,
            version,
            output_schema_version,
        }
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn version(self) -> &'static str {
        self.version
    }

    pub const fn output_schema_version(self) -> &'static str {
        self.output_schema_version
    }
}

/// Strength of a normalizer match for a raw signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NormalizerSupport {
    Unsupported,
    Fallback,
    Exact,
}

impl NormalizerSupport {
    pub const fn is_supported(self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

#[derive(Clone, Copy)]
pub struct SelectedNormalizer<'a> {
    normalizer: &'a dyn Normalizer,
    support: NormalizerSupport,
}

impl<'a> SelectedNormalizer<'a> {
    pub fn normalizer(self) -> &'a dyn Normalizer {
        self.normalizer
    }

    pub fn descriptor(self) -> NormalizerDescriptor {
        self.normalizer.descriptor()
    }

    pub fn support(self) -> NormalizerSupport {
        self.support
    }
}

/// Selects supported normalizers; strongest-match queries keep registration order for ties.
pub struct NormalizerRouter<'a> {
    normalizers: Vec<&'a dyn Normalizer>,
}

impl<'a> NormalizerRouter<'a> {
    pub fn new(
        normalizers: impl IntoIterator<Item = &'a dyn Normalizer>,
    ) -> Result<Self, NormalizerRouterError> {
        let normalizers = normalizers.into_iter().collect::<Vec<_>>();
        if normalizers.is_empty() {
            return Err(NormalizerRouterError::Empty);
        }
        Ok(Self { normalizers })
    }

    pub fn single(normalizer: &'a dyn Normalizer) -> Self {
        Self {
            normalizers: vec![normalizer],
        }
    }

    pub fn select(&self, raw: &RawSignal) -> Option<SelectedNormalizer<'a>> {
        let mut best = None;

        for selection in self.select_all(raw) {
            let support = selection.support();
            if best.is_none_or(|best_selection: SelectedNormalizer<'_>| {
                support > best_selection.support
            }) {
                best = Some(selection);
            }
        }

        best
    }

    pub fn select_all(&self, raw: &RawSignal) -> Vec<SelectedNormalizer<'a>> {
        let mut selections = Vec::new();

        for normalizer in &self.normalizers {
            let support = normalizer.supports(raw);
            if !support.is_supported() {
                continue;
            }

            selections.push(SelectedNormalizer {
                normalizer: *normalizer,
                support,
            });
        }

        selections
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NormalizerRouterError {
    #[error("normalizer router requires at least one normalizer")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawObservationRef {
    id: String,
}

impl RawObservationRef {
    pub fn new(id: impl Into<String>) -> Result<Self, RawStoreError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(RawStoreError::BlankId);
        }
        Ok(Self { id })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Process metadata available without assuming a particular harness.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessContext {
    /// Operating-system process identifier, when available.
    pub pid: Option<u32>,
    /// Command name/path as requested by the supervisor.
    pub command: Option<PathBuf>,
    /// Full argument vector passed to the child process.
    pub argv: Vec<String>,
    /// Working directory inherited by the child process.
    pub cwd: Option<PathBuf>,
}

/// Interceptor metadata stamped onto normalized output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapperContext {
    pub name: &'static str,
    pub version: &'static str,
}

impl WrapperContext {
    pub const fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

/// Context shared by every normalizer invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationContext {
    fork: ForkContext,
    pub process: Option<ProcessContext>,
    pub wrapper: WrapperContext,
}

impl NormalizationContext {
    pub fn new(fork: ForkContext) -> Self {
        Self {
            fork,
            process: None,
            wrapper: WrapperContext::current(),
        }
    }

    #[must_use]
    pub fn with_process(mut self, process: ProcessContext) -> Self {
        self.process = Some(process);
        self
    }

    pub fn fork_context(&self) -> &ForkContext {
        &self.fork
    }
}

impl From<ForkContext> for NormalizationContext {
    fn from(fork: ForkContext) -> Self {
        Self::new(fork)
    }
}

/// Policy requested for the raw observation after semantic extraction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RawRetentionPolicy {
    Preserve,
    #[default]
    DiscardAfterNormalize,
}

impl RawRetentionPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preserve => "preserve",
            Self::DiscardAfterNormalize => "discard_after_normalize",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationDiagnostic {
    pub severity: DiagnosticSeverity,
    pub message: String,
}

/// Events and side information produced from one raw observation.
#[derive(Debug, Clone, Default)]
pub struct NormalizationOutcome {
    events: Vec<Event>,
    diagnostics: Vec<NormalizationDiagnostic>,
    raw_retention: RawRetentionPolicy,
}

impl NormalizationOutcome {
    pub fn from_events(events: Vec<Event>) -> Self {
        Self {
            events,
            diagnostics: Vec::new(),
            raw_retention: RawRetentionPolicy::DiscardAfterNormalize,
        }
    }

    #[must_use]
    pub fn with_raw_retention(mut self, raw_retention: RawRetentionPolicy) -> Self {
        self.raw_retention = raw_retention;
        self
    }

    #[must_use]
    pub fn with_diagnostic(mut self, diagnostic: NormalizationDiagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn diagnostics(&self) -> &[NormalizationDiagnostic] {
        &self.diagnostics
    }

    pub fn raw_retention_policy(&self) -> RawRetentionPolicy {
        self.raw_retention
    }

    pub fn into_events(self) -> Vec<Event> {
        self.events
    }
}

/// Turns raw signals into fork-stamped events.
#[async_trait]
pub trait Normalizer: Send + Sync {
    /// Stable identity used for provenance, replay, and schema evolution.
    fn descriptor(&self) -> NormalizerDescriptor;

    /// Report whether this normalizer should handle a raw signal.
    fn supports(&self, raw: &RawSignal) -> NormalizerSupport;

    /// Normalize one raw signal. Returning multiple events covers batch payloads like OTLP exports.
    async fn normalize(
        &self,
        context: &NormalizationContext,
        raw: RawSignal,
    ) -> Result<NormalizationOutcome, NormalizeError>;
}

/// Ships normalized events to a downstream bus or store.
#[async_trait]
pub trait Exporter: Send + Sync {
    /// Export a batch of events. Implementations should handle empty batches as
    /// no-ops.
    async fn export(&self, events: &[Event]) -> Result<(), ExportError>;

    /// Flush buffered events before shutdown.
    async fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

#[async_trait]
pub trait RawStore: Send + Sync {
    async fn store(
        &self,
        context: &NormalizationContext,
        raw: &RawSignal,
    ) -> Result<RawObservationRef, RawStoreError>;

    async fn flush(&self) -> Result<(), RawStoreError> {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("source `{source_name}` stopped: {reason}")]
    Stopped { source_name: String, reason: String },
    #[error("source `{source_name}` dropped {dropped} signals due to back-pressure")]
    Backpressure { source_name: String, dropped: u64 },
    #[error("source `{source_name}` failed: {message}")]
    Other {
        source_name: String,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum NormalizeError {
    #[error("normalizer `{normalizer}` does not support `{kind}` signal from `{source_name}`")]
    Unsupported {
        normalizer: &'static str,
        source_name: String,
        kind: String,
    },
    #[error("failed to decode `{kind}` signal from `{source_name}`: {message}")]
    Decode {
        source_name: String,
        kind: String,
        message: String,
    },
    #[error("failed to offload payload for `{kind}` signal from `{source_name}`: {message}")]
    PayloadOffload {
        source_name: String,
        kind: String,
        message: String,
    },
    #[error("normalizer `{normalizer}` produced invalid output: {message}")]
    InvalidOutput {
        normalizer: &'static str,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("exporter `{exporter}` is applying back-pressure: {message}")]
    Backpressure { exporter: String, message: String },
    #[error("exporter `{exporter}` failed: {message}")]
    Other {
        exporter: String,
        message: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

#[derive(Debug, Error)]
pub enum RawStoreError {
    #[error("raw observation id must not be blank")]
    BlankId,
    #[error("raw store `{store}` failed: {message}")]
    Other {
        store: String,
        message: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl RawStoreError {
    pub fn other(store: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Other {
            store: store.into(),
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        store: impl Into<String>,
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Other {
            store: store.into(),
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl ExportError {
    pub fn other(exporter: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Other {
            exporter: exporter.into(),
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        exporter: impl Into<String>,
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Other {
            exporter: exporter.into(),
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Test helpers and mock implementations for seam conformance suites.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use super::{
        ExportError, Exporter, NormalizationContext, NormalizationOutcome, Normalizer,
        RawObservationRef, RawSignal, RawSignalSink, RawStore, RawStoreError, Source, SourceError,
    };
    use async_trait::async_trait;
    use hiloop_core::event::Event;
    use hiloop_core::identity::{ForkContext, Hlc};
    use std::sync::Mutex;

    /// Drive a self-terminating [`Source`] (one whose input ends on its own) to
    /// completion and collect what it delivered. `shutdown` never fires, so this
    /// covers the input-exhausted exit path; use [`drain_source_until`] for a
    /// server-style source that runs until told to stop.
    ///
    /// # Panics
    /// Panics if `queue_capacity` is zero.
    pub async fn drain_source<S>(
        source: S,
        queue_capacity: usize,
    ) -> (Result<(), SourceError>, Vec<Result<RawSignal, SourceError>>)
    where
        S: Source,
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel(queue_capacity);
        let sink = RawSignalSink::new(tx);
        let shutdown = Box::pin(std::future::pending());

        // Concurrent (not spawned) so borrowing, non-`'static` sources work.
        let driver = async move { Box::new(source).run(sink, shutdown).await };
        let collector = async {
            let mut collected = Vec::new();
            while let Some(item) = rx.recv().await {
                collected.push(item);
            }
            collected
        };

        tokio::join!(driver, collector)
    }

    /// Drive a server-style [`Source`] through the same lifecycle: resolve
    /// `shutdown` once `stop_after` signals have arrived, then collect what it
    /// delivered. The source must emit at least `stop_after` signals before going
    /// idle, or the collector would block.
    pub async fn drain_source_until<S>(
        source: S,
        queue_capacity: usize,
        stop_after: usize,
    ) -> (Result<(), SourceError>, Vec<Result<RawSignal, SourceError>>)
    where
        S: Source,
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel(queue_capacity);
        let sink = RawSignalSink::new(tx);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let shutdown = Box::pin(async move {
            let _ = shutdown_rx.await;
        });

        let driver = async move { Box::new(source).run(sink, shutdown).await };
        let collector = async {
            let mut collected = Vec::new();
            let mut shutdown_tx = Some(shutdown_tx);
            while let Some(item) = rx.recv().await {
                collected.push(item);
                if collected.len() >= stop_after
                    && let Some(tx) = shutdown_tx.take()
                {
                    let _ = tx.send(());
                }
            }
            collected
        };

        tokio::join!(driver, collector)
    }

    /// Assert the baseline [`Source`] contract: a non-blank name and a `run` that
    /// terminates cleanly when the sink drains.
    pub async fn assert_source_contract<S>(source: S, queue_capacity: usize) -> Vec<RawSignal>
    where
        S: Source,
    {
        let name = source.name();
        assert!(!name.trim().is_empty(), "source name must not be blank");

        let (result, collected) = drain_source(source, queue_capacity).await;
        result.expect("source run should finish cleanly when its input ends");

        collected
            .into_iter()
            .map(|item| item.expect("conformance source must not emit errors"))
            .collect()
    }

    /// Minimal pull [`Source`] that replays a fixed list of signals, then returns.
    pub struct VecSource {
        name: &'static str,
        signals: Vec<RawSignal>,
    }

    impl VecSource {
        pub fn new(name: &'static str, signals: Vec<RawSignal>) -> Self {
            Self { name, signals }
        }
    }

    #[async_trait]
    impl Source for VecSource {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn run(
            self: Box<Self>,
            sink: RawSignalSink,
            mut shutdown: super::ShutdownSignal,
        ) -> Result<(), SourceError> {
            for raw in self.signals {
                tokio::select! {
                    () = &mut shutdown => break,
                    sent = sink.send(raw) => {
                        if !sent.is_open() {
                            break;
                        }
                    }
                }
            }
            Ok(())
        }
    }

    /// Server-style [`Source`] that emits forever until `shutdown` — the push
    /// counterpart to [`VecSource`].
    pub struct EndlessSource {
        name: &'static str,
    }

    impl EndlessSource {
        pub fn new(name: &'static str) -> Self {
            Self { name }
        }
    }

    #[async_trait]
    impl Source for EndlessSource {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn run(
            self: Box<Self>,
            sink: RawSignalSink,
            mut shutdown: super::ShutdownSignal,
        ) -> Result<(), SourceError> {
            let mut tick = 0_u64;
            loop {
                let raw = RawSignal::new(
                    "endless",
                    "tick",
                    Hlc {
                        wall_ns: tick,
                        logical: 0,
                    },
                    tick.to_le_bytes().to_vec(),
                );
                tokio::select! {
                    () = &mut shutdown => return Ok(()),
                    sent = sink.send(raw) => {
                        if !sent.is_open() {
                            return Ok(());
                        }
                    }
                }
                tick += 1;
            }
        }
    }

    pub async fn assert_normalizer_accepts_supported_raw<N>(
        normalizer: &N,
        raw: RawSignal,
    ) -> Result<NormalizationOutcome, super::NormalizeError>
    where
        N: Normalizer,
    {
        let descriptor = normalizer.descriptor();
        assert!(!descriptor.name().trim().is_empty());
        assert!(!descriptor.version().trim().is_empty());
        assert!(!descriptor.output_schema_version().trim().is_empty());
        assert!(normalizer.supports(&raw).is_supported());

        normalizer
            .normalize(
                &NormalizationContext::new(ForkContext::new_local_root()),
                raw,
            )
            .await
    }

    /// In-memory exporter used by contract tests.
    #[derive(Debug, Default)]
    pub struct MemoryExporter {
        events: Mutex<Vec<Event>>,
    }

    impl MemoryExporter {
        pub fn events(&self) -> Vec<Event> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl Exporter for MemoryExporter {
        async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(events);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    pub struct MemoryRawStore {
        raws: Mutex<Vec<(RawObservationRef, RawSignal)>>,
    }

    impl MemoryRawStore {
        pub fn raws(&self) -> Vec<(RawObservationRef, RawSignal)> {
            self.raws
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl RawStore for MemoryRawStore {
        async fn store(
            &self,
            _context: &NormalizationContext,
            raw: &RawSignal,
        ) -> Result<RawObservationRef, RawStoreError> {
            let mut raws = self
                .raws
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let raw_ref = RawObservationRef::new(format!("raw-{}", raws.len() + 1))?;
            raws.push((raw_ref.clone(), raw.clone()));
            Ok(raw_ref)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct StubNormalizer {
        descriptor: NormalizerDescriptor,
        support: NormalizerSupport,
    }

    #[async_trait]
    impl Normalizer for StubNormalizer {
        fn descriptor(&self) -> NormalizerDescriptor {
            self.descriptor
        }

        fn supports(&self, _raw: &RawSignal) -> NormalizerSupport {
            self.support
        }

        async fn normalize(
            &self,
            _context: &NormalizationContext,
            _raw: RawSignal,
        ) -> Result<NormalizationOutcome, NormalizeError> {
            Ok(NormalizationOutcome::default())
        }
    }

    #[test]
    fn normalizer_router_selects_strongest_supported_match() {
        let fallback = StubNormalizer {
            descriptor: NormalizerDescriptor::new("fallback", "1", "event.v1"),
            support: NormalizerSupport::Fallback,
        };
        let unsupported = StubNormalizer {
            descriptor: NormalizerDescriptor::new("unsupported", "1", "event.v1"),
            support: NormalizerSupport::Unsupported,
        };
        let exact = StubNormalizer {
            descriptor: NormalizerDescriptor::new("exact", "1", "event.v1"),
            support: NormalizerSupport::Exact,
        };
        let normalizers: [&dyn Normalizer; 3] = [&fallback, &unsupported, &exact];
        let router = NormalizerRouter::new(normalizers).expect("router");
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::new(),
        );

        let selected = router.select(&raw).expect("selected normalizer");

        assert_eq!(selected.descriptor().name(), "exact");
        assert_eq!(selected.support(), NormalizerSupport::Exact);
    }

    #[test]
    fn normalizer_router_rejects_empty_registry() {
        let normalizers: [&dyn Normalizer; 0] = [];

        assert!(NormalizerRouter::new(normalizers).is_err());
    }

    fn sample_raw(body: &'static [u8]) -> RawSignal {
        RawSignal::new(
            "test",
            "kind",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(body),
        )
    }

    #[test]
    fn raw_signal_payload_ref_is_optional_and_additive() {
        use hiloop_core::event::{PayloadDigest, PayloadRef};

        let plain = sample_raw(b"inline");
        assert!(plain.payload_ref().is_none());
        assert_eq!(plain.body.as_ref(), b"inline");

        let digest = PayloadDigest::new("sha256:abc").expect("digest");
        let offloaded = sample_raw(b"").with_payload_ref(PayloadRef::new(digest));
        assert!(offloaded.payload_ref().is_some());
        assert!(offloaded.body.is_empty());
    }

    #[tokio::test]
    async fn vec_source_satisfies_source_contract() {
        let source = testing::VecSource::new("test", vec![sample_raw(b"one"), sample_raw(b"two")]);

        let signals = testing::assert_source_contract(source, 4).await;

        let bodies = signals
            .iter()
            .map(|raw| raw.body.as_ref().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(bodies, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[tokio::test]
    async fn endless_source_stops_on_shutdown() {
        let (result, collected) =
            testing::drain_source_until(testing::EndlessSource::new("endless"), 4, 3).await;

        result.expect("server source should finish cleanly on shutdown");
        assert!(collected.len() >= 3);
    }

    // --- NormalizationOutcome ---

    #[test]
    fn normalization_outcome_defaults() {
        let outcome = NormalizationOutcome::default();
        assert!(outcome.events().is_empty());
        assert!(outcome.diagnostics().is_empty());
        assert_eq!(
            outcome.raw_retention_policy(),
            RawRetentionPolicy::DiscardAfterNormalize
        );
    }

    #[test]
    fn normalization_outcome_with_raw_retention_override() {
        let outcome =
            NormalizationOutcome::default().with_raw_retention(RawRetentionPolicy::Preserve);
        assert_eq!(outcome.raw_retention_policy(), RawRetentionPolicy::Preserve);
    }

    #[test]
    fn normalization_outcome_with_diagnostic() {
        let outcome = NormalizationOutcome::default().with_diagnostic(NormalizationDiagnostic {
            severity: DiagnosticSeverity::Warn,
            message: "something fishy".to_owned(),
        });
        assert_eq!(outcome.diagnostics().len(), 1);
        assert_eq!(outcome.diagnostics()[0].severity, DiagnosticSeverity::Warn);
        assert_eq!(outcome.diagnostics()[0].message, "something fishy");
    }

    #[test]
    fn normalization_outcome_into_events() {
        let event = hiloop_core::event::Event::new(
            &ForkContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            hiloop_core::event::SignalType::Log,
            hiloop_core::event::EventName::new("test.event").expect("event name"),
        );
        let outcome = NormalizationOutcome::from_events(vec![event]);
        assert_eq!(outcome.events().len(), 1);
        let events = outcome.into_events();
        assert_eq!(events.len(), 1);
    }

    // --- RawObservationRef ---

    #[test]
    fn raw_observation_ref_rejects_blank_id() {
        assert!(RawObservationRef::new("").is_err());
        assert!(RawObservationRef::new("   ").is_err());
    }

    #[test]
    fn raw_observation_ref_accepts_valid_id() {
        let r = RawObservationRef::new("raw-1").expect("valid id");
        assert_eq!(r.id(), "raw-1");
    }

    // --- NormalizerSupport ---

    #[test]
    fn normalizer_support_ordering() {
        assert!(NormalizerSupport::Exact > NormalizerSupport::Fallback);
        assert!(NormalizerSupport::Fallback > NormalizerSupport::Unsupported);
        assert!(!NormalizerSupport::Unsupported.is_supported());
        assert!(NormalizerSupport::Fallback.is_supported());
        assert!(NormalizerSupport::Exact.is_supported());
    }

    // --- RawSignal builder ---

    #[test]
    fn raw_signal_with_attribute_is_additive() {
        let raw = sample_raw(b"data")
            .with_attribute("key1", "val1")
            .with_attribute("key2", "val2");
        assert_eq!(raw.attributes.len(), 2);
        assert_eq!(raw.attributes["key1"], "val1");
        assert_eq!(raw.attributes["key2"], "val2");
    }

    // --- Error types ---

    #[test]
    fn export_error_other_format() {
        let error = ExportError::other("test-exporter", "connection lost");
        let display = error.to_string();
        assert!(display.contains("test-exporter"));
        assert!(display.contains("connection lost"));
    }

    #[test]
    fn export_error_with_source_preserves_chain() {
        let source = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke");
        let error = ExportError::with_source("test-exporter", "write failed", source);
        assert!(error.to_string().contains("write failed"));
    }

    #[test]
    fn raw_store_error_other_format() {
        let error = RawStoreError::other("test-store", "disk full");
        let display = error.to_string();
        assert!(display.contains("test-store"));
        assert!(display.contains("disk full"));
    }

    #[test]
    fn raw_store_error_blank_id_format() {
        let error = RawStoreError::BlankId;
        assert!(error.to_string().contains("blank"));
    }

    #[test]
    fn normalize_error_display_variants() {
        let unsupported = NormalizeError::Unsupported {
            normalizer: "test",
            source_name: "stdio".to_owned(),
            kind: "stdout".to_owned(),
        };
        assert!(unsupported.to_string().contains("does not support"));

        let decode = NormalizeError::Decode {
            source_name: "otlp".to_owned(),
            kind: "traces".to_owned(),
            message: "bad proto".to_owned(),
        };
        assert!(decode.to_string().contains("bad proto"));
    }

    #[test]
    fn source_error_display_variants() {
        let stopped = SourceError::Stopped {
            source_name: "stdio".to_owned(),
            reason: "eof".to_owned(),
        };
        assert!(stopped.to_string().contains("stopped"));

        let bp = SourceError::Backpressure {
            source_name: "proxy".to_owned(),
            dropped: 42,
        };
        assert!(bp.to_string().contains("42"));
    }

    // --- NormalizationContext ---

    #[test]
    fn normalization_context_from_fork() {
        let fork = ForkContext::new_local_root();
        let context: NormalizationContext = fork.clone().into();
        assert_eq!(context.fork_context(), &fork);
        assert!(context.process.is_none());
    }

    // --- NormalizerRouter select_all ---

    #[test]
    fn normalizer_router_select_all_returns_multiple_matches() {
        let fallback = StubNormalizer {
            descriptor: NormalizerDescriptor::new("fallback", "1", "event.v1"),
            support: NormalizerSupport::Fallback,
        };
        let exact = StubNormalizer {
            descriptor: NormalizerDescriptor::new("exact", "1", "event.v1"),
            support: NormalizerSupport::Exact,
        };
        let normalizers: [&dyn Normalizer; 2] = [&fallback, &exact];
        let router = NormalizerRouter::new(normalizers).expect("router");
        let raw = sample_raw(b"x");

        let all = router.select_all(&raw);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn normalizer_router_select_returns_none_for_all_unsupported() {
        let unsupported = StubNormalizer {
            descriptor: NormalizerDescriptor::new("u", "1", "event.v1"),
            support: NormalizerSupport::Unsupported,
        };
        let normalizers: [&dyn Normalizer; 1] = [&unsupported];
        let router = NormalizerRouter::new(normalizers).expect("router");
        let raw = sample_raw(b"x");

        assert!(router.select(&raw).is_none());
    }

    #[tokio::test]
    async fn raw_signal_sink_reports_closed_when_receiver_drops() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let sink = RawSignalSink::new(tx);
        drop(rx);

        assert_eq!(sink.send(sample_raw(b"x")).await, SinkSend::Closed);
    }
}
