//! Wrapper-local seam traits.
//!
//! These traits are extension points for the interceptor binary/library. They
//! intentionally live here instead of `hiloop-core`: private-only system seams
//! belong in the private monorepo, and wrapper-only seams belong with the wrapper.

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use hiloop_core::{
    event::Event,
    identity::{ForkContext, Hlc},
};
use std::{collections::BTreeMap, error::Error as StdError, path::PathBuf, pin::Pin};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSignal {
    pub source: String,
    pub kind: String,
    pub observed_at: Hlc,
    pub attributes: BTreeMap<String, String>,
    pub body: Bytes,
}

impl RawSignal {
    /// Raw signals start with an empty attribute map.
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
        }
    }

    /// Add one source-specific attribute.
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
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

/// Produces raw signals such as OTLP payloads, proxy events, or stdio lines.
pub trait Source: Send + Sync {
    /// Stable source name.
    fn name(&self) -> &'static str;

    /// Start or attach to the raw signal stream.
    fn signals(&self) -> RawSignalStream;
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
        RawObservationRef, RawSignal, RawStore, RawStoreError,
    };
    use async_trait::async_trait;
    use hiloop_core::event::Event;
    use hiloop_core::identity::ForkContext;
    use std::sync::Mutex;

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
}
