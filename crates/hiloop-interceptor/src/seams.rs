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
    pub const RAW_SOURCE: &str = "raw.source";
    pub const RAW_KIND: &str = "raw.kind";
    pub const RAW_RETENTION: &str = "raw.retention";
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

/// Process metadata available without assuming a particular harness.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessContext {
    pub pid: Option<u32>,
    pub executable: Option<PathBuf>,
    pub argv: Vec<String>,
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

/// Policy requested for the raw observation after semantic extraction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RawRetentionPolicy {
    #[default]
    Preserve,
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
            raw_retention: RawRetentionPolicy::Preserve,
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
        ExportError, Exporter, NormalizationContext, NormalizationOutcome, Normalizer, RawSignal,
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
}
