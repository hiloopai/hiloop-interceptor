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
use std::{collections::BTreeMap, error::Error as StdError, pin::Pin};
use thiserror::Error;

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

/// Turns raw signals into fork-stamped events.
#[async_trait]
pub trait Normalizer: Send + Sync {
    /// Normalize one raw signal. Returning multiple events covers batch payloads
    /// like OTLP exports.
    async fn normalize(
        &self,
        context: &ForkContext,
        raw: RawSignal,
    ) -> Result<Vec<Event>, NormalizeError>;
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
    use super::{ExportError, Exporter};
    use async_trait::async_trait;
    use hiloop_core::event::Event;
    use std::sync::Mutex;

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
