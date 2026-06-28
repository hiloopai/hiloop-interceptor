//! Tree-native telemetry event schema.
//!
//! Every event is stamped with the fork-tree spine. Large payloads such as LLM
//! prompts, responses, and HTTP bodies are referenced by content hash instead of
//! embedded in the row.

use crate::identity::{EventId, ForkContext, ForkNodeId, ForkPath, Hlc, RunId};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

/// Attributes are ordered for deterministic serialization.
pub type Attributes = BTreeMap<AttributeKey, AttributeValue>;

/// Errors returned by event schema constructors.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum EventError {
    #[error("{field} must not be blank")]
    BlankText { field: &'static str },
    #[error("floating-point attribute values must be finite: {value}")]
    NonFiniteFloat { value: f64 },
}

/// Attribute map key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributeKey(String);

/// Stable name of the event within its signal family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventName(String);

/// Opaque content digest for an out-of-row payload.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PayloadDigest(String);

/// MIME media type for an out-of-row payload.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediaType(String);

macro_rules! impl_non_empty_text {
    ($type:ident, $field:literal) => {
        impl $type {
            /// Validate and wrap a non-blank string.
            pub fn new(value: impl Into<String>) -> Result<Self, EventError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(EventError::BlankText { field: $field });
                }
                Ok(Self(value))
            }

            /// Wrap a string constant known at compile time to be non-blank.
            ///
            /// Intended for fixed values such as provenance attribute keys and
            /// fixed event names. Panics if `value` is blank: for a hardcoded
            /// constant that is a programming error surfaced at first use, not a
            /// runtime condition a caller should handle, so this stays infallible
            /// and avoids threading a `Result` through code that cannot fail.
            #[must_use]
            pub fn from_static(value: &'static str) -> Self {
                assert!(
                    !value.trim().is_empty(),
                    concat!($field, " constant must not be blank")
                );
                Self(value.to_owned())
            }

            /// Original string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl TryFrom<String> for $type {
            type Error = EventError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $type {
            type Error = EventError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

impl_non_empty_text!(AttributeKey, "attribute key");
impl_non_empty_text!(EventName, "event name");
impl_non_empty_text!(PayloadDigest, "payload digest");
impl_non_empty_text!(MediaType, "media type");

/// Finite floating-point telemetry value.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FiniteF64(f64);

impl FiniteF64 {
    /// Rejects NaN and infinity.
    pub fn new(value: f64) -> Result<Self, EventError> {
        if value.is_finite() {
            Ok(Self(value))
        } else {
            Err(EventError::NonFiniteFloat { value })
        }
    }

    /// Raw floating-point value.
    pub fn as_f64(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for FiniteF64 {
    type Error = EventError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Display for FiniteF64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Serialize for FiniteF64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for FiniteF64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Narrow scalar value for a telemetry attribute.
///
/// Keep this intentionally smaller than OTEL's full value model until a signal
/// needs more shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    I64(i64),
    F64(FiniteF64),
    Bool(bool),
}

impl From<String> for AttributeValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for AttributeValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<i64> for AttributeValue {
    fn from(value: i64) -> Self {
        Self::I64(value)
    }
}

impl From<FiniteF64> for AttributeValue {
    fn from(value: FiniteF64) -> Self {
        Self::F64(value)
    }
}

impl TryFrom<f64> for AttributeValue {
    type Error = EventError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        FiniteF64::new(value).map(Self::F64)
    }
}

impl From<bool> for AttributeValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

/// High-level family used for routing and storage projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    /// OpenTelemetry span-like operation.
    Span,
    /// Log record or structured diagnostic message.
    Log,
    /// Metric sample or aggregate.
    Metric,
    /// Network request, response, or proxy observation.
    Net,
    /// Process execution event.
    Exec,
    /// LLM request, response, or tool-call event.
    Llm,
    /// Human- or agent-authored annotation attached to the fork tree.
    Annotation,
}

/// Reference to a large payload stored out-of-row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRef {
    pub digest: PayloadDigest,
    pub media_type: Option<MediaType>,
    pub size_bytes: Option<u64>,
}

impl PayloadRef {
    /// Start a payload reference with no optional metadata.
    pub fn new(digest: PayloadDigest) -> Self {
        Self {
            digest,
            media_type: None,
            size_bytes: None,
        }
    }

    /// Set the declared media type.
    #[must_use]
    pub fn with_media_type(mut self, media_type: MediaType) -> Self {
        self.media_type = Some(media_type);
        self
    }

    /// Set the payload size in bytes when known.
    #[must_use]
    pub fn with_size_bytes(mut self, size_bytes: u64) -> Self {
        self.size_bytes = Some(size_bytes);
        self
    }
}

/// A single normalized, fork-stamped telemetry event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Stable per-event identity. Defaults when absent (older records) so deserialization stays
    /// backward-compatible; freshly captured events always carry a minted id from [`Event::new`].
    #[serde(default)]
    pub event_id: EventId,
    pub ts: Hlc,
    pub run_id: RunId,
    pub fork_node_id: ForkNodeId,
    pub fork_path: ForkPath,
    pub signal: SignalType,
    pub name: EventName,
    pub attributes: Attributes,
    pub payload_ref: Option<PayloadRef>,
}

impl Event {
    /// Creates an event stamped with the resolved fork context and a freshly minted event id.
    pub fn new(context: &ForkContext, ts: Hlc, signal: SignalType, name: EventName) -> Self {
        Self {
            event_id: EventId::new(),
            ts,
            run_id: context.run_id,
            fork_node_id: context.fork_node_id,
            fork_path: context.fork_path.clone(),
            signal,
            name,
            attributes: Attributes::new(),
            payload_ref: None,
        }
    }

    /// Inserts or replaces one attribute.
    #[must_use]
    pub fn with_attribute(mut self, key: AttributeKey, value: impl Into<AttributeValue>) -> Self {
        self.attributes.insert(key, value.into());
        self
    }

    /// Sets the out-of-row payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: PayloadRef) -> Self {
        self.payload_ref = Some(payload_ref);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ForkContext;
    use serde_json::json;

    #[test]
    fn event_schema_serializes_opaque_text_types_as_strings() {
        let context = ForkContext::new_local_root();
        let payload_ref = PayloadRef::new(PayloadDigest::new("sha256:abc").expect("digest"))
            .with_media_type(MediaType::new("application/json").expect("media type"))
            .with_size_bytes(12);
        let event = Event::new(
            &context,
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Net,
            EventName::new("http.request").expect("event name"),
        )
        .with_attribute(
            AttributeKey::new("http.status_code").expect("attribute key"),
            200_i64,
        )
        .with_payload_ref(payload_ref);

        let value = serde_json::to_value(event).expect("serialize event");

        assert_eq!(value["name"], json!("http.request"));
        assert_eq!(value["attributes"]["http.status_code"], json!(200));
        assert_eq!(value["payload_ref"]["digest"], json!("sha256:abc"));
        assert_eq!(
            value["payload_ref"]["media_type"],
            json!("application/json")
        );
        assert_eq!(value["payload_ref"]["size_bytes"], json!(12));
    }

    #[test]
    fn signal_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(SignalType::Annotation).expect("serialize"),
            json!("annotation")
        );
        assert_eq!(
            serde_json::from_value::<SignalType>(json!("annotation")).expect("deserialize"),
            SignalType::Annotation
        );
    }

    #[test]
    fn text_newtypes_reject_blank_values() {
        assert!(AttributeKey::new("").is_err());
        assert!(EventName::new(" ").is_err());
        assert!(PayloadDigest::new("").is_err());
        assert!(MediaType::new("\t").is_err());
    }

    #[test]
    fn from_static_wraps_non_blank_constants() {
        assert_eq!(
            AttributeKey::from_static("normalizer.name").as_str(),
            "normalizer.name"
        );
        assert_eq!(
            EventName::from_static("process.stdout").as_str(),
            "process.stdout"
        );
    }

    #[test]
    #[should_panic(expected = "must not be blank")]
    fn from_static_panics_on_blank_constant() {
        let _ = AttributeKey::from_static("   ");
    }

    #[test]
    fn float_attributes_must_be_finite() {
        assert!(FiniteF64::new(1.5).is_ok());
        assert!(FiniteF64::new(f64::NAN).is_err());
        assert!(FiniteF64::new(f64::INFINITY).is_err());
    }
}
