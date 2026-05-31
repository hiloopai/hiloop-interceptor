//! Stdio capture and normalization.

use crate::seams::{NormalizeError, Normalizer, RawSignal};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hiloop_core::{
    event::{AttributeKey, Event, EventName, SignalType},
    identity::ForkContext,
};

/// Normalizes captured stdout/stderr lines as log events.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdioLogNormalizer;

#[async_trait]
impl Normalizer for StdioLogNormalizer {
    async fn normalize(
        &self,
        context: &ForkContext,
        raw: RawSignal,
    ) -> Result<Vec<Event>, NormalizeError> {
        let event_name = match raw.kind.as_str() {
            "stdout" => EventName::new("process.stdout"),
            "stderr" => EventName::new("process.stderr"),
            _ => {
                return Err(NormalizeError::Decode {
                    source_name: raw.source,
                    kind: raw.kind,
                    message: "unsupported stdio stream".to_owned(),
                });
            }
        }
        .map_err(|error| NormalizeError::Decode {
            source_name: raw.source.clone(),
            kind: raw.kind.clone(),
            message: error.to_string(),
        })?;

        let message_key = attribute_key("message", &raw)?;
        let message_base64_key = attribute_key("message_base64", &raw)?;
        let message_encoding_key = attribute_key("message_encoding", &raw)?;
        let stream_key = attribute_key("stream", &raw)?;
        let source_key = attribute_key("source", &raw)?;
        let mut event = Event::new(context, raw.observed_at, SignalType::Log, event_name);

        match std::str::from_utf8(&raw.body) {
            Ok(message) => {
                event = event.with_attribute(message_key, message);
            }
            Err(_) => {
                event = event
                    .with_attribute(message_base64_key, STANDARD.encode(&raw.body))
                    .with_attribute(message_encoding_key, "base64");
            }
        }

        let event = event
            .with_attribute(stream_key, raw.kind)
            .with_attribute(source_key, raw.source);

        Ok(vec![event])
    }
}

fn attribute_key(value: &'static str, raw: &RawSignal) -> Result<AttributeKey, NormalizeError> {
    AttributeKey::new(value).map_err(|error| NormalizeError::Decode {
        source_name: raw.source.clone(),
        kind: raw.kind.clone(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hiloop_core::identity::{ForkContext, Hlc};

    #[tokio::test]
    async fn normalizes_stdout_into_log_event() {
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(b"hello"),
        );

        let events = StdioLogNormalizer
            .normalize(&ForkContext::new_local_root(), raw)
            .await
            .expect("normalize stdout");

        assert_eq!(events.len(), 1);
        let value = serde_json::to_value(&events[0]).expect("serialize event");
        assert_eq!(value["signal"], "log");
        assert_eq!(value["name"], "process.stdout");
        assert_eq!(value["attributes"]["message"], "hello");
        assert_eq!(value["attributes"]["stream"], "stdout");
        assert_eq!(value["attributes"]["source"], "stdio");
    }

    #[tokio::test]
    async fn rejects_unknown_stdio_kind() {
        let raw = RawSignal::new(
            "stdio",
            "stdin",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::new(),
        );

        assert!(
            StdioLogNormalizer
                .normalize(&ForkContext::new_local_root(), raw)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn non_utf8_output_is_encoded_losslessly() {
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(&[0xff, 0x00, b'a']),
        );

        let events = StdioLogNormalizer
            .normalize(&ForkContext::new_local_root(), raw)
            .await
            .expect("normalize stdout");

        let value = serde_json::to_value(&events[0]).expect("serialize event");
        assert_eq!(value["attributes"]["message_base64"], "/wBh");
        assert_eq!(value["attributes"]["message_encoding"], "base64");
        assert!(value["attributes"].get("message").is_none());
    }
}
