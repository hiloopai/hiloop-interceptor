//! Stdio capture and normalization.

use crate::seams::{
    NormalizationContext, NormalizationOutcome, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerSupport, RawSignal,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hiloop_core::event::{AttributeKey, Event, EventName, SignalType};

const DESCRIPTOR: NormalizerDescriptor =
    NormalizerDescriptor::new("stdio-log", env!("CARGO_PKG_VERSION"), "hiloop.event.v1");

/// Normalizes captured stdout/stderr lines as log events.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdioLogNormalizer;

#[async_trait]
impl Normalizer for StdioLogNormalizer {
    fn descriptor(&self) -> NormalizerDescriptor {
        DESCRIPTOR
    }

    fn supports(&self, raw: &RawSignal) -> NormalizerSupport {
        if raw.source == "stdio" && matches!(raw.kind.as_str(), "stdout" | "stderr") {
            NormalizerSupport::Exact
        } else {
            NormalizerSupport::Unsupported
        }
    }

    async fn normalize(
        &self,
        context: &NormalizationContext,
        raw: RawSignal,
    ) -> Result<NormalizationOutcome, NormalizeError> {
        let event_name = match raw.kind.as_str() {
            "stdout" => EventName::new("process.stdout"),
            "stderr" => EventName::new("process.stderr"),
            _ => {
                return Err(NormalizeError::Unsupported {
                    normalizer: self.descriptor().name(),
                    source_name: raw.source,
                    kind: raw.kind,
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
        let mut event = Event::new(
            context.fork_context(),
            raw.observed_at,
            SignalType::Log,
            event_name,
        );

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

        Ok(NormalizationOutcome::from_events(vec![event]))
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

        let outcome = StdioLogNormalizer
            .normalize(
                &NormalizationContext::new(ForkContext::new_local_root()),
                raw,
            )
            .await
            .expect("normalize stdout");

        let events = outcome.events();
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
                .normalize(
                    &NormalizationContext::new(ForkContext::new_local_root()),
                    raw
                )
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

        let outcome = StdioLogNormalizer
            .normalize(
                &NormalizationContext::new(ForkContext::new_local_root()),
                raw,
            )
            .await
            .expect("normalize stdout");

        let events = outcome.events();
        let value = serde_json::to_value(&events[0]).expect("serialize event");
        assert_eq!(value["attributes"]["message_base64"], "/wBh");
        assert_eq!(value["attributes"]["message_encoding"], "base64");
        assert!(value["attributes"].get("message").is_none());
    }

    #[tokio::test]
    async fn satisfies_normalizer_contract_for_supported_stdio() {
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(b"hello"),
        );

        let outcome = crate::seams::testing::assert_normalizer_accepts_supported_raw(
            &StdioLogNormalizer,
            raw,
        )
        .await
        .expect("normalizer contract");

        assert_eq!(outcome.events().len(), 1);
    }
}
