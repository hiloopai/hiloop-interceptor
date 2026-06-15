//! Stdio capture and normalization.

use crate::framing::LineFramer;
use crate::seams::{
    NormalizationContext, NormalizationOutcome, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerSupport, RawSignal, RawSignalSink, ShutdownSignal, SinkSend, Source, SourceError,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hiloop_core::{
    event::{AttributeKey, Event, EventName, SignalType},
    identity::HlcClock,
};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

const DESCRIPTOR: NormalizerDescriptor =
    NormalizerDescriptor::new("stdio-log", env!("CARGO_PKG_VERSION"), "hiloop.event.v1");

/// Default read buffer for [`StdioSource`].
const STDIO_READ_BUFFER_BYTES: usize = 8192;

/// Pull-style [`Source`] that frames one child stream into stdio raw signals.
///
/// Composes [`LineFramer`] (it does not reimplement framing) over an
/// [`AsyncRead`], tees every byte verbatim to a paired [`AsyncWrite`] before
/// framing, and emits one `stdio`/`{stream_name}` [`RawSignal`] per completed
/// record. This is the concrete proof of the [`Source`] lifecycle for the pull
/// case: `run` is a read loop that returns at end-of-input.
///
/// The tee preserves the child's exact bytes and ordering (TESTING.md B1/B6):
/// bytes are written and flushed downstream *before* being handed to the framer,
/// and records from one stream are sent in order. Pair two `StdioSource`s (stdout
/// and stderr) to capture both child streams.
pub struct StdioSource<R, W> {
    reader: R,
    writer: W,
    stream_name: &'static str,
    clock: Arc<HlcClock>,
    max_record_bytes: usize,
    read_buffer_bytes: usize,
}

impl<R, W> StdioSource<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Capture `reader`, teeing to `writer`, framing records at `max_record_bytes`.
    ///
    /// `stream_name` becomes the raw `kind` (`"stdout"` or `"stderr"`); `clock`
    /// stamps each record's observation time.
    ///
    /// # Panics
    ///
    /// Panics if `max_record_bytes` is zero (see [`LineFramer::new`]).
    pub fn new(
        reader: R,
        writer: W,
        stream_name: &'static str,
        clock: Arc<HlcClock>,
        max_record_bytes: usize,
    ) -> Self {
        assert!(
            max_record_bytes > 0,
            "max_record_bytes must be greater than zero"
        );
        Self {
            reader,
            writer,
            stream_name,
            clock,
            max_record_bytes,
            read_buffer_bytes: STDIO_READ_BUFFER_BYTES,
        }
    }
}

async fn deliver_record(
    sink: &RawSignalSink,
    stream_name: &'static str,
    clock: &HlcClock,
    record: Vec<u8>,
) -> SinkSend {
    let raw = RawSignal::new("stdio", stream_name, clock.tick(), Bytes::from(record));
    sink.send(raw).await
}

#[async_trait]
impl<R, W> Source for StdioSource<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    fn name(&self) -> &'static str {
        self.stream_name
    }

    async fn run(
        self: Box<Self>,
        sink: RawSignalSink,
        mut shutdown: ShutdownSignal,
    ) -> Result<(), SourceError> {
        let Self {
            mut reader,
            mut writer,
            stream_name,
            clock,
            max_record_bytes,
            read_buffer_bytes,
        } = *self;

        let tee_error = |verb: &str, error: std::io::Error| SourceError::Other {
            source_name: stream_name.to_owned(),
            message: format!("failed to {verb} child {stream_name}: {error}"),
        };

        let mut framer = LineFramer::new(max_record_bytes);
        let mut buffer = vec![0u8; read_buffer_bytes];

        loop {
            let read = tokio::select! {
                () = &mut shutdown => break,
                read = reader.read(&mut buffer) => read.map_err(|error| SourceError::Other {
                    source_name: stream_name.to_owned(),
                    message: format!("failed to read child {stream_name}: {error}"),
                })?,
            };
            if read == 0 {
                break;
            }

            let chunk = &buffer[..read];
            // Tee verbatim before framing so downstream sees the child's exact
            // bytes and ordering (TESTING.md B1).
            writer
                .write_all(chunk)
                .await
                .map_err(|error| tee_error("tee", error))?;
            writer
                .flush()
                .await
                .map_err(|error| tee_error("flush tee for", error))?;

            for record in framer.push(chunk) {
                if !deliver_record(&sink, stream_name, &clock, record)
                    .await
                    .is_open()
                {
                    return Ok(());
                }
            }
        }

        if let Some(record) = framer.flush()
            && !deliver_record(&sink, stream_name, &clock, record)
                .await
                .is_open()
        {
            return Ok(());
        }

        Ok(())
    }
}

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

    const TEST_MAX_RECORD_BYTES: usize = 64 * 1024;

    fn stdio_source(
        input: &'static [u8],
        max_record_bytes: usize,
    ) -> StdioSource<&'static [u8], Vec<u8>> {
        StdioSource::new(
            input,
            Vec::new(),
            "stdout",
            Arc::new(HlcClock::new()),
            max_record_bytes,
        )
    }

    #[tokio::test]
    async fn stdio_source_frames_lines_into_signals() {
        let signals = crate::seams::testing::assert_source_contract(
            stdio_source(b"alpha\nbeta\n", TEST_MAX_RECORD_BYTES),
            8,
        )
        .await;

        let bodies = signals
            .iter()
            .map(|raw| raw.body.as_ref().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(bodies, vec![b"alpha".to_vec(), b"beta".to_vec()]);
        assert!(signals.iter().all(|raw| raw.source == "stdio"));
        assert!(signals.iter().all(|raw| raw.kind == "stdout"));
    }

    #[tokio::test]
    async fn stdio_source_emits_trailing_partial_line() {
        let signals = crate::seams::testing::assert_source_contract(
            stdio_source(b"done\npartial", TEST_MAX_RECORD_BYTES),
            8,
        )
        .await;

        let bodies = signals
            .iter()
            .map(|raw| raw.body.as_ref().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(bodies, vec![b"done".to_vec(), b"partial".to_vec()]);
    }

    #[tokio::test]
    async fn stdio_source_chunks_overlong_record() {
        let signals =
            crate::seams::testing::assert_source_contract(stdio_source(b"aaaaaa", 4), 8).await;

        let lengths = signals.iter().map(|raw| raw.body.len()).collect::<Vec<_>>();
        assert_eq!(lengths, vec![4, 2]);
    }

    #[tokio::test]
    async fn stdio_source_tees_bytes_verbatim() {
        let clock = Arc::new(HlcClock::new());
        let mut tee = Vec::new();
        let source = StdioSource::new(
            &b"hi\nthere\r\n"[..],
            &mut tee,
            "stdout",
            clock,
            TEST_MAX_RECORD_BYTES,
        );

        let (result, _signals) = crate::seams::testing::drain_source(source, 8).await;
        result.expect("stdio source runs cleanly");

        // The tee preserves the child's exact bytes, including the CRLF that
        // framing trims from the emitted record.
        assert_eq!(tee, b"hi\nthere\r\n");
    }
}
