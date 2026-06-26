//! Local exporters used by the interceptor runtime and tests.

use crate::seams::{ExportError, Exporter};
use async_trait::async_trait;
use hiloop_core::event::Event;
use std::{io, path::Path};
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};

/// Writes normalized events as newline-delimited JSON.
#[derive(Debug)]
pub struct JsonlExporter {
    file: Mutex<File>,
}

impl JsonlExporter {
    /// Creates a JSONL output file, failing if the path already exists.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .await?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

#[async_trait]
impl Exporter for JsonlExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        let mut file = self.file.lock().await;
        for event in events {
            let line = serde_json::to_vec(event).map_err(jsonl_error)?;
            file.write_all(&line)
                .await
                .map_err(|error| io_error("failed to write event", error))?;
            file.write_all(b"\n")
                .await
                .map_err(|error| io_error("failed to write event separator", error))?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), ExportError> {
        self.file
            .lock()
            .await
            .flush()
            .await
            .map_err(|error| io_error("failed to flush events", error))
    }
}

fn io_error(message: &'static str, error: io::Error) -> ExportError {
    ExportError::with_source("jsonl", message, error)
}

fn jsonl_error(error: serde_json::Error) -> ExportError {
    ExportError::with_source("jsonl", "failed to encode event as JSON", error)
}

/// Fans every batch out to several exporters (e.g. local JSONL + the telemetry gateway), so one wrap
/// can both keep a local trail and stream to the backend. Every exporter is attempted on each call;
/// the first error is returned afterward so a failing sink (e.g. a gateway outage) is surfaced without
/// preventing the others from receiving the batch.
pub struct FanoutExporter {
    exporters: Vec<Box<dyn Exporter>>,
}

impl FanoutExporter {
    /// Builds a fanout over `exporters`.
    #[must_use]
    pub fn new(exporters: Vec<Box<dyn Exporter>>) -> Self {
        Self { exporters }
    }
}

#[async_trait]
impl Exporter for FanoutExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        let mut first_error = None;
        for exporter in &self.exporters {
            if let Err(error) = exporter.export(events).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn flush(&self) -> Result<(), ExportError> {
        let mut first_error = None;
        for exporter in &self.exporters {
            if let Err(error) = exporter.flush().await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use hiloop_core::{
        event::{AttributeKey, Event, EventName, SignalType},
        identity::{ForkContext, Hlc},
    };

    pub(crate) fn sample_log_event() -> Event {
        Event::new(
            &ForkContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Log,
            EventName::new("process.stdout").expect("event name"),
        )
        .with_attribute(
            AttributeKey::new("message").expect("attribute key"),
            "hello",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::sample_log_event, *};
    use crate::seams::{Exporter, testing::MemoryExporter};
    use serde_json::Value;

    async fn assert_exporter_accepts_empty_batch_and_flushes<E>(exporter: &E)
    where
        E: Exporter,
    {
        exporter
            .export(&[])
            .await
            .expect("empty batch should succeed");
        exporter
            .export(&[sample_log_event()])
            .await
            .expect("event batch should succeed");
        exporter.flush().await.expect("flush should succeed");
    }

    #[tokio::test]
    async fn memory_exporter_satisfies_exporter_contract() {
        let exporter = MemoryExporter::default();

        assert_exporter_accepts_empty_batch_and_flushes(&exporter).await;

        assert_eq!(exporter.events().len(), 1);
    }

    #[tokio::test]
    async fn jsonl_exporter_satisfies_exporter_contract() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("events.jsonl");
        let exporter = JsonlExporter::create(&path).await.expect("create exporter");

        assert_exporter_accepts_empty_batch_and_flushes(&exporter).await;

        let contents = tokio::fs::read_to_string(path).await.expect("read jsonl");
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);

        let event = serde_json::from_str::<Value>(lines[0]).expect("event json");
        assert_eq!(event["signal"], "log");
        assert_eq!(event["name"], "process.stdout");
        assert_eq!(event["attributes"]["message"], "hello");
    }

    #[tokio::test]
    async fn jsonl_exporter_refuses_to_overwrite_existing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("events.jsonl");
        tokio::fs::write(&path, "existing")
            .await
            .expect("seed file");

        let error = JsonlExporter::create(&path)
            .await
            .expect_err("existing file should not be overwritten");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        let contents = tokio::fs::read_to_string(path).await.expect("read file");
        assert_eq!(contents, "existing");
    }
}
