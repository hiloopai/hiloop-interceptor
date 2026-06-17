//! Raw observation storage implementations.

use crate::jsonl::JsonlWriter;
use crate::seams::{NormalizationContext, RawObservationRef, RawSignal, RawStore, RawStoreError};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    io,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

/// Writes retained raw observations as newline-delimited JSON.
#[derive(Debug)]
pub struct JsonlRawStore {
    writer: JsonlWriter,
    next_id: AtomicU64,
}

impl JsonlRawStore {
    /// Creates a raw-observation JSONL file, failing if the path already exists.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            writer: JsonlWriter::create(path).await?,
            next_id: AtomicU64::new(1),
        })
    }
}

#[async_trait]
impl RawStore for JsonlRawStore {
    async fn store(
        &self,
        context: &NormalizationContext,
        raw: &RawSignal,
    ) -> Result<RawObservationRef, RawStoreError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let raw_ref = RawObservationRef::new(format!("raw-jsonl-{id}"))?;
        let record = raw_record(&raw_ref, context, raw);
        let line = serde_json::to_vec(&record).map_err(|error| {
            RawStoreError::with_source("raw-jsonl", "failed to encode raw observation", error)
        })?;

        self.writer
            .write_line(&line)
            .await
            .map_err(|error| raw_io_error("failed to write raw observation", error))?;

        Ok(raw_ref)
    }

    async fn flush(&self) -> Result<(), RawStoreError> {
        self.writer
            .flush()
            .await
            .map_err(|error| raw_io_error("failed to flush raw observations", error))
    }
}

fn raw_record(
    raw_ref: &RawObservationRef,
    context: &NormalizationContext,
    raw: &RawSignal,
) -> Value {
    let fork = context.fork_context();
    json!({
        "schema": "hiloop.raw_observation.v1",
        "id": raw_ref.id(),
        "run_id": fork.run_id,
        "fork_node_id": fork.fork_node_id,
        "fork_path": &fork.fork_path,
        "observed_at": raw.observed_at,
        "source": raw.source.as_str(),
        "kind": raw.kind.as_str(),
        "attributes": &raw.attributes,
        "body_base64": STANDARD.encode(raw.body.as_ref()),
        "body_encoding": "base64",
        "wrapper": {
            "name": context.wrapper.name,
            "version": context.wrapper.version,
        },
        "process": process_record(context),
    })
}

fn process_record(context: &NormalizationContext) -> Value {
    let Some(process) = &context.process else {
        return Value::Null;
    };

    json!({
        "pid": process.pid,
        "command": process.command.as_ref().map(|path| path.display().to_string()),
        "argv": &process.argv,
        "cwd": process.cwd.as_ref().map(|path| path.display().to_string()),
    })
}

fn raw_io_error(message: &'static str, error: io::Error) -> RawStoreError {
    RawStoreError::with_source("raw-jsonl", message, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hiloop_core::identity::{ForkContext, Hlc};
    use serde_json::Value;

    #[tokio::test]
    async fn jsonl_raw_store_writes_raw_observations() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("raw.jsonl");
        let store = JsonlRawStore::create(&path)
            .await
            .expect("create raw store");
        let context = NormalizationContext::new(ForkContext::new_local_root());
        let raw = RawSignal::new(
            "stdio",
            "stdout",
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            Bytes::from_static(b"hello"),
        )
        .with_attribute("stream", "stdout");

        let raw_ref = store.store(&context, &raw).await.expect("store raw");
        store.flush().await.expect("flush raw");

        assert_eq!(raw_ref.id(), "raw-jsonl-1");
        let contents = tokio::fs::read_to_string(path)
            .await
            .expect("read raw jsonl");
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);

        let record = serde_json::from_str::<Value>(lines[0]).expect("raw record");
        assert_eq!(record["schema"], "hiloop.raw_observation.v1");
        assert_eq!(record["id"], "raw-jsonl-1");
        assert_eq!(record["source"], "stdio");
        assert_eq!(record["kind"], "stdout");
        assert_eq!(record["attributes"]["stream"], "stdout");
        assert_eq!(record["body_base64"], "aGVsbG8=");
        assert_eq!(record["body_encoding"], "base64");
    }

    #[tokio::test]
    async fn jsonl_raw_store_refuses_to_overwrite_existing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("raw.jsonl");
        tokio::fs::write(&path, "existing")
            .await
            .expect("seed file");

        let error = JsonlRawStore::create(&path)
            .await
            .expect_err("existing raw file should not be overwritten");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }
}
