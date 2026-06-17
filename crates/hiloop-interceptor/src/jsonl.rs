//! Shared exclusive-create JSONL writer.
//!
//! Both the event exporter and the raw observation store write
//! newline-delimited JSON to an exclusive-create file behind a `Mutex`.
//! This module extracts that common pattern so each consumer only implements
//! its own serialization logic.

use std::{io, path::Path};

use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};

/// Mutex-guarded, exclusive-create JSONL file.
///
/// Handles the `OpenOptions::create_new(true)` idiom, line-delimited writes,
/// and flush — the same mechanics that `JsonlExporter` and `JsonlRawStore`
/// previously duplicated.
#[derive(Debug)]
pub struct JsonlWriter {
    file: Mutex<File>,
}

impl JsonlWriter {
    /// Create an output file, failing if the path already exists.
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

    /// Write one pre-serialized line followed by a newline separator.
    ///
    /// Callers are responsible for serialization; this method only appends and
    /// separates. The write is atomic with respect to other `write_line` /
    /// `flush` calls on the same writer (guarded by the internal mutex).
    pub async fn write_line(&self, line: &[u8]) -> io::Result<()> {
        let mut file = self.file.lock().await;
        file.write_all(line).await?;
        file.write_all(b"\n").await?;
        Ok(())
    }

    /// Flush the underlying file.
    pub async fn flush(&self) -> io::Result<()> {
        self.file.lock().await.flush().await
    }
}
