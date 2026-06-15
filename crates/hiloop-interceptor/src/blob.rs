//! Content-addressed blob storage for streamed HTTP bodies.
//!
//! The proxy streams each body frame into a [`BlobWriter`] as it arrives, so only
//! one frame is in memory at a time. `finish` returns a [`PayloadRef`] keyed by the
//! sha256 of the content; identical bodies dedup to the same file.

use std::{
    error::Error as StdError,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use hiloop_core::event::{PayloadDigest, PayloadRef};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

/// Boxed future returned by [`BlobWriter`] methods.
//
// Hand-rolled (not `#[async_trait]`) and `Sync`-bound because the proxy stores
// the writer inside the streaming response Body, which hudsucker requires to be
// `Sync`; `async_trait` only produces `Send` futures.
pub type BlobFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;

/// Opens streaming writers that persist blobs by content hash.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Open a streaming writer for one blob.
    fn writer(&self) -> Box<dyn BlobWriter>;
}

/// Streams one blob's bytes and finalizes its content-addressed reference.
pub trait BlobWriter: Send + Sync {
    fn write<'a>(&'a mut self, chunk: &'a [u8]) -> BlobFuture<'a, Result<(), BlobStoreError>>;

    /// Finalize and return the content-addressed reference (sha256 + size).
    fn finish(self: Box<Self>) -> BlobFuture<'static, Result<PayloadRef, BlobStoreError>>;
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

#[derive(Debug, Error)]
pub enum BlobStoreError {
    #[error("blob store `{store}` failed: {message}")]
    Other {
        store: String,
        message: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl BlobStoreError {
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

const STORE_NAME: &str = "blob-dir";

/// File-backed content-addressed store: blobs land at `<dir>/sha256-<hex>`.
#[derive(Debug, Clone)]
pub struct DirBlobStore {
    dir: PathBuf,
}

impl DirBlobStore {
    /// Create the store directory if it does not yet exist.
    pub async fn create(dir: impl Into<PathBuf>) -> Result<Self, BlobStoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).await.map_err(|error| {
            BlobStoreError::with_source(STORE_NAME, "failed to create dir", error)
        })?;
        Ok(Self { dir })
    }
}

// Temp-file uniqueness within one process: pid plus a monotonic counter.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[async_trait]
impl BlobStore for DirBlobStore {
    fn writer(&self) -> Box<dyn BlobWriter> {
        Box::new(DirBlobWriter {
            dir: self.dir.clone(),
            state: None,
        })
    }
}

struct DirBlobWriterOpen {
    temp_path: PathBuf,
    file: File,
    hasher: Sha256,
    size: u64,
}

struct DirBlobWriter {
    dir: PathBuf,
    state: Option<DirBlobWriterOpen>,
}

impl DirBlobWriter {
    async fn open(&mut self) -> Result<&mut DirBlobWriterOpen, BlobStoreError> {
        if self.state.is_none() {
            let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temp_path = self
                .dir
                .join(format!(".tmp-{}-{id:016x}", std::process::id()));
            let file = File::create(&temp_path).await.map_err(|error| {
                BlobStoreError::with_source(STORE_NAME, "failed to create temp blob", error)
            })?;
            self.state = Some(DirBlobWriterOpen {
                temp_path,
                file,
                hasher: Sha256::new(),
                size: 0,
            });
        }
        Ok(self.state.as_mut().expect("state opened above"))
    }
}

impl BlobWriter for DirBlobWriter {
    fn write<'a>(&'a mut self, chunk: &'a [u8]) -> BlobFuture<'a, Result<(), BlobStoreError>> {
        Box::pin(async move {
            let open = self.open().await?;
            open.file.write_all(chunk).await.map_err(|error| {
                BlobStoreError::with_source(STORE_NAME, "failed to write blob chunk", error)
            })?;
            open.hasher.update(chunk);
            open.size += chunk.len() as u64;
            Ok(())
        })
    }

    fn finish(mut self: Box<Self>) -> BlobFuture<'static, Result<PayloadRef, BlobStoreError>> {
        Box::pin(async move {
            // A writer that never received a write still has a valid (empty) blob.
            self.open().await?;
            let mut open = self
                .state
                .take()
                .ok_or_else(|| BlobStoreError::other(STORE_NAME, "writer state missing"))?;

            open.file.flush().await.map_err(|error| {
                BlobStoreError::with_source(STORE_NAME, "failed to flush blob", error)
            })?;
            drop(open.file);

            let hex = to_hex(&open.hasher.finalize());
            let target = self.dir.join(format!("sha256-{hex}"));

            // Content-addressed dedup: identical content already at the target
            // makes the rename redundant, so drop the temp instead.
            if fs::try_exists(&target).await.unwrap_or(false) {
                let _ = fs::remove_file(&open.temp_path).await;
            } else {
                fs::rename(&open.temp_path, &target)
                    .await
                    .map_err(|error| {
                        BlobStoreError::with_source(STORE_NAME, "failed to commit blob", error)
                    })?;
            }

            let digest = PayloadDigest::new(format!("sha256:{hex}")).map_err(|error| {
                BlobStoreError::with_source(STORE_NAME, "invalid digest", error)
            })?;
            Ok(PayloadRef::new(digest).with_size_bytes(open.size))
        })
    }
}

/// Test helpers and an in-memory store for conformance suites.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use super::{BlobFuture, BlobStore, BlobStoreError, BlobWriter};
    use async_trait::async_trait;
    use hiloop_core::event::{PayloadDigest, PayloadRef};
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};

    type Recorded = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// In-memory [`BlobStore`] that records finalized blobs by digest.
    #[derive(Debug, Default, Clone)]
    pub struct MemoryBlobStore {
        blobs: Recorded,
    }

    impl MemoryBlobStore {
        pub fn blobs(&self) -> Vec<(String, Vec<u8>)> {
            self.blobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl BlobStore for MemoryBlobStore {
        fn writer(&self) -> Box<dyn BlobWriter> {
            Box::new(MemoryBlobWriter {
                buffer: Vec::new(),
                sink: Arc::clone(&self.blobs),
            })
        }
    }

    struct MemoryBlobWriter {
        buffer: Vec<u8>,
        sink: Recorded,
    }

    impl BlobWriter for MemoryBlobWriter {
        fn write<'a>(&'a mut self, chunk: &'a [u8]) -> BlobFuture<'a, Result<(), BlobStoreError>> {
            self.buffer.extend_from_slice(chunk);
            Box::pin(async { Ok(()) })
        }

        fn finish(self: Box<Self>) -> BlobFuture<'static, Result<PayloadRef, BlobStoreError>> {
            Box::pin(async move {
                let hex = super::to_hex(&Sha256::digest(&self.buffer));
                let size = self.buffer.len() as u64;
                self.sink
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((format!("sha256:{hex}"), self.buffer));
                let digest = PayloadDigest::new(format!("sha256:{hex}")).map_err(|error| {
                    BlobStoreError::with_source("memory-blob", "invalid digest", error)
                })?;
                Ok(PayloadRef::new(digest).with_size_bytes(size))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_in_chunks_yields_stable_sha256() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = DirBlobStore::create(temp.path())
            .await
            .expect("create store");

        let mut writer = store.writer();
        writer.write(b"hello ").await.expect("write");
        writer.write(b"world").await.expect("write");
        let payload_ref = writer.finish().await.expect("finish");

        // Reference sha256 of "hello world".
        assert_eq!(
            payload_ref.digest.as_str(),
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(payload_ref.size_bytes, Some(11));
        let blob = temp
            .path()
            .join("sha256-b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(
            tokio::fs::read(&blob).await.expect("read blob"),
            b"hello world"
        );
    }

    #[tokio::test]
    async fn identical_content_dedups_to_one_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = DirBlobStore::create(temp.path())
            .await
            .expect("create store");

        let mut first = store.writer();
        first.write(b"same").await.expect("write");
        let first_ref = first.finish().await.expect("finish");

        let mut second = store.writer();
        second.write(b"same").await.expect("write");
        let second_ref = second.finish().await.expect("finish");

        assert_eq!(first_ref.digest, second_ref.digest);
        let mut entries = tokio::fs::read_dir(temp.path()).await.expect("read dir");
        let mut count = 0;
        while entries.next_entry().await.expect("entry").is_some() {
            count += 1;
        }
        assert_eq!(count, 1, "identical content dedups to a single blob file");
    }

    #[tokio::test]
    async fn different_content_differs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = DirBlobStore::create(temp.path())
            .await
            .expect("create store");

        let mut first = store.writer();
        first.write(b"alpha").await.expect("write");
        let first_ref = first.finish().await.expect("finish");

        let mut second = store.writer();
        second.write(b"beta").await.expect("write");
        let second_ref = second.finish().await.expect("finish");

        assert_ne!(first_ref.digest, second_ref.digest);
    }
}
