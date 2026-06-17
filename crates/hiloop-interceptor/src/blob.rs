//! Content-addressed blob storage for streamed HTTP bodies.
//!
//! The proxy streams each body frame into a [`BlobWriter`] as it arrives, so only
//! one frame is in memory at a time. `finish` returns a [`PayloadRef`] keyed by the
//! blake3 of the content; identical bodies dedup to the same file. blake3 matches
//! the snapshot store's CAS (DESIGN §7) and is fast on the proxy hot path.

use std::{
    error::Error as StdError,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use blake3::Hasher;
use hiloop_core::event::{PayloadDigest, PayloadRef};
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

    /// Finalize and return the content-addressed reference (blake3 + size).
    fn finish(self: Box<Self>) -> BlobFuture<'static, Result<PayloadRef, BlobStoreError>>;
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

/// File-backed content-addressed store: blobs land at `<dir>/blake3-<hex>`.
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
    hasher: Hasher,
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
                hasher: Hasher::new(),
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

            let hex = open.hasher.finalize().to_hex().to_string();
            let target = self.dir.join(format!("blake3-{hex}"));

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

            let digest = PayloadDigest::new(format!("blake3:{hex}")).map_err(|error| {
                BlobStoreError::with_source(STORE_NAME, "invalid digest", error)
            })?;
            Ok(PayloadRef::new(digest).with_size_bytes(open.size))
        })
    }
}

/// Ships local blobs to a hosted backend, deduplicating by digest first.
///
/// The protocol is digest-first: ask the backend which digests it lacks via
/// [`find_missing`](BlobUploader::find_missing), then [`upload`](BlobUploader::upload)
/// only those. The backend re-hashes on receipt, so a corrupt or mislabeled
/// blob is rejected rather than trusted. This sits off the capture hot path;
/// the OSS repo ships only the seam and [`NoopUploader`], with the real hosted
/// uploader (HTTP/gRPC, presigned-URL direct-to-object-storage) living elsewhere.
#[async_trait]
pub trait BlobUploader: Send + Sync {
    /// Digest-first dedup: of these digests, return the subset the backend lacks.
    async fn find_missing(
        &self,
        digests: &[PayloadDigest],
    ) -> Result<Vec<PayloadDigest>, BlobStoreError>;

    /// Upload one blob's bytes; the backend re-hashes and rejects a mismatch.
    // Takes the full bytes for the sketch; a streaming reader is a future refinement.
    async fn upload(&self, digest: &PayloadDigest, bytes: &[u8]) -> Result<(), BlobStoreError>;
}

/// Standalone/air-gapped default: reports nothing missing, so blobs stay local.
#[derive(Debug, Default, Clone)]
pub struct NoopUploader;

#[async_trait]
impl BlobUploader for NoopUploader {
    async fn find_missing(
        &self,
        _digests: &[PayloadDigest],
    ) -> Result<Vec<PayloadDigest>, BlobStoreError> {
        Ok(Vec::new())
    }

    async fn upload(&self, _digest: &PayloadDigest, _bytes: &[u8]) -> Result<(), BlobStoreError> {
        Ok(())
    }
}

/// Upload the given blobs to `uploader`, skipping any the backend already has.
///
/// `blobs` pairs each digest with its already-read bytes (the caller supplies
/// these, e.g. by reading `<dir>/blake3-<hex>`), keeping this helper pure and
/// free of filesystem coupling. Returns how many blobs were uploaded.
//
// The real hosted path adds the "read from DirBlobStore + background queue +
// retry" wiring around this digest-first core.
pub async fn drain_to_uploader(
    uploader: &dyn BlobUploader,
    blobs: &[(PayloadDigest, Vec<u8>)],
) -> Result<usize, BlobStoreError> {
    let digests: Vec<PayloadDigest> = blobs.iter().map(|(digest, _)| digest.clone()).collect();
    let missing: std::collections::HashSet<PayloadDigest> =
        uploader.find_missing(&digests).await?.into_iter().collect();

    let mut uploaded = 0;
    for (digest, bytes) in blobs {
        if missing.contains(digest) {
            uploader.upload(digest, bytes).await?;
            uploaded += 1;
        }
    }
    Ok(uploaded)
}

/// Test helpers and an in-memory store for conformance suites.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use super::{BlobFuture, BlobStore, BlobStoreError, BlobUploader, BlobWriter};
    use async_trait::async_trait;
    use hiloop_core::event::{PayloadDigest, PayloadRef};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    type Recorded = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    type RecordedUploads = Arc<Mutex<Vec<(PayloadDigest, Vec<u8>)>>>;

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
                let hex = blake3::hash(&self.buffer).to_hex().to_string();
                let size = self.buffer.len() as u64;
                self.sink
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((format!("blake3:{hex}"), self.buffer));
                let digest = PayloadDigest::new(format!("blake3:{hex}")).map_err(|error| {
                    BlobStoreError::with_source("memory-blob", "invalid digest", error)
                })?;
                Ok(PayloadRef::new(digest).with_size_bytes(size))
            })
        }
    }

    /// Test [`BlobUploader`] recording every `find_missing` and `upload` call.
    ///
    /// Constructed with the digests the backend already "has"; `find_missing`
    /// returns the complement of that set, so a test can assert the dedup path.
    #[derive(Debug, Default, Clone)]
    pub struct RecordingUploader {
        have: Arc<HashSet<PayloadDigest>>,
        queried: Arc<Mutex<Vec<PayloadDigest>>>,
        uploaded: RecordedUploads,
    }

    impl RecordingUploader {
        /// Backend already holds `have`; everything else is reported missing.
        pub fn with_existing(have: impl IntoIterator<Item = PayloadDigest>) -> Self {
            Self {
                have: Arc::new(have.into_iter().collect()),
                queried: Arc::default(),
                uploaded: Arc::default(),
            }
        }

        pub fn queried(&self) -> Vec<PayloadDigest> {
            self.queried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        pub fn uploaded(&self) -> Vec<(PayloadDigest, Vec<u8>)> {
            self.uploaded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl BlobUploader for RecordingUploader {
        async fn find_missing(
            &self,
            digests: &[PayloadDigest],
        ) -> Result<Vec<PayloadDigest>, BlobStoreError> {
            self.queried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(digests);
            Ok(digests
                .iter()
                .filter(|digest| !self.have.contains(*digest))
                .cloned()
                .collect())
        }

        async fn upload(&self, digest: &PayloadDigest, bytes: &[u8]) -> Result<(), BlobStoreError> {
            self.uploaded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((digest.clone(), bytes.to_vec()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_in_chunks_yields_stable_blake3() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = DirBlobStore::create(temp.path())
            .await
            .expect("create store");

        let mut writer = store.writer();
        writer.write(b"hello ").await.expect("write");
        writer.write(b"world").await.expect("write");
        let payload_ref = writer.finish().await.expect("finish");

        // Reference blake3 of "hello world".
        assert_eq!(
            payload_ref.digest.as_str(),
            "blake3:d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
        assert_eq!(payload_ref.size_bytes, Some(11));
        let blob = temp
            .path()
            .join("blake3-d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
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

    fn digest(label: &str) -> PayloadDigest {
        // Any well-formed blake3 digest works here; the bytes are opaque to the seam.
        let hex = blake3::hash(label.as_bytes()).to_hex().to_string();
        PayloadDigest::new(format!("blake3:{hex}")).expect("valid digest")
    }

    #[tokio::test]
    async fn drain_uploads_only_missing_digests() {
        let have = digest("have");
        let missing = digest("missing");
        let uploader = testing::RecordingUploader::with_existing([have.clone()]);

        let blobs = vec![
            (have.clone(), b"existing".to_vec()),
            (missing.clone(), b"new".to_vec()),
        ];
        let count = drain_to_uploader(&uploader, &blobs).await.expect("drain");

        assert_eq!(count, 1);
        assert_eq!(uploader.queried(), vec![have, missing.clone()]);
        assert_eq!(uploader.uploaded(), vec![(missing, b"new".to_vec())]);
    }

    #[tokio::test]
    async fn empty_blob_writer_yields_valid_ref() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = DirBlobStore::create(temp.path())
            .await
            .expect("create store");

        let writer = store.writer();
        let payload_ref = writer.finish().await.expect("finish empty blob");

        assert_eq!(payload_ref.size_bytes, Some(0));
        let expected_hash = blake3::hash(b"").to_hex().to_string();
        assert_eq!(
            payload_ref.digest.as_str(),
            format!("blake3:{expected_hash}")
        );
    }

    #[tokio::test]
    async fn memory_blob_store_records_finalized_blobs() {
        let store = testing::MemoryBlobStore::default();

        let mut writer = store.writer();
        writer.write(b"chunk-a").await.expect("write");
        writer.write(b"-chunk-b").await.expect("write");
        let payload_ref = writer.finish().await.expect("finish");

        let blobs = store.blobs();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].1, b"chunk-a-chunk-b");
        assert_eq!(payload_ref.size_bytes, Some(15));
        assert_eq!(payload_ref.digest.as_str(), &blobs[0].0);
    }

    #[test]
    fn blob_store_error_other_without_source() {
        let error = BlobStoreError::other("test-store", "something broke");
        let display = error.to_string();
        assert!(display.contains("test-store"));
        assert!(display.contains("something broke"));
    }

    #[test]
    fn blob_store_error_with_source_preserves_chain() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let error = BlobStoreError::with_source("test-store", "io failed", source);
        let display = error.to_string();
        assert!(display.contains("io failed"));
        assert!(error.source().is_some());
    }

    #[tokio::test]
    async fn recording_uploader_with_no_existing_reports_all_missing() {
        let uploader = testing::RecordingUploader::default();
        let d = digest("new");
        let blobs = vec![(d.clone(), b"data".to_vec())];
        let count = drain_to_uploader(&uploader, &blobs).await.expect("drain");

        assert_eq!(count, 1);
        assert_eq!(uploader.uploaded().len(), 1);
    }

    #[tokio::test]
    async fn drain_to_uploader_with_empty_list_uploads_nothing() {
        let uploader = testing::RecordingUploader::default();
        let count = drain_to_uploader(&uploader, &[]).await.expect("drain");
        assert_eq!(count, 0);
        assert!(uploader.queried().is_empty());
        assert!(uploader.uploaded().is_empty());
    }

    #[tokio::test]
    async fn noop_uploader_uploads_nothing() {
        let blobs = vec![(digest("a"), b"a".to_vec()), (digest("b"), b"b".to_vec())];
        let count = drain_to_uploader(&NoopUploader, &blobs)
            .await
            .expect("drain");
        assert_eq!(count, 0);
    }
}
