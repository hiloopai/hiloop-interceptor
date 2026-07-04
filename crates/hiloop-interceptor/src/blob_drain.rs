//! Durable shipping of captured payload blobs to a gateway.
//!
//! [`BlobDrainer`] pairs a [`DirBlobStore`] with a [`BlobUploader`] and keeps run-scoped
//! accounting across drain passes. Incremental [`pass`](BlobDrainer::pass)es ship newly
//! finalized blobs while the run is still alive, so a hard-killed process loses at most the
//! blobs captured since the last pass. The final [`finish`](BlobDrainer::finish) re-probes
//! every digest against the backend (the backend, not the local cache, is the durability
//! authority), retries transient failures with bounded exponential backoff, and reports the
//! end state — the numbers behind the run's `capture.drain` health record.

use std::{collections::HashSet, sync::Arc, time::Duration};

use hiloop_core::event::PayloadDigest;
use tokio::fs;

use crate::blob::{
    BlobStoreError, BlobUploader, DirBlobStore, FinalizedBlob, MAX_UPLOAD_BLOB_BYTES,
};

const STORE_NAME: &str = "blob-drain";

/// Bounded retry schedule for the final drain: up to `attempts` passes in total, sleeping
/// `initial_backoff` before the first retry and doubling per retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainRetryPolicy {
    /// Total drain passes; one pass always runs, even at `0`.
    pub attempts: u32,
    /// Sleep before the first retry; doubles per retry.
    pub initial_backoff: Duration,
}

impl Default for DrainRetryPolicy {
    // 3 attempts with 500 ms/1 s backoff keeps the worst case (per-RPC timeouts included)
    // inside a Kubernetes pod's default 30 s termination grace, while a fast failure
    // (connection refused, DNS) costs ~1.5 s of exit latency.
    fn default() -> Self {
        Self {
            attempts: 3,
            initial_backoff: Duration::from_millis(500),
        }
    }
}

/// End-state accounting of the store against the backend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlobDrainReport {
    /// Finalized blobs in the store.
    pub found: usize,
    /// Confirmed present on the backend — uploaded by this drainer or already there.
    pub landed: usize,
    /// Shipped by this drainer, cumulative across passes.
    pub uploaded: usize,
    /// Over the upload cap: never sent, local only.
    pub oversize_skipped: usize,
    /// Neither confirmed landed nor oversize — lost if the local store is destroyed.
    pub missing: usize,
    /// Total size of the missing blobs.
    pub missing_bytes: u64,
}

/// One drain pass's result. The report keeps partial progress even when `error`
/// aborted the pass, so a failed drain still yields honest numbers.
#[derive(Debug)]
pub struct BlobDrainOutcome {
    pub report: BlobDrainReport,
    pub error: Option<BlobStoreError>,
}

impl BlobDrainOutcome {
    /// True when every uploadable blob is confirmed on the backend. Oversize blobs are
    /// excluded: they can never land and are reported separately.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.error.is_none() && self.report.missing == 0
    }
}

/// Drains a [`DirBlobStore`] to a [`BlobUploader`] with run-scoped landed-digest accounting.
pub struct BlobDrainer {
    store: DirBlobStore,
    uploader: Arc<dyn BlobUploader>,
    upload_cap: u64,
    landed: HashSet<PayloadDigest>,
    uploaded: usize,
}

impl BlobDrainer {
    pub fn new(store: DirBlobStore, uploader: Arc<dyn BlobUploader>) -> Self {
        Self {
            store,
            uploader,
            upload_cap: MAX_UPLOAD_BLOB_BYTES,
            landed: HashSet::new(),
            uploaded: 0,
        }
    }

    /// Incremental pass: ship finalized blobs not yet confirmed landed. When every blob is
    /// already confirmed the pass makes no RPC at all, so a periodic caller stays cheap on
    /// idle intervals. An error aborts the pass (the remaining uploads share the transport's
    /// fate) and is returned in the outcome; the next pass retries naturally.
    pub async fn pass(&mut self) -> BlobDrainOutcome {
        self.drain_once(false).await
    }

    /// Final authoritative drain: re-probe every digest (ignoring the landed cache), upload
    /// stragglers, and retry per `policy` until complete or the budget is exhausted.
    pub async fn finish(mut self, policy: &DrainRetryPolicy) -> BlobDrainOutcome {
        let mut outcome = self.drain_once(true).await;
        let mut backoff = policy.initial_backoff;
        for _ in 1..policy.attempts.max(1) {
            if outcome.is_complete() {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
            outcome = self.drain_once(true).await;
        }
        outcome
    }

    async fn drain_once(&mut self, reprobe_landed: bool) -> BlobDrainOutcome {
        let blobs = match self.store.finalized_blobs().await {
            Ok(blobs) => blobs,
            Err(error) => {
                return BlobDrainOutcome {
                    report: self.report(&[]),
                    error: Some(error),
                };
            }
        };
        let error = self.ship(&blobs, reprobe_landed).await.err();
        BlobDrainOutcome {
            report: self.report(&blobs),
            error,
        }
    }

    /// Digest-first shipping: one [`BlobUploader::find_missing`] probe over the candidates,
    /// then one [`BlobUploader::upload`] per missing digest, read one blob at a time so
    /// memory stays bounded by the largest blob. The first transport error aborts, since the
    /// remaining uploads share its fate.
    async fn ship(
        &mut self,
        blobs: &[FinalizedBlob],
        reprobe_landed: bool,
    ) -> Result<(), BlobStoreError> {
        let candidates: Vec<&FinalizedBlob> = blobs
            .iter()
            .filter(|blob| blob.size_bytes <= self.upload_cap)
            .filter(|blob| reprobe_landed || !self.landed.contains(&blob.digest))
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }

        let digests: Vec<PayloadDigest> =
            candidates.iter().map(|blob| blob.digest.clone()).collect();
        let missing: HashSet<PayloadDigest> = self
            .uploader
            .find_missing(&digests)
            .await?
            .into_iter()
            .collect();

        for blob in &candidates {
            if !missing.contains(&blob.digest) {
                self.landed.insert(blob.digest.clone());
            }
        }
        for blob in candidates {
            if !missing.contains(&blob.digest) {
                continue;
            }
            let bytes = fs::read(&blob.path).await.map_err(|error| {
                BlobStoreError::with_source(STORE_NAME, "failed to read blob", error)
            })?;
            self.uploader.upload(&blob.digest, &bytes).await?;
            self.landed.insert(blob.digest.clone());
            self.uploaded += 1;
        }
        Ok(())
    }

    fn report(&self, blobs: &[FinalizedBlob]) -> BlobDrainReport {
        let mut report = BlobDrainReport {
            found: blobs.len(),
            uploaded: self.uploaded,
            ..BlobDrainReport::default()
        };
        for blob in blobs {
            if self.landed.contains(&blob.digest) {
                report.landed += 1;
            } else if blob.size_bytes > self.upload_cap {
                report.oversize_skipped += 1;
            } else {
                report.missing += 1;
                report.missing_bytes += blob.size_bytes;
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::testing::RecordingUploader;
    use crate::blob::{BlobStore, BlobStoreError};
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Finalize `content` into `store` and return its minted digest.
    async fn store_blob(store: &DirBlobStore, content: &[u8]) -> PayloadDigest {
        let mut writer = store.writer();
        writer.write(content).await.expect("write");
        writer.finish().await.expect("finish").digest
    }

    async fn dir_store() -> (tempfile::TempDir, DirBlobStore) {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = DirBlobStore::create(temp.path())
            .await
            .expect("create store");
        (temp, store)
    }

    fn fast_policy(attempts: u32) -> DrainRetryPolicy {
        DrainRetryPolicy {
            attempts,
            initial_backoff: Duration::from_millis(1),
        }
    }

    /// Fails every call (probe and upload alike) while the fuse is lit, then delegates.
    #[derive(Default)]
    struct FlakyUploader {
        failures_left: AtomicU32,
        inner: RecordingUploader,
    }

    impl FlakyUploader {
        fn failing_first(failures: u32) -> Self {
            Self {
                failures_left: AtomicU32::new(failures),
                inner: RecordingUploader::default(),
            }
        }

        fn blow_fuse(&self) -> Result<(), BlobStoreError> {
            let lit = self
                .failures_left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                });
            match lit {
                Ok(_) => Err(BlobStoreError::other("flaky", "transient outage")),
                Err(_) => Ok(()),
            }
        }
    }

    #[async_trait]
    impl BlobUploader for FlakyUploader {
        async fn find_missing(
            &self,
            digests: &[PayloadDigest],
        ) -> Result<Vec<PayloadDigest>, BlobStoreError> {
            self.blow_fuse()?;
            self.inner.find_missing(digests).await
        }

        async fn upload(&self, digest: &PayloadDigest, bytes: &[u8]) -> Result<(), BlobStoreError> {
            self.blow_fuse()?;
            self.inner.upload(digest, bytes).await
        }
    }

    /// Probes normally; the first `failures` uploads error, later ones succeed and record.
    #[derive(Default)]
    struct UploadFailingUploader {
        upload_failures_left: Mutex<u32>,
        inner: RecordingUploader,
    }

    #[async_trait]
    impl BlobUploader for UploadFailingUploader {
        async fn find_missing(
            &self,
            digests: &[PayloadDigest],
        ) -> Result<Vec<PayloadDigest>, BlobStoreError> {
            self.inner.find_missing(digests).await
        }

        async fn upload(&self, digest: &PayloadDigest, bytes: &[u8]) -> Result<(), BlobStoreError> {
            {
                let mut left = self.upload_failures_left.lock().expect("lock");
                if *left > 0 {
                    *left -= 1;
                    return Err(BlobStoreError::other("flaky-upload", "transient outage"));
                }
            }
            self.inner.upload(digest, bytes).await
        }
    }

    #[tokio::test]
    async fn pass_ships_only_backend_missing_blobs() {
        let (_temp, store) = dir_store().await;
        let have = store_blob(&store, b"existing").await;
        let fresh = store_blob(&store, b"new").await;
        let uploader = Arc::new(RecordingUploader::with_existing([have.clone()]));
        let mut drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);

        let outcome = drainer.pass().await;

        assert!(outcome.is_complete(), "outcome: {outcome:?}");
        assert_eq!(
            outcome.report,
            BlobDrainReport {
                found: 2,
                landed: 2,
                uploaded: 1,
                oversize_skipped: 0,
                missing: 0,
                missing_bytes: 0,
            }
        );
        let mut queried = uploader.queried();
        queried.sort();
        let mut expected = vec![have, fresh.clone()];
        expected.sort();
        assert_eq!(queried, expected);
        assert_eq!(uploader.uploaded(), vec![(fresh, b"new".to_vec())]);
    }

    #[tokio::test]
    async fn pass_skips_every_rpc_once_all_blobs_landed() {
        let (_temp, store) = dir_store().await;
        store_blob(&store, b"payload").await;
        let uploader = Arc::new(RecordingUploader::default());
        let mut drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);

        assert!(drainer.pass().await.is_complete());
        let probes_after_first = uploader.queried().len();
        let outcome = drainer.pass().await;

        assert!(outcome.is_complete());
        assert_eq!(
            uploader.queried().len(),
            probes_after_first,
            "an idle pass must not probe again"
        );
        assert_eq!(outcome.report.landed, 1);
    }

    #[tokio::test]
    async fn pass_picks_up_blobs_finalized_after_the_last_pass() {
        let (_temp, store) = dir_store().await;
        store_blob(&store, b"first").await;
        let uploader = Arc::new(RecordingUploader::default());
        let mut drainer = BlobDrainer::new(
            store.clone(),
            Arc::clone(&uploader) as Arc<dyn BlobUploader>,
        );
        assert!(drainer.pass().await.is_complete());

        let late = store_blob(&store, b"late arrival").await;
        let outcome = drainer.pass().await;

        assert!(outcome.is_complete());
        assert_eq!(outcome.report.found, 2);
        assert_eq!(outcome.report.landed, 2);
        // The second probe covers only the late blob; the first is cached as landed.
        assert_eq!(uploader.queried().last(), Some(&late));
        assert_eq!(uploader.uploaded().len(), 2);
    }

    #[tokio::test]
    async fn empty_store_pass_makes_no_rpcs() {
        let (_temp, store) = dir_store().await;
        let uploader = Arc::new(RecordingUploader::default());
        let mut drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);

        let outcome = drainer.pass().await;

        assert!(outcome.is_complete());
        assert_eq!(outcome.report, BlobDrainReport::default());
        assert!(uploader.queried().is_empty());
    }

    #[tokio::test]
    async fn finish_reprobes_blobs_the_cache_already_landed() {
        let (_temp, store) = dir_store().await;
        let blob = store_blob(&store, b"payload").await;
        let uploader = Arc::new(RecordingUploader::default());
        let mut drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);
        assert!(drainer.pass().await.is_complete());

        let outcome = drainer.finish(&fast_policy(1)).await;

        assert!(outcome.is_complete());
        // Two probes for the same digest: the incremental pass and the authoritative finish.
        assert_eq!(uploader.queried(), vec![blob.clone(), blob]);
    }

    #[tokio::test]
    async fn finish_retries_until_a_transient_outage_recovers() {
        let (_temp, store) = dir_store().await;
        let blob = store_blob(&store, b"payload").await;
        let uploader = Arc::new(FlakyUploader::failing_first(2));
        let drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);

        let outcome = drainer.finish(&fast_policy(3)).await;

        assert!(outcome.is_complete(), "outcome: {outcome:?}");
        assert_eq!(outcome.report.landed, 1);
        assert_eq!(outcome.report.uploaded, 1);
        assert_eq!(uploader.inner.uploaded(), vec![(blob, b"payload".to_vec())]);
    }

    #[tokio::test]
    async fn finish_reports_missing_when_the_retry_budget_exhausts() {
        let (_temp, store) = dir_store().await;
        store_blob(&store, b"lost-a").await;
        store_blob(&store, b"lost-bb").await;
        let uploader = Arc::new(FlakyUploader::failing_first(u32::MAX));
        let drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);

        let outcome = drainer.finish(&fast_policy(2)).await;

        assert!(!outcome.is_complete());
        assert!(outcome.error.is_some(), "the last error must surface");
        assert_eq!(outcome.report.found, 2);
        assert_eq!(outcome.report.missing, 2);
        assert_eq!(outcome.report.missing_bytes, 13);
        assert_eq!(outcome.report.landed, 0);
    }

    #[tokio::test]
    async fn mid_pass_upload_failure_keeps_partial_progress() {
        let (_temp, store) = dir_store().await;
        store_blob(&store, b"one").await;
        store_blob(&store, b"two").await;
        let uploader = Arc::new(UploadFailingUploader {
            upload_failures_left: Mutex::new(1),
            ..UploadFailingUploader::default()
        });
        let mut drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);

        let outcome = drainer.pass().await;

        assert!(!outcome.is_complete());
        assert!(outcome.error.is_some());
        assert_eq!(outcome.report.found, 2);
        assert_eq!(outcome.report.landed, 0);
        assert_eq!(outcome.report.missing, 2);

        // The next pass retries only what has not landed and completes.
        let outcome = drainer.pass().await;
        assert!(outcome.is_complete(), "outcome: {outcome:?}");
        assert_eq!(outcome.report.landed, 2);
        assert_eq!(uploader.inner.uploaded().len(), 2);
    }

    #[tokio::test]
    async fn oversize_blobs_are_skipped_and_reported() {
        let (_temp, store) = dir_store().await;
        store_blob(&store, b"way over the cap").await;
        let small = store_blob(&store, b"ok").await;
        let uploader = Arc::new(RecordingUploader::default());
        let mut drainer = BlobDrainer::new(store, Arc::clone(&uploader) as Arc<dyn BlobUploader>);
        drainer.upload_cap = 8;

        let outcome = drainer.finish(&fast_policy(1)).await;

        assert!(
            outcome.is_complete(),
            "oversize blobs are reported, not missing: {outcome:?}"
        );
        assert_eq!(outcome.report.found, 2);
        assert_eq!(outcome.report.landed, 1);
        assert_eq!(outcome.report.oversize_skipped, 1);
        assert_eq!(outcome.report.missing, 0);
        assert_eq!(uploader.uploaded(), vec![(small, b"ok".to_vec())]);
    }
}
