//! Bounded blocking execution for captured-body credential scans.
//!
//! Small and large bodies use separate lanes so maximum-size captures cannot queue
//! ahead of unrelated small exchanges. Each lane is independently bounded; the
//! large lane is narrower to avoid oversubscribing detector-parallel workers. The
//! scan permit stays with the blocking closure if its async caller is canceled.

use std::{fmt, sync::Arc};

use tokio::sync::Semaphore;

const MAX_CONCURRENT_SMALL_BODY_SCANS: usize = 4;
const MAX_CONCURRENT_LARGE_BODY_SCANS: usize = 2;
const LARGE_BODY_SCAN_THRESHOLD: usize = 256 * 1024;

static BODY_SCAN_LANES: std::sync::LazyLock<BodyScanLanes> = std::sync::LazyLock::new(|| {
    BodyScanLanes::new(
        MAX_CONCURRENT_SMALL_BODY_SCANS,
        MAX_CONCURRENT_LARGE_BODY_SCANS,
        LARGE_BODY_SCAN_THRESHOLD,
    )
});

/// Failure to complete a captured-body credential scan on a blocking worker.
#[derive(Debug)]
pub struct RedactionError {
    source: tokio::task::JoinError,
}

impl fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "credential scan task failed: {}", self.source)
    }
}

impl std::error::Error for RedactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone)]
struct BodyScanPool {
    permits: Arc<Semaphore>,
}

impl BodyScanPool {
    fn new(max_concurrent_scans: usize) -> Self {
        assert!(
            max_concurrent_scans > 0,
            "body scan pool must have capacity"
        );
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent_scans)),
        }
    }

    async fn run<T, F>(&self, work: F) -> Result<T, RedactionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .expect("body scan semaphore is never closed");
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|source| RedactionError { source })
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}

#[derive(Debug, Clone)]
struct BodyScanLanes {
    small: BodyScanPool,
    large: BodyScanPool,
    large_body_threshold: usize,
}

impl BodyScanLanes {
    fn new(
        max_concurrent_small_scans: usize,
        max_concurrent_large_scans: usize,
        large_body_threshold: usize,
    ) -> Self {
        assert!(
            large_body_threshold > 0,
            "large-body threshold must be positive"
        );
        Self {
            small: BodyScanPool::new(max_concurrent_small_scans),
            large: BodyScanPool::new(max_concurrent_large_scans),
            large_body_threshold,
        }
    }

    async fn run<T, F>(&self, body_size: usize, work: F) -> Result<T, RedactionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        if body_size < self.large_body_threshold {
            self.small.run(work).await
        } else {
            self.large.run(work).await
        }
    }
}

pub(super) async fn run_body_scan<T, F>(body_size: usize, work: F) -> Result<T, RedactionError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    BODY_SCAN_LANES.run(body_size, work).await
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier, mpsc},
        thread,
    };

    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_runs_off_the_async_executor() {
        let caller = thread::current().id();
        let worker = BodyScanPool::new(1)
            .run(|| thread::current().id())
            .await
            .expect("scan");
        assert_ne!(worker, caller);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn small_scan_starts_while_large_lane_is_saturated() {
        let lanes = BodyScanLanes::new(2, 2, 8);
        let release = Arc::new(Barrier::new(3));
        let mut large = Vec::new();
        let mut started = Vec::new();
        for _ in 0..2 {
            let lanes = lanes.clone();
            let release = Arc::clone(&release);
            let (started_tx, started_rx) = oneshot::channel();
            started.push(started_rx);
            large.push(tokio::spawn(async move {
                lanes
                    .run(8, move || {
                        let _ = started_tx.send(());
                        release.wait();
                    })
                    .await
            }));
        }
        for started_rx in started {
            started_rx.await.expect("large scan started");
        }
        assert_eq!(lanes.large.available_permits(), 0);

        let (small_started_tx, small_started_rx) = oneshot::channel();
        lanes
            .run(7, move || {
                let _ = small_started_tx.send(());
            })
            .await
            .expect("small scan");
        small_started_rx.await.expect("small scan started");

        tokio::task::spawn_blocking(move || release.wait())
            .await
            .expect("release barrier");
        for task in large {
            task.await.expect("large scan task").expect("large scan");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrency_never_exceeds_the_pool_capacity() {
        let pool = BodyScanPool::new(2);
        let release = Arc::new(Barrier::new(3));
        let mut running = Vec::new();
        let mut started = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let release = Arc::clone(&release);
            let (started_tx, started_rx) = oneshot::channel();
            started.push(started_rx);
            running.push(tokio::spawn(async move {
                pool.run(move || {
                    let _ = started_tx.send(());
                    release.wait();
                })
                .await
            }));
        }
        for started_rx in started {
            started_rx.await.expect("scan started");
        }
        assert_eq!(pool.available_permits(), 0);

        let waiting_pool = pool.clone();
        let (third_started_tx, mut third_started_rx) = oneshot::channel();
        let waiting = tokio::spawn(async move {
            waiting_pool
                .run(move || {
                    let _ = third_started_tx.send(());
                })
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            third_started_rx.try_recv().is_err(),
            "third scan must wait for capacity"
        );

        tokio::task::spawn_blocking(move || release.wait())
            .await
            .expect("release barrier");
        for task in running {
            task.await.expect("scan task").expect("scan");
        }
        waiting.await.expect("waiting task").expect("waiting scan");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_returns_capacity_after_started_work_finishes() {
        let pool = BodyScanPool::new(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let running_pool = pool.clone();
        let running = tokio::spawn(async move {
            running_pool
                .run(move || {
                    let _ = started_tx.send(());
                    release_rx.recv().expect("release scan");
                })
                .await
        });
        started_rx.await.expect("scan started");
        running.abort();
        assert!(running.await.expect_err("task canceled").is_cancelled());
        assert_eq!(pool.available_permits(), 0);

        release_tx.send(()).expect("release scan");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while pool.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("capacity recovered");
        assert_eq!(pool.run(|| 7).await.expect("next scan"), 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panic_returns_capacity() {
        let pool = BodyScanPool::new(1);
        let error = pool
            .run(|| -> () { panic!("synthetic scan panic") })
            .await
            .expect_err("panic must be reported");
        assert!(error.to_string().contains("credential scan task failed"));
        assert_eq!(pool.available_permits(), 1);
        assert_eq!(pool.run(|| 9).await.expect("next scan"), 9);
    }
}
