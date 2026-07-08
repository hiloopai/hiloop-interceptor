//! Spooling, classified-retry decorator for the [`Exporter`] seam.
//!
//! [`SpoolingExporter`] wraps a single-shot exporter (in production the gRPC ingest
//! exporter) so a telemetry-gateway outage degrades capture measurably instead of
//! killing it. Delivery failures dispatch on the [`ExportError`] retry taxonomy:
//!
//! - **transient** ([`ExportError::Backpressure`], [`ExportError::Unavailable`]) —
//!   the batch parks in the spool and redelivery waits out a bounded exponential
//!   backoff; while the backoff is armed, new batches park immediately, so capture
//!   never stalls on a sink known to be down;
//! - **permanent** ([`ExportError::Rejected`]) — the sink judged that batch and
//!   refused it, so it is dropped on the spot with a loud, specific warning
//!   (redelivering a judged batch can never succeed) and counted;
//! - **ambiguous** ([`ExportError::Other`]) — one immediate inline retry (a blip may
//!   pass), then the batch parks like a transient failure.
//!
//! The spool is bounded by events *and* bytes — the seam mandate: bounded buffering,
//! never unbounded internal queues. Over either cap the oldest events are dropped and
//! counted, so a sustained outage degrades capture measurably rather than exhausting
//! memory. Redelivery is strictly in arrival order: a new batch is never sent while
//! older events wait, so recovery preserves the export order.
//!
//! The spool lives in memory: the wrapper keeps no persistent state directory (its
//! only on-disk stores are the payload-blob CAS and per-run scratch staging), and the
//! supervisor's exit path gives spooled events a final bounded-budget chance via
//! [`drain`](SpoolingExporter::drain) before reporting what remains undelivered.
//!
//! Delivery is at-least-once: a redelivery cancelled in flight (a caller-imposed
//! deadline) may resend its chunk on the next pass. Events carry globally unique
//! `event_id`s, so the sink can deduplicate.

use crate::blob_drain::DrainRetryPolicy;
use crate::pipeline::DEFAULT_EXPORT_BATCH_SIZE;
use crate::seams::{ExportError, Exporter};
use async_trait::async_trait;
use hiloop_core::event::Event;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Bounds and cadence of the spool-and-retry behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolPolicy {
    /// Spooled-event cap; past it the oldest events are dropped and counted.
    pub max_events: usize,
    /// Spooled-byte cap (each event's serialized size); same drop-oldest behavior.
    pub max_bytes: u64,
    /// Backoff armed after a failed delivery attempt; doubles per consecutive failure.
    pub initial_backoff: Duration,
    /// Ceiling for the doubled backoff.
    pub max_backoff: Duration,
    /// Hard deadline on one delivery attempt, so an unresponsive (black-holed) sink
    /// cannot stall the export stage. A timed-out attempt classifies as transient.
    pub attempt_timeout: Duration,
    /// Events per redelivery call when draining the spool.
    pub drain_batch_size: usize,
}

impl Default for SpoolPolicy {
    // 8192 events / 32 MiB holds minutes of typical capture through an outage while
    // staying a bounded fraction of the wrapper's footprint (stdio events are capped at
    // 64 KiB lines; proxy bodies travel out-of-line as payload refs, so spooled events
    // stay small). Backoff mirrors the blob drain's 500 ms start and caps at 30 s so a
    // long outage still probes the gateway at a useful cadence; 10 s per attempt matches
    // the blob probe deadline.
    fn default() -> Self {
        Self {
            max_events: 8192,
            max_bytes: 32 * 1024 * 1024,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(10),
            drain_batch_size: DEFAULT_EXPORT_BATCH_SIZE,
        }
    }
}

/// Backlog and loss accounting of one spool at one instant.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SpoolReport {
    /// Events parked in the spool, awaiting redelivery.
    pub pending_events: usize,
    /// Serialized size of the pending events.
    pub pending_bytes: u64,
    /// Oldest events dropped because the spool hit a cap.
    pub dropped_events: u64,
    /// Events dropped because the sink permanently rejected their batch.
    pub rejected_events: u64,
}

impl SpoolReport {
    /// True when nothing was lost and nothing is still waiting.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.pending_events == 0 && self.dropped_events == 0 && self.rejected_events == 0
    }

    /// True when no event was dropped (pending events may still await redelivery).
    #[must_use]
    pub const fn is_lossless_so_far(&self) -> bool {
        self.dropped_events == 0 && self.rejected_events == 0
    }
}

/// How one delivery attempt failed, per the [`ExportError`] retry taxonomy.
enum AttemptFailure {
    Transient(String),
    Permanent(String),
    Ambiguous(String),
}

impl AttemptFailure {
    fn message(&self) -> &str {
        match self {
            Self::Transient(message) | Self::Permanent(message) | Self::Ambiguous(message) => {
                message
            }
        }
    }
}

fn classify(error: &ExportError) -> AttemptFailure {
    let message = error.to_string();
    match error {
        ExportError::Backpressure { .. } | ExportError::Unavailable { .. } => {
            AttemptFailure::Transient(message)
        }
        ExportError::Rejected { .. } => AttemptFailure::Permanent(message),
        ExportError::Other { .. } => AttemptFailure::Ambiguous(message),
    }
}

struct SpooledEvent {
    event: Event,
    bytes: u64,
}

#[derive(Default)]
struct SpoolState {
    queue: VecDeque<SpooledEvent>,
    queued_bytes: u64,
    dropped_events: u64,
    rejected_events: u64,
    /// Consecutive failed delivery attempts; drives the exponential backoff.
    consecutive_failures: u32,
    /// No delivery attempt before this instant; `None` means deliver immediately.
    next_attempt_at: Option<Instant>,
    /// Last transient/ambiguous failure, kept for the run-end warning.
    last_failure: Option<String>,
    /// One loud stderr line per run when dropping starts, not one per dropped event.
    drop_warned: bool,
}

impl SpoolState {
    fn in_backoff(&self) -> bool {
        self.next_attempt_at.is_some_and(|at| Instant::now() < at)
    }

    fn report(&self) -> SpoolReport {
        SpoolReport {
            pending_events: self.queue.len(),
            pending_bytes: self.queued_bytes,
            dropped_events: self.dropped_events,
            rejected_events: self.rejected_events,
        }
    }

    fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_attempt_at = None;
    }

    fn on_failure(&mut self, policy: &SpoolPolicy, message: String) {
        let exponent = self.consecutive_failures.min(16);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let backoff = policy
            .initial_backoff
            .saturating_mul(2_u32.saturating_pow(exponent))
            .min(policy.max_backoff);
        self.next_attempt_at = Some(Instant::now() + backoff);
        self.last_failure = Some(message);
    }
}

/// Decorator that makes a single-shot [`Exporter`] survive sink outages: bounded
/// in-memory spool, classified retry, in-order redelivery. See the module docs for
/// the behavior contract.
pub struct SpoolingExporter<E> {
    inner: E,
    policy: SpoolPolicy,
    state: Mutex<SpoolState>,
}

impl<E: Exporter> SpoolingExporter<E> {
    pub fn new(inner: E, policy: SpoolPolicy) -> Self {
        Self {
            inner,
            policy,
            state: Mutex::new(SpoolState::default()),
        }
    }

    /// Snapshot of the spool's backlog and loss counters.
    pub async fn report(&self) -> SpoolReport {
        self.state.lock().await.report()
    }

    /// The last transient/ambiguous delivery failure, for attributing what kept the
    /// pending events undelivered.
    pub async fn last_failure(&self) -> Option<String> {
        self.state.lock().await.last_failure.clone()
    }

    /// Run-end drain: give the spooled backlog its final chance within `retry`'s
    /// bounded budget (the same schedule shape as the run-end blob drain), ignoring
    /// the in-run backoff gate — the budget is the gate now. Returns the end state;
    /// `pending_events` is what remains undelivered when the budget is exhausted.
    pub async fn drain(&self, retry: &DrainRetryPolicy) -> SpoolReport {
        let mut backoff = retry.initial_backoff;
        for attempt in 0..retry.attempts.max(1) {
            if attempt > 0 {
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
            let mut state = self.state.lock().await;
            if state.queue.is_empty() || self.deliver_queue(&mut state).await.is_ok() {
                break;
            }
        }
        self.state.lock().await.report()
    }

    /// One timeout-bounded call into the inner exporter, classified on failure.
    async fn attempt(&self, events: &[Event]) -> Result<(), AttemptFailure> {
        match tokio::time::timeout(self.policy.attempt_timeout, self.inner.export(events)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(classify(&error)),
            Err(_elapsed) => Err(AttemptFailure::Transient(format!(
                "export attempt timed out after {:?}",
                self.policy.attempt_timeout
            ))),
        }
    }

    /// One delivery try for `events`: an ambiguous failure gets a single immediate
    /// inline retry (a blip may pass) before the failure is reported for spooling.
    async fn deliver(&self, events: &[Event]) -> Result<(), AttemptFailure> {
        match self.attempt(events).await {
            Err(AttemptFailure::Ambiguous(_)) => self.attempt(events).await,
            outcome => outcome,
        }
    }

    /// Redeliver the spooled backlog in arrival order. A permanent rejection drops
    /// only the refused chunk (the verdict is about that batch) and keeps going; a
    /// transient/ambiguous failure stops the pass and arms the backoff.
    async fn deliver_queue(&self, state: &mut SpoolState) -> Result<(), ()> {
        while !state.queue.is_empty() {
            let chunk_len = state.queue.len().min(self.policy.drain_batch_size);
            let chunk: Vec<Event> = state
                .queue
                .iter()
                .take(chunk_len)
                .map(|spooled| spooled.event.clone())
                .collect();
            match self.deliver(&chunk).await {
                Ok(()) => {
                    Self::pop_front(state, chunk_len);
                    state.on_success();
                }
                Err(AttemptFailure::Permanent(message)) => {
                    Self::pop_front(state, chunk_len);
                    state.rejected_events += chunk_len as u64;
                    warn_rejected(chunk_len, &message);
                }
                Err(failure) => {
                    state.on_failure(&self.policy, failure.message().to_owned());
                    return Err(());
                }
            }
        }
        Ok(())
    }

    fn pop_front(state: &mut SpoolState, count: usize) {
        for _ in 0..count {
            if let Some(spooled) = state.queue.pop_front() {
                state.queued_bytes = state.queued_bytes.saturating_sub(spooled.bytes);
            }
        }
    }

    /// Park `events` at the spool's tail, then enforce both caps by dropping the
    /// oldest events (counted; one loud warning per run when dropping starts).
    fn enqueue(&self, state: &mut SpoolState, events: &[Event]) {
        for event in events {
            let bytes = approx_event_bytes(event);
            state.queue.push_back(SpooledEvent {
                event: event.clone(),
                bytes,
            });
            state.queued_bytes += bytes;
        }
        while state.queue.len() > self.policy.max_events
            || state.queued_bytes > self.policy.max_bytes
        {
            let Some(dropped) = state.queue.pop_front() else {
                break;
            };
            state.queued_bytes = state.queued_bytes.saturating_sub(dropped.bytes);
            state.dropped_events += 1;
            if !state.drop_warned {
                state.drop_warned = true;
                eprintln!(
                    "hiloop-interceptor: warning: the export spool is full ({} events / {} bytes); dropping the oldest spooled events — the count is reported at run end",
                    self.policy.max_events, self.policy.max_bytes
                );
            }
        }
    }
}

#[async_trait]
impl<E: Exporter> Exporter for SpoolingExporter<E> {
    /// Never blocks capture on a sink known to be down: while the backoff is armed
    /// the batch parks immediately, otherwise the spooled backlog is redelivered
    /// first (arrival order) and only then this batch. All failure handling happens
    /// here — transient/ambiguous failures spool, permanent rejections drop loudly —
    /// so this always returns `Ok` and an outage can never abort the pipeline.
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        if events.is_empty() {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        if state.in_backoff() || self.deliver_queue(&mut state).await.is_err() {
            self.enqueue(&mut state, events);
            return Ok(());
        }
        match self.deliver(events).await {
            Ok(()) => state.on_success(),
            Err(AttemptFailure::Permanent(message)) => {
                state.rejected_events += events.len() as u64;
                warn_rejected(events.len(), &message);
            }
            Err(failure) => {
                state.on_failure(&self.policy, failure.message().to_owned());
                self.enqueue(&mut state, events);
            }
        }
        Ok(())
    }

    /// Best-effort: redeliver the backlog when the backoff allows, then flush the
    /// inner exporter. Events still spooled after an outage-time flush stay parked
    /// for the run-end [`drain`](SpoolingExporter::drain).
    async fn flush(&self) -> Result<(), ExportError> {
        let mut state = self.state.lock().await;
        if !state.queue.is_empty() && !state.in_backoff() {
            let _ = self.deliver_queue(&mut state).await;
        }
        drop(state);
        self.inner.flush().await
    }
}

/// The event's serialized size — what it would occupy on the JSONL wire. Falls back
/// to a fixed estimate for the (unreachable) case of an unserializable event.
fn approx_event_bytes(event: &Event) -> u64 {
    serde_json::to_vec(event).map_or(1024, |encoded| encoded.len() as u64)
}

fn warn_rejected(count: usize, message: &str) {
    eprintln!(
        "hiloop-interceptor: warning: dropping a batch of {count} event(s) the export sink permanently rejected (redelivery cannot succeed): {message}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::event::{AttributeKey, EventName, SignalType};
    use hiloop_core::identity::{Hlc, RunContext};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Scripted response for one `export` call on the fake sink.
    #[derive(Clone, Copy, Debug)]
    enum Respond {
        Deliver,
        Backpressure,
        Unavailable,
        Rejected,
        Other,
        /// Never resolves, to exercise the attempt timeout.
        Hang,
    }

    /// Fake ingest sink at the `Exporter` seam: pops one scripted response per
    /// `export` call (an exhausted script delivers) and records delivered batches.
    #[derive(Default)]
    struct FakeSink {
        script: StdMutex<VecDeque<Respond>>,
        delivered: StdMutex<Vec<Vec<Event>>>,
        calls: AtomicUsize,
    }

    impl FakeSink {
        fn scripted(script: impl IntoIterator<Item = Respond>) -> Self {
            Self {
                script: StdMutex::new(script.into_iter().collect()),
                ..Self::default()
            }
        }

        fn delivered_flat(&self) -> Vec<Event> {
            self.delivered
                .lock()
                .expect("lock")
                .iter()
                .flatten()
                .cloned()
                .collect()
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Exporter for FakeSink {
        async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = self
                .script
                .lock()
                .expect("lock")
                .pop_front()
                .unwrap_or(Respond::Deliver);
            match response {
                Respond::Deliver => {
                    self.delivered.lock().expect("lock").push(events.to_vec());
                    Ok(())
                }
                Respond::Backpressure => Err(ExportError::backpressure("fake", "shedding load")),
                Respond::Unavailable => Err(ExportError::unavailable("fake", "gateway down")),
                Respond::Rejected => Err(ExportError::rejected("fake", "bad batch")),
                Respond::Other => Err(ExportError::other("fake", "wat")),
                Respond::Hang => {
                    std::future::pending::<()>().await;
                    unreachable!("pending future never resolves")
                }
            }
        }
    }

    fn event(message: &str) -> Event {
        Event::new(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Log,
            EventName::new("process.stdout").expect("event name"),
        )
        .with_attribute(AttributeKey::new("message").expect("key"), message)
    }

    fn messages(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|event| {
                serde_json::to_value(event).expect("event json")["attributes"]["message"]
                    .as_str()
                    .expect("message attribute")
                    .to_owned()
            })
            .collect()
    }

    fn fast_policy() -> SpoolPolicy {
        SpoolPolicy {
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(10),
            ..SpoolPolicy::default()
        }
    }

    fn fast_drain(attempts: u32) -> DrainRetryPolicy {
        DrainRetryPolicy {
            attempts,
            initial_backoff: Duration::from_millis(1),
        }
    }

    #[tokio::test]
    async fn healthy_path_passes_batches_straight_through() {
        let spool = SpoolingExporter::new(FakeSink::default(), fast_policy());

        spool.export(&[event("one")]).await.expect("export");
        spool
            .export(&[event("two"), event("three")])
            .await
            .expect("export");
        spool.flush().await.expect("flush");

        assert_eq!(
            messages(&spool.inner.delivered_flat()),
            ["one", "two", "three"]
        );
        assert!(spool.report().await.is_clean());
    }

    #[tokio::test]
    async fn empty_batch_never_reaches_the_sink() {
        let spool = SpoolingExporter::new(FakeSink::default(), fast_policy());

        spool.export(&[]).await.expect("export");

        assert_eq!(spool.inner.calls(), 0);
    }

    /// Both transient classes — an outage (`UNAVAILABLE`/transport) and a typed
    /// backlog shed (`RESOURCE_EXHAUSTED`) — spool and redeliver identically.
    async fn assert_transient_spools_and_recovery_redelivers_in_order(transient: Respond) {
        let sink = FakeSink::scripted([transient]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool.export(&[event("one")]).await.expect("export");
        // The backoff is armed: the next batch must park without touching the sink.
        spool
            .export(&[event("two"), event("three")])
            .await
            .expect("export");
        assert_eq!(spool.inner.calls(), 1, "backoff parks without attempting");
        assert_eq!(spool.report().await.pending_events, 3);

        // Past the backoff, the next export drains the backlog first, in order.
        tokio::time::advance(Duration::from_millis(600)).await;
        spool.export(&[event("four")]).await.expect("export");

        assert_eq!(
            messages(&spool.inner.delivered_flat()),
            ["one", "two", "three", "four"]
        );
        assert!(spool.report().await.is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn outage_spools_and_recovery_redelivers_in_order_with_zero_loss() {
        assert_transient_spools_and_recovery_redelivers_in_order(Respond::Unavailable).await;
    }

    #[tokio::test(start_paused = true)]
    async fn backpressure_spools_and_recovery_redelivers_in_order_with_zero_loss() {
        assert_transient_spools_and_recovery_redelivers_in_order(Respond::Backpressure).await;
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_doubles_per_consecutive_failure() {
        let sink = FakeSink::scripted([Respond::Unavailable, Respond::Unavailable]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool.export(&[event("one")]).await.expect("export");
        assert_eq!(spool.inner.calls(), 1);

        // First backoff window is 500ms; a retry at 600ms fails again → 1s window.
        tokio::time::advance(Duration::from_millis(600)).await;
        spool.export(&[event("two")]).await.expect("export");
        assert_eq!(spool.inner.calls(), 2);

        // 600ms later the doubled window is still open: no attempt.
        tokio::time::advance(Duration::from_millis(600)).await;
        spool.export(&[event("three")]).await.expect("export");
        assert_eq!(spool.inner.calls(), 2, "doubled backoff still armed");

        // Another 500ms crosses the 1s window; the sink has recovered.
        tokio::time::advance(Duration::from_millis(500)).await;
        spool.export(&[event("four")]).await.expect("export");
        assert_eq!(
            messages(&spool.inner.delivered_flat()),
            ["one", "two", "three", "four"]
        );
        assert!(spool.report().await.is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn over_cap_drops_oldest_and_counts() {
        let sink = FakeSink::scripted([Respond::Unavailable]);
        let policy = SpoolPolicy {
            max_events: 4,
            ..fast_policy()
        };
        let spool = SpoolingExporter::new(sink, policy);

        for label in ["one", "two", "three", "four", "five", "six"] {
            spool.export(&[event(label)]).await.expect("export");
        }
        let report = spool.report().await;
        assert_eq!(report.pending_events, 4);
        assert_eq!(report.dropped_events, 2);

        tokio::time::advance(Duration::from_millis(600)).await;
        let report = spool.drain(&fast_drain(1)).await;

        assert_eq!(
            messages(&spool.inner.delivered_flat()),
            ["three", "four", "five", "six"],
            "the oldest events are the dropped ones"
        );
        assert_eq!(report.pending_events, 0);
        assert_eq!(report.dropped_events, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn byte_cap_bounds_the_spool_too() {
        let sink = FakeSink::scripted([Respond::Unavailable]);
        let one_event_bytes = approx_event_bytes(&event("x"));
        let policy = SpoolPolicy {
            max_bytes: one_event_bytes * 2,
            ..fast_policy()
        };
        let spool = SpoolingExporter::new(sink, policy);

        for label in ["a", "b", "c"] {
            spool.export(&[event(label)]).await.expect("export");
        }

        let report = spool.report().await;
        assert_eq!(report.pending_events, 2);
        assert_eq!(report.dropped_events, 1);
        assert!(report.pending_bytes <= one_event_bytes * 2);
    }

    #[tokio::test]
    async fn permanent_rejection_drops_only_that_batch() {
        let sink = FakeSink::scripted([Respond::Rejected]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool
            .export(&[event("bad-one"), event("bad-two")])
            .await
            .expect("export");
        spool.export(&[event("good")]).await.expect("export");

        assert_eq!(messages(&spool.inner.delivered_flat()), ["good"]);
        let report = spool.report().await;
        assert_eq!(report.rejected_events, 2);
        assert_eq!(
            report.pending_events, 0,
            "a rejected batch is never spooled"
        );
    }

    #[tokio::test]
    async fn ambiguous_failure_gets_one_inline_retry() {
        let sink = FakeSink::scripted([Respond::Other, Respond::Deliver]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool.export(&[event("one")]).await.expect("export");

        assert_eq!(spool.inner.calls(), 2, "one inline retry");
        assert_eq!(messages(&spool.inner.delivered_flat()), ["one"]);
        assert!(spool.report().await.is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn ambiguous_failure_twice_spools_like_a_transient() {
        let sink = FakeSink::scripted([Respond::Other, Respond::Other]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool.export(&[event("one")]).await.expect("export");

        assert_eq!(spool.inner.calls(), 2);
        let report = spool.report().await;
        assert_eq!(report.pending_events, 1);
        assert!(spool.last_failure().await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn hanging_sink_times_out_and_spools() {
        let sink = FakeSink::scripted([Respond::Hang]);
        let policy = SpoolPolicy {
            attempt_timeout: Duration::from_millis(50),
            ..fast_policy()
        };
        let spool = SpoolingExporter::new(sink, policy);

        spool.export(&[event("one")]).await.expect("export");

        let report = spool.report().await;
        assert_eq!(report.pending_events, 1);
        assert!(
            spool
                .last_failure()
                .await
                .expect("failure recorded")
                .contains("timed out"),
            "the timeout is attributed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_end_drain_delivers_after_recovery() {
        let sink = FakeSink::scripted([Respond::Unavailable, Respond::Unavailable]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool.export(&[event("one")]).await.expect("export");
        spool.export(&[event("two")]).await.expect("export");

        // Attempt 1 fails (scripted), attempt 2 succeeds after the budgeted sleep.
        let report = spool.drain(&fast_drain(3)).await;

        assert_eq!(messages(&spool.inner.delivered_flat()), ["one", "two"]);
        assert!(report.is_clean(), "report: {report:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn run_end_drain_reports_undelivered_when_the_budget_exhausts() {
        let sink = FakeSink::scripted([
            Respond::Unavailable,
            Respond::Unavailable,
            Respond::Unavailable,
            Respond::Unavailable,
        ]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool.export(&[event("one")]).await.expect("export");
        spool.export(&[event("two")]).await.expect("export");

        let report = spool.drain(&fast_drain(2)).await;

        assert_eq!(report.pending_events, 2, "undelivered events are reported");
        assert!(!report.is_clean());
        assert!(report.is_lossless_so_far(), "spooled, not dropped");
    }

    #[tokio::test(start_paused = true)]
    async fn flush_redelivers_the_backlog_when_the_backoff_allows() {
        let sink = FakeSink::scripted([Respond::Unavailable]);
        let spool = SpoolingExporter::new(sink, fast_policy());

        spool.export(&[event("one")]).await.expect("export");
        assert_eq!(spool.report().await.pending_events, 1);

        // In backoff: flush must not hammer the sink.
        spool.flush().await.expect("flush");
        assert_eq!(spool.inner.calls(), 1);

        tokio::time::advance(Duration::from_millis(600)).await;
        spool.flush().await.expect("flush");

        assert_eq!(messages(&spool.inner.delivered_flat()), ["one"]);
        assert!(spool.report().await.is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn rejection_mid_drain_drops_the_refused_chunk_and_keeps_going() {
        let sink = FakeSink::scripted([Respond::Unavailable, Respond::Rejected]);
        let policy = SpoolPolicy {
            drain_batch_size: 1,
            ..fast_policy()
        };
        let spool = SpoolingExporter::new(sink, policy);

        spool.export(&[event("refused")]).await.expect("export");
        spool.export(&[event("fine")]).await.expect("export");
        tokio::time::advance(Duration::from_millis(600)).await;

        let report = spool.drain(&fast_drain(1)).await;

        assert_eq!(messages(&spool.inner.delivered_flat()), ["fine"]);
        assert_eq!(report.rejected_events, 1);
        assert_eq!(report.pending_events, 0);
    }
}
