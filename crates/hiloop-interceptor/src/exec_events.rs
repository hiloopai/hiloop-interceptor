//! Process-boundary lifecycle capture (the `exec` signal).
//!
//! The supervisor observes the wrapped child's process lifecycle directly —
//! spawn, exit, and forwarded terminating signals — and records each fact as a
//! `supervisor`-sourced raw signal. [`ExecLifecycleNormalizer`] maps those to
//! `exec` events named `process.start`, `process.exit`, and `process.signal`.
//! Process identity (`process.pid`/`process.argv`/`process.cwd`) is stamped by
//! the pipeline's provenance pass on every event, so the raw signals carry only
//! the lifecycle-specific attributes. A child that fails to spawn produces the
//! `process.spawn_failed` `exec` event instead, emitted directly by the
//! supervisor since no process (and thus no pipeline run) ever existed.

use crate::redact::RedactionPolicy;
use crate::seams::{
    NormalizationContext, NormalizationOutcome, NormalizeError, Normalizer, NormalizerDescriptor,
    NormalizerSupport, RawSignal, SourceError,
};
use async_trait::async_trait;
use bytes::Bytes;
use hiloop_core::{
    event::{AttributeKey, AttributeValue, Event, EventName, SignalType},
    identity::{Hlc, HlcClock},
};
use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const DESCRIPTOR: NormalizerDescriptor = NormalizerDescriptor::new(
    "exec-lifecycle",
    env!("CARGO_PKG_VERSION"),
    "hiloop.event.v1",
);

/// Raw-signal source for supervisor-observed process lifecycle facts.
pub const EXEC_SOURCE: &str = "supervisor";

/// Event name / raw kind: the child process spawned.
pub const PROCESS_START: &str = "process.start";
/// Event name / raw kind: the child process exited.
pub const PROCESS_EXIT: &str = "process.exit";
/// Event name / raw kind: a terminating signal was forwarded to the child.
pub const PROCESS_SIGNAL: &str = "process.signal";
/// Event name: the child command could not be spawned, so no process ever started. Emitted
/// directly by the supervisor (there is no process to drain raw signals from) — full capture
/// includes failed attempts, so the attempt itself is the recorded fact.
pub const PROCESS_SPAWN_FAILED: &str = "process.spawn_failed";

/// Attribute keys carried by process lifecycle events.
pub mod keys {
    /// Comma-separated environment variable *names* recorded for the run.
    /// Every allowlisted name is listed here whether or not it is set.
    pub const PROCESS_ENV_ALLOWLIST: &str = "process.env_allowlist";
    /// Key prefix for captured environment variable values: each allowlisted
    /// variable that is set in the child's environment lands as one
    /// `process.env.<NAME>` attribute, scrubbed by the run's capture-side
    /// redaction before it is recorded. Non-allowlisted variables are never
    /// captured.
    pub const PROCESS_ENV_PREFIX: &str = "process.env.";
    /// The child's exit byte: its exit code, or `128 + signo` on a signal kill.
    pub const PROCESS_EXIT_CODE: &str = "process.exit_code";
    /// Wall-clock duration of the child in milliseconds.
    pub const PROCESS_DURATION_MS: &str = "process.duration_ms";
    /// The signal that terminated the child (e.g. `SIGKILL`), when signal-killed.
    pub const PROCESS_TERM_SIGNAL: &str = "process.term_signal";
    /// The OS error that prevented the child from spawning
    /// (e.g. `No such file or directory (os error 2)`).
    pub const PROCESS_ERROR: &str = "process.error";
    /// The signal forwarded to the child's process group (e.g. `SIGINT`).
    pub const SIGNAL: &str = "signal";
}

/// Attribute keys whose raw string values normalize to 64-bit integers.
const I64_KEYS: [&str; 2] = [keys::PROCESS_EXIT_CODE, keys::PROCESS_DURATION_MS];

/// Resolve the captured `(name, value)` pairs for the allowlisted environment
/// variables, scrubbing each value through the run's capture-side redaction —
/// the same pattern and known-secret-literal passes applied to captured bodies
/// — before it can land in an attribute. An unset variable yields no pair (its
/// name still appears in `process.env_allowlist`); a non-UTF-8 value is
/// captured lossily rather than dropped.
pub(crate) fn captured_env_values(
    env_allowlist: &[String],
    lookup: impl Fn(&str) -> Option<OsString>,
    redaction: RedactionPolicy,
    secret_literals: &[&[u8]],
) -> Vec<(String, String)> {
    env_allowlist
        .iter()
        .filter_map(|name| {
            let value = lookup(name)?.to_string_lossy().into_owned();
            let scrubbed = redaction.redact_body_with_literals(Bytes::from(value), secret_literals);
            Some((
                name.clone(),
                String::from_utf8_lossy(&scrubbed).into_owned(),
            ))
        })
        .collect()
}

/// Emits process lifecycle raw signals into the capture pipeline.
///
/// Sends are best effort, matching the stdio capture path: telemetry must never
/// fail or stall the child (TESTING.md B12), so a closed pipeline drops the
/// lifecycle signal and the run's exit-code transparency is preserved.
pub(crate) struct ExecLifecycleEmitter {
    signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
    clock: Arc<HlcClock>,
}

impl ExecLifecycleEmitter {
    pub(crate) fn new(
        signal_tx: mpsc::Sender<Result<RawSignal, SourceError>>,
        clock: Arc<HlcClock>,
    ) -> Self {
        Self { signal_tx, clock }
    }

    /// Record the child spawn, observed at `observed_at` (the tick taken right
    /// after `spawn` returned, so `process.start` orders before the child's
    /// first stdio event). `env_values` are the already-redacted values of the
    /// allowlisted environment variables (see [`captured_env_values`]), each
    /// recorded as one `process.env.<NAME>` attribute.
    pub(crate) async fn emit_start(
        &self,
        observed_at: Hlc,
        env_allowlist: &[String],
        env_values: &[(String, String)],
    ) {
        let mut raw = RawSignal::new(EXEC_SOURCE, PROCESS_START, observed_at, Bytes::new());
        if !env_allowlist.is_empty() {
            raw = raw.with_attribute(keys::PROCESS_ENV_ALLOWLIST, env_allowlist.join(","));
        }
        for (name, value) in env_values {
            raw = raw.with_attribute(format!("{}{name}", keys::PROCESS_ENV_PREFIX), value.clone());
        }
        self.send(raw).await;
    }

    /// Record the child exit: its exit byte, the terminating signal when
    /// signal-killed, and the wall-clock duration since spawn.
    pub(crate) async fn emit_exit(
        &self,
        exit_code: u8,
        term_signal: Option<&str>,
        duration: Duration,
    ) {
        let duration_ms = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
        let mut raw = RawSignal::new(EXEC_SOURCE, PROCESS_EXIT, self.clock.tick(), Bytes::new())
            .with_attribute(keys::PROCESS_EXIT_CODE, i64::from(exit_code).to_string())
            .with_attribute(keys::PROCESS_DURATION_MS, duration_ms.to_string());
        if let Some(term_signal) = term_signal {
            raw = raw.with_attribute(keys::PROCESS_TERM_SIGNAL, term_signal);
        }
        self.send(raw).await;
    }

    /// Record one terminating signal forwarded to the child's process group.
    pub(crate) async fn emit_signal(&self, signal_name: &str) {
        let raw = RawSignal::new(EXEC_SOURCE, PROCESS_SIGNAL, self.clock.tick(), Bytes::new())
            .with_attribute(keys::SIGNAL, signal_name);
        self.send(raw).await;
    }

    async fn send(&self, raw: RawSignal) {
        // Best effort: a closed pipeline means capture already wound down; the
        // child's liveness and exit code always win over telemetry (B12).
        let _ = self.signal_tx.send(Ok(raw)).await;
    }
}

/// Normalizes supervisor process lifecycle raw signals into `exec` events.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExecLifecycleNormalizer;

#[async_trait]
impl Normalizer for ExecLifecycleNormalizer {
    fn descriptor(&self) -> NormalizerDescriptor {
        DESCRIPTOR
    }

    fn supports(&self, raw: &RawSignal) -> NormalizerSupport {
        if raw.source == EXEC_SOURCE
            && matches!(
                raw.kind.as_str(),
                PROCESS_START | PROCESS_EXIT | PROCESS_SIGNAL
            )
        {
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
        if !self.supports(&raw).is_supported() {
            return Err(NormalizeError::Unsupported {
                normalizer: DESCRIPTOR.name(),
                source_name: raw.source,
                kind: raw.kind,
            });
        }

        let name = EventName::new(raw.kind.clone()).map_err(|error| NormalizeError::Decode {
            source_name: raw.source.clone(),
            kind: raw.kind.clone(),
            message: error.to_string(),
        })?;

        let mut event = Event::new(
            context.run_context(),
            raw.observed_at,
            SignalType::Exec,
            name,
        );
        for (key, value) in &raw.attributes {
            let attribute_key =
                AttributeKey::new(key.clone()).map_err(|error| NormalizeError::Decode {
                    source_name: raw.source.clone(),
                    kind: raw.kind.clone(),
                    message: error.to_string(),
                })?;
            let attribute_value = if I64_KEYS.contains(&key.as_str()) {
                let parsed = value
                    .parse::<i64>()
                    .map_err(|error| NormalizeError::Decode {
                        source_name: raw.source.clone(),
                        kind: raw.kind.clone(),
                        message: format!("attribute `{key}` is not a 64-bit integer: {error}"),
                    })?;
                AttributeValue::from(parsed)
            } else {
                AttributeValue::from(value.clone())
            };
            event = event.with_attribute(attribute_key, attribute_value);
        }

        Ok(NormalizationOutcome::from_events(vec![event]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::identity::RunContext;

    fn context() -> NormalizationContext {
        NormalizationContext::new(RunContext::new_local_root())
    }

    fn zero_ts() -> Hlc {
        Hlc {
            wall_ns: 0,
            logical: 0,
        }
    }

    fn raw(kind: &str) -> RawSignal {
        RawSignal::new(EXEC_SOURCE, kind, zero_ts(), Bytes::new())
    }

    #[test]
    fn supports_only_supervisor_lifecycle_kinds() {
        let normalizer = ExecLifecycleNormalizer;
        for kind in [PROCESS_START, PROCESS_EXIT, PROCESS_SIGNAL] {
            assert!(normalizer.supports(&raw(kind)).is_supported(), "{kind}");
        }
        assert!(!normalizer.supports(&raw("stdout")).is_supported());
        let stdio = RawSignal::new("stdio", PROCESS_START, zero_ts(), Bytes::new());
        assert!(!normalizer.supports(&stdio).is_supported());
    }

    #[tokio::test]
    async fn normalizes_process_start_with_env_allowlist_and_values() {
        let context = context();
        let signal = raw(PROCESS_START)
            .with_attribute(keys::PROCESS_ENV_ALLOWLIST, "PATH,HOME,PYTHONPATH")
            .with_attribute("process.env.PYTHONPATH", "/opt/lib");

        let outcome = ExecLifecycleNormalizer
            .normalize(&context, signal)
            .await
            .expect("normalize process.start");

        let [event] = outcome.events() else {
            panic!("expected exactly one event");
        };
        assert_eq!(event.signal, SignalType::Exec);
        assert_eq!(event.name.as_str(), PROCESS_START);
        assert_eq!(event.run_id, context.run_context().run_id);
        let value = serde_json::to_value(event).expect("serialize event");
        assert_eq!(value["signal"], "exec");
        assert_eq!(
            value["attributes"][keys::PROCESS_ENV_ALLOWLIST],
            "PATH,HOME,PYTHONPATH"
        );
        assert_eq!(value["attributes"]["process.env.PYTHONPATH"], "/opt/lib");
    }

    #[tokio::test]
    async fn exotic_env_names_never_sink_the_start_event() {
        // `AttributeKey` rejects only blank keys, and the `process.env.` prefix
        // keeps every env-derived key non-blank, so no allowlisted name — however
        // exotic — can fail normalization and drop the whole `process.start`.
        let signal = raw(PROCESS_START)
            .with_attribute("process.env.LC_ALL@host", "C")
            .with_attribute("process.env.変数", "value")
            .with_attribute("process.env. ", "space-named");

        let outcome = ExecLifecycleNormalizer
            .normalize(&context(), signal)
            .await
            .expect("normalize process.start with exotic env names");

        let value = serde_json::to_value(&outcome.events()[0]).expect("serialize event");
        assert_eq!(value["attributes"]["process.env.LC_ALL@host"], "C");
        assert_eq!(value["attributes"]["process.env.変数"], "value");
        assert_eq!(value["attributes"]["process.env. "], "space-named");
    }

    #[tokio::test]
    async fn normalizes_process_exit_integers_and_term_signal() {
        let context = context();
        let signal = raw(PROCESS_EXIT)
            .with_attribute(keys::PROCESS_EXIT_CODE, "143")
            .with_attribute(keys::PROCESS_DURATION_MS, "312000")
            .with_attribute(keys::PROCESS_TERM_SIGNAL, "SIGTERM");

        let outcome = ExecLifecycleNormalizer
            .normalize(&context, signal)
            .await
            .expect("normalize process.exit");

        let value = serde_json::to_value(&outcome.events()[0]).expect("serialize event");
        assert_eq!(value["name"], PROCESS_EXIT);
        assert_eq!(value["attributes"][keys::PROCESS_EXIT_CODE], 143);
        assert_eq!(value["attributes"][keys::PROCESS_DURATION_MS], 312_000);
        assert_eq!(value["attributes"][keys::PROCESS_TERM_SIGNAL], "SIGTERM");
    }

    #[tokio::test]
    async fn normalizes_process_signal() {
        let context = context();
        let signal = raw(PROCESS_SIGNAL).with_attribute(keys::SIGNAL, "SIGINT");

        let outcome = ExecLifecycleNormalizer
            .normalize(&context, signal)
            .await
            .expect("normalize process.signal");

        let value = serde_json::to_value(&outcome.events()[0]).expect("serialize event");
        assert_eq!(value["name"], PROCESS_SIGNAL);
        assert_eq!(value["attributes"][keys::SIGNAL], "SIGINT");
    }

    #[tokio::test]
    async fn rejects_non_integer_exit_code() {
        let signal = raw(PROCESS_EXIT).with_attribute(keys::PROCESS_EXIT_CODE, "not-a-number");

        let error = ExecLifecycleNormalizer
            .normalize(&context(), signal)
            .await
            .expect_err("non-integer exit code must fail decode");

        assert!(matches!(error, NormalizeError::Decode { .. }), "{error}");
    }

    #[tokio::test]
    async fn rejects_unsupported_kind() {
        let signal = RawSignal::new("stdio", "stdout", zero_ts(), Bytes::new());

        let error = ExecLifecycleNormalizer
            .normalize(&context(), signal)
            .await
            .expect_err("unsupported source must be rejected");

        assert!(
            matches!(error, NormalizeError::Unsupported { .. }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn preserves_the_observation_timestamp() {
        let observed_at = Hlc {
            wall_ns: 1_751_450_401_000_000_000,
            logical: 7,
        };
        let signal = RawSignal::new(EXEC_SOURCE, PROCESS_START, observed_at, Bytes::new());

        let outcome = ExecLifecycleNormalizer
            .normalize(&context(), signal)
            .await
            .expect("normalize");

        assert_eq!(outcome.events()[0].ts, observed_at);
    }

    #[tokio::test]
    async fn emitter_sends_lifecycle_signals_best_effort() {
        let (tx, mut rx) = mpsc::channel(4);
        let emitter = ExecLifecycleEmitter::new(tx, Arc::new(HlcClock::new()));

        emitter
            .emit_start(
                zero_ts(),
                &["PATH".to_owned(), "HOME".to_owned()],
                &[("HOME".to_owned(), "/home/agent".to_owned())],
            )
            .await;
        emitter
            .emit_exit(143, Some("SIGTERM"), Duration::from_millis(250))
            .await;
        emitter.emit_signal("SIGINT").await;
        drop(emitter);

        let start = rx.recv().await.expect("start signal").expect("ok");
        assert_eq!(start.source, EXEC_SOURCE);
        assert_eq!(start.kind, PROCESS_START);
        assert_eq!(
            start.attributes.get(keys::PROCESS_ENV_ALLOWLIST),
            Some(&"PATH,HOME".to_owned())
        );
        assert_eq!(
            start.attributes.get("process.env.HOME"),
            Some(&"/home/agent".to_owned())
        );

        let exit = rx.recv().await.expect("exit signal").expect("ok");
        assert_eq!(exit.kind, PROCESS_EXIT);
        assert_eq!(
            exit.attributes.get(keys::PROCESS_EXIT_CODE),
            Some(&"143".to_owned())
        );
        assert_eq!(
            exit.attributes.get(keys::PROCESS_DURATION_MS),
            Some(&"250".to_owned())
        );
        assert_eq!(
            exit.attributes.get(keys::PROCESS_TERM_SIGNAL),
            Some(&"SIGTERM".to_owned())
        );

        let signal = rx.recv().await.expect("signal signal").expect("ok");
        assert_eq!(signal.kind, PROCESS_SIGNAL);
        assert_eq!(
            signal.attributes.get(keys::SIGNAL),
            Some(&"SIGINT".to_owned())
        );

        // A dropped receiver must not error the emitter (best effort).
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let emitter = ExecLifecycleEmitter::new(tx, Arc::new(HlcClock::new()));
        emitter.emit_signal("SIGTERM").await;
    }

    fn fake_env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let vars: Vec<(String, OsString)> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(*value)))
            .collect();
        move |name| {
            vars.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn captures_only_set_allowlisted_values() {
        let allowlist = ["LEARNING_RATE".to_owned(), "UNSET_VAR".to_owned()];
        let lookup = fake_env(&[("LEARNING_RATE", "0.001"), ("OFF_LIST", "ignored")]);

        let values = captured_env_values(&allowlist, lookup, RedactionPolicy::enabled(), &[]);

        assert_eq!(
            values,
            vec![("LEARNING_RATE".to_owned(), "0.001".to_owned())],
            "an unset allowlisted variable yields no pair and off-list variables are never read"
        );
    }

    #[test]
    fn captured_values_run_through_pattern_redaction() {
        let allowlist = ["ACCIDENTAL_KEY".to_owned()];
        let lookup = fake_env(&[("ACCIDENTAL_KEY", "sk-live-abc123")]);

        let values = captured_env_values(&allowlist, lookup, RedactionPolicy::enabled(), &[]);

        assert_eq!(
            values,
            vec![("ACCIDENTAL_KEY".to_owned(), "[REDACTED]".to_owned())]
        );
    }

    #[test]
    fn captured_values_scrub_known_secret_literals_even_with_redaction_disabled() {
        let allowlist = ["BROKER_TOKEN".to_owned(), "PLAIN".to_owned()];
        let lookup = fake_env(&[("BROKER_TOKEN", "opaque-token-xyz"), ("PLAIN", "sk-live-1")]);

        let values = captured_env_values(
            &allowlist,
            lookup,
            RedactionPolicy::disabled(),
            &[b"opaque-token-xyz"],
        );

        assert_eq!(
            values,
            vec![
                ("BROKER_TOKEN".to_owned(), "[REDACTED]".to_owned()),
                ("PLAIN".to_owned(), "sk-live-1".to_owned()),
            ],
            "literals are scrubbed regardless of the toggle; pattern redaction honors it, \
             matching captured-body behavior"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_values_are_captured_lossily() {
        use std::os::unix::ffi::OsStringExt;

        let allowlist = ["BINARY".to_owned()];
        let lookup = |name: &str| {
            (name == "BINARY").then(|| OsString::from_vec(vec![b'o', b'k', 0xFF, b'!']))
        };

        let values = captured_env_values(&allowlist, lookup, RedactionPolicy::enabled(), &[]);

        assert_eq!(
            values,
            vec![("BINARY".to_owned(), "ok\u{FFFD}!".to_owned())]
        );
    }
}
