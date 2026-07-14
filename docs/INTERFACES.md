# Interface Boundaries

This document tracks the current implementation seams in `hiloop-interceptor`, how they are
expected to grow, and where they can fail. It should evolve with the implementation. Durable Rust
style rules live in [`RUST_STYLE.md`](RUST_STYLE.md).

## Layering

`hiloop-core` owns shared contracts, not orchestration. Keep it dependency-light and stable:

- run-lineage identity types;
- telemetry event data types;
- parsing and validation helpers for those data types;
- future protobuf/schema contracts that public and private components both consume.

Do not put implementation seams in `hiloop-core` unless at least one of these is true:

- both OSS and private repos compile against the trait;
- the type defines persisted or wire compatibility;
- it is a public extension API;
- its conformance suite must be shared across public and private implementations.

Wrapper-only traits live in `hiloop-interceptor`. Private-only traits live in the private monorepo
near the component that owns them.

Raw ingress types may be looser than normalized contracts. For example,
`hiloop_interceptor::seams::RawSignal` keeps source/kind/attribute data as strings because it
represents heterogeneous pre-normalization input. This is an explicit exception to the narrow-type
rule, not a precedent for normalized schemas. Revisit those fields once the source and kind
taxonomy is stable.

## Contract Stability

`hiloop_core::event::Event` and the `hiloop_core::identity` types are **persisted and wire
contracts**. Treat their serialized shape as frozen at v1: a change to the field set, field
names, enum discriminants, or the lineage-path / HLC encoding is a coordinated schema decision
plus a migration, never an incidental edit.

This policy is enforced executably by
[`crates/hiloop-core/tests/spine_conformance.rs`](../crates/hiloop-core/tests/spine_conformance.rs)
(`event_v1_schema_is_locked`). If that test fails, either revert the change or, when the schema
change is intended, bump the normalizer `output_schema_version`, update the lock, and document the
migration. Internal, non-serialized APIs such as the `Source` / `Normalizer` trait signatures and
the pipeline internals are *not* frozen and may change freely — that is the whole point of keeping
them out of `hiloop-core`.

### Transparent-capture contracts

Transparent capture extends the existing Event v1 envelope; it does not introduce a second event
type. `hiloop_core::capture` owns typed constructors and closed reason sets for:

- `tls.interception_failed`;
- `tls.passthrough`;
- `net.passthrough`;
- `capture.transport`; and
- `capture.fatal`.

The constructors preserve scalar attribute types through Event v1 serialization. Normalizers must
not stringify their boolean or integer fields. They accept only route metadata, reason values, and
byte counts; request bodies, certificates, secret identifiers, and secret values have no input seam
and `payload_ref` remains empty.

`NetCaptureMode` is the shared selection contract. Its exact, case-sensitive values are `auto`,
`netns`, `proxy`, and `off`. The product CLI owns exposing that selector and combining it with run
policy; this repository owns the provisioner and dataplane selected by it. Defining the value type
does not make any transparent runtime available by itself.

The first-connection TLS compatibility registry is a versioned interceptor configuration made of
reviewed exact host-and-port rows. Wildcards, embedded ports, duplicates, zero ports, blank evidence
or ownership, and invalid `YYYY-MM-DD` revalidation dates are rejected. Registry matching may never
weaken restrictive-policy or secret-binding behavior.

## Current Seams

### Source

`Source` owns raw capture. It produces ordered `RawSignal` values from process stdio, proxy
payloads, OTLP/protobuf input, files, or future harness integrations.

A source should preserve raw bytes, timestamps, source identity, and source-local metadata. It
should not infer semantic event meaning that belongs in a normalizer.

The trait is a one-shot async lifecycle, not a stream accessor:

```rust
#[async_trait]
pub trait Source: Send {
    fn name(&self) -> &'static str;
    async fn run(
        self: Box<Self>,
        sink: RawSignalSink,
        shutdown: ShutdownSignal,
    ) -> Result<(), SourceError>;
}
```

Construction-time config (a bound socket, an open reader, credentials) lives on the concrete type;
the trait does not prescribe a config shape. `run` consumes the source, pushes signals into the
`RawSignalSink` (a transport-hiding wrapper over the pipeline's bounded channel, so sends apply
real back-pressure), and returns when its input is exhausted, `shutdown` resolves, or the sink
reports `SinkSend::Closed`. This single method covers both producer styles: **push** sources
(OTLP/proxy servers) make `run` an accept loop that selects on `shutdown`; **pull** sources (stdio)
make `run` a read loop that returns at end-of-input. `StdioSource` is the reference pull
implementation — it composes `LineFramer` and tees bytes verbatim before framing. The pipeline
drives a source through `Pipeline::run_source` (input-exhausted exit) or `run_source_until`
(external shutdown trigger).

`RawSignal` now also carries an optional, additive out-of-line body reference via
`RawSignal::with_payload_ref(PayloadRef)`. `RawSignal::new` is unchanged; when `payload_ref` is
`Some` it is where the body lives and `body` may be empty (aligned with
`hiloop_core::event::PayloadRef`, so a normalizer can carry it straight onto
`Event::with_payload_ref`).

The OTLP receiver and MITM proxy still feed the pipeline channel through their own
`serve(signal_tx, shutdown)` methods rather than implementing `Source`. Adopting the trait is **not**
mechanical: both are two-phase (bind, expose `local_addr()` so the supervisor can inject the
endpoint/proxy env, *then* run), the proxy's `serve` takes extra config (the CA), and they would need
to thread a `RawSignalSink` through their per-connection handlers. The trait does not yet model that
bind→expose-addr→run lifecycle — that is the main thing to design when migrating them. The
supervisor's inline `capture_stream` likewise predates `StdioSource`; see the `TODO(source-seam)` in
`supervisor.rs` (it treats a closed event pipeline as fatal, which `StdioSource::run` deliberately
does not, and it fans four producers into one shared channel).

Expected growth:

- richer source identity and credential/config types for networked sources;
- adopting `Source` in the OTLP/proxy receivers and the supervisor stdio path;
- durable raw payload references becoming the default for large bodies (the hatch exists; the
  offload backend does not yet).

Ways this may go awry:

- buffering without bounds (rely on the sink's back-pressure, not internal queues);
- losing raw bytes or timestamps;
- over-normalizing too early;
- hiding shutdown failures or ignoring the `shutdown` signal;
- letting source/kind string conventions leak into normalized schemas.

### Normalizer

`Normalizer` owns semantic extraction. It declares stable identity through `NormalizerDescriptor`,
reports applicability with `supports`, and converts one raw observation into zero or more normalized
`Event` values through `NormalizationOutcome`.

The pipeline, not individual normalizers, stamps common provenance such as normalizer name/version,
output schema version, raw source/kind, and raw retention policy. The shared half of that
provenance — the run's static attributes (including the per-invocation `wrapper.invocation_id`),
wrapper identity, and generic process metadata when available — lives on
`NormalizationContext::stamp_provenance`, the single construction seam the pipeline applies to
every normalized event and out-of-band supervisor records (capture health, spawn failure) call
directly, so an event built outside the pipeline cannot silently lose scope identity.
`process.command_args` is currently JSON-encoded into a string attribute because
`hiloop-core::event::AttributeValue` is intentionally scalar-only; revisit this if arrays become a
first-class attribute value.

`NormalizerRouter` returns every supported normalizer for each raw signal. This keeps generic source
normalization from being bypassed when later semantic enrichers are registered. The helper that
selects one "best" normalizer keeps the strongest support level and uses registration order for
ties.

Raw retention is explicit. The default is `discard_after_normalize`; if a normalizer requests
`preserve`, the pipeline requires a configured `RawStore`, stores the raw observation once, and
stamps `raw.observation_id` onto emitted events. `JsonlRawStore` is the current local bronze-store
implementation; production object storage and replay indexing are still future work. Diagnostics
are counted in `PipelineReport`, but they are not yet routed to exporters or side channels.

The current router can run every supported normalizer for a raw signal, which lets a generic source
normalizer and an early semantic normalizer coexist. Before shipping harness-specific enrichment as
a stable extension point, split that into two explicit stages:

```rust
pub trait SourceNormalizer {
    fn descriptor(&self) -> NormalizerDescriptor;
    fn supports(&self, raw: &RawSignal) -> NormalizerSupport;
    async fn normalize(
        &self,
        context: &NormalizationContext,
        raw: RawSignal,
    ) -> Result<NormalizationOutcome, NormalizeError>;
}

pub trait SemanticEnricher {
    fn descriptor(&self) -> NormalizerDescriptor;
    fn supports(&self, raw: &RawSignal, events: &[Event]) -> NormalizerSupport;
    async fn enrich(
        &self,
        context: &NormalizationContext,
        raw: &RawSignal,
        events: Vec<Event>,
    ) -> Result<NormalizationOutcome, NormalizeError>;
}
```

Migration steps: rename the existing `Normalizer` trait to `SourceNormalizer`, keep a type alias or
blanket adapter for current implementations, add a separate `SemanticEnricher` registry to the
pipeline after raw retention, then change `NormalizerRouter::select_all` back to source-normalizer
selection only.

Expected growth:

- optional harness-specific semantic enrichers layered after generic source normalizers;
- replay tooling for raw observations;
- richer diagnostics surfaced to exporters or side channels;
- typed normalizer output schema versions;
- configurable raw retention policies.

Ways this may go awry:

- silently accepting unsupported raw input;
- mutating hidden global state;
- dropping raw data before retention policy is honored;
- emitting events that are not replayable or versioned;
- treating diagnostics as invisible;
- overfitting to one harness.

### Exporter

`Exporter` owns delivery. It receives already-normalized event batches and flushes them before
shutdown. Exporters should not rewrite event semantics; enrichment belongs before export.

`ExportError` carries retry semantics in its variants — transient (`Backpressure`,
`Unavailable`), permanent (`Rejected`), ambiguous (`Other`) — so retry policy composes at the
seam instead of leaking transport knowledge upward. `SpoolingExporter` is that composition: a
decorator that keeps the wrapped exporter single-shot and honest while it absorbs outages into
a bounded in-memory spool with in-order redelivery, classified retry, and explicit drop
accounting.

Expected growth:

- additional export sinks (e.g. OTLP) and local test exporters;
- compression and authentication;
- partitioning;
- durable checkpoints.

Ways this may go awry:

- ambiguous partial failures;
- duplicate events from retries without a strategy;
- blocking the Tokio runtime;
- batches growing without bound;
- shutdown returning before buffered events are durable.

## Review Checklist

Use this checklist when reviewing changes to these seams:

- Does the change keep raw capture, semantic extraction, and delivery responsibilities separate?
- Is common provenance enforced centrally by the pipeline when possible?
- Does any persisted or replayable output include stable identity and versioning for the producer?
- Is support/routing behavior explicit instead of guessed inside the main operation?
- Are raw data retention, diagnostics, and lossy conversions explicit in signatures or documented as
  deferred decisions?
- Does a new implementation pass shared conformance tests plus focused source/protocol tests?
- Are shutdown, flush, cancellation, back-pressure, and partial failure semantics testable?
- Are string keys, schema names, and sentinel values centralized as constants, enums, or newtypes?
- Does the change avoid moving private-only workflow concepts into `hiloop-core`?
