# Interface Boundaries

This document tracks the current implementation seams in `hiloop-interceptor`, how they are
expected to grow, and where they can fail. It should evolve with the implementation. Durable Rust
style rules live in [`RUST_STYLE.md`](RUST_STYLE.md).

## Layering

`hiloop-core` owns shared contracts, not orchestration. Keep it dependency-light and stable:

- fork identity types;
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

## Current Seams

### Source

`Source` owns raw capture. It produces ordered `RawSignal` values from process stdio, proxy
payloads, OTLP/protobuf input, files, or future harness integrations.

A source should preserve raw bytes, timestamps, source identity, and source-local metadata. It
should not infer semantic event meaning that belongs in a normalizer.

Expected growth:

- cancellation and child process lifecycle handling;
- source-specific back-pressure reporting;
- credentials and config for networked sources;
- richer source identity;
- durable raw payload references when bodies become too large to inline.

Ways this may go awry:

- buffering without bounds;
- losing raw bytes or timestamps;
- over-normalizing too early;
- hiding shutdown failures;
- letting source/kind string conventions leak into normalized schemas.

### Normalizer

`Normalizer` owns semantic extraction. It declares stable identity through `NormalizerDescriptor`,
reports applicability with `supports`, and converts one raw observation into zero or more normalized
`Event` values through `NormalizationOutcome`.

The pipeline, not individual normalizers, stamps common provenance such as normalizer name/version,
output schema version, raw source/kind, raw retention policy, wrapper identity, and generic process
metadata when available. `process.argv` is currently JSON-encoded into a string attribute because
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

Expected growth:

- ClickHouse, OTEL, and local test exporters;
- retries and partial-failure policy;
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
