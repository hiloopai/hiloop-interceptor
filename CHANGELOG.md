# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the project is pre-1.0,
minor releases may include breaking changes to the CLI, its flags, and the event schema.

## [Unreleased]

### Added

- The gRPC event export now survives telemetry-gateway outages: export failures are classified by
  gRPC status — a transient failure (`UNAVAILABLE`, `RESOURCE_EXHAUSTED`, transport errors) parks
  the batch in a bounded in-memory spool (8192 events / 32 MiB; over the caps the oldest events
  are dropped and counted) and is redelivered strictly in arrival order under bounded exponential
  backoff (500 ms doubling to 30 s, 10 s per attempt); a permanent rejection (`INVALID_ARGUMENT`,
  `PERMISSION_DENIED`, `UNAUTHENTICATED`) drops that batch immediately with a loud warning
  (redelivering a judged batch cannot succeed); anything else gets one inline retry, then spools.
  An outage no longer aborts the capture pipeline, so local sinks (`--events-jsonl`) keep
  capturing through it, and the child is never blocked on a sink known to be down. At run end the
  spool drains best-effort within the same bounded budget as the payload-blob drain; anything
  still undelivered is reported on stderr with counts instead of being dropped silently. The
  `capture.drain` health record is now emitted for every gRPC-exported run (previously only
  proxy-capturing runs) and gains `capture.events.dropped`, `capture.events.rejected`, and
  `capture.events.pending` attributes; `capture.complete` now also requires that no exported
  event was lost. `ExportError` gains `Unavailable` and `Rejected` variants carrying these retry
  semantics at the exporter seam.

- Every event the wrapper emits now carries `wrapper.invocation_id`: a ULID minted once per wrap
  invocation (at `RunOptions` construction) that identifies which invocation produced the event —
  the scope key that correlates one wrapped process's capture (lifecycle, stdio, exchanges,
  OTLP-derived telemetry, capture health) even when no orchestrator-assigned `execution.id` exists,
  and keeps sibling invocations sharing one run distinguishable. Out-of-band records
  (`capture.drain`, `process.spawn_failed`) are stamped through the same provenance seam as
  pipeline-normalized events (`NormalizationContext::stamp_provenance`), so they now also carry the
  full shared provenance set — `capture.drain` gains `process.pid`/`process.command`/
  `process.argv`/`process.cwd`, and `process.spawn_failed` gains `process.command`. Purely
  additive to the event schema.
- Payload blob upload to the telemetry gateway: with `--export-grpc` and `--proxy`, captured
  request/response bodies now ship to the gateway's blob service at run end over the same endpoint
  and Bearer auth as the event export (`GrpcBlobUploader`, behind the existing `BlobUploader`
  seam). The protocol is digest-first — a `HasBlobs` probe reports which blake3 digests the gateway
  is missing and only those are uploaded, as chunked client-streams (1 MiB frames, 64 MiB per-blob
  cap) the gateway re-hashes before storing. `--blob-dir` becomes optional with a gRPC export:
  omitted, bodies stage in a per-run scratch store that is removed once every blob has shipped —
  an incomplete drain (upload failure, over-cap blob) keeps the store and names its path in the
  warning, so captured bodies are never silently destroyed. The upload is best-effort like the
  rest of the telemetry drain: a failure is reported on stderr and never overrides the child's
  exit code.

- Process-boundary lifecycle events on the `exec` signal (previously declared but never emitted):
  every captured run now records `process.start` at spawn, `process.exit` with the child's exit byte
  and wall-clock duration (plus `process.term_signal` when the child was signal-killed), and one
  `process.signal` per forwarded terminating signal. A new `--env-allowlist` flag (or
  `RunOptions::with_env_allowlist`) records the listed environment variable *names* on
  `process.start` (`process.env_allowlist`), and captures each listed variable that is set in the
  child's environment as a `process.env.<NAME>` attribute — the value scrubbed by the capture-side
  secret redaction (the same pattern and known-secret-literal passes applied to captured bodies)
  before it is recorded. The environment is a known secret carrier, so value capture is strictly
  opt-in per name: variables outside the allowlist are never captured.
- Egress policy enforcement for intercepted HTTP(S) traffic (`--egress-mode allow|deny` with
  repeatable `--egress-domain` / `--egress-cidr` rules, and the `RunOptions::with_egress` builder).
  Hosts are canonicalized (control-char/percent/userinfo rejection, IDNA→punycode, IP-literal
  detection across dotted/decimal/hex/octal/IPv6/IPv4-mapped notations) before a label-anchored
  domain match or CIDR membership check; a denied CONNECT or decrypted request — or a decrypted
  `Host` that disagrees with the CONNECT's SNI host — short-circuits with `403` and emits a structured
  `egress.denied` event. This is a **cooperative** control over proxied traffic; the un-bypassable
  egress boundary is host-side.
- Request-body anomaly detection over intercepted traffic (`--detect-anomalies`, optional
  `--block-anomalies`, and the `RunOptions::with_anomaly_detection` builder). Three config-driven
  heuristics run on the redacted captured request body: a large base64-dominated blob
  (`--anomaly-min-base64-bytes` size floor + `--anomaly-base64-ratio` character ratio), a suspicious
  `Content-Type` (`--anomaly-suspicious-content-type`, defaulting to binary/archive types), and an
  upload-shaped write (`--anomaly-max-upload-bytes` on `POST`/`PUT`/`PATCH`). Each match stamps an
  `anomaly.flagged` attribute (rule names only, never body content) on the exchange; block mode
  additionally short-circuits the request with `403` and stamps `anomaly.blocked`. This is a
  **cooperative** defense-in-depth detection layer over proxied traffic; the un-bypassable boundary is
  host-side. Off by default.
- Credential injection: bind a named secret to a destination host and request header
  (`--secret-binding`, broker via `--secret-broker-url` + `HILOOP_SECRET_BROKER_TOKEN`, and the
  `RunOptions::with_secret_bindings` builder). On a request to the bound host the proxy resolves the
  secret from the broker and writes `<scheme> <value>` into the header; the value is scrubbed from the
  captured telemetry, zeroized after use, and a broker failure fails the request closed.
- gRPC export now flushes on a size **or** age trigger, whichever comes first: a partial batch ships
  once it has waited `--export-flush-interval-ms` (default 1000 ms; `0` disables the timer) even
  before it reaches `--export-batch-size` (default 128). This bounds export latency so a long-running
  harness's events reach the gateway — and any live tail — progressively rather than only at exit.
  Both knobs are also configurable via `HILOOP_EXPORT_FLUSH_INTERVAL_MS` / `HILOOP_EXPORT_BATCH_SIZE`
  and on the embeddable `RunOptions` builder.

### Fixed

- The gRPC event export is now deadline-bounded end to end: the gateway channel bounds its
  (re)connect at 10 s and every `Ingest` RPC — including the lazy connect it may perform — is
  capped at 10 s, classifying a timeout as a transient (retryable) failure. Previously the
  channel connected with no connect or RPC timeout, so an unreachable/black-holed gateway could
  stall the wrapper's teardown drain — and the child's exit-status propagation — indefinitely;
  the run-level spool and drain budgets bounded the wrapper's own paths, but the exporter seam
  itself was unbounded for any direct (embedder) caller.

- The wrapper installs its SIGINT/SIGTERM forwarding handlers before spawning the child, closing
  a startup window where a terminating signal could kill the wrapper by its default disposition —
  ending the wrap without the signal ever being forwarded and leaving the just-spawned child's
  process group orphaned.
- A telemetry capture/export failure no longer overrides the exit code of a child that already
  ran: `run` is exit-code transparent, and post-exit drain failures are reported on stderr as
  `warning:` diagnostics instead of failing the wrapper. Only a missing/failed-to-spawn child or a
  misconfiguration still exits nonzero on the wrapper's behalf.
- Rejected ingest RPCs now render as one human-readable line (status message or code description
  plus the deduplicated source chain) instead of leaking `tonic` transport `Debug` internals or a
  mangled empty message (`ingest rejected: `).

### Changed

- `http.exchange_id` is now a minted ULID instead of a `xchg-`-prefixed process-local counter.
  The counter restarted at zero in every wrapper invocation, so two invocations emitting into one
  run both minted `xchg-0000000000000000` and their unrelated exchanges collided under a single id;
  ULIDs are globally unique across invocations. The attribute key and its request/response pairing
  semantics are unchanged — only the value format changes, and only for newly captured events.
- **Breaking (embedders):** the generated `hiloop.telemetry.v1` client stubs moved from
  `grpc_export::proto` to `grpc_client::proto`, alongside the shared gateway-client plumbing
  (`TOKEN_ENV`, channel construction, Bearer auth) now used by both the event exporter and the
  blob uploader. Imports of `grpc_export::proto` or `grpc_export::TOKEN_ENV` switch to the
  `grpc_client` paths.
- **Breaking:** the telemetry spine is now keyed on a run and its **lineage path** (the dotted
  sequence of run ULIDs from the root run to this run) instead of an intra-run fork tree. The
  `ForkContext { run_id, fork_node_id, fork_path }` type is replaced by `RunContext { run_id,
  lineage_path }` (with `LineagePath` superseding `ForkPath`); `ForkNodeId`, `ForkOrdinal`, and
  `ChildOrdinalAllocator` are removed. `Event` drops `fork_node_id` / `fork_path` and gains
  `lineage_path` (wire field 10; fields 3–4 reserved). The `run` command replaces `--node` /
  `--fork-path` (and `HILOOP_FORK_NODE_ID` / `HILOOP_FORK_PATH`) with `--lineage-path` /
  `HILOOP_LINEAGE_PATH`, and stamps `HILOOP_LINEAGE_PATH` + `hiloop.run.lineage_path` into the child
  environment. `inspect` groups and diffs by lineage path. This aligns the wire contract with the
  telemetry gateway, which keys ingested events on `run_id` + `lineage_path`.

## [0.1.0] - 2026-06-26

First public release. Early alpha — it captures real agent harnesses end-to-end, but APIs, flags,
and the event schema will still change.

### Added

- `run` command that wraps an agent harness, resolves a run-lineage context, and injects the spine
  into the child environment (`HILOOP_*`, `OTEL_RESOURCE_ATTRIBUTES`).
- stdio capture: tee the child's stdout, stderr, and stdin into normalized, run-lineage-stamped JSONL
  events (`--events-jsonl`), with optional raw-observation preservation (`--raw-jsonl`).
- Embedded OTLP/HTTP receiver (`--otlp`) that captures the harness's own OpenTelemetry trace
  export; `gen_ai.*` / `llm.*` spans become `llm` events.
- Embedded cooperative MITM proxy (`--proxy`) that mints an ephemeral, child-scoped CA, decrypts
  the harness's HTTPS traffic, and emits run-lineage-stamped `net` / `llm` events. Bodies stream into a
  content-addressed blob store (`--blob-dir`), so memory stays bounded for streaming/SSE responses.
- gRPC export (`--export-grpc`) to a hiloop telemetry gateway, with the API key read from
  `HILOOP_API_KEY` (never a flag). Composes with local JSONL durability logging.
- `inspect` command to summarize a captured events file by run lineage path and to diff two runs.
- Prebuilt binaries for Linux (x86_64, arm64), macOS (Intel, Apple Silicon), and Windows (x86_64),
  attached to each GitHub Release with SHA-256 checksums.

[Unreleased]: https://github.com/hiloopai/hiloop-interceptor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hiloopai/hiloop-interceptor/releases/tag/v0.1.0
