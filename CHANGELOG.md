# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the project is pre-1.0,
minor releases may include breaking changes to the CLI, its flags, and the event schema.

## [Unreleased]

### Added

- Egress policy enforcement for intercepted HTTP(S) traffic (`--egress-mode allow|deny` with
  repeatable `--egress-domain` / `--egress-cidr` rules, and the `RunOptions::with_egress` builder).
  Hosts are canonicalized (control-char/percent/userinfo rejection, IDNA→punycode, IP-literal
  detection across dotted/decimal/hex/octal/IPv6/IPv4-mapped notations) before a label-anchored
  domain match or CIDR membership check; a denied CONNECT or decrypted request — or a decrypted
  `Host` that disagrees with the CONNECT's SNI host — short-circuits with `403` and emits a structured
  `egress.denied` event. This is a **cooperative** control over proxied traffic; the un-bypassable
  egress boundary is host-side.
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

### Changed

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
