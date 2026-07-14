# hiloop-interceptor

> ⚠️ Early alpha. It works today — it wraps a real agent harness and captures its
> LLM calls, network traffic, telemetry, and stdio end-to-end — but APIs, flags, and the
> event schema will still change. Pin a commit if you depend on it.

The **interception wrapper** for agent harnesses. It runs anywhere — your laptop or
inside a sandbox — wraps your harness command, and captures its telemetry (OpenTelemetry,
logs, network calls) **tagged with run-lineage identity**, so observability branches with
your experiments.

It is the open-source edge of hiloop: snapshottable, forkable agent sandboxes with tree-native
observability. The interceptor is the part that runs on *your* machine, so it's open source
(MIT OR Apache-2.0); the sandbox/snapshot/control-plane infrastructure lives in a separate,
private monorepo.

## Status

Early alpha. The core capture path — run-lineage identity stamping, stdio/OTLP/HTTPS-proxy
capture, JSONL and gRPC export — works end-to-end and is covered by the integration suite.
What's still evolving: the event schema, harness-aware semantic normalization, and
additional export sinks. See [`docs/INTERFACES.md`](./docs/INTERFACES.md) for the architecture
and seam design, and [`docs/TESTING.md`](./docs/TESTING.md) for the behavior contract.

## Quick start

```sh
cargo run -p hiloop-interceptor -- run -- echo hello
```

Today this resolves a run-lineage context, injects the spine into the child environment
(`HILOOP_*`, `OTEL_RESOURCE_ATTRIBUTES`), and passes the command through.

To capture stdout/stderr into normalized JSONL events while still teeing child output:

```sh
cargo run -p hiloop-interceptor -- run --events-jsonl ./events.jsonl -- sh -c 'printf "hello\n"'
```

Add `--raw-jsonl ./raw.jsonl` with `--events-jsonl` to preserve captured raw observations and stamp
`raw.observation_id` on the normalized events that came from them.

Add `--otlp` (with `--events-jsonl`) to also run an embedded OTLP/HTTP receiver: the wrapper injects
`OTEL_EXPORTER_OTLP_ENDPOINT` into the child, captures the harness's own OpenTelemetry trace export,
and emits run-lineage-stamped events — `gen_ai.*` / `llm.*` spans become `llm` events.

```sh
cargo run -p hiloop-interceptor -- run --otlp --events-jsonl ./events.jsonl -- <harness command>
```

Add `--proxy` (with an export target, plus `--blob-dir` — or `--export-grpc`, see below) to run an
embedded MITM proxy: the wrapper
mints an ephemeral CA, injects `HTTPS_PROXY` plus a child-scoped CA bundle, decrypts the harness's
HTTPS traffic, and emits run-lineage-stamped `net` events (`llm` for known LLM API hosts). Bodies are
streamed frame-by-frame into a content-addressed blob store (`--blob-dir`), so events carry only a
`payload_ref` and memory stays bounded even for streaming/SSE responses.

```sh
cargo run -p hiloop-interceptor -- run --proxy --events-jsonl ./events.jsonl --blob-dir ./blobs -- <harness command>
```

> **The `--proxy` CLI mode is cooperative capture.** It injects proxy + CA-trust env vars
> (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) into
> the wrapped child only — it never touches the machine root trust store. So it decrypts HTTPS for
> clients that honor the proxy env and trust the injected CA (Node, Python `requests`, `curl`, and most
> SDKs — Claude Code, for one, is captured fully). It does **not** capture certificate-pinned clients,
> mTLS, clients with a hardcoded trust store, or clients that ignore the proxy env. Guaranteed,
> client-agnostic capture needs a transparent transport. Embedding products can select the library's
> Linux network-namespace transport through `NetnsRun`; the public CLI intentionally exposes only
> this portable cooperative mode. See [the interface contract](./docs/INTERFACES.md#transparent-capture-contracts)
> and
> [`docs/decisions/0001-cooperative-capture-vs-ebpf.md`](./docs/decisions/0001-cooperative-capture-vs-ebpf.md).

Add `--export-grpc <URL>` to stream captured events to a hiloop telemetry gateway over gRPC. It
composes with `--events-jsonl` (list both to keep a local JSONL durability log alongside the remote
export). With `--proxy`, the captured request/response bodies are uploaded to the same gateway at
run end (digest-first: only content the gateway is missing is sent), so `--blob-dir` becomes
optional — omitted, bodies stage in a per-run scratch store that is removed once every blob has
shipped (kept, and named in the run's warning, if any upload fails). The
API key is read from the `HILOOP_API_KEY` environment variable — never a flag, so
it stays out of `process.command_args`. An authenticated gateway derives the tenant from that token, so leave
`--tenant-id` empty there; `--project-id` selects the project to record under. Use `--insecure-grpc`
for a cleartext local gateway (and `--tenant-id` to assert tenancy when it has no auth).

```sh
# Hosted, authenticated:
HILOOP_API_KEY=hil_… cargo run -p hiloop-interceptor -- \
  run --export-grpc https://telemetry.example.com:443 --project-id my-project -- <harness command>

# Local dev gateway (no auth, cleartext):
cargo run -p hiloop-interceptor -- \
  run --export-grpc http://127.0.0.1:50051 --insecure-grpc --tenant-id dev --project-id local \
  --events-jsonl ./events.jsonl -- <harness command>
```

Captured events are shipped in batches. A batch ships as soon as it reaches `--export-batch-size`
(default 128 events) **or** once the oldest buffered event has waited `--export-flush-interval-ms`
(default 1000 ms), whichever comes first — so a long-running harness's events reach the gateway (and
any live tail) progressively rather than only when it exits. Lower the interval for a snappier tail,
or set `--export-flush-interval-ms 0` to disable the timer and flush only on a full batch or at exit.

## What it captures

Wrapping a real Claude Code turn with `--proxy --otlp` captures the whole footprint of the harness —
its LLM calls, every tool/MCP request, its own telemetry export, and its stdio — all run-lineage-stamped.
From one `claude -p "…"` (`inspect` output):

```
57 events across 1 run lineage path(s)
  signals: llm=13 log=2 net=42
  llm  http.request  api.anthropic.com          # the model calls (request/response bodies → blob store)
  net  http.request  mcp.slack.com / mcp.notion.com / mcp.linear.app   # MCP tool traffic
  net  http.request  http-intake.…datadoghq.com                        # the harness's own telemetry
  net  http.response …                                                 # paired responses
  log  process.stdin / process.stdout / process.stderr                 # the operator's input + console output
```

Each `llm`/`net` event carries the decrypted request/response body by `payload_ref` into the blob
store (content-addressed, so identical bodies dedupe and memory stays bounded for SSE). Capturing the
harness's *own* telemetry (the Datadog export above) is intentional — it's signal, not noise.

Inspect a captured events file — counts grouped by run lineage path, or how two runs diverged:

```sh
cargo run -p hiloop-interceptor -- inspect ./events.jsonl
cargo run -p hiloop-interceptor -- inspect ./events.jsonl --diff <root-run-ulid> <root-run-ulid>.<child-run-ulid>
```

The integration tests wrap a real command and assert child output is teed while run-lineage-stamped stdio
events are flushed to JSONL, that an OTLP trace export from the child is captured, and that the MITM
proxy captures decrypted HTTPS and correlates request/response over chunked upstreams. That proves
the supervisor, env stamping, OTLP ingest, proxy capture, local normalization, and exporter seam
wiring. Additional export sinks and harness-aware semantic normalization are still planned behind
the existing seams.

## Workspace

This repo follows the same basic shape as modern Rust CLI workspaces: root-owned package
metadata, dependency versions, lints, profiles, and toolchain pinning; crates under
`crates/`; a thin binary crate over testable library modules.

- `hiloop-core`: stable shared contracts for run-lineage identity and telemetry events.
- `hiloop-interceptor`: CLI, supervisor scaffolding, and wrapper-local seam traits.

Rust is pinned to stable `1.96.0`; the crate edition and rustfmt style edition are both
`2024`.

Rust code style and testing conventions are documented in
[`docs/RUST_STYLE.md`](./docs/RUST_STYLE.md).
The behavior contract, E2E ladder, and initial performance budgets are documented in
[`docs/TESTING.md`](./docs/TESTING.md).
Performance benchmarking plans are tracked in [`docs/BENCHMARKING.md`](./docs/BENCHMARKING.md).

## Verification and security

Local verification covers CI plus the local dependency policy:

```sh
cargo fmt --all --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo deny check
```

Run the compiled-binary mock-harness E2E suite directly with:

```sh
cargo test -p hiloop-interceptor --test interceptor_e2e --all-features --locked
```

`cargo deny check` is optional until `cargo-deny` is installed locally, but should be run for
dependency, license, or lockfile changes. GitHub Dependency Review runs on PRs, and GitHub CodeQL
default setup should be enabled in repository security settings.

## Install

Prebuilt binaries for Linux (x86_64, arm64), macOS (Intel, Apple Silicon), and Windows (x86_64)
are attached to every [GitHub Release](https://github.com/hiloopai/hiloop-interceptor/releases).
Download the archive for your platform, verify it against the published `.sha256`, extract
`hiloop-interceptor`, and put it on your `PATH`.

Prefer to build from source:

```sh
cargo install --git https://github.com/hiloopai/hiloop-interceptor hiloop-interceptor
```

GitHub Releases is the only distribution channel; this tool is intentionally **not** published to
crates.io.

## License

Dual-licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your
option.
