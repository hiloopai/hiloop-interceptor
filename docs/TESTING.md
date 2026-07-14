# Testing Strategy

The interceptor sits between a harness and the outside world. Its first obligation is to preserve
the harness's behavior; its second is to capture useful, correctly attributed telemetry without
silent loss. Tests should make both obligations explicit.

Implemented correctness contracts gate CI. Wall-clock performance is recorded and reviewed until
representative workloads and stable runners give us enough evidence to set hard regression
thresholds.

## Behavior Contract

| ID | Required behavior | Primary proof |
|---|---|---|
| B1 | The wrapped command receives the requested argv and run context. | Mock-harness E2E |
| B2 | Without capture enabled, stdout/stderr and the child exit code pass through unchanged. | Mock-harness E2E |
| B3 | With capture enabled, stdout/stderr are teed byte-for-byte while normalized events are emitted. | Mock-harness E2E |
| B4 | Every normalized event carries the requested run id and lineage path plus normalizer, wrapper, raw-source, and process provenance. | Pipeline tests + E2E |
| B5 | Each source stream preserves observation order. No total order between independent sources such as stdout and stderr is promised. | Load E2E |
| B6 | LF and CRLF delimit records; a final partial line is emitted; empty lines are events; lines over 64 KiB are emitted in bounded chunks. | Supervisor unit tests + E2E |
| B7 | Non-UTF-8 bodies are preserved losslessly as base64 rather than replaced or decoded lossily. | Normalizer unit test + E2E |
| B8 | The default capture path is lossless and bounded: downstream pressure may block the child, but it must not silently drop or duplicate observations. | Pipeline tests + load E2E; backpressure stress pending |
| B9 | Raw preservation stores one raw observation per captured signal and links every derived event to it. Default retention does not create raw records. | Pipeline tests + E2E |
| B10 | On normal or nonzero child exit, capture drains and exporters/raw stores flush before the wrapper returns the child exit code. | Pipeline tests + E2E |
| B11 | Invalid output configuration and output-file conflicts fail before the child starts. | Mock-harness E2E |
| B12 | A telemetry pipeline failure does not abruptly kill a still-running child; the wrapper drains the child and then reports telemetry failure. | Supervisor unit test |
| B13 | The child leads its own process group; on SIGINT/SIGTERM the wrapper forwards the signal to that group, then still drains the child and reports its exit. | Mock-harness E2E |
| B14 | A normal child exit passes its code through; a child terminated by a signal is reported as `128 + signo`. | Supervisor unit test + E2E |
| B15 | With `--otlp`, the wrapper injects `OTEL_EXPORTER_OTLP_ENDPOINT`, receives the child's OTLP trace export, and emits run-lineage-stamped events; LLM spans become `llm`. | Mock-harness E2E + normalizer tests |
| B16 | With `--proxy`, the wrapper injects `HTTPS_PROXY` + a child-scoped CA bundle, decrypts the child's HTTPS, and emits run-lineage-stamped `net`/`llm` events; bodies stream frame-by-frame into a content-addressed blob store (`--blob-dir`) and events carry a `payload_ref`. | Mock-harness MITM E2E + blob/handler/normalizer tests |
| B17 | With capture enabled, the wrapper emits process-boundary lifecycle events on the `exec` signal: `process.start` at spawn (process identity via provenance, the configured `--env-allowlist` names, and one `process.env.<NAME>` attribute per allowlisted variable set in the child's environment — the value scrubbed by the capture-side redaction before it is recorded; non-allowlisted variables are never captured), `process.exit` with the child's exit byte and wall-clock duration (plus the terminating signal when signal-killed), and one `process.signal` per forwarded terminating signal. | Mock-harness E2E + normalizer/emitter unit tests |
| B18 | With capture enabled, a child that fails to spawn is still captured: the wrapper exports one `process.spawn_failed` `exec` event (attempted argv, working directory, OS error, run identity and static attributes including `execution.id`) before the spawn error propagates — full capture includes failed attempts. | Mock-harness E2E + supervisor unit test |
| B19 | Every event the wrapper exports — including out-of-band records built outside the pipeline (`capture.drain`, `process.spawn_failed`) — carries `wrapper.invocation_id`, a ULID minted once per wrap invocation at `RunOptions` construction; sequential invocations in one process mint distinct ids. Producer-minted join keys are globally unique: `http.exchange_id` is a minted ULID, never a process-local counter, so invocations sharing one run cannot collide. | Full-surface mock-harness E2E + public-run-API test + supervisor/proxy unit tests |
| B20 | A telemetry-gateway outage never aborts capture and never blocks the child: gRPC export failures are classified — transient (`UNAVAILABLE`, `RESOURCE_EXHAUSTED`, transport) park the batch in a bounded in-memory spool (event + byte caps; over-cap drops oldest, counted) redelivered strictly in arrival order under bounded exponential backoff; permanent rejections (`INVALID_ARGUMENT`, `PERMISSION_DENIED`, `UNAUTHENTICATED`) drop that batch immediately with a loud warning; anything else gets one inline retry, then spools. Local sinks (JSONL) keep capturing regardless. At run end the spool drains best-effort within a bounded budget; loss and undelivered backlog are reported with counts on stderr and on the `capture.drain` record (`capture.events.dropped`/`rejected`/`pending`), which every gRPC-exported run emits. | Spool unit tests + gRPC classification tests + gateway-outage mock-harness E2E |
| B21 | Transparent composition exposes preflight separately, never starts a strict-mode child after failed preflight, strips proxy variables, supplies CA-only trust hints, emits `capture.transport`, and preserves close-first fatal teardown. | Public netns-run API tests with deterministic fakes; ignored capable-host HTTP E2E |

These are desired contracts, not incidental implementation details. Changing one requires an
explicit design decision and updated tests.

## Known Contract Gaps

The following behavior is needed before the interceptor is a production supervisor:

- **Live export latency:** a partial batch is currently exported only when it fills or the child
  exits. Add a configurable maximum batch delay and prove emit-to-export p95 stays under one second.
- **Signals and process trees:** SIGINT/SIGTERM forwarding to the child's process group and
  signal-aware exit codes (`128 + signo`) are implemented and tested (B13/B14). Still open: orphan
  reaping when running as true PID 1 (Linux `PR_SET_CHILD_SUBREAPER`), SIGKILL escalation after a
  configurable grace period, and wrapper behavior when its own parent disappears.
- **Telemetry failure policy:** the current policy protects child liveness and reports failure
  afterward. Define configurable fail-open/fail-closed policy before production exporters land.
- **Existing environment:** define merge/override behavior for pre-existing
  `OTEL_RESOURCE_ATTRIBUTES`, proxy variables, and CA bundle variables.
- **Slow and failed sinks:** prove bounded memory, lossless blocking, cancellation, flush ordering,
  and recovery with a deliberately slow/failing exporter and raw store.
- **Capture surfaces:** OTLP trace ingest (B15) and proxy HTTPS MITM (B16) are covered; add the same
  contract coverage for future eBPF sources, extend OTLP to logs/metrics, correlate proxy
  request/response pairs, stream large/SSE bodies instead of buffering, and add streaming-offload by
  content hash.

## Test Layers

### Pull Requests

PR CI runs:

1. Unit and property tests for narrow logic and schema invariants.
2. Seam conformance tests against every implementation and its in-memory mock.
3. Mock-harness E2E tests against the compiled interceptor binary.
4. Formatting, compile, clippy, rustdoc, and dependency-review checks.

The deterministic mock harness lives at
`crates/hiloop-interceptor/tests/fixtures/mock_harness.sh`. It has explicit modes for context
inspection, mixed streams, binary output, nonzero exits, high-volume output, and child-start
markers. It uses POSIX `sh`, matching the interceptor's current Unix/PID-1 product scope.

Run the fast E2E suite directly:

```sh
cargo test -p hiloop-interceptor --test interceptor_e2e --all-features --locked
```

The real Linux network-substrate contract is intentionally ignored on ordinary PR runners. It
requires an unprivileged-user-namespace host whose policy permits nested network namespaces,
nftables TPROXY, `/dev/net/tun`, and the exact pinned pasta executable. Run it on that capable lane
with:

```sh
HILOOP_TEST_PASTA=/path/to/pasta \
  cargo test -p hiloop-interceptor --test netns_substrate --all-features --locked \
  -- --ignored
```

The same capable lane runs the production composer through a real cleartext HTTP request and asserts
that the transparent gateway emits request and response capture:

```sh
HILOOP_TEST_PASTA=/path/to/pasta \
  cargo test -p hiloop-interceptor --test netns_run_api --all-features --locked \
  -- --ignored
```

That contract has an outer timeout and covers original IPv4/IPv6 destinations, private workload
loopback, dual-stack mapped host loopback without gateway re-entry, boundary PMTU plus per-family
fragment counters, transparent dual-stack UDP relay and reply-source identity,
capability/descriptor and process-inspection confinement, workload exec failure, worker and pasta
crashes, an IPC-reported fatal transition with a detached descendant, explicit shutdown, drop
cleanup, and a detached descendant. It scans `/proc` after every
path so no owned helper or carrier remains to retain namespace, mount, veth, or nftables state.

Normal CI still runs the provisioner/fake conformance tests, exact nft and policy-route generation,
pasta argument/version and timeout checks, capability and descriptor plans, host-namespace UDP/TCP
DNS relay, exact TTL-bounded answer tracking, resolver-file preservation, dual-stack UDP flow and
policy-matrix tests, close-latch flow cancellation, fatal-report wire round trips, direct
post-teardown fatal persistence under blocked export, cleanup order, and MTU/fragment policy. A
skipped real contract is not evidence that the host substrate works.

### Nightly

Nightly tests should add workloads that are too slow or timing-sensitive for every PR:

- 100,000+ events through small queues with a slow exporter;
- cancellation and exporter/raw-store failure at each pipeline stage;
- memory high-water measurement during sustained capture;
- repeated start/stop and nonzero-exit loops to detect leaked processes or file descriptors;
- Criterion wall-clock benchmark recording.

### Pre-Release

Pre-release testing should use real integrations:

- representative harnesses, including at least one customer-shaped custom harness;
- real OTLP SDKs and the embedded receiver;
- HTTPS proxy capture across supported runtimes;
- production exporter/backend;
- PID-1 execution in the target sandbox image;
- a multi-hour soak with telemetry and dependency failures.

## E2E Review Rules

- Assert observable behavior at the binary boundary, not private implementation details.
- Use fixed run-lineage identity in E2E tests so provenance assertions are deterministic.
- Assert exact bytes at the tee boundary and parsed values at JSONL boundaries.
- Assert per-stream order only; scheduling makes stdout/stderr total order nondeterministic.
- Keep PR scenarios deterministic and small. Throughput measurements belong in benchmarks, not
  wall-clock assertions on shared CI runners.
- Give every external-process scenario a timeout so a deadlock fails instead of hanging CI.
- A load test may gate on zero loss, duplication, or deadlock. It must not gate on elapsed time
  until it runs on a stable performance runner.

## Performance Contract

Correctness under load must become a hard gate as the corresponding implementations and
deterministic stress harnesses land:

- no dropped or duplicated observations in the default blocking mode;
- memory remains bounded by configured queues, batches, maximum in-flight bodies, and exporter
  buffers rather than total run duration;
- shutdown drains accepted observations and flushes durable sinks;
- pressure is observable through metrics and does not become an unexplained hang.

The initial directional budgets are:

| Surface | Metric | Directional budget |
|---|---|---|
| Wrapper | release binary / idle RSS | `< 20 MB` / `< 30 MB` |
| Pass-through | added process startup p95 | `< 25 ms` |
| Stdio capture | short-line throughput | `>= 100k events/s/node` |
| Stdio capture | 1 KiB aggregate throughput | `>= 50 MiB/s/node` |
| Live export | capture-to-export p95 | `< 1 s` |
| Proxy, once implemented | added request latency p99 | `< 5 ms` |
| Soak | memory/file-descriptor/process growth | flat after warm-up |

These budgets are hypotheses. Record the hardware, OS, toolchain, workload, and queue/batch
configuration with every result. Promote a budget to a CI gate only after repeated measurements on
a stable runner and validation against real harness workloads. See
[`BENCHMARKING.md`](BENCHMARKING.md) for the benchmark implementation plan.
