# Capture Surfaces — Design & Decision

**Status:** decision doc. This compares the two candidate first network-capture surfaces so we
can pick one deliberately. It builds on the seam contracts in [`INTERFACES.md`](INTERFACES.md).

## Why this decision matters

Today the only real capture surface is stdout/stderr line capture. That proves the
spine/pipeline/exporter plumbing but not the product thesis: an agent harness's *interesting*
behavior — LLM calls, tool calls — happens over HTTPS, not on stdout. This work adds the first surface
that captures that. Two candidates, very different cost/risk/coverage profiles. Both are **Tier-1
cooperative** mechanisms (env injection); the sandbox-only transparent-redirect and eBPF tiers
(DESIGN.md §2) stay deferred behind the same `Source` seam.

The wrapper already injects `OTEL_RESOURCE_ATTRIBUTES` (the spine) into the child, so either
surface inherits run-lineage-stamping for free.

## Candidate A — OTLP receiver

The wrapper becomes the child's local OpenTelemetry collector: inject
`OTEL_EXPORTER_OTLP_ENDPOINT` (already in the DESIGN.md §2 env table) at a port the wrapper owns,
receive the harness's own OTLP export, and normalize spans/logs/metrics into `Event`s — mapping the
`gen_ai.*` / `llm.*` semantic conventions to `SignalType::Llm` where present.

- **Mechanism:** an OTLP server. SDKs default to **gRPC on `:4317`** (needs `tonic`/`prost`);
  OTLP/HTTP on `:4318` (protobuf or JSON over `hyper`) is lighter but not the default. Starting
  HTTP-only captures fewer harnesses out of the box; gRPC captures the default but adds `tonic`.
- **Dependencies (shipped):** `opentelemetry-proto` + `prost` (+ `tonic` for gRPC, or `hyper` for
  HTTP). Moderate; no TLS/crypto.
- **Data quality:** **high and pre-structured** — you get exactly the spans the SDK chose to emit,
  already semantic (`gen_ai.request.model`, token counts, tool calls). Little parsing.
- **Coverage:** **cooperative only.** A harness that doesn't emit OTEL, or ignores the endpoint,
  produces nothing. Custom or un-instrumented harnesses are invisible.
- **Security surface:** **minimal.** No decryption, no CA, no private key. A localhost receiver.
- **Effort:** smaller. No cert lifecycle, no MITM, no HTTP/2-over-TLS.

## Candidate B — MITM proxy

The wrapper runs a TLS-intercepting proxy; inject `HTTPS_PROXY`/`HTTP_PROXY` plus **child-scoped**
CA-bundle vars (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, …) so the proxy can
decrypt without touching the system trust store. Read request/response bodies, offload large ones to
a `RawStore` by hash, normalize to `net.*` and (per-provider) `llm.*` events.

- **Mechanism:** `hudsucker` + `rustls` (DESIGN.md §2). Pre-generate an **ECDSA** CA and **cache leaf
  certs per host** — the naive RSA-keygen-per-handshake path is the documented way these proxies
  fall over. **HTTP/2 matters:** Anthropic/OpenAI APIs use h2, so ALPN/h2 handling is in scope, not
  optional, for the first useful slice.
- **Dependencies (shipped):** `hudsucker`, `rustls`, `rcgen`, a crypto backend (`ring`/`aws-lc-rs`),
  `hyper`. The heaviest addition to the **shipped** binary — relevant to the `<20 MB` budget
  (`TESTING.md`).
- **Data quality:** **ground truth on the wire** — every request regardless of SDK instrumentation.
  But raw: extracting `llm.*` semantics needs a per-provider body parser (a semantic enricher), so
  structured LLM data is a second step, not free.
- **Coverage:** **universal among non-pinned clients** — any HTTP client, any language, instrumented
  or not. This is the "regardless of how the harness evolves" thesis. Breaks on cert pinning / mTLS
  (that's the eBPF tier's job, deferred).
- **Security surface:** **significant.** The wrapper holds a CA private key and decrypts all child
  TLS. Key handling, child-scoped trust, and "the workload can see the CA" are real concerns.
- **Effort:** larger and security-sensitive.

## Comparison

| Axis | OTLP receiver | MITM proxy |
|---|---|---|
| Effort to first value | Low | High |
| Shipped-binary footprint | Moderate (`prost`/`tonic`) | Heavy (TLS stack + `rcgen`) |
| Security surface | Minimal (no decryption) | Significant (CA key, decrypts all TLS) |
| Harness coverage | OTEL-emitting only (cooperative) | Any non-pinned HTTP client |
| Data shape | Pre-structured `gen_ai.*` spans | Raw bodies; needs per-provider parsing |
| HTTP/2 complexity | N/A | Required (LLM APIs use h2) |
| Matches the core thesis | Partially | Fully |

## What both demand of the `Source` trait

Today `Source` is pull-shaped and config-free:

```rust
pub trait Source: Send + Sync {
    fn name(&self) -> &'static str;
    fn signals(&self) -> RawSignalStream;
}
```

Both candidates are **network servers** (push-driven), so building either will — as
`INTERFACES.md` already anticipates under "Expected growth" — force `Source` to grow:

- **construction-time config** (bind address / proxy port; for the proxy, CA material);
- **lifecycle / cancellation** — start listening, then shut down cleanly when the child exits
  (the current `signals(&self)` has no shutdown handle);
- **backpressure** — already provided by the bounded channel behind `RawSignalStream`.

The proxy additionally pressures the **`RawSignal`** contract: bodies can be large, but
`RawSignal { body: Bytes }` is inline-only. The proxy needs an out-of-line escape hatch (offload to
`RawStore` by hash, carry a payload ref) before emitting — a real schema pressure the OTLP path does
not create.

This is the "second implementor reveals the real API" point from the review: whichever we build
first will reshape `Source`. Building the **simpler** server (OTLP) first lets that lifecycle/config
reshape happen under lower complexity, before the proxy's TLS + large-body concerns pile on.

## Recommendation

**OTLP receiver first, MITM proxy second.** Rationale:

1. Fastest path to dogfood value: structured LLM telemetry for OTEL-emitting harnesses with no
   crypto, no CA lifecycle, no h2-over-TLS.
2. Smallest security surface to ship first.
3. It de-risks the `Source` trait redesign (lifecycle + config) under a simple server before the
   proxy adds TLS and large-body offload.
4. The proxy is the broader-coverage tier — it captures any client that honors proxy env + the
   injected CA (not just OTEL-emitting ones), built second on a `Source` API that has already settled,
   with the per-provider `llm.*` semantic enrichers it needs anyway. Note it is still **cooperative**
   (env injection), not cooperation-free; client-agnostic capture (pinned/mTLS clients) is the
   sandbox-only eBPF tier — see
   [`decisions/0001-cooperative-capture-vs-ebpf.md`](./decisions/0001-cooperative-capture-vs-ebpf.md).

Counter-argument worth weighing: if the harnesses we actually want to dogfood **don't** emit OTEL,
OTLP-first captures nothing useful and the proxy is the only path to value — in which case build the
proxy first and accept the larger lift. **This hinges on a fact we should check: does our intended
first dogfooding harness emit OpenTelemetry?**

## Dependency selection — OTLP receiver (verified 2026-06)

Versions were web-checked against crates.io for the newest viable releases, not pinned to whatever
was already in cache. Recorded so the next person can re-evaluate, and so the proxy follows
the same discipline.

| Crate | Version | Why |
|---|---|---|
| `opentelemetry-proto` | `0.32` | Latest (2026-05-08; prior was 0.31, Sep 2025). The canonical OTLP protobuf message types, tracking the spec upstream. `default-features = false, features = ["gen-tonic-messages", "trace"]`: `gen-tonic-messages` gives prost-decodable structs without tonic transport, and `trace` is required for the trace message module. See the footprint note below — `trace` also pulls the `opentelemetry` SDK, which we don't use but which LTO strips. |
| `prost` | `0.14` | Latest (0.14.4, 2026-06-13). **Pinned to match** opentelemetry-proto 0.32's `prost ^0.14` requirement so the `prost::Message` trait is the same crate; a mismatch would make `.decode()` not resolve. |
| `hyper` | `1` (`server`, `http1`) | The leanest production HTTP server; `tonic` itself is built on it. |
| `hyper-util` / `http-body-util` | `0.1` | The current companion crates for hyper 1.x connection serving and body collection. |

**Transport — `http/protobuf` over hyper, not gRPC over tonic.** OTLP defines three transports
(`grpc` on `:4317`, `http/protobuf` and `http/json` on `:4318`). gRPC is the SDK default and is the
most ecosystem-native (opentelemetry-proto's `gen-tonic` even generates the service trait), but
`tonic` pulls `h2` + `tower` into the **shipped** binary, and the wrapper's footprint multiplies
across every sandbox (DESIGN.md's core mandate). Because the wrapper *controls the child
environment*, it injects `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` and forces the SDK onto the
lean HTTP path — keeping the ecosystem-compat win without the gRPC dependency weight. A gRPC
receiver can be added later behind the same `Source` seam if a harness can't be steered off gRPC.

**Server — raw `hyper`, not `axum`.** `axum` is cleaner for multi-route apps but adds `tower` +
routing for what is one internal endpoint (`POST /v1/traces`, later `/v1/logs`, `/v1/metrics`).
Footprint wins for a handful of routes.

**Footprint note — the unused SDK that LTO removes.** `opentelemetry-proto` 0.32 gates the trace
*message* module behind the same `trace` feature that adds proto↔SDK conversions, so enabling it
drags `opentelemetry` + `opentelemetry_sdk` into the dependency graph even though a receiver only
decodes protobuf and never touches the SDK. That looked wrong, so it was measured rather than
assumed: the release binary (profile `release`: `lto = "fat"`, `strip = true`, `codegen-units = 1`)
is **~1.4 MB** — dead-code elimination removes the unreachable SDK, so the graph size does not become
binary size. If a future binary-size budget regresses on this, the lean alternative is to own the
OTLP `.proto` files and generate just the messages with `prost-build` + `protox` (pure-Rust, no
`protoc`), dropping the SDK from the graph entirely. Deferred under record-don't-gate: the canonical,
spec-tracking crate is worth more than shaving an already-stripped dependency.

## Dependency selection — MITM proxy (verified 2026-06)

| Crate | Version | Why |
|---|---|---|
| `hudsucker` | `0.24` | Latest (0.24.1, 2026-05-04). The maintained Rust MITM proxy (Rust 2024 edition); gives the `HttpHandler` capture seam, `RcgenAuthority` (rcgen CA + `moka` leaf-cert cache — exactly DESIGN.md's "ECDSA CA + cached leaf certs"), and CONNECT/TLS/HTTP-2 handling we'd otherwise hand-roll. Alternatives `third-wheel` and `http-mitm-proxy` are less active. Enable `http2` (LLM APIs need it); `rustls-client` + `rcgen-ca` are default. |
| `rcgen` (via `hudsucker::rcgen`) | `0.14` | hudsucker **re-exports** `rcgen`, so we use `hudsucker::rcgen` instead of a direct dep — guarantees the `KeyPair`/`Issuer` types we generate match what `RcgenAuthority::new` accepts (no version-skew risk). Used to mint an ephemeral **ECDSA P-256** CA per run. |
| `rustls` (via `hudsucker::rustls`) crypto provider | `aws-lc-rs` | rustls 0.23 requires an explicit `CryptoProvider`. I wanted `ring` (no C toolchain), but hudsucker pulls `hyper-rustls` with rustls's default `aws-lc-rs` and exposes no feature to swap it — forcing ring-only would mean forking hudsucker's feature graph. So we align on `aws-lc-rs` (the rustls-recommended default; needs `cmake` + a C compiler at build, which standard CI has). hudsucker also re-exports rustls and takes the provider explicitly, so we use `hudsucker::rustls::crypto::aws_lc_rs::default_provider()` and need no direct rustls dep or process-wide provider install. If the build matrix ever can't host the C toolchain, revisit (own the proxy on raw rustls+ring, or a hudsucker fork). |

The proxy's TLS stack (hudsucker + rustls + aws-lc-rs + moka) takes the release binary from ~1.4 MB
to **~5.8 MB** — still well under the `< 20 MB` wrapper budget (`TESTING.md`).

## Decision

**2026-06-14 — build both, OTLP receiver first, then the MITM proxy.** We want both surfaces; OTLP
leads because it is the faster, lower-risk path to structured LLM telemetry and lets the `Source`
trait's lifecycle/config shape settle under a simpler (no-TLS) load before the proxy adds cert
handling and large-body offload. The proxy follows for universal, cooperation-free coverage.

**Status — proxy shipped (`--proxy`).** `hiloop_interceptor::proxy` runs a hudsucker MITM proxy with
a per-run ECDSA CA, injects `HTTPS_PROXY` + a child-scoped CA bundle, and captures decrypted
request/response traffic as `net` (or `llm` for known hosts). Verified end-to-end by a hermetic MITM
e2e (curl tunnels HTTPS through the proxy, the decrypted request is captured before the upstream
attempt) and a plain-HTTP e2e against a chunked upstream (request/response correlation + streaming
capture + blob offload).

**Streaming passthrough + content-addressed offload (shipped).** *Response* bodies are forwarded as a
streaming tee: each frame is passed downstream the instant it arrives (SSE/chunked responses are not
blocked on buffering) while the *captured copy* is accumulated separately, bounded by the capture cap
(8 MiB by default, `--max-capture-bytes` to override, `0` for unlimited — the finite default bounds
interceptor memory so a large body can't OOM the wrapper). When the stream ends the captured copy is redacted once (so a secret split
across frames is still caught — see redaction below) and offloaded to the content-addressed blob
store (`crate::blob`, blake3-keyed, `--blob-dir`), and the event carries only a `payload_ref` (empty
inline `body`). On client disconnect a `Drop` finalizes the partial blob on a detached task and emits
a `http.capture.truncated` signal. *Request* bodies are buffered eagerly (the small side of an
exchange; buffering guarantees a request signal even when the upstream fails before draining the body)
then redacted and offloaded too, with an inline-body fallback if the blob write fails. Capturing the
response copy in a buffer (rather than streaming it frame-by-frame into the blob) is the deliberate
cost of correct cross-frame redaction; the cap bounds the buffer, and forwarding to the origin still
streams a frame at a time.

**Capture-side redaction (shipped, on by default).** Before a captured request/response body is
persisted (events or blob store), credential patterns — bearer tokens, `sk-…` / `hil_…` keys, AWS
access-key ids — are replaced with `[REDACTED]` (`crate::redact`). Redaction rewrites only the
captured copy, never the bytes forwarded to the origin, and is best-effort (only known patterns;
bytes beyond the capture cap are never captured or scanned). Disable per run with `--no-redact`.

**Request/response correlation (shipped).** Each non-`CONNECT` exchange gets a minted ULID
`http.exchange_id` stamped on both its request and response events. (It was originally a
process-local counter; that restarted at zero in every wrapper invocation, so sibling invocations
emitting into one run collided on the same id — a ULID is globally unique across invocations.)
hudsucker clones the handler per request (`serve_stream` → `self.clone().proxy(req)`) and that one
clone drives both `handle_request` and `handle_response`, so the id minted on the request is read
back from per-instance state on the matching response — robust even under HTTP/2 multiplexing, since
each multiplexed request still gets its own clone and `proxy()` future. Limit: when the upstream
errors before a response, hudsucker calls `handle_error` (not `handle_response`), so a request event
is recorded with no paired response — absent rather than mis-correlated.

**Remaining gaps (tracked in TESTING.md):** both request and response captured copies are buffered
whole (within the capture cap) before offload; on a blob-write failure either degrades to metadata
only (no inline fallback). The capture cap bounds memory by default (8 MiB); setting it to `0` opts
into unlimited capture, where a very large body buffers its captured copy in full.

**Blob upload to the telemetry gateway (shipped).** `DirBlobStore` writes blobs to a local
directory (blake3-keyed) and the `Event` carries only the `payload_ref` digest. With a gRPC export
configured, a run-end drain ships those blobs to the gateway's blob service over the same endpoint
and Bearer auth as the event export (`src/blob_upload.rs`, behind the `BlobUploader` seam in
`src/blob.rs`): a digest-first `HasBlobs` probe asks which digests the gateway is missing, and only
those are uploaded as chunked client-streams (1 MiB frames, ≤ 64 MiB per blob) — the gateway
re-hashes before storing, so a corrupt or mislabeled upload is rejected, and re-running against
already-present content sends nothing. Without a gRPC export (`--events-jsonl` only) blobs stay
local in `--blob-dir` (`NoopUploader`, the standalone/air-gapped default); with a gRPC export and
no `--blob-dir`, bodies stage in a per-run scratch store that is removed once every blob has
shipped — an incomplete drain (upload failure, over-cap blob) keeps the store and names its path
in the warning, so captured bodies are never silently destroyed. The drain is best-effort like
the rest of telemetry: a failure is a stderr warning, never the child's exit code. Capture size is bounded by `--max-capture-bytes` (default 8 MiB, `0` for unlimited):
bodies over the cap are captured up to it, marked `http.capture.truncated`, and still forwarded in
full to the client.

**Status — OTLP shipped (`--otlp`).** `hiloop_interceptor::otlp` runs an embedded OTLP/HTTP receiver
bound to an ephemeral localhost port; the supervisor injects the endpoint, registers
`OtlpTraceNormalizer` alongside the stdio normalizer, and shuts the receiver down on child exit so
the pipeline drains. As predicted, the receiver does **not** yet flow through the `Source` trait — it
feeds the supervisor's signal channel directly, the same shortcut stdio capture takes. Now that two
real producers exist, the next `Source` refactor should give the trait construction-time config and
a shutdown handle (and `RawSignal` a large-body escape hatch before the proxy lands).
