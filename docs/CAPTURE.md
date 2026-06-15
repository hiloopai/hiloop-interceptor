# Capture Surfaces — Design & Decision (WS-B)

**Status:** decision doc, nothing implemented yet. This compares the two candidate first
network-capture surfaces so we can pick one deliberately. It refines, and defers to,
`../agent-harness-infra/design/DESIGN.md` §2 (interception wrapper) and the seam contracts in
[`INTERFACES.md`](INTERFACES.md).

## Why this decision matters

Today the only real capture surface is stdout/stderr line capture. That proves the
spine/pipeline/exporter plumbing but not the product thesis: an agent harness's *interesting*
behavior — LLM calls, tool calls — happens over HTTPS, not on stdout. WS-B adds the first surface
that captures that. Two candidates, very different cost/risk/coverage profiles. Both are **Tier-1
cooperative** mechanisms (env injection); the sandbox-only transparent-redirect and eBPF tiers
(DESIGN.md §2) stay deferred behind the same `Source` seam.

The wrapper already injects `OTEL_RESOURCE_ATTRIBUTES` (the spine) into the child, so either
surface inherits fork-stamping for free.

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
4. The proxy remains the eventual differentiator for universal, cooperation-free coverage — built
   second, on a `Source` API that has already settled, and with the per-provider `llm.*` semantic
   enrichers the proxy needs anyway.

Counter-argument worth weighing: if the harnesses we actually want to dogfood **don't** emit OTEL,
OTLP-first captures nothing useful and the proxy is the only path to value — in which case build the
proxy first and accept the larger lift. **This hinges on a fact we should check: does our intended
first dogfooding harness emit OpenTelemetry?**

## Decision

_TBD — fill in once chosen, with the date and the rationale, and link the implementing commits._
