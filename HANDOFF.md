# Phase 0 Hand-off — `hiloop-interceptor`

> ## Phase 0 structure direction
> This repo is now a small Rust workspace: `hiloop-core` owns the stable OSS contract
> surface, and `hiloop-interceptor` is the shippable CLI/supervisor crate. That follows the
> modern Rust CLI pattern used by projects like uv/Ruff: workspace-owned metadata,
> dependency versions, lints, profiles, and toolchain pinning; thin binaries over testable
> library modules. Still open: exactly how the private `hiloop` monorepo consumes this
> contract crate and how Bazel wraps/releases it.

## What this is

The **interception wrapper** (DESIGN.md §2) — the open-source edge of the system. It runs
anywhere (laptop or in-sandbox), wraps an agent-harness command as a **supervisor / PID 1**,
and captures telemetry (OTEL, logs, network) **stamped with fork-tree identity**.

It's the V1 *vertical walking skeleton's* front half: in Phase 1, wrapper + a cheap fork +
a telemetry backend make **branch-diff work end-to-end on day one** (DESIGN.md §11, decision
**D11**). It's OSS (MIT/Apache-2.0) because it runs on users' machines and is the adoption
surface; everything else (sandbox runtime, snapshot store, control plane, ClickHouse, operator,
Helm) lives in the **private `hiloop` monorepo** (sibling dir; see its handoff).

**Read the design first:** `../agent-harness-infra/design/DESIGN.md` — especially **§2**
(wrapper), **§4** (fork identity & causality — the spine), **§6** (telemetry), **§11**
(sequencing/testing), **Appendix A** (decision log), **Appendix D** (risk register; `[Rn]`
tags below reference it).

## Phase 0 goal (contracts first)

Nail the **contracts + the spine + mocks**, so P1 can be built/tested against them:

1. **Fork-identity spine** (`hiloop-core::identity`) — the #1 artifact (**D12 / R3**). The
   core contract now exists; remaining work is integration with the control plane/state store:
   - node-local `fork_node_id` allocation (ULID) — keep it off the control-plane path;
   - **parent-owned, gap-free `fork_path` ordinal allocation** under concurrent fork (atomic;
     `ChildOrdinalAllocator` exists; wire it into the node-agent/control-plane flow);
   - a real **HLC** clock (`HlcClock` exists; wire remote observe points into ingest/control);
   - the **write-ordering contract** (node row committed before referencing telemetry, or
     event-sourced lazy creation);
   - a **conformance/`proptest` suite** asserting the invariant: every event's `fork_node_id`
     resolves to one node; every node has a unique `fork_path`; sibling ordinals gap-free.
   - **Decision:** `ForkPath` stores typed `ForkOrdinal` values internally. Root is an explicit
     empty ordinal sequence and serializes as `""`; non-root paths serialize as canonical
     slash-delimited ordinals like `/0/3`. Max depth is 128.
2. **Event schema** (`hiloop-core::event`) — align with OTEL conventions where they exist;
   decide the internal mapping for non-OTEL signals (proxy/eBPF/exec) (risk **R-m8**).
   **Decision:** `hiloop_core::event::Event` is the canonical logical event schema, not a
   physical ClickHouse/Parquet/OTLP table shape. Storage/live/query connectors should convert
   to efficient backend-specific formats and either round-trip through the logical schema or
   explicitly document lossy projections. Event names, attribute keys, payload digests, and media
   types are narrow non-blank text types. Attribute values use a deliberately narrow scalar enum
   (`String`, `I64`, finite `F64`, `Bool`) rather than stringly-typed or arbitrary JSON values.
3. **Wrapper seam traits** (`hiloop_interceptor::seams`) — `Source` / `Normalizer` / `Exporter`.
   These live with the wrapper because they are not currently a cross-repo contract. Keep
   private-only system seams in the private monorepo near their implementations. Promote a trait
   into `hiloop-core` only when both repos compile against it, it defines persisted/wire
   compatibility, it is a public extension API, or its conformance suite must be shared across
   public/private implementations. **Decision:** `RawSignal` is intentionally stringly typed
   because it represents heterogeneous pre-normalization ingress. The normalized `Event` boundary
   remains narrow. Revisit `RawSignal::source`, `RawSignal::kind`, and raw attributes once source
   categories stabilize.
4. **CI / tooling** — fmt + clippy + test wired (`.github/workflows/ci.yml`); add a
   **record-don't-gate** bench job (criterion + iai-callgrind → Bencher Self-Hosted) (**R18**).

## Phase 1 scope (what the binary becomes)

Tier-1 interception (DESIGN.md §2), single-node, no k8s:
- **env injection** into the child: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_RESOURCE_ATTRIBUTES`
  (stamps the spine onto all OTEL signals), `HTTPS_PROXY`, **child-scoped** CA bundle vars.
- **MITM proxy** (`rustls`-based) with **ECDSA + cached leaf certs** (avoid the RSA-keygen
  cliff); reads HTTPS bodies, offloads large payloads to the blob store by hash.
- **OTLP receiver** (the wrapper *is* the local collector endpoint) + **stdio capture**.
- **Normalizer → Exporter** to the telemetry backend (ClickHouse in V1 — **D7/R12**).
- a **cheap fork primitive** (process clone / full-copy restore) lives in `hiloop` for the
  vertical skeleton; the interceptor just needs to be handed its fork context.

Deferred behind seams: **eBPF Tier-2** (priority TBD post-V1 — **Appendix B**); transparent
in-sandbox redirect; egress policy + **credential brokering** (recommended — **R9**).

## What's scaffolded now

```
hiloop-interceptor/
  Cargo.toml                      # workspace
  rust-toolchain.toml, rustfmt.toml, .gitignore
  LICENSE-MIT, LICENSE-APACHE
  README.md, CONTRIBUTING.md, HANDOFF.md
  .github/workflows/ci.yml        # fmt/clippy/test (bench job TODO)
  crates/
    hiloop-core/                  # shared identity (spine) · event schema
    hiloop-interceptor/           # CLI supervisor · wrapper-local seams
```
`cargo run -p hiloop-interceptor -- run -- echo hi` works (mints a local fork context, injects
`HILOOP_*`/`OTEL_RESOURCE_ATTRIBUTES`, execs).

## Decisions that constrain implementation (don't re-litigate without cause)

- **Rust** (footprint × every sandbox + eBPF) — **W1/D10-adjacent**.
- **Build the fork engine ourselves** (Firecracker+UFFD) — **R7**; adopt-behind-seam is a fallback.
- **ClickHouse for V1** telemetry store; DataFusion+Parquet = open cold tier behind the seam — **R12/D7**.
- **Keep clear seams**; **record-don't-gate** perf — **R17/R18**.
- Two-namespace encryption + KMS, egress/credential broker: **flagged, design at impl** — **R8/R9/R10**.
- Multi-tenancy isolation: **explicitly OPEN**, do not lock node-pool-per-tenant — **R11**.

## Remaining structural questions to GRILL

- **Decision:** `hiloop-core` is the OSS data/contract crate consumed by both this repo and
  private `hiloop`. It owns identity and event schema. It does **not** own wrapper-only or
  private-only implementation traits unless they become true cross-boundary/public contracts.
- **Decision:** private `hiloop` pins one exact `hiloop-interceptor` git commit. From that same
  commit it consumes `crates/hiloop-core` as the contract dependency and builds the
  `hiloop-interceptor` binary artifact for genesis/runtime images. Record the commit SHA in
  image/build provenance. Later, once the contract is stable, switch `hiloop-core` to a published
  semver crate and relax exact commit matching to an explicit compatibility range.
- **Decision:** private `hiloop` is Bazel-first. Use Bazel 9.x LTS with Bzlmod (`MODULE.bazel`,
  no legacy `WORKSPACE`) and `rules_rust` for Rust. CI/release/image builds should go through
  Bazel for hermeticity. This OSS repo can remain Cargo-native initially, with Cargo supported
  for local Rust dev loops; add Bazel wrappers only when the private monorepo needs to build or
  package the interceptor/core from the pinned commit.
- MSRV/toolchain policy after public release; currently pinned to stable Rust 1.96.0 with
  edition/style edition 2024. `unsafe_code` warns by default; eBPF modules will need explicit
  local policy when introduced.
- Install channels to support (cargo / cargo-dist releases / Homebrew / `curl|sh` / container).

## Out of scope for now
GPU anything, k8s/operator/Helm, the snapshot store/CAS internals, the control plane — all
in `hiloop`. eBPF, transparent redirect, egress policy — deferred behind seams.
