# hiloop-interceptor

> ⚠️ Pre-alpha scaffold. APIs, layout, and behavior will change. Not yet usable.

The **interception wrapper** for agent harnesses. It runs anywhere — your laptop or
inside a sandbox — wraps your harness command, and captures its telemetry (OpenTelemetry,
logs, network calls) **tagged with fork-tree identity**, so observability branches with
your experiments.

It is the open-source edge of hiloop: snapshottable, forkable agent sandboxes with tree-native
observability. The interceptor is the part that runs on *your* machine, so it's open source
(MIT OR Apache-2.0); the sandbox/snapshot/control-plane infrastructure lives in a separate,
private monorepo.

## Status

Phase 0 — scaffolding. See [`HANDOFF.md`](./HANDOFF.md) for the plan, the design context,
and the remaining structural questions.

## Quick start (scaffold)

```sh
cargo run -p hiloop-interceptor -- run -- echo hello
```

Today this resolves a fork-tree context, injects the spine into the child environment
(`HILOOP_*`, `OTEL_RESOURCE_ATTRIBUTES`), and passes the command through.

To capture stdout/stderr into normalized JSONL events while still teeing child output:

```sh
cargo run -p hiloop-interceptor -- run --events-jsonl ./events.jsonl -- sh -c 'printf "hello\n"'
```

Add `--raw-jsonl ./raw.jsonl` with `--events-jsonl` to preserve captured raw observations and stamp
`raw.observation_id` on the normalized events that came from them.

The current integration test wraps a real command and asserts child output is teed while
fork-stamped stdio events are flushed to JSONL. That proves the supervisor, env stamping, local
normalization, and exporter seam wiring. It does not yet prove OTLP ingest, HTTPS proxy capture,
ClickHouse export, or harness-aware semantic normalization; those are still planned behind the
existing seams.

## Workspace

This repo follows the same basic shape as modern Rust CLI workspaces: root-owned package
metadata, dependency versions, lints, profiles, and toolchain pinning; crates under
`crates/`; a thin binary crate over testable library modules.

- `hiloop-core`: stable shared contracts for fork identity and telemetry events.
- `hiloop-interceptor`: CLI, supervisor scaffolding, and wrapper-local seam traits.

Rust is pinned to stable `1.96.0`; the crate edition and rustfmt style edition are both
`2024`.

Rust code style and testing conventions are documented in
[`docs/RUST_STYLE.md`](./docs/RUST_STYLE.md).
Performance benchmarking plans are tracked in [`docs/BENCHMARKING.md`](./docs/BENCHMARKING.md).

## Verification and security

Local verification mirrors CI:

```sh
cargo fmt --all --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo test --workspace --all-targets --all-features --locked
cargo deny check
```

`cargo deny check` is optional until `cargo-deny` is installed locally, but should be run for
dependency, license, or lockfile changes. GitHub Dependency Review runs on PRs, and GitHub CodeQL
default setup should be enabled in repository security settings.

## Install (eventually)

Planned channels (none live yet): `cargo install hiloop-interceptor`, prebuilt binaries via
GitHub Releases (cargo-dist), Homebrew tap, a `curl | sh` installer, and a container image.
See HANDOFF.

## License

Dual-licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your
option.
