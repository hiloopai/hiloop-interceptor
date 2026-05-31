# Contributing

Pre-alpha; external contributions aren't being solicited yet. Internal workflow:

- Follow [`docs/RUST_STYLE.md`](./docs/RUST_STYLE.md) for Rust code style, docs, and test shape.
- `cargo fmt --all --check` must pass.
- `cargo check --workspace --all-targets --all-features` must pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` must pass.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps` must pass for
  public API docs.
- `cargo test --workspace --all-features` must pass.
- Each wrapper seam (`Source`, `Normalizer`, `Exporter`, …) ships with a **conformance suite**
  run against every implementation incl. a mock. See [`HANDOFF.md`](./HANDOFF.md) for sequencing.
- Performance: we **record, not gate** (criterion + iai-callgrind → Bencher) until SLOs
  come from real workloads.

Unless you state otherwise, contributions are dual-licensed under MIT OR Apache-2.0.
