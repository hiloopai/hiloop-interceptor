# Contributing

Pre-alpha; external contributions aren't being solicited yet. Internal workflow:

- Follow [`docs/RUST_STYLE.md`](./docs/RUST_STYLE.md) for Rust code style, docs, and test shape.
- `cargo fmt --all --check` must pass.
- `cargo check --workspace --all-targets --all-features --locked` must pass.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` must pass.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked` must pass for
  public API docs.
- `cargo test --workspace --all-targets --all-features --locked` must pass.
- `cargo test --workspace --doc --all-features --locked` must pass.
- `cargo test -p hiloop-interceptor --test interceptor_e2e --all-features --locked` runs the
  compiled-binary mock-harness scenarios directly.
- If `cargo-deny` is installed, `cargo deny check` must pass before dependency changes merge.
- Each wrapper seam (`Source`, `Normalizer`, `Exporter`, …) ships with a **conformance suite**
  run against every implementation incl. a mock. See [`HANDOFF.md`](./HANDOFF.md) for sequencing.
- Performance: we **record, not gate** (criterion + iai-callgrind → Bencher) until SLOs
  come from real workloads.
- Follow [`docs/TESTING.md`](./docs/TESTING.md) for the behavior contract, test ladder, and rules
  for promoting directional performance budgets into gates.

## Security and dependency review

- CI actions are pinned to full commit SHAs with the intended upstream tag left in a comment.
- PRs run GitHub Dependency Review for Cargo and GitHub Actions changes. It fails on new runtime or
  development-scope vulnerabilities at `moderate` severity or higher.
- `deny.toml` is the local Rust dependency policy for advisories, duplicate crate versions, licenses,
  and dependency sources.
- Enable CodeQL default setup in the GitHub repository security settings for Rust scanning. Keep a
  committed CodeQL workflow only if the default setup is not enough for this repo.

Unless you state otherwise, contributions are dual-licensed under MIT OR Apache-2.0.
