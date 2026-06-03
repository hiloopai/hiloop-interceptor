## Review Checklist

- [ ] Behavioral correctness: error propagation, shutdown, backpressure, and data-loss risks.
- [ ] Rust style: comments/rustdoc, narrow types, visibility, and API shape.
- [ ] Tests: unit/integration/contract coverage matches the behavior changed.
- [ ] Tooling: CI, generated docs, dependency metadata, and lockfile changes are intentional.

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo check --workspace --all-targets --all-features --locked`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked`
- [ ] `cargo test --workspace --all-targets --all-features --locked`
- [ ] `cargo deny check` if dependencies, licenses, or `Cargo.lock` changed
