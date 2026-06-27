# Rust Style

This repo follows the style of modern Rust CLI workspaces like uv and Ruff, with a smaller
surface area for now. Prefer consistency with nearby code over cleverness.

## Defaults

- Use Rust `2024` edition and the pinned stable toolchain in `rust-toolchain.toml`.
- Let `rustfmt` decide formatting. Do not hand-align fields or arguments.
- Keep imports at the top of the file.
- Prefer explicit, descriptive names over abbreviations.
- Prefer narrow visibility: `pub(crate)` before `pub`, and private before either.
- Prefer `#[expect(...)]` over `#[allow(...)]` when a lint suppression is deliberate.
  Keep suppressions local and include the reason when it is not obvious.
- Use `Option<T>` for true absence. Do not encode missing values as empty strings, zero, empty
  collections, or arbitrary JSON. Boundary sentinel encodings are allowed only when documented by
  the contract, such as a wire format that reserves a specific root identifier.
- Public configuration should not expose invalid states. Prefer private fields plus constructors
  and getters when validation is needed; public fields are best reserved for passive wire/data
  structs.
- Avoid `panic!`, `unreachable!`, `unwrap`, and `expect` in production code. Encode invariants in
  types or return errors. Tests may use `expect` when it clarifies setup.
- Avoid `unsafe`. When it becomes necessary, require a `SAFETY:` comment that explains the
  invariant the caller/implementation must uphold.

## Comments And Rustdoc

Rust has two comment channels:

- `///` and `//!` are rustdoc comments. They generate API documentation and, in CLI/config structs,
  often become user-facing reference docs.
- `//` comments are implementation notes. They should explain invariants, edge cases, or why the
  code is shaped a certain way.

Use rustdoc for:

- crate and module overviews;
- public types/functions that are true API;
- CLI args and config fields, because tools can generate reference docs from them;
- examples that are worth compiling as doctests.

Use canonical rustdoc sections where they add real information:

- `# Errors` for public fallible APIs;
- `# Panics` for intentional panics;
- `# Safety` for unsafe APIs;
- examples that use `?` instead of `unwrap` unless the unwrap is the point of the example.

Do not use rustdoc to narrate every obvious field. Rustdoc should answer "what contract does this
API expose?" or "why would I use this?", not "this field stores the value named by the field."
Do not add a comment just because an item exists. Private helpers usually need no comment unless
they encode a non-obvious invariant, ordering constraint, or interoperability rule.

Use normal comments sparingly. Good comments usually explain one of:

- an invariant the type system does not express;
- a non-obvious ordering or concurrency constraint;
- an interoperability quirk;
- a security or data-loss caveat;
- why a simpler-looking approach is wrong.

Prefer rustdoc links when referencing local API items.

## Public Contracts

Shared contract crates should stay dependency-light and stable. They are best suited for:

- persisted or wire-format data types;
- identity and schema types used by multiple crates or repositories;
- parsing and validation helpers for those contracts;
- public extension APIs with shared conformance tests.

Do not put implementation seams in a shared contract crate unless at least one of these is true:

- multiple independently owned components compile against the trait;
- the type defines persisted or wire compatibility;
- it is a public extension API;
- its conformance suite must be shared across implementations.

Implementation-local traits should live near the component that owns them. Private-only traits
should stay private until they become a real cross-component contract.

Boundary ingress types may be looser than normalized contracts when they represent heterogeneous
pre-normalization input. Treat that as an explicit exception to the narrow-type rule, not as a
precedent for normalized schemas. Revisit loose fields once the taxonomy is stable.

## Interface Boundaries

Interfaces should make the correct path the easy path. A trait should usually exist only when it
represents an external boundary, a plugin point, or a contract that needs shared conformance tests.
Avoid trait layers that only wrap one concrete implementation without clarifying ownership, failure
modes, or future extension.

Implementation-specific interface notes belong in a separate design document that can evolve with
the codebase. Keep this style guide focused on review principles that should remain stable.

### Review Checklist

Use this checklist when adding or changing a trait, persisted type, or cross-crate boundary:

- Is this a real boundary with multiple plausible implementations, or a shared wire/persisted
  contract? If not, prefer concrete functions/types.
- Does the interface live at the right layer: shared contract crate, extension-point crate, or the
  private component that owns the behavior?
- Is the contract minimal? Each method should have one clear responsibility and one owner.
- Are invalid states unrepresentable where practical? Prefer enums, newtypes, validated
  constructors, `Option<T>` for absence, and `Result<T, E>` for recoverable failure.
- Are string keys, schema names, and sentinel values centralized as constants, enums, or newtypes?
  Avoid magic strings at call sites.
- Does persisted or replayable output include stable identity and versioning for the implementation
  that produced it?
- Is support/routing behavior explicit? Implementations should report whether they can handle an
  input instead of guessing inside the main operation.
- Does shared metadata get enforced centrally by the orchestration layer when possible, rather than
  relying on each implementation to remember it?
- Are raw data retention, diagnostics, and lossy conversions explicit in the type signatures or
  documented as deferred decisions?
- Are shutdown, flush, cancellation, back-pressure, and partial failure semantics testable?
- Does every new implementation pass shared conformance tests, plus focused tests for its own
  source/protocol behavior?
- Are public fields limited to passive wire/data structs? Use private fields plus constructors and
  getters when validation or invariants matter.

## Error Handling

- Libraries return typed errors with `thiserror` when callers may match on the failure.
- Binaries can use `anyhow` at the outer CLI boundary.
- Preserve source error chains when wrapping lower-level failures across library boundaries.
- Keep error messages actionable and user-facing at the CLI layer.
- Use `Result<T, E>` for recoverable failures. Reserve process exit for the binary edge.

## Testing

Every behavior change needs a test. Choose the narrowest test that proves the contract:

- unit tests for pure logic and small invariants;
- property tests for identity/path/ordering invariants;
- seam conformance tests once a trait has multiple implementations;
- shared contract helpers for boundary implementations so new implementations inherit the same
  behavioral checks;
- async workflow tests for shutdown, backpressure, error propagation, and flush ordering;
- integration tests for process behavior, filesystem behavior, and real dependencies;
- snapshot tests only when textual output is the API.

Prefer tests that exercise public behavior over tests that lock down private implementation detail.
When adding tests, first look for an existing nearby test module/file.

## Generated Documentation

Reference docs should come from code when the code is the source of truth:

- Rust API docs:
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked`.
- CLI help: generated from `clap` doc comments and attributes.
- Future config/API reference: generate from typed schema/protobuf/config structs rather than
  manually duplicating options in Markdown.

When a change updates CLI args, config schema, protobuf contracts, or public rustdoc examples,
the generated docs must be regenerated in the same change once the generator exists.

## Review Workflow

Use focused review passes at implementation checkpoints:

- one pass for behavioral correctness, error propagation, shutdown, and data-loss risks;
- one pass for Rust style, comments/rustdoc, narrow types, and API shape;
- one pass for CI/tooling/test coverage when the change affects repo workflow.

Review comments should cite the style rule or contract they are enforcing. Do not add comments or
abstractions just to satisfy review; change the code only when it improves the contract,
correctness, or maintainability.

## Python-To-Rust Notes

- Rustdoc comments are not Python docstrings. They attach to API items and are rendered as
  reference documentation.
- Rust usually does not document every parameter/field in a separate block. Types and names carry
  more of that weight.
- Prefer small, composable types with explicit invariants over broad dynamic structs.
- Use enums for closed state machines and mode sets.
- Make types as narrow as practical. Prefer a small enum or newtype over `String`/`serde_json::Value`
  when the allowed shape is known.
- Avoid inheritance-style abstractions. Traits are most useful at real boundaries, not as a default
  way to organize code.
