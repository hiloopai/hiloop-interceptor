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
- Use `Option<T>` for true absence. Do not encode missing values as empty strings, zero, empty
  collections, or arbitrary JSON. Boundary sentinel encodings are allowed only when documented by
  the contract, such as root `ForkPath` serializing as `""`.
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

Do not use rustdoc to narrate every obvious field. Rustdoc should answer "what contract does this
API expose?" or "why would I use this?", not "this field stores the value named by the field."

Use normal comments sparingly. Good comments usually explain one of:

- an invariant the type system does not express;
- a non-obvious ordering or concurrency constraint;
- an interoperability quirk;
- a security or data-loss caveat;
- why a simpler-looking approach is wrong.

Prefer rustdoc links like [`ForkPath`] or [`Event`] when referencing local API items.

## Public Contracts

`hiloop-core` is the shared contract crate. Keep it dependency-light and stable:

- fork identity types;
- telemetry event data types;
- parsing/validation helpers for those data types.

Do not put implementation seams in `hiloop-core` unless at least one of these is true:

- both OSS and private repos compile against the trait;
- the type defines persisted or wire compatibility;
- it is a public extension API;
- its conformance suite must be shared across public and private implementations.

Wrapper-only traits live in `hiloop-interceptor`. Private-only traits live in the private monorepo
near the component that owns them.

Raw ingress types may be looser than normalized contracts. For example,
`hiloop_interceptor::seams::RawSignal` keeps source/kind/attribute data as strings because it
represents heterogeneous pre-normalization input. This is an explicit exception to the narrow-type
rule, not a precedent for normalized schemas. Revisit those fields once the source and kind
taxonomy is stable.

## Error Handling

- Libraries return typed errors with `thiserror` when callers may match on the failure.
- Binaries can use `anyhow` at the outer CLI boundary.
- Keep error messages actionable and user-facing at the CLI layer.
- Use `Result<T, E>` for recoverable failures. Reserve process exit for the binary edge.

## Testing

Every behavior change needs a test. Choose the narrowest test that proves the contract:

- unit tests for pure logic and small invariants;
- property tests for identity/path/ordering invariants;
- seam conformance tests once a trait has multiple implementations;
- integration tests for process behavior, filesystem behavior, and real dependencies;
- snapshot tests only when textual output is the API.

Prefer tests that exercise public behavior over tests that lock down private implementation detail.
When adding tests, first look for an existing nearby test module/file.

## Generated Documentation

Reference docs should come from code when the code is the source of truth:

- Rust API docs: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`.
- CLI help: generated from `clap` doc comments and attributes.
- Future config/API reference: generate from typed schema/protobuf/config structs rather than
  manually duplicating options in Markdown.

When a change updates CLI args, config schema, protobuf contracts, or public rustdoc examples,
the generated docs must be regenerated in the same change once the generator exists.

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
