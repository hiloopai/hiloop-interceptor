# AGENTS.md — hiloop-interceptor

> **This file is the single source of truth for agent instructions.**
> `CLAUDE.md` is a symlink pointing here. Edit this file, not the symlink.
> For new repos, always create `AGENTS.md` first and symlink `CLAUDE.md → AGENTS.md`.

Open-source interception wrapper for agent harnesses. Rust-only workspace.
See `README.md` for project context; `docs/RUST_STYLE.md` for full Rust conventions.

## Code Philosophy

Before writing code, walk the ladder:

1. Does this need to exist? No → skip it (YAGNI).
2. Stdlib/language built-in does it? → use it.
3. Already-installed dependency does it? → use it.
4. One line solves it? → one line.
5. Only then: write the minimum that works.

- **DRY.** Check the codebase (and the web) before writing new code.
- **Boy Scout Rule.** Leave code cleaner than you found it.
- **Small files.** Refactor when a file grows beyond a single clear responsibility.
- **Interfaces close to implementation.** Traits live near the primary implementor.
- **Deep research for new deps.** Use the latest stable. Investigate trade-offs first.
- **Challenge assumptions.** State them explicitly before implementing. Surface tradeoffs.
- **Surgical changes.** Touch only what you must. Don't "improve" unrelated code.

## Testing

**Always prefer TDD.** Think about what the code should do, express it as a test, then
write the implementation.

- **Debugging = TDD.** Reproduce the bug with a failing test first, then fix it.
- **Avoid mocking.** Use real implementations or lightweight fakes.
- **Parametrize.** Use `proptest` for identity/path/ordering invariants.
- **Inline snapshots.** Use `insta` to keep assertions readable.
- **Network recordings (VCR/replay).** Record real interactions, replay for speed.
- See `docs/TESTING.md` for the full behavior contract and test ladder.

## Observability

- **Prefer spans + derived metrics over direct metrics.** Structured tracing with spans;
  derive metrics from spans rather than emitting standalone counters/gauges.
- **Single init function.** One shared observability setup at the entrypoint.

## Comments

- Prefer self-documenting code. Good names > comments.
- Rustdoc (`///`) on public APIs — answer "what contract?" not "what is the field name?".
- **Never** comment what you changed or why you changed it. That's for the commit/PR.
- Diff-explaining comments are unacceptable. Remove them immediately during review;
  never leave them for later cleanup.
- Inline comments are for unintuitive behaviour, gotchas, and TODOs — nothing else.
- See `docs/RUST_STYLE.md` § Comments And Rustdoc for full guidance.

## Commits & PRs

- **Conventional Commits:** `type(scope): summary`.
- Pre-commit hooks run automatically on changed files — they are the source of truth
  for lint/format checks.
- CI actions are pinned to full commit SHAs and updated by Dependabot (tag in comment).
- CI bootstrap tools should be Dependabot-managed where possible; otherwise pin exact
  versions and justify the exception in the PR.
