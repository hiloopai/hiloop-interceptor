# Code Review Standards

This document defines the review bar for hiloop-interceptor. Every PR — human or agent —
must meet these standards before merge. Reviewers: enforce them consistently.

## Review Principle

> A PR must *improve overall code health*. Approve when it clearly does, even if
> imperfect. Block when it degrades correctness, safety, clarity, or maintainability.
> — adapted from Google eng-practices

## Review Passes

Run three focused passes on every PR:

1. **Correctness & safety.** Error propagation, shutdown/flush ordering, data-loss risks,
   `unsafe` justification, panic-freedom in library code, backpressure under load.
2. **Design & style.** Narrow types, minimal visibility (`pub(crate)` before `pub`),
   traits only at real boundaries, naming, rustdoc on public API, comment quality
   (see `docs/RUST_STYLE.md`).
3. **Tests & CI.** New behavior has a test. Test level matches the contract (unit → property
   → conformance → integration → e2e, per `docs/TESTING.md`). CI is green. No new
   warnings suppressed without `#[expect]` + reason.

## What To Look For

### Always block on
- Logic bugs, off-by-one, race conditions, unsound `unsafe`.
- Missing or inadequate error handling (swallowed errors, `.unwrap()` in lib code).
- Comments that explain the diff instead of the system; remove them before merge.
- Security: secrets in code, path traversal, injection, unbounded allocations.
- Breaking public API changes without a migration path.
- Tests deleted or weakened without justification.
- `#[allow]` without `#[expect]` + reason string.
- Unpinned CI actions or CI bootstrap tools that bypass Dependabot-managed manifests.
- Magic strings/numbers — use constants, enums, or newtypes.
- New dependencies without trade-off analysis in the PR description.

### Always flag (may not block)
- Complexity: if you can't understand it in one read, it's too complex.
- Naming: does every symbol communicate its purpose?
- Missing docs on public API items.
- Test gaps: what scenarios are untested?
- Performance: unnecessary allocations, clones, or `.collect()` when an iterator suffices.
- Nits: prefix with `nit:` so the author knows it's non-blocking.

## PR Authoring Standards

- **< 200 lines changed** (soft target). Smaller PRs get better reviews.
- **Description answers:** what changed, why, how to test, risks/tradeoffs.
- **Conventional Commits** for every commit: `type(scope): summary`.
- **One logical change per PR.** Refactors and features in separate PRs.
- **CI must be green** before requesting review.
- **Self-review first.** Read your own diff before pushing. Catch the easy stuff.

## Feedback Culture

- Be direct. Cite the rule or doc section you're enforcing.
- Prefix educational/optional comments with `nit:` or `suggestion:`.
- If you request changes, be specific about what you want — not just "this is wrong."
- Resolve conflicts by deferring to: style guide → existing precedent → reviewer judgment.
- Timely: first review within 4 hours (business hours) for PRs under 200 lines.

## Agent-Authored PR Policy

Agent PRs are held to the *same bar* as human PRs — no lower, no higher. Additionally:

- Verify the agent didn't introduce unnecessary abstractions or dependencies.
- Check for hallucinated APIs, crate names, or feature flags.
- Ensure tests are real assertions, not just "does it compile" scaffolding.
- Watch for over-engineered solutions to simple problems.

## Continuous Improvement

After every PR that required more than one review round, capture what went wrong:

- Missing context? → update `AGENTS.md`, `docs/`, or knowledge notes.
- Recurring mistake? → add a clippy lint, deny.toml rule, or CI check.
- Style disagreement? → update `docs/RUST_STYLE.md` and close the loop.
- Review took too long? → break the next PR smaller.

The goal: the same class of issue should never require human review twice.
Automate it or document it so it's caught by tooling or agents next time.
