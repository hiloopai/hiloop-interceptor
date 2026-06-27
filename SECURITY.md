# Security Policy

`hiloop-interceptor` wraps agent harnesses and, when `--proxy` is enabled, decrypts the wrapped
child's HTTPS traffic with an ephemeral, child-scoped CA. We take its security posture seriously and
appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through either channel:

- **GitHub** — use [Report a vulnerability](https://github.com/hiloopai/hiloop-interceptor/security/advisories/new)
  (Security → Advisories) to open a private advisory.
- **Email** — <security@hiloop.ai>.

Please include a description of the issue, the affected version or commit, and a minimal
reproduction if you have one. We aim to acknowledge reports within 3 business days and to keep you
updated as we investigate and ship a fix. We'll credit reporters who want it once a fix is released.

## Scope

This repository covers the laptop-/sandbox-side interceptor only. The hosted sandbox, snapshot
store, and control plane live in a separate, private system and are out of scope here.

## Supported versions

This project is in early alpha and has no stable release line yet. Security fixes land on `main`;
please track the latest commit until tagged releases begin.
