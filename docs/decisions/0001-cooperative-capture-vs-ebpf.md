# 0001 — Cooperative capture now, eBPF later (in the sandbox)

Status: accepted (2026-06-26)

## Context

The interceptor's `--proxy` mode is a **cooperative** MITM: it mints an ephemeral CA, injects
`HTTPS_PROXY` + a child-scoped CA bundle (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) into the wrapped child, and decrypts the TLS the child
chooses to send through it. It never installs anything into the machine root trust store.

This captures the clients that honor proxy env and trust the injected CA — Node, Python `requests`,
`curl`, and most SDKs, which is the entire footprint of harnesses like Claude Code (verified: a
single `claude -p` turn yields the model calls, MCP tool traffic, the harness's own telemetry export,
and stdio). It does **not** capture certificate-pinned clients, mTLS, clients with a hardcoded trust
store, or clients that bypass the proxy env.

## Decision

Ship cooperative capture as the laptop-side default. **Do not** build eBPF capture now.

- eBPF (or equivalent kernel-level interception) is the only way to get guaranteed, client-agnostic
  capture, but it is Linux-only and intrusive. The right home for it is the **sandbox runtime** (the
  private monorepo), where we own the kernel and the trust root — not the open-source laptop wrapper.
- For the cooperating harnesses we target today, the cost/benefit of eBPF is poor: it adds large
  platform-specific complexity to capture a long tail (pinned/mTLS clients) our harnesses don't use.
- The README is explicit about the boundary so the capability is never oversold.

## What we capture, and what "more" would mean

Today, composing `--proxy` + `--otlp` + stdio capture covers: HTTPS (LLM + tool/MCP calls, request &
response bodies via the blob store), the harness's own OpenTelemetry spans, the harness's own
outbound telemetry (e.g. its Datadog export — kept on purpose; it's signal), and stdout/stderr.

Reachable extensions, in rough priority:

1. **stdin** — the operator's prompts into the harness. **Done:** the supervisor pumps the parent's
   stdin to the child while capturing it as `process.stdin` log events (cancelled on child exit so an
   interactive TTY can't hang teardown). No eBPF needed.
2. **child process tree / exec** — tools the harness shells out to. Partially visible via the proxy
   (their network) and the harness's own spans; full syscall-level coverage needs ptrace/eBPF.
3. **file I/O** — reads/writes the harness performs. Needs eBPF/`fanotify`; sandbox-era.

Items 2–3 are the eBPF case and stay deferred to the sandbox.
