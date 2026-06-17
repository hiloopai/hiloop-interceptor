# Payload Handoff — interceptor team response

**Status:** reply to [`PAYLOAD-HANDOFF.md`](PAYLOAD-HANDOFF.md) from the interceptor side. Agreement
in principle, with four adjustments. Nothing here is final until the cross-repo points (hash, wire
shape) are settled together.

**Date:** 2026-06-15 · **Against:** interceptor `main` (post blob-store merge; the handoff's
`9544c6d` predates `src/blob.rs`).

## Agreement

The diagnosis is correct and the foundation is right. Offloaded bodies are local-only today; the
`Event` carries a `sha256:…` digest the backend cannot resolve. The digest-first upload protocol
(`HasBlobs → UploadBlob`, backend re-hashes) behind the `BlobStore` seam is the right shape, and
content-addressing at the edge is worth keeping because it enables dedup-on-upload (shared system
prompts, retried calls, identical context across sibling forks ship once). We accept the proposal
with the adjustments below.

## Adjustments

### 1. Separate uploader; keep `BlobStore`/`finish()` local and Drop-safe
Do **not** make `finish()` perform the upload. The proxy finalizes blobs from a detached `Drop` task
on client disconnect; if `finish()` did network I/O, a disconnect would trigger a fire-and-forget
upload with no backpressure/retry, possibly during runtime shutdown.

- `BlobStore` (`DirBlobStore`) stays local, fast, Drop-safe: commit to the dir, return the ref.
- A **separate `BlobUploader`** drains the local dir to the backend asynchronously, owning batching,
  retry, and backpressure.

This resolves the handoff's "impl vs uploader" question (→ separate uploader) and makes
upload-failure trivial: the local blob is the durable buffer; the event already shipped a valid
digest; the uploader retries.

### 2. Hash algorithm — lower-stakes than it looks; we lean blake3
- `PayloadDigest` is already `"<algo>:<hex>"` (self-describing). The **frozen `Event` v1 schema is
  not locked to sha256** and a store can hold mixed `sha256:`/`blake3:` keys, so this is not a
  schema-migration emergency.
- **But** dedup never crosses the algorithm boundary, so DESIGN §7's "one CAS for snapshot chunks
  *and* telemetry payloads" *requires* a single algorithm.
- **Recommendation:** if the one-CAS vision is firm, switch the edge to **blake3 now** — it matches
  the snapshot store, it's faster on the proxy hot path (we hash every body), and the change is
  trivial today (swap the `sha2` dep for `blake3`, change the prefix) with zero persisted production
  data. If one-CAS is not firm, keep sha256 in a separate telemetry namespace. This is the cross-team
  call; settle it before the backend CAS fixes its keying.

### 3. Edge enforces a max blob size
The edge currently has no size cap — a pathological body streams to a huge local blob and would
upload it. The edge should enforce a **configurable max blob size**: cap, stamp
`http.capture.truncated`, stop writing. The backend ingest limit stays as defense-in-depth.

### 4. "Bytes pending" is a first-class state
With resolve-later, an `Event` routinely arrives before its blob uploads. The contract should state
that **a digest in an event is a promise, not a guarantee of present bytes** — consumers (UI replay)
show "uploading…" rather than "missing." One line in the proto/contract.

## Answers to the handoff's "decisions for the interceptor team"

1. **Eager vs lazy:** lazy/background uploader, decoupled from `finish()` (adjustment 1).
2. **Upload-failure:** resolve-later; local blob is the durable buffer + retry source; never block the
   event (matches B12 — telemetry never kills the child).
3. **Endpoint/creds:** hosted-only, via the existing `HILOOP_*` config; OSS users get no uploader.
4. **Where it lives:** hosted-only impl in the private monorepo, behind the OSS `BlobStore` seam. The
   OSS repo keeps the trait + `DirBlobStore` only.
5. **Local GC:** evict after confirmed upload (uploader owns retention); `DirBlobStore`-only mode keeps
   everything.

## Cross-repo points still to settle together
- **Hash algorithm** (adjustment 2) — **decided: blake3.** The edge now content-addresses with blake3
  (matches the snapshot store's CAS; registered CAS digest in OCI image-spec and Bazel REAPI). The
  digest is algorithm-prefixed (`blake3:<hex>`), so a mixed store stays possible. The backend's CAS
  must key + re-hash on blake3.
- **Wire shape** for the blob API — design together (see the ingestion-interface section below) so
  the edge's digest is exactly the backend's key, and the backend re-hash uses blake3.
- **Truncated/oversized payloads** — edge caps + stamps `http.capture.truncated` (configurable
  `--max-capture-bytes`); define backend behavior for a truncated blob (store partial? keep event,
  drop blob?).
- `media_type` / `size_bytes` on `PayloadRef` — we keep populating them.

## Ingestion interface — recommended design

Backed by a survey of how production telemetry + CAS systems solve exactly this (Sentry, OTLP,
Honeycomb, Datadog, Grafana, Langfuse/LangSmith/Helicone for LLM-body offload; OCI Distribution,
Bazel REAPI, Git, restic/casync for content-addressed upload; the OAuth RFCs for untrusted-client
auth). The findings converge hard.

### One control plane, two data planes

The team's "single ingestor is nicer for auth" intuition is **right about auth/control and wrong
about transport.** The split that matters is **events vs payloads, not events-by-type** — splitting
the *event* stream into per-signal endpoints (OTLP/Datadog/Grafana style) is an ecosystem-interop
choice with no scaling payoff for a first-party agent (Sentry and Honeycomb run high rate over one
multiplexed event endpoint). So:

- **One authenticated front door** — one per-agent credential; auth, TLS, rate-limiting, quota, and
  audit enforced once. Concretely an API gateway fanning out to two backends, **or** (lighter) one
  gRPC service with `IngestEvents` (unary) + `UploadBlob` (client-streaming) behind a single auth
  interceptor.
- **Two independently-tuned data paths behind it.** Events: small body limit (~1 MB, the universal
  in-band cap), tight timeout, request-count rate limits → the telemetry store. Blobs: long timeout,
  byte/bandwidth limits, and ideally **not proxied through the API tier at all** — the front door
  hands back a presigned/short-lived URL and the edge uploads the bytes **direct to object storage**.

**Transport caveat:** do not co-mingle blob and event bytes on one connection. HTTP/2 multiplexing
does not save you — a lost TCP segment on a stalled blob upload head-of-line-blocks interleaved
event streams at the TCP layer. Blobs get their own connection, or (better) presigned direct upload.

### The blob upload protocol (digest-first, dedup-on-upload, verify-on-write)

From OCI / Bazel REAPI / Langfuse, the proven shape:

1. **Negotiate**: the edge asks `find-missing([{digest, size}…])` and the backend returns only the
   digests it lacks. This collapses the common case (retries, shared system prompts, sibling-fork
   duplicates) to no-ops in one round trip (Bazel `FindMissingBlobs`; Git have/want; Langfuse
   "already have it → skip upload").
2. **Transfer the missing**: batch small blobs in one call; stream large ones resumably
   (offset-query + append). Or hand back a presigned object-storage PUT and upload direct.
3. **Verify-on-write (the trust spine)**: because the edge is an untrusted OSS client, the backend
   **MUST recompute the blake3 of received bytes and reject mismatches** — otherwise a client could
   claim digest X but upload Y and poison the CAS. Existence checks are an optimization, sound only
   because every stored blob was verified on write. The digest *is* the idempotency key (re-upload =
   no-op).

### Auth for the OSS edge

The edge is a "public client" (RFC 6749) — it ships **no long-lived secret** (anything embedded is
extractable). Use a **public, write-only ingest credential** like Sentry's DSN / Datadog's client
token: safe to be non-secret because it is write-only + rate-limited + namespace-scoped, and it can
*never* make the backend assert it has a blob (only a verified write can). Security rests on
server-side rate limits + quotas, not secrecy. Hosted deployments can provision per-tenant /
short-lived tokens (device-authorization grant, RFC 8628) or mTLS / certificate-bound tokens
(RFC 8705) for replay-resistant agent identity when the PKI cost is worth it.

### Edge-side seams

Two seams on the edge, both pointed at the **same endpoint + credential**:

- **`Exporter`** (exists) → events. `JsonlExporter` is the local impl; a `RemoteExporter` is the
  hosted impl.
- **`BlobUploader`** (new; sketched in `src/blob.rs`) → drains the local `DirBlobStore` to the
  backend with `find_missing` + `upload`, **decoupled from the proxy hot path via a background
  queue**. `DirBlobStore` stays as the durable buffer and the OSS / air-gapped mode (a `NoopUploader`
  keeps everything local). The real hosted uploader (HTTP/gRPC, presigned direct-to-object-storage)
  lives in the private monorepo, behind this seam.

**Net:** one ingest endpoint + one credential (control plane); `Exporter` and `BlobUploader` as the
two edge seams; events → telemetry store and blobs → object storage on separate connections; upload
decoupled from capture. Don't split events by signal; don't couple the blob backend to the event
backend.
