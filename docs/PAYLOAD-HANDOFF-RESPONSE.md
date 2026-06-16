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
- **Hash algorithm** (adjustment 2) — the one real decision.
- **Wire shape** for `HasBlobs`/`UploadBlob` — design together so the edge's digest is exactly the
  backend's key (and so the backend re-hash uses the same algorithm).
- **Truncated/oversized payloads** — edge caps + stamps (adjustment 3); define backend behavior for a
  truncated blob (store partial? keep event, drop blob?).
- `media_type` / `size_bytes` on `PayloadRef` — we keep populating them.
