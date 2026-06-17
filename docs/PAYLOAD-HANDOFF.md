# Payload Handoff — getting offloaded bodies from the edge to the backend

**Status:** open cross-repo design question. Handoff *from* the backend telemetry-store team
*to* the interceptor team. Nothing here is decided — it's a proposal + a set of decisions to make
together.

**Date:** 2026-06-14 · **Against:** interceptor `9544c6d` · backend `hiloopai/hiloop` (the private
telemetry store that consumes `Event`s).

**Reading:** [`CAPTURE.md`](CAPTURE.md), [`INTERFACES.md`](INTERFACES.md), `src/blob.rs`,
`src/proxy.rs`, `src/seams.rs` (`RawSignal::with_payload_ref`), `hiloop_core::event::PayloadRef`;
backend side: `hiloopai/hiloop` → `docs/technical/telemetry-store.md`,
`proto/hiloop/telemetry/v1/telemetry.proto`, `services/telemetry/`.

## TL;DR

- Your `BlobStore` seam + **sha256 content-addressing** is the right foundation. This is **not** a
  "rip it out" note — the hard part is done well.
- **The gap:** offloaded bodies land in a **local** directory (`DirBlobStore`), the `Event` carries
  only the `payload_ref` *digest*, and **the backend ingest contract carries the digest, not the
  bytes**. So an offloaded LLM/HTTP body never reaches the backend — the digest is unresolvable
  downstream (we can record `sha256:…` but can't show the actual request/response).
- **Proposed:** a **digest-first upload protocol** to a backend content-addressed store, behind your
  existing `BlobStore` seam (a remote/uploading impl, or a post-`finish` uploader). The backend owns
  the durable CAS; the edge keeps content-addressing because it enables dedup-on-upload.
- A few decisions are yours to make (below), plus two cross-repo contract points — notably **sha256
  (yours) vs blake3 (the snapshot store's)** for the shared-CAS question in DESIGN §7.

## Current state — accurate read (supersedes the `CAPTURE.md` "observation-id" note)

`CAPTURE.md` still says "raw-body offload is keyed by observation id rather than content hash." The
code has moved past that. As of `9544c6d`:

- `src/blob.rs` defines a `BlobStore` seam: `writer()` → `BlobWriter` (streaming `write` + `finish`).
  `finish()` returns `PayloadRef { digest: "sha256:<hex>", size_bytes }`. **Content-addressed.**
- `DirBlobStore` persists each blob at `<dir>/sha256-<hex>`; **identical bodies dedup to the same
  file**. `MemoryBlobStore` backs tests.
- The proxy (`src/proxy.rs`) streams each body frame into the writer (one frame in memory at a
  time), then emits a `RawSignal` with an **empty `body`** and the `payload_ref` — honoring the
  authority rule in `seams.rs` ("when `payload_ref` is `Some`, that's where the body lives"). The
  normalizer carries it onto `Event::with_payload_ref`.

**Net effect today:** an `Event` leaves the edge carrying a `sha256:…` digest; the bytes sit in the
local blob directory on the user's machine.

## The gap

1. **Blobs are local-only.** There is no path that moves `<dir>/sha256-<hex>` to the backend.
2. **The backend ingest contract has no body channel.** Both ingest paths the backend accepts —
   `Event v1` JSONL and the gRPC `TelemetryIngestService` (`proto/hiloop/telemetry/v1`) — carry
   `payload_ref` (digest / media_type / size_bytes) but **no bytes**. The store records the digest
   and cannot fetch the body.
3. **The edge can't write to the backend's CAS directly.** The interceptor is OSS and runs on user
   machines; it has no trust/credentials/route into the backend's private blob store. DESIGN §7
   wants *one* content-addressed store for snapshot chunks *and* telemetry payloads, but the bytes
   still have to get there over the wire.

## Why content-addressing at the edge is still right

(An earlier backend-side take suggested "the edge shouldn't content-address at all." Having read
`blob.rs`, that take is wrong — here's the corrected reasoning.)

- The bytes must cross the wire regardless; the backend can't read the edge's disk. So a naive
  "offload locally and forget" buys nothing for the backend.
- **But** content-addressing enables **digest-first dedup on upload**: the edge asks the backend
  "do you already have `sha256:X`?" and uploads only what's missing. Repeated payloads — a shared
  system prompt, a retried call, identical context across sibling forks — are then sent **once**.
  Your streaming writer + dedup-to-same-file already set this up. This is a real wire saving, and the
  reason to keep the seam.

## Proposed integration

A digest-first handoff, with the durable store on the backend and your `BlobStore` seam as the edge
abstraction:

1. **Backend blob API (we build it):** `HasBlobs(digests) -> missing[]` and an idempotent,
   content-verified `UploadBlob(stream { digest, chunk })` (backend re-hashes on receipt). Events
   keep carrying *only* the digest.
2. **Edge uploader behind your seam:** a `BlobStore` impl (or a post-`finish` uploader) that, per
   finalized blob, runs digest-first upload to the backend. The local `DirBlobStore` stays for
   local/dev/air-gapped runs (or becomes a write-through cache).
3. **Resolution stays lazy on the backend:** the telemetry store resolves `digest → bytes` from the
   CAS on demand (trajectory replay, the UI opening a specific call) — bodies never bloat the
   columnar event rows.
4. **Modes:**
   - *Hosted:* uploader ships to the backend CAS (S3/our store).
   - *Local / air-gapped:* `DirBlobStore` only, or the customer's in-cluster MinIO; no external hop.
   - *OSS, no backend:* `DirBlobStore` as today — the wrapper stays fully useful standalone.

## Decisions for the interceptor team

1. **Eager vs lazy upload** — upload at `finish`, or batch/background? How much local buffering, and
   what backpressure/retry?
2. **Upload-failure semantics** — if upload fails, the `Event` still ships with a digest the backend
   lacks. Acceptable (resolve-later / mark pending), or block the event? Probably resolve-later.
3. **Where the endpoint + credentials come from** — hosted-only, presumably via the same config/env
   the wrapper already takes (`HILOOP_*`). OSS users get no uploader (BYO blob store or none).
4. **Does the uploader live in the OSS interceptor, or a hosted-only add-on/impl?** Keeping it a
   separate impl behind the seam keeps the OSS core clean and the hosted path out of the public repo.
5. **Local-blob retention/GC** after a successful upload.

## Cross-repo contract points

- **Hash algorithm — please weigh in.** You content-address with **sha256**; the snapshot store
  (DESIGN §7) uses **blake3**. DESIGN envisions *one* CAS for snapshot chunks *and* telemetry
  payloads. Either telemetry payloads live in a separate namespace (sha256 is fine there) or they
  join the snapshot CAS (then we'd align on blake3). Worth settling before the backend CAS fixes its
  addressing — cheap now, migration later.
- **`media_type` / `size_bytes`** — keep populating them on `PayloadRef`; the backend stores them on
  the event row and uses `size_bytes` for ingest limits.
- **Truncation / oversized bodies** — you already stamp `http.capture.truncated`. Define what the
  backend should do with a truncated/oversized payload (store partial? skip the blob, keep the
  event?).
- **Wire shape** — the backend's gRPC contract (`proto/hiloop/telemetry/v1`) currently has
  `PayloadRef` but no bytes; we'll add the blob API alongside it. Let's design that shape together so
  the digest the edge computes is exactly what the backend keys on.

## What the backend already provides / will provide

- **Today:** the telemetry store carries the `payload_ref` columns (`payload_digest` /
  `payload_media_type` / `payload_size_bytes`) and promotes `net`/`llm` attributes — it's ready to
  record digests now; it just can't resolve them.
- **Next:** the digest-first blob-ingest endpoint + CAS storage (S3/MinIO) + `digest → bytes`
  resolution for queries and replay.

## Pointers

- **interceptor:** `src/blob.rs` (`BlobStore`/`BlobWriter`/`DirBlobStore`), `src/proxy.rs`
  (`offload_bytes`, request/response signal builders), `src/seams.rs`
  (`RawSignal::with_payload_ref`), `docs/CAPTURE.md`, `docs/INTERFACES.md`.
- **backend (`hiloopai/hiloop`):** `docs/technical/telemetry-store.md` (data model + the
  payload-handoff follow-up), `proto/hiloop/telemetry/v1/telemetry.proto`, `services/telemetry/`.
