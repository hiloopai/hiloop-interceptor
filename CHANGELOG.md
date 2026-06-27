# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the project is pre-1.0,
minor releases may include breaking changes to the CLI, its flags, and the event schema.

## [Unreleased]

## [0.1.0] - 2026-06-26

First public release. Early alpha — it captures real agent harnesses end-to-end, but APIs, flags,
and the event schema will still change.

### Added

- `run` command that wraps an agent harness, resolves a fork-tree context, and injects the spine
  into the child environment (`HILOOP_*`, `OTEL_RESOURCE_ATTRIBUTES`).
- stdio capture: tee the child's stdout, stderr, and stdin into normalized, fork-stamped JSONL
  events (`--events-jsonl`), with optional raw-observation preservation (`--raw-jsonl`).
- Embedded OTLP/HTTP receiver (`--otlp`) that captures the harness's own OpenTelemetry trace
  export; `gen_ai.*` / `llm.*` spans become `llm` events.
- Embedded cooperative MITM proxy (`--proxy`) that mints an ephemeral, child-scoped CA, decrypts
  the harness's HTTPS traffic, and emits fork-stamped `net` / `llm` events. Bodies stream into a
  content-addressed blob store (`--blob-dir`), so memory stays bounded for streaming/SSE responses.
- gRPC export (`--export-grpc`) to a hiloop telemetry gateway, with the API key read from
  `HILOOP_API_KEY` (never a flag). Composes with local JSONL durability logging.
- `inspect` command to summarize a captured events file by fork-tree node and to diff two branches.
- Prebuilt binaries for Linux (x86_64, arm64), macOS (Intel, Apple Silicon), and Windows (x86_64),
  attached to each GitHub Release with SHA-256 checksums.

[Unreleased]: https://github.com/hiloopai/hiloop-interceptor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hiloopai/hiloop-interceptor/releases/tag/v0.1.0
