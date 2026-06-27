# Benchmarking Plan

Use benchmarks to understand interceptor overhead over time. Start by recording results, not gating
PRs, until workloads and runners are stable. Correctness under load remains a hard gate; the
directional performance budgets and promotion rules live in [`TESTING.md`](TESTING.md).

## Implemented

`crates/hiloop-interceptor/benches/stdio_path.rs` (Criterion, `harness = false`) records the two
synchronous CPU costs on the default capture path, run with `cargo bench -p hiloop-interceptor`:

- `line_framer/{16,256,4096}` — `LineFramer::push` throughput over a ~64 KiB buffer of fixed-length
  lines (covers part of `stdio_normalizer` and `stdio_e2e_binary` below). Early local readings show
  short lines bottlenecked on the per-record `Vec` allocation, which is the first optimization
  candidate if the events/s budget needs it.
- `event_serialize_json` — `serde_json` cost per event (the CPU half of `jsonl_exporter`).

These are recorded, not gated. The async end-to-end benchmarks below (`pipeline_memory_exporter`,
`stdio_e2e_binary`, `backpressure_slow_exporter`) are still to come, as is iai-callgrind and Bencher
historical tracking.

## Tooling

- Start with Criterion for wall-clock and throughput benchmarks. It works on stable Rust, supports
  async benchmarks, and can report bytes/items per iteration.
- Add iai-callgrind after the first Criterion baselines for deterministic CPU-cost tracking of
  normalization, provenance stamping, router selection, and JSON serialization.
- Use Bencher as the historical tracking layer once benchmark commands are stable. Keep it
  record-only until there are enough comparable runs to define meaningful alerts.
- Consider Divan later if allocation-focused ergonomics become more valuable than Criterion's
  historical comparability.

## First Benchmarks

1. `stdio_normalizer`
   - Cases: 32 B, 1 KiB, and 64 KiB UTF-8 stdout; 1 KiB non-UTF-8 stdout.
   - Track: ns/event, events/s, input bytes/s, and later instruction count.

2. `pipeline_memory_exporter`
   - Drive `Pipeline::new(...).run(stream)` with generated `RawSignal`s and an in-memory exporter.
   - Sweep raw/event queue capacities and export batch sizes.
   - Track: events/s, batch count, and producer stall time once instrumentation exists.

3. `jsonl_exporter`
   - Export representative event batches to a temp file.
   - Separate CPU-only serialization from filesystem write/flush cost.
   - Track: events/s, JSONL bytes/s, serialized bytes/event, and flush time.

4. `stdio_e2e_binary`
   - Run `hiloop-interceptor run --events-jsonl ... -- <native line generator>` using the same
     workload shapes as the mock-harness E2E suite. The POSIX shell fixture is for correctness,
     not throughput measurement.
   - Measure direct child execution separately, then report interceptor added time and slowdown
     ratio.
   - Compare against the same child command without capture.
   - Track: child slowdown ratio, captured lines/s, stdout/stderr bytes/s, and JSONL bytes/s.

5. `backpressure_slow_exporter`
   - Use a synthetic exporter that delays per batch.
   - Track: completion time, producer blocking, and whether the lossless/blocking contract holds.

## CI Shape

- PR CI should compile benchmark targets but not run expensive benchmarks by default.
- A scheduled or manual perf workflow should run Criterion on a stable runner and upload artifacts.
- A Linux-only perf workflow can run iai-callgrind for deterministic instruction/cache-style
  metrics once Valgrind setup is stable.
- Every recorded run should include commit SHA, rustc version, OS/kernel, CPU model, runner type,
  profile, benchmark command, and benchmark tool versions.
- Wall-clock results from shared GitHub runners are diagnostic artifacts, not comparable baselines.
- Keep benchmark input generation out of the timed region.
- Measure pass-through, event JSONL, and event+raw JSONL separately so retention cost is visible.

## Standard Metrics

- `events_per_sec`
- `raw_signals_per_sec`
- `input_bytes_per_sec`
- `jsonl_bytes_per_sec`
- `ns_per_event`
- `capture_to_export_latency_p50`
- `capture_to_export_latency_p95`
- `capture_to_export_latency_p99`
- `child_slowdown_ratio`
- `allocations_per_event`
- `bytes_allocated_per_event`
- `instruction_count`
- `export_batch_size`
- `queue_capacity`
- `producer_block_ns`
