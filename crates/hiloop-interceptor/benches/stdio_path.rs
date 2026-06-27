//! Record-don't-gate benchmarks for the stdio capture hot path.
//!
//! These measure the two synchronous CPU costs on the default capture path —
//! framing raw bytes into records, and serializing a normalized event to JSONL —
//! without any async runtime, so the numbers are stable and attributable. They
//! are recorded for trend tracking, not asserted; see `docs/BENCHMARKING.md`.
//!
//! Run with `cargo bench -p hiloop-interceptor`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hiloop_core::event::{AttributeKey, Event, EventName, SignalType};
use hiloop_core::identity::{ForkContext, Hlc};
use hiloop_interceptor::framing::LineFramer;

const MAX_RECORD_BYTES: usize = 64 * 1024;
const BUFFER_BYTES: usize = 64 * 1024;

/// Build a ~64 KiB buffer of fixed-length newline-terminated lines.
fn line_buffer(line_len: usize) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(BUFFER_BYTES + line_len);
    while buffer.len() < BUFFER_BYTES {
        buffer.extend(std::iter::repeat_n(b'a', line_len));
        buffer.push(b'\n');
    }
    buffer
}

fn bench_line_framer(c: &mut Criterion) {
    let mut group = c.benchmark_group("line_framer");
    for line_len in [16_usize, 256, 4096] {
        let buffer = line_buffer(line_len);
        group.throughput(Throughput::Bytes(buffer.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(line_len),
            &buffer,
            |b, buffer| {
                b.iter(|| {
                    let mut framer = LineFramer::new(MAX_RECORD_BYTES);
                    let records = framer.push(black_box(buffer));
                    black_box(records.len())
                });
            },
        );
    }
    group.finish();
}

fn bench_event_serialize(c: &mut Criterion) {
    let context = ForkContext::new_local_root();
    let event = Event::new(
        &context,
        Hlc {
            wall_ns: 1,
            logical: 0,
        },
        SignalType::Log,
        EventName::new("process.stdout").expect("event name"),
    )
    .with_attribute(
        AttributeKey::new("message").expect("attribute key"),
        "a log line of fairly typical length emitted by a wrapped harness",
    );

    c.bench_function("event_serialize_json", |b| {
        b.iter(|| {
            let json = serde_json::to_string(black_box(&event)).expect("serialize event");
            black_box(json.len())
        });
    });
}

criterion_group!(benches, bench_line_framer, bench_event_serialize);
criterion_main!(benches);
