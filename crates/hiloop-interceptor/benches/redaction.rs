//! Record-don't-gate benchmarks for captured-body credential scanning.
//!
//! The serial cases isolate leakguard CPU cost. The async cases measure the
//! production bounded blocking path, including detector-level parallelism for
//! large bodies and saturation at 1, 4, and 16 concurrent completions.
//!
//! Run with `cargo bench -p hiloop-interceptor --bench redaction`.

use std::{hint::black_box, time::Duration};

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_util::future::join_all;
use hiloop_interceptor::RedactionPolicy;

const BODY_CASES: [(usize, &str); 5] = [
    (1024, "1k"),
    (64 * 1024, "64k"),
    (256 * 1024, "256k"),
    (1024 * 1024, "1m"),
    (8 * 1024 * 1024, "8m"),
];

fn redaction_body(size: usize, credential: bool) -> Bytes {
    let mut body = String::with_capacity(size + 64);
    body.push_str(r#"{"model":"claude-sonnet","input":""#);
    body.extend(std::iter::repeat_n(
        'a',
        size.saturating_sub(body.len() + 2),
    ));
    body.push_str("\"}");
    if credential {
        let middle = body.len() / 2;
        body.insert_str(middle, " sk-abc1234567890xyzABCDEF ");
    }
    Bytes::from(body)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("benchmark runtime")
}

fn bench_serial_vs_bounded(c: &mut Criterion) {
    let policy = RedactionPolicy::enabled();
    let runtime = runtime();
    let mut group = c.benchmark_group("credential_redaction_mode");
    for (size, name) in BODY_CASES {
        for (dirty, content) in [(false, "clean"), (true, "credential")] {
            let body = redaction_body(size, dirty);
            group.throughput(Throughput::Bytes(body.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("serial_{content}"), name),
                &body,
                |b, body| b.iter(|| policy.redact_body(black_box(body.clone()))),
            );
            group.bench_with_input(
                BenchmarkId::new(format!("bounded_async_{content}"), name),
                &body,
                |b, body| {
                    b.iter(|| {
                        runtime
                            .block_on(policy.redact_body_async(black_box(body.clone())))
                            .expect("body scan")
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_bounded_concurrency(c: &mut Criterion) {
    let policy = RedactionPolicy::enabled();
    let runtime = runtime();
    let mut group = c.benchmark_group("credential_redaction_concurrency");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    for (size, name) in [
        (64 * 1024, "64k"),
        (1024 * 1024, "1m"),
        (8 * 1024 * 1024, "8m"),
    ] {
        let body = redaction_body(size, true);
        for concurrency in [1_usize, 2, 4, 16] {
            group.throughput(Throughput::Bytes((body.len() * concurrency) as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("{name}_credential"), concurrency),
                &(body.clone(), concurrency),
                |b, (body, concurrency)| {
                    b.iter(|| {
                        runtime.block_on(async {
                            let scans = std::iter::repeat_with(|| {
                                policy.redact_body_async(black_box(body.clone()))
                            })
                            .take(*concurrency);
                            for result in join_all(scans).await {
                                black_box(result.expect("body scan"));
                            }
                        });
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_serial_vs_bounded, bench_bounded_concurrency);
criterion_main!(benches);
