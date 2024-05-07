use criterion::{criterion_group, criterion_main, Criterion};
use sbd_bench::CTurnoverBenchmark;
use std::sync::Arc;
use tokio::sync::Mutex;

fn criterion_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let test = Arc::new(Mutex::new(rt.block_on(CTurnoverBenchmark::new())));
    let test = &test;

    c.bench_function("c_turnover", |b| {
        b.to_async(&rt).iter(|| async move {
            test.lock().await.iter().await;
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
