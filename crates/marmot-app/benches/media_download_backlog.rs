//! Same-origin encrypted-media transport backlog benchmark.
//!
//! Run with:
//! `cargo bench -p marmot-app --bench media_download_backlog --features media-benchmarks`

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use marmot_app::MediaDownloadBenchmarkTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BACKLOG_SIZE: usize = 16;
const BODY_SIZE: usize = 64 * 1024;

/// Start a loopback HTTP/1.1 server that keeps each accepted connection alive
/// so the benchmark can distinguish connection reuse from per-request setup.
async fn spawn_keep_alive_server(
    requests_expected: usize,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(vec![0x5a; BODY_SIZE]);
    let served = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(async move {
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
        while served.load(Ordering::SeqCst) < requests_expected {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    let body = body.clone();
                    let served = served.clone();
                    let done_tx = done_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut request = Vec::new();
                            let mut buffer = [0_u8; 1024];
                            loop {
                                let read = stream.read(&mut buffer).await.unwrap();
                                if read == 0 {
                                    return;
                                }
                                request.extend_from_slice(&buffer[..read]);
                                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            let headers = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                                body.len()
                            );
                            stream.write_all(headers.as_bytes()).await.unwrap();
                            stream.write_all(&body).await.unwrap();
                            served.fetch_add(1, Ordering::SeqCst);
                            let _ = done_tx.send(());
                        }
                    });
                }
                completed = done_rx.recv() => {
                    if completed.is_none() {
                        break;
                    }
                }
            }
        }
    });
    (format!("http://localhost:{port}/blob.bin"), server)
}

/// Download one fixed backlog either through one shared transport or through a
/// fresh transport per item while keeping payload and server behavior equal.
async fn run_backlog(reuse_transport: bool) {
    let (url, server) = spawn_keep_alive_server(BACKLOG_SIZE).await;
    let shared = reuse_transport.then(MediaDownloadBenchmarkTransport::new);
    for _ in 0..BACKLOG_SIZE {
        let fresh = (!reuse_transport).then(MediaDownloadBenchmarkTransport::new);
        let transport = fresh
            .as_ref()
            .or(shared.as_ref())
            .expect("one transport policy must be selected");
        let body = transport.fetch(&url).await.unwrap();
        assert_eq!(body.len(), BODY_SIZE);
    }
    server.await.unwrap();
}

/// Measure a stable wall-clock p95 for the complete backlog outside Criterion's
/// statistical report so before/after evidence uses the same definition.
async fn backlog_p95(reuse_transport: bool, samples: usize) -> Duration {
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        run_backlog(reuse_transport).await;
        durations.push(started.elapsed());
    }
    durations.sort_unstable();
    durations[(samples * 95).div_ceil(100).saturating_sub(1)]
}

/// Register both transport policies and print their directly comparable p95s.
fn media_download_backlog(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let shared_p95 = runtime.block_on(backlog_p95(true, 20));
    let cold_p95 = runtime.block_on(backlog_p95(false, 20));
    eprintln!(
        "media_download_same_origin_backlog samples=20 shared_p95_ms={:.3} cold_p95_ms={:.3}",
        shared_p95.as_secs_f64() * 1_000.0,
        cold_p95.as_secs_f64() * 1_000.0,
    );
    let mut group = c.benchmark_group("media_download_same_origin_backlog");
    group.throughput(Throughput::Bytes(
        (BACKLOG_SIZE * BODY_SIZE).try_into().unwrap(),
    ));
    group.bench_function("shared_vetted_transport", |b| {
        b.to_async(&runtime).iter(|| run_backlog(true));
    });
    group.bench_function("cold_transport_per_download", |b| {
        b.to_async(&runtime).iter(|| run_backlog(false));
    });
    group.finish();
}

criterion_group!(benches, media_download_backlog);
criterion_main!(benches);
