//! Same-origin encrypted-media transport backlog benchmark.
//!
//! Run with:
//! `cargo bench -p marmot-app --bench media_download_backlog --features media-benchmarks`

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use marmot_app::{
    AppPerformanceOperationSnapshot, AppPerformanceSnapshot, AppPerformanceTelemetry,
    MediaDownloadBenchmarkTransport,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BACKLOG_SIZE: usize = 16;
const P95_SAMPLES: usize = 20;
const FIXTURES: [BacklogFixture; 2] = [
    BacklogFixture {
        name: "small_64_kib",
        body_size: 64 * 1024,
    },
    BacklogFixture {
        name: "large_1_mib",
        body_size: 1024 * 1024,
    },
];

#[derive(Clone, Copy)]
struct BacklogFixture {
    name: &'static str,
    body_size: usize,
}

struct BacklogProfile {
    completion_p95: Duration,
    telemetry: AppPerformanceSnapshot,
}

/// Start a loopback HTTP/1.1 server that keeps each accepted connection alive
/// so the benchmark can distinguish connection reuse from per-request setup.
async fn spawn_keep_alive_server(
    requests_expected: usize,
    body_size: usize,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(vec![0x5a; body_size]);
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
async fn run_backlog(reuse_transport: bool, body_size: usize, telemetry: &AppPerformanceTelemetry) {
    let (url, server) = spawn_keep_alive_server(BACKLOG_SIZE, body_size).await;
    let shared = reuse_transport.then(MediaDownloadBenchmarkTransport::new);
    for _ in 0..BACKLOG_SIZE {
        let fresh = (!reuse_transport).then(MediaDownloadBenchmarkTransport::new);
        let transport = fresh
            .as_ref()
            .or(shared.as_ref())
            .expect("one transport policy must be selected");
        let body = transport
            .fetch_with_telemetry(&url, telemetry)
            .await
            .unwrap();
        assert_eq!(body.len(), body_size);
    }
    server.await.unwrap();
}

/// Measure a stable wall-clock p95 for the complete backlog outside Criterion's
/// statistical report and retain only fixed aggregate phase histograms.
async fn backlog_profile(
    reuse_transport: bool,
    body_size: usize,
    samples: usize,
) -> BacklogProfile {
    let telemetry = AppPerformanceTelemetry::default();
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        run_backlog(reuse_transport, body_size, &telemetry).await;
        durations.push(started.elapsed());
    }
    durations.sort_unstable();
    BacklogProfile {
        completion_p95: durations[(samples * 95).div_ceil(100).saturating_sub(1)],
        telemetry: telemetry.snapshot(),
    }
}

/// Render one aggregate phase percentile without exposing request metadata.
fn phase_p95(snapshot: &AppPerformanceOperationSnapshot) -> String {
    snapshot
        .duration_ms
        .approx_percentile_ms(0.95)
        .map_or_else(|| "overflow".to_owned(), |value| value.to_string())
}

/// Print fixed fixture, policy, throughput, and phase summaries for evidence.
fn print_profile(fixture: BacklogFixture, policy: &str, profile: &BacklogProfile) {
    let completed_bytes = (BACKLOG_SIZE * fixture.body_size) as f64;
    let throughput_mib_s =
        completed_bytes / profile.completion_p95.as_secs_f64() / (1024.0 * 1024.0);
    eprintln!(
        "media_download_same_origin_backlog fixture={} policy={} samples={} completion_p95_ms={:.3} throughput_p95_mib_s={:.3} host_setup_p95_ms={} response_headers_p95_ms={} first_byte_p95_ms={} body_transfer_p95_ms={}",
        fixture.name,
        policy,
        P95_SAMPLES,
        profile.completion_p95.as_secs_f64() * 1_000.0,
        throughput_mib_s,
        phase_p95(&profile.telemetry.media_download_host_setup),
        phase_p95(&profile.telemetry.media_download_response_headers),
        phase_p95(&profile.telemetry.media_download_first_byte),
        phase_p95(&profile.telemetry.media_download_body_transfer),
    );
}

/// Register both fixture sizes and transport policies, then print comparable
/// aggregate p95 phase and throughput evidence for every combination.
fn media_download_backlog(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for fixture in FIXTURES {
        let shared_profile =
            runtime.block_on(backlog_profile(true, fixture.body_size, P95_SAMPLES));
        let cold_profile = runtime.block_on(backlog_profile(false, fixture.body_size, P95_SAMPLES));
        print_profile(fixture, "shared", &shared_profile);
        print_profile(fixture, "cold", &cold_profile);

        let mut group = c.benchmark_group(format!(
            "media_download_same_origin_backlog/{}",
            fixture.name
        ));
        group.throughput(Throughput::Bytes(
            (BACKLOG_SIZE * fixture.body_size).try_into().unwrap(),
        ));
        let shared_telemetry = AppPerformanceTelemetry::default();
        group.bench_function("shared_vetted_transport", |b| {
            b.to_async(&runtime)
                .iter(|| run_backlog(true, fixture.body_size, &shared_telemetry));
        });
        let cold_telemetry = AppPerformanceTelemetry::default();
        group.bench_function("cold_transport_per_download", |b| {
            b.to_async(&runtime)
                .iter(|| run_backlog(false, fixture.body_size, &cold_telemetry));
        });
        group.finish();
    }
}

criterion_group!(benches, media_download_backlog);
criterion_main!(benches);
