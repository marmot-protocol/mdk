//! Android-shaped media download deadline benchmark.
//!
//! Run with:
//! `cargo bench -p marmot-app --bench android_media_download --features media-benchmarks`

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use futures::future::join_all;
use marmot_app::{AppPerformanceTelemetry, MediaDownloadBenchmarkTransport};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ANDROID_PARALLELISM: usize = 3;
const LOCATOR_COUNT: usize = 3;
const BODY_BYTES: usize = 192 * 1024;
const TRANSFER_TIME: Duration = Duration::from_millis(300);
const STARTUP_TIMEOUT: Duration = Duration::from_millis(80);
const ACQUISITION_TIMEOUT: Duration = Duration::from_millis(600);
const PROFILE_SAMPLES: usize = 9;

#[derive(Clone, Copy)]
enum ServerBehavior {
    Progressing(Duration),
    StartupStall,
}

struct ScenarioResult {
    elapsed: Duration,
    successes: usize,
}

/// Serve one integrity-valid body while controlling only its delivery timing.
async fn spawn_media_server(
    body: Arc<Vec<u8>>,
    behavior: ServerBehavior,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else {
                        return;
                    };
                    let body = body.clone();
                    connections.spawn(async move {
                        let mut request = Vec::new();
                        let mut buffer = [0_u8; 1024];
                        loop {
                            let Ok(read) = stream.read(&mut buffer).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            request.extend_from_slice(&buffer[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        match behavior {
                            ServerBehavior::StartupStall => std::future::pending::<()>().await,
                            ServerBehavior::Progressing(duration) => {
                                let headers = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                                    body.len()
                                );
                                if stream.write_all(headers.as_bytes()).await.is_err() {
                                    return;
                                }
                                const CHUNKS: usize = 15;
                                let chunk_len = body.len().div_ceil(CHUNKS);
                                let delay = duration / CHUNKS as u32;
                                for chunk in body.chunks(chunk_len) {
                                    tokio::time::sleep(delay).await;
                                    if stream.write_all(chunk).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    let _ = completed;
                }
            }
        }
    });
    (base_url, server)
}

/// Model Android's three admitted downloads sharing one account transport.
async fn run_android_scenario(behaviors: [ServerBehavior; LOCATOR_COUNT]) -> ScenarioResult {
    let body = Arc::new(vec![0x5a; BODY_BYTES]);
    let hash = hex::encode(Sha256::digest(body.as_slice()));
    let mut locators = Vec::with_capacity(LOCATOR_COUNT);
    let mut servers = Vec::with_capacity(LOCATOR_COUNT);
    for behavior in behaviors {
        let (server, task) = spawn_media_server(body.clone(), behavior).await;
        locators.push(format!("{server}/{hash}.bin"));
        servers.push(task);
    }
    let transport =
        MediaDownloadBenchmarkTransport::with_timeouts(STARTUP_TIMEOUT, ACQUISITION_TIMEOUT);
    let telemetry = AppPerformanceTelemetry::default();
    let started = Instant::now();
    let outcomes = tokio::time::timeout(
        Duration::from_secs(2),
        join_all(
            (0..ANDROID_PARALLELISM)
                .map(|_| transport.fetch_candidates(locators.clone(), hash.clone(), &telemetry)),
        ),
    )
    .await
    .unwrap_or_else(|_| {
        (0..ANDROID_PARALLELISM)
            .map(|_| Err(marmot_app::AppError::BlobStore("benchmark timeout".into())))
            .collect()
    });
    let result = ScenarioResult {
        elapsed: started.elapsed(),
        successes: outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
    };
    for server in servers {
        server.abort();
    }
    result
}

/// Return a wall-clock p95 and the minimum success count across identical runs.
async fn profile(behaviors: [ServerBehavior; LOCATOR_COUNT]) -> (Duration, usize) {
    let mut durations = Vec::with_capacity(PROFILE_SAMPLES);
    let mut minimum_successes = ANDROID_PARALLELISM;
    for _ in 0..PROFILE_SAMPLES {
        let result = run_android_scenario(behaviors).await;
        durations.push(result.elapsed);
        minimum_successes = minimum_successes.min(result.successes);
    }
    durations.sort_unstable();
    (
        durations[(PROFILE_SAMPLES * 95).div_ceil(100).saturating_sub(1)],
        minimum_successes,
    )
}

/// Print and benchmark viable-slow and stalled-primary Android workloads.
fn android_media_download(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let viable = [ServerBehavior::Progressing(TRANSFER_TIME); LOCATOR_COUNT];
    let stalled = [
        ServerBehavior::StartupStall,
        ServerBehavior::Progressing(Duration::from_millis(100)),
        ServerBehavior::Progressing(Duration::from_millis(100)),
    ];
    for (name, behaviors) in [("viable_slow", viable), ("stalled_primary", stalled)] {
        let (completion_p95, minimum_successes) = runtime.block_on(profile(behaviors));
        eprintln!(
            "android_media_download scenario={name} samples={PROFILE_SAMPLES} parallelism={ANDROID_PARALLELISM} locators={LOCATOR_COUNT} successes_min={minimum_successes}/{ANDROID_PARALLELISM} completion_p95_ms={:.3}",
            completion_p95.as_secs_f64() * 1_000.0,
        );
        if std::env::var_os("ANDROID_MEDIA_PROFILE_ONLY").is_some() {
            continue;
        }
        let mut group = c.benchmark_group(format!("android_media_download/{name}"));
        group.sample_size(10);
        group.bench_function("three_parallel", |b| {
            b.to_async(&runtime)
                .iter(|| run_android_scenario(behaviors));
        });
        group.finish();
    }
}

criterion_group!(benches, android_media_download);
criterion_main!(benches);
