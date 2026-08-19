//! Founding-image critical-path benchmark for mdk#1485.
//!
//! Results use stable `MDK_BENCH ...` rows. `baseline_serialized_ms` models
//! the former response boundary by summing the same preprocessing, upload, and
//! canonical-create phases. `canonical_create_ms` measures the new boundary,
//! where no Blossom transfer occurs. Run with `just bench-group-image-create`.

use std::sync::Arc;
use std::time::Instant;

use image::ImageEncoder as _;
use marmot_account::AccountHome;
use marmot_app::{
    AppPreparedGroupImageUploadState, MAX_GROUP_IMAGE_BYTES, MarmotApp, MarmotAppConfig,
    MarmotAppRuntime,
};
use nostr_relay_builder::MockRelay;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const BENCH_ACCOUNT: &str = "bench";

fn one_pixel_png() -> Vec<u8> {
    let mut bytes = Vec::new();
    image::codecs::png::PngEncoder::new(&mut bytes)
        .write_image(&[0, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
        .unwrap();
    bytes
}

async fn read_blossom_upload(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let header_end = loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "upload closed before its headers completed");
        request.extend_from_slice(&buffer[..read]);
        if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap();
    let hash = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-sha-256")
                .then(|| value.trim().to_owned())
        })
        .unwrap();
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "upload closed before its body completed");
        request.extend_from_slice(&buffer[..read]);
    }
    hash
}

struct BenchmarkBlossomServer {
    url: String,
    stalled_upload_received: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

async fn spawn_benchmark_blossom_server() -> BenchmarkBlossomServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server_url = url.clone();
    let stalled_upload_received = Arc::new(tokio::sync::Notify::new());
    let stalled_signal = stalled_upload_received.clone();
    let task = tokio::spawn(async move {
        for upload_index in 0..4 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let hash = read_blossom_upload(&mut stream).await;
            if upload_index == 3 {
                stalled_signal.notify_one();
                std::future::pending::<()>().await;
            }
            let body = serde_json::json!({
                "url": format!("{server_url}/{hash}.bin"),
                "sha256": hash,
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    BenchmarkBlossomServer {
        url,
        stalled_upload_received,
        task,
    }
}

async fn measure_prepared_group_image_case(
    runtime: &MarmotAppRuntime,
    blossom_server: &str,
    case: &str,
    image: Vec<u8>,
) {
    let source_bytes = image.len();
    let preprocess_started = Instant::now();
    let staged = runtime
        .stage_prepared_group_image(BENCH_ACCOUNT, image, "image/png".to_owned())
        .await
        .unwrap();
    let preprocess = preprocess_started.elapsed();
    let upload_started = Instant::now();
    let uploaded = runtime
        .upload_prepared_group_image_to_server_for_test(
            BENCH_ACCOUNT,
            staged.upload_id.clone(),
            blossom_server.to_owned(),
        )
        .await
        .unwrap();
    let upload = upload_started.elapsed();
    assert_eq!(uploaded.state, AppPreparedGroupImageUploadState::Uploaded);
    let create_started = Instant::now();
    runtime
        .create_group_with_prepared_initial_image(BENCH_ACCOUNT, case, &[], None, staged.upload_id)
        .await
        .unwrap();
    let create = create_started.elapsed();
    let baseline_serialized = preprocess + upload + create;
    println!(
        "MDK_BENCH group_image_create case={case} source_bytes={source_bytes} \
         baseline_serialized_ms={} preprocess_ms={} upload_ms={} canonical_create_ms={} \
         upload_in_create=false",
        baseline_serialized.as_millis(),
        preprocess.as_millis(),
        upload.as_millis(),
        create.as_millis(),
    );
}

async fn run_measurement_matrix() {
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let blossom = spawn_benchmark_blossom_server().await;
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account(BENCH_ACCOUNT)
        .unwrap();
    let config = MarmotAppConfig::default()
        .with_allow_loopback_blob_endpoints(true)
        .with_allow_loopback_relay_endpoints(true)
        .with_open_ranking_provider(None, Vec::new());
    let runtime = Arc::new(MarmotAppRuntime::new(MarmotApp::with_relay_and_config(
        dir.path(),
        relay_url,
        config,
    )));
    runtime.start().await.unwrap();

    let create_started = Instant::now();
    runtime
        .create_group(BENCH_ACCOUNT, "no image", &[], None)
        .await
        .unwrap();
    let no_image = create_started.elapsed();
    println!(
        "MDK_BENCH group_image_create case=no_image source_bytes=0 \
         baseline_serialized_ms={} preprocess_ms=0 upload_ms=0 canonical_create_ms={} \
         upload_in_create=false",
        no_image.as_millis(),
        no_image.as_millis(),
    );

    measure_prepared_group_image_case(&runtime, &blossom.url, "typical", one_pixel_png()).await;
    let mut maximum = one_pixel_png();
    maximum.resize(MAX_GROUP_IMAGE_BYTES, 0);
    measure_prepared_group_image_case(&runtime, &blossom.url, "maximum_accepted_bytes", maximum)
        .await;

    let ready = runtime
        .stage_prepared_group_image(BENCH_ACCOUNT, one_pixel_png(), "image/png".to_owned())
        .await
        .unwrap();
    runtime
        .upload_prepared_group_image_to_server_for_test(
            BENCH_ACCOUNT,
            ready.upload_id.clone(),
            blossom.url.clone(),
        )
        .await
        .unwrap();
    let stalled = runtime
        .stage_prepared_group_image(BENCH_ACCOUNT, one_pixel_png(), "image/png".to_owned())
        .await
        .unwrap();
    let upload_runtime = runtime.clone();
    let stalled_server = blossom.url.clone();
    let stalled_upload = tokio::spawn(async move {
        upload_runtime
            .upload_prepared_group_image_to_server_for_test(
                BENCH_ACCOUNT,
                stalled.upload_id,
                stalled_server,
            )
            .await
    });
    blossom.stalled_upload_received.notified().await;
    let create_started = Instant::now();
    runtime
        .create_group_with_prepared_initial_image(
            BENCH_ACCOUNT,
            "stalled server independence",
            &[],
            None,
            ready.upload_id,
        )
        .await
        .unwrap();
    let create = create_started.elapsed();
    println!(
        "MDK_BENCH group_image_create case=stalled_server source_bytes={} \
         baseline_serialized_ms=stalled preprocess_ms=measured_separately upload_ms=stalled \
         canonical_create_ms={} upload_in_create=false",
        one_pixel_png().len(),
        create.as_millis(),
    );

    stalled_upload.abort();
    assert!(stalled_upload.await.unwrap_err().is_cancelled());
    runtime.shutdown_and_close().await.unwrap();
    blossom.task.abort();
    let _ = blossom.task.await;
}

fn run_benchmark(name: &'static str, body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(body)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[ignore = "group-image create benchmark; run via `just bench-group-image-create`"]
fn prepared_group_image_create_measurement_matrix() {
    run_benchmark("group-image-create-bench", || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_measurement_matrix());
    });
}
