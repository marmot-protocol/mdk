//! End-to-end push test for the opt-in OTLP exporter.
//!
//! Runs only with the `otlp-export` feature. It stands up a minimal local HTTP
//! server (no real collector needed), opts the exporter in against it, and
//! asserts the push lands as an `application/x-protobuf` POST to `/v1/metrics`
//! with a non-empty OTLP body. The protobuf *contents* are unit-tested in the
//! crate; this test covers the wire transport.
#![cfg(feature = "otlp-export")]

use std::time::Duration;

use marmot_app::{
    MarmotApp, MarmotAppConfig, MarmotAppRuntime, MarmotRelayPlane, MarmotServiceEndpoints,
    RelayTelemetryExportConfig, RelayTelemetryResource, RelayTelemetryRuntimeConfig,
    RelayTelemetrySettings,
};
use nostr_relay_builder::MockRelay;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct CapturedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body_len: usize,
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn capture_one_request(listener: TcpListener, tx: oneshot::Sender<CapturedRequest>) {
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        buf.extend_from_slice(&chunk[..read]);

        let Some(header_end) = find_subsequence(&buf, b"\r\n\r\n").map(|pos| pos + 4) else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => buf.extend_from_slice(&chunk[..read]),
            }
        }

        let request_line = headers.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let header_value = |name: &str| {
            let prefix = format!("{name}:");
            headers.lines().find_map(|line| {
                line.get(..prefix.len())
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(&prefix))
                    .then(|| line[prefix.len()..].trim().to_owned())
            })
        };
        let content_type = header_value("content-type");
        let authorization = header_value("authorization");

        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        let _ = tx.send(CapturedRequest {
            method,
            path,
            authorization,
            content_type,
            body_len: content_length,
        });
        return;
    }
}

async fn capture_requests(
    listener: TcpListener,
    statuses: Vec<u16>,
    tx: oneshot::Sender<Vec<CapturedRequest>>,
) {
    let mut captured = Vec::new();
    for status in statuses {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let Some(request) = read_request(&mut stream).await else {
            return;
        };
        let response = format!("HTTP/1.1 {status} OK\r\nContent-Length: 0\r\n\r\n");
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
        captured.push(request);
    }
    let _ = tx.send(captured);
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<CapturedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => read,
        };
        buf.extend_from_slice(&chunk[..read]);

        let Some(header_end) = find_subsequence(&buf, b"\r\n\r\n").map(|pos| pos + 4) else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => buf.extend_from_slice(&chunk[..read]),
            }
        }

        let request_line = headers.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let header_value = |name: &str| {
            let prefix = format!("{name}:");
            headers.lines().find_map(|line| {
                line.get(..prefix.len())
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(&prefix))
                    .then(|| line[prefix.len()..].trim().to_owned())
            })
        };
        return Some(CapturedRequest {
            method,
            path,
            authorization: header_value("authorization"),
            content_type: header_value("content-type"),
            body_len: content_length,
        });
    }
}

fn runtime_config(endpoint: impl Into<String>) -> RelayTelemetryRuntimeConfig {
    RelayTelemetryRuntimeConfig {
        otlp_endpoint: Some(endpoint.into()),
        authorization_bearer_token: Some("test-token".to_owned()),
        resource: Some(RelayTelemetryResource {
            service_version: "1.4.2".to_owned(),
            service_instance_id: "8e1ca50b-05a2-4c31-a31c-1e69c75a9366".to_owned(),
            deployment_environment: "staging".to_owned(),
            os_type: "ios".to_owned(),
            os_version: "17.5".to_owned(),
            device_model_identifier: None,
        }),
    }
}

fn runtime_config_without_endpoint() -> RelayTelemetryRuntimeConfig {
    RelayTelemetryRuntimeConfig {
        otlp_endpoint: None,
        authorization_bearer_token: Some("test-token".to_owned()),
        resource: Some(RelayTelemetryResource {
            service_version: "1.4.2".to_owned(),
            service_instance_id: "8e1ca50b-05a2-4c31-a31c-1e69c75a9366".to_owned(),
            deployment_environment: "staging".to_owned(),
            os_type: "ios".to_owned(),
            os_version: "17.5".to_owned(),
            device_model_identifier: None,
        }),
    }
}

#[tokio::test]
async fn export_once_pushes_otlp_metrics_over_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let relay_plane = MarmotRelayPlane::full_history();
    let endpoint = format!("http://{addr}/custom/v1/metrics");
    let exporter = relay_plane
        .telemetry_exporter(
            RelayTelemetryExportConfig::enabled(endpoint.clone())
                .with_runtime_config(runtime_config(endpoint)),
        )
        .expect("opted-in exporter is constructed");

    let count = exporter
        .export_once(None)
        .await
        .expect("export push succeeds");
    assert!(count > 0, "population metrics are always present");

    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("server responded in time")
        .expect("captured request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/custom/v1/metrics");
    assert_eq!(captured.authorization.as_deref(), Some("Bearer test-token"));
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-protobuf")
    );
    assert!(captured.body_len > 0, "OTLP protobuf body is non-empty");

    server.await.unwrap();
}

#[tokio::test]
async fn export_retries_transient_collector_failures_within_interval() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_requests(listener, vec![500, 500, 200], tx));

    let relay_plane = MarmotRelayPlane::full_history();
    let endpoint = format!("http://{addr}/v1/metrics");
    let exporter = relay_plane
        .telemetry_exporter(
            RelayTelemetryExportConfig::enabled(endpoint.clone())
                .with_interval(Duration::from_secs(1))
                .with_runtime_config(runtime_config(endpoint)),
        )
        .expect("opted-in exporter is constructed");

    let count = exporter
        .export_once_with_retries(None)
        .await
        .expect("retry eventually succeeds");
    assert!(count > 0, "population metrics are always present");

    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("server responded in time")
        .expect("captured requests");
    assert_eq!(captured.len(), 3);
    assert!(
        captured
            .iter()
            .all(|request| request.authorization.as_deref() == Some("Bearer test-token"))
    );
    assert!(
        captured
            .iter()
            .all(|request| request.content_type.as_deref() == Some("application/x-protobuf"))
    );

    server.await.unwrap();
}

#[tokio::test]
async fn running_runtime_pushes_after_telemetry_settings_toggle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let tmp = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let app = MarmotApp::with_relay(tmp.path(), relay.url().await.to_string());
    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.expect("runtime starts");

    runtime
        .set_relay_telemetry_runtime_config(runtime_config(format!("http://{addr}/v1/metrics")))
        .expect("runtime telemetry metadata is accepted");
    runtime
        .set_relay_telemetry_settings(RelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 10,
        })
        .expect("telemetry settings persist");

    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("runtime exporter pushed in time")
        .expect("captured request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/v1/metrics");
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-protobuf")
    );
    assert!(captured.body_len > 0, "OTLP protobuf body is non-empty");

    runtime.shutdown().await;
    server.await.unwrap();
}

#[tokio::test]
async fn running_runtime_pushes_to_default_telemetry_endpoint_when_runtime_endpoint_missing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let tmp = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let config = MarmotAppConfig::default().with_service_endpoints(MarmotServiceEndpoints {
        relay_telemetry_otlp_endpoint: Some(format!("http://{addr}/v1/metrics")),
        audit_log_tracker_endpoint: None,
    });
    let app = MarmotApp::with_relay_and_config(tmp.path(), relay.url().await.to_string(), config);
    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.expect("runtime starts");

    runtime
        .set_relay_telemetry_runtime_config(runtime_config_without_endpoint())
        .expect("runtime telemetry metadata is accepted");
    runtime
        .set_relay_telemetry_settings(RelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 10,
        })
        .expect("telemetry settings persist");

    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("runtime exporter pushed in time")
        .expect("captured request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/v1/metrics");
    assert_eq!(captured.authorization.as_deref(), Some("Bearer test-token"));
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-protobuf")
    );
    assert!(captured.body_len > 0, "OTLP protobuf body is non-empty");

    runtime.shutdown().await;
    server.await.unwrap();
}

#[tokio::test]
async fn runtime_start_pushes_from_persisted_telemetry_settings() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let tmp = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let app = MarmotApp::with_relay(tmp.path(), relay.url().await.to_string());
    app.set_relay_telemetry_settings(RelayTelemetrySettings {
        export_enabled: true,
        export_interval_seconds: 10,
    })
    .expect("telemetry settings persist before start");

    let runtime = MarmotAppRuntime::new(app);
    runtime
        .set_relay_telemetry_runtime_config(runtime_config(format!("http://{addr}/v1/metrics")))
        .expect("runtime telemetry metadata is accepted");
    runtime.start().await.expect("runtime starts");

    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("runtime exporter pushed in time")
        .expect("captured request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/v1/metrics");
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-protobuf")
    );
    assert!(captured.body_len > 0, "OTLP protobuf body is non-empty");

    runtime.shutdown().await;
    server.await.unwrap();
}
