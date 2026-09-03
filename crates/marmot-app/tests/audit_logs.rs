use marmot_account::AccountHome;
use marmot_app::{
    AuditLogSettings, AuditLogTrackerConfig, AuditLogUploadSource, MarmotApp, MarmotAppConfig,
    MarmotAppRuntime, MarmotServiceEndpoints,
};
use nostr_relay_builder::MockRelay;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct CapturedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    device_label: Option<String>,
    platform: Option<String>,
    app_version: Option<String>,
    body: Vec<u8>,
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

async fn capture_one_request(listener: TcpListener, tx: oneshot::Sender<CapturedRequest>) {
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };
    let Some(request) = read_captured_request(&mut stream).await else {
        return;
    };
    write_http_response(&mut stream, 204).await;
    let _ = stream.shutdown().await;
    let _ = tx.send(request);
}

async fn capture_requests(
    listener: TcpListener,
    tx: oneshot::Sender<Vec<CapturedRequest>>,
    statuses: Vec<u16>,
) {
    let mut requests = Vec::new();
    for status in statuses {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let Some(request) = read_captured_request(&mut stream).await else {
            return;
        };
        write_http_response(&mut stream, status).await;
        let _ = stream.shutdown().await;
        requests.push(request);
    }
    let _ = tx.send(requests);
}

async fn read_captured_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
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
        let authorization = header_value(&headers, "authorization");
        let content_type = header_value(&headers, "content-type");
        let device_label = header_value(&headers, "x-goggles-device-label");
        let platform = header_value(&headers, "x-goggles-platform");
        let app_version = header_value(&headers, "x-goggles-app-version");
        let body = buf[header_end..header_end + content_length].to_vec();

        return Some(CapturedRequest {
            method,
            path,
            authorization,
            content_type,
            device_label,
            platform,
            app_version,
            body,
        });
    }
}

async fn write_http_response(stream: &mut TcpStream, status: u16) {
    let reason = if status == 204 {
        "No Content"
    } else {
        "Test Response"
    };
    let response = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
}

#[tokio::test]
async fn post_audit_log_tracker_update_uses_configured_goggles_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let audit_body = b"{\"seq\":1}\n{\"seq\":2}\n";
    let audit_path = home
        .account_dir(&account.label)
        .join("audit-tracker-update.jsonl");
    std::fs::write(&audit_path, audit_body).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("goggles_dev_secret".to_owned()),
            source: AuditLogUploadSource {
                device_label: Some("Alice iPhone".to_owned()),
                platform: Some("ios".to_owned()),
                app_version: Some("2026.6.8".to_owned()),
            },
        })
        .unwrap();

    let result = runtime.post_audit_log_tracker_update().await.unwrap();

    assert!(result.enabled);
    assert_eq!(result.skipped_reason, None);
    assert_eq!(result.uploaded.len(), 1);
    assert_eq!(result.uploaded[0].status, 204);
    assert_eq!(result.uploaded[0].bytes_sent, audit_body.len() as u64);

    let captured = rx.await.unwrap();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/audit-logs/");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer goggles_dev_secret")
    );
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-ndjson")
    );
    assert_eq!(captured.device_label.as_deref(), Some("Alice iPhone"));
    assert_eq!(captured.platform.as_deref(), Some("ios"));
    assert_eq!(captured.app_version.as_deref(), Some("2026.6.8"));
    assert_eq!(captured.body, audit_body);
    server.await.unwrap();
}

#[tokio::test]
async fn post_audit_log_tracker_update_uses_default_endpoint_with_host_token() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let audit_body = b"{\"seq\":1}\n";
    let audit_path = home
        .account_dir(&account.label)
        .join("audit-default-endpoint.jsonl");
    std::fs::write(&audit_path, audit_body).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let config = MarmotAppConfig::default().with_service_endpoints(MarmotServiceEndpoints {
        relay_telemetry_otlp_endpoint: None,
        audit_log_tracker_endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
        encrypted_media_blob_endpoints: Vec::new(),
        profile_image_blob_endpoint: None,
        ..MarmotServiceEndpoints::default()
    });
    let app = MarmotApp::with_relay_and_config(tmp.path(), "wss://relay.example", config);
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: None,
            authorization_bearer_token: Some("goggles_client_secret".to_owned()),
            source: AuditLogUploadSource {
                device_label: Some("Alice iPhone".to_owned()),
                platform: Some("ios".to_owned()),
                app_version: Some("2026.6.8".to_owned()),
            },
        })
        .unwrap();

    let result = runtime.post_audit_log_tracker_update().await.unwrap();

    assert!(result.enabled);
    assert_eq!(result.skipped_reason, None);
    assert_eq!(result.uploaded.len(), 1);
    assert_eq!(result.uploaded[0].status, 204);

    let captured = rx.await.unwrap();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/audit-logs/");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer goggles_client_secret")
    );
    assert_eq!(captured.platform.as_deref(), Some("ios"));
    assert_eq!(captured.body, audit_body);
    server.await.unwrap();
}

#[tokio::test]
async fn post_audit_log_tracker_update_continues_after_file_upload_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let failed_body = b"{\"seq\":1}\n";
    let successful_body = b"{\"seq\":2}\n";
    std::fs::write(
        home.account_dir(&account.label)
            .join("audit-0001-fails.jsonl"),
        failed_body,
    )
    .unwrap();
    std::fs::write(
        home.account_dir(&account.label)
            .join("audit-0002-succeeds.jsonl"),
        successful_body,
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_requests(listener, tx, vec![500, 204]));

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("goggles_dev_secret".to_owned()),
            source: AuditLogUploadSource::default(),
        })
        .unwrap();

    let result = runtime.post_audit_log_tracker_update().await.unwrap();

    assert!(result.enabled);
    assert_eq!(result.skipped_reason, None);
    assert_eq!(result.uploaded.len(), 1);
    assert_eq!(result.uploaded[0].status, 204);
    assert_eq!(result.uploaded[0].bytes_sent, successful_body.len() as u64);

    let captured = rx.await.unwrap();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].body, failed_body);
    assert_eq!(captured[1].body, successful_body);
    server.await.unwrap();
}

#[tokio::test]
async fn post_audit_log_tracker_update_skips_when_disabled_or_unconfigured() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    std::fs::write(
        home.account_dir(&account.label)
            .join("audit-tracker-skip.jsonl"),
        b"{\"seq\":1}\n",
    )
    .unwrap();

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());

    let disabled = runtime.post_audit_log_tracker_update().await.unwrap();
    assert!(!disabled.enabled);
    assert!(disabled.uploaded.is_empty());
    assert_eq!(
        disabled.skipped_reason.as_deref(),
        Some("audit logging disabled")
    );

    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let missing_endpoint = runtime.post_audit_log_tracker_update().await.unwrap();
    assert!(missing_endpoint.enabled);
    assert!(missing_endpoint.uploaded.is_empty());
    assert_eq!(
        missing_endpoint.skipped_reason.as_deref(),
        Some("audit log tracker endpoint missing")
    );

    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some("http://127.0.0.1:9/api/v1/audit-logs/".to_owned()),
            authorization_bearer_token: None,
            source: AuditLogUploadSource::default(),
        })
        .unwrap();
    let missing_token = runtime.post_audit_log_tracker_update().await.unwrap();
    assert!(missing_token.enabled);
    assert!(missing_token.uploaded.is_empty());
    assert_eq!(
        missing_token.skipped_reason.as_deref(),
        Some("audit log tracker authorization token missing")
    );
}

#[test]
fn audit_log_files_lists_local_jsonl_logs() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let audit_path = home.account_dir(&account.label).join("audit-abc123.jsonl");
    std::fs::write(
        &audit_path,
        b"{\"schema_version\":\"marmot-forensics-audit/v1\"}\n",
    )
    .unwrap();

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let files = app.audit_log_files().unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].account_ref, "alice");
    assert_eq!(files[0].file_name, "audit-abc123.jsonl");
    assert_eq!(files[0].path, audit_path.to_string_lossy());
    assert!(files[0].size_bytes > 0);
}

#[tokio::test]
async fn post_audit_log_file_posts_jsonl_body() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let audit_body = b"{\"seq\":1}\n{\"seq\":2}\n";
    let audit_path = home
        .account_dir(&account.label)
        .join("audit-feedface.jsonl");
    std::fs::write(&audit_path, audit_body).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let result = app
        .post_audit_log_file(
            &audit_path.to_string_lossy(),
            &format!("http://{addr}/ingest"),
        )
        .await
        .unwrap();

    assert_eq!(result.status, 204);
    assert_eq!(result.bytes_sent, audit_body.len() as u64);

    let captured = rx.await.unwrap();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/ingest");
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-ndjson")
    );
    assert_eq!(captured.body, audit_body);
    server.await.unwrap();
}

#[tokio::test]
async fn post_audit_log_file_rejects_remote_endpoint_without_token() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let audit_path = home
        .account_dir(&account.label)
        .join("audit-unauthenticated-remote.jsonl");
    std::fs::write(&audit_path, b"{\"seq\":1}\n").unwrap();

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let err = app
        .post_audit_log_file(
            &audit_path.to_string_lossy(),
            "https://goggles.example/api/v1/audit-logs/",
        )
        .await
        .expect_err("remote forensic audit upload should require authorization");

    assert!(
        err.to_string().contains("authorization bearer token"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn post_audit_log_file_rejects_oversized_files_before_upload() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let audit_path = home.account_dir(&account.label).join("audit-huge.jsonl");
    let file = std::fs::File::create(&audit_path).unwrap();
    file.set_len(64 * 1024 * 1024 + 1).unwrap();

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let err = app
        .post_audit_log_file(&audit_path.to_string_lossy(), "http://127.0.0.1:9/ingest")
        .await
        .expect_err("oversized audit log should be rejected");

    assert!(
        err.to_string().contains("upload limit"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn audit_log_setting_enables_jsonl_recorder_for_opened_accounts() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");

    let client = app.client(&account.label).await.unwrap();
    assert!(
        app.audit_log_files().unwrap().is_empty(),
        "audit logs should be off by default"
    );
    drop(client);

    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let _client = app.client(&account.label).await.unwrap();

    let files = app.audit_log_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].account_ref, "alice");
    assert!(files[0].file_name.starts_with("audit-"));
    assert!(files[0].file_name.ends_with(".jsonl"));
}

#[tokio::test]
async fn local_group_action_writes_human_action_context() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();

    let mut client = app.client(&account.label).await.unwrap();
    client.create_group("audit actions", &[]).await.unwrap();

    let files = app.audit_log_files().unwrap();
    assert_eq!(files.len(), 1);
    let body = std::fs::read_to_string(&files[0].path).unwrap();
    let events = body
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    let human_action = events
        .iter()
        .find(|event| {
            event["kind"]["type"] == "human_action"
                && event["kind"]["action"] == "create_group"
                && event["kind"]["phase"] == "succeeded"
        })
        .expect("create_group should write a human_action audit row");
    assert_eq!(human_action["kind"]["origin"], "local_user");
    assert!(
        human_action["kind"]["fields"]
            .as_array()
            .unwrap()
            .contains(&Value::String("name".into()))
    );
    assert!(
        human_action["kind"]["fields"]
            .as_array()
            .unwrap()
            .contains(&Value::String("members".into()))
    );

    let create_entry = events
        .iter()
        .find(|event| event["kind"]["type"] == "create_group_entry")
        .expect("create_group should write a create_group_entry audit row");
    assert_eq!(
        create_entry["context"]["human_action"]["action"],
        "create_group"
    );
    assert_eq!(
        create_entry["context"]["human_action"]["origin"],
        "local_user"
    );
}

#[tokio::test]
async fn local_message_send_tags_engine_rows_with_human_action() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay_and_config(
        tmp.path(),
        relay_url,
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();

    let mut client = app.client(&account.label).await.unwrap();
    let group_id = client.create_group("audit actions", &[]).await.unwrap();
    client
        .send(&group_id, b"hello marmots")
        .await
        .expect("mock relay should accept the audited send");

    let files = app.audit_log_files().unwrap();
    let body = std::fs::read_to_string(&files[0].path).unwrap();
    let events = body
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    // The app threads the human action through `send_with_audit_context`, so the
    // engine's `send_entry` row carries it (previously context-free for sends).
    let send_entry = events
        .iter()
        .find(|event| event["kind"]["type"] == "send_entry")
        .expect("send should write a send_entry audit row");
    assert_eq!(
        send_entry["context"]["human_action"]["action"],
        "send_message"
    );
    assert_eq!(
        send_entry["context"]["human_action"]["origin"],
        "local_user"
    );

    // The engine's ambient operation context backfills the secondary
    // `message_state_changed` row, which the engine emits context-free.
    let state_changed = events
        .iter()
        .find(|event| {
            event["kind"]["type"] == "message_state_changed"
                && event["context"]["human_action"]["action"] == "send_message"
        })
        .expect("send's message_state_changed row should inherit the human action");
    assert_eq!(
        state_changed["context"]["human_action"]["origin"],
        "local_user"
    );
}

// ---------------------------------------------------------------------------
// Incremental upload contract (mdk#1181)
// ---------------------------------------------------------------------------

/// Capture sink that stays up across many tracker runs, so a test can assert on
/// what was *not* re-transferred as well as what was.
// The pacing/concurrency knobs exist for the coalescing regression, which needs
// the `test-policy-overrides` trigger seam; without that feature they are unused.
#[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
struct CaptureSink {
    addr: std::net::SocketAddr,
    requests: std::sync::Arc<std::sync::Mutex<Vec<CapturedRequest>>>,
    statuses: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u16>>>,
    /// Milliseconds a handler holds a request open before answering, so a test
    /// can schedule more triggers while an upload is genuinely in flight.
    hold_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
    default_status: std::sync::Arc<std::sync::atomic::AtomicU16>,
    in_flight: std::sync::Arc<std::sync::Mutex<(usize, usize)>>,
    handle: tokio::task::JoinHandle<()>,
}

#[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
impl CaptureSink {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let statuses = std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::<u16>::new(),
        ));
        let hold_ms = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let default_status = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(204));
        let in_flight = std::sync::Arc::new(std::sync::Mutex::new((0_usize, 0_usize)));
        let handle = tokio::spawn({
            use std::sync::atomic::Ordering;
            let requests = requests.clone();
            let statuses = statuses.clone();
            let hold_ms = hold_ms.clone();
            let default_status = default_status.clone();
            let in_flight = in_flight.clone();
            async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let requests = requests.clone();
                    let statuses = statuses.clone();
                    let hold_ms = hold_ms.clone();
                    let default_status = default_status.clone();
                    let in_flight = in_flight.clone();
                    // One task per connection so overlapping uploads are
                    // observable instead of serialized behind `accept`.
                    tokio::spawn(async move {
                        let Some(request) = read_captured_request(&mut stream).await else {
                            return;
                        };
                        {
                            let mut counts = in_flight.lock().unwrap();
                            counts.0 += 1;
                            counts.1 = counts.1.max(counts.0);
                        }
                        let hold = hold_ms.load(Ordering::Relaxed);
                        if hold > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(hold)).await;
                        }
                        let status = statuses
                            .lock()
                            .unwrap()
                            .pop_front()
                            .unwrap_or_else(|| default_status.load(Ordering::Relaxed));
                        // Record the body before answering, after the hold: once the
                        // response is written the client may fire its next request,
                        // and the order-asserting tests need bodies pushed in serve
                        // order. Pushing before the hold would instead expose a body
                        // while its request is still deliberately in flight, which
                        // the coalescing test's contract cannot tolerate.
                        requests.lock().unwrap().push(request);
                        write_http_response(&mut stream, status).await;
                        let _ = stream.shutdown().await;
                        in_flight.lock().unwrap().0 -= 1;
                    });
                }
            }
        });
        Self {
            addr,
            requests,
            statuses,
            hold_ms,
            default_status,
            in_flight,
            handle,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}/api/v1/audit-logs/", self.addr)
    }

    fn script(&self, statuses: &[u16]) {
        *self.statuses.lock().unwrap() = statuses.iter().copied().collect();
    }

    fn hold_each_request_for(&self, millis: u64) {
        self.hold_ms
            .store(millis, std::sync::atomic::Ordering::Relaxed);
    }

    fn always_answer(&self, status: u16) {
        self.default_status
            .store(status, std::sync::atomic::Ordering::Relaxed);
    }

    fn max_concurrent_requests(&self) -> usize {
        self.in_flight.lock().unwrap().1
    }

    fn take_bodies(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.requests.lock().unwrap())
            .into_iter()
            .map(|request| request.body)
            .collect()
    }
}

impl Drop for CaptureSink {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn tracker_runtime(root: &std::path::Path, endpoint: &str) -> MarmotAppRuntime {
    let app = MarmotApp::with_relay(root, "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    runtime
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(endpoint.to_owned()),
            authorization_bearer_token: Some("goggles_dev_secret".to_owned()),
            source: AuditLogUploadSource::default(),
        })
        .unwrap();
    runtime
}

fn checkpoint_path(home: &AccountHome, label: &str) -> std::path::PathBuf {
    home.account_dir(label).join("audit-upload-checkpoint.json")
}

#[tokio::test]
async fn acknowledged_audit_files_are_not_re_posted_without_new_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let sealed = b"{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3}\n";
    std::fs::write(
        home.account_dir(&account.label)
            .join("audit-engine-v3-seg000001.jsonl"),
        sealed,
    )
    .unwrap();

    let sink = CaptureSink::start().await;
    let runtime = tracker_runtime(tmp.path(), &sink.endpoint());

    let first = runtime.post_audit_log_tracker_update().await.unwrap();
    assert_eq!(first.uploaded.len(), 1);
    assert_eq!(sink.take_bodies(), vec![sealed.to_vec()]);

    for _ in 0..5 {
        let repeat = runtime.post_audit_log_tracker_update().await.unwrap();
        assert!(repeat.uploaded.is_empty(), "{repeat:?}");
    }
    assert!(
        sink.take_bodies().is_empty(),
        "an acknowledged segment must never be re-read or re-posted"
    );
}

#[tokio::test]
async fn appending_a_suffix_transfers_only_the_changed_file() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let dir = home.account_dir(&account.label);
    let sealed = b"{\"seq\":1}\n";
    std::fs::write(dir.join("audit-engine-v3-seg000001.jsonl"), sealed).unwrap();
    std::fs::write(dir.join("audit-engine-v3.jsonl"), b"{\"seq\":2}\n").unwrap();

    let sink = CaptureSink::start().await;
    let runtime = tracker_runtime(tmp.path(), &sink.endpoint());

    runtime.post_audit_log_tracker_update().await.unwrap();
    assert_eq!(sink.take_bodies().len(), 2);

    // A new immutable segment plus growth of the active file.
    std::fs::write(
        dir.join("audit-engine-v3-seg000002.jsonl"),
        b"{\"seq\":3}\n",
    )
    .unwrap();
    let active = b"{\"seq\":2}\n{\"seq\":4}\n";
    std::fs::write(dir.join("audit-engine-v3.jsonl"), active).unwrap();

    runtime.post_audit_log_tracker_update().await.unwrap();

    let bodies = sink.take_bodies();
    assert_eq!(
        bodies,
        vec![b"{\"seq\":3}\n".to_vec(), active.to_vec()],
        "only the new segment and the grown active file should transfer"
    );
}

#[tokio::test]
async fn acknowledgement_survives_restart_and_a_lost_checkpoint_costs_one_repeat() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let sealed = b"{\"seq\":1}\n";
    std::fs::write(
        home.account_dir(&account.label)
            .join("audit-engine-v3-seg000001.jsonl"),
        sealed,
    )
    .unwrap();

    let sink = CaptureSink::start().await;
    {
        let runtime = tracker_runtime(tmp.path(), &sink.endpoint());
        runtime.post_audit_log_tracker_update().await.unwrap();
    }
    assert_eq!(sink.take_bodies().len(), 1);

    // Restart after acknowledgement: nothing re-transfers.
    {
        let runtime = tracker_runtime(tmp.path(), &sink.endpoint());
        runtime.post_audit_log_tracker_update().await.unwrap();
    }
    assert!(sink.take_bodies().is_empty());

    // Checkpoint loss is bounded: exactly one repeat transfer, which the
    // endpoint's whole-file dedupe absorbs, and then quiet again.
    std::fs::remove_file(checkpoint_path(&home, &account.label)).unwrap();
    {
        let runtime = tracker_runtime(tmp.path(), &sink.endpoint());
        runtime.post_audit_log_tracker_update().await.unwrap();
        assert_eq!(sink.take_bodies(), vec![sealed.to_vec()]);
        runtime.post_audit_log_tracker_update().await.unwrap();
    }
    assert!(sink.take_bodies().is_empty());
}

#[tokio::test]
async fn failed_uploads_retry_while_acknowledged_files_do_not() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let dir = home.account_dir(&account.label);
    let failing = b"{\"seq\":1}\n";
    let succeeding = b"{\"seq\":2}\n";
    std::fs::write(dir.join("audit-engine-v3-seg000001.jsonl"), failing).unwrap();
    std::fs::write(dir.join("audit-engine-v3-seg000002.jsonl"), succeeding).unwrap();

    let sink = CaptureSink::start().await;
    sink.script(&[500, 204]);
    let runtime = tracker_runtime(tmp.path(), &sink.endpoint());

    let first = runtime.post_audit_log_tracker_update().await.unwrap();
    assert_eq!(first.uploaded.len(), 1);
    assert_eq!(
        sink.take_bodies(),
        vec![failing.to_vec(), succeeding.to_vec()]
    );

    let second = runtime.post_audit_log_tracker_update().await.unwrap();
    assert_eq!(second.uploaded.len(), 1);
    assert_eq!(
        sink.take_bodies(),
        vec![failing.to_vec()],
        "only the unacknowledged file retries"
    );
}

#[tokio::test]
async fn oversized_legacy_file_is_reported_once_and_never_wedges_other_uploads() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let dir = home.account_dir(&account.label);
    // Upgrade path: an active file grown past the request ceiling by a build
    // without segment rotation. It sorts first, so it also proves the oversized
    // file does not block the files behind it.
    let huge = std::fs::File::create(dir.join("audit-engine-v3-seg000001.jsonl")).unwrap();
    huge.set_len(64 * 1024 * 1024 + 1).unwrap();
    let normal = b"{\"seq\":1}\n";
    std::fs::write(dir.join("audit-engine-v3.jsonl"), normal).unwrap();

    let sink = CaptureSink::start().await;
    let runtime = tracker_runtime(tmp.path(), &sink.endpoint());

    let first = runtime.post_audit_log_tracker_update().await.unwrap();
    assert_eq!(first.uploaded.len(), 1);
    assert_eq!(sink.take_bodies(), vec![normal.to_vec()]);
    // Never deleted or truncated: retention is mdk#1014's contract.
    assert_eq!(
        std::fs::metadata(dir.join("audit-engine-v3-seg000001.jsonl"))
            .unwrap()
            .len(),
        64 * 1024 * 1024 + 1
    );

    // The verdict is recorded, which is what makes the skip a one-time report
    // rather than a silent re-evaluation on every trigger. Asserted through the
    // sidecar because the skip never reaches the network, so the capture sink
    // cannot tell "recorded once" from "retried forever" on its own.
    let checkpoint = std::fs::read_to_string(checkpoint_path(&home, &account.label))
        .expect("checkpoint written");
    let checkpoint: serde_json::Value = serde_json::from_str(&checkpoint).unwrap();
    assert_eq!(
        checkpoint["files"]["audit-engine-v3-seg000001.jsonl"]["outcome"],
        serde_json::json!("too_large_to_upload")
    );
    assert_eq!(
        checkpoint["files"]["audit-engine-v3.jsonl"]["outcome"],
        serde_json::json!("uploaded")
    );

    // A second run neither retries the oversized file nor re-posts the small
    // one it already acknowledged.
    runtime.post_audit_log_tracker_update().await.unwrap();
    assert!(sink.take_bodies().is_empty());
}

#[tokio::test]
async fn recorder_segments_upload_once_each_and_stay_under_the_request_ceiling() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let path = home
        .account_dir(&account.label)
        .join("audit-00112233445566778899aabbccddeeff-v3.jsonl");
    let recorder = marmot_forensics::JsonlRecorder::open(&path, "0011".repeat(8)).unwrap();
    {
        use marmot_forensics::ForensicRecorder as _;
        // Enough rows to seal several segments at the recorder's threshold.
        while std::fs::read_dir(home.account_dir(&account.label))
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains("-seg"))
            .count()
            < 2
        {
            recorder.record(marmot_forensics::AuditRecord::new(
                None,
                marmot_forensics::AuditEventKind::SendEntry {
                    intent_kind: "app_message".into(),
                },
            ));
        }
    }

    let sink = CaptureSink::start().await;
    let runtime = tracker_runtime(tmp.path(), &sink.endpoint());
    runtime.post_audit_log_tracker_update().await.unwrap();

    let bodies = sink.take_bodies();
    assert_eq!(bodies.len(), 3, "two sealed segments plus the active file");
    for body in &bodies {
        assert!(
            (body.len() as u64) < 64 * 1024 * 1024,
            "every transfer must stay under the per-request ceiling"
        );
        assert!((body.len() as u64) < 2 * marmot_forensics::AUDIT_LOG_SEGMENT_MAX_BYTES);
    }

    // No new rows: nothing at all is re-read or re-posted.
    runtime.post_audit_log_tracker_update().await.unwrap();
    assert!(sink.take_bodies().is_empty());
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn trigger_bursts_coalesce_into_one_follow_up_run() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let dir = home.account_dir(&account.label);
    std::fs::write(dir.join("audit-engine-v3.jsonl"), b"{\"seq\":1}\n").unwrap();

    let sink = CaptureSink::start().await;
    // Hold each upload open so the burst lands while a run is in flight, which
    // is the case the coalescing contract is about, and refuse every upload so
    // nothing is ever acknowledged — then each run posts, and the request count
    // measures runs rather than changed content.
    sink.hold_each_request_for(400);
    sink.always_answer(500);
    let runtime = tracker_runtime(tmp.path(), &sink.endpoint());

    runtime.schedule_audit_log_tracker_update_for_test("burst");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    for _ in 0..50 {
        runtime.schedule_audit_log_tracker_update_for_test("burst");
    }
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;

    // 50 triggers arriving during a run collapse into exactly one follow-up,
    // and no two uploads are ever in flight at once.
    assert_eq!(
        sink.take_bodies().len(),
        2,
        "a burst during an in-flight run must produce one follow-up, not one run per trigger"
    );
    assert_eq!(
        sink.max_concurrent_requests(),
        1,
        "tracker updates must never upload concurrently"
    );
}
