use marmot_account::AccountHome;
use marmot_app::{
    AuditLogSettings, AuditLogTrackerConfig, AuditLogUploadSource, MarmotApp, MarmotAppConfig,
    MarmotAppRuntime, MarmotServiceEndpoints,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct CapturedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    account_label: Option<String>,
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
        let account_label = header_value(&headers, "x-goggles-account-label");
        let device_label = header_value(&headers, "x-goggles-device-label");
        let platform = header_value(&headers, "x-goggles-platform");
        let app_version = header_value(&headers, "x-goggles-app-version");
        let body = buf[header_end..header_end + content_length].to_vec();

        return Some(CapturedRequest {
            method,
            path,
            authorization,
            content_type,
            account_label,
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
                account_label: Some("Alice".to_owned()),
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
    assert_eq!(captured.account_label.as_deref(), Some("Alice"));
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
                account_label: Some("Alice".to_owned()),
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

    let _client = app.client(&account.label).await.unwrap();
    assert!(
        app.audit_log_files().unwrap().is_empty(),
        "audit logs should be off by default"
    );

    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let _client = app.client(&account.label).await.unwrap();

    let files = app.audit_log_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].account_ref, "alice");
    assert!(files[0].file_name.starts_with("audit-"));
    assert!(files[0].file_name.ends_with(".jsonl"));
}
