use marmot_account::AccountHome;
use marmot_app::{AuditLogSettings, MarmotApp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct CapturedRequest {
    method: String,
    path: String,
    content_type: Option<String>,
    body: Vec<u8>,
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
        let content_type = headers.lines().find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-type:")
                .map(|value| value.trim().to_owned())
        });
        let body = buf[header_end..header_end + content_length].to_vec();

        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        let _ = tx.send(CapturedRequest {
            method,
            path,
            content_type,
            body,
        });
        return;
    }
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
