use super::*;
use marmot_forensics::audit::{
    AuditEventKind, AuditRecord, ForensicRecorder, JsonlRecorder, default_jsonl_path,
};
use marmot_forensics::local_delivery::{DeliveryStep, LocalAuditDelivery, Preparation};
use std::io::Write as _;
use std::process::{Command, Stdio};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn prepared() -> (
    TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    DeliveryBatch,
) {
    let dir = TempDir::new().unwrap();
    let active = default_jsonl_path(dir.path(), "engine-abc");
    let state = dir.path().join("delivery");
    let recorder = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "quote \" and \\ slash".into(),
        },
    ));
    let mut owner = LocalAuditDelivery::open(&active, &state, "audit-gateway").unwrap();
    let batch = match owner.prepare_once().unwrap() {
        Preparation::Batch(batch) => batch,
        other => panic!("expected batch: {other:?}"),
    };
    drop(owner);
    (dir, active, state, batch)
}

struct Request {
    headers: String,
    body: Vec<u8>,
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Request {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0, "request ended before headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let length: usize = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse().ok())
        })
        .unwrap();
    while bytes.len() - header_end < length {
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0, "request ended before body");
        bytes.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(bytes.len() - header_end, length);
    Request {
        headers,
        body: bytes[header_end..].to_vec(),
    }
}

async fn service(reply: Vec<u8>) -> (String, tokio::task::JoinHandle<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        stream.write_all(&reply).await.unwrap();
        request
    });
    (endpoint, task)
}

fn reply(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[tokio::test]
async fn exact_original_bodies_and_full_success_advance_after_reacquiring_ownership() {
    let (_dir, active, state, batch) = prepared();
    let token = batch.token.clone();
    let original_bodies: Vec<String> = batch
        .bodies
        .iter()
        .map(|line| String::from_utf8(line.strip_suffix(b"\n").unwrap().to_vec()).unwrap())
        .collect();
    let (endpoint, service) = service(reply(200, "{}")).await;
    let sender = AuditOtlpSender::for_loopback_dev(endpoint, "dedicated-test-token").unwrap();
    assert!(!format!("{sender:?}").contains("dedicated-test-token"));
    assert_eq!(sender.send(batch).await, AuditOtlpSendResult::Complete);
    let request = service.await.unwrap();
    assert!(request.headers.starts_with("POST /v1/logs HTTP/1.1\r\n"));
    assert!(
        request
            .headers
            .contains("content-type: application/json\r\n")
    );
    assert!(
        request
            .headers
            .contains("authorization: Bearer dedicated-test-token\r\n")
    );
    assert_eq!(request.headers.matches("content-length:").count(), 1);
    assert!(!request.headers.contains("content-encoding:"));
    assert!(!request.headers.contains("transfer-encoding:"));
    let wire: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(wire.as_object().unwrap().len(), 1);
    assert_eq!(wire["resourceLogs"].as_array().unwrap().len(), 1);
    assert_eq!(wire["resourceLogs"][0].as_object().unwrap().len(), 1);
    let scope = &wire["resourceLogs"][0]["scopeLogs"][0];
    assert_eq!(scope.as_object().unwrap().len(), 2);
    assert_eq!(scope["scope"], serde_json::json!({"name":"marmot.audit"}));
    assert_eq!(
        scope["logRecords"].as_array().unwrap().len(),
        original_bodies.len()
    );
    for (record, original_body) in scope["logRecords"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&original_bodies)
    {
        assert_eq!(
            record,
            &serde_json::json!({"body":{"stringValue":original_body}})
        );
    }
    let mut owner = LocalAuditDelivery::open(&active, &state, "audit-gateway").unwrap();
    assert_eq!(
        owner
            .finish(&token, AuditOtlpSendResult::Complete.for_finish().unwrap())
            .unwrap(),
        DeliveryStep::Accepted
    );
    assert_eq!(
        owner.prepare_once().unwrap(),
        Preparation::Step(DeliveryStep::Idle)
    );
}

#[tokio::test]
async fn response_contract_classifies_only_exact_200_as_complete() {
    let (_dir, _active, _state, batch) = prepared();
    for (status, body, expected) in [
        (409, "{}", AuditOtlpSendResult::Partial),
        (503, "{}", AuditOtlpSendResult::Retryable),
        (429, "{}", AuditOtlpSendResult::Retryable),
        (400, "{}", AuditOtlpSendResult::Blocked),
        (401, "{}", AuditOtlpSendResult::Blocked),
        (413, "{}", AuditOtlpSendResult::Blocked),
        (204, "", AuditOtlpSendResult::Blocked),
        (202, "{}", AuditOtlpSendResult::Blocked),
        (200, "", AuditOtlpSendResult::Blocked),
        (200, "{\"partialSuccess\":{}}", AuditOtlpSendResult::Blocked),
        (200, "{", AuditOtlpSendResult::Blocked),
        (200, "{} ", AuditOtlpSendResult::Blocked),
    ] {
        let (endpoint, task) = service(reply(status, body)).await;
        let sender = AuditOtlpSender::for_loopback_dev(endpoint, "token").unwrap();
        assert_eq!(
            sender.send(batch.clone()).await,
            expected,
            "status {status}"
        );
        task.await.unwrap();
    }
    let (endpoint, task) = service(reply(503, &"x".repeat(MAX_RESPONSE_BYTES + 1))).await;
    let sender = AuditOtlpSender::for_loopback_dev(endpoint, "token").unwrap();
    assert_eq!(
        sender.send(batch.clone()).await,
        AuditOtlpSendResult::Retryable
    );
    task.await.unwrap();
    assert_eq!(AuditOtlpSendResult::Unknown.for_finish(), None);
    assert_eq!(
        AuditOtlpSendResult::Blocked.for_finish(),
        Some(ReceiverResult::Permanent)
    );
}

#[tokio::test]
async fn lost_or_unreadable_response_keeps_identical_prepared_bodies() {
    let (_dir, active, state, batch) = prepared();
    let original = batch.bodies.clone();
    let token = batch.token.clone();

    let (endpoint, task) = service(Vec::new()).await;
    let sender = AuditOtlpSender::for_loopback_dev(endpoint, "token").unwrap();
    assert_eq!(sender.send(batch).await, AuditOtlpSendResult::Unknown);
    let first_request = task.await.unwrap();

    let mut owner = LocalAuditDelivery::open(&active, &state, "audit-gateway").unwrap();
    let replay = match owner.prepare_once().unwrap() {
        Preparation::Batch(batch) => batch,
        other => panic!("expected replay: {other:?}"),
    };
    assert_eq!(replay.token, token);
    assert_eq!(replay.bodies, original);
    drop(owner);
    let (endpoint, task) = service(reply(200, "{}")).await;
    let sender = AuditOtlpSender::for_loopback_dev(endpoint, "token").unwrap();
    assert_eq!(sender.send(replay).await, AuditOtlpSendResult::Complete);
    let retried = task.await.unwrap();
    assert_eq!(retried.body, first_request.body);
    let wire: serde_json::Value = serde_json::from_slice(&retried.body).unwrap();
    assert_eq!(
        wire["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"],
        String::from_utf8(original[0][..original[0].len() - 1].to_vec()).unwrap()
    );

    let (endpoint, task) =
        service(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}".to_vec()).await;
    let sender = AuditOtlpSender::for_loopback_dev(endpoint, "token").unwrap();
    let mut owner = LocalAuditDelivery::open(&active, &state, "audit-gateway").unwrap();
    let replay = match owner.prepare_once().unwrap() {
        Preparation::Batch(batch) => batch,
        other => panic!("expected replay: {other:?}"),
    };
    drop(owner);
    assert_eq!(sender.send(replay).await, AuditOtlpSendResult::Unknown);
    task.await.unwrap();
}

#[tokio::test]
async fn timeout_after_acceptance_is_unknown() {
    let (_dir, active, state, batch) = prepared();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        request
    });
    let mut sender = AuditOtlpSender::for_loopback_dev(endpoint, "token").unwrap();
    sender.timeout = Duration::from_millis(50);
    assert_eq!(sender.send(batch).await, AuditOtlpSendResult::Unknown);
    task.await.unwrap();
    let mut owner = LocalAuditDelivery::open(&active, &state, "audit-gateway").unwrap();
    assert!(matches!(
        owner.prepare_once().unwrap(),
        Preparation::Batch(_)
    ));
}

#[test]
fn endpoint_and_batch_limits_are_checked_before_network() {
    for endpoint in [
        "http://example.org/v1/logs",
        "http://127.0.0.1/v1/logs",
        "https://example.org/v1/metrics",
        "https://example.org/v1/logs?tenant=x",
        "https://user:pass@example.org/v1/logs",
    ] {
        assert!(AuditOtlpSender::new(endpoint, "token").is_err());
    }
    assert!(AuditOtlpSender::new("https://example.org/v1/logs", "\r\ntoken").is_err());
    let (_dir, _active, _state, mut batch) = prepared();
    batch.bodies[0].extend_from_slice(b"extra");
    assert!(encode_batch(batch).is_none());
}

/// Run explicitly where the pinned Python receiver dependency is available.
/// It feeds this sender's actual wire bytes into #1997's reference validator.
#[test]
#[ignore = "requires uv and the #1997 Python reference receiver"]
fn reference_receiver_accepts_exact_sender_wire() {
    let (_dir, _active, _state, batch) = prepared();
    let original = batch.bodies.concat();
    let wire = encode_batch(batch).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut child = Command::new("uv")
        .current_dir(root)
        .args([
            "run",
            "--with",
            "jsonschema==4.25.1",
            "python",
            "-c",
            "import sys; sys.path.insert(0, 'scripts/audit-otlp-receiver'); from receiver import validate_batch; rows = validate_batch(sys.stdin.buffer.read()); sys.stdout.buffer.write(b''.join(body.encode('utf-8') + b'\\n' for body, _ in rows))",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&wire).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "reference receiver rejected sender wire"
    );
    assert_eq!(output.stdout, original);
}
