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

const TEST_DESTINATION: &str = "audit-gateway";

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
    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
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
    let sender =
        AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "dedicated-test-token")
            .unwrap();
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
    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
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
        (403, "{}", AuditOtlpSendResult::Blocked),
        (404, "{}", AuditOtlpSendResult::Blocked),
        (408, "{}", AuditOtlpSendResult::Blocked),
        (413, "{}", AuditOtlpSendResult::Blocked),
        (302, "{}", AuditOtlpSendResult::Blocked),
        (204, "", AuditOtlpSendResult::Blocked),
        (202, "{}", AuditOtlpSendResult::Blocked),
        (200, "", AuditOtlpSendResult::Blocked),
        (200, "{\"partialSuccess\":{}}", AuditOtlpSendResult::Blocked),
        (200, "{", AuditOtlpSendResult::Blocked),
        (200, "{} ", AuditOtlpSendResult::Blocked),
    ] {
        let (endpoint, task) = service(reply(status, body)).await;
        let sender =
            AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
        assert_eq!(
            sender.send(batch.clone()).await,
            expected,
            "status {status}"
        );
        task.await.unwrap();
    }
    let (endpoint, task) = service(reply(503, &"x".repeat(2048))).await;
    let sender = AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
    assert_eq!(
        sender.send(batch.clone()).await,
        AuditOtlpSendResult::Retryable
    );
    task.await.unwrap();
    assert_eq!(AuditOtlpSendResult::Unknown.for_finish(), None);
    assert_eq!(AuditOtlpSendResult::Blocked.for_finish(), None);
}

#[tokio::test]
async fn parsed_409_blocks_even_if_its_diagnostic_body_is_incomplete_or_stalled() {
    let (_dir, active, state, batch) = prepared();
    let token = batch.token.clone();
    let (endpoint, task) =
        service(b"HTTP/1.1 409 Conflict\r\nContent-Length: 9\r\n\r\n{}".to_vec()).await;
    let sender = AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
    assert_eq!(
        sender.send(batch.clone()).await,
        AuditOtlpSendResult::Partial
    );
    task.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 9\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let mut sender =
        AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
    sender.timeout = Duration::from_millis(50);
    assert_eq!(sender.send(batch).await, AuditOtlpSendResult::Partial);
    task.await.unwrap();

    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
    assert_eq!(
        owner
            .finish(&token, AuditOtlpSendResult::Partial.for_finish().unwrap())
            .unwrap(),
        DeliveryStep::Blocked
    );
}

#[tokio::test]
async fn mismatched_destination_never_dials_or_advances_the_source_cursor() {
    let (_dir, active, state, batch) = prepared();
    let token = batch.token.clone();
    let bodies = batch.bodies.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
    let sender = AuditOtlpSender::for_loopback_dev("other-gateway", endpoint, "token").unwrap();
    let outcome = sender.send(batch).await;
    assert_eq!(outcome, AuditOtlpSendResult::Blocked);
    assert_eq!(outcome.for_finish(), None);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );

    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
    let replay = match owner.prepare_once().unwrap() {
        Preparation::Batch(batch) => batch,
        other => panic!("expected replay: {other:?}"),
    };
    assert_eq!(replay.token, token);
    assert_eq!(replay.bodies, bodies);
}

#[tokio::test]
async fn authentication_rejection_leaves_the_prepared_range_replayable() {
    let (_dir, active, state, batch) = prepared();
    let token = batch.token.clone();
    let (endpoint, task) = service(reply(401, "{}")).await;
    let sender =
        AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "old-token").unwrap();
    let outcome = sender.send(batch).await;
    assert_eq!(outcome, AuditOtlpSendResult::Blocked);
    assert_eq!(outcome.for_finish(), None);
    task.await.unwrap();
    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
    let replay = match owner.prepare_once().unwrap() {
        Preparation::Batch(batch) => batch,
        other => panic!("expected replay: {other:?}"),
    };
    assert_eq!(replay.token, token);
}

#[tokio::test]
async fn lost_or_unreadable_response_keeps_identical_prepared_bodies() {
    let (_dir, active, state, batch) = prepared();
    let original = batch.bodies.clone();
    let token = batch.token.clone();

    let (endpoint, task) = service(Vec::new()).await;
    let sender = AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
    assert_eq!(sender.send(batch).await, AuditOtlpSendResult::Unknown);
    let first_request = task.await.unwrap();

    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
    let replay = match owner.prepare_once().unwrap() {
        Preparation::Batch(batch) => batch,
        other => panic!("expected replay: {other:?}"),
    };
    assert_eq!(replay.token, token);
    assert_eq!(replay.bodies, original);
    drop(owner);
    let (endpoint, task) = service(reply(200, "{}")).await;
    let sender = AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
    assert_eq!(sender.send(replay).await, AuditOtlpSendResult::Complete);
    let retried = task.await.unwrap();
    assert_eq!(retried.body, first_request.body);
    let wire: serde_json::Value = serde_json::from_slice(&retried.body).unwrap();
    assert_eq!(
        wire["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"],
        String::from_utf8(original[0][..original[0].len() - 1].to_vec()).unwrap()
    );

    let (endpoint, task) = service(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{".to_vec(),
    )
    .await;
    let sender = AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
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
    let mut sender =
        AuditOtlpSender::for_loopback_dev(TEST_DESTINATION, endpoint, "token").unwrap();
    sender.timeout = Duration::from_millis(50);
    assert_eq!(sender.send(batch).await, AuditOtlpSendResult::Unknown);
    task.await.unwrap();
    let mut owner = LocalAuditDelivery::open(&active, &state, TEST_DESTINATION).unwrap();
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
        "https://localhost/v1/logs",
    ] {
        assert!(AuditOtlpSender::new(TEST_DESTINATION, endpoint, "token").is_err());
    }
    let retired = crate::retired_relay_hosts();
    let retired_host = &retired[0];
    for host in [
        retired_host.clone(),
        format!("{}.", retired_host.to_ascii_uppercase()),
    ] {
        assert!(
            AuditOtlpSender::new(TEST_DESTINATION, format!("https://{host}/v1/logs"), "token")
                .is_err()
        );
    }
    assert!(AuditOtlpSender::new(TEST_DESTINATION, "https://example.org/v1/logs", "").is_err());
    assert!(
        AuditOtlpSender::new(TEST_DESTINATION, "https://example.org/v1/logs", "\r\ntoken").is_err()
    );
    let (_dir, _active, _state, batch) = prepared();
    let mut invalid = batch.clone();
    invalid.bodies[0].extend_from_slice(b"extra");
    assert!(encode_batch(invalid).is_none());
    let mut empty = batch.clone();
    empty.bodies.clear();
    assert!(encode_batch(empty).is_none());
    let mut too_many = batch.clone();
    too_many.bodies = vec![batch.bodies[0].clone(); MAX_RECORDS + 1];
    assert!(encode_batch(too_many).is_none());
    let mut too_large = batch;
    too_large.bodies[0] = vec![b'a'; MAX_BODY_BYTES + 1];
    too_large.bodies[0].push(b'\n');
    assert!(encode_batch(too_large).is_none());
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
