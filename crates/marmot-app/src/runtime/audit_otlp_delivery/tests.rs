use super::*;
use crate::AuditLogSettings;
use marmot_account::AccountHome;
use marmot_forensics::{AuditEventKind, AuditRecord};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

const DEST: &str = "audit-test-profile";

struct Fixture {
    _temp: tempfile::TempDir,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    active: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = AccountHome::open(temp.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            temp.path(),
            vec![],
            home,
            Default::default(),
        )
        .unwrap();
        app.set_audit_log_settings(AuditLogSettings { enabled: true })
            .unwrap();
        let recorder = app.build_audit_recorder("alice", true);
        recorder.record(AuditRecord::new(
            None,
            AuditEventKind::SendEntry {
                intent_kind: "one original body".into(),
            },
        ));
        let active = recorder.audit_log_path().unwrap();
        drop(recorder);
        let state = app
            .account_dir("alice")
            .join("audit-otlp-delivery/local-delivery.json");
        let runtime = app.runtime();
        Self {
            _temp: temp,
            app,
            runtime,
            active,
            state,
        }
    }

    fn cursor(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(&self.state).unwrap()).unwrap()
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0; 4096];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&chunk[..n]);
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
        let mut chunk = [0; 4096];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&chunk[..n]);
    }
    bytes[header_end..].to_vec()
}

async fn held_receiver(
    status: u16,
) -> (
    String,
    oneshot::Receiver<Vec<u8>>,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
    let (observed, request) = oneshot::channel();
    let (release, proceed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let body = read_request(&mut stream).await;
        observed.send(body).unwrap();
        let _ = proceed.await;
        let reply = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        );
        let _ = stream.write_all(reply.as_bytes()).await;
    });
    (endpoint, request, release, task)
}

fn test_sender(endpoint: String) -> Arc<AuditOtlpSender> {
    Arc::new(AuditOtlpSender::for_loopback_dev(DEST, endpoint, "test-token").unwrap())
}

fn sent_bodies(wire: &[u8]) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_slice(wire).unwrap();
    value["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["body"]["stringValue"].as_str().unwrap().to_owned())
        .collect()
}

async fn request_or_completed<T: std::fmt::Debug>(
    observed: oneshot::Receiver<Vec<u8>>,
    task: &mut tokio::task::JoinHandle<T>,
) -> Vec<u8> {
    tokio::select! {
        wire = observed => wire.unwrap(),
        result = task => panic!("attempt ended before HTTP: {result:?}"),
    }
}

#[test]
fn presend_recheck_rejects_a_changed_prepared_source() {
    let f = Fixture::new();
    let account = f.app.account_home().account("alice").unwrap();
    let attempt = f
        .app
        .audit_export_lifecycle
        .reserve(&account.account_id_hex, DEST)
        .unwrap();
    let active = f.app.audit_delivery_active_path(&account.label).unwrap();
    let state_dir = f
        .app
        .account_dir(&account.label)
        .join("audit-otlp-delivery");
    let Preparation::Batch(batch) = LocalAuditDelivery::open(&active, &state_dir, DEST)
        .unwrap()
        .prepare_once()
        .unwrap()
    else {
        panic!("real recorder should yield a prepared batch");
    };
    assert!(prepared_batch_still_matches(&f.app, &account.label, &attempt, &batch).unwrap());

    let original = std::fs::read_to_string(&active).unwrap();
    let changed = original.replace("one original body", "one replaced body");
    assert_ne!(changed, original);
    assert_eq!(changed.len(), original.len());
    std::fs::write(&active, changed).unwrap();
    assert!(!prepared_batch_still_matches(&f.app, &account.label, &attempt, &batch).unwrap());
}

#[tokio::test]
async fn real_recorder_exact_bodies_success_and_partial_block() {
    let f = Fixture::new();
    let original: Vec<String> = std::fs::read_to_string(&f.active)
        .unwrap()
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    let (endpoint, observed, release, server) = held_receiver(200).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    let wire = request_or_completed(observed, &mut task).await;
    assert_eq!(sent_bodies(&wire), original);
    release.send(()).unwrap();
    assert_eq!(
        task.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Complete,
            local: Some(DeliveryStep::Accepted),
        }
    );
    server.await.unwrap();
    assert!(f.cursor()["journals"][0]["acknowledged"].as_u64().unwrap() > 0);

    // A fresh row gives the same real recorder a second prepared range.
    let recorder = f.app.build_audit_recorder("alice", true);
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "second".into(),
        },
    ));
    drop(recorder);
    let before = f.cursor()["journals"][0]["acknowledged"].clone();
    let (endpoint, observed, release, server) = held_receiver(409).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    request_or_completed(observed, &mut task).await;
    release.send(()).unwrap();
    assert_eq!(
        task.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Partial,
            local: Some(DeliveryStep::Blocked),
        }
    );
    server.await.unwrap();
    assert_eq!(f.cursor()["journals"][0]["acknowledged"], before);
    assert_eq!(
        f.cursor()["journals"][0]["blocked"],
        "partial receiver acceptance"
    );
}

#[tokio::test]
async fn disable_reenable_cannot_finish_old_http_and_replays_exact_range() {
    let f = Fixture::new();
    let (endpoint, observed, release, server) = held_receiver(200).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    let first = request_or_completed(observed, &mut task).await;
    let prepared = f.cursor();
    let overlapping_sender = test_sender("http://127.0.0.1:1/v1/logs".into());
    assert_eq!(
        f.runtime
            .send_audit_otlp_once("alice", &overlapping_sender)
            .await
            .unwrap(),
        AuditOtlpAttemptOutcome::Busy
    );
    f.runtime
        .set_audit_log_settings(AuditLogSettings { enabled: false })
        .await
        .unwrap();
    f.runtime
        .set_audit_log_settings(AuditLogSettings { enabled: true })
        .await
        .unwrap();
    release.send(()).unwrap();
    assert_eq!(
        task.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Complete,
            local: None,
        }
    );
    server.await.unwrap();
    assert_eq!(f.cursor(), prepared);

    let (endpoint, observed, release, server) = held_receiver(200).await;
    let replay_sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &replay_sender)
            .await
            .unwrap()
    });
    assert_eq!(
        sent_bodies(&request_or_completed(observed, &mut task).await),
        sent_bodies(&first)
    );
    release.send(()).unwrap();
    assert_eq!(
        task.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Complete,
            local: Some(DeliveryStep::Accepted),
        }
    );
    server.await.unwrap();
}

#[tokio::test]
async fn cancelled_caller_replays_prepared_range_without_acknowledging_it() {
    let f = Fixture::new();
    let (endpoint, observed, release, server) = held_receiver(200).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    let first = request_or_completed(observed, &mut task).await;
    let prepared = f.cursor();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(f.cursor(), prepared);

    let (endpoint, observed, replay_release, replay_server) = held_receiver(200).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut replay = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    assert_eq!(
        sent_bodies(&request_or_completed(observed, &mut replay).await),
        sent_bodies(&first)
    );
    replay_release.send(()).unwrap();
    assert_eq!(
        replay.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Complete,
            local: Some(DeliveryStep::Accepted),
        }
    );
    release.send(()).unwrap();
    server.await.unwrap();
    replay_server.await.unwrap();
}

#[tokio::test]
async fn retryable_response_retains_the_prepared_range() {
    let f = Fixture::new();
    let (endpoint, observed, release, server) = held_receiver(503).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    let first = request_or_completed(observed, &mut task).await;
    let prepared = f.cursor();
    release.send(()).unwrap();
    assert_eq!(
        task.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Retryable,
            local: Some(DeliveryStep::Retryable),
        }
    );
    server.await.unwrap();
    assert_eq!(f.cursor(), prepared);

    let (endpoint, observed, release, server) = held_receiver(200).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut retry = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    assert_eq!(
        sent_bodies(&request_or_completed(observed, &mut retry).await),
        sent_bodies(&first)
    );
    release.send(()).unwrap();
    assert_eq!(
        retry.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Complete,
            local: Some(DeliveryStep::Accepted),
        }
    );
    server.await.unwrap();
}

#[tokio::test]
async fn different_destination_cancels_old_result_and_does_not_retarget_cursor() {
    let f = Fixture::new();
    let (endpoint, observed, release, server) = held_receiver(200).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    request_or_completed(observed, &mut task).await;
    let prepared = f.cursor();
    let changed = AuditOtlpSender::for_loopback_dev(
        "another-profile",
        "http://127.0.0.1:1/v1/logs",
        "test-token",
    )
    .unwrap();
    assert_eq!(
        f.runtime
            .send_audit_otlp_once("alice", &changed)
            .await
            .unwrap(),
        AuditOtlpAttemptOutcome::Busy
    );
    release.send(()).unwrap();
    assert_eq!(
        task.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Complete,
            local: None,
        }
    );
    server.await.unwrap();
    assert_eq!(f.cursor(), prepared);
}

#[tokio::test]
async fn runtime_delete_direct_delete_and_account_removal_cancel_late_success() {
    for action in ["runtime_delete", "direct_delete", "remove_account"] {
        let f = Fixture::new();
        let (endpoint, observed, release, server) = held_receiver(200).await;
        let sender = test_sender(endpoint);
        let runtime = f.runtime.clone();
        let mut task = tokio::spawn(async move {
            runtime
                .send_audit_otlp_once("alice", &sender)
                .await
                .unwrap()
        });
        request_or_completed(observed, &mut task).await;
        let prepared = f.cursor();
        match action {
            "remove_account" => f.runtime.accounts().remove_account("alice").await.unwrap(),
            "direct_delete" => f.app.remove_audit_log_file(&f.active).unwrap(),
            _ => {
                f.runtime
                    .delete_audit_log_file(&f.active.to_string_lossy())
                    .await
                    .unwrap();
            }
        }
        release.send(()).unwrap();
        assert_eq!(
            task.await.unwrap(),
            AuditOtlpAttemptOutcome::Sent {
                receiver: AuditOtlpSendResult::Complete,
                local: None,
            }
        );
        server.await.unwrap();
        if action != "remove_account" {
            assert_eq!(f.cursor(), prepared);
        }
    }
}

#[tokio::test]
async fn terminal_close_releases_root_before_stalled_http_and_late_success_cannot_finish() {
    let f = Fixture::new();
    let (endpoint, observed, release, server) = held_receiver(200).await;
    let sender = test_sender(endpoint);
    let runtime = f.runtime.clone();
    let mut task = tokio::spawn(async move {
        runtime
            .send_audit_otlp_once("alice", &sender)
            .await
            .unwrap()
    });
    request_or_completed(observed, &mut task).await;
    let prepared = f.cursor();
    // A completed shutdown while the receiver is blocked proves that no
    // storage_lifecycle guard or file handle crosses sender.send.
    f.runtime.shutdown_and_close().await.unwrap();
    assert!(f.app.storage_is_closed());
    let replacement = MarmotApp::try_with_relays_and_account_home_and_config(
        f._temp.path(),
        vec![],
        AccountHome::open(f._temp.path()),
        Default::default(),
    )
    .unwrap();
    release.send(()).unwrap();
    assert_eq!(
        task.await.unwrap(),
        AuditOtlpAttemptOutcome::Sent {
            receiver: AuditOtlpSendResult::Complete,
            local: None,
        }
    );
    server.await.unwrap();
    assert_eq!(f.cursor(), prepared);
    replacement.close_storage().unwrap();
}

#[tokio::test]
async fn explicit_attempt_requires_the_exclusive_root_lease() {
    let temp = tempfile::tempdir().unwrap();
    AccountHome::open(temp.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(temp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let sender = test_sender("http://127.0.0.1:1/v1/logs".into());
    let result = app.runtime().send_audit_otlp_once("alice", &sender).await;
    assert!(
        matches!(result, Err(AppError::AuditLogUpload(message)) if message == "audit export requires exclusive root ownership")
    );
}
