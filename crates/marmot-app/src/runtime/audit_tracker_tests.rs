use super::*;
use std::collections::VecDeque;
use tokio::sync::Notify;

struct Scheduler {
    triggers: mpsc::Sender<&'static str>,
    stop: watch::Sender<bool>,
    starts: mpsc::UnboundedReceiver<Instant>,
    release: Arc<Notify>,
    worker: JoinHandle<()>,
}

impl Scheduler {
    fn new(results: Vec<bool>) -> Self {
        let (triggers, commands) = mpsc::channel(1);
        let (stop, stopping) = watch::channel(false);
        let (started, starts) = mpsc::unbounded_channel();
        let release = Arc::new(Notify::new());
        let gate = release.clone();
        let mut results = VecDeque::from(results);
        let worker = tokio::spawn(async move {
            run_batched_audit_uploads(commands, stopping, AuditBatchWindow::default(), |_| {
                let result = results.pop_front().expect("unexpected extra upload");
                let gate = gate.clone();
                started.send(Instant::now()).unwrap();
                async move {
                    gate.notified().await;
                    AuditPassSchedule { retry: result }
                }
            })
            .await;
        });
        Self {
            triggers,
            stop,
            starts,
            release,
            worker,
        }
    }

    async fn trigger(&self) {
        let _ = self.triggers.try_send("test");
        tokio::task::yield_now().await;
    }

    async fn advance(&self, seconds: u64) {
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::task::yield_now().await;
    }

    async fn finish(&self) {
        self.release.notify_one();
        tokio::task::yield_now().await;
    }

    async fn shutdown(self) {
        self.stop.send(true).unwrap();
        self.worker.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn activity_batches_without_extending_the_first_deadline() {
    let mut s = Scheduler::new(vec![false]);
    let start = Instant::now();
    s.trigger().await;
    for _ in 0..29 {
        s.advance(1).await;
        s.trigger().await;
    }
    assert!(s.starts.try_recv().is_err());
    s.advance(1).await;
    assert_eq!(s.starts.try_recv().unwrap() - start, AUDIT_BATCH_WINDOW);
    s.finish().await;
    s.advance(300).await;
    assert!(s.starts.try_recv().is_err(), "idle success must not poll");
    s.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn activity_during_upload_has_one_delayed_follow_up_and_no_overlap() {
    let mut s = Scheduler::new(vec![false, false]);
    s.trigger().await;
    s.advance(30).await;
    s.starts.try_recv().unwrap();
    for _ in 0..50 {
        s.trigger().await;
    }
    s.advance(90).await;
    assert!(s.starts.try_recv().is_err(), "in-flight pass is serialized");
    s.finish().await;
    s.advance(29).await;
    assert!(s.starts.try_recv().is_err());
    s.advance(1).await;
    s.starts.try_recv().unwrap();
    s.finish().await;
    s.advance(300).await;
    assert!(s.starts.try_recv().is_err());
    s.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn retries_back_off_without_new_activity_and_reset_after_success() {
    let mut s = Scheduler::new(vec![true, true, true, true, true, false, true, false]);
    s.trigger().await;
    s.advance(30).await;
    s.starts.try_recv().unwrap();
    for wait in [60, 120, 240, 300, 300] {
        s.finish().await;
        s.advance(wait - 1).await;
        assert!(s.starts.try_recv().is_err());
        s.advance(1).await;
        s.starts.try_recv().unwrap();
    }
    s.finish().await;
    s.advance(300).await;
    assert!(s.starts.try_recv().is_err());
    s.trigger().await;
    s.advance(30).await;
    s.starts.try_recv().unwrap();
    s.finish().await;
    s.advance(60).await;
    s.starts.try_recv().unwrap();
    s.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn retry_cooldown_survives_continuous_activity() {
    let mut s = Scheduler::new(vec![true, false]);
    s.trigger().await;
    s.advance(30).await;
    let first = s.starts.try_recv().unwrap();
    s.finish().await;
    for _ in 0..5 {
        s.advance(10).await;
        s.trigger().await;
    }
    assert!(s.starts.try_recv().is_err());
    s.advance(10).await;
    assert_eq!(s.starts.try_recv().unwrap() - first, AUDIT_RETRY_INITIAL);
    s.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_pending_and_in_flight_passes() {
    let s = Scheduler::new(vec![]);
    s.trigger().await;
    let start = Instant::now();
    s.shutdown().await;
    assert_eq!(Instant::now(), start);
    let mut s = Scheduler::new(vec![false]);
    s.trigger().await;
    s.advance(30).await;
    s.starts.try_recv().unwrap();
    let start = Instant::now();
    s.shutdown().await;
    assert_eq!(Instant::now(), start);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v5_catalog_failure_is_reported_as_skipped_and_requests_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    std::fs::write(tmp.path().join("accounts"), b"not a directory").unwrap();
    let sender = AuditOtlpSender::for_loopback_dev(
        "audit-v5-test",
        "http://127.0.0.1:1/v1/logs",
        "test-token",
    )
    .unwrap();
    let mut schedule = AuditPassSchedule::default();
    let result = post_audit_log_tracker_update(
        &app,
        Some(&sender),
        None,
        &RuntimeLifecycle::new(),
        false,
        &mut schedule,
    )
    .await
    .unwrap();
    assert!(result.enabled);
    assert_eq!(
        result.v5.unwrap().skipped_reason.as_deref(),
        Some("v5 delivery pass failed")
    );
    assert!(schedule.retry);
}

#[test]
fn batch_window_override_is_local_to_one_uploader() {
    let first = AuditBatchWindow::default();
    let second = AuditBatchWindow::default();
    *first.override_duration.lock().unwrap() = Some(Duration::ZERO);
    assert_eq!(first.clone().duration(), Duration::ZERO);
    assert_eq!(second.duration(), Duration::from_secs(30));
}

#[tokio::test(start_paused = true)]
async fn batches_preserve_first_trigger_and_label_automatic_retries() {
    let (triggers, commands) = mpsc::channel(1);
    let (stop, stopping) = watch::channel(false);
    let (seen, mut observed) = mpsc::unbounded_channel();
    let worker = tokio::spawn(run_batched_audit_uploads(
        commands,
        stopping,
        AuditBatchWindow::default(),
        move |trigger| {
            seen.send(trigger).unwrap();
            async { AuditPassSchedule { retry: true } }
        },
    ));
    triggers.send("send_message").await.unwrap();
    tokio::task::yield_now().await;
    triggers.send("inbound_event").await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(observed.recv().await.unwrap(), "send_message");
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(observed.recv().await.unwrap(), "retry");
    stop.send(true).unwrap();
    worker.await.unwrap();
}

const V5_DEST: &str = "audit-status-test";

/// A runtime holding the root lease, with one real recorder row for "alice"
/// when the account is new.
fn v5_runtime(root: &std::path::Path) -> (MarmotApp, crate::MarmotAppRuntime) {
    let home = marmot_account::AccountHome::open(root);
    let created = home.account("alice").is_err();
    if created {
        home.create_account("alice").unwrap();
    }
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        root,
        vec![],
        home,
        Default::default(),
    )
    .unwrap();
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    if created {
        record_v5_row(&app);
    }
    let runtime = app.runtime();
    (app, runtime)
}

fn record_v5_row(app: &MarmotApp) {
    let recorder = app.build_audit_recorder("alice", true);
    recorder.record(marmot_forensics::AuditRecord::new(
        None,
        marmot_forensics::AuditEventKind::SendEntry {
            intent_kind: "status test".into(),
        },
    ));
}

fn v5_sender(endpoint: &str, token: &str) -> AuditOtlpSender {
    AuditOtlpSender::for_loopback_dev(V5_DEST, endpoint, token).unwrap()
}

/// An OTLP receiver answering requests with `statuses` in order (the last one
/// repeats), reporting each request on the returned channel.
async fn v5_receiver(statuses: Vec<u16>) -> (String, mpsc::UnboundedReceiver<u16>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
    let (requests, observed) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut statuses = VecDeque::from(statuses);
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                let Some(end) = bytes.windows(4).position(|x| x == b"\r\n\r\n") else {
                    continue;
                };
                let length: usize = String::from_utf8_lossy(&bytes[..end])
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse().ok())
                    })
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
            let status = if statuses.len() > 1 {
                statuses.pop_front().unwrap()
            } else {
                statuses[0]
            };
            requests.send(status).unwrap();
            let reply = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    (endpoint, observed)
}

/// One automatic pass, exactly as the activity scheduler runs it.
async fn automatic_v5_pass(
    app: &MarmotApp,
    runtime: &crate::MarmotAppRuntime,
) -> (AuditOtlpTrackerResult, AuditPassSchedule) {
    let sender = runtime.shared.audit_otlp_sender();
    let mut schedule = AuditPassSchedule::default();
    let result = post_audit_log_tracker_update(
        app,
        sender.as_deref(),
        Some(&runtime.shared.audit_otlp_sender),
        &runtime.shared.lifecycle(),
        true,
        &mut schedule,
    )
    .await
    .unwrap();
    (result.v5.unwrap(), schedule)
}

fn alice_status(runtime: &crate::MarmotAppRuntime) -> crate::AuditDeliveryStatus {
    let mut statuses = runtime.audit_delivery_status().unwrap();
    assert_eq!(statuses.len(), 1);
    let status = statuses.pop().unwrap();
    assert_eq!(status.account_ref, "alice");
    status
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receiver_block_pauses_automatic_delivery_until_manual_retry_or_config_change() {
    let tmp = tempfile::tempdir().unwrap();
    let (endpoint, mut requests) = v5_receiver(vec![401, 200, 401, 200]).await;
    let (app, runtime) = v5_runtime(tmp.path());
    runtime
        .set_audit_otlp_sender(Some(v5_sender(&endpoint, "old-token")))
        .unwrap();

    let (result, schedule) = automatic_v5_pass(&app, &runtime).await;
    assert_eq!(requests.try_recv().unwrap(), 401);
    assert_eq!(result.blocked_accounts, 1);
    assert!(!schedule.retry, "a block does not arm the retry timer");
    let status = alice_status(&runtime);
    assert!(status.destination_configured);
    assert!(status.paused);
    assert_eq!(status.consecutive_failures, 1);
    assert_eq!(status.last_success_at_ms, None);
    let failure = status.last_failure.unwrap();
    assert_eq!(
        failure.kind,
        crate::AuditDeliveryFailureKind::ReceiverBlocked
    );
    assert_eq!(failure.http_status, Some(401));
    let backlog = status.backlog.unwrap();
    assert!(backlog.undelivered_bytes > 0);
    assert_eq!(backlog.undelivered_segments, 1);
    assert!(backlog.oldest_undelivered_at_ms.is_some());

    let (result, _) = automatic_v5_pass(&app, &runtime).await;
    assert_eq!(result.blocked_accounts, 1);
    assert!(
        requests.try_recv().is_err(),
        "a paused account is not resent"
    );
    // An automatic attempt that read "unpaused" before a concurrent attempt
    // recorded the pause rechecks it under its own admission.
    let sender = runtime.shared.audit_otlp_sender().unwrap();
    let report = super::attempt_audit_otlp_once(
        &app,
        &runtime.shared.lifecycle(),
        "alice",
        &sender,
        Some(&runtime.shared.audit_otlp_sender),
        AttemptStatus::Automatic,
    )
    .await
    .unwrap();
    assert!(report.paused);
    assert!(requests.try_recv().is_err());

    // The pause is durable: a restart with the same configuration keeps it.
    runtime.shutdown_and_close().await.unwrap();
    drop(app);
    let (app, runtime) = v5_runtime(tmp.path());
    runtime
        .set_audit_otlp_sender(Some(v5_sender(&endpoint, "old-token")))
        .unwrap();
    assert!(alice_status(&runtime).paused);
    automatic_v5_pass(&app, &runtime).await;
    assert!(requests.try_recv().is_err());

    // A manual tracker update is the host's retry; success lifts the pause.
    let manual = runtime.post_audit_log_tracker_update().await.unwrap();
    assert_eq!(requests.try_recv().unwrap(), 200);
    assert_eq!(manual.v5.unwrap().accepted_batches, 1);
    let status = alice_status(&runtime);
    assert!(!status.paused);
    assert_eq!(status.consecutive_failures, 0);
    assert!(status.last_success_at_ms.is_some());
    assert_eq!(
        status.last_failure.unwrap().http_status,
        Some(401),
        "the last failure stays visible after recovery"
    );
    assert_eq!(status.backlog.unwrap().undelivered_bytes, 0);

    // Blocked again, then a changed credential lifts the pause by itself.
    record_v5_row(&app);
    automatic_v5_pass(&app, &runtime).await;
    assert_eq!(requests.try_recv().unwrap(), 401);
    assert!(alice_status(&runtime).paused);
    runtime
        .set_audit_otlp_sender(Some(v5_sender(&endpoint, "new-token")))
        .unwrap();
    assert!(!alice_status(&runtime).paused);
    let (result, _) = automatic_v5_pass(&app, &runtime).await;
    assert_eq!(requests.try_recv().unwrap(), 200);
    assert_eq!(result.accepted_batches, 1);
    assert_eq!(alice_status(&runtime).consecutive_failures, 0);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_status_distinguishes_receiver_rejection_from_local_state_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let (endpoint, mut requests) = v5_receiver(vec![400]).await;
    let (app, runtime) = v5_runtime(tmp.path());
    runtime
        .set_audit_otlp_sender(Some(v5_sender(&endpoint, "token")))
        .unwrap();

    // A receiver that rejects every batch: local delivery halves each
    // rejected batch until one record is isolated, records a gap for it and
    // moves on, all within one pass and without pausing.
    automatic_v5_pass(&app, &runtime).await;
    let mut rejections = 0;
    while let Ok(status) = requests.try_recv() {
        assert_eq!(status, 400);
        rejections += 1;
    }
    assert!(rejections > 1, "the rejected batch is split and retried");
    let status = alice_status(&runtime);
    assert!(
        !status.paused,
        "a content rejection does not pause delivery"
    );
    // Only isolated records the receiver still refused count as rejected;
    // each is skipped as a gap (adjacent ones share a gap), while the split
    // steps that narrowed them down do not count.
    let rejected = status.rejected_batches;
    assert!(rejected > 0 && rejected < rejections);
    assert!(status.backlog.as_ref().unwrap().gaps > 0);
    let failure = status.last_failure.unwrap();
    assert_eq!(
        failure.kind,
        crate::AuditDeliveryFailureKind::ReceiverRejected
    );
    assert_eq!(failure.http_status, Some(400));

    // The stalled-device shape from mdk#3300: an over-limit cursor fails
    // locally before any request, and the status says so.
    let state_dir = app.account_dir("alice").join("audit-otlp-delivery-v5");
    std::fs::write(
        state_dir.join("local-delivery.json"),
        vec![b'x'; 1024 * 1024 + 1],
    )
    .unwrap();
    let (result, schedule) = automatic_v5_pass(&app, &runtime).await;
    assert!(requests.try_recv().is_err());
    assert_eq!(result.blocked_accounts, 1);
    assert!(schedule.retry);
    let status = alice_status(&runtime);
    assert!(!status.paused, "local failures keep retrying");
    assert_eq!(status.rejected_batches, rejected);
    let failure = status.last_failure.unwrap();
    assert_eq!(
        failure.kind,
        crate::AuditDeliveryFailureKind::StateOverLimit
    );
    assert_eq!(failure.http_status, None);
    runtime.shutdown_and_close().await.unwrap();
}
