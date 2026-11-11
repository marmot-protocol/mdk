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
    fn new(results: Vec<Option<Duration>>) -> Self {
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
                    AuditPassSchedule {
                        retry_after: result,
                    }
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
    let mut s = Scheduler::new(vec![None]);
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
    let mut s = Scheduler::new(vec![None, None]);
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
    let mut s = Scheduler::new(vec![
        Some(Duration::ZERO),
        Some(Duration::ZERO),
        Some(Duration::ZERO),
        Some(Duration::ZERO),
        Some(Duration::ZERO),
        None,
        Some(Duration::ZERO),
        None,
    ]);
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
async fn server_delay_survives_continuous_activity() {
    let mut s = Scheduler::new(vec![Some(Duration::from_secs(300)), None]);
    s.trigger().await;
    s.advance(30).await;
    let first = s.starts.try_recv().unwrap();
    s.finish().await;
    for _ in 0..9 {
        s.advance(30).await;
        s.trigger().await;
    }
    assert!(s.starts.try_recv().is_err());
    s.advance(30).await;
    assert_eq!(
        s.starts.try_recv().unwrap() - first,
        Duration::from_secs(300)
    );
    s.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_pending_and_in_flight_passes() {
    let s = Scheduler::new(vec![]);
    s.trigger().await;
    let start = Instant::now();
    s.shutdown().await;
    assert_eq!(Instant::now(), start);
    let mut s = Scheduler::new(vec![None]);
    s.trigger().await;
    s.advance(30).await;
    s.starts.try_recv().unwrap();
    let start = Instant::now();
    s.shutdown().await;
    assert_eq!(Instant::now(), start);
}

/// Real HTTP path: endpoint-wide failures stop automatic passes, but the manual
/// API remains immediate and continues through the retained files.
/// Answers every request with `status` and reports each one on the returned
/// channel. The response carries `Retry-After` only when one is given.
async fn status_server(
    status: u16,
    retry_after: Option<&'static str>,
) -> (JoinHandle<()>, String, mpsc::UnboundedReceiver<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/ingest", listener.local_addr().unwrap());
    let (requests, observed) = mpsc::unbounded_channel();
    let retry_after =
        retry_after.map_or(String::new(), |value| format!("Retry-After: {value}\r\n"));
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 2048];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                if let Some(end) = bytes.windows(4).position(|x| x == b"\r\n\r\n")
                    && bytes.len() >= end + 4 + 3
                {
                    break;
                }
            }
            requests.send(()).unwrap();
            let response = format!(
                "HTTP/1.1 {status} Test\r\n{retry_after}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (server, endpoint, observed)
}

fn two_file_audit_app(root: &std::path::Path) -> MarmotApp {
    let home = marmot_account::AccountHome::open(root);
    home.create_account("alice").unwrap();
    for name in ["audit-a.jsonl", "audit-b.jsonl"] {
        std::fs::write(home.account_dir("alice").join(name),
            b"{\"schema_version\":\"marmot-forensics-audit/v4\",\"seq\":0,\"wall_time_ms\":0,\"engine_id\":\"test\",\"kind\":{\"type\":\"recorder_started\",\"recorder\":\"test\"}}\n"
        ).unwrap();
    }
    let app = MarmotApp::with_relay(root, "wss://relay.example");
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    app
}

fn tracker_config(endpoint: String) -> AuditLogTrackerConfig {
    AuditLogTrackerConfig {
        endpoint: Some(endpoint),
        authorization_bearer_token: Some("test-token".into()),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v5_catalog_failure_retains_completed_v4_result_and_requests_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    // V4 exits with its own missing-endpoint result before enumerating the
    // account catalog. V5 must report the catalog failure independently.
    std::fs::write(tmp.path().join("accounts"), b"not a directory").unwrap();
    let sender = AuditOtlpSender::for_loopback_dev(
        "audit-v5-test",
        "http://127.0.0.1:1/v1/logs",
        "test-token",
    )
    .unwrap();
    let mut schedule = AuditPassSchedule::default();
    let result = post_audit_log_tracker_update_with_v5(
        &app,
        AuditLogTrackerConfig::default(),
        Some(&sender),
        None,
        &RuntimeLifecycle::new(),
        false,
        &mut schedule,
    )
    .await
    .unwrap();
    assert_eq!(
        result.skipped_reason.as_deref(),
        Some("audit log tracker endpoint missing")
    );
    assert_eq!(
        result.v5.unwrap().skipped_reason.as_deref(),
        Some("v5 delivery pass failed")
    );
    assert_eq!(schedule.retry_after, Some(Duration::ZERO));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_pass_stops_on_auth_rate_limit_and_server_failure() {
    // 400 and 413 are the file-specific controls: with Retry-After present,
    // both are ordinary rejections, so the pass continues and the cooldown
    // applies. The bare-413 latch is pinned separately below.
    for status in [401, 403, 429, 503, 400, 413] {
        let tmp = tempfile::tempdir().unwrap();
        let app = two_file_audit_app(tmp.path());
        let (server, endpoint, mut observed) = status_server(status, Some("120")).await;
        let config = tracker_config(endpoint);
        let mut schedule = AuditPassSchedule::default();
        post_audit_log_tracker_update(&app, config.clone(), true, &mut schedule)
            .await
            .unwrap();
        let count = if matches!(status, 400 | 413) { 2 } else { 1 };
        for _ in 0..count {
            observed.try_recv().unwrap();
        }
        assert!(observed.try_recv().is_err());
        assert_eq!(
            schedule.retry_after,
            Some(Duration::from_secs(if matches!(status, 401 | 403) {
                300
            } else {
                120
            }))
        );
        post_audit_log_tracker_update_for_app(&app, config)
            .await
            .unwrap();
        for _ in 0..2 {
            observed.try_recv().unwrap();
        }
        assert!(observed.try_recv().is_err());
        server.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_413_latches_the_file_while_any_retry_after_keeps_it_retryable() {
    // "\u{e9}" is obs-text: hyper accepts it, but `HeaderValue::to_str` does
    // not, so the header must count as present even without a readable value.
    for (retry_after, latched) in [(None, true), (Some("soon"), false), (Some("\u{e9}"), false)] {
        let tmp = tempfile::tempdir().unwrap();
        let app = two_file_audit_app(tmp.path());
        let (server, endpoint, mut observed) = status_server(413, retry_after).await;
        let config = tracker_config(endpoint);
        let mut schedule = AuditPassSchedule::default();
        post_audit_log_tracker_update(&app, config.clone(), true, &mut schedule)
            .await
            .unwrap();
        // A refusal never blocks the file behind it.
        for _ in 0..2 {
            observed.try_recv().unwrap();
        }
        assert!(observed.try_recv().is_err());
        assert_eq!(
            schedule.retry_after.is_none(),
            latched,
            "only a bare 413 leaves the retry timer unarmed"
        );

        post_audit_log_tracker_update_for_app(&app, config)
            .await
            .unwrap();
        let re_posted = std::iter::from_fn(|| observed.try_recv().ok()).count();
        assert_eq!(re_posted, if latched { 0 } else { 2 });
        server.abort();
    }
}

#[test]
fn batch_window_override_is_local_to_one_uploader() {
    let first = AuditBatchWindow::default();
    let second = AuditBatchWindow::default();
    *first.override_duration.lock().unwrap() = Some(Duration::ZERO);
    assert_eq!(first.clone().duration(), Duration::ZERO);
    assert_eq!(second.duration(), Duration::from_secs(30));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirected_tracker_upload_is_not_checkpointed_until_direct_success() {
    let tmp = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(tmp.path());
    home.create_account("alice").unwrap();
    std::fs::write(
        home.account_dir("alice").join("audit-a.jsonl"),
        b"{\"schema_version\":\"marmot-forensics-audit/v4\",\"seq\":0,\"wall_time_ms\":0,\"engine_id\":\"test\",\"kind\":{\"type\":\"recorder_started\",\"recorder\":\"test\"}}\n",
    )
    .unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    let first = app.audit_log_files().unwrap().remove(0);

    let source = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let location = format!("http://{}/stolen", sink.local_addr().unwrap());
    let redirect_endpoint = format!("http://{}/ingest", source.local_addr().unwrap());
    let redirect_server = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let (mut stream, _) = source.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 2048];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let (sink_tx, mut sink_rx) = tokio::sync::oneshot::channel();
    let sink_server = tokio::spawn(async move {
        if sink.accept().await.is_ok() {
            let _ = sink_tx.send(());
        }
    });

    let redirected = post_audit_log_tracker_update_for_app(&app, tracker_config(redirect_endpoint))
        .await
        .unwrap();
    assert!(redirected.uploaded.is_empty());
    assert!(
        app.audit_upload_checkpoint("alice")
            .acknowledged(&first)
            .is_none()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut sink_rx)
            .await
            .is_err(),
        "redirect sink received a tracker upload"
    );
    sink_server.abort();
    redirect_server.await.unwrap();

    let (server, endpoint, mut observed) = status_server(204, None).await;
    let uploaded = post_audit_log_tracker_update_for_app(&app, tracker_config(endpoint))
        .await
        .unwrap();
    assert_eq!(uploaded.uploaded.len(), 1);
    assert!(observed.try_recv().is_ok());
    assert_eq!(
        app.audit_upload_checkpoint("alice").acknowledged(&first),
        Some(marmot_observability::AuditUploadOutcome::Uploaded)
    );
    server.abort();
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
            async {
                AuditPassSchedule {
                    retry_after: Some(Duration::ZERO),
                }
            }
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
    let result = post_audit_log_tracker_update_with_v5(
        app,
        AuditLogTrackerConfig::default(),
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
    assert_eq!(
        schedule.retry_after, None,
        "a block does not arm the retry timer"
    );
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

    automatic_v5_pass(&app, &runtime).await;
    assert_eq!(requests.try_recv().unwrap(), 400);
    let status = alice_status(&runtime);
    assert!(
        !status.paused,
        "a content rejection does not pause delivery"
    );
    assert_eq!(status.rejected_batches, 1);
    let failure = status.last_failure.unwrap();
    assert_eq!(
        failure.kind,
        crate::AuditDeliveryFailureKind::ReceiverRejected
    );
    assert_eq!(failure.http_status, Some(400));
    assert_eq!(status.consecutive_failures, 1);

    // Until local delivery moves past a rejected batch, its journal stays
    // blocked. The next pass sends nothing and still reports the rejection.
    automatic_v5_pass(&app, &runtime).await;
    assert!(requests.try_recv().is_err());
    let status = alice_status(&runtime);
    let failure = status.last_failure.unwrap();
    assert_eq!(
        failure.kind,
        crate::AuditDeliveryFailureKind::ReceiverRejected
    );
    assert_eq!(failure.http_status, Some(400));
    assert_eq!(status.rejected_batches, 1);
    assert_eq!(status.consecutive_failures, 2);

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
    assert_eq!(schedule.retry_after, Some(Duration::ZERO));
    let status = alice_status(&runtime);
    assert!(!status.paused, "local failures keep retrying");
    assert_eq!(status.rejected_batches, 1);
    let failure = status.last_failure.unwrap();
    assert_eq!(
        failure.kind,
        crate::AuditDeliveryFailureKind::StateOverLimit
    );
    assert_eq!(failure.http_status, None);
    runtime.shutdown_and_close().await.unwrap();
}
