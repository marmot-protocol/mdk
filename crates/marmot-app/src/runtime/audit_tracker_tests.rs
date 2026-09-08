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
        std::fs::write(home.account_dir("alice").join(name), b"{}\n").unwrap();
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

#[tokio::test]
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

#[tokio::test]
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
