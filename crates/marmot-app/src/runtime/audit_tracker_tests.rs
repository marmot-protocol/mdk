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
            run_batched_audit_uploads(commands, stopping, || {
                let result = results.pop_front().expect("unexpected extra upload");
                let gate = gate.clone();
                started.send(Instant::now()).unwrap();
                async move {
                    gate.notified().await;
                    AuditPassSchedule {
                        retry_after: result,
                        ..Default::default()
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
    let mut s = Scheduler::new(vec![Some(Duration::from_secs(600)), None]);
    s.trigger().await;
    s.advance(30).await;
    let first = s.starts.try_recv().unwrap();
    s.finish().await;
    for _ in 0..19 {
        s.advance(30).await;
        s.trigger().await;
    }
    assert!(s.starts.try_recv().is_err());
    s.advance(30).await;
    assert_eq!(
        s.starts.try_recv().unwrap() - first,
        Duration::from_secs(600)
    );
    s.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn unfinished_snapshot_retries_quickly_then_backs_off_while_idle() {
    let (triggers, commands) = mpsc::channel(1);
    let (stop, stopping) = watch::channel(false);
    let (started, mut starts) = mpsc::unbounded_channel();
    let worker = tokio::spawn(async move {
        run_batched_audit_uploads(commands, stopping, || {
            started.send(Instant::now()).unwrap();
            async {
                AuditPassSchedule {
                    pending: true,
                    retry_after: None,
                }
            }
        })
        .await;
    });
    triggers.send("test").await.unwrap();
    tokio::task::yield_now().await;
    let start = Instant::now();
    let mut elapsed = 0;
    for seconds in [30, 30, 60, 120, 240, 300] {
        elapsed += seconds;
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            starts.try_recv().unwrap() - start,
            Duration::from_secs(elapsed)
        );
    }
    triggers.send("new activity").await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(AUDIT_BATCH_WINDOW).await;
    tokio::task::yield_now().await;
    assert_eq!(
        starts.try_recv().unwrap() - start,
        Duration::from_secs(elapsed + 30)
    );
    stop.send(true).unwrap();
    worker.await.unwrap();
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
#[tokio::test]
async fn automatic_pass_stops_on_auth_rate_limit_and_server_failure() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for status in [401, 403, 429, 503, 400] {
        let tmp = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(tmp.path());
        home.create_account("alice").unwrap();
        for name in ["audit-a.jsonl", "audit-b.jsonl"] {
            std::fs::write(home.account_dir("alice").join(name), b"{}\n").unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = AuditLogTrackerConfig {
            endpoint: Some(format!("http://{}/ingest", listener.local_addr().unwrap())),
            authorization_bearer_token: Some("test-token".into()),
            ..Default::default()
        };
        let (requests, mut observed) = mpsc::unbounded_channel();
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
                    "HTTP/1.1 {status} Test\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();
        let mut schedule = AuditPassSchedule::default();
        post_audit_log_tracker_update(&app, config.clone(), true, &mut schedule)
            .await
            .unwrap();
        let count = if status == 400 { 2 } else { 1 };
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
