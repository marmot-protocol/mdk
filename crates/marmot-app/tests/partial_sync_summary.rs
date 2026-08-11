//! Regression for a catch-up drain that fails after earlier deliveries commit.
//!
//! The first delivery is durable before the injected second-step failure. The
//! managed runtime must still broadcast that delivery's `SyncSummary`; otherwise
//! a live-only subscriber can never learn about the already-projected message.
#![cfg(feature = "test-policy-overrides")]

use std::time::Duration;

use cgka_traits::GroupId;
use marmot_account::AccountHome;
use marmot_app::{
    AppClient, AuditLogSettings, AuditLogTrackerConfig, MarmotApp, MarmotAppConfig, MarmotAppEvent,
    MarmotAppRuntime,
};
use nostr_relay_builder::MockRelay;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn open_store(
    dir: &tempfile::TempDir,
    relay_url: &str,
    fail_sync_before_delivery: Option<u64>,
) -> MarmotApp {
    let mut config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    if let Some(deliveries) = fail_sync_before_delivery {
        config = config.with_dev_fail_sync_before_delivery(deliveries);
    }
    MarmotApp::with_relay_and_config(dir.path(), relay_url.to_owned(), config)
}

fn open_store_with_boundary_failure(
    dir: &tempfile::TempDir,
    relay_url: &str,
    completed_deliveries: u64,
) -> MarmotApp {
    let config = MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_fail_sync_before_boundary_save(completed_deliveries);
    MarmotApp::with_relay_and_config(dir.path(), relay_url.to_owned(), config)
}

async fn wait_for_event<F>(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    mut matches_event: F,
) where
    F: FnMut(&MarmotAppEvent) -> bool,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.expect("runtime event stream");
            if matches_event(&event) {
                return;
            }
        }
    })
    .await
    .expect("matching runtime event");
}

struct PendingMessageBatch {
    _relay: MockRelay,
    bob_dir: tempfile::TempDir,
    _alice_dir: tempfile::TempDir,
    relay_url: String,
    bob_id: String,
    group_id: GroupId,
    alice: AppClient,
}

impl PendingMessageBatch {
    fn bob_app(&self, fail_sync_before_delivery: Option<u64>) -> MarmotApp {
        open_store(&self.bob_dir, &self.relay_url, fail_sync_before_delivery)
    }
}

async fn pending_two_message_batch() -> PendingMessageBatch {
    pending_message_batch(vec![
        "committed before batch failure".to_owned(),
        "still queued after batch failure".to_owned(),
    ])
    .await
}

async fn pending_message_batch(messages: Vec<String>) -> PendingMessageBatch {
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();

    let bob_dir = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(bob_dir.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;

    let alice_dir = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(alice_dir.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&alice_dir, &relay_url, None);

    // Boot bob once so the welcome is consumed before the failing batch. The
    // cold second boot then drains exactly the application messages below.
    let app_bob_boot1 = open_store(&bob_dir, &relay_url, None);
    app_bob_boot1
        .set_audit_log_settings(AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
        .unwrap();
    {
        let mut bob_setup = app_bob_boot1.client("bob").await.unwrap();
        bob_setup.publish_key_package().await.unwrap();
    }
    let runtime_bob_boot1 = MarmotAppRuntime::new(app_bob_boot1.clone());
    let mut events_bob_boot1 = runtime_bob_boot1.subscribe();
    runtime_bob_boot1.start().await.unwrap();

    let mut alice = app_alice.client("alice").await.unwrap();
    let group_id = alice
        .create_group("partial sync summary", &[bob_id.as_str()])
        .await
        .unwrap();
    wait_for_event(&mut events_bob_boot1, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined {
                account_id_hex,
                group_id: joined,
                ..
            } if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;
    runtime_bob_boot1.shutdown().await;

    for message in messages {
        alice.send(&group_id, message.as_bytes()).await.unwrap();
    }

    PendingMessageBatch {
        _relay: relay,
        bob_dir,
        _alice_dir: alice_dir,
        relay_url,
        bob_id,
        group_id,
        alice,
    }
}

async fn acknowledge_one_http_request(listener: TcpListener, observed: oneshot::Sender<()>) {
    let (mut stream, _) = listener.accept().await.expect("audit tracker request");
    let mut request = [0_u8; 4096];
    let _ = stream.read(&mut request).await;
    let _ = observed.send(());
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
}

#[tokio::test]
async fn direct_sync_failure_returns_applied_prefix() {
    let batch = pending_two_message_batch().await;
    let app_bob = batch.bob_app(Some(1));
    let mut bob = app_bob.client("bob").await.unwrap();

    let failure = bob
        .sync()
        .await
        .expect_err("the second delivery must hit the injected ingest failure");
    assert_eq!(failure.partial_summary.messages.len(), 1);
    assert!(
        failure
            .source
            .to_string()
            .contains("injected catch-up delivery failure"),
        "the fault must come from the N+1 ingest attempt: {}",
        failure.source
    );
}

#[tokio::test]
async fn delivery_with_failed_boundary_save_is_excluded_from_applied_prefix() {
    let batch = pending_two_message_batch().await;
    let app_bob = open_store_with_boundary_failure(&batch.bob_dir, &batch.relay_url, 1);
    let mut bob = app_bob.client("bob").await.unwrap();

    let failure = bob
        .sync()
        .await
        .expect_err("the second delivery boundary save must fail");
    assert_eq!(
        failure.partial_summary.messages.len(),
        1,
        "the delivery whose completion boundary failed is not part of the completed prefix",
    );
    assert!(
        failure
            .source
            .to_string()
            .contains("injected catch-up boundary save failure"),
        "the fault must come from the N+1 completion boundary: {}",
        failure.source
    );
}

#[tokio::test]
async fn route_changing_delivery_persists_seen_id_before_later_failure() {
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();

    let bob_dir = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(bob_dir.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;
    let app_bob_setup = open_store(&bob_dir, &relay_url, None);
    {
        let mut bob = app_bob_setup.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        bob.publish_key_package().await.unwrap();
    }

    let alice_dir = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(alice_dir.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&alice_dir, &relay_url, None);
    let mut alice = app_alice.client("alice").await.unwrap();
    let first_group_id = alice
        .create_group("route boundary one", &[bob_id.as_str()])
        .await
        .unwrap();
    let second_group_id = alice
        .create_group("route boundary two", &[bob_id.as_str()])
        .await
        .unwrap();
    let expected_groups = [first_group_id, second_group_id];

    // Both welcomes are already stored in MockRelay before this sync starts,
    // so the N+1 fault must observe them in the same drain.
    let app_bob_failing = open_store(&bob_dir, &relay_url, Some(1));
    let mut bob_failing = app_bob_failing.client("bob").await.unwrap();
    let failure = bob_failing
        .sync()
        .await
        .expect_err("the second welcome must fail before ingest");
    assert_eq!(
        failure.partial_summary.joined_groups.len(),
        1,
        "exactly one route-changing welcome must cross the completion boundary",
    );
    assert!(failure.partial_summary.messages.is_empty());
    let completed_group = failure.partial_summary.joined_groups[0].clone();
    assert!(expected_groups.contains(&completed_group));
    drop(bob_failing);
    drop(app_bob_failing);

    let app_bob_restart = open_store(&bob_dir, &relay_url, None);
    let mut bob_restart = app_bob_restart.client("bob").await.unwrap();
    let resumed = bob_restart.sync().await.unwrap();
    assert_eq!(
        resumed.joined_groups.len(),
        1,
        "restart must emit only the welcome that failed before ingest",
    );
    assert_ne!(
        resumed.joined_groups[0], completed_group,
        "the persisted welcome event id must suppress route-changing replay",
    );
    assert!(expected_groups.contains(&resumed.joined_groups[0]));
}

#[tokio::test]
async fn catch_up_failure_emits_summary_for_earlier_committed_delivery() {
    let mut batch = pending_two_message_batch().await;
    let app_bob_boot2 = batch.bob_app(Some(1));
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2);
    let mut events_bob_boot2 = runtime_bob_boot2.subscribe();
    let tracker_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tracker_addr = tracker_listener.local_addr().unwrap();
    let (tracker_observed, tracker_request) = oneshot::channel();
    let tracker_server = tokio::spawn(acknowledge_one_http_request(
        tracker_listener,
        tracker_observed,
    ));
    runtime_bob_boot2
        .set_audit_log_tracker_config(AuditLogTrackerConfig {
            endpoint: Some(format!("http://{tracker_addr}/api/v1/audit-logs/")),
            authorization_bearer_token: Some("partial-summary-test-token".to_owned()),
            ..Default::default()
        })
        .unwrap();
    runtime_bob_boot2.start().await.unwrap();

    let committed_before_failure = tokio::time::timeout(Duration::from_secs(10), async {
        let mut message_arrived = None;
        loop {
            match events_bob_boot2.recv().await.expect("runtime event stream") {
                MarmotAppEvent::MessageReceived(message)
                    if message.account_id_hex == batch.bob_id
                        && message.message.group_id == batch.group_id
                        && matches!(
                            message.message.plaintext.as_str(),
                            "committed before batch failure" | "still queued after batch failure"
                        ) =>
                {
                    message_arrived = Some(message.message.plaintext);
                }
                MarmotAppEvent::AccountError(error)
                    if error.account_id_hex == batch.bob_id
                        && error.message.starts_with("runtime startup receive failed:") =>
                {
                    break message_arrived;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("injected catch-up failure event")
    .expect("the completed delivery's summary must be emitted before the later batch error");

    assert_eq!(
        runtime_bob_boot2
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_sync
            .failures,
        1,
        "the test must exercise the injected mid-batch failure",
    );
    tokio::time::timeout(Duration::from_secs(10), tracker_request)
        .await
        .expect("partial summary must schedule the audit tracker")
        .expect("audit tracker observation channel");
    tracker_server.await.unwrap();
    runtime_bob_boot2.shutdown().await;

    // The same per-delivery boundary must persist the seen-id/cursor state and
    // app-outbox acknowledgement. Bound the third boot with fresh traffic and
    // prove the delivery announced before the failure is not replayed.
    let app_bob_boot3 = batch.bob_app(None);
    let runtime_bob_boot3 = MarmotAppRuntime::new(app_bob_boot3);
    let mut events_bob_boot3 = runtime_bob_boot3.subscribe();
    runtime_bob_boot3.start().await.unwrap();
    batch
        .alice
        .send(&batch.group_id, b"fresh after failed batch restart")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let MarmotAppEvent::MessageReceived(message) =
                events_bob_boot3.recv().await.expect("runtime event stream")
                && message.account_id_hex == batch.bob_id
                && message.message.group_id == batch.group_id
            {
                assert_ne!(
                    message.message.plaintext, committed_before_failure,
                    "the persisted delivery must not replay after restart"
                );
                if message.message.plaintext == "fresh after failed batch restart" {
                    break;
                }
            }
        }
    })
    .await
    .expect("fresh message after restart");
    runtime_bob_boot3.shutdown().await;
}
