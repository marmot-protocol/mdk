//! Regression for a catch-up drain that fails after earlier deliveries commit.
//!
//! The first delivery is durable before the injected second-step failure. The
//! managed runtime must still broadcast that delivery's `SyncSummary`; otherwise
//! a live-only subscriber can never learn about the already-projected message.
#![cfg(feature = "test-policy-overrides")]

use std::time::Duration;

use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppConfig, MarmotAppEvent, MarmotAppRuntime};
use nostr_relay_builder::MockRelay;

fn open_store(
    dir: &tempfile::TempDir,
    relay_url: &str,
    fail_sync_after_messages: Option<u64>,
) -> MarmotApp {
    let mut config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    if let Some(messages) = fail_sync_after_messages {
        config = config.with_dev_fail_sync_after_messages(messages);
    }
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

#[tokio::test]
async fn catch_up_failure_emits_summary_for_earlier_committed_delivery() {
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();

    let dir_bob = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(dir_bob.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;

    let dir_alice = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(dir_alice.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&dir_alice, &relay_url, None);

    // Boot bob once so the welcome is consumed before the failing batch. The
    // cold second boot then drains exactly the two application messages below.
    let app_bob_boot1 = open_store(&dir_bob, &relay_url, None);
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

    alice
        .send(&group_id, b"committed before batch failure")
        .await
        .unwrap();
    alice
        .send(&group_id, b"still queued after batch failure")
        .await
        .unwrap();

    let app_bob_boot2 = open_store(&dir_bob, &relay_url, Some(1));
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2);
    let mut events_bob_boot2 = runtime_bob_boot2.subscribe();
    runtime_bob_boot2.start().await.unwrap();

    let committed_before_failure = tokio::time::timeout(Duration::from_secs(10), async {
        let mut message_arrived = None;
        loop {
            match events_bob_boot2.recv().await.expect("runtime event stream") {
                MarmotAppEvent::MessageReceived(message)
                    if message.account_id_hex == bob_id
                        && message.message.group_id == group_id
                        && matches!(
                            message.message.plaintext.as_str(),
                            "committed before batch failure" | "still queued after batch failure"
                        ) =>
                {
                    message_arrived = Some(message.message.plaintext);
                }
                MarmotAppEvent::AccountError(error)
                    if error.account_id_hex == bob_id
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
    runtime_bob_boot2.shutdown().await;

    // The same per-delivery boundary must persist the seen-id/cursor state and
    // app-outbox acknowledgement. Bound the third boot with fresh traffic and
    // prove the delivery announced before the failure is not replayed.
    let app_bob_boot3 = open_store(&dir_bob, &relay_url, None);
    let runtime_bob_boot3 = MarmotAppRuntime::new(app_bob_boot3);
    let mut events_bob_boot3 = runtime_bob_boot3.subscribe();
    runtime_bob_boot3.start().await.unwrap();
    alice
        .send(&group_id, b"fresh after failed batch restart")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let MarmotAppEvent::MessageReceived(message) =
                events_bob_boot3.recv().await.expect("runtime event stream")
                && message.account_id_hex == bob_id
                && message.message.group_id == group_id
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
