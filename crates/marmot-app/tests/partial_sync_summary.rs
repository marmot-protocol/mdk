//! Regressions for a sync that fails after earlier deliveries commit.
//!
//! The first delivery is durable before the injected second-step failure. The
//! caller must still learn that delivery's `SyncSummary` exactly once, across
//! a retry and a restart; otherwise it can never learn about the
//! already-projected message.
#![cfg(feature = "test-policy-overrides")]

use std::time::Duration;

use cgka_traits::GroupId;
use marmot_account::AccountHome;
use marmot_app::{
    AppClient, AppError, AuditLogSettings, MarmotApp, MarmotAppConfig, MarmotAppEvent,
    MarmotAppRuntime,
};
use nostr_relay_builder::MockRelay;
#[path = "support/limited_relay.rs"]
mod limited_relay;
use limited_relay::TestRelay;

fn open_store(
    dir: &tempfile::TempDir,
    relay_url: &str,
    fail_sync_before_delivery: Option<u64>,
) -> MarmotApp {
    // These faults prove committed state and replay, not power-loss durability.
    storage_sqlite::relax_storage_for_test_process();
    let mut config = MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
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
    storage_sqlite::relax_storage_for_test_process();
    let config = MarmotAppConfig::white_noise()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_fail_sync_before_boundary_save(completed_deliveries);
    MarmotApp::with_relay_and_config(dir.path(), relay_url.to_owned(), config)
}

fn open_store_with_post_ack_failure(dir: &tempfile::TempDir, relay_url: &str) -> MarmotApp {
    storage_sqlite::relax_storage_for_test_process();
    let config = MarmotAppConfig::white_noise()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_fail_ingest_after_application_event_ack();
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
    _relay: TestRelay,
    bob_dir: tempfile::TempDir,
    _alice_dir: tempfile::TempDir,
    relay_url: String,
    group_id: GroupId,
    alice: AppClient,
    pending_messages: Vec<String>,
}

impl PendingMessageBatch {
    fn bob_app(&self, fail_sync_before_delivery: Option<u64>) -> MarmotApp {
        open_store(&self.bob_dir, &self.relay_url, fail_sync_before_delivery)
    }

    async fn publish_pending_messages(&mut self) {
        for message in std::mem::take(&mut self.pending_messages) {
            self.alice
                .send(&self.group_id, message.as_bytes())
                .await
                .unwrap();
        }
    }

    async fn activate_then_publish(&mut self, bob: &mut AppClient) {
        // These faults belong to ordinary native ingress, which remains
        // supported without a native backward pager. Establish its live
        // subscription before publishing; cold replay may instead be admitted
        // by the recovery runner and cannot witness native-drain faults.
        assert!(bob.sync().await.unwrap().messages.is_empty());
        self.publish_pending_messages().await;
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
    // A truthful cap lets the current-second replay reach the injected
    // ingestion/projection fault; unknown-cap fencing is a separate contract.
    let (relay, relay_url) = limited_relay::mock_relay().await;

    let bob_dir = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(bob_dir.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;

    let alice_dir = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(alice_dir.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&alice_dir, &relay_url, None);

    // Consume the Welcome before preparing the failing application batch.
    // Each test chooses live ingress or the explicit old startup-drain control.
    let app_bob_boot1 = open_store(&bob_dir, &relay_url, None);
    app_bob_boot1
        .set_audit_log_settings(AuditLogSettings { enabled: true })
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
        .unwrap()
        .operation
        .expect("eligible fixture members");
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

    PendingMessageBatch {
        _relay: relay,
        bob_dir,
        _alice_dir: alice_dir,
        relay_url,
        group_id,
        alice,
        pending_messages: messages,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_sync_failure_returns_applied_prefix() {
    let mut batch = pending_two_message_batch().await;
    let app_bob = batch.bob_app(Some(1));
    let mut bob = app_bob.client("bob").await.unwrap();
    batch.activate_then_publish(&mut bob).await;

    let failure = bob
        .sync_with_partial_progress()
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
    let audit_rows = app_bob
        .audit_log_files()
        .unwrap()
        .into_iter()
        .flat_map(|file| {
            std::fs::read_to_string(file.path)
                .unwrap()
                .lines()
                .map(|line| {
                    marmot_forensics::v5::Record::from_json(line.as_bytes())
                        .expect("real v5 sync row");
                    serde_json::from_str::<serde_json::Value>(line).unwrap()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert!(
        audit_rows
            .iter()
            .any(|row| { row["event"]["type"] == "sync_drain" && row["event"]["deliveries"] == 1 }),
        "the failed drain must retain forensic span and completed-delivery evidence",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_after_application_event_ack_replays_summary_exactly_once() {
    let mut batch =
        pending_message_batch(vec!["applied before projection failure".to_owned()]).await;
    let app_bob = open_store_with_post_ack_failure(&batch.bob_dir, &batch.relay_url);
    let mut bob = app_bob.client("bob").await.unwrap();
    batch.activate_then_publish(&mut bob).await;

    let failure = bob
        .sync_with_partial_progress()
        .await
        .expect_err("projection must fail after staging the application-event acknowledgement");
    assert!(
        failure
            .source
            .to_string()
            .contains("injected failure after application-event acknowledgement")
    );
    assert!(
        failure.partial_summary.messages.is_empty(),
        "the failed delivery is not reportable until its engine event replays",
    );
    drop(bob);
    drop(app_bob);

    let app_bob_reopened = open_store(&batch.bob_dir, &batch.relay_url, None);
    let mut bob_reopened = app_bob_reopened.client("bob").await.unwrap();
    assert_eq!(
        bob_reopened.sync().await.unwrap().messages.len(),
        1,
        "the unacknowledged engine event must replay after reopen",
    );
    assert!(
        bob_reopened.sync().await.unwrap().messages.is_empty(),
        "the replayed application event must be acknowledged exactly once",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_prefix_survives_error() {
    let mut batch = pending_two_message_batch().await;
    let app_bob = open_store_with_boundary_failure(&batch.bob_dir, &batch.relay_url, 1);
    let mut bob = app_bob.client("bob").await.unwrap();
    batch.activate_then_publish(&mut bob).await;

    let failure = bob
        .sync_with_partial_progress()
        .await
        .expect_err("the final drain checkpoint fails after native commits");
    assert_eq!(
        failure.partial_summary.messages.len(),
        2,
        "the failure must return both already-committed native outputs",
    );
    assert_eq!(
        app_bob
            .messages("bob")
            .unwrap()
            .into_iter()
            .map(|message| message.plaintext)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "committed before batch failure".to_owned(),
            "still queued after batch failure".to_owned(),
        ]),
    );
    drop(bob);
    drop(app_bob);

    let app_bob_recovered = open_store(&batch.bob_dir, &batch.relay_url, None);
    let mut bob_recovered = app_bob_recovered.client("bob").await.unwrap();
    assert!(
        bob_recovered.sync().await.unwrap().messages.is_empty(),
        "already-reported native outputs must not replay after reopen"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_prefix_reports_once() {
    let mut batch = pending_two_message_batch().await;
    let app_bob = open_store_with_boundary_failure(&batch.bob_dir, &batch.relay_url, 1);
    let mut bob = app_bob.client("bob").await.unwrap();
    batch.activate_then_publish(&mut bob).await;

    let failure = bob
        .sync_with_partial_progress()
        .await
        .expect_err("the final drain checkpoint must fail");
    assert_eq!(failure.partial_summary.messages.len(), 2);

    let recovered = bob
        .sync_with_partial_progress()
        .await
        .expect("the retained projection and outbox acknowledgements retry");
    assert!(recovered.messages.is_empty());
    assert!(
        bob.sync_with_partial_progress()
            .await
            .unwrap()
            .messages
            .is_empty(),
        "the retained client must return the checkpointed summary exactly once",
    );
}

/// Bob, invited by alice, with the Welcome still on the relay: bob's next sync
/// is the cold pass that joins the group.
struct PendingWelcome {
    _relay: MockRelay,
    relay_url: String,
    bob_dir: tempfile::TempDir,
    _alice_dir: tempfile::TempDir,
    _alice: AppClient,
    group_id: GroupId,
}

async fn pending_welcome(group_name: &str) -> PendingWelcome {
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
    }
    drop(app_bob_setup);

    let alice_dir = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(alice_dir.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&alice_dir, &relay_url, None);
    let mut alice = app_alice.client("alice").await.unwrap();
    let group_id = alice
        .create_group(group_name, &[bob_id.as_str()])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    PendingWelcome {
        _relay: relay,
        relay_url,
        bob_dir,
        _alice_dir: alice_dir,
        _alice: alice,
        group_id,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joined_group_replays_once_after_boundary_save_failure_and_restart() {
    let welcome = pending_welcome("join boundary recovery").await;

    let app_bob_failing = open_store_with_boundary_failure(&welcome.bob_dir, &welcome.relay_url, 0);
    let mut bob_failing = app_bob_failing.client("bob").await.unwrap();
    let failure = bob_failing
        .sync_with_partial_progress()
        .await
        .expect_err("the Welcome projection boundary must fail");
    assert!(failure.partial_summary.joined_groups.is_empty());
    assert!(
        failure
            .source
            .to_string()
            .contains("injected catch-up boundary save failure")
    );
    drop(bob_failing);
    drop(app_bob_failing);

    let app_bob_recovered = open_store(&welcome.bob_dir, &welcome.relay_url, None);
    let mut bob_recovered = app_bob_recovered.client("bob").await.unwrap();
    let recovered = bob_recovered.sync().await.unwrap();
    assert_eq!(
        recovered.joined_groups,
        vec![welcome.group_id.clone()],
        "the durable engine-to-app outbox must replay the joined group"
    );
    drop(bob_recovered);
    drop(app_bob_recovered);

    let app_bob_acknowledged = open_store(&welcome.bob_dir, &welcome.relay_url, None);
    let mut bob_acknowledged = app_bob_acknowledged.client("bob").await.unwrap();
    let after_ack = bob_acknowledged.sync().await.unwrap();
    assert!(
        after_ack.joined_groups.is_empty(),
        "the projection save must acknowledge the replay exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_account_keeps_open_failure_apart_from_pass_failure() {
    let welcome = pending_welcome("sync account failures").await;
    let app_bob = open_store_with_boundary_failure(&welcome.bob_dir, &welcome.relay_url, 0);

    // Another open holds bob's engine session, so `sync_account` fails to
    // open before anything syncs: the open's own error, not an empty partial
    // sync.
    let held = app_bob.client("bob").await.unwrap();
    let busy = app_bob.sync_account("bob").await;
    assert!(
        matches!(busy, Err(AppError::AccountSessionBusy)),
        "a failed open must surface as its AppError: {busy:?}",
    );
    drop(held);

    // The cold pass `wn sync` runs fails projecting the Welcome: a pass
    // failure, returned inside the open that succeeded.
    let failure = app_bob
        .sync_account("bob")
        .await
        .expect("the client opens once the other open is dropped")
        .expect_err("the Welcome projection boundary must fail");
    assert!(
        failure
            .source
            .to_string()
            .contains("injected catch-up boundary save failure"),
        "the fault must come from the pass: {}",
        failure.source
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let second_group_id = alice
        .create_group("route boundary two", &[bob_id.as_str()])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let expected_groups = [first_group_id, second_group_id];

    // Both welcomes are already stored in MockRelay before this sync starts,
    // so the N+1 fault must observe them in the same drain.
    let app_bob_failing = open_store(&bob_dir, &relay_url, Some(1));
    let mut bob_failing = app_bob_failing.client("bob").await.unwrap();
    let failure = bob_failing
        .sync_with_partial_progress()
        .await
        .expect_err("the second welcome must fail before ingest");
    assert_eq!(
        failure.partial_summary.joined_groups.len(),
        1,
        "exactly one route-changing welcome must cross the accumulated-prefix checkpoint",
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
