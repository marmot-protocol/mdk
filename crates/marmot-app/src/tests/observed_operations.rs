//! What an operation recorded as one product outcome records, through a real call site (#2627).
//!
//! Each such operation runs its body through the observed-operation combinator with an outcome
//! rule. These tests make real calls and read the collector's payloads back: one test per rule,
//! and one for a call dropped before its work finishes.

use super::*;

/// An app on `relay` whose collector has usage diagnostics granted.
fn observed_app(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    let mut app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    app.product_analytics = crate::observability_test_support::test_product_collector();
    app.set_usage_diagnostics_consent(true).unwrap();
    app
}

/// Each recorded row of `event`, as `(operation, unit, outcome, count bucket)`, sorted.
fn recorded(app: &MarmotApp, event: &str) -> Vec<(String, String, String, String)> {
    let mut rows: Vec<_> = app
        .product_analytics
        .test_payloads()
        .iter()
        .filter(|row| row["eventName"] == event)
        .map(|row| {
            let props = &row["props"];
            let field = |name: &str| props[name].as_str().unwrap_or_default().to_owned();
            (
                field("operation"),
                field("unit"),
                field("outcome"),
                field("count_bucket"),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn rows(expected: &[(&str, &str, &str)]) -> Vec<(String, String, String, String)> {
    let mut rows: Vec<_> = expected
        .iter()
        .map(|(operation, unit, outcome)| {
            (
                (*operation).to_owned(),
                (*unit).to_owned(),
                (*outcome).to_owned(),
                "1".to_owned(),
            )
        })
        .collect();
    rows.sort();
    rows
}

/// `success` or `failure`, from the client's and the runtime's recorders, sync and async.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operation_records_success_or_failure() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = observed_app(&dir, Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("observed", &[]).await.unwrap();
    let unknown = GroupId::new(vec![0x5a; 16]);

    client.set_group_archived(&group, true).unwrap();
    client.set_group_archived(&unknown, false).unwrap_err();
    client
        .update_group_profile(&group, Some("renamed"), None)
        .await
        .unwrap();
    client
        .update_group_profile(&unknown, Some("renamed"), None)
        .await
        .unwrap_err();
    drop(client);
    let runtime = app.runtime();
    runtime
        .set_chat_muted("alice", &hex::encode(group.as_slice()), None)
        .unwrap();
    runtime
        .clear_chat_muted("nobody", &hex::encode(group.as_slice()))
        .unwrap_err();

    assert_eq!(
        recorded(&app, "mdk_group_summary"),
        rows(&[
            ("archive", "action", "success"),
            ("unarchive", "action", "failure"),
            ("profile_update", "action", "success"),
            ("profile_update", "action", "failure"),
        ])
    );
    assert_eq!(
        recorded(&app, "mdk_notification_summary"),
        rows(&[
            ("mute", "action", "success"),
            ("unmute", "action", "failure")
        ])
    );
    runtime.shutdown().await;
}

/// A send records how the engine accepted it: `confirmed`, `unknown` or `pending`, or
/// `rejected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_records_its_delivery_outcome() {
    use cgka_traits::SendAcceptDisposition::{AcceptedPending, CompletionUnknown, Published};

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = observed_app(&dir, relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("sends", &[]).await.unwrap();
    let held = client.create_group("held", &[]).await.unwrap();

    let published = client.send(&group, b"published").await.unwrap();
    relay.fail_publishes_as_unavailable();
    let unknown = client.send(&group, b"no relay took it").await.unwrap();
    // A commit no relay took leaves its group resolving that publication, so the engine
    // queues a message sent to the group behind it.
    client
        .update_group_profile(&held, Some("renamed"), None)
        .await
        .unwrap();
    let pending = client
        .send(&held, b"queued behind the commit")
        .await
        .unwrap();
    client
        .send(&GroupId::new(vec![0x5a; 16]), b"no such group")
        .await
        .unwrap_err();

    assert_eq!(
        [published, unknown, pending].map(|summary| summary.accept_disposition),
        [Published, CompletionUnknown, AcceptedPending]
    );
    let sends: Vec<_> = recorded(&app, "mdk_message_action_summary")
        .into_iter()
        .filter(|(operation, ..)| operation == "text")
        .collect();
    assert_eq!(
        sends,
        rows(&[
            ("text", "action", "confirmed"),
            ("text", "action", "unknown"),
            ("text", "action", "pending"),
            ("text", "action", "rejected"),
        ])
    );
}

/// Welcome redelivery records `confirmed` once the Welcome lands, and `failure` otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn welcome_redelivery_records_confirmed_or_failure() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = observed_app(&dir, relay.clone());
    remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    app.client("bob")
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap();
    let mut alice = app.client("alice").await.unwrap();
    relay.fail_publishes_of_kind(1059);
    alice
        .create_group("redelivery", &[&bob.account_id_hex])
        .await
        .unwrap();
    let owed = alice.pending_welcome_deliveries().unwrap();
    assert_eq!(owed.len(), 1, "the Welcome no relay took stays owed");

    alice
        .redeliver_welcome(&owed[0].message_id_hex)
        .await
        .unwrap_err();
    relay.allow_all_publish_kinds();
    alice
        .redeliver_welcome(&owed[0].message_id_hex)
        .await
        .unwrap();

    assert!(alice.pending_welcome_deliveries().unwrap().is_empty());
    let retries: Vec<_> = recorded(&app, "mdk_welcome_summary")
        .into_iter()
        .filter(|(operation, ..)| operation == "retry")
        .collect();
    assert_eq!(
        retries,
        rows(&[
            ("retry", "attempt", "confirmed"),
            ("retry", "attempt", "failure"),
        ])
    );
}

/// Wake collection records `success` unless the collection reported an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_collection_records_whether_it_reported_an_error() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = observed_app(&dir, relay.clone());
    let mut setup = app.client("alice").await.unwrap();
    let group = setup.create_group("wake", &[]).await.unwrap();
    drop(setup);
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();

    // An idle worker catches up well within the budget; the wake then drains until it ends.
    let quiet = runtime
        .collect_notifications_after_wake(3_000, NotificationWakeSource::ManualCatchUp)
        .await;
    assert_eq!(quiet.error, None);
    // A send held in its publish keeps the account's worker busy, so catch-up cannot finish
    // within the wake's budget.
    relay.block_next_publish();
    let held = tokio::spawn({
        let runtime = runtime.clone();
        let group = group.clone();
        async move {
            runtime
                .send_message("alice", &group, b"held".to_vec())
                .await
        }
    });
    relay.wait_for_blocked_publish().await;
    let timed_out = runtime
        .collect_notifications_after_wake(50, NotificationWakeSource::ManualCatchUp)
        .await;
    assert!(timed_out.error.is_some());
    relay.release_publish();
    held.await.unwrap().unwrap();

    let wakes: Vec<_> = recorded(&app, "mdk_notification_summary")
        .into_iter()
        .filter(|(operation, ..)| operation == "schedule")
        .collect();
    assert_eq!(
        wakes,
        rows(&[
            ("schedule", "attempt", "success"),
            ("schedule", "attempt", "failure"),
        ])
    );
    runtime.shutdown().await;
}

/// A call dropped before its work finishes records `cancelled`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_call_records_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = observed_app(&dir, relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("dropped", &[]).await.unwrap();

    relay.block_next_publish();
    tokio::select! {
        _ = client.send(&group, b"dropped while it publishes") => {
            panic!("the publish is held");
        }
        () = relay.wait_for_blocked_publish() => {}
    }
    relay.release_publish();

    let sends: Vec<_> = recorded(&app, "mdk_message_action_summary")
        .into_iter()
        .filter(|(operation, ..)| operation == "text")
        .collect();
    assert_eq!(sends, rows(&[("text", "action", "cancelled")]));
}
