//! Sends and group changes do not wait on group subscriptions (mdk#2562).
//!
//! The SDK relay client refuses a REQ for a relay it currently considers
//! unreachable, so a group whose relays are down cannot commit its new
//! subscription. Publishing does not need that subscription, so the refusal
//! must not fail the send or reject a token-admitted message.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_and_group_changes_continue_while_the_group_subscription_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    relay.refuse_group_subscribes(true);
    let group = client.create_group("unreachable", &[]).await.unwrap();
    assert!(
        client.has_pending_runtime_group_subscription_refresh(),
        "the new group's subscription was refused, so its refresh stays owed"
    );

    let sent = client
        .send(&group, b"sent while unsubscribed")
        .await
        .unwrap();
    let renamed = client
        .update_group_profile(&group, Some("renamed"), None)
        .await
        .unwrap();

    for summary in [&sent, &renamed] {
        assert_eq!(
            summary.accept_disposition,
            cgka_traits::SendAcceptDisposition::Published
        );
    }
    assert!(client.has_pending_runtime_group_subscription_refresh());
    assert!(
        !relay
            .accepted_subscriptions()
            .iter()
            .any(|subscription| subscription.carries_group(&group))
    );

    relay.refuse_group_subscribes(false);
    client
        .retry_pending_runtime_group_subscription_refresh()
        .await
        .unwrap();
    assert!(!client.has_pending_runtime_group_subscription_refresh());
    assert!(
        relay
            .accepted_subscriptions()
            .iter()
            .any(|subscription| subscription.carries_group(&group)),
        "the owed subscription registers once the relay accepts it"
    );
}
