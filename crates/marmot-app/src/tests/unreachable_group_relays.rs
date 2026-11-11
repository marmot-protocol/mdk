//! Sends and group changes do not wait on group subscriptions (mdk#2562).
//!
//! The SDK relay client refuses a REQ for a relay it currently considers
//! unreachable, so a group whose relays are down cannot commit its new
//! subscription. Publishing does not need that subscription, so the refusal
//! must not fail the send or reject a token-admitted message.
//!
//! A group relay the host-safety rule refuses is never contacted, so a send
//! there has a definite outcome rather than an unknown one (mdk#3276).
//!
//! A group relay's answer counts for the relay as the group spells it, even
//! where parsing spells it another way (mdk#3305).

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

/// `sync_runtime_groups` arms its retry only once it reaches the adapter, so
/// an earlier failure, such as reading the rebuild floor, must be armed by
/// the send path that now continues past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tolerated_refresh_failure_arms_the_subscription_retry() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    assert!(!client.pending_runtime_group_subscription_refresh);

    client
        .tolerate_pre_send_sync_failure(
            "test",
            Err(AppError::BlockingTask("rebuild floor read failed".into())),
        )
        .unwrap();
    assert!(client.pending_runtime_group_subscription_refresh);

    client.pending_runtime_group_subscription_refresh = false;
    let inactive = AppError::Transport(cgka_traits::TransportAdapterError::AccountNotActive(
        cgka_traits::MemberId::new(vec![7; 32]),
    ));
    let error = client
        .tolerate_pre_send_sync_failure("test", Err(inactive))
        .unwrap_err();
    assert!(error.is_account_not_active());
    assert!(client.pending_runtime_group_subscription_refresh);
}

/// The relay this test's app runs on, and a group relay the host-safety rule
/// refuses: a private address, which no relay is ever dialled at.
const SAFE_RELAY: &str = "wss://relay.example";
const UNSAFE_RELAY: &str = "wss://10.0.0.1";

/// Route `group` through `relays`, as a peer admin's routing commit can: this
/// device's own create refuses an unsafe relay, but a routing component is
/// only checked against the relay URL profile.
async fn route_group_through(client: &mut AppClient, group: &GroupId, relays: &[&str]) {
    let mut relays = relays
        .iter()
        .map(|relay| (*relay).to_owned())
        .collect::<Vec<_>>();
    relays.sort();
    let route = NostrRoutingV1::new([0x5A; 32], relays).unwrap();
    client
        .runtime
        .send(cgka_traits::engine::SendIntent::UpdateAppComponents {
            group_id: group.clone(),
            updates: vec![cgka_traits::app_components::AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: cgka_traits::app_components::encode_nostr_routing_v1(&route).unwrap(),
            }],
        })
        .await
        .unwrap();
    client.refresh_group(group);
    client.refresh_group_routes().unwrap();
}

/// The failure of a send that every relay it could reach refused: definite,
/// where a relay that might hold the event leaves its completion unknown.
fn assert_refused_everywhere(error: &AppError) {
    assert!(
        matches!(error, AppError::Publish(reason) if reason == "insufficient publish acknowledgements"),
        "{error:?}"
    );
}

/// A group relay the host-safety rule refuses is never sent to, and its
/// outcome is definite, not an unknown (mdk#3276). A commit every relay it
/// could reach refused rolls back; one another relay accepted confirms; and
/// neither leaves the refused relay owed a retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_group_relay_the_safety_rule_refuses_is_a_definite_non_delivery() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), SAFE_RELAY).with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("unsafe route", &[]).await.unwrap();
    route_group_through(&mut client, &group, &[SAFE_RELAY, UNSAFE_RELAY]).await;
    let epoch = client.runtime.epoch_state(&group).unwrap().epoch();
    let attempted = relay.attempted_routes().len();

    relay.reject_next_publish();
    let error = client
        .update_group_profile(&group, Some("refused"), None)
        .await
        .unwrap_err();
    assert_refused_everywhere(&error);
    let state = client.runtime.epoch_state(&group).unwrap();
    assert!(
        matches!(state, cgka_traits::engine_state::EpochState::Stable { .. }),
        "the refused commit rolled back: {state:?}"
    );
    assert_eq!(state.epoch(), epoch);

    client
        .update_group_profile(&group, Some("accepted"), None)
        .await
        .unwrap();
    assert_eq!(
        client.runtime.epoch_state(&group).unwrap().epoch().0,
        epoch.0 + 1
    );

    assert!(
        !client.runtime.has_pending_outbound_fanouts(&group).unwrap(),
        "no relay is owed a retry"
    );
    let routes = relay.attempted_routes()[attempted..].to_vec();
    assert_eq!(routes.len(), 2, "{routes:?}");
    assert!(
        routes
            .iter()
            .all(|(_, endpoints)| endpoints == &[TransportEndpoint(SAFE_RELAY.into())]),
        "nothing was sent to the refused relay: {routes:?}"
    );
}

/// A group whose relays all fail the host-safety rule can send nothing: a
/// commit rolls back and a message fails at once, and neither is retried
/// (mdk#3276).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_group_whose_relays_all_fail_the_safety_rule_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), SAFE_RELAY).with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("unsafe route", &[]).await.unwrap();
    route_group_through(&mut client, &group, &[UNSAFE_RELAY]).await;
    let epoch = client.runtime.epoch_state(&group).unwrap().epoch();
    let attempted = relay.attempted_routes().len();

    let error = client
        .update_group_profile(&group, Some("unsent"), None)
        .await
        .unwrap_err();
    assert_refused_everywhere(&error);
    let state = client.runtime.epoch_state(&group).unwrap();
    assert!(
        matches!(state, cgka_traits::engine_state::EpochState::Stable { .. }),
        "the unsent commit rolled back: {state:?}"
    );
    assert_eq!(state.epoch(), epoch);
    assert_refused_everywhere(&client.send(&group, b"unsent").await.unwrap_err());

    assert!(
        !client.runtime.has_pending_outbound_fanouts(&group).unwrap(),
        "no relay is owed a retry"
    );
    assert_eq!(
        relay.attempted_routes().len(),
        attempted,
        "nothing was sent"
    );
}

/// A group relay spelled differently from its parsed form, with an
/// upper-case host and an explicit default port: parsing names it
/// `wss://relay.example`.
const RESPELLED_GROUP_RELAY: &str = "wss://Relay.example:443";

/// A commit to a group whose only relay it spells differently from parsing
/// has the relay's own outcome (mdk#3305): a refusal rolls it back and an
/// acceptance confirms it, rather than reading as possibly exposed and
/// leaving the commit pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_counts_the_answer_of_a_group_relay_spelled_another_way() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), SAFE_RELAY).with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("respelled route", &[]).await.unwrap();
    route_group_through(&mut client, &group, &[RESPELLED_GROUP_RELAY]).await;
    let epoch = client.runtime.epoch_state(&group).unwrap().epoch();

    relay.reject_next_publish();
    let error = client
        .update_group_profile(&group, Some("refused"), None)
        .await
        .unwrap_err();
    assert_refused_everywhere(&error);
    let state = client.runtime.epoch_state(&group).unwrap();
    assert!(
        matches!(state, cgka_traits::engine_state::EpochState::Stable { .. }),
        "the refused commit rolled back: {state:?}"
    );
    assert_eq!(state.epoch(), epoch);

    client
        .update_group_profile(&group, Some("accepted"), None)
        .await
        .unwrap();
    assert_eq!(
        client.runtime.epoch_state(&group).unwrap().epoch().0,
        epoch.0 + 1
    );
    assert!(
        !client.runtime.has_pending_outbound_fanouts(&group).unwrap(),
        "no relay is owed a retry"
    );
}
