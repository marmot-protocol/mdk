//! Replaceable identity records keep reaching relays a one-ack quorum
//! cancelled (mdk#2216). Saves still return on the first acknowledgement.

use std::sync::Arc;
use std::time::Duration;

use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;
use transport_nostr_adapter::{KIND_MARMOT_INBOX_RELAY_LIST, KIND_NIP65_RELAY_LIST};

use super::ScriptedPushRelayClient;
use crate::{
    AccountRelayListBootstrap, KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA, MarmotApp,
    UserProfileMetadata,
};

const FAST: &str = "wss://fast.example";
const SLOW: &str = "wss://slow.example";

fn endpoint(url: &str) -> TransportEndpoint {
    TransportEndpoint(url.to_owned())
}

fn two_relay_bootstrap() -> AccountRelayListBootstrap {
    AccountRelayListBootstrap::new(vec![endpoint(FAST), endpoint(SLOW)], Vec::new())
}

fn quorum_app() -> (
    tempfile::TempDir,
    MarmotApp,
    Arc<ScriptedPushRelayClient>,
    String,
) {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        // Production accounts are labelled by id; the copy registry
        // resolves the account that way before scheduling.
        .create_nostr_account()
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.accept_first_endpoint_only();
    let app = MarmotApp::with_relay(directory.path(), FAST).with_test_relay_client(relay.clone());
    (directory, app, relay, account.label)
}

/// Wait until every `kind` record was also sent to `SLOW` on its own, then
/// require that the retry carried the identical signed event.
async fn assert_completed_to_slow_relay(relay: &ScriptedPushRelayClient, kinds: &[u64]) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let routes = relay.attempted_routes();
            if kinds
                .iter()
                .all(|kind| routes.contains(&(*kind, vec![endpoint(SLOW)])))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "quorum-cancelled relay never received kinds {kinds:?}; routes: {:?}",
            relay.attempted_routes()
        )
    });
    let events = relay.attempted_events();
    for kind in kinds {
        let ids = events
            .iter()
            .filter(|event| event.kind == *kind)
            .map(|event| (event.id.clone(), event.sig.is_some()))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            ids.len(),
            1,
            "kind {kind} completion must resend the acknowledged signed event: {ids:?}"
        );
        assert!(
            ids.iter().all(|(_, signed)| *signed),
            "kind {kind} must be signed before its first send"
        );
    }
}

#[tokio::test]
async fn profile_save_completes_quorum_cancelled_relays() {
    let (_directory, app, relay, label) = quorum_app();

    app.publish_user_profile(
        &label,
        UserProfileMetadata {
            name: Some("Chosen Heron".into()),
            ..UserProfileMetadata::default()
        },
        two_relay_bootstrap(),
    )
    .await
    .expect("the first acknowledgement confirms the save");

    assert_completed_to_slow_relay(&relay, &[KIND_NOSTR_METADATA]).await;
}

#[tokio::test]
async fn follow_list_save_completes_quorum_cancelled_relays() {
    let (_directory, app, relay, label) = quorum_app();

    app.publish_account_follow_list(&label, &[], two_relay_bootstrap())
        .await
        .expect("the first acknowledgement confirms the save");

    assert_completed_to_slow_relay(&relay, &[KIND_NOSTR_CONTACT_LIST]).await;
}

#[tokio::test]
async fn relay_list_save_completes_quorum_cancelled_relays() {
    let (_directory, app, relay, label) = quorum_app();

    app.publish_account_relay_lists(&label, two_relay_bootstrap())
        .await
        .expect("the first acknowledgement confirms the save");

    assert_completed_to_slow_relay(
        &relay,
        &[KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST],
    )
    .await;
}

#[tokio::test]
async fn generated_bootstrap_completes_quorum_cancelled_relays() {
    let (_directory, app, relay, label) = quorum_app();
    let profile = UserProfileMetadata {
        name: Some("Chosen Heron".into()),
        created_at: 42,
        ..UserProfileMetadata::default()
    };

    app.publish_generated_account_bootstrap(&label, two_relay_bootstrap(), &profile)
        .await
        .expect("the first acknowledgement confirms bootstrap");

    assert_completed_to_slow_relay(
        &relay,
        &[
            KIND_NIP65_RELAY_LIST,
            KIND_MARMOT_INBOX_RELAY_LIST,
            KIND_NOSTR_CONTACT_LIST,
            KIND_NOSTR_METADATA,
        ],
    )
    .await;
}

#[tokio::test]
async fn fully_acknowledged_profile_save_schedules_no_completion() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        // Production accounts are labelled by id; the copy registry
        // resolves the account that way before scheduling.
        .create_nostr_account()
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), FAST).with_test_relay_client(relay.clone());

    app.publish_user_profile(
        &account.label,
        UserProfileMetadata::default(),
        two_relay_bootstrap(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        relay.attempted_routes(),
        vec![(KIND_NOSTR_METADATA, vec![endpoint(FAST), endpoint(SLOW)])],
        "relays that acknowledged must not be sent the record again"
    );
}
