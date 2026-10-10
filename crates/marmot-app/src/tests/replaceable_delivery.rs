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

/// Wait until `SLOW` accepted every `kind` record on its own, then require
/// that the retry carried the identical signed event.
async fn assert_completed_to_slow_relay(relay: &ScriptedPushRelayClient, kinds: &[u64]) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let routes = relay.accepted_routes();
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
            "quorum-cancelled relay never accepted kinds {kinds:?}; routes: {:?}",
            relay.accepted_routes()
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

#[tokio::test]
async fn successive_saves_of_one_kind_author_strictly_increasing_timestamps() {
    let (_directory, app, relay, label) = quorum_app();

    for name in ["First", "Second", "Third"] {
        app.publish_user_profile(
            &label,
            UserProfileMetadata {
                name: Some(name.into()),
                ..UserProfileMetadata::default()
            },
            two_relay_bootstrap(),
        )
        .await
        .unwrap();
        app.publish_account_follow_list(&label, &[], two_relay_bootstrap())
            .await
            .unwrap();
    }

    // Relays keep the lower event id on a `created_at` tie, so a completion
    // that lands after a same-second newer save could otherwise win.
    for kind in [KIND_NOSTR_METADATA, KIND_NOSTR_CONTACT_LIST] {
        let mut authored = Vec::new();
        for event in relay.attempted_events() {
            if event.kind == kind && !authored.iter().any(|(id, _)| *id == event.id) {
                authored.push((event.id, event.created_at));
            }
        }
        assert_eq!(authored.len(), 3, "kind {kind} authors one event per save");
        assert!(
            authored.windows(2).all(|pair| pair[0].1 < pair[1].1),
            "kind {kind} versions must have strictly increasing created_at: {authored:?}"
        );
    }
}

#[tokio::test]
async fn rapid_profile_saves_cache_the_authored_timestamp() {
    let (_directory, app, relay, label) = quorum_app();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let save = |name: &'static str| {
        runtime.publish_user_profile(
            &label,
            UserProfileMetadata {
                name: Some(name.into()),
                ..UserProfileMetadata::default()
            },
            two_relay_bootstrap(),
        )
    };
    save("First").await.unwrap();
    save("Second").await.unwrap();
    let returned = save("Third").await.unwrap();

    let authored = relay
        .attempted_events()
        .into_iter()
        .filter(|event| event.kind == KIND_NOSTR_METADATA)
        .map(|event| event.created_at)
        .max()
        .unwrap();
    assert_eq!(
        returned.created_at, authored,
        "the returned profile must carry the published event's timestamp"
    );
    // A late copy of the second save must not replace the third.
    let account_id_hex = app.account_home().account(&label).unwrap().account_id_hex;
    app.remember_directory_profile_if_newer(
        &account_id_hex,
        &UserProfileMetadata {
            name: Some("Second".into()),
            created_at: authored - 1,
            ..UserProfileMetadata::default()
        },
    )
    .unwrap();
    let cached = app
        .directory_entry_for_account_id(&account_id_hex)
        .unwrap()
        .and_then(|entry| entry.profile)
        .unwrap();
    assert_eq!(cached.name.as_deref(), Some("Third"));
    assert_eq!(cached.created_at, authored);
    runtime.shutdown().await;
}

#[tokio::test]
async fn reopened_app_authors_after_previously_published_versions() {
    let (directory, app, relay, label) = quorum_app();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    for name in ["First", "Second", "Third"] {
        runtime
            .publish_user_profile(
                &label,
                UserProfileMetadata {
                    name: Some(name.into()),
                    ..UserProfileMetadata::default()
                },
                two_relay_bootstrap(),
            )
            .await
            .unwrap();
        app.publish_account_relay_lists(&label, two_relay_bootstrap())
            .await
            .unwrap();
    }
    runtime.shutdown().await;
    drop(runtime);
    drop(app);

    let reopened =
        MarmotApp::with_relay(directory.path(), FAST).with_test_relay_client(relay.clone());
    let newest_before = |kind: u64| {
        relay
            .attempted_events()
            .into_iter()
            .filter(|event| event.kind == kind)
            .map(|event| event.created_at)
            .max()
            .unwrap()
    };
    let profile_floor = newest_before(KIND_NOSTR_METADATA);
    let relay_list_floor = newest_before(KIND_NIP65_RELAY_LIST);
    let attempted_before = relay.attempted_events().len();
    reopened
        .publish_user_profile(
            &label,
            UserProfileMetadata {
                name: Some("Fourth".into()),
                ..UserProfileMetadata::default()
            },
            two_relay_bootstrap(),
        )
        .await
        .unwrap();
    reopened
        .publish_account_relay_lists(&label, two_relay_bootstrap())
        .await
        .unwrap();

    let after = relay.attempted_events().split_off(attempted_before);
    for (kind, floor) in [
        (KIND_NOSTR_METADATA, profile_floor),
        (KIND_NIP65_RELAY_LIST, relay_list_floor),
    ] {
        let created_at = after
            .iter()
            .find(|event| event.kind == kind)
            .map(|event| event.created_at)
            .unwrap();
        assert!(
            created_at > floor,
            "kind {kind} after reopen authored {created_at}, not after {floor}"
        );
    }
}
