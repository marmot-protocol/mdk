//! Events over a relay's known limit are refused before they are sent (mdk#2334).

use super::*;

/// An app whose deployment gives these relays known event limits. Its group
/// relay is `wss://relay.example`.
fn app_with_event_limits(
    dir: &tempfile::TempDir,
    relay: Arc<ScriptedPushRelayClient>,
    limits: &[(&str, u64)],
) -> MarmotApp {
    let deployment = MarmotDeployment {
        relay_event_limits: limits
            .iter()
            .map(|(relay, max_event_bytes)| RelayEventLimit {
                relay: (*relay).to_owned(),
                max_event_bytes: *max_event_bytes,
            })
            .collect(),
        ..MarmotDeployment::white_noise()
    };
    MarmotApp::with_relays_and_config(
        dir.path(),
        vec!["wss://relay.example".into()],
        MarmotAppConfig::white_noise()
            .with_deployment(deployment)
            .with_allow_loopback_relay_endpoints(true)
            .with_open_ranking_provider(None, Vec::new()),
    )
    .with_test_relay_client(relay)
}

/// A commit or message over its group relay's known limit is never sent: it
/// fails as too large, and the commit rolls back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_events_over_a_known_limit_are_refused_unsent() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_with_event_limits(&dir, relay.clone(), &[("wss://relay.example", 200)]);
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("limited", &[]).await.unwrap();
    let epoch = client.runtime.epoch_state(&group).unwrap().epoch();
    let attempted = relay.attempted_events().len();

    let error = client
        .update_group_profile(&group, Some("renamed"), None)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::EventTooLarge {
                artifact: OversizedArtifact::Commit,
                size_class: EventSizeClass::Under64Kib,
            }
        ),
        "{error:?}"
    );
    let state = client.runtime.epoch_state(&group).unwrap();
    assert!(
        matches!(state, cgka_traits::engine_state::EpochState::Stable { .. }),
        "the refused commit rolled back: {state:?}"
    );
    assert_eq!(state.epoch(), epoch);

    let error = client.send(&group, &[b'x'; 1_000]).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::EventTooLarge {
                artifact: OversizedArtifact::ApplicationMessage,
                size_class: EventSizeClass::Under64Kib,
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "neither event reached a relay"
    );
}

/// A Welcome over every inbox relay's known limit is never sent. It stays
/// owed, and its pending delivery names its size like a relay's refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_welcome_over_the_inbox_limit_stays_owed_with_its_size() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_with_event_limits(&dir, relay.clone(), &[("wss://inbox.example", 200)]);
    remember_test_member_inbox(&app, &bob.account_id_hex, "wss://inbox.example");
    app.client("bob")
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap();
    let mut alice = app.client("alice").await.unwrap();

    alice
        .create_group("invite", &[&bob.account_id_hex])
        .await
        .unwrap();

    let owed = alice.pending_welcome_deliveries().unwrap();
    assert_eq!(owed.len(), 1, "the refused Welcome stays owed");
    assert_eq!(owed[0].size_class, Some(EventSizeClass::Under64Kib));
    assert!(
        relay
            .attempted_events()
            .iter()
            .all(|event| event.kind != 1059),
        "no Welcome reached a relay"
    );
}

/// An invite whose Welcome fits none of the invitee's inbox relays is refused
/// before its commit is sent: the commit rolls back, no Welcome stays owed,
/// and nothing reaches a relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invite_whose_welcome_fits_no_inbox_relay_is_refused_unsent() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_with_event_limits(&dir, relay.clone(), &[("wss://inbox.example", 200)]);
    remember_test_member_inbox(&app, &bob.account_id_hex, "wss://inbox.example");
    app.client("bob")
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let group = alice.create_group("invite", &[]).await.unwrap();
    let epoch = alice.runtime.epoch_state(&group).unwrap().epoch();
    let attempted = relay.attempted_events().len();

    let error = alice
        .invite_members(&group, &[bob.account_id_hex.as_str()])
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            AppError::EventTooLarge {
                artifact: OversizedArtifact::Welcome,
                size_class: EventSizeClass::Under64Kib,
            }
        ),
        "{error:?}"
    );
    let state = alice.runtime.epoch_state(&group).unwrap();
    assert!(
        matches!(state, cgka_traits::engine_state::EpochState::Stable { .. }),
        "the refused invite rolled back: {state:?}"
    );
    assert_eq!(state.epoch(), epoch);
    assert!(alice.pending_welcome_deliveries().unwrap().is_empty());
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "neither the commit nor the Welcome reached a relay"
    );
}

/// Account publishes, a profile here, go through the same refusal: no relay is
/// sent an event over its known limit, and an event over every relay's limit
/// fails as too large, sent nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_publishes_over_a_known_limit_are_refused_unsent() {
    let dir = tempfile::tempdir().unwrap();
    let alice = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_with_event_limits(&dir, relay.clone(), &[("wss://limited.example", 200)]);
    let limited = TransportEndpoint("wss://limited.example".into());
    let open = TransportEndpoint("wss://open.example".into());
    let profile = UserProfileMetadata {
        about: Some("x".repeat(500)),
        ..UserProfileMetadata::default()
    };
    let profile_routes = || {
        relay
            .attempted_routes()
            .into_iter()
            .filter(|(kind, _)| *kind == 0)
            .collect::<Vec<_>>()
    };

    let error = app
        .publish_user_profile(
            &alice.label,
            profile.clone(),
            AccountRelayListBootstrap::new(vec![limited.clone()], Vec::new()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::EventTooLarge {
                artifact: OversizedArtifact::Other,
                size_class: EventSizeClass::Under64Kib,
            }
        ),
        "{error:?}"
    );
    assert!(profile_routes().is_empty(), "no relay was sent the profile");

    app.publish_user_profile(
        &alice.label,
        profile,
        AccountRelayListBootstrap::new(vec![limited, open.clone()], Vec::new()),
    )
    .await
    .unwrap();
    assert_eq!(profile_routes(), [(0, vec![open])]);
}
