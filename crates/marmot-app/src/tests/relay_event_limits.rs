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

/// A create whose founding Welcome fits none of the invitee's inbox relays is
/// refused before anything is written: no group, no Welcome owed, and nothing
/// reaches a relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_whose_welcome_fits_no_inbox_relay_is_refused_unsent() {
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
    let attempted = relay.attempted_events().len();

    let error = alice
        .create_group("invite", &[&bob.account_id_hex])
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
    assert!(app.groups("alice").unwrap().is_empty(), "no group was made");
    assert!(alice.pending_welcome_deliveries().unwrap().is_empty());
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "nothing reached a relay"
    );
}

/// A founding Welcome that fits one of the invitee's inbox relays passes the
/// check, and publish sends it to exactly that relay: the check and publish
/// judge the same relays (mdk#2334).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_whose_welcome_fits_one_inbox_relay_sends_it_only_there() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_with_event_limits(&dir, relay.clone(), &[("wss://inbox.example", 200)]);
    let mut inboxes = AccountRelayListStatus::empty();
    inboxes.inbox.created_at = 1;
    inboxes.inbox.relays = vec!["wss://inbox.example".into(), "wss://open.example".into()];
    inboxes.refresh();
    app.directory()
        .remember_directory_relay_lists(&bob.account_id_hex, &inboxes)
        .unwrap();
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

    let welcome_routes: Vec<_> = relay
        .attempted_routes()
        .into_iter()
        .filter(|(kind, _)| *kind == 1059)
        .collect();
    assert_eq!(
        welcome_routes,
        [(1059, vec![TransportEndpoint("wss://open.example".into())])]
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

/// Founding-Welcome sizes measured on both sides of the 64 KiB boundary
/// (mdk#2334); see the notes in the file.
const FOUNDING_WELCOME_SIZES: &str =
    include_str!("../../tests/fixtures/founding_welcome_sizes.json");

#[derive(Debug, serde::Deserialize)]
struct FoundingWelcomeSizes {
    rows: Vec<FoundingWelcomeSize>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FoundingWelcomeSize {
    members: usize,
    mls_welcome_bytes: usize,
    rumor_json_bytes: usize,
    seal_json_bytes: usize,
    gift_wrap_json_bytes: usize,
    gift_wrap_size_class: EventSizeClass,
}

/// Point `account`'s inbox relay list at `relay`, replacing any older list.
fn remember_member_inbox_at(app: &MarmotApp, account_id_hex: &str, relay: &str, created_at: u64) {
    let mut relay_lists = AccountRelayListStatus::empty();
    relay_lists.inbox.created_at = created_at;
    relay_lists.inbox.relays = vec![relay.to_owned()];
    relay_lists.refresh();
    app.directory()
        .remember_directory_relay_lists(account_id_hex, &relay_lists)
        .unwrap();
}

/// The founding Welcome's layers, read from the gift wraps a create sent
/// after `sent_before` of the relay's attempted events. Every invitee's
/// wrap has the same size; the first is opened with its recipient's keys.
fn founding_welcome_size(
    relay: &ScriptedPushRelayClient,
    sent_before: usize,
    members: usize,
    keys: &std::collections::HashMap<String, nostr::prelude::Keys>,
) -> FoundingWelcomeSize {
    use base64::Engine as _;

    let wraps: Vec<_> = relay.attempted_events()[sent_before..]
        .iter()
        .filter(|event| event.kind == 1059)
        .cloned()
        .collect();
    assert_eq!(wraps.len(), members - 1, "one gift wrap per invitee");
    let wrap_sizes: std::collections::BTreeSet<usize> = wraps
        .iter()
        .map(|wrap| serde_json::to_vec(wrap).unwrap().len())
        .collect();
    assert_eq!(wrap_sizes.len(), 1, "every invitee's wrap is the same size");
    let recipient = &keys[wraps[0].single_tag_value("p").unwrap()];
    let wrap = wraps[0].to_verified_nostr_event().unwrap();
    let seal_json =
        nostr::nips::nip44::decrypt(recipient.secret_key(), &wrap.pubkey, &wrap.content).unwrap();
    let seal: NostrTransportEvent = serde_json::from_str(&seal_json).unwrap();
    let rumor_json = nostr::nips::nip44::decrypt(
        recipient.secret_key(),
        &nostr::prelude::PublicKey::from_hex(&seal.pubkey).unwrap(),
        &seal.content,
    )
    .unwrap();
    let rumor: NostrTransportEvent = serde_json::from_str(&rumor_json).unwrap();
    assert_eq!(rumor.kind, 444);
    let gift_wrap_json_bytes = wrap_sizes.into_iter().next().unwrap();
    FoundingWelcomeSize {
        members,
        mls_welcome_bytes: base64::engine::general_purpose::STANDARD
            .decode(&rumor.content)
            .unwrap()
            .len(),
        rumor_json_bytes: rumor_json.len(),
        seal_json_bytes: seal_json.len(),
        gift_wrap_json_bytes,
        gift_wrap_size_class: EventSizeClass::of_bytes(gift_wrap_json_bytes),
    }
}

/// A founding Welcome's bytes, not its roster count, decide the known-limit
/// boundary (mdk#2334). Under a 64 KiB limit the largest roster that fits is
/// created and its Welcomes are sent there; one more member is refused with
/// nothing written or sent. On a 2 MiB relay that larger roster is created.
/// The measured Welcome layers match the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bulk_create_fits_a_known_limit_up_to_the_fixture_boundary() {
    const SMALL: &str = "wss://small.example";
    const LARGE: &str = "wss://large.example";
    const SMALL_LIMIT: u64 = 64 * 1024;
    let expected: FoundingWelcomeSizes = serde_json::from_str(FOUNDING_WELCOME_SIZES).unwrap();
    let (fits, too_large) = expected
        .rows
        .windows(2)
        .find(|pair| {
            pair[0].gift_wrap_json_bytes as u64 <= SMALL_LIMIT
                && pair[1].gift_wrap_json_bytes as u64 > SMALL_LIMIT
        })
        .map(|pair| (pair[0].members, pair[1].members))
        .expect("the fixture has rosters on both sides of 64 KiB");
    assert_eq!(too_large, fits + 1, "the fixture pins adjacent rosters");

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_with_event_limits(
        &dir,
        relay.clone(),
        &[(SMALL, SMALL_LIMIT), (LARGE, 2 * 1024 * 1024)],
    );
    let mut keys = std::collections::HashMap::new();
    let mut invitees = Vec::new();
    for index in 0..too_large - 1 {
        let label = format!("member{index}");
        let member_keys = nostr::prelude::Keys::generate();
        let account = home
            .import_account(&label, &member_keys.secret_key().to_secret_hex())
            .unwrap();
        keys.insert(member_keys.public_key().to_hex(), member_keys);
        remember_member_inbox_at(&app, &account.account_id_hex, LARGE, 1);
        app.client(&label)
            .await
            .unwrap()
            .publish_key_package()
            .await
            .unwrap();
        invitees.push(account.account_id_hex);
    }
    let invitees: Vec<&str> = invitees.iter().map(String::as_str).collect();
    let mut alice = app.client("alice").await.unwrap();
    let mut measured = Vec::new();

    // On the 2 MiB relay both rosters are created.
    for members in [2, too_large] {
        let sent_before = relay.attempted_events().len();
        alice
            .create_group("sizes", &invitees[..members - 1])
            .await
            .unwrap();
        measured.push(founding_welcome_size(&relay, sent_before, members, &keys));
    }
    let too_large_wrap = measured[1].gift_wrap_json_bytes;

    // On the 64 KiB relay the larger roster is refused unsent.
    for invitee in &invitees {
        remember_member_inbox_at(&app, invitee, SMALL, 2);
    }
    let groups = app.groups("alice").unwrap().len();
    let pending = alice.pending_welcome_deliveries().unwrap().len();
    let sent_before = relay.attempted_events().len();
    let error = alice
        .create_group("sizes", &invitees[..too_large - 1])
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::EventTooLarge {
                artifact: OversizedArtifact::Welcome,
                size_class,
            } if size_class == EventSizeClass::of_bytes(too_large_wrap)
        ),
        "{error:?}"
    );
    assert_eq!(
        app.groups("alice").unwrap().len(),
        groups,
        "no group was made"
    );
    assert_eq!(alice.pending_welcome_deliveries().unwrap().len(), pending);
    assert_eq!(
        relay.attempted_events().len(),
        sent_before,
        "nothing was sent"
    );

    // The largest roster that fits is created there, and its Welcomes go
    // only to that relay.
    let routes_before = relay.attempted_routes().len();
    let sent_before = relay.attempted_events().len();
    alice
        .create_group("sizes", &invitees[..fits - 1])
        .await
        .unwrap();
    let welcome_routes: Vec<_> = relay.attempted_routes()[routes_before..]
        .iter()
        .filter(|(kind, _)| *kind == 1059)
        .map(|(_, endpoints)| endpoints.clone())
        .collect();
    assert_eq!(welcome_routes.len(), fits - 1);
    assert!(
        welcome_routes
            .iter()
            .all(|endpoints| endpoints == &[TransportEndpoint(SMALL.into())]),
        "{welcome_routes:?}"
    );
    measured.push(founding_welcome_size(&relay, sent_before, fits, &keys));

    measured.sort_by_key(|row| row.members);
    assert!(measured[1].gift_wrap_json_bytes as u64 <= SMALL_LIMIT);
    assert!(measured[2].gift_wrap_json_bytes as u64 > SMALL_LIMIT);
    assert_eq!(
        measured,
        expected.rows,
        "founding Welcome sizes changed; measured rows:\n{}",
        serde_json::to_string_pretty(&measured).unwrap()
    );
}
