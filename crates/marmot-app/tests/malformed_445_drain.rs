//! Acceptance test for hostile-input resilience of the transport drain.
//!
//! Anyone can publish a kind-445 event to a group's cleartext routing tag
//! without being a member, so an event carrying tags outside the exact
//! `h`/optional-`expiration` shape is ordinary hostile wire input, not an
//! exceptional condition. It must be rejected before engine delivery and
//! never surface as a sync failure: an ingest error that aborts the whole
//! catch-up drain loses the sync
//! summary (and with it every `MessageReceived` event the drain had
//! produced), skips the app-state save, and — because the garbage event
//! remains unremembered — re-aborts every subsequent catch-up the relay
//! replays it into. One garbage event starves every message queued behind it.
//!
//! The shape mirrors `since_floor.rs`'s cold-boot harness (see that file's
//! module docs for why one account per store and why a full shutdown, not
//! `restart_account`): bob goes fully offline, a malformed kind-445 and a
//! real message land in his backlog, and a cold boot's first catch-up must
//! deliver the real message and record zero sync failures.

use std::time::Duration;

use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppConfig, MarmotAppEvent, MarmotAppRuntime};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::{
    Alphabet, Client as NostrSdkClient, EventBuilder, Keys, Kind, SingleLetterTag, Tag, TagKind,
    Timestamp as NostrTimestamp,
};
use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};
use transport_nostr_peeler::{NOSTR_GROUP_CONTENT_MIN_LEN, NostrPeelerError, NostrTransportEvent};

async fn mock_relay() -> (MockRelay, String) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

fn open_store(dir: &tempfile::TempDir, relay_url: &str) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        relay_url.to_owned(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    )
}

fn test_unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn wait_for_event<F>(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    mut matches_event: F,
) where
    F: FnMut(&MarmotAppEvent) -> bool,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.unwrap();
            if matches_event(&event) {
                return;
            }
        }
    })
    .await
    .expect("runtime event")
}

/// Publish a signed kind-445 carrying a forbidden extra tag. The direct mapping
/// assertion and the cold relay catch-up exercise the same fixture at both
/// ingress seams; neither may deliver it to engine state.
async fn publish_malformed_group_message_at(
    relay_url: &str,
    nostr_group_id_hex: &str,
    created_at: u64,
) {
    let short = b"too short";
    assert!(short.len() < NOSTR_GROUP_CONTENT_MIN_LEN);
    let ephemeral = Keys::generate();
    let signed = EventBuilder::new(Kind::MlsGroupMessage, BASE64_STANDARD.encode(short))
        .tags([
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::H)),
                [nostr_group_id_hex.to_owned()],
            ),
            Tag::custom(TagKind::custom("encoding"), ["base64"]),
        ])
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .sign_with_keys(&ephemeral)
        .expect("sign ephemeral kind-445 test event");
    let transport_event =
        NostrTransportEvent::from_nostr_event(&signed).expect("dto from signed event");
    assert!(matches!(
        transport_event.to_transport_message(),
        Err(NostrPeelerError::Malformed(_))
    ));
    let relay_client = NostrSdkRelayClient::new(NostrSdkClient::builder().build());
    relay_client
        .publish_event(
            &[cgka_traits::TransportEndpoint(relay_url.to_owned())],
            &transport_event,
            1,
        )
        .await
        .expect("publish malformed kind-445 test event");
}

fn account_sync_failures(runtime: &MarmotAppRuntime) -> u64 {
    runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot()
        .account_sync
        .failures
}

#[tokio::test]
async fn malformed_group_message_does_not_starve_messages_behind_it() {
    let (_relay, url) = mock_relay().await;

    // One account per store, exactly as documented in `since_floor.rs`.
    let dir_bob = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(dir_bob.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;

    let dir_alice = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(dir_alice.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&dir_alice, &url);

    // --- boot 1: bob live, joins the group ---
    let app_bob_boot1 = open_store(&dir_bob, &url);
    {
        let mut bob_setup = app_bob_boot1.client("bob").await.unwrap();
        bob_setup.publish_key_package().await.unwrap();
    }
    let runtime_bob_boot1 = MarmotAppRuntime::new(app_bob_boot1.clone());
    let mut events_bob_boot1 = runtime_bob_boot1.subscribe();
    runtime_bob_boot1.start().await.unwrap();

    let mut alice_client = app_alice.client("alice").await.unwrap();
    let group_id = alice_client
        .create_group("malformed drain resilience", &[bob_id.as_str()])
        .await
        .unwrap();
    wait_for_event(&mut events_bob_boot1, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined, .. }
                if account_id_hex == &bob_id && joined == &group_id
        )
    })
    .await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let nostr_group_id_hex = app_bob_boot1
        .group("bob", &group_id_hex)
        .unwrap()
        .expect("bob's group projection")
        .nostr_routing
        .nostr_group_id_hex;

    // bob fully offline before the hostile event and the real message land in
    // his backlog (a live subscription would deliver them piecemeal; the
    // production wedge is the cold catch-up drain that replays both at once).
    runtime_bob_boot1.shutdown().await;

    // Hostile input first (slightly in the past), then a real message behind
    // it — the delivery this test insists must survive the garbage.
    publish_malformed_group_message_at(
        &url,
        &nostr_group_id_hex,
        test_unix_now_seconds().saturating_sub(30),
    )
    .await;
    alice_client
        .send(&group_id, b"delivered behind the garbage")
        .await
        .unwrap();

    // --- boot 2: the cold catch-up must drain past the garbage ---
    let app_bob_boot2 = open_store(&dir_bob, &url);
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2.clone());
    let mut events_bob_boot2 = runtime_bob_boot2.subscribe();
    runtime_bob_boot2.start().await.unwrap();
    wait_for_event(&mut events_bob_boot2, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "delivered behind the garbage"
        )
    })
    .await;
    assert_eq!(
        account_sync_failures(&runtime_bob_boot2),
        0,
        "hostile wire input must be rejected before engine delivery, never \
         surface as a sync failure",
    );
    runtime_bob_boot2.shutdown().await;
}
