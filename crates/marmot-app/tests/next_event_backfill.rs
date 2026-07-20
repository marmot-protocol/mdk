//! Steady-state coverage for the epoch-gap backfill seam in `next_event`.
//!
//! When a *live* delivery arms the epoch-gap backfill — a run of undecryptable
//! traffic at a stalled epoch crossing `EPOCH_STALL_BACKFILL_THRESHOLD` — the
//! arming produces no visible `SyncSummary` content (an undecryptable kind-445
//! yields `IngestOutcome::Stale`, no `MarmotAppEvent`). `next_event` must still
//! RETURN so the worker's post-`next_event`
//! `run_pending_epoch_backfill` seam (`runtime/account_worker.rs`) runs. If the
//! empty-summary guard does not also check `epoch_backfill_pending`, the call
//! instead `continue`s and blocks on the next `receive()` — for a permanently
//! stalled group that next visible event may never arrive, so the armed backfill
//! is never acted on: a liveness gap.
//!
//! This drives `AppClient::next_event` directly (the worker's exact call, at
//! `account_worker.rs`) rather than through the full runtime. The observable is
//! precisely "did `next_event` return", which the telemetry-based `since_floor`
//! harness cannot see: it exercises the cold-boot catch-up seam
//! (`run_pending_epoch_backfill` after the initial `sync()`), not the live
//! `next_event` seam this test pins. Before the guard learned about
//! `epoch_backfill_pending` this call hangs, and the timeout below is the RED
//! signal.

use std::time::{Duration, Instant};

use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppConfig};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::{
    Alphabet, Client as NostrSdkClient, EventBuilder, Keys, Kind, SingleLetterTag, Tag, TagKind,
    Timestamp as NostrTimestamp,
};
use tokio::time::{sleep, timeout};
use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};
use transport_nostr_peeler::{NOSTR_GROUP_CONTENT_MIN_LEN, NostrTransportEvent};

/// Mirrors `marmot_app::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD`
/// (crate-private, hence mirrored): the number of distinct undecryptable
/// messages a group must accumulate at one stalled epoch before the runtime
/// arms a full-history epoch-gap backfill.
const BACKFILL_THRESHOLD: usize = 8;

/// How long the arming `next_event` call is allowed to run before the test
/// gives up. With the fix it returns as soon as the threshold-crossing delivery
/// arms the backfill; without it the call blocks forever on the next
/// `receive()`, and this bound is the RED failure.
const NEXT_EVENT_DEADLINE: Duration = Duration::from_secs(10);

/// Deadline for bob's welcome to arrive and the group to become live.
const JOIN_DEADLINE: Duration = Duration::from_secs(10);

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

/// Publish an envelope-shaped undecryptable kind-445 probe with a fresh
/// ephemeral key and a caller-chosen `created_at`, h-tagged to
/// `nostr_group_id_hex`. Copied from `since_floor.rs`: real kind-445 senders are
/// always a fresh per-event key, and a zero-nonce marker body peels to a clean
/// `PeelerError::DecryptFailed`, the `IngestOutcome::Stale { PeelFailed }` shape
/// the epoch-stall detector counts.
async fn publish_garbage_group_message_at(
    relay_url: &str,
    nostr_group_id_hex: &str,
    created_at: u64,
    marker: &str,
) {
    let mut envelope = vec![0u8; 12];
    envelope.extend_from_slice(format!("backfill-seam-probe:{marker}").as_bytes());
    assert!(envelope.len() >= NOSTR_GROUP_CONTENT_MIN_LEN);
    let ephemeral = Keys::generate();
    let signed = EventBuilder::new(Kind::MlsGroupMessage, BASE64_STANDARD.encode(envelope))
        .tags([Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::H)),
            [nostr_group_id_hex.to_owned()],
        )])
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .sign_with_keys(&ephemeral)
        .expect("sign ephemeral kind-445 test event");
    let transport_event =
        NostrTransportEvent::from_nostr_event(&signed).expect("dto from signed event");
    let relay_client = NostrSdkRelayClient::new(NostrSdkClient::builder().build());
    relay_client
        .publish_event(
            &[cgka_traits::TransportEndpoint(relay_url.to_owned())],
            &transport_event,
            1,
        )
        .await
        .expect("publish garbage kind-445 test event");
}

/// A live delivery that arms the epoch-gap backfill but yields no visible
/// summary content must still make `next_event` return, so the worker reaches
/// its `run_pending_epoch_backfill` seam.
#[tokio::test]
async fn next_event_returns_when_a_live_delivery_arms_the_epoch_backfill() {
    let (_relay, url) = mock_relay().await;

    // --- bob: the stalled account whose `next_event` seam we pin ---
    let dir_bob = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(dir_bob.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;
    let app_bob = open_store(&dir_bob, &url);
    {
        let mut bob_setup = app_bob.client("bob").await.unwrap();
        bob_setup.publish_key_package().await.unwrap();
    }

    // --- alice: separate store, only creates the group so bob has a live
    // group subscription to receive undecryptable traffic on ---
    let dir_alice = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(dir_alice.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&dir_alice, &url);
    let mut alice_client = app_alice.client("alice").await.unwrap();
    let group_id = alice_client
        .create_group("epoch-gap backfill next_event seam", &[bob_id.as_str()])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    // bob joins by draining the welcome; poll `sync` until the group is live so
    // its route is subscribed and later garbage is delivered on it.
    let mut bob = app_bob.client("bob").await.unwrap();
    let deadline = Instant::now() + JOIN_DEADLINE;
    loop {
        bob.sync().await.unwrap();
        if app_bob.group("bob", &group_id_hex).unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bob did not join the group within the deadline",
        );
        sleep(Duration::from_millis(50)).await;
    }

    let nostr_group_id_hex = app_bob
        .group("bob", &group_id_hex)
        .unwrap()
        .expect("bob's group projection")
        .nostr_routing
        .nostr_group_id_hex;

    // Arm the detector with exactly `BACKFILL_THRESHOLD` distinct undecryptable
    // messages at bob's live epoch. Present-dated so they clear any since floor
    // and reach bob's live subscription; distinct markers make distinct event
    // ids, hence distinct undecryptables at the one stalled epoch. None produces
    // a visible `MarmotAppEvent`, so the summary stays empty across all of them
    // and only the armed backfill can force the return.
    let created_at = test_unix_now_seconds();
    for arm in 0..BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &url,
            &nostr_group_id_hex,
            created_at,
            &format!("arm-{arm}"),
        )
        .await;
    }

    // The threshold-crossing delivery arms the backfill with an empty summary.
    // With the guard fix `next_event` returns here; without it the call blocks
    // on the next `receive()` and this timeout is the RED failure.
    let summary = timeout(NEXT_EVENT_DEADLINE, bob.next_event())
        .await
        .expect("next_event must return once a live delivery arms the epoch backfill")
        .expect("next_event should not error");

    // The return is driven purely by the armed backfill: the undecryptable
    // probes carry no visible content, so an empty summary is the expected and
    // harmless payload the worker forwards to `publish_app_runtime_summary`.
    assert!(
        summary.joined_groups.is_empty()
            && summary.messages.is_empty()
            && summary.events.is_empty(),
        "the arming deliveries are undecryptable and must not surface visible \
         summary content; the return is forced by the armed backfill alone",
    );
}
