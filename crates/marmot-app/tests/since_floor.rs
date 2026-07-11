//! Characterization test for the since-floor commit-loss defect
//! (`plan.md`, "The defect, in two sentences"):
//!
//! > `last_transport_timestamp` is one account-wide durable cursor advanced
//! > from the sender-controlled `created_at` of every ingested kind-445
//! > (undecryptable included), and every subscription rebuild floors at
//! > `since = cursor − 120s` — so any 445 not delivered while the cursor was
//! > still low is permanently unfetchable, with no gap detection.
//!
//! This test PINS today's behavior on purpose: an event whose `created_at`
//! falls below the rebuilt subscription's `since` floor is never delivered to
//! the runtime, while a sibling event just above the floor is delivered —
//! and the miss survives a cold restart because the floor is derived from a
//! durable, monotonic cursor. It is deliberately independent of Phases 1-6:
//! Phase 4 (frozen wake-collection cursor) does not change this outcome (a
//! `Frozen` wake between the two probe events still leaves the same floor in
//! place), and Phases 5/6 (EOSE-gated cursor completeness, epoch-gap
//! backfill) are the fixes that are expected to flip these assertions —
//! when they land, the below-floor probe should start arriving (via
//! backfill) and this file's expectations must be updated accordingly.
//!
//! # Why one account per store
//!
//! `MarmotRelayPlane` runs one shared router per `MarmotApp`/store
//! (`relay_plane/mod.rs`): every locally managed account's group and inbox
//! subscriptions are dispatched through the same underlying SDK client and
//! routing index. Two accounts opened from the *same* store would therefore
//! share delivery plumbing, and an unrelated account's still-open, unfloored
//! subscription can mask the very floor this test exists to pin (a
//! documented harness pitfall — see `plan.md` Phase 7 and the handoff notes).
//! This test gives the probed account (`bob`) its own store; `alice` — who
//! only needs to create the group and send one ordinary message — gets a
//! second, independent store pointed at the same relay.
//!
//! # Why a cold restart, not `restart_account`
//!
//! A relay only honors NIP-01 `since` for the *initial* backlog reply to a
//! freshly issued `REQ`; once a subscription is live, any newly published
//! event matching its filter streams in immediately, with no regard to
//! `created_at`. So publishing the two probe events while `bob`'s group
//! subscription is still open would deliver *both* of them live and prove
//! nothing about the floor. The two probe events must instead be published
//! while `bob` is completely disconnected, so a *subsequent* fresh
//! subscription's initial backlog replay is what the relay's `since` bound
//! actually filters.
//!
//! `MarmotAppRuntime::restart_account` cannot create that disconnected
//! window: the new worker's `activate_account` unsubscribes the old
//! registration and re-subscribes in the same call, with no gap in which to
//! publish. A full `MarmotAppRuntime::shutdown()` is also unsuitable to
//! resume from: it calls the underlying SDK relay pool's `shutdown()`, which
//! nostr-sdk documents as terminal ("the `RelayPool` can no longer be used").
//!
//! So this test drives the rebuild the way the confirmed iOS trigger actually
//! does it (`plan.md`: "a full runtime per push"): it shuts a fully-live
//! runtime down for good, publishes the probe events while `bob` has no
//! store-side app instance running at all, then opens a *brand new*
//! `MarmotApp`/`MarmotAppRuntime` pair against the same on-disk store. That
//! new pair's first subscription rebuild is a genuine cold boot, and doing it
//! twice (independently) demonstrates the permanence property: the
//! below-floor probe never arrives, not even on a second independent boot.
//!
//! # Delivery observable
//!
//! The two probe events are deliberately undecryptable garbage (spec allows
//! this: kind-445 senders are always a fresh per-event key, unrelated to any
//! account identity, and this test exercises *delivery*, not decryption). An
//! undecryptable delivery produces no `MarmotAppEvent` — decrypt failure
//! yields `IngestOutcome::Stale` with no observable side effect at the
//! `MarmotAppRuntime` event-stream layer. The chosen observable is instead
//! `MarmotApp::relay_telemetry().metrics.inbound_events_delivered`
//! (`transport-nostr-adapter`'s `NostrAdapterMetrics`, already public,
//! already used by other tests in this crate via `relay_telemetry()`/
//! `relay_health()`). It increments in `NostrTransportAdapter::handle_relay_event`
//! the moment a relay event is routed to a locally subscribed account —
//! before, and independent of, any engine-level decrypt attempt — so it is a
//! faithful "did this reach the runtime" signal for a payload that is
//! designed to decrypt-fail. No new test-support surface was needed for
//! this: the existing public telemetry API is sufficient.
//!
//! Because a cold boot's *first* catch-up also naturally re-delivers the
//! group's real history (the welcome and the one ordinary message this test
//! sends to advance the cursor), the test measures that legitimate count on
//! the very first (still-live) boot rather than assuming it, then asserts
//! each subsequent cold boot's delivered count is exactly
//! `legitimate_count + 1` (the sibling, and only the sibling) — never
//! `+ 2` (which would mean the below-floor probe leaked through).

use std::time::{Duration, Instant};

use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppConfig, MarmotAppEvent, MarmotAppRuntime};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::{
    Alphabet, Client as NostrSdkClient, EventBuilder, Keys, Kind, SingleLetterTag, Tag, TagKind,
    Timestamp as NostrTimestamp,
};
use tokio::time::sleep;
use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

/// Mirrors `marmot_app::lib.rs`'s private `APP_RUNTIME_RELAY_REBUILD_LOOKBACK`
/// (120s). Not importable (crate-private); every production runtime plane
/// uses this exact fixed value, so the test must match it, not merely be
/// consistent with itself.
const REBUILD_LOOKBACK_SECS: u64 = 120;

/// How long a cold boot's initial catch-up is allowed to take before this
/// test gives up waiting for it. Generous relative to the crate's own
/// `SDK_FIRST_SYNC_WAIT` (750ms) / `SDK_DRAIN_WAIT` (250ms) internals.
const CATCH_UP_DEADLINE: Duration = Duration::from_secs(10);

/// Extra settle margin after the catch-up telemetry op is recorded, in case
/// any last delivery's routing telemetry update is still landing.
const TELEMETRY_SETTLE_GRACE: Duration = Duration::from_millis(250);

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
    tokio::time::timeout(Duration::from_secs(5), async {
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

fn account_sync_attempts(runtime: &MarmotAppRuntime) -> u64 {
    runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot()
        .account_sync
        .attempts
}

/// Poll for a cold boot's first catch-up to complete. `restart`/`start` are
/// documented (and independently confirmed by this crate's own
/// `app_runtime_serves_member_reads_before_initial_catch_up_completes` test)
/// to return once the worker is command-ready, not once the background
/// catch-up finishes — so this must poll rather than assume the call awaited
/// the sync.
async fn wait_for_first_catch_up(runtime: &MarmotAppRuntime) {
    let deadline = Instant::now() + CATCH_UP_DEADLINE;
    loop {
        if account_sync_attempts(runtime) > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "cold-boot catch-up did not complete within the deadline",
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn inbound_events_delivered(app: &MarmotApp) -> usize {
    app.relay_telemetry().await.metrics.inbound_events_delivered
}

/// Publish a kind-445 group-message event at the wire level with a fresh,
/// arbitrary (non-member) ephemeral signing key and a caller-chosen
/// `created_at`. This is legitimate wire traffic, not a forged event: real
/// kind-445 senders are always a fresh per-event key, never the account
/// identity (spec/transports/nostr.md:64-66; mirrors the existing
/// `signed_group_event_dto` precedent in
/// `transport-nostr-adapter/src/sdk_client.rs`'s own tests). The content is
/// undecryptable garbage — this test exercises delivery, not decryption.
async fn publish_garbage_group_message_at(
    relay_url: &str,
    nostr_group_id_hex: &str,
    created_at: u64,
    marker: &str,
) {
    let ephemeral = Keys::generate();
    let signed = EventBuilder::new(
        Kind::MlsGroupMessage,
        BASE64_STANDARD.encode(format!("since-floor-probe:{marker}").as_bytes()),
    )
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

#[tokio::test]
async fn cold_restart_since_floor_permanently_drops_backlog_below_it() {
    let (_relay, url) = mock_relay().await;

    // --- bob's store: the account whose since-floor we are pinning ---
    let dir_bob = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(dir_bob.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;

    // --- alice's store: a separate account/store, only used to create the
    // group and send one ordinary message. Kept apart from bob's store per
    // the one-account-per-store rule above. ---
    let dir_alice = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(dir_alice.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&dir_alice, &url);

    // --- boot 1: bob live, joins the group, receives one ordinary message ---
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
        .create_group("since floor characterization", &[bob_id.as_str()])
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

    // Ordinary traffic: advances bob's durable transport cursor exactly the
    // way the defect describes (every ingested kind-445 advances it).
    alice_client
        .send(&group_id, b"ordinary traffic advances the cursor")
        .await
        .unwrap();
    wait_for_event(&mut events_bob_boot1, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "ordinary traffic advances the cursor"
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

    // Measure (not assume) how many kind-445/1059 deliveries a fresh cold
    // boot will legitimately re-fetch: the welcome and this one message. This
    // is exactly what boot 1's own live subscription needed to receive to
    // reach this point.
    let legitimate_delivery_count = inbound_events_delivered(&app_bob_boot1).await;

    // Reference wall-clock used to place the two probe events relative to
    // the floor. `reference_now` is captured after the message is confirmed
    // received, so it is a safe upper bound on the real cursor (cursor <=
    // reference_now); the margins below (180s / 60s either side of the
    // assumed floor) comfortably absorb that skew.
    let reference_now = test_unix_now_seconds();
    let floor_estimate = reference_now.saturating_sub(REBUILD_LOOKBACK_SECS);
    let below_floor_created_at = floor_estimate.saturating_sub(180);
    let above_floor_created_at = floor_estimate.saturating_add(60);
    assert!(above_floor_created_at < reference_now);

    // bob must be fully offline before the probes are published: a still-open
    // subscription would deliver them live regardless of `created_at` (see
    // the module doc comment). This is boot 1's last use — never reopened.
    runtime_bob_boot1.shutdown().await;

    publish_garbage_group_message_at(&url, &nostr_group_id_hex, below_floor_created_at, "below")
        .await;
    publish_garbage_group_message_at(&url, &nostr_group_id_hex, above_floor_created_at, "above")
        .await;

    // --- boot 2: cold restart, first subscription rebuild since the probes
    // landed ---
    let app_bob_boot2 = open_store(&dir_bob, &url);
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2.clone());
    runtime_bob_boot2.start().await.unwrap();
    wait_for_first_catch_up(&runtime_bob_boot2).await;
    sleep(TELEMETRY_SETTLE_GRACE).await;
    let delivered_after_boot2 = inbound_events_delivered(&app_bob_boot2).await;
    assert_eq!(
        delivered_after_boot2,
        legitimate_delivery_count + 1,
        "only the above-floor sibling should reach ingest on a cold boot; the \
         below-floor probe must be silently dropped by the rebuilt \
         subscription's since floor (plan.md Phase 7 / 'the defect, in two \
         sentences')",
    );
    runtime_bob_boot2.shutdown().await;

    // --- boot 3: a second, independent cold restart — the permanence
    // property. If the miss were a timing fluke rather than a permanent
    // consequence of the durable cursor, a second independent rebuild could
    // behave differently; it must not. ---
    let app_bob_boot3 = open_store(&dir_bob, &url);
    let runtime_bob_boot3 = MarmotAppRuntime::new(app_bob_boot3.clone());
    runtime_bob_boot3.start().await.unwrap();
    wait_for_first_catch_up(&runtime_bob_boot3).await;
    sleep(TELEMETRY_SETTLE_GRACE).await;
    let delivered_after_boot3 = inbound_events_delivered(&app_bob_boot3).await;
    assert_eq!(
        delivered_after_boot3,
        legitimate_delivery_count + 1,
        "a second, independent cold restart must still never deliver the \
         below-floor probe: the miss is permanent, not a one-off timing \
         fluke (plan.md Phase 7 permanence property)",
    );
    runtime_bob_boot3.shutdown().await;
}
