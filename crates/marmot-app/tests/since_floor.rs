//! Characterization test for the since-floor defect. In two sentences:
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
//! durable, monotonic cursor. It is deliberately independent of the other
//! fixes: the frozen wake-collection cursor does not change this outcome (a
//! `Frozen` wake between the two probe events still leaves the same floor in
//! place), and EOSE-gated cursor completeness and epoch-gap backfill are the
//! fixes that are expected to flip these assertions — when they land, the
//! below-floor probe should start arriving (via backfill) and this file's
//! expectations must be updated accordingly.
//!
//! Epoch-gap backfill has since landed, splitting this file in two:
//! `cold_restart_since_floor_permanently_drops_backlog_below_it` still pins the
//! UNARMED floor-drop (one undecryptable probe stays under the backfill
//! threshold, so it stays dropped forever), while
//! `stalled_epoch_backfill_recovers_below_floor_backlog_when_armed` pins the
//! ARMED recovery of below-floor backlog through the full-history backfill.
//!
//! # Why one account per store
//!
//! `MarmotRelayPlane` runs one shared router per `MarmotApp`/store
//! (`relay_plane/mod.rs`): every locally managed account's group and inbox
//! subscriptions are dispatched through the same underlying SDK client and
//! routing index. Two accounts opened from the *same* store would therefore
//! share delivery plumbing, and an unrelated account's still-open, unfloored
//! subscription can mask the very floor this test exists to pin (a
//! known harness pitfall).
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
//! does it — a full runtime per push: it shuts a fully-live
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
use transport_nostr_peeler::{NOSTR_GROUP_CONTENT_MIN_LEN, NostrTransportEvent};

/// Mirrors `marmot_app::lib.rs`'s private `APP_RUNTIME_RELAY_REBUILD_LOOKBACK`
/// (120s). Not importable (crate-private); every production runtime plane
/// uses this exact fixed value, so the test must match it, not merely be
/// consistent with itself.
const REBUILD_LOOKBACK_SECS: u64 = 120;

/// Mirrors `marmot_app::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD`
/// (crate-private, hence mirrored): the number of distinct undecryptable
/// messages a group must accumulate at one stalled epoch before the runtime
/// arms a full-history epoch-gap backfill.
const BACKFILL_THRESHOLD: usize = 8;

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

/// Poll delivery telemetry until at least `target` inbound events have been
/// routed to the account, failing at `CATCH_UP_DEADLINE`. A behavioral await
/// on observable state: the epoch-gap backfill replay runs *after* the initial
/// catch-up op is recorded, so `wait_for_first_catch_up` alone cannot see it —
/// the delivered count is the signal that the replay has landed.
async fn wait_for_inbound_delivered(app: &MarmotApp, target: usize) {
    let deadline = Instant::now() + CATCH_UP_DEADLINE;
    loop {
        let delivered = inbound_events_delivered(app).await;
        if delivered >= target {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "inbound deliveries stalled at {delivered}, expected at least \
             {target} within the deadline",
        );
        sleep(Duration::from_millis(25)).await;
    }
}

/// Publish a kind-445 group-message event at the wire level with a fresh,
/// arbitrary (non-member) ephemeral signing key and a caller-chosen
/// `created_at`. This is legitimate wire traffic, not a forged event: real
/// kind-445 senders are always a fresh per-event key, never the sender's
/// Marmot account identity. This mirrors the existing `signed_group_event_dto`
/// precedent in `transport-nostr-adapter/src/sdk_client.rs`'s own tests.
///
/// The content is an *envelope-shaped* undecryptable probe. Per
/// `spec/transports/nostr.md`, kind-445 content is `base64(nonce ||
/// ciphertext)`; the probe carries a zero nonce plus marker bytes that
/// authenticate under no key, so the recipient peels it to a clean
/// `PeelerError::DecryptFailed` — the same shape as real traffic sealed under
/// an exporter secret this device does not hold, and the shape the epoch-stall
/// detector counts as `IngestOutcome::Stale { reason: PeelFailed }`. (A
/// shorter-than-envelope body would instead be `Malformed`, a hard ingest
/// error rather than an undecryptable-message observation.)
async fn publish_garbage_group_message_at(
    relay_url: &str,
    nostr_group_id_hex: &str,
    created_at: u64,
    marker: &str,
) {
    // 12-byte zero nonce, then the marker as the unauthenticatable ciphertext.
    let mut envelope = vec![0u8; 12];
    envelope.extend_from_slice(format!("since-floor-probe:{marker}").as_bytes());
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
         subscription's since floor",
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
         fluke (the permanent-drop property)",
    );
    runtime_bob_boot3.shutdown().await;
}

/// The armed counterpart to
/// [`cold_restart_since_floor_permanently_drops_backlog_below_it`]: with enough
/// undecryptable traffic at a stalled epoch, epoch-gap backfill recovers the
/// backlog the rebuilt subscription's since floor would otherwise drop forever.
///
/// The probes play two distinct roles on either side of the floor:
///
/// - **Arming** (`arm-0`..`arm-7`, above the floor): the cold boot's ordinary
///   floored catch-up delivers them, each fails to peel, and — being distinct
///   event ids — each counts as a distinct undecryptable message at bob's
///   stalled epoch. The eighth crosses `EPOCH_STALL_BACKFILL_THRESHOLD` and
///   arms a full-history transport replay (`since = None`).
/// - **Recovery target** (`below-target`, below the floor): the floored
///   catch-up can never deliver it; the only path to ingest is the unfloored
///   backfill replay the arming probes trigger.
///
/// Boot 2 pins the heal itself. Boot 3 pins that the heal is *durable and
/// debounced*: ingested event ids persist in the account's seen-event state,
/// so a later cold boot neither re-arms the detector nor replays full history
/// again — recovery costs one backfill, not one per boot.
#[tokio::test]
async fn stalled_epoch_backfill_recovers_below_floor_backlog_when_armed() {
    let (_relay, url) = mock_relay().await;

    // Same one-account-per-store split as the floor-drop test above.
    let dir_bob = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(dir_bob.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;

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
        .create_group("epoch-gap backfill recovery", &[bob_id.as_str()])
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

    // Measured, not assumed, exactly as in the floor-drop test: how many
    // deliveries a fresh cold boot legitimately re-fetches (the welcome and
    // the one ordinary message).
    let legitimate_delivery_count = inbound_events_delivered(&app_bob_boot1).await;

    // Same floor placement as the floor-drop test above.
    let reference_now = test_unix_now_seconds();
    let floor_estimate = reference_now.saturating_sub(REBUILD_LOOKBACK_SECS);
    let below_floor_created_at = floor_estimate.saturating_sub(180);
    let above_floor_created_at = floor_estimate.saturating_add(60);
    assert!(above_floor_created_at < reference_now);

    // bob must be fully offline before any probe is published (see the module
    // doc comment on live subscriptions ignoring `since`).
    runtime_bob_boot1.shutdown().await;

    // The recovery target: below the floor, unreachable by any floored
    // catch-up — only an unfloored backfill replay can deliver it.
    publish_garbage_group_message_at(
        &url,
        &nostr_group_id_hex,
        below_floor_created_at,
        "below-target",
    )
    .await;
    // The arming probes: above the floor, so the ordinary catch-up delivers
    // them. Distinct markers make distinct event ids, hence distinct
    // undecryptable messages at bob's stalled epoch.
    for arm in 0..BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &url,
            &nostr_group_id_hex,
            above_floor_created_at,
            &format!("arm-{arm}"),
        )
        .await;
    }

    // Expected exact delivery count for the armed cold boot:
    //   legitimate_delivery_count — the catch-up re-fetches the welcome and
    //                               the one ordinary message;
    // + BACKFILL_THRESHOLD        — the above-floor arming probes arrive
    //                               through the floored catch-up and arm the
    //                               detector at bob's stalled epoch;
    // + 1                         — the armed backfill's `since = None` replay
    //                               recovers the below-floor probe.
    // The unfloored replay re-serves every already-seen event too, but
    // nostr-sdk emits an `Event` notification only for events new to its
    // database, so re-fetches are not re-counted and the total is exact — a
    // higher count would mean double-counted replays, a lower one a dropped
    // probe.
    let expected_healed = legitimate_delivery_count + BACKFILL_THRESHOLD + 1;

    // --- boot 2: cold restart; catch-up arms the detector, backfill heals ---
    let app_bob_boot2 = open_store(&dir_bob, &url);
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2.clone());
    runtime_bob_boot2.start().await.unwrap();
    wait_for_first_catch_up(&runtime_bob_boot2).await;
    wait_for_inbound_delivered(&app_bob_boot2, expected_healed).await;
    // Settle grace so any spurious extra delivery lands before the
    // exact-equality check (mirrors the floor-drop test's settle).
    sleep(TELEMETRY_SETTLE_GRACE).await;
    assert_eq!(
        inbound_events_delivered(&app_bob_boot2).await,
        expected_healed,
        "an armed cold boot must deliver exactly the legitimate re-fetches, \
         the arming probes, and — via the epoch-gap backfill replay — the \
         below-floor probe, with no replayed duplicate re-counted",
    );
    runtime_bob_boot2.shutdown().await;

    // --- boot 3: the heal is durable, not a per-boot replay storm. Boot 2
    // consumed the arming evidence (ingested event ids persist in the
    // account's seen-event state and are skipped before ingest), so this
    // independent cold boot re-fetches the above-floor history at the
    // transport layer without re-arming the per-boot, in-memory detector: no
    // second full-history replay fires, and the below-floor probe — already
    // recovered once — stays below the rebuilt floor without being
    // re-delivered. Exactly the legitimate re-fetches plus the eight
    // above-floor probes arrive, and nothing else. ---
    let expected_after_heal = legitimate_delivery_count + BACKFILL_THRESHOLD;
    let app_bob_boot3 = open_store(&dir_bob, &url);
    let runtime_bob_boot3 = MarmotAppRuntime::new(app_bob_boot3.clone());
    runtime_bob_boot3.start().await.unwrap();
    wait_for_first_catch_up(&runtime_bob_boot3).await;
    wait_for_inbound_delivered(&app_bob_boot3, expected_after_heal).await;
    sleep(TELEMETRY_SETTLE_GRACE).await;
    assert_eq!(
        inbound_events_delivered(&app_bob_boot3).await,
        expected_after_heal,
        "a cold boot after the heal must not replay full history again: the \
         backfill is debounced by the durable seen-event state, so only the \
         floored catch-up's above-floor re-fetches arrive",
    );
    runtime_bob_boot3.shutdown().await;
}
