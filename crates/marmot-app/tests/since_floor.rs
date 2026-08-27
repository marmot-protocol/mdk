//! Regression coverage for the since-floor defect and its set-reconciliation
//! correctness backstop.
//!
//! Retained kind-445 events may advance an in-memory cursor candidate, but only
//! a completed transport drain promotes that candidate to the durable
//! subscription floor. Once such a drain establishes a floor, an event that is
//! authored earlier but replicated later can still fall below
//! `since = checkpoint − 120s`. A NIP-77 pass therefore reconciles each
//! inbox/group route by event id against a durable per-route set, making that
//! late event discoverable without discarding the cheap timestamp fast path.
//!
//! The first test explicitly completes a checkpointing cold boot, then proves
//! reconciliation downloads a below-floor sibling on the next boot and records
//! it in the exact route inventory. A later boot has no set difference for that
//! sibling, so it avoids replaying the payload again.
//!
//! The second test retains the independent epoch-stall arm coverage: a burst of
//! undecryptable traffic still arms its full-history recovery path even though
//! route reconciliation now supplies timestamp-independent discovery first.
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
//! new pair's first subscription rebuild is a genuine cold boot. The tests use
//! one clean boot to promote a completed-drain checkpoint, then separate boots
//! to demonstrate reconciliation and its durable no-redownload property.
//!
//! # Delivery observable
//!
//! The two probe events are deliberately undecryptable garbage (spec allows
//! this: kind-445 senders are always a fresh per-event key, unrelated to any
//! account identity, and this test exercises *delivery*, not decryption). An
//! undecryptable delivery produces no `MarmotAppEvent` — decrypt failure
//! yields `IngestOutcome::TransportDeferred` with no observable side effect at the
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
//! the very first (still-live) boot rather than assuming it, then asserts boot
//! 2 delivers `legitimate_count + 2` (both siblings) and boot 3 returns to
//! `legitimate_count + 1` because the below-floor event is already present in
//! the exact reconciliation set.

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

/// Keep these cursor-characterization tests scoped to the ordinary incremental
/// group subscription and the epoch-gap backfill they explicitly arm. New
/// post-join groups also have an independent full-history maintenance
/// subscription; allowing that here would recover the below-floor probe
/// through a different feature and make the assertions meaningless.
async fn start_with_maintenance_paused(runtime: &MarmotAppRuntime, account_ref: &str) {
    runtime.start().await.unwrap();
    runtime.pause_maintenance(account_ref).await.unwrap();
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
/// detector counts as `IngestOutcome::TransportDeferred`. (A
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
async fn cold_restart_reconciles_backlog_below_since_floor() {
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
    start_with_maintenance_paused(&runtime_bob_boot1, "bob").await;

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

    // Ordinary live traffic advances bob's in-memory cursor candidate. Its
    // isolated projection save must retain the prior completed-drain floor.
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
    let initial_delivery_count = inbound_events_delivered(&app_bob_boot1).await;

    // PR #1567 deliberately keeps isolated live-delivery candidates out of the
    // durable subscription floor. Complete one clean cold-boot drain before
    // publishing the probes so this test exercises the remaining #1579 case:
    // late relay history below a floor that was legitimately checkpointed.
    runtime_bob_boot1.shutdown().await;
    alice_client
        .send(&group_id, b"offline checkpoint anchor")
        .await
        .unwrap();
    let app_bob_checkpoint = open_store(&dir_bob, &url);
    let runtime_bob_checkpoint = MarmotAppRuntime::new(app_bob_checkpoint.clone());
    start_with_maintenance_paused(&runtime_bob_checkpoint, "bob").await;
    wait_for_first_catch_up(&runtime_bob_checkpoint).await;
    sleep(TELEMETRY_SETTLE_GRACE).await;
    let legitimate_delivery_count = inbound_events_delivered(&app_bob_checkpoint).await;
    assert_eq!(
        legitimate_delivery_count,
        initial_delivery_count + 1,
        "the checkpointing boot must drain the established history plus the new offline anchor",
    );
    runtime_bob_checkpoint.shutdown().await;

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

    // bob is fully offline while the probes are published: a still-open
    // subscription would deliver them live regardless of `created_at` (see
    // the module doc comment).

    publish_garbage_group_message_at(&url, &nostr_group_id_hex, below_floor_created_at, "below")
        .await;
    publish_garbage_group_message_at(&url, &nostr_group_id_hex, above_floor_created_at, "above")
        .await;

    // --- boot 2: cold restart, first subscription rebuild and route-set
    // reconciliation since the probes landed ---
    let app_bob_boot2 = open_store(&dir_bob, &url);
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2.clone());
    start_with_maintenance_paused(&runtime_bob_boot2, "bob").await;
    wait_for_first_catch_up(&runtime_bob_boot2).await;
    sleep(TELEMETRY_SETTLE_GRACE).await;
    let delivered_after_boot2 = inbound_events_delivered(&app_bob_boot2).await;
    assert_eq!(
        delivered_after_boot2,
        legitimate_delivery_count + 2,
        "normal cold-boot catch-up must reconcile both the above-floor sibling \
         and the below-floor probe without an independently armed backfill",
    );
    let boot2_reconciliation = app_bob_boot2.relay_telemetry().await.metrics;
    assert!(boot2_reconciliation.reconciliation_attempts >= 1);
    assert!(
        boot2_reconciliation.reconciliation_remote_items >= 1,
        "the route set difference must identify the below-floor probe \
         independently of the subscription timestamp floor"
    );
    assert!(
        boot2_reconciliation.reconciliation_received_items >= 1,
        "the below-floor route difference must download while the ordinary \
         subscription owns the above-floor sibling"
    );
    runtime_bob_boot2.shutdown().await;

    // --- boot 3: a second independent cold restart. The durable inventory
    // makes the route set equal, so reconciliation downloads no payload for the
    // already-observed below-floor event. ---
    let app_bob_boot3 = open_store(&dir_bob, &url);
    let runtime_bob_boot3 = MarmotAppRuntime::new(app_bob_boot3.clone());
    start_with_maintenance_paused(&runtime_bob_boot3, "bob").await;
    wait_for_first_catch_up(&runtime_bob_boot3).await;
    sleep(TELEMETRY_SETTLE_GRACE).await;
    let delivered_after_boot3 = inbound_events_delivered(&app_bob_boot3).await;
    assert_eq!(
        delivered_after_boot3,
        legitimate_delivery_count + 1,
        "the reconciled below-floor event must remain in the durable route set, \
         so a second cold boot has no set difference to download and only the \
         ordinary above-floor sibling is redelivered",
    );
    let boot3_reconciliation = app_bob_boot3.relay_telemetry().await.metrics;
    assert!(boot3_reconciliation.reconciliation_attempts >= 1);
    assert_eq!(
        boot3_reconciliation.reconciliation_remote_items, 0,
        "the durable route inventory must make the next reconciliation a \
         set-equal exchange rather than another full-history payload replay"
    );
    runtime_bob_boot3.shutdown().await;
}

/// The armed counterpart to [`cold_restart_reconciles_backlog_below_since_floor`]:
/// enough undecryptable traffic at a stalled epoch still arms epoch-gap
/// backfill after route reconciliation has supplied timestamp-independent
/// discovery.
///
/// The probes play two distinct roles on either side of the floor:
///
/// - **Arming** (`arm-0`..`arm-7`, above the floor): the cold boot's ordinary
///   floored catch-up delivers them, each fails to peel, and — being distinct
///   event ids — each counts as a distinct undecryptable message at bob's
///   stalled epoch. The eighth crosses `EPOCH_STALL_BACKFILL_THRESHOLD` and
///   arms a full-history transport replay (`since = None`).
/// - **Reconciliation target** (`below-target`, below the floor): the floored
///   catch-up cannot deliver it, so the route-set pass discovers it before the
///   drain that observes the stalled epoch.
///
/// Boot 2 pins that discovery and epoch-stall arming coexist. Boot 3 pins that
/// reconciliation is durable and the epoch detector remains debounced:
/// ingested event ids persist, so a later cold boot does not trigger another
/// full-history replay.
#[tokio::test]
async fn stalled_epoch_backfill_still_arms_after_route_reconciliation() {
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
    start_with_maintenance_paused(&runtime_bob_boot1, "bob").await;

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
    let initial_delivery_count = inbound_events_delivered(&app_bob_boot1).await;

    // Establish a completed-drain checkpoint before placing the epoch-stall
    // probes around its floor. This keeps the test independent from overflow
    // recovery's newer rule that isolated live deliveries do not advance the
    // durable subscription cursor.
    runtime_bob_boot1.shutdown().await;
    alice_client
        .send(&group_id, b"offline checkpoint anchor")
        .await
        .unwrap();
    let app_bob_checkpoint = open_store(&dir_bob, &url);
    let runtime_bob_checkpoint = MarmotAppRuntime::new(app_bob_checkpoint.clone());
    start_with_maintenance_paused(&runtime_bob_checkpoint, "bob").await;
    wait_for_first_catch_up(&runtime_bob_checkpoint).await;
    sleep(TELEMETRY_SETTLE_GRACE).await;
    let legitimate_delivery_count = inbound_events_delivered(&app_bob_checkpoint).await;
    assert_eq!(
        legitimate_delivery_count,
        initial_delivery_count + 1,
        "the checkpointing boot must drain the established history plus the new offline anchor",
    );
    runtime_bob_checkpoint.shutdown().await;

    // Same floor placement as the floor-drop test above.
    let reference_now = test_unix_now_seconds();
    let floor_estimate = reference_now.saturating_sub(REBUILD_LOOKBACK_SECS);
    let below_floor_created_at = floor_estimate.saturating_sub(180);
    let above_floor_created_at = floor_estimate.saturating_add(60);
    assert!(above_floor_created_at < reference_now);

    // bob remains fully offline while probes are published (see the module doc
    // comment on live subscriptions ignoring `since`).

    // The reconciliation target: below the floor and therefore unreachable by
    // the ordinary catch-up, but discoverable by the route-set pass.
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
    // + 1                         — route reconciliation discovers the
    //                               below-floor probe.
    // The unfloored replay re-serves every already-seen event too, but
    // nostr-sdk emits an `Event` notification only for events new to its
    // database, so re-fetches are not re-counted and the total is exact — a
    // higher count would mean double-counted replays, a lower one a dropped
    // probe.
    let expected_healed = legitimate_delivery_count + BACKFILL_THRESHOLD + 1;

    // --- boot 2: reconciliation discovers the target and the same drain's
    // above-floor probes still arm the epoch-stall detector. ---
    let app_bob_boot2 = open_store(&dir_bob, &url);
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2.clone());
    start_with_maintenance_paused(&runtime_bob_boot2, "bob").await;
    wait_for_first_catch_up(&runtime_bob_boot2).await;
    wait_for_inbound_delivered(&app_bob_boot2, expected_healed).await;
    // Settle grace so any spurious extra delivery lands before the
    // exact-equality check (mirrors the floor-drop test's settle).
    sleep(TELEMETRY_SETTLE_GRACE).await;
    assert_eq!(
        inbound_events_delivered(&app_bob_boot2).await,
        expected_healed,
        "an armed cold boot must deliver exactly the legitimate re-fetches, \
         the arming probes, and the reconciled below-floor probe, with no \
         replayed duplicate re-counted",
    );
    runtime_bob_boot2.shutdown().await;

    // --- boot 3: reconciliation is durable, not a per-boot replay storm.
    // Boot 2 consumed the arming evidence (ingested event ids persist in the
    // account's seen-event state and are skipped before ingest), so this
    // independent cold boot re-fetches the above-floor history at the
    // transport layer without re-arming the per-boot, in-memory detector: no
    // second full-history replay fires, and the below-floor probe — already
    // reconciled once — stays below the rebuilt floor without being
    // re-delivered. Exactly the legitimate re-fetches plus the eight
    // above-floor probes arrive, and nothing else. ---
    let expected_after_heal = legitimate_delivery_count + BACKFILL_THRESHOLD;
    let app_bob_boot3 = open_store(&dir_bob, &url);
    let runtime_bob_boot3 = MarmotAppRuntime::new(app_bob_boot3.clone());
    start_with_maintenance_paused(&runtime_bob_boot3, "bob").await;
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
