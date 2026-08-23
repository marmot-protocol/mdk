//! Acceptance coverage for the epoch-stall backfill arm and escalation
//! decisions, through the forensic audit JSONL and the sync summary.
//!
//! PR #892 ships an epoch-gap backfill: once a group accumulates
//! `EPOCH_STALL_BACKFILL_THRESHOLD` distinct undecryptable messages at one
//! stalled epoch, the runtime arms a full-history transport replay to recover
//! the missed commit. The threshold is an empirical, single-cohort estimate the
//! detector's own docstring flags as provisional. To firm it up against more
//! cohorts a field export must reveal when and why a backfill fired — so the arm
//! decision emits one `epoch_stall_backfill_armed` forensic audit row, carrying
//! the stalled epoch and the threshold in force. These tests pin that row
//! through the account's forensic audit JSONL, the sanctioned channel for this
//! group-scoped evidence.
//!
//! Arming can also fail to work. A device that keeps arming and keeps trailing
//! the group is the 2026-07-29 field failure, where a device armed at three
//! successive stalled epochs and stayed hours behind with nothing surfaced. So
//! the third arm of an unrecovered run escalates: one `EpochStallEscalation` on
//! the sync summary (published to app subscribers as
//! `MarmotAppEvent::EpochStallEscalated`) plus one durable
//! `epoch_stall_backfill_escalated` row. The escalation tests below pin that
//! decision, its once-per-run latch, its reset when bob passes cleanly through
//! an epoch, and that the reset also lands when a convergence fold is what
//! carried him through — an epoch no delivery is ever read at, so only the
//! engine's own epoch passage can report it.
//!
//! The arm is driven through `AppClient::next_event` exactly as
//! `next_event_backfill.rs` does — the deterministic seam that avoids the full
//! runtime. Harness helpers (`mock_relay`, `open_store`, `test_unix_now_seconds`,
//! `publish_garbage_group_message_at`) are copied from `next_event_backfill.rs`
//! and the audit-JSONL readers (`AuditRowTracker`, `rows_of_kind`) from
//! `cursor_persistence.rs`, following the established test convention of
//! duplicating these helpers rather than sharing them.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use marmot_account::AccountHome;
use marmot_app::{AuditLogSettings, MarmotApp, MarmotAppConfig};
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
/// gives up. With the arm it returns as soon as the threshold-crossing delivery
/// fires; the bound guards against a permanent hang.
const NEXT_EVENT_DEADLINE: Duration = Duration::from_secs(10);

/// Deadline for bob's welcome to arrive and the group to become live.
const JOIN_DEADLINE: Duration = Duration::from_secs(10);

/// Mirrors `marmot_app::client::epoch_stall::EPOCH_STALL_ESCALATION_ARM_THRESHOLD`
/// (crate-private, hence mirrored): backfills one group may arm in an
/// unrecovered run before the runtime escalates.
const ESCALATION_ARM_THRESHOLD: usize = 3;

/// Deadline for one of alice's commits to reach bob and advance his epoch.
const EPOCH_ADVANCE_DEADLINE: Duration = Duration::from_secs(20);

/// Poll interval while waiting for bob's epoch to advance.
///
/// The engine's settlement quiescence window ([`SETTLEMENT_QUIESCENCE_MS`])
/// is a genuine floor on how soon bob's open convergence pass can freeze and
/// fold alice's commit, so this wait cannot be removed — but it can be *waited
/// out* rather than slept through. The window's deadline is only pushed back when
/// the pass admits an input that could change its deterministic resolution
/// (`cgka_engine::distributed_convergence::admit_convergence_input`), and neither
/// re-draining nor re-driving convergence admits one once alice's single commit
/// is in, so polling this fast converges on the floor instead of on a multiple of
/// it.
const EPOCH_ADVANCE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The convergence settlement quiescence window this harness runs both of its
/// clients on, mirroring the protocol-pinned
/// `cgka_engine::canonicalization::V1_SETTLEMENT_QUIESCENCE_MS`.
///
/// Pinned explicitly rather than inherited, because the value a test-policy
/// build inherits is not the production one: `MarmotApp::with_relay_and_config`
/// defaults `dev_settlement_quiescence_ms` to `0` — instant settlement — under
/// the `test-policy-overrides` feature, which the workspace CI run enables
/// through `wn-cli`. That difference is not cosmetic here. At 1 s a convergence
/// pass stays open across a drain, so a device reads a burst of commits at the
/// epoch it was already sitting at and folds afterwards; at 0 ms every commit
/// folds inside its own ingest, so the runtime lands on an epoch per delivery and
/// no device can be carried *through* an epoch at all. The carry that
/// [`a_clean_recovery_reported_as_a_passage_ends_the_arm_run`] needs — an epoch
/// no landing report can cover — exists only in the first regime, which is also
/// the one real devices run in, so this file states the window it means instead
/// of taking whichever one the feature resolution hands it.
const SETTLEMENT_QUIESCENCE_MS: u64 = 1_000;

async fn mock_relay() -> (MockRelay, String) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

fn open_store(dir: &tempfile::TempDir, relay_url: &str) -> MarmotApp {
    open_store_with_config(dir, relay_url, MarmotAppConfig::default())
}

fn open_store_with_config(
    dir: &tempfile::TempDir,
    relay_url: &str,
    config: MarmotAppConfig,
) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        relay_url.to_owned(),
        config
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_settlement_quiescence_ms(SETTLEMENT_QUIESCENCE_MS),
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
/// `nostr_group_id_hex`. Copied from `next_event_backfill.rs`: real kind-445
/// senders are always a fresh per-event key, and a zero-nonce marker body peels
/// to a clean `PeelerError::DecryptFailed`, the `IngestOutcome::TransportDeferred`
/// shape the epoch-stall detector counts.
async fn publish_garbage_group_message_at(
    relay_url: &str,
    nostr_group_id_hex: &str,
    created_at: u64,
    marker: &str,
) {
    let mut envelope = vec![0u8; 12];
    envelope.extend_from_slice(format!("backfill-audit-probe:{marker}").as_bytes());
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

/// Incremental reader over an account's forensic audit JSONL files: each call
/// returns only the rows appended since the previous call, so a burst can be
/// asserted in isolation. Copied from `cursor_persistence.rs`.
#[derive(Default)]
struct AuditRowTracker {
    consumed_lines: HashMap<String, usize>,
}

impl AuditRowTracker {
    fn new_rows(&mut self, app: &MarmotApp, account_ref: &str) -> Vec<serde_json::Value> {
        let mut files = app.audit_log_files().unwrap();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut rows = Vec::new();
        for file in files.iter().filter(|file| file.account_ref == account_ref) {
            let text = std::fs::read_to_string(&file.path).unwrap();
            let lines = text.lines().collect::<Vec<_>>();
            let seen = self.consumed_lines.entry(file.path.clone()).or_insert(0);
            for line in &lines[*seen..] {
                rows.push(serde_json::from_str::<serde_json::Value>(line).unwrap());
            }
            *seen = lines.len();
        }
        rows
    }
}

fn rows_of_kind<'rows>(
    rows: &'rows [serde_json::Value],
    kind: &str,
) -> Vec<&'rows serde_json::Value> {
    rows.iter()
        .filter(|row| row["kind"]["type"] == kind)
        .collect()
}

/// Sum the `deliveries` counter across every `sync_drain` row: positive
/// evidence that a drain window actually ingested traffic. The absence tests
/// assert this against their probe count first, so a too-short drain window
/// fails loudly instead of letting the no-armed-row assertion pass vacuously.
fn total_sync_drain_deliveries(rows: &[serde_json::Value]) -> u64 {
    rows_of_kind(rows, "sync_drain")
        .iter()
        .filter_map(|row| row["kind"]["deliveries"].as_u64())
        .sum()
}

/// The transport message ids the engine reported an ingest outcome for.
///
/// This is the per-delivery evidence `sync_drain`'s aggregate count cannot
/// give: a test that has published a specific message can wait for *that*
/// delivery to have reached the engine rather than for some delivery to have.
/// `msg_id` is a public transport id and survives the default obfuscated audit
/// mode, so the ids match the ones the publishing client reported.
fn ingested_message_ids(rows: &[serde_json::Value]) -> Vec<String> {
    rows_of_kind(rows, "ingest_outcome")
        .iter()
        .filter_map(|row| row["kind"]["msg_id"].as_str().map(ToOwned::to_owned))
        .collect()
}

/// A live group with bob (the stalled account under test) and alice, each in
/// their own store, plus the handles the tests drive them through.
struct StalledGroup {
    /// Kept bound so the mock relay outlives the clients.
    _relay: MockRelay,
    app_bob: MarmotApp,
    bob: marmot_app::AppClient,
    /// Alice advances the group epoch so bob can stall again at a new one.
    alice: marmot_app::AppClient,
    relay_url: String,
    group_id: cgka_traits::GroupId,
    /// Bob's transport route for the group, so tests can spray undecryptable
    /// traffic at it.
    nostr_group_id_hex: String,
}

/// Set up bob (the stalled account under test, own store) joined to a group
/// alice created (separate store), with forensic audit recording enabled.
async fn stalled_bob_in_a_live_group(
    dir_bob: &tempfile::TempDir,
    dir_alice: &tempfile::TempDir,
) -> StalledGroup {
    stalled_bob_in_a_live_group_with_config(dir_bob, dir_alice, MarmotAppConfig::default()).await
}

async fn stalled_bob_in_a_live_group_with_config(
    dir_bob: &tempfile::TempDir,
    dir_alice: &tempfile::TempDir,
    bob_config: MarmotAppConfig,
) -> StalledGroup {
    let (relay, url) = mock_relay().await;

    // --- bob: the stalled account whose arm decision we pin (own store) ---
    let home_bob = AccountHome::open(dir_bob.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;
    let app_bob = open_store_with_config(dir_bob, &url, bob_config);
    // Enable forensic audit recording before any client opens; the setting
    // persists in the store so every client this account builds records.
    app_bob
        .set_audit_log_settings(AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
        .unwrap();
    {
        let mut bob_setup = app_bob.client("bob").await.unwrap();
        bob_setup.publish_key_package().await.unwrap();
    }

    // --- alice: separate store, creates the group so bob has a live group
    // subscription to receive undecryptable traffic on, and commits to it when a
    // test needs bob's epoch to advance ---
    let home_alice = AccountHome::open(dir_alice.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(dir_alice, &url);
    let mut alice = app_alice.client("alice").await.unwrap();
    let group_id = alice
        .create_group("epoch-stall backfill audit", &[bob_id.as_str()])
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

    StalledGroup {
        _relay: relay,
        app_bob,
        bob,
        alice,
        relay_url: url,
        group_id,
        nostr_group_id_hex,
    }
}

impl StalledGroup {
    /// Spray `BACKFILL_THRESHOLD` distinct undecryptable messages at bob's group
    /// route and drain them, which arms one epoch-gap backfill at bob's current
    /// epoch. Returns every escalation the draining syncs reported; the callers
    /// assert the arm rows themselves, so a run that failed to arm cannot leave
    /// an absence assertion holding vacuously.
    async fn stall_bob_for_one_run(&mut self, run: usize) -> Vec<marmot_app::EpochStallEscalation> {
        let created_at = test_unix_now_seconds();
        for probe in 0..BACKFILL_THRESHOLD {
            publish_garbage_group_message_at(
                &self.relay_url,
                &self.nostr_group_id_hex,
                created_at,
                &format!("run-{run}-probe-{probe}"),
            )
            .await;
        }
        let mut escalations = Vec::new();
        for _ in 0..5 {
            escalations.extend(self.bob.sync().await.unwrap().epoch_stall_escalations);
            sleep(Duration::from_millis(50)).await;
        }
        escalations
    }

    /// Alice commits a group-profile change and bob applies it, so bob's epoch
    /// advances the way the field devices' epochs advanced: by folding a peer's
    /// commit, without ever reaching the group's live epoch on his own.
    ///
    /// Applying an inbound commit is a two-step in this crate: the delivery is
    /// retained by `sync`, and the convergence pass that folds it cannot freeze
    /// until its quiescence window closes. The account worker drives that second
    /// step; a direct client must call `retry_group_convergence` itself.
    ///
    /// Awaits bob's observable epoch rather than a fixed wait, the shape
    /// `wait_for_inbound_delivered` in `since_floor.rs` uses: each pass re-drains,
    /// re-drives convergence, and reads the epoch, so the loop returns as soon as
    /// the fold lands instead of one whole `EPOCH_ADVANCE_POLL_INTERVAL` late.
    async fn advance_bobs_epoch(&mut self, name: &str) {
        let before = self.bobs_epoch();
        self.alice
            .update_group_profile(&self.group_id, Some(name), None)
            .await
            .unwrap();
        let deadline = Instant::now() + EPOCH_ADVANCE_DEADLINE;
        loop {
            self.bob.sync().await.unwrap();
            self.bob
                .retry_group_convergence(&self.group_id)
                .await
                .unwrap();
            if self.bobs_epoch() > before {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "bob did not apply alice's commit within the deadline",
            );
            sleep(EPOCH_ADVANCE_POLL_INTERVAL).await;
        }
    }

    /// Carry bob *through* an epoch instead of stopping at it: alice commits
    /// twice, bob retains *both* commits before he folds either, and the folds
    /// then take him past the middle epoch without a single delivery ever being
    /// read while he is there. That isolates the epoch *passage* as the only
    /// report that can decide the run: a landing position always arrives at the
    /// epoch bob sits on, and he never sits on the middle one.
    ///
    /// Ingesting and folding are two phases here, not one loop, and the split is
    /// what makes the carry deterministic rather than a race. Both commits have
    /// to be read before either is folded. Neither half of that is left to
    /// timing: [`SETTLEMENT_QUIESCENCE_MS`] keeps the convergence pass open
    /// across the drain that reads them (bob retains the first commit as
    /// convergence input and cannot even peel the second from below its epoch),
    /// and the fold is driven explicitly, by `retry_group_convergence`, only
    /// once the ingest phase has both. Interleaving the two — drain, fold, drain
    /// — would instead let a slow relay hand bob the second commit after the
    /// first had already been folded: that delivery is then read at the middle
    /// epoch, a landing report ends the run all by itself, and a test about
    /// passages passes without one. The ingest phase therefore waits on the
    /// engine's own ingest outcomes for exactly alice's two commit ids — the
    /// group's undecryptable probe traffic shares its `group_ref`, so a count
    /// would not do — and the epoch assertion between the phases pins that
    /// nothing folded early.
    async fn carry_bob_through_an_epoch(&mut self, name: &str) {
        let before = self.bobs_epoch();
        let mut audit_rows = AuditRowTracker::default();
        let _baseline = audit_rows.new_rows(&self.app_bob, "bob");
        let mut commits = Vec::new();
        for step in ["a", "b"] {
            commits.extend(
                self.alice
                    .update_group_profile(&self.group_id, Some(&format!("{name}-{step}")), None)
                    .await
                    .unwrap()
                    .message_ids,
            );
        }
        assert_eq!(
            commits.len(),
            2,
            "the carry needs exactly two published commits: {commits:?}",
        );

        // Phase one: ingest both commits, fold neither.
        let deadline = Instant::now() + EPOCH_ADVANCE_DEADLINE;
        let mut ingested = HashSet::new();
        loop {
            self.bob.sync().await.unwrap();
            ingested.extend(ingested_message_ids(
                &audit_rows.new_rows(&self.app_bob, "bob"),
            ));
            if commits.iter().all(|commit| ingested.contains(commit)) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "bob did not ingest both of alice's commits within the deadline",
            );
            sleep(EPOCH_ADVANCE_POLL_INTERVAL).await;
        }
        assert_eq!(
            self.bobs_epoch(),
            before,
            "reading deliveries must not fold: both commits have to be read at the armed epoch",
        );

        // Phase two: fold, without reading anything else. Bob transits the
        // middle epoch with no delivery to read it at, which is exactly the
        // runtime behavior under test.
        let deadline = Instant::now() + EPOCH_ADVANCE_DEADLINE;
        loop {
            self.bob
                .retry_group_convergence(&self.group_id)
                .await
                .unwrap();
            if self.bobs_epoch() >= before + 2 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "bob did not fold both of alice's commits within the deadline",
            );
            sleep(EPOCH_ADVANCE_POLL_INTERVAL).await;
        }
    }

    /// Bob's current group epoch.
    fn bobs_epoch(&self) -> u64 {
        self.bob.group_mls_state(&self.group_id).unwrap().epoch
    }
}

/// Arming a backfill records exactly one `epoch_stall_backfill_armed` row,
/// group-scoped and carrying the stalled epoch and the threshold in force.
#[tokio::test]
async fn arming_a_backfill_records_one_epoch_stall_backfill_armed_row() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let mut live = stalled_bob_in_a_live_group(&dir_bob, &dir_alice).await;

    let stalled_epoch = live.bob.group_mls_state(&live.group_id).unwrap().epoch;

    // Arm the detector with exactly `BACKFILL_THRESHOLD` distinct undecryptable
    // messages at bob's live epoch. Present-dated so they clear any since floor
    // and reach bob's live subscription; distinct markers make distinct event
    // ids, hence distinct undecryptables at the one stalled epoch.
    let created_at = test_unix_now_seconds();
    for arm in 0..BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &live.relay_url,
            &live.nostr_group_id_hex,
            created_at,
            &format!("arm-{arm}"),
        )
        .await;
    }

    // Each deferred delivery now also returns a pending scheduler edge. Drive
    // the whole burst so the threshold-crossing delivery arms the backfill.
    for _ in 0..BACKFILL_THRESHOLD {
        timeout(NEXT_EVENT_DEADLINE, live.bob.next_event())
            .await
            .expect("next_event must return for each live deferred delivery")
            .expect("next_event should not error");
    }

    let mut audit_rows = AuditRowTracker::default();
    let rows = audit_rows.new_rows(&live.app_bob, "bob");
    let armed = rows_of_kind(&rows, "epoch_stall_backfill_armed");
    assert_eq!(
        armed.len(),
        1,
        "arming a backfill must record exactly one epoch_stall_backfill_armed row: {rows:?}"
    );
    let row = armed[0];
    assert_eq!(
        row["kind"]["stalled_epoch"].as_u64(),
        Some(stalled_epoch),
        "the row must carry the epoch bob was stalled at: {row}"
    );
    assert_eq!(
        row["kind"]["threshold"].as_u64(),
        Some(BACKFILL_THRESHOLD as u64),
        "the row must carry the threshold in force: {row}"
    );
    assert_eq!(
        row["group_ref"].as_str(),
        Some(hex::encode(live.group_id.as_slice()).as_str()),
        "the row is group-scoped via group_ref, not a duplicated field: {row}"
    );
}

/// Below-threshold undecryptable traffic never crosses the arm decision, so it
/// records no `epoch_stall_backfill_armed` row. Guards the
/// `observe_undecryptable == false` path.
#[tokio::test]
async fn below_threshold_undecryptable_traffic_records_no_backfill_armed_row() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let mut live = stalled_bob_in_a_live_group(&dir_bob, &dir_alice).await;

    // Consume the setup rows (join-phase drains) so the delivery evidence
    // below counts the probes alone, not the welcome traffic.
    let mut audit_rows = AuditRowTracker::default();
    let _setup_rows = audit_rows.new_rows(&live.app_bob, "bob");

    // One below the threshold: enough to accumulate a stall run but never arm.
    let created_at = test_unix_now_seconds();
    for probe in 0..(BACKFILL_THRESHOLD - 1) {
        publish_garbage_group_message_at(
            &live.relay_url,
            &live.nostr_group_id_hex,
            created_at,
            &format!("below-{probe}"),
        )
        .await;
    }

    // The probes arm nothing, so `next_event` would block — drain with `sync`,
    // which returns after each drain window. Several passes give the mock relay
    // ample time to deliver all of the pre-published probes.
    for _ in 0..5 {
        live.bob.sync().await.unwrap();
        sleep(Duration::from_millis(50)).await;
    }

    let rows = audit_rows.new_rows(&live.app_bob, "bob");
    // Positive delivery evidence first: the drains must have ingested every
    // probe, otherwise the absence assertion below would hold vacuously.
    assert!(
        total_sync_drain_deliveries(&rows) >= (BACKFILL_THRESHOLD - 1) as u64,
        "the drain windows must have delivered all {} below-threshold probes: {rows:?}",
        BACKFILL_THRESHOLD - 1
    );
    assert!(
        rows_of_kind(&rows, "epoch_stall_backfill_armed").is_empty(),
        "below-threshold traffic must not arm a backfill: {rows:?}"
    );
}

/// A second burst of distinct undecryptable traffic at the *same* stalled epoch
/// records no further row: the row inherits the detector's once-per-stalled-epoch
/// debounce, since the recorder is only reached when `observe_undecryptable`
/// returns `true`.
#[tokio::test]
async fn a_second_stall_burst_at_the_same_epoch_records_no_further_row() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let mut live = stalled_bob_in_a_live_group(&dir_bob, &dir_alice).await;

    let stalled_epoch = live.bob.group_mls_state(&live.group_id).unwrap().epoch;
    let mut audit_rows = AuditRowTracker::default();

    // First burst arms the backfill (row 1).
    let created_at = test_unix_now_seconds();
    for arm in 0..BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &live.relay_url,
            &live.nostr_group_id_hex,
            created_at,
            &format!("arm-{arm}"),
        )
        .await;
    }
    for _ in 0..BACKFILL_THRESHOLD {
        timeout(NEXT_EVENT_DEADLINE, live.bob.next_event())
            .await
            .expect("next_event must return for each first-burst delivery")
            .expect("next_event should not error");
    }
    let arm_rows = audit_rows.new_rows(&live.app_bob, "bob");
    assert_eq!(
        rows_of_kind(&arm_rows, "epoch_stall_backfill_armed").len(),
        1,
        "the first burst must have armed and recorded exactly one row: {arm_rows:?}"
    );

    // A second burst of *distinct* undecryptables at the same stalled epoch: the
    // group never advanced (undecryptable traffic does not move the epoch), so
    // the detector's debounce holds and no further row may be recorded. These
    // arm nothing, so drain with `sync` rather than the blocking `next_event`.
    assert_eq!(
        live.bob.group_mls_state(&live.group_id).unwrap().epoch,
        stalled_epoch,
        "sanity: undecryptable traffic must not have advanced bob's epoch",
    );
    for again in 0..BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &live.relay_url,
            &live.nostr_group_id_hex,
            created_at,
            &format!("again-{again}"),
        )
        .await;
    }
    for _ in 0..5 {
        live.bob.sync().await.unwrap();
        sleep(Duration::from_millis(50)).await;
    }

    let post_arm_rows = audit_rows.new_rows(&live.app_bob, "bob");
    // Positive delivery evidence first: the post-arm drains must have ingested
    // the whole second burst, otherwise the debounce assertion below would
    // hold vacuously.
    assert!(
        total_sync_drain_deliveries(&post_arm_rows) >= BACKFILL_THRESHOLD as u64,
        "the drain windows must have delivered all {BACKFILL_THRESHOLD} second-burst probes: \
         {post_arm_rows:?}"
    );
    assert!(
        rows_of_kind(&post_arm_rows, "epoch_stall_backfill_armed").is_empty(),
        "a second burst at the same stalled epoch must not record a further row: {post_arm_rows:?}"
    );
}

/// Arming the backfill again and again without ever catching up reports the
/// group exactly once: `ESCALATION_ARM_THRESHOLD` arms in one unrecovered run
/// produce one `EpochStallEscalation` on the sync summary and one
/// `epoch_stall_backfill_escalated` row, while the arms below the threshold
/// report nothing. This is the field failure the escalation exists for — a
/// device that armed at three successive stalled epochs and stayed hours behind
/// with nothing surfaced.
#[tokio::test]
async fn repeated_arming_without_recovery_escalates_exactly_once() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let mut live = stalled_bob_in_a_live_group(&dir_bob, &dir_alice).await;
    let mut audit_rows = AuditRowTracker::default();
    let _setup_rows = audit_rows.new_rows(&live.app_bob, "bob");

    let mut escalations = Vec::new();
    let mut stalled_epochs = Vec::new();
    for run in 0..ESCALATION_ARM_THRESHOLD {
        stalled_epochs.push(live.bobs_epoch());
        let reported = live.stall_bob_for_one_run(run).await;
        if run + 1 < ESCALATION_ARM_THRESHOLD {
            assert!(
                reported.is_empty(),
                "arm {} of {ESCALATION_ARM_THRESHOLD} must not escalate yet: {reported:?}",
                run + 1
            );
            // The device recovers part of the backlog and moves an epoch — the
            // shape that made the field failure invisible — but it is still
            // behind, so the next stall continues the same run.
            live.advance_bobs_epoch(&format!("advanced-{run}")).await;
        }
        escalations.extend(reported);
    }

    assert_eq!(
        escalations.len(),
        1,
        "an unrecovered run must escalate exactly once: {escalations:?}"
    );
    let escalation = &escalations[0];
    assert_eq!(escalation.group_id, live.group_id);
    assert_eq!(
        escalation.arms, ESCALATION_ARM_THRESHOLD as u32,
        "the escalation must carry the arms it took to decide: {escalation:?}"
    );
    assert_eq!(
        escalation.stalled_epoch,
        *stalled_epochs.last().unwrap(),
        "the escalation must carry the epoch bob was stalled at: {escalation:?}"
    );

    let rows = audit_rows.new_rows(&live.app_bob, "bob");
    assert_eq!(
        rows_of_kind(&rows, "epoch_stall_backfill_armed").len(),
        ESCALATION_ARM_THRESHOLD,
        "each stalled epoch must still record its own arm row: {rows:?}"
    );
    let escalated = rows_of_kind(&rows, "epoch_stall_backfill_escalated");
    assert_eq!(
        escalated.len(),
        1,
        "the escalation must be durable in the forensic record exactly once: {rows:?}"
    );
    let row = escalated[0];
    assert_eq!(
        row["kind"]["stalled_epoch"].as_u64(),
        Some(*stalled_epochs.last().unwrap()),
        "the row must carry the epoch bob was stalled at: {row}"
    );
    assert_eq!(
        row["kind"]["arms"].as_u64(),
        Some(ESCALATION_ARM_THRESHOLD as u64),
        "the row must carry the arms in the run: {row}"
    );
    assert_eq!(
        row["kind"]["arm_threshold"].as_u64(),
        Some(ESCALATION_ARM_THRESHOLD as u64),
        "the row must carry the threshold in force: {row}"
    );
    assert_eq!(
        row["group_ref"].as_str(),
        Some(hex::encode(live.group_id.as_slice()).as_str()),
        "the row is group-scoped via group_ref, not a duplicated field: {row}"
    );
}

/// A device that recovers cleanly is not escalated, because the convergence fold
/// that carried it reports the epochs it passed through.
///
/// Bob arms, then one real fold takes him past an epoch he never stalled at. No
/// delivery is ever read while he is there — the epoch a delivery is read at is
/// a landing position, and he never lands on that one — so the only report that
/// can end his unrecovered run is the engine's `EpochChanged` passage. The
/// runtime feeds it to the detector, the run ends, and his next two stalls are a
/// fresh run's first and second arms rather than the old run's second and third.
///
/// This is the runtime half of the passage report, and the half the detector unit
/// tests cannot pin: they hand the detector a passage directly, so they keep
/// passing whether or not a real fold produces one. The rule the passage feeds is
/// `GroupStall::observe_epoch`; the arithmetic that turns one passage into two
/// reports is pinned by
/// `a_spanning_passage_off_the_armed_epoch_ends_the_arm_run`.
#[tokio::test]
async fn a_clean_recovery_reported_as_a_passage_ends_the_arm_run() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let mut live = stalled_bob_in_a_live_group(&dir_bob, &dir_alice).await;
    let mut audit_rows = AuditRowTracker::default();
    let _setup_rows = audit_rows.new_rows(&live.app_bob, "bob");

    // Arm one: bob stalls at the epoch he starts on.
    assert!(
        live.stall_bob_for_one_run(0).await.is_empty(),
        "the first arm of a run must not escalate",
    );

    // He then recovers cleanly through an epoch — the one thing that ends the
    // run — carried by a fold that reports its passage and nothing else.
    let armed_epoch = live.bobs_epoch();
    live.carry_bob_through_an_epoch("recovered").await;
    assert!(
        live.bobs_epoch() >= armed_epoch + 2,
        "the carry must take bob past an epoch, not stop at the next one",
    );

    // The two stalls that follow are unrelated to the armed run, and the detector
    // now knows it: they open a new run instead of completing the old one.
    assert!(
        live.stall_bob_for_one_run(1).await.is_empty(),
        "a stall after a clean recovery must not escalate on its own",
    );
    live.advance_bobs_epoch("advanced").await;
    let escalations = live.stall_bob_for_one_run(2).await;

    assert!(
        escalations.is_empty(),
        "a recovery the runtime reported must not be counted as an arm: {escalations:?}",
    );
    // Three arms did happen — the absence above is a decision, not a run that
    // never armed — and none of them was reported.
    let rows = audit_rows.new_rows(&live.app_bob, "bob");
    assert_eq!(
        rows_of_kind(&rows, "epoch_stall_backfill_armed").len(),
        ESCALATION_ARM_THRESHOLD,
        "each stalled epoch must still record its own arm row: {rows:?}"
    );
    assert!(
        rows_of_kind(&rows, "epoch_stall_backfill_escalated").is_empty(),
        "no escalation row may be recorded: {rows:?}"
    );
}

/// A later delivery failure must not strand an escalation produced by the
/// completed delivery immediately before it. The escalation belongs to N's
/// persisted boundary and therefore travels in the error's completed prefix
/// when N+1 fails before ingest.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn escalation_from_completed_delivery_survives_later_sync_failure() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let config =
        MarmotAppConfig::default().with_dev_fail_sync_before_delivery(BACKFILL_THRESHOLD as u64);
    let mut live = stalled_bob_in_a_live_group_with_config(&dir_bob, &dir_alice, config).await;

    // Two prior arms establish one unrecovered run. Each burst has exactly the
    // configured number of deliveries, so no N+1 exists to trigger the fault.
    for run in 0..(ESCALATION_ARM_THRESHOLD - 1) {
        assert!(live.stall_bob_for_one_run(run).await.is_empty());
        live.advance_bobs_epoch(&format!("advanced-{run}")).await;
    }

    let stalled_epoch = live.bobs_epoch();
    let created_at = test_unix_now_seconds();
    for probe in 0..=BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &live.relay_url,
            &live.nostr_group_id_hex,
            created_at,
            &format!("failing-run-probe-{probe}"),
        )
        .await;
    }

    let failure = live
        .bob
        .sync_with_partial_progress()
        .await
        .expect_err("delivery after the threshold-crossing escalation must fail");
    assert!(
        failure
            .source
            .to_string()
            .contains("injected catch-up delivery failure")
    );
    assert_eq!(failure.partial_summary.epoch_stall_escalations.len(), 1);
    let escalation = &failure.partial_summary.epoch_stall_escalations[0];
    assert_eq!(escalation.group_id, live.group_id);
    assert_eq!(escalation.stalled_epoch, stalled_epoch);
    assert_eq!(escalation.arms, ESCALATION_ARM_THRESHOLD as u32);
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn compatibility_sync_retains_escalation_after_failure() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let config =
        MarmotAppConfig::default().with_dev_fail_sync_before_delivery(BACKFILL_THRESHOLD as u64);
    let mut live = stalled_bob_in_a_live_group_with_config(&dir_bob, &dir_alice, config).await;

    for run in 0..(ESCALATION_ARM_THRESHOLD - 1) {
        assert!(live.stall_bob_for_one_run(run).await.is_empty());
        live.advance_bobs_epoch(&format!("compatibility-advanced-{run}"))
            .await;
    }

    let stalled_epoch = live.bobs_epoch();
    let created_at = test_unix_now_seconds();
    for probe in 0..=BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &live.relay_url,
            &live.nostr_group_id_hex,
            created_at,
            &format!("compatibility-failing-run-probe-{probe}"),
        )
        .await;
    }

    let error = live
        .bob
        .sync()
        .await
        .expect_err("the delivery after the threshold-crossing escalation must fail");
    assert!(
        error
            .to_string()
            .contains("injected catch-up delivery failure")
    );

    let recovered = live
        .bob
        .sync()
        .await
        .expect("the retained client must surface the stashed escalation");
    assert_eq!(recovered.epoch_stall_escalations.len(), 1);
    let escalation = &recovered.epoch_stall_escalations[0];
    assert_eq!(escalation.group_id, live.group_id);
    assert_eq!(escalation.stalled_epoch, stalled_epoch);
    assert_eq!(escalation.arms, ESCALATION_ARM_THRESHOLD as u32);
    assert!(
        live.bob
            .sync()
            .await
            .unwrap()
            .epoch_stall_escalations
            .is_empty(),
        "the retained escalation must be reported exactly once",
    );
}

/// A failed app-projection checkpoint excludes that batch's message/join
/// outputs, but it must not discard the one-shot escalation raised by a durable
/// engine outcome in the same batch.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn escalation_survives_failed_projection_checkpoint() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let config = MarmotAppConfig::default()
        .with_dev_fail_sync_before_boundary_save(BACKFILL_THRESHOLD as u64);
    let mut live = stalled_bob_in_a_live_group_with_config(&dir_bob, &dir_alice, config).await;

    for run in 0..(ESCALATION_ARM_THRESHOLD - 1) {
        assert!(live.stall_bob_for_one_run(run).await.is_empty());
        live.advance_bobs_epoch(&format!("checkpoint-advanced-{run}"))
            .await;
    }

    let stalled_epoch = live.bobs_epoch();
    let created_at = test_unix_now_seconds();
    for probe in 0..=BACKFILL_THRESHOLD {
        publish_garbage_group_message_at(
            &live.relay_url,
            &live.nostr_group_id_hex,
            created_at,
            &format!("checkpoint-failing-probe-{probe}"),
        )
        .await;
    }

    let failure = live
        .bob
        .sync_with_partial_progress()
        .await
        .expect_err("the accumulated projection checkpoint must fail");
    assert!(
        failure
            .source
            .to_string()
            .contains("injected catch-up boundary save failure")
    );
    assert!(failure.partial_summary.messages.is_empty());
    assert!(failure.partial_summary.joined_groups.is_empty());
    assert_eq!(failure.partial_summary.epoch_stall_escalations.len(), 1);
    let escalation = &failure.partial_summary.epoch_stall_escalations[0];
    assert_eq!(escalation.group_id, live.group_id);
    assert_eq!(escalation.stalled_epoch, stalled_epoch);
    assert_eq!(escalation.arms, ESCALATION_ARM_THRESHOLD as u32);
}

/// An epoch bob passes through cleanly — he keeps up with alice's commits
/// without stalling at that epoch — ends the arm run. Later arms then open a new
/// run, so `ESCALATION_ARM_THRESHOLD` arms spread across a recovery never
/// escalate: escalation reports a device that cannot catch up, not one that
/// needed repair more than once.
#[tokio::test]
async fn an_epoch_passed_cleanly_between_arms_never_escalates() {
    let dir_bob = tempfile::tempdir().unwrap();
    let dir_alice = tempfile::tempdir().unwrap();
    let mut live = stalled_bob_in_a_live_group(&dir_bob, &dir_alice).await;
    let mut audit_rows = AuditRowTracker::default();
    let _setup_rows = audit_rows.new_rows(&live.app_bob, "bob");

    let mut escalations = live.stall_bob_for_one_run(0).await;
    // Bob now keeps up with two of alice's commits without stalling in between,
    // so he left an epoch cleanly: whatever the first arm was about is over.
    live.advance_bobs_epoch("kept-up-1").await;
    live.advance_bobs_epoch("kept-up-2").await;

    // Two further arms — three in total, the escalation threshold — but the run
    // restarted, so none of them escalates.
    for run in 1..ESCALATION_ARM_THRESHOLD {
        escalations.extend(live.stall_bob_for_one_run(run).await);
        live.advance_bobs_epoch(&format!("behind-again-{run}"))
            .await;
    }

    assert!(
        escalations.is_empty(),
        "arms split by a clean epoch must not escalate: {escalations:?}"
    );
    let rows = audit_rows.new_rows(&live.app_bob, "bob");
    assert_eq!(
        rows_of_kind(&rows, "epoch_stall_backfill_armed").len(),
        ESCALATION_ARM_THRESHOLD,
        "all three arms must have happened, so the absence above is not vacuous: {rows:?}"
    );
    assert!(
        rows_of_kind(&rows, "epoch_stall_backfill_escalated").is_empty(),
        "no escalation row may be recorded: {rows:?}"
    );
}
