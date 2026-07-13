//! Integration test for `CursorPersistence`:
//! a `Frozen` (wake-collection) runtime still ingests, decrypts, and projects
//! a delivered message, but the durable transport cursor it persists is
//! byte-identical to the one it loaded — and a subsequent `Advance` runtime
//! over the same store loads exactly that untouched cursor and advances it
//! normally on fresh delivery.
//!
//! # Harness shape
//!
//! Mirrors `since_floor.rs`: one account per store (`bob`, the account under
//! test, has his own store; `alice` — who only creates the group and sends
//! messages — gets a second, independent store pointed at the same relay; two
//! accounts in one store would share the relay-plane router, a documented
//! harness pitfall), and every bob boot is a brand-new `MarmotApp`/
//! `MarmotAppRuntime` pair over the same on-disk store, exactly how the
//! confirmed iOS trigger runs ("a full runtime per push"). Messages destined
//! for a cold boot are sent while bob is fully offline so the boot's initial
//! catch-up drain — not a live subscription — is what delivers them.
//!
//! # Cursor observable
//!
//! The persisted cursor has no public accessor by design; the observation
//! channel is the forensic audit rows added for exactly this
//! comparison. A `sync_drain` row records the in-memory cursor before/after
//! each drain, and the *first* drain of a cold boot records the
//! freshly-loaded persisted value as `cursor_before_secs` — so the frozen
//! boot's rows prove the pass itself never moved the cursor, and the next
//! (Advance) boot's rows prove the *store* still holds the pre-frozen value.
//! `subscription_rebuild` rows double-check the derived `since` floor. This
//! is the same evidence chain a field export would show, which is the point.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use marmot_account::AccountHome;
use marmot_app::{
    AppMessageQuery, AuditLogSettings, CursorPersistence, MarmotApp, MarmotAppConfig,
    MarmotAppEvent, MarmotAppRuntime,
};
use nostr_relay_builder::MockRelay;
use tokio::time::sleep;

/// How long a cold boot's initial catch-up is allowed to take. Generous
/// relative to the crate's own `SDK_FIRST_SYNC_WAIT` / `SDK_DRAIN_WAIT`.
const CATCH_UP_DEADLINE: Duration = Duration::from_secs(10);

async fn mock_relay() -> (MockRelay, String) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

fn open_store(
    dir: &tempfile::TempDir,
    relay_url: &str,
    cursor_persistence: CursorPersistence,
) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        relay_url.to_owned(),
        MarmotAppConfig::default()
            .with_allow_loopback_relay_endpoints(true)
            .with_cursor_persistence(cursor_persistence),
    )
}

fn test_unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Wait until the local wall clock has strictly passed `reference`, so the
/// next message alice publishes gets a `created_at` strictly greater than any
/// cursor value persisted at or before `reference`. Keeps the frozen-cursor
/// equality assertion discriminating: under `Advance` semantics that same
/// delivery *would* have advanced the cursor.
async fn wait_for_wall_clock_past(reference: u64) {
    while test_unix_now_seconds() <= reference {
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_event<F>(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    mut matches_event: F,
) where
    F: FnMut(&MarmotAppEvent) -> bool,
{
    tokio::time::timeout(CATCH_UP_DEADLINE, async {
        loop {
            let event = events.recv().await.unwrap();
            if matches_event(&event) {
                return;
            }
        }
    })
    .await
    .expect("runtime event");
}

/// Poll for a cold boot's first catch-up to complete: `start` returns once the
/// worker is command-ready, not once the background catch-up finishes.
async fn wait_for_first_catch_up(runtime: &MarmotAppRuntime) {
    let deadline = Instant::now() + CATCH_UP_DEADLINE;
    loop {
        if runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_sync
            .attempts
            > 0
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "cold-boot catch-up did not complete within the deadline",
        );
        sleep(Duration::from_millis(25)).await;
    }
}

/// Incremental reader over an account's forensic audit JSONL files: each call
/// returns only the rows appended since the previous call, so each boot's
/// rows can be asserted in isolation.
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

#[tokio::test]
async fn frozen_wake_collection_ingests_without_moving_the_durable_cursor() {
    let (_relay, url) = mock_relay().await;

    // --- bob: the account whose durable cursor is under test (own store) ---
    let dir_bob = tempfile::tempdir().unwrap();
    let home_bob = AccountHome::open(dir_bob.path());
    home_bob.create_account("bob").unwrap();
    let bob_id = home_bob.account("bob").unwrap().account_id_hex;

    // --- alice: group creator / sender, in her own independent store ---
    let dir_alice = tempfile::tempdir().unwrap();
    let home_alice = AccountHome::open(dir_alice.path());
    home_alice.create_account("alice").unwrap();
    let app_alice = open_store(&dir_alice, &url, CursorPersistence::Advance);

    // --- boot 1 (Advance): join the group, receive one ordinary message so
    // the store holds a real advanced cursor for the frozen boot to load ---
    let app_bob_boot1 = open_store(&dir_bob, &url, CursorPersistence::Advance);
    // Enable forensic audit recording before any runtime starts; the setting
    // persists in the store, so boots 2 and 3 record as well.
    app_bob_boot1
        .set_audit_log_settings(AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
        .unwrap();
    {
        let mut bob_setup = app_bob_boot1.client("bob").await.unwrap();
        bob_setup.publish_key_package().await.unwrap();
    }
    let runtime_bob_boot1 = MarmotAppRuntime::new(app_bob_boot1.clone());
    let mut events_boot1 = runtime_bob_boot1.subscribe();
    runtime_bob_boot1.start().await.unwrap();

    let mut alice_client = app_alice.client("alice").await.unwrap();
    let group_id = alice_client
        .create_group("cursor persistence", &[bob_id.as_str()])
        .await
        .unwrap();
    wait_for_event(&mut events_boot1, |event| {
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
    wait_for_event(&mut events_boot1, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "ordinary traffic advances the cursor"
        )
    })
    .await;
    // Upper bound on whatever cursor boot 1 persisted: captured after the
    // message is confirmed received, before shutdown.
    let cursor_upper_bound = test_unix_now_seconds();
    runtime_bob_boot1.shutdown().await;

    let mut audit_rows = AuditRowTracker::default();
    // Consume boot 1's rows so each later boot is asserted in isolation.
    let _boot1_rows = audit_rows.new_rows(&app_bob_boot1, "bob");

    // The frozen boot's delivery must carry a created_at strictly above the
    // persisted cursor, otherwise the "cursor did not move" assertion would
    // hold vacuously even under Advance semantics.
    wait_for_wall_clock_past(cursor_upper_bound).await;
    alice_client
        .send(&group_id, b"frozen wake ingests without moving the floor")
        .await
        .unwrap();

    // --- boot 2 (Frozen): a brand-new runtime over the same store, the way
    // the NSE runs one per push. It must ingest and project the message, and
    // every drain must leave the cursor exactly where it loaded it. ---
    let app_bob_boot2 = open_store(&dir_bob, &url, CursorPersistence::Frozen);
    let runtime_bob_boot2 = MarmotAppRuntime::new(app_bob_boot2.clone());
    let mut events_boot2 = runtime_bob_boot2.subscribe();
    runtime_bob_boot2.start().await.unwrap();
    wait_for_first_catch_up(&runtime_bob_boot2).await;
    wait_for_event(&mut events_boot2, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext
                        == "frozen wake ingests without moving the floor"
        )
    })
    .await;
    // Force one more completed, awaited sync so the drain rows are flushed.
    runtime_bob_boot2.catch_up_accounts().await.unwrap();
    // The frozen pass projected the message durably: visible in the stored
    // app-message projection, not merely as a broadcast event.
    let group_id_hex = hex::encode(group_id.as_slice());
    let frozen_boot_messages = app_bob_boot2
        .messages_with_query(
            "bob",
            AppMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                limit: None,
            },
        )
        .unwrap();
    assert!(
        frozen_boot_messages
            .iter()
            .any(|message| message.plaintext == "frozen wake ingests without moving the floor"),
        "the frozen runtime must still ingest, decrypt, and project the delivery"
    );
    runtime_bob_boot2.shutdown().await;

    let boot2_rows = audit_rows.new_rows(&app_bob_boot2, "bob");
    let boot2_drains = rows_of_kind(&boot2_rows, "sync_drain");
    assert!(
        !boot2_drains.is_empty(),
        "the frozen boot must have recorded at least one sync_drain row"
    );
    // The first drain's cursor_before is the persisted cursor as loaded from
    // the store — the baseline every later assertion compares against.
    let baseline = boot2_drains[0]["kind"]["cursor_before_secs"]
        .as_u64()
        .expect("boot 1 advanced and persisted a cursor for the frozen boot to load");
    assert!(
        baseline <= cursor_upper_bound,
        "sanity: the loaded cursor cannot postdate boot 1's shutdown, so the \
         frozen boot's delivery (created_at > {cursor_upper_bound}) sits above \
         it and would have advanced an Advance cursor"
    );
    for drain in &boot2_drains {
        assert_eq!(
            drain["kind"]["cursor_before_secs"].as_u64(),
            Some(baseline),
            "a frozen runtime's in-memory cursor never moves between drains: {drain}"
        );
        assert_eq!(
            drain["kind"]["cursor_after_secs"].as_u64(),
            Some(baseline),
            "a frozen drain must leave the cursor exactly where it loaded it: {drain}"
        );
    }
    assert!(
        boot2_drains
            .iter()
            .any(|drain| drain["kind"]["deliveries"].as_u64().unwrap_or(0) >= 1),
        "the frozen boot's catch-up drain — not a live tail — must have \
         ingested the offline-published delivery: {boot2_drains:?}"
    );
    // Frozen rebuilds keep deriving the subscription `since` floor from the
    // loaded cursor — the audit rows
    // themselves show wake passes not moving the floor.
    let boot2_rebuilds = rows_of_kind(&boot2_rows, "subscription_rebuild");
    assert!(!boot2_rebuilds.is_empty());
    for rebuild in &boot2_rebuilds {
        let lookback = rebuild["kind"]["lookback_secs"]
            .as_u64()
            .expect("rebuild rows record the lookback");
        assert_eq!(
            rebuild["kind"]["since_secs"].as_u64(),
            Some(baseline - lookback),
            "a frozen rebuild still floors at the loaded cursor minus the \
             lookback: {rebuild}"
        );
    }

    // A fresh message for the Advance boot: the frozen-ingested one is
    // seen-id deduped on redelivery (by design — bounded redelivery is the
    // documented worst case), so only genuinely new traffic advances the
    // cursor. Published while bob is offline so the first catch-up drain
    // ingests it.
    alice_client
        .send(&group_id, b"advance resumes the ratchet")
        .await
        .unwrap();

    // --- boot 3 (Advance, the default): the same store must surface the
    // byte-identical pre-frozen cursor, then advance it normally. ---
    let app_bob_boot3 = open_store(&dir_bob, &url, CursorPersistence::Advance);
    let runtime_bob_boot3 = MarmotAppRuntime::new(app_bob_boot3.clone());
    let mut events_boot3 = runtime_bob_boot3.subscribe();
    runtime_bob_boot3.start().await.unwrap();
    wait_for_first_catch_up(&runtime_bob_boot3).await;
    wait_for_event(&mut events_boot3, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "advance resumes the ratchet"
        )
    })
    .await;
    runtime_bob_boot3.catch_up_accounts().await.unwrap();

    // Bounded redelivery absorbed by seen-id dedup: the rebuilt floor covers
    // the frozen-ingested message, so the relay redelivers it, but it must
    // not project twice.
    let advance_boot_messages = app_bob_boot3
        .messages_with_query(
            "bob",
            AppMessageQuery {
                group_id_hex: Some(group_id_hex),
                limit: None,
            },
        )
        .unwrap();
    assert_eq!(
        advance_boot_messages
            .iter()
            .filter(|message| message.plaintext == "frozen wake ingests without moving the floor")
            .count(),
        1,
        "redelivery of the frozen-ingested message is absorbed by seen-id dedup"
    );
    runtime_bob_boot3.shutdown().await;

    let boot3_rows = audit_rows.new_rows(&app_bob_boot3, "bob");
    let boot3_drains = rows_of_kind(&boot3_rows, "sync_drain");
    // Core assertion: the Advance boot loaded a persisted cursor
    // byte-identical to the pre-frozen baseline — the frozen pass's
    // save_state never moved the durable floor — and a fresh delivery
    // advanced it normally in the same drain.
    assert!(
        boot3_drains.iter().any(|drain| {
            drain["kind"]["cursor_before_secs"].as_u64() == Some(baseline)
                && drain["kind"]["deliveries"].as_u64().unwrap_or(0) >= 1
                && drain["kind"]["cursor_after_secs"]
                    .as_u64()
                    .is_some_and(|after| after > baseline)
        }),
        "an Advance runtime over the same store must load the untouched \
         pre-frozen cursor ({baseline}) and advance past it on fresh \
         delivery: {boot3_drains:?}"
    );
}
