//! The account worker's detached Welcome waves (mdk#3466 PR 1): what a
//! wave beside the writer keeps of a wave on it. The session's tests own
//! the wave's terms, one publisher per Welcome, the abandoned wave's owed
//! Welcomes and the counted inputs a run leaves alone. These own what only
//! the worker decides: a wave of a group gone before it settles, the
//! pending-deliveries read that waits for earlier waves (W8), the client
//! replacement and worker exits a wave can meet, and the bounded wait runtime
//! shutdown gives a wave (L3).
//!
//! Each test holds a create's founding gift wrap on the relays, as hold 4's
//! flip does, and the worker answers commands while it is held.

use super::writer_hold_tests::{Alice, SETTLE, alice_with_groups};
use super::*;
use tokio::sync::Notify;

/// Alice's create with bob, whose founding Welcome waits on the relays.
async fn held_founding_wave(dir: &tempfile::TempDir) -> (Alice<0>, GroupId) {
    let (alice, bob) = alice_and_bob(dir).await;
    let group = hold_founding_wave(&alice, &bob).await;
    (alice, group)
}

/// Alice's runtime, with bob's account and KeyPackage ready for an invite.
async fn alice_and_bob(dir: &tempfile::TempDir) -> (Alice<0>, marmot_account::AccountSummary) {
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let alice = alice_with_groups(dir, []).await;
    crate::tests::remember_test_member_inbox(
        &alice.app,
        &bob.account_id_hex,
        "wss://relay.example",
    );
    alice.runtime.publish_key_package("bob").await.unwrap();
    (alice, bob)
}

/// Alice creates a group with bob, and its founding Welcome waits on the
/// relays.
async fn hold_founding_wave(alice: &Alice<0>, bob: &marmot_account::AccountSummary) -> GroupId {
    alice
        .relay
        .block_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let group = alice
        .runtime
        .create_group(
            "alice",
            "held wave",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, alice.relay.wait_for_blocked_publish())
        .await
        .expect("the founding Welcome reaches its relays");
    group
}

/// Send a `Drain` to alice's worker, answered once every wave it started
/// before has settled.
pub(super) async fn drain(runtime: &crate::MarmotAppRuntime) -> oneshot::Receiver<()> {
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let (respond, drained) = oneshot::channel();
    lane.commands
        .send(AccountWorkerCommand::Drain { respond })
        .await
        .unwrap();
    drained
}

/// A hold the worker of one account enters after it settles a wave and
/// before it answers the waits on it: the notifiers it enters and waits on.
/// Kept by account id, so tests that share a process do not take each
/// other's hold.
type SettleHold = (Arc<Notify>, Arc<Notify>);
static HOLD_AFTER_SETTLE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, SettleHold>>,
> = std::sync::LazyLock::new(Default::default);

/// Hold the worker of the account `account_id_hex` after it next settles a
/// wave.
fn hold_after_settle(account_id_hex: &str) -> (Arc<Notify>, Arc<Notify>) {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    HOLD_AFTER_SETTLE.lock().unwrap().insert(
        account_id_hex.to_owned(),
        (entered.clone(), release.clone()),
    );
    (entered, release)
}

/// The worker's side of [`hold_after_settle`].
pub(in crate::runtime::account_worker) async fn held_after_settle(account_id_hex: &str) {
    let held = HOLD_AFTER_SETTLE.lock().unwrap().remove(account_id_hex);
    if let Some((entered, release)) = held {
        entered.notify_one();
        release.notified().await;
    }
}

static HOLD_AFTER_STARTUP_PASS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, SettleHold>>,
> = std::sync::LazyLock::new(Default::default);

/// Hold the worker of the account `account_id_hex` once its startup pass
/// has run, before its first loop turn: no wave settled, no maintenance.
fn hold_after_startup_pass(account_id_hex: &str) -> (Arc<Notify>, Arc<Notify>) {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    HOLD_AFTER_STARTUP_PASS.lock().unwrap().insert(
        account_id_hex.to_owned(),
        (entered.clone(), release.clone()),
    );
    (entered, release)
}

/// The worker's side of [`hold_after_startup_pass`].
pub(in crate::runtime::account_worker) async fn held_after_startup_pass(account_id_hex: &str) {
    let held = HOLD_AFTER_STARTUP_PASS
        .lock()
        .unwrap()
        .remove(account_id_hex);
    if let Some((entered, release)) = held {
        entered.notify_one();
        release.notified().await;
    }
}

/// Send a pending-deliveries read to alice's worker, answered once every
/// wave it started before has settled (W8).
pub(super) async fn read_pending(
    runtime: &crate::MarmotAppRuntime,
) -> oneshot::Receiver<Result<Vec<crate::PendingWelcomeDelivery>, AppError>> {
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let (respond, listed) = ReadReply::unobserved();
    lane.commands
        .send(AccountWorkerCommand::PendingWelcomeDeliveries { respond })
        .await
        .unwrap();
    listed
}

/// Stop the workers, then close storage. A settled wave's own Welcome comes
/// back as a local copy that the worker ingests after the `Drain` answers;
/// stopping first keeps terminal close from landing inside that ingest,
/// whose failure the read-state oracle would then meet with closed storage.
pub(super) async fn close(runtime: &crate::MarmotAppRuntime) {
    runtime.shutdown().await;
    runtime.shutdown_and_close().await.unwrap();
}

/// Date every relay attempt on alice's stored Welcome retry records an hour
/// earlier, past any relay's backoff, as if the app had stayed closed that
/// long: the next start asks those relays again (mdk#3589).
fn age_welcome_attempts(dir: &tempfile::TempDir) {
    use cgka_traits::storage::MaintenanceStorage as _;
    let storage = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .account_storage("alice")
        .unwrap();
    for mut fanout in storage.list_transport_fanouts().unwrap() {
        if !matches!(
            fanout.exact_message.envelope,
            cgka_traits::TransportEnvelope::Welcome { .. }
        ) {
            continue;
        }
        for at in fanout
            .targets
            .iter_mut()
            .filter_map(|target| target.last_attempt_at.as_mut())
        {
            at.0 = at.0.saturating_sub(60 * 60);
        }
        storage.put_transport_fanout(&fanout).unwrap();
    }
}

/// Move the delivery deadline of every Welcome alice still owes into the
/// past, as if the app had stayed closed past it (mdk#3589).
fn pass_welcome_deadlines(dir: &tempfile::TempDir) {
    use cgka_traits::storage::{MaintenanceStorage as _, MessageStorage as _};
    let storage = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .account_storage("alice")
        .unwrap();
    for fanout in storage.list_transport_fanouts().unwrap() {
        if !matches!(
            fanout.exact_message.envelope,
            cgka_traits::TransportEnvelope::Welcome { .. }
        ) {
            continue;
        }
        let mut record = storage.get_message(&fanout.exact_message.id).unwrap();
        let mut payload =
            cgka_traits::message::StoredMessagePayload::decode(&record.payload).unwrap();
        let cgka_traits::message::StoredMessagePayload::OutboundWelcome { deliver_until, .. } =
            &mut payload
        else {
            panic!("an owed Welcome")
        };
        *deliver_until = Some(cgka_traits::transport::Timestamp(1));
        record.payload = payload.encode().unwrap();
        storage.put_message(&record).unwrap();
    }
}

/// How many times a gift wrap reached the relays.
fn gift_wraps_published(relay: &ScriptedPushRelayClient) -> usize {
    published_gift_wraps(relay).len()
}

/// The gift wraps that reached the relays, by event id, in order.
fn published_gift_wraps(relay: &ScriptedPushRelayClient) -> Vec<String> {
    let gift_wraps = relay
        .attempted_events()
        .into_iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_NIP59_GIFT_WRAP)
        .map(|event| event.id)
        .collect::<std::collections::HashSet<_>>();
    relay
        .published_event_ids()
        .into_iter()
        .filter(|id| gift_wraps.contains(id))
        .collect()
}

/// Start alice's next runtime over the same root and relay, and wait for
/// its startup retry, the first wave, to settle.
async fn restart(
    dir: &tempfile::TempDir,
    relay: &Arc<ScriptedPushRelayClient>,
) -> crate::MarmotAppRuntime {
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = crate::MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, "alice")
        .await
        .unwrap();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    runtime
}

/// Wait until `runtime` has begun shutting down.
async fn until_stopping(runtime: &crate::MarmotAppRuntime) {
    timeout(SETTLE, async {
        while !runtime.is_stopping() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown begins");
}

/// The undelivered Welcomes of `group` the host is shown.
async fn pending_of(
    runtime: &crate::MarmotAppRuntime,
    group: &GroupId,
) -> Vec<crate::PendingWelcomeDelivery> {
    runtime
        .pending_welcome_deliveries("alice")
        .await
        .unwrap()
        .into_iter()
        .filter(|pending| pending.group_id_hex == hex::encode(group.as_slice()))
        .collect()
}

/// W5: a wave whose chat the host deletes while it runs changes nothing of
/// the group when it settles. Its Welcome fails, which would leave a pending
/// delivery and its event for a chat the host no longer shows. The pass
/// that reached the relays is still audited to its end: its finished row
/// records what the relays answered, with no stored outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wave_settling_after_its_chat_is_deleted_leaves_it_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob) = alice_and_bob(&dir).await;
    alice
        .runtime
        .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .await
        .unwrap();
    let group = hold_founding_wave(&alice, &bob).await;
    let Alice {
        app,
        relay,
        runtime,
        ..
    } = alice;
    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    assert!(runtime.delete_group_local("alice", &group).await.unwrap());
    let mut events = runtime.subscribe();

    let drained = drain(&runtime).await;
    relay.release_publish();
    timeout(SETTLE, drained).await.unwrap().unwrap();
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                &event,
                MarmotAppEvent::WelcomeDeliveryPending { group_id, .. } if group_id == &group
            ),
            "a deleted chat's settle emits no pending delivery"
        );
    }
    // The engine still owes the Welcome, as it did while the wave ran: a
    // read then would have listed it the same way.
    assert_eq!(pending_of(&runtime, &group).await.len(), 1);
    close(&runtime).await;
    let passes = crate::tests::v5_audit_rows(&app, "alice")
        .into_iter()
        .filter(|row| {
            row["event"]["type"]
                .as_str()
                .unwrap()
                .starts_with("welcome_publish_")
        })
        .collect::<Vec<_>>();
    let kinds = passes
        .iter()
        .map(|row| row["event"]["type"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        ["welcome_publish_started", "welcome_publish_finished"],
        "{passes:?}"
    );
    let finished = &passes[1]["event"];
    assert_eq!(finished["attempt_id"], passes[0]["event"]["attempt_id"]);
    assert_eq!(finished["accepted_total_count"], serde_json::Value::Null);
    assert_eq!(finished["policy"], "unknown");
    assert_eq!(finished["retained_state"], "unknown");
}

/// W5 for a wave with no group of its own: the startup retry's wave carries
/// each Welcome's group, and a Welcome whose chat the host deletes while the
/// wave runs settles to nothing. The engine keeps the group and its owed
/// Welcome, so only the settle can leave the deleted chat alone. Alice's first Welcome to bob failed, so the next
/// start retries it, and that retry fails too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_startup_retry_settling_after_its_chat_is_deleted_leaves_it_alone() {
    let dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let Alice {
        app,
        relay,
        runtime,
        ..
    } = alice_with_groups(&dir, []).await;
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    runtime.publish_key_package("bob").await.unwrap();
    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let group = runtime
        .create_group(
            "alice",
            "retried",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !pending_of(&runtime, &group).await.is_empty(),
        "the first Welcome failed"
    );
    close(&runtime).await;
    age_welcome_attempts(&dir);

    relay.block_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = crate::MarmotAppRuntime::new(app);
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    timeout(SETTLE, relay.wait_for_blocked_publish())
        .await
        .expect("the startup retry reaches the relays");
    assert!(runtime.delete_group_local("alice", &group).await.unwrap());

    let drained = drain(&runtime).await;
    relay.release_publish();
    timeout(SETTLE, drained).await.unwrap().unwrap();
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                &event,
                MarmotAppEvent::WelcomeDeliveryPending { group_id, .. } if group_id == &group
            ),
            "a deleted chat's settle emits no pending delivery"
        );
    }
    assert_eq!(pending_of(&runtime, &group).await.len(), 1);
    close(&runtime).await;
}

/// A founding Welcome to bob, whose two inbox relays answer at different
/// speeds, settles at the first relay's acceptance: a pending-deliveries
/// read answers with it delivered while the other relay is held, since a
/// read waits for no remaining wave. Once that relay answers, the worker
/// settles the remaining wave, which records its acceptance as a pass of
/// its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_welcome_settles_at_its_first_relay_and_records_the_slower_one() {
    let dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let Alice {
        account,
        app,
        relay,
        runtime,
        ..
    } = alice_with_groups(&dir, []).await;
    let mut relay_lists = crate::AccountRelayListStatus::empty();
    relay_lists.inbox.created_at = 1;
    relay_lists.inbox.relays = vec![
        "wss://relay.example".to_owned(),
        "wss://slow.example".to_owned(),
    ];
    relay_lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&bob.account_id_hex, &relay_lists)
        .unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    runtime
        .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .await
        .unwrap();
    let (held, release) =
        relay.hold_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let group = runtime
        .create_group(
            "alice",
            "two inbox relays",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, held.notified())
        .await
        .expect("one inbox relay holds the Welcome");

    let listed = timeout(SETTLE, read_pending(&runtime).await)
        .await
        .expect("the read does not wait for the held relay")
        .unwrap()
        .unwrap();
    assert!(
        listed
            .iter()
            .all(|pending| pending.group_id_hex != hex::encode(group.as_slice())),
        "the other relay's acceptance settled the Welcome"
    );

    let (settled, resume) = hold_after_settle(&account.account_id_hex);
    release.notify_one();
    timeout(SETTLE, settled.notified())
        .await
        .expect("the worker settles the remaining wave once the relay answers");
    resume.notify_one();
    close(&runtime).await;
    let passes = crate::tests::v5_audit_rows(&app, "alice")
        .into_iter()
        .filter(|row| row["event"]["type"] == "welcome_publish_finished")
        .collect::<Vec<_>>();
    assert_eq!(passes.len(), 2, "{passes:?}");
    assert_eq!(passes[0]["event"]["policy"], "met", "{passes:?}");
    let remaining = &passes[1]["event"];
    assert_eq!(remaining["results_complete"], true, "{remaining}");
    assert_eq!(remaining["accepted_this_attempt_count"], 1, "{remaining}");
    assert_eq!(remaining["accepted_total_count"], 2, "{remaining}");
    assert_eq!(remaining["retained_state"], "completed", "{remaining}");
}

/// Remember `relays` as the inbox relays of `account_id_hex`.
fn remember_inboxes(app: &MarmotApp, account_id_hex: &str, relays: &[&str]) {
    let mut relay_lists = crate::AccountRelayListStatus::empty();
    relay_lists.inbox.created_at = 1;
    relay_lists.inbox.relays = relays.iter().map(|relay| (*relay).to_owned()).collect();
    relay_lists.refresh();
    app.directory()
        .remember_directory_relay_lists(account_id_hex, &relay_lists)
        .unwrap();
}

/// Alice creates a group with bob, whose inbox relays are
/// `wss://bob-first.example`, which takes his Welcome at once, and
/// `wss://index.example`, which holds it for good. Returns once the wave
/// settled the Welcome delivered and its remaining wave runs, asking the held
/// relay.
async fn a_held_remaining_wave(dir: &tempfile::TempDir) -> Alice<0> {
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let alice = alice_with_groups(dir, []).await;
    remember_inboxes(
        &alice.app,
        &bob.account_id_hex,
        &["wss://bob-first.example", "wss://index.example"],
    );
    alice.runtime.publish_key_package("bob").await.unwrap();
    alice
        .runtime
        .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .await
        .unwrap();
    alice
        .relay
        .block_indexer_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let group = alice
        .runtime
        .create_group(
            "alice",
            "held remaining wave",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let listed = timeout(SETTLE, read_pending(&alice.runtime).await)
        .await
        .expect("the read does not wait for the held relay")
        .unwrap()
        .unwrap();
    assert!(
        listed
            .iter()
            .all(|pending| pending.group_id_hex != hex::encode(group.as_slice())),
        "the first relay's acceptance settled the Welcome"
    );
    timeout(SETTLE, async {
        while remaining_pass_rows(&alice.app, "welcome_publish_started").is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the remaining wave starts");
    alice
}

/// The rows of type `kind` of the remaining passes, the passes over the
/// relays a settled pass left answering.
fn remaining_pass_rows(app: &MarmotApp, kind: &str) -> Vec<serde_json::Value> {
    let rows = crate::tests::v5_audit_rows(app, "alice");
    let remaining = rows
        .iter()
        .filter(|row| {
            row["event"]["type"] == "welcome_publish_started"
                && row["event"]["route_source"] == "retained_target"
        })
        .map(|row| row["event"]["attempt_id"].clone())
        .collect::<Vec<_>>();
    rows.into_iter()
        .filter(|row| {
            row["event"]["type"] == kind && remaining.contains(&row["event"]["attempt_id"])
        })
        .collect()
}

/// A cancelled remaining wave records nothing: its pass has its started row
/// and no finished row, and its relay stays owed. Each first pass's
/// finished row stands, its Welcome delivered by its one stored acceptance.
fn assert_the_cancelled_remaining_wave_recorded_nothing(app: &MarmotApp, first_passes: usize) {
    assert_eq!(remaining_pass_rows(app, "welcome_publish_started").len(), 1);
    let finished = remaining_pass_rows(app, "welcome_publish_finished");
    assert!(finished.is_empty(), "{finished:?}");
    let first = crate::tests::v5_audit_rows(app, "alice")
        .into_iter()
        .filter(|row| row["event"]["type"] == "welcome_publish_finished")
        .collect::<Vec<_>>();
    assert_eq!(
        first.len(),
        first_passes,
        "each first pass finished: {first:?}"
    );
    for first in &first {
        assert_eq!(first["event"]["accepted_total_count"], 1, "{first}");
        assert_eq!(first["event"]["retained_state"], "completed", "{first}");
    }
}

/// L3 with a remaining wave still held when the shutdown bound passes: the
/// worker cancels it and waits for it before the audit closes, and it
/// records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_a_held_remaining_wave_and_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let Alice { app, runtime, .. } = a_held_remaining_wave(&dir).await;

    close(&runtime).await;

    assert_the_cancelled_remaining_wave_recorded_nothing(&app, 1);
}

/// The same at sign-out (`WelcomeRuns::stop`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_cancels_a_held_remaining_wave_and_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let Alice { app, runtime, .. } = a_held_remaining_wave(&dir).await;

    timeout(
        SETTLE,
        runtime.sign_out(
            "alice",
            crate::SignOutOptions {
                delete_key_packages: false,
            },
        ),
    )
    .await
    .expect("sign-out ends the remaining wave")
    .unwrap();
    runtime.shutdown_and_close().await.unwrap();

    assert_the_cancelled_remaining_wave_recorded_nothing(&app, 1);
}

/// The same at an unlink, which stops the worker its own way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlinking_cancels_a_held_remaining_wave_and_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let Alice { app, runtime, .. } = a_held_remaining_wave(&dir).await;

    timeout(SETTLE, runtime.accounts().unlink_device_for_test("alice"))
        .await
        .expect("the worker takes the unlink")
        .unwrap();
    close(&runtime).await;

    assert_the_cancelled_remaining_wave_recorded_nothing(&app, 1);
}

/// A stop that finds a first wave already returned, its pass settled at one
/// relay's acceptance while another relay is still pending, settles it as
/// the worker would have: the acceptance reaches the retry record and the
/// Welcome is delivered, while the pending relay's remaining wave is
/// cancelled, records nothing, and leaves that relay owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_settles_a_first_wave_that_already_returned() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let bob = home.create_account("bob").unwrap();
    let carol = home.create_account("carol").unwrap();
    let Alice {
        account,
        app,
        relay,
        runtime,
        ..
    } = alice_with_groups(&dir, []).await;
    remember_inboxes(
        &app,
        &bob.account_id_hex,
        &["wss://bob-first.example", "wss://index.example"],
    );
    remember_inboxes(&app, &carol.account_id_hex, &["wss://carol-only.example"]);
    runtime.publish_key_package("bob").await.unwrap();
    runtime.publish_key_package("carol").await.unwrap();
    runtime
        .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .await
        .unwrap();
    relay
        .block_indexer_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);
    // Bob's first relay holds his Welcome, so his wave has not returned yet.
    let (held, release) =
        relay.hold_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    runtime
        .create_group(
            "alice",
            "bob's chat",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, held.notified())
        .await
        .expect("bob's first relay holds his Welcome");
    // The worker holds still once it settled carol's wave, so bob's wave
    // returns while nothing settles it.
    let (settled, resume) = hold_after_settle(&account.account_id_hex);
    runtime
        .create_group(
            "alice",
            "carol's chat",
            std::slice::from_ref(&carol.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, settled.notified())
        .await
        .expect("the worker settles carol's wave");
    release.notify_one();
    // The returning wave starts the remaining pass over bob's held relay.
    timeout(SETTLE, async {
        while remaining_pass_rows(&app, "welcome_publish_started").is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bob's wave returns");
    let worker = runtime
        .accounts()
        .workers
        .lock()
        .await
        .remove(&account.account_id_hex)
        .expect("alice's worker");
    worker.shutdown.send(()).unwrap();
    resume.notify_one();
    timeout(SETTLE, worker.handle)
        .await
        .expect("the worker stops")
        .unwrap();

    assert_the_cancelled_remaining_wave_recorded_nothing(&app, 2);
    runtime.shutdown_and_close().await.unwrap();
}

/// A stop that finds a remaining wave already returned, but not yet settled,
/// settles it as the worker would have: its relay's acceptance reaches the
/// retry record, so the finished row reports the stored total, not an
/// unknown one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_settles_a_remaining_wave_that_already_returned() {
    let dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let Alice {
        account,
        app,
        relay,
        runtime,
        ..
    } = alice_with_groups(&dir, []).await;
    remember_inboxes(
        &app,
        &bob.account_id_hex,
        &["wss://bob-first.example", "wss://bob-second.example"],
    );
    runtime.publish_key_package("bob").await.unwrap();
    runtime
        .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .await
        .unwrap();
    let (held, release) =
        relay.hold_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    // The worker holds still once it settled the first wave, before it takes
    // the remaining wave up.
    let (settled, resume) = hold_after_settle(&account.account_id_hex);
    runtime
        .create_group(
            "alice",
            "returned remaining wave",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, held.notified())
        .await
        .expect("bob's first relay holds his Welcome");
    timeout(SETTLE, settled.notified())
        .await
        .expect("the worker settles the first wave");

    release.notify_one();
    app.welcome_waves_in_flight
        .ended_by(tokio::time::Instant::now() + SETTLE)
        .await;
    assert_eq!(
        gift_wraps_published(&relay),
        2,
        "both relays took the Welcome"
    );
    let worker = runtime
        .accounts()
        .workers
        .lock()
        .await
        .remove(&account.account_id_hex)
        .expect("alice's worker");
    worker.shutdown.send(()).unwrap();
    resume.notify_one();
    timeout(SETTLE, worker.handle)
        .await
        .expect("the worker stops")
        .unwrap();

    let finished = remaining_pass_rows(&app, "welcome_publish_finished");
    let [remaining] = finished.as_slice() else {
        panic!("one remaining pass: {finished:?}");
    };
    assert_eq!(remaining["event"]["results_complete"], true, "{remaining}");
    assert_eq!(remaining["event"]["accepted_total_count"], 2, "{remaining}");
    runtime.shutdown_and_close().await.unwrap();
}

/// W8: a pending-deliveries read waits only for the waves started before
/// the worker took it up. A wave the next create starts, held on the relays,
/// doesn't extend the wait: the read answers once the earlier wave settles,
/// with that wave's Welcome delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_wave_does_not_extend_a_pending_deliveries_read() {
    let dir = tempfile::tempdir().unwrap();
    let carol = AccountHome::open(dir.path())
        .create_account("carol")
        .unwrap();
    let (
        Alice {
            app,
            relay,
            runtime,
            ..
        },
        group,
    ) = held_founding_wave(&dir).await;
    crate::tests::remember_test_member_inbox(&app, &carol.account_id_hex, "wss://relay.example");
    runtime.publish_key_package("carol").await.unwrap();

    let mut listed = read_pending(&runtime).await;
    let (later_entered, later_release) =
        relay.hold_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    runtime
        .create_group(
            "alice",
            "later wave",
            std::slice::from_ref(&carol.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, later_entered.notified())
        .await
        .expect("the later wave reaches its relays");
    assert!(
        matches!(listed.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "the read waits for the earlier wave"
    );

    relay.release_publish();
    let listed = timeout(SETTLE, listed)
        .await
        .expect("the read answers while the later wave is held")
        .unwrap()
        .unwrap();
    assert!(
        listed
            .iter()
            .all(|pending| pending.group_id_hex != hex::encode(group.as_slice())),
        "the earlier wave delivered its Welcome before the read answered"
    );
    assert_eq!(
        gift_wraps_published(&relay),
        1,
        "the later wave is still held"
    );

    later_release.notify_one();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    close(&runtime).await;
}

/// L1: a client replacement during a held wave abandons it on the client
/// that started it, and a `Drain` and a pending-deliveries read waiting for
/// the wave answer on that client, before the worker backs off to reopen:
/// an outage never holds them. Its Welcome stays owed, the next client's
/// maintenance sends it, and it reaches the relays once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_replacement_abandons_a_held_wave_and_its_welcome_is_sent_once() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { relay, runtime, .. }, _) = held_founding_wave(&dir).await;
    let drained = drain(&runtime).await;
    let listed = read_pending(&runtime).await;
    let mut events = runtime.subscribe();
    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    timeout(SETTLE, async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::AccountError(error))
                    if error.message.starts_with("runtime receive failed") =>
                {
                    break;
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("runtime events closed before the failed receive")
                }
            }
        }
    })
    .await
    .expect("the consumer exit fails the worker's receive");
    timeout(SETTLE, drained)
        .await
        .expect("the replacement settles the held wave")
        .unwrap();
    timeout(SETTLE, listed)
        .await
        .expect("the replacement answers the waiting read")
        .unwrap()
        .unwrap();
    // Both answered before the reopen: the backoff, two seconds at least,
    // drops a command unanswered, and the worker is still in it.
    assert!(
        timeout(SETTLE, drain(&runtime).await)
            .await
            .expect("the worker takes the probe up")
            .is_err(),
        "the replacement answers its waits before the worker backs off to reopen"
    );
    assert_eq!(gift_wraps_published(&relay), 0);

    runtime.notify_connectivity_restored().await.unwrap();
    timeout(SETTLE, async {
        while runtime.run_due_maintenance("alice").await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the next client takes commands");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gift_wraps_published(&relay), 1, "maintenance sends it");
    // A publish the abandoned wave left parked would reach the relays now.
    relay.release_publish();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gift_wraps_published(&relay), 1);
    close(&runtime).await;
}

/// L3: a wave whose publish ends within the shutdown bound settles before
/// the worker returns. A pending-deliveries read waiting for it answers with
/// its list (W8), the settle's audit row lands before the recording's stop
/// row, the Welcome is recorded as delivered, and the next start sends
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_settles_a_wave_that_ends_within_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob) = alice_and_bob(&dir).await;
    alice
        .runtime
        .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .await
        .unwrap();
    let group = hold_founding_wave(&alice, &bob).await;
    let Alice {
        app,
        relay,
        runtime,
        ..
    } = alice;
    let listed = read_pending(&runtime).await;
    // The worker takes commands in order: once this one answers, it has
    // taken the read, which waits for the held wave.
    runtime.publish_key_package("alice").await.unwrap();
    let stopping = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.shutdown().await }
    });
    until_stopping(&runtime).await;

    relay.release_publish();
    let listed = timeout(SETTLE, listed)
        .await
        .expect("the worker answers the read")
        .unwrap()
        .expect("the read answers with its list");
    assert!(
        listed
            .iter()
            .all(|pending| pending.group_id_hex != hex::encode(group.as_slice())),
        "the wave settled its Welcome delivered before the read answered"
    );
    timeout(SETTLE, stopping).await.unwrap().unwrap();
    assert_eq!(gift_wraps_published(&relay), 1);
    let settled_before_stop = app.audit_log_files().unwrap().iter().any(|file| {
        let events = std::fs::read_to_string(&file.path)
            .unwrap()
            .lines()
            .map(|line| marmot_forensics::v5::Record::from_json(line.as_bytes()).unwrap())
            .map(|record| record.fields().event.clone())
            .collect::<Vec<_>>();
        matches!(
            events.last(),
            Some(marmot_forensics::v5::Event::RecordingSessionStopped(stop))
                if stop.reason == marmot_forensics::v5::RecordingStopReason::CleanRuntimeShutdown
        ) && events.iter().any(|event| {
            matches!(
                event,
                marmot_forensics::v5::Event::WelcomePublishFinished(_)
            )
        })
    });
    assert!(
        settled_before_stop,
        "the settle is recorded before the recording stops"
    );
    runtime.shutdown_and_close().await.unwrap();

    let runtime = restart(&dir, &relay).await;
    assert_eq!(
        gift_wraps_published(&relay),
        1,
        "the settle recorded the Welcome, so the next start owes nothing"
    );
    close(&runtime).await;
}

/// L3 from the host's answer: a create's wave counts before the create
/// answers, so a shutdown begun from that answer, before the wave has
/// started, keeps the relay plane up while it publishes. The wave settles,
/// and the next start owes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_begun_from_the_create_answer_waits_for_its_wave() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { relay, runtime, .. }, bob) = alice_and_bob(&dir).await;
    let teardown = runtime.stall_shutdown_for_test(crate::runtime::ShutdownTestPhase::RelayPlane);
    relay.block_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    runtime
        .create_group(
            "alice",
            "answered wave",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let stopping = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.shutdown().await }
    });

    timeout(SETTLE, relay.wait_for_blocked_publish())
        .await
        .expect("the founding Welcome reaches its relays");
    assert!(
        !teardown.was_entered(),
        "the relay plane stays up while the wave publishes"
    );
    relay.release_publish();
    timeout(SETTLE, teardown.wait_until_entered())
        .await
        .expect("the relay plane is torn down once the wave ends");
    teardown.release();
    timeout(SETTLE, stopping).await.unwrap().unwrap();
    assert_eq!(gift_wraps_published(&relay), 1);
    runtime.shutdown_and_close().await.unwrap();

    let runtime = restart(&dir, &relay).await;
    assert_eq!(
        gift_wraps_published(&relay),
        1,
        "the settle recorded the Welcome, so the next start owes nothing"
    );
    close(&runtime).await;
}

/// L3 and L2: a wave that never answers doesn't hold the close, and keeps
/// the relay plane up only until the shutdown bound, when exit cancels it.
/// Its Welcome stays owed, a pending-deliveries read waiting for it gets the
/// error a queued command gets (W8), and the next start sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_a_wave_held_past_the_bound_and_the_next_start_sends_its_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { relay, runtime, .. }, _) = held_founding_wave(&dir).await;
    let listed = read_pending(&runtime).await;
    runtime.publish_key_package("alice").await.unwrap();
    let teardown = runtime.stall_shutdown_for_test(crate::runtime::ShutdownTestPhase::RelayPlane);
    let started = Instant::now();
    let closing = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.shutdown_and_close().await }
    });
    timeout(SETTLE, teardown.wait_until_entered())
        .await
        .expect("the relay plane is torn down");
    assert!(
        runtime.storage_is_closed(),
        "the close doesn't wait for the wave"
    );
    assert!(
        started.elapsed() >= crate::WELCOME_WAVE_SHUTDOWN_WAIT,
        "the relay plane stays up for the wave until the bound"
    );
    teardown.release();
    timeout(SETTLE, closing).await.unwrap().unwrap().unwrap();
    assert!(
        matches!(
            timeout(SETTLE, listed)
                .await
                .expect("shutdown answers the read"),
            Ok(Err(AppError::TransportClosed))
        ),
        "the read is answered, not dropped"
    );
    relay.release_publish();
    assert_eq!(gift_wraps_published(&relay), 0);

    let runtime = restart(&dir, &relay).await;
    assert_eq!(gift_wraps_published(&relay), 1);
    close(&runtime).await;
}

/// L3 after a terminal close: a wave that ends within the bound still
/// reaches the relays, but its settle meets closed storage. Its Welcome
/// stays owed, and the next start sends it once more as the same event. A
/// recipient that already joined leaves its state as it was
/// (`audit_v5_probe::tests::duplicate_delivery_does_not_rejoin`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_welcome_published_after_the_close_is_sent_once_more_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { relay, runtime, .. }, _) = held_founding_wave(&dir).await;
    let closing = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.shutdown_and_close().await }
    });
    timeout(SETTLE, async {
        while !runtime.storage_is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("storage closes while the wave is held");

    relay.release_publish();
    timeout(SETTLE, closing).await.unwrap().unwrap().unwrap();
    assert_eq!(
        gift_wraps_published(&relay),
        1,
        "the wave reaches the relays after the close"
    );

    let runtime = restart(&dir, &relay).await;
    let sent = published_gift_wraps(&relay);
    assert_eq!(sent.len(), 2, "the next start sends it once more");
    assert_eq!(sent[0], sent[1], "as the same event");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gift_wraps_published(&relay), 2, "and only once");
    close(&runtime).await;
}

/// W8 at shutdown: a read whose wave settles as shutdown begins is
/// answered, with its list or with the error a queued command gets. Which
/// one is not a host contract; that it never hangs is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_whose_wave_settles_as_shutdown_begins_is_answered() {
    let dir = tempfile::tempdir().unwrap();
    let (
        Alice {
            account,
            relay,
            runtime,
            ..
        },
        _,
    ) = held_founding_wave(&dir).await;
    let listed = read_pending(&runtime).await;
    // Once this answers, the worker has taken the read up.
    runtime.publish_key_package("alice").await.unwrap();
    let (settled, resume) = hold_after_settle(&account.account_id_hex);
    relay.release_publish();
    timeout(SETTLE, settled.notified())
        .await
        .expect("the worker settles the released wave");

    let stopping = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.shutdown().await }
    });
    timeout(SETTLE, async {
        while !runtime.is_stopping() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown begins");
    resume.notify_one();
    assert!(
        matches!(
            timeout(SETTLE, listed)
                .await
                .expect("the worker answers the read"),
            Ok(Ok(_) | Err(AppError::TransportClosed))
        ),
        "the read answers with its list or the shutdown error"
    );
    timeout(SETTLE, stopping).await.unwrap().unwrap();
    runtime.shutdown_and_close().await.unwrap();
}

/// L2, sign-out: a held wave doesn't hold the sign-out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_ends_a_held_wave() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { runtime, .. }, _) = held_founding_wave(&dir).await;
    timeout(
        SETTLE,
        runtime.sign_out(
            "alice",
            crate::SignOutOptions {
                delete_key_packages: false,
            },
        ),
    )
    .await
    .expect("sign-out ends the held wave")
    .unwrap();
    runtime.shutdown_and_close().await.unwrap();
}

/// L2, unlink: a held wave doesn't hold the device's removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlinking_ends_a_held_wave() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { runtime, .. }, _) = held_founding_wave(&dir).await;
    timeout(SETTLE, runtime.accounts().unlink_device_for_test("alice"))
        .await
        .expect("unlinking ends the held wave")
        .unwrap();
    runtime.shutdown_and_close().await.unwrap();
}

/// mdk#1706: a host reads each invite's delivery from the public runtime,
/// and is told when it changes. A founding Welcome no relay takes reads as
/// still being sent, and its worker announces that; after a restart whose
/// retry a relay stores, the durable record reads as accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invite_deliveries_answer_from_durable_records_and_announce_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob) = alice_and_bob(&dir).await;
    let Alice { relay, runtime, .. } = alice;
    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let mut events = runtime.subscribe();
    let group = runtime
        .create_group(
            "alice",
            "invite delivery",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();

    let invites = runtime
        .invite_deliveries("alice", Some(&group))
        .await
        .unwrap();
    assert_eq!(invites.len(), 1, "{invites:?}");
    let invite = &invites[0];
    assert_eq!(invite.recipient_hex, bob.account_id_hex);
    assert_eq!(invite.invite_id_hex, None, "the create added bob");
    assert!(
        matches!(
            invite.state,
            crate::WelcomeDeliveryState::Sending {
                last_problem: Some(_)
            }
        ),
        "{invite:?}"
    );
    assert_eq!((invite.accepted_device_count, invite.device_count), (0, 1));
    let mut announced = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let MarmotAppEvent::InviteDeliveryChanged { delivery, .. } = event {
            announced.push(delivery);
        }
    }
    assert_eq!(announced.last(), Some(invite), "{announced:?}");
    close(&runtime).await;
    age_welcome_attempts(&dir);

    relay.allow_all_publish_kinds();
    let runtime = restart(&dir, &relay).await;
    let invites = runtime
        .invite_deliveries("alice", Some(&group))
        .await
        .unwrap();
    assert_eq!(invites[0].state, crate::WelcomeDeliveryState::RelayAccepted);
    assert_eq!(invites[0].accepted_device_count, 1);
    assert_eq!(
        runtime.invite_deliveries("alice", None).await.unwrap(),
        invites
    );
    close(&runtime).await;
}

/// A raw connection to alice's account database, for putting it in a state
/// no runtime call makes. The runtime must not be running.
fn alices_database(app: &MarmotApp) -> rusqlite::Connection {
    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    storage_sqlite::expect_uncounted_writes_for_test(&path);
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// mdk#1706: an invite whose Welcome existed before the device kept invite
/// delivery records (an upgrade) is never listed by `invite_deliveries` and
/// announces nothing, yet is delivered as before and stays a pending
/// delivery while owed. An invite sent to the same account after the
/// upgrade is listed and announced as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invite_from_before_the_upgrade_is_delivered_but_not_listed() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob) = alice_and_bob(&dir).await;
    let Alice {
        app,
        relay,
        runtime,
        ..
    } = alice;
    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let group = runtime
        .create_group(
            "alice",
            "from before",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    close(&runtime).await;
    // As a database from before the ledger: the owed Welcome has no record.
    alices_database(&app)
        .execute_batch("DELETE FROM cgka_welcome_delivery_ledger;")
        .unwrap();

    let runtime = restart(&dir, &relay).await;
    let mut events = runtime.subscribe();
    assert!(
        runtime
            .invite_deliveries("alice", Some(&group))
            .await
            .unwrap()
            .is_empty()
    );
    let pending = pending_of(&runtime, &group).await;
    assert_eq!(pending.len(), 1, "still a pending delivery while owed");

    relay.allow_all_publish_kinds();
    runtime
        .redeliver_welcome("alice", &pending[0].message_id_hex)
        .await
        .unwrap();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert!(pending_of(&runtime, &group).await.is_empty(), "delivered");
    assert!(
        runtime
            .invite_deliveries("alice", Some(&group))
            .await
            .unwrap()
            .is_empty()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, MarmotAppEvent::InviteDeliveryChanged { .. }),
            "{event:?}"
        );
    }

    // Bob is invited again after the upgrade: that invite is listed.
    runtime
        .remove_members("alice", &group, std::slice::from_ref(&bob.account_id_hex))
        .await
        .unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    runtime
        .invite_members("alice", &group, std::slice::from_ref(&bob.account_id_hex))
        .await
        .unwrap();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    let invites = runtime
        .invite_deliveries("alice", Some(&group))
        .await
        .unwrap();
    assert_eq!(invites.len(), 1, "{invites:?}");
    assert_eq!(invites[0].recipient_hex, bob.account_id_hex);
    assert!(invites[0].invite_id_hex.is_some(), "the re-invite's commit");
    assert_eq!(invites[0].state, crate::WelcomeDeliveryState::RelayAccepted);
    let mut announced = false;
    while let Ok(event) = events.try_recv() {
        announced |= matches!(event, MarmotAppEvent::InviteDeliveryChanged { .. });
    }
    assert!(announced, "the re-invite is announced");
    close(&runtime).await;
}

/// A Welcome whose deadline passed while the app was closed, with nothing
/// else owed, is announced as soon as the worker starts: the startup pass
/// records the expiry and the worker publishes its `InviteDeliveryChanged`
/// with no startup wave to settle. A later start reads it recorded and
/// queues no notice, so one held back until some later turn would be lost
/// to a stop before that turn (mdk#3589).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expiry_recorded_at_startup_is_announced_with_no_wave() {
    let dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let Alice {
        app,
        account,
        relay,
        runtime,
        ..
    } = alice_with_groups(&dir, []).await;
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    runtime.publish_key_package("bob").await.unwrap();
    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let group = runtime
        .create_group(
            "alice",
            "expired while closed",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    close(&runtime).await;
    pass_welcome_deadlines(&dir);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = crate::MarmotAppRuntime::new(app);
    let mut events = runtime.subscribe();
    let sent_before = gift_wraps_published(&relay);
    let (entered, release) = hold_after_startup_pass(&account.account_id_hex);
    let reconciled = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.reconcile_accounts().await }
    });
    timeout(SETTLE, entered.notified())
        .await
        .expect("the worker runs its startup pass");
    let mut announced = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let MarmotAppEvent::InviteDeliveryChanged { delivery, .. } = event
            && delivery.group_id_hex == hex::encode(group.as_slice())
        {
            announced.push(delivery.state);
        }
    }
    release.notify_one();
    reconciled.await.unwrap().unwrap();
    assert!(
        matches!(
            announced.as_slice(),
            [cgka_traits::maintenance::WelcomeDeliveryState::Undeliverable { .. }]
        ),
        "announced before the worker's first turn: {announced:?}"
    );
    assert_eq!(gift_wraps_published(&relay), sent_before);
    close(&runtime).await;
}
