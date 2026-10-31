//! The runner host over a real account: a directly owned client's in-place
//! pass, a spawned runner's stop, and the chokepoints that wake the account's
//! runner.

use cgka_traits::engine::GroupEvent;
use cgka_traits::storage::MessageStorage;
use nostr_relay_builder::prelude::{BoxedFuture, Filter as RelayFilter, PolicyResult, QueryPolicy};
use nostr_relay_builder::{LocalRelay, MockRelay, RelayBuilder};
use std::sync::Arc;
use std::time::Duration;
use storage_sqlite::{
    RecoveryCause, RecoveryCoverageProof, RecoveryCoverageSlice, RecoveryUnitOutcome,
    SqliteAppStorage, StoredEpochBackfillIntent, TransportReconciliationRoute,
};
use tokio::sync::watch;

use super::super::RecoveryRunner;
use super::super::open_attempts::AttemptKind;
use super::super::{RecoveryRunnerPolicy, RunnerHost, UnitKey};
use super::{AccountRunner, AccountRunnerHost, RunnerSeat, SpawnedRunner};
use crate::client::AppClient;
use crate::client::audit_recovery::recorded_v5_rows;
use crate::client::history_notices::park_recovery_for_test;
use crate::client::recovery_coverage::scenario_tests::{Fixture, fixture};
use crate::unix_now_seconds;

const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;

/// One account on a real relay, its client opened directly, with the
/// internal gate as given.
async fn direct_client(gate: bool) -> (tempfile::TempDir, MockRelay, crate::MarmotApp, AppClient) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let (dir, app, client) = direct_client_on(url, gate).await;
    (dir, relay, app, client)
}

async fn direct_client_on(
    url: String,
    gate: bool,
) -> (tempfile::TempDir, crate::MarmotApp, AppClient) {
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        url,
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    let app = if gate {
        app.with_recovery_runner_owning_debt()
    } else {
        app
    };
    let client = app.client("alice").await.unwrap();
    (dir, app, client)
}

/// Holds every bounded history request (a sweep's slice carries `until`, a
/// live REQ does not) until released, and says when one arrives.
#[derive(Clone, Debug, Default)]
struct HeldSweeps {
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl QueryPolicy for HeldSweeps {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a std::net::SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if query.until.is_some() && query.ids.is_none() {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                self.reached.notify_one();
                released.await;
            }
            PolicyResult::Accept
        })
    }
}

fn group_routes(client: &AppClient) -> Vec<TransportReconciliationRoute> {
    client
        .recovery_runner_routes()
        .into_iter()
        .map(|route| route.route)
        .filter(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .collect()
}

/// The inbox owes nothing on its relays, so only the groups' debt runs.
fn cover_inbox(client: &AppClient, storage: &SqliteAppStorage) {
    let now = unix_now_seconds();
    for route in client
        .recovery_runner_routes()
        .into_iter()
        .filter(|route| route.route == TransportReconciliationRoute::Inbox)
    {
        for relay in route.required.iter().chain(&route.best_effort) {
            storage
                .record_recovery_coverage(
                    &[RecoveryCoverageSlice {
                        route: &route.route,
                        relay,
                        since_seconds: 0,
                        until_seconds: now + DAY,
                        proof: RecoveryCoverageProof::Comparison,
                    }],
                    now + DAY,
                )
                .unwrap();
        }
    }
}

fn passes(client: &AppClient) -> u32 {
    match &client.recovery_runner {
        RunnerSeat::InPlace(seat) => seat.as_ref().as_ref().map_or(0, |seat| seat.passes),
        RunnerSeat::Absent => 0,
    }
}

/// A subscriber to the account's runner wake, with what it has seen marked.
fn wake(client: &AppClient) -> watch::Receiver<u64> {
    let mut wake = client.routing.recovery_runner_wake().subscribe();
    wake.borrow_and_update();
    wake
}

fn woken(wake: &mut watch::Receiver<u64>) -> bool {
    let changed = wake.has_changed().unwrap();
    wake.borrow_and_update();
    changed
}

/// With the gate off, a directly owned client runs no runner and its sync
/// passes nothing to one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_client_runs_no_runner_with_the_gate_off() {
    let (_dir, _relay, _app, mut client) = direct_client(false).await;
    assert!(!client.has_in_place_recovery_runner());
    client.sync().await.unwrap();
    assert!(client.run_recovery_runner_pass().await.is_none());
    assert!(matches!(client.recovery_runner, RunnerSeat::Absent));
}

/// With the gate on, an explicit sync runs one pass in place, and the pass
/// serves each unit due then once: two groups that each owe the last hour
/// are each swept once over the account's own relay pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_clients_pass_serves_each_due_unit_once() {
    let (_dir, _relay, app, mut client) = direct_client(true).await;
    assert!(client.has_in_place_recovery_runner());
    client.sync().await.unwrap();
    assert_eq!(passes(&client), 1, "an explicit sync runs one pass");

    client.create_group("first", &[]).await.unwrap();
    client.create_group("second", &[]).await.unwrap();
    let groups = group_routes(&client);
    assert_eq!(groups.len(), 2);
    let storage = app.account_storage("alice").unwrap().app_storage();
    let started = unix_now_seconds();
    storage
        .widen_recovery_coverage_goals(&groups, started - HOUR)
        .unwrap();
    let before = storage.recovery_account_usage(started).unwrap().attempts;

    let report = client.run_recovery_runner_pass().await.unwrap();
    let served = storage
        .recovery_units()
        .unwrap()
        .into_iter()
        .filter(|unit| unit.last_served_at_seconds.is_some_and(|at| at >= started))
        .collect::<Vec<_>>();
    for group in &groups {
        assert!(
            served.iter().any(|unit| &unit.route == group),
            "each group's unit was served"
        );
    }
    assert_eq!(usize::try_from(report.quanta).unwrap(), served.len());
    assert_eq!(
        storage
            .recovery_account_usage(unix_now_seconds())
            .unwrap()
            .attempts
            - before,
        u64::from(report.quanta),
        "no unit ran twice"
    );
    assert!(report.advanced >= 2, "each group's empty hour was proved");
    assert_eq!(passes(&client), 2);
}

/// With the gate on, a directly owned client's `next_event()` runs one pass
/// in place when it meets delivery loss, after the recovery it already runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_clients_next_event_runs_a_pass_on_delivery_loss() {
    let (_dir, _relay, _app, mut client) = direct_client(true).await;
    client.sync().await.unwrap();
    assert_eq!(passes(&client), 1);
    client.discard_spilled_deliveries(&[]).unwrap();
    // Nothing surfaces, so `next_event()` keeps waiting after the pass.
    let waited = tokio::time::timeout(std::time::Duration::from_secs(5), client.next_event()).await;
    assert!(waited.is_err(), "the loss surfaces no event");
    assert_eq!(passes(&client), 2, "the loss runs one pass");
}

/// A direct client with the gate on and one group owing the last hour, on a
/// relay whose sweeps `hold` holds.
async fn held_client(
    hold: &HeldSweeps,
) -> (tempfile::TempDir, LocalRelay, AppClient, SqliteAppStorage) {
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(hold.clone()));
    relay.run().await.unwrap();
    let (dir, app, mut client) = direct_client_on(relay.url().await.to_string(), true).await;
    client.create_group("held", &[]).await.unwrap();
    let storage = app.account_storage("alice").unwrap().app_storage();
    storage
        .widen_recovery_coverage_goals(&group_routes(&client), unix_now_seconds() - HOUR)
        .unwrap();
    cover_inbox(&client, &storage);
    (dir, relay, client, storage)
}

/// The attempts charged to the account's rolling hour.
fn charged(storage: &SqliteAppStorage) -> u64 {
    storage
        .recovery_account_usage(unix_now_seconds())
        .unwrap()
        .attempts
}

/// Serve a spawned runner's turns until its sweep waits on the relay.
async fn serve_until_held(runner: &mut SpawnedRunner, client: &mut AppClient, hold: &HeldSweeps) {
    loop {
        tokio::select! {
            () = hold.reached.notified() => break,
            turn = runner.next_turn() => turn.serve(client).await,
        }
    }
}

/// Stopping a spawned runner settles the quantum it preempted on the account's
/// client: the sweep held at the relay ends unanswered, which gives its
/// attempt back to the account's hour.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_runner_settles_the_quantum_it_preempted() {
    let hold = HeldSweeps::default();
    let (_dir, _relay, mut client, storage) = held_client(&hold).await;
    let before = charged(&storage);
    let mut runner = client.spawn_recovery_runner().await.unwrap();
    serve_until_held(&mut runner, &mut client, &hold).await;
    assert_eq!(charged(&storage), before + 1, "the quantum began");

    runner.stop(&mut client).await;
    assert_eq!(charged(&storage), before, "the preempted quantum settled");
    hold.release.notify_waiters();
}

/// A second connection to the account's database, only to inject write
/// faults.
fn fault_connection(client: &AppClient) -> rusqlite::Connection {
    let app = &client.app;
    let label = &client.state.label;
    let path = app.account_storage_path(label);
    let keys = app.account_home().load_signing_keys(label).unwrap();
    let key = app
        .sqlcipher_key(label, &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// A settle the stop serves whose write fails leaves its attempt open, so the
/// stop still refunds it once the runner can send no more turns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_refunds_an_attempt_whose_settle_failed() {
    let hold = HeldSweeps::default();
    let (_dir, _relay, mut client, storage) = held_client(&hold).await;
    let before = charged(&storage);
    let mut runner = client.spawn_recovery_runner().await.unwrap();
    serve_until_held(&mut runner, &mut client, &hold).await;
    assert_eq!(charged(&storage), before + 1, "the quantum began");

    // The stop's first part, by hand: the preempted quantum's settle is
    // served and fails.
    let faults = fault_connection(&client);
    faults
        .execute_batch(
            "CREATE TRIGGER fail_settle BEFORE UPDATE OF attempt_minute ON account_recovery_units
             WHEN NEW.attempt_minute IS NULL BEGIN SELECT RAISE(ABORT, 'settle fault'); END;",
        )
        .unwrap();
    runner.handle.shutdown();
    while !runner.task.is_finished() {
        tokio::select! {
            turn = runner.next_turn() => SpawnedRunner::serve_stopping(turn, &mut client).await,
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert_eq!(charged(&storage), before + 1, "the failed settle kept it");
    assert!(!runner._refund.open.is_empty(), "its attempt stays open");

    faults.execute_batch("DROP TRIGGER fail_settle;").unwrap();
    runner.stop(&mut client).await;
    assert_eq!(charged(&storage), before, "the stop refunded it");
    hold.release.notify_waiters();
}

/// The account's runner, never spawned, with one attempt on `key` begun as
/// its begin turn begins one, owned as the worker owns a runner whose task
/// still waits on its relay. Returns it with the runner, which holds the
/// host its turns go through.
async fn begun_runner(
    client: &AppClient,
    storage: &SqliteAppStorage,
    key: &UnitKey,
) -> (SpawnedRunner, RecoveryRunner<AccountRunnerHost>) {
    let AccountRunner {
        runner,
        handle,
        turns,
        refund,
    } = client.build_recovery_runner().await;
    storage
        .begin_recovery_unit_attempt(&key.route, &key.relay, None, unix_now_seconds())
        .unwrap();
    runner.open_attempts().begun(key, AttemptKind::Debt);
    let spawned = SpawnedRunner {
        handle,
        task: tokio::spawn(std::future::pending()),
        turns,
        _refund: refund,
    };
    (spawned, runner)
}

/// A runner turn's audit sink records into the account's own v5 recorder,
/// which takes the breaker's row as written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runner_turn_records_into_the_accounts_audit() {
    let relay = MockRelay::run().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        relay.url().await.to_string(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    )
    .with_recovery_runner_owning_debt();
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    let mut client = app.client("alice").await.unwrap();
    let AccountRunner {
        runner, mut turns, ..
    } = client.build_recovery_runner().await;
    let host = runner.host.clone();
    let recorded = tokio::spawn(async move {
        host.turn(|turn| {
            (turn.audit)(marmot_forensics::AuditEventKind::RecoveryRunnerPaused {
                cap: marmot_forensics::RecoveryRunnerCap::Attempts,
                attempts: 120,
                event_bytes: 4096,
                paused_for_secs: 1_800,
                pauses: 1,
                late_findings: 0,
            });
        })
        .await
    });
    turns.recv().await.unwrap().serve(&mut client).await;
    recorded.await.unwrap().expect("the turn was served");

    let rows = recorded_v5_rows(&app, "recovery_runner_paused");
    assert_eq!(rows.len(), 1);
    let event = &rows[0]["event"];
    assert_eq!(
        (&event["cap"], &event["attempts"], &event["paused_for_secs"]),
        (&"attempts".into(), &120.into(), &1_800.into())
    );
    assert!(rows[0]["group_ref"].is_null());
}

/// A deadline the stop has already passed.
fn passed() -> tokio::time::Instant {
    tokio::time::Instant::now() - Duration::from_secs(1)
}

/// A stop whose wait ends before the preempted quantum's settle comes, as
/// when its relay is slow to honour the cancel and the quantum still waits
/// out its grace, refunds the attempt as unanswered: the charge goes back and
/// the relay gets no verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_whose_settle_never_comes_refunds_the_attempt() {
    const RELAY: &str = "wss://slow.example";
    let (_dir, _relay, app, mut client) = direct_client(true).await;
    let storage = app.account_storage("alice").unwrap().app_storage();
    let route = TransportReconciliationRoute::Group([9; 32]);
    let key = UnitKey {
        route: route.clone(),
        relay: RELAY.to_owned(),
    };
    let before = charged(&storage);
    let (spawned, _runner) = begun_runner(&client, &storage, &key).await;
    assert_eq!(charged(&storage), before + 1, "the quantum began");

    spawned.stop(&mut client).await;
    assert_eq!(charged(&storage), before, "the stop refunded the attempt");
    let health = storage.recovery_relay_health(RELAY).unwrap().unwrap();
    assert_eq!((health.unreachable_streak, health.cooldown), (0, None));
}

/// A settle the runner sent by the stop's deadline is still served after the
/// deadline: its verdict, not a refund, decides the charge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settle_sent_by_the_stops_deadline_beats_the_refund() {
    const RELAY: &str = "wss://settled.example";
    let (_dir, _relay, app, mut client) = direct_client(true).await;
    let storage = app.account_storage("alice").unwrap().app_storage();
    let route = TransportReconciliationRoute::Group([9; 32]);
    let key = UnitKey {
        route: route.clone(),
        relay: RELAY.to_owned(),
    };
    let (spawned, runner) = begun_runner(&client, &storage, &key).await;
    let before = charged(&storage);

    // Its settle, sent and waiting: an answer without progress keeps the
    // charge and backs the unit off.
    let open = runner.open_attempts();
    let host = runner.host.clone();
    let settle = tokio::spawn(async move {
        host.turn(move |turn| {
            open.settled(&key);
            turn.app.settle_recovery_unit(
                &key.route,
                &key.relay,
                RecoveryUnitOutcome::NoProgress,
                &RecoveryRunnerPolicy::default().unit,
                turn.now,
            )
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while spawned.turns.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the settle is sent");

    spawned.stop_by(&mut client, passed()).await;
    assert!(
        matches!(settle.await.unwrap(), Some(Ok(_))),
        "the settle was served"
    );
    assert_eq!(charged(&storage), before, "its verdict kept the charge");
    let unit = storage.recovery_unit(&route, RELAY).unwrap().unwrap();
    assert_eq!(unit.backoff_step, 1, "and backed the unit off");
}

/// A directly owned client's pass dropped mid-quantum refunds the attempt it
/// began, and leaves the seat for the next pass to build a runner in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_in_place_pass_refunds_its_attempt() {
    let hold = HeldSweeps::default();
    let (_dir, _relay, mut client, storage) = held_client(&hold).await;
    let before = charged(&storage);
    let mut pass = Box::pin(client.run_recovery_runner_pass());
    tokio::select! {
        () = hold.reached.notified() => {}
        _ = &mut pass => panic!("the pass ended before its sweep reached the relay"),
    }
    assert_eq!(charged(&storage), before + 1, "the pass began a quantum");

    drop(pass);
    assert_eq!(charged(&storage), before, "the dropped pass refunded it");
    assert!(matches!(&client.recovery_runner, RunnerSeat::InPlace(seat) if seat.is_none()));
    hold.release.notify_waiters();
}

/// An idle connected account's in-place passes charge nothing: the live
/// boundaries prove its history and its live tails are not owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_clients_pass_never_charges_an_idle_connected_account() {
    let Fixture {
        mut client,
        storage,
        _dir,
        _pump,
        ..
    } = fixture().await;
    let app = storage.app_storage();
    let groups = group_routes(&client);
    assert!(!groups.is_empty());
    app.widen_recovery_coverage_goals(&groups, unix_now_seconds() - DAY)
        .unwrap();
    client.seat_in_place().await;
    for _ in 0..2 {
        let report = client.run_recovery_runner_pass().await.unwrap();
        assert_eq!(report.quanta, 0);
    }
    assert_eq!(
        app.recovery_account_usage(unix_now_seconds())
            .unwrap()
            .attempts,
        0
    );
}

/// Each chokepoint that can change the account's debt or what the runner may
/// serve wakes it: loss import, goal widening, a route change, a released
/// receipt, a dismissal and a group lifecycle change. Reinstalling the same
/// routes does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_chokepoint_wakes_the_runner() {
    let Fixture {
        mut client,
        storage,
        group,
        _dir,
        _pump,
        ..
    } = fixture().await;
    let app: SqliteAppStorage = storage.app_storage();
    let mut wake = wake(&client);

    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    client.synchronize_recovery_loss(&app).unwrap();
    assert!(woken(&mut wake), "loss import");

    client.record_coverage_request(RecoveryCause::ExplicitHistory);
    assert!(woken(&mut wake), "goal widening");

    client.routing.replace(client.routing.snapshot());
    assert!(!woken(&mut wake), "the same routes change nothing");
    let routes = client
        .routing
        .snapshot()
        .group_routes
        .into_iter()
        .filter(|route| route.group_id == group)
        .collect::<Vec<_>>();
    client.routing.replace_group_routes(&group, Vec::new());
    assert!(woken(&mut wake), "a route removed");
    client.routing.replace_group_routes(&group, routes);
    assert!(woken(&mut wake), "a route added");

    let record = cgka_traits::MessageRecord {
        id: cgka_traits::MessageId::new(vec![0xfb; 32]),
        group_id: group.clone(),
        epoch: cgka_traits::EpochId(0),
        state: cgka_traits::MessageState::PeelDeferred,
        payload: Vec::new(),
        deferred_peel: None,
    };
    storage.put_message(&record).unwrap();
    storage.release_message_for_replay(&record).unwrap();
    assert_eq!(
        client
            .reconcile_released_transport_receipts()
            .unwrap()
            .len(),
        1
    );
    assert!(woken(&mut wake), "a released receipt");
    assert!(
        client
            .reconcile_released_transport_receipts()
            .unwrap()
            .is_empty()
    );
    assert!(!woken(&mut wake), "no release, no wake");

    client.observe_recovery_evidence(&marmot_session::AccountDeviceEffects {
        events: vec![GroupEvent::GroupUnrecoverable {
            group_id: group.clone(),
        }],
        ..Default::default()
    });
    assert!(woken(&mut wake), "a group lifecycle change");
    client.observe_recovery_evidence(&marmot_session::AccountDeviceEffects {
        events: vec![GroupEvent::EpochChanged {
            group_id: group.clone(),
            from: cgka_traits::EpochId(1),
            to: cgka_traits::EpochId(2),
        }],
        ..Default::default()
    });
    assert!(
        !woken(&mut wake),
        "an epoch change is not a lifecycle change"
    );

    let epoch = client.group_mls_state(&group).unwrap().epoch;
    app.arm_epoch_backfill_intents(&[StoredEpochBackfillIntent {
        group_id_hex: hex::encode(group.as_slice()),
        stalled_epoch: epoch,
    }])
    .unwrap();
    let gap = app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.cause == RecoveryCause::EpochGap)
        .unwrap()
        .ticket
        .id;
    park_recovery_for_test(&storage, gap);
    let notice = client
        .history_notices()
        .unwrap()
        .into_iter()
        .find(|notice| notice.group_id_hex.is_some())
        .unwrap();
    woken(&mut wake);
    assert!(client.dismiss_history_notice(&notice.notice_id).unwrap());
    assert!(woken(&mut wake), "a dismissal");
}

/// A relay a group's own route replacement drops retires as route gone at
/// the runner's next debt turn, once the turn confirms it: the group still
/// has a route that no longer lists the relay. A group emptied for a while,
/// or a drop restored before the turn, retires nothing. A relay that comes
/// back owes the whole goal again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_dropped_from_its_route_retires_once_confirmed() {
    use cgka_traits::TransportEndpoint;
    use storage_sqlite::{RecoverySpanRetirement, RecoveryUnitState};
    let (_dir, _relay, app, mut client) = direct_client(true).await;
    let group = client.create_group("gone", &[]).await.unwrap();
    let storage = app.account_storage("alice").unwrap().app_storage();
    let installed = client
        .routing
        .snapshot()
        .group_routes
        .into_iter()
        .filter(|route| route.group_id == group)
        .collect::<Vec<_>>();
    let runner_route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap();
    let (route, relay) = (runner_route.route, runner_route.required[0].clone());
    let now = unix_now_seconds();
    storage
        .widen_recovery_coverage_goals(std::slice::from_ref(&route), now - HOUR)
        .unwrap();
    let policy = RecoveryRunnerPolicy::default().unit;
    for _ in 0..policy.break_after_no_progress {
        storage
            .begin_recovery_unit_attempt(&route, &relay, None, now)
            .unwrap();
        storage
            .settle_recovery_unit(
                &route,
                &relay,
                RecoveryUnitOutcome::NoProgress,
                &policy,
                now,
            )
            .unwrap();
    }
    let state = |storage: &SqliteAppStorage| {
        storage
            .recovery_unit(&route, &relay)
            .unwrap()
            .unwrap()
            .state
    };
    assert!(matches!(state(&storage), RecoveryUnitState::Broken(_)));
    client.settle_recovery_route_changes(&storage, now);

    // Emptied while it may be waiting to hydrate, then back.
    client.routing.replace_group_routes(&group, Vec::new());
    client.settle_recovery_route_changes(&storage, now);
    client
        .routing
        .replace_group_routes(&group, installed.clone());
    client.settle_recovery_route_changes(&storage, now);
    assert!(matches!(state(&storage), RecoveryUnitState::Broken(_)));

    // Dropped and restored within one command.
    let mut moved = installed.clone();
    moved[0].endpoints = vec![TransportEndpoint("wss://other.example".to_owned())];
    client.routing.replace_group_routes(&group, moved.clone());
    client
        .routing
        .replace_group_routes(&group, installed.clone());
    client.settle_recovery_route_changes(&storage, now);
    assert!(matches!(state(&storage), RecoveryUnitState::Broken(_)));
    assert_eq!(storage.parked_recovery_routes().unwrap().len(), 1);

    // Dropped for good: the group's route goes on without the relay.
    client.routing.replace_group_routes(&group, moved);
    client.settle_recovery_route_changes(&storage, now);
    assert_eq!(state(&storage), RecoveryUnitState::Retired);
    assert!(
        storage
            .recovery_unit_spans(&route, &relay)
            .unwrap()
            .iter()
            .all(|span| span.retired == Some(RecoverySpanRetirement::RouteGone))
    );
    assert!(storage.parked_recovery_routes().unwrap().is_empty());
    assert!(
        storage
            .recovery_unit_debt(&route, &relay, now)
            .unwrap()
            .is_empty()
    );

    // Back on the route: it owes the whole goal again.
    client.routing.replace_group_routes(&group, installed);
    client.settle_recovery_route_changes(&storage, now);
    assert_eq!(state(&storage), RecoveryUnitState::Active);
    assert!(
        storage
            .recovery_unit_spans(&route, &relay)
            .unwrap()
            .is_empty()
    );
    assert!(
        !storage
            .recovery_unit_debt(&route, &relay, now)
            .unwrap()
            .is_empty()
    );
}

/// With the gate off no runner tracks route changes, so nothing is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_route_changes_are_kept_with_the_gate_off() {
    let (_dir, _relay, _app, mut client) = direct_client(false).await;
    let group = client.create_group("untracked", &[]).await.unwrap();
    client.routing.replace_group_routes(&group, Vec::new());
    assert!(client.routing.take_route_changes().is_none());
}
