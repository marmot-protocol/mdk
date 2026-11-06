//! The runner host over a real account: a directly owned client's in-place
//! pass, a spawned runner's stop, a repair caller's cancel and deadline, and
//! the chokepoints that wake the account's runner.

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
use super::super::{PassBound, RecoveryRunnerPolicy, RepairEnd, RunnerHost, UnitKey};
use super::{
    AccountRunner, AccountRunnerHost, RunnerSeat, RunnerTurn, SpawnedRunner, serve_repair,
};
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
    let app = app.with_recovery_runner_ownership_for_test(gate);
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

/// Read through the real account host's debt turn, then publish the production
/// survey to the same status watch the runner uses. No relay work is scripted.
async fn restart_goal_survey(client: &mut AppClient) -> super::super::select::Survey {
    let counts = client.recovery_runner_live_counts().await.counts;
    let AccountRunner {
        runner, mut turns, ..
    } = client.build_recovery_runner().await;
    let host = runner.host.clone();
    let surveyed = tokio::spawn(async move {
        let result = host
            .debt_turn(move |turn| {
                let turn = super::super::DebtTurn {
                    live_counts: &counts,
                    ..*turn
                };
                assert!(
                    super::super::admission::live_fences(&turn)
                        .unwrap()
                        .is_empty(),
                    "restart debt and an empty live count never fence"
                );
                super::super::select::survey(
                    &turn,
                    &RecoveryRunnerPolicy::default(),
                    &super::super::admission::Stalled::default(),
                )
            })
            .await
            .expect("the debt turn was served")
            .expect("route preparation and survey succeeded");
        host.surveyed(result.catching_up.clone());
        result
    });
    turns.recv().await.unwrap().serve(client).await;
    surveyed.await.unwrap()
}

/// One real debt turn on `client`: the fences it answers, as release points.
async fn debt_turn_fences(client: &mut AppClient) -> Vec<u64> {
    let AccountRunner {
        runner, mut turns, ..
    } = client.build_recovery_runner().await;
    let host = runner.host.clone();
    let fenced = tokio::spawn(async move {
        host.debt_turn(super::super::admission::live_fences)
            .await
            .expect("the debt turn was served")
            .expect("the fences were read")
    });
    turns.recv().await.unwrap().serve(client).await;
    let fences = fenced.await.unwrap();
    fences
        .into_iter()
        .map(|fence| fence.release_before)
        .collect()
}

/// The runner's debt turns age the ledger out of the retention window, as
/// grant settlement did before the runner owned debt: a capture its relay
/// never answered, older than the window, joins its route's parked remainder
/// and fences nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_debt_turn_parks_a_capture_older_than_the_retention_window() {
    use crate::client::recovery_coverage::scenario_tests::fixture_on;
    let Fixture {
        mut client,
        storage,
        _dir,
        _pump,
        ..
    } = fixture_on(
        vec!["wss://a.example".into()],
        true,
        None,
        Some(Duration::from_secs(120)),
    )
    .await;
    let ledger = storage.app_storage();
    let route = group_routes(&client).pop().unwrap();
    let relay = transport_nostr::canonical_relay("wss://a.example");
    let now = unix_now_seconds();
    let aged = storage_sqlite::RecoveryCoverageRange {
        since_seconds: now - 32 * DAY,
        until_seconds: now - 31 * DAY,
    };
    ledger
        .widen_recovery_coverage_goals(std::slice::from_ref(&route), aged.since_seconds)
        .unwrap();
    ledger
        .set_recovery_unit_fences(&route, &relay, &[aged])
        .unwrap();

    assert_eq!(debt_turn_fences(&mut client).await, Vec::<u64>::new());
    // Another route's goal may slip a second below the floor while the
    // fixture starts; only this route's parked history is under test.
    let remainders = ledger
        .recovery_coverage_remainders()
        .unwrap()
        .into_iter()
        .filter(|remainder| remainder.route == route)
        .collect::<Vec<_>>();
    let [remainder] = remainders.as_slice() else {
        panic!("one parked remainder, not {}", remainders.len());
    };
    assert_eq!(remainder.range.since_seconds, aged.since_seconds);
    assert!(remainder.range.until_seconds >= aged.until_seconds);
}

/// A cursor-present reopen must owe a group added after cold start on each
/// relay. A quiet replay cannot erase that gap, and only proving both relays
/// clears the group's catching-up status (mdk#2862).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cursor_reopen_owes_each_relays_restart_gap_without_fencing() {
    for fail_open_write in [false, true] {
        cursor_reopen_owes_restart_gap(fail_open_write).await;
    }
}

async fn cursor_reopen_owes_restart_gap(fail_open_write: bool) {
    use crate::client::recovery_coverage::scenario_tests::{fixture_on, reactivate_client};
    let Fixture {
        client,
        storage,
        group,
        _dir,
        _pump,
        relay: _relay,
    } = fixture_on(
        vec!["wss://a.example".into(), "wss://b.example".into()],
        false,
        None,
        Some(Duration::from_secs(120)),
    )
    .await;
    let app = client.app.clone();
    let ledger = storage.app_storage();
    let route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap();
    assert_eq!(route.required.len(), 2);
    let now = unix_now_seconds();
    let last_proof = now - HOUR;
    for relay in &route.required {
        ledger
            .record_recovery_coverage(
                &[RecoveryCoverageSlice {
                    route: &route.route,
                    relay,
                    since_seconds: now - 30 * DAY,
                    until_seconds: last_proof,
                    proof: RecoveryCoverageProof::Comparison,
                }],
                now,
            )
            .unwrap();
    }
    assert_eq!(ledger.recovery_coverage_goal(&route.route).unwrap(), None);
    assert!(client.state.last_transport_timestamp.is_some());
    assert!(
        app.relay_plane
            .subscription_rebuild_since(app.load_state("alice").unwrap().last_transport_timestamp)
            .is_some(),
        "the persisted cursor must select the production incremental REQ path"
    );
    let faults = fail_open_write.then(|| fault_connection(&client));
    if let Some(faults) = &faults {
        faults
            .execute_batch(
                "CREATE TRIGGER fail_open_goal BEFORE INSERT ON account_recovery_coverage_goals
                 BEGIN SELECT RAISE(FAIL, 'open goal write failed'); END;",
            )
            .unwrap();
    }
    drop(client);

    // Open on the existing plane, without network maintenance: the goal must
    // exist before transport activation or any epoch-gap demand can supply it.
    let reopened = app
        .local_client_with_relay_plane("alice", &app.relay_plane, None)
        .await
        .unwrap();
    assert!(reopened.state.last_transport_timestamp.is_some());
    let goal = ledger.recovery_coverage_goal(&route.route).unwrap();
    if let Some(faults) = faults {
        assert_eq!(goal, None, "the failed open write left no group goal");
        faults.execute_batch("DROP TRIGGER fail_open_goal").unwrap();
    } else {
        assert!(
            goal.is_some(),
            "account open must give a cursor-present group's route a goal"
        );
    }
    assert!(
        ledger
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .all(|demand| demand.cause != RecoveryCause::IncrementalHistory),
        "ledger widening must not start the old owner's history job"
    );
    let off = reopened.account_recovery_status().unwrap();
    assert!(off.catching_up_group_ids_hex.is_empty());
    assert!(!off.inbox_catching_up);
    assert!(off.notices.is_empty());

    // A real takeover stops the old account context before installing the
    // new policy; switching an already active adapter is deliberately refused.
    let enabled_app = reopened.app.clone().with_recovery_runner_owning_debt();
    enabled_app
        .relay_plane
        .deactivate_account_context(reopened.adapter.account_id())
        .await
        .unwrap();
    drop(reopened);
    let mut reopened = enabled_app
        .local_client_with_relay_plane("alice", &enabled_app.relay_plane, None)
        .await
        .unwrap();
    reactivate_client(&mut reopened).await;
    let counts = reopened.recovery_runner_live_counts().await.counts;
    let group_counts = counts
        .iter()
        .filter(|count| count.routes.contains(&route.route))
        .collect::<Vec<_>>();
    assert_eq!(
        group_counts.len(),
        2,
        "both relays answered the quiet group"
    );
    assert!(group_counts.iter().all(|count| count.oldest_seen.is_none()));
    for (proved, relay) in route.required.iter().enumerate() {
        let survey = restart_goal_survey(&mut reopened).await;
        let remaining = survey
            .candidates
            .iter()
            .filter(|candidate| candidate.key.route == route.route)
            .collect::<Vec<_>>();
        assert_eq!(remaining.len(), route.required.len() - proved);
        for candidate in remaining {
            assert_eq!(candidate.position, last_proof + 1);
            assert!(!candidate.blocked);
        }
        assert_eq!(
            reopened
                .account_recovery_status()
                .unwrap()
                .catching_up_group_ids_hex,
            [hex::encode(group.as_slice())]
        );
        ledger
            .record_recovery_coverage(
                &[RecoveryCoverageSlice {
                    route: &route.route,
                    relay,
                    since_seconds: last_proof + 1,
                    until_seconds: now + DAY,
                    proof: RecoveryCoverageProof::Comparison,
                }],
                now + DAY,
            )
            .unwrap();
    }
    let survey = restart_goal_survey(&mut reopened).await;
    assert!(
        survey
            .candidates
            .iter()
            .all(|candidate| candidate.key.route != route.route)
    );
    assert!(
        reopened
            .account_recovery_status()
            .unwrap()
            .catching_up_group_ids_hex
            .is_empty()
    );
}

/// A group becoming current during an open account gets a goal before the
/// runner selects work, with no restart or epoch-gap demand (mdk#2862).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_current_route_gets_a_standing_goal_before_the_runner_selects_it() {
    use crate::client::recovery_coverage::scenario_tests::fixture_on;
    let Fixture {
        mut client,
        storage,
        group,
        _dir,
        _pump,
        relay: _relay,
    } = fixture_on(
        vec!["wss://a.example".into()],
        true,
        None,
        Some(Duration::from_secs(120)),
    )
    .await;
    let ledger = storage.app_storage();
    let first_route = group_routes(&client).pop().unwrap();
    restart_goal_survey(&mut client).await;
    let first_goal = ledger.recovery_coverage_goal(&first_route).unwrap();
    assert!(first_goal.is_some());
    let second_group = client
        .create_group("after the first survey", &[])
        .await
        .unwrap();
    let route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(second_group.as_slice()))
        .unwrap()
        .route;
    let before = unix_now_seconds();
    let mut settling_wake = wake(&client);
    let survey = restart_goal_survey(&mut client).await;
    assert!(
        !woken(&mut settling_wake),
        "settling a route change must not wake its own runner"
    );
    let candidate = survey
        .candidates
        .iter()
        .find(|candidate| candidate.key.route == route)
        .expect("a new group's retained history is runnable without an epoch gap");
    assert!(candidate.position <= before);
    let goal = ledger.recovery_coverage_goal(&route).unwrap().unwrap();
    assert!(goal >= before - 30 * DAY);
    assert!(goal <= unix_now_seconds() - 30 * DAY);
    let catching_up = client
        .account_recovery_status()
        .unwrap()
        .catching_up_group_ids_hex;
    assert!(catching_up.contains(&hex::encode(group.as_slice())));
    assert!(catching_up.contains(&hex::encode(second_group.as_slice())));
    assert_eq!(
        ledger.recovery_coverage_goal(&first_route).unwrap(),
        first_goal
    );
    let mut wake = wake(&client);
    restart_goal_survey(&mut client).await;
    assert!(
        !woken(&mut wake),
        "unchanged routes must not keep waking an idle runner"
    );
    assert_eq!(ledger.recovery_coverage_goal(&route).unwrap(), Some(goal));
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
    // A loss owes the last hour: the quiet groups' live REQs, which their
    // relay answered with nothing, already proved it.
    storage
        .uncover_recovery_coverage(&groups, started - HOUR)
        .unwrap();
    let before = storage.recovery_account_usage(started).unwrap().attempts;
    // Fresh service markers make this pass observable even when setup's
    // inbox turn happened in the same wall-clock second.
    fault_connection(&client)
        .execute(
            "UPDATE account_recovery_units SET last_served_at_seconds = NULL",
            [],
        )
        .unwrap();

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

/// Admission writes a command's inventory rows once, after its last ingest
/// and before its settle. A crash between the two leaves an event the
/// account holds, still staged, with no row. The restarted runner admits the
/// staged copy again as held: the event gains its row, staging lets it go,
/// and the window its slice proved stays proven. Nothing is fetched again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_before_the_inventory_write_readmits_the_held_event() {
    use storage_sqlite::{RecoveryCoverageRange, RecoveryStagedSlice};
    let (_dir, _relay, app, mut client) = direct_client(true).await;
    let group = client.create_group("group", &[]).await.unwrap();
    let route = group_routes(&client).remove(0);
    let relay = client
        .recovery_runner_routes()
        .into_iter()
        .find(|candidate| candidate.route == route)
        .unwrap()
        .required[0]
        .clone();
    let storage = app.account_storage("alice").unwrap().app_storage();
    let now = unix_now_seconds();
    cover_inbox(&client, &storage);
    storage
        .record_recovery_coverage(
            &[RecoveryCoverageSlice {
                route: &route,
                relay: &relay,
                since_seconds: 0,
                until_seconds: now + DAY,
                proof: RecoveryCoverageProof::Comparison,
            }],
            now + DAY,
        )
        .unwrap();
    // A group message the plane routed, as a sweep stages it.
    let mut held = super::super::repair::tests::unadmitted(&route, now - 60);
    held.group_id_hint = Some(group);
    let window = RecoveryCoverageRange {
        since_seconds: now - HOUR,
        until_seconds: now,
    };
    storage
        .stage_recovery_slice(
            &RecoveryStagedSlice {
                route: &route,
                relay: &relay,
                events: std::slice::from_ref(&held),
                fetched_bytes: 0,
                covered: &[window],
                proof: RecoveryCoverageProof::SweepSlice,
                mark: storage.recovery_coverage_mark().unwrap(),
            },
            now + DAY,
        )
        .unwrap();
    // The ingest committed and the process died before the command wrote
    // its inventory.
    client.remember_seen_event(hex::encode(held.message.id.as_slice()));
    client
        .save_state_with_pending_local_group_deletion_frontier_clears()
        .unwrap();
    drop(client);
    let inventory = || {
        storage
            .transport_reconciliation_inventory(&route, now + 1)
            .unwrap()
            .items
            .into_iter()
            .map(|item| item.event_id.to_vec())
            .collect::<Vec<_>>()
    };
    let proven = || {
        storage
            .recovery_coverage_ranges(&route, &relay)
            .unwrap()
            .iter()
            .any(|proved| {
                proved.range.since_seconds <= window.since_seconds
                    && proved.range.until_seconds >= window.until_seconds
            })
    };
    assert!(!inventory().contains(&held.message.id.as_slice().to_vec()));
    assert_eq!(storage.staged_recovery_total().unwrap().events, 1);
    assert!(proven());

    let mut client = app.client("alice").await.unwrap();
    client.run_recovery_runner_pass().await.unwrap();
    assert!(
        inventory().contains(&held.message.id.as_slice().to_vec()),
        "the held event gained its row"
    );
    assert_eq!(
        storage.staged_recovery_total().unwrap().events,
        0,
        "staging let the held copy go"
    );
    assert!(proven(), "the slice's window stays proven");
}

/// Bob's app over `dir` on `url`, as one `wn` process opens it.
fn process_app(dir: &std::path::Path, url: &str) -> crate::MarmotApp {
    crate::MarmotApp::with_relay_and_config(
        dir,
        url,
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    )
    .with_recovery_runner_ownership_for_test(true)
}

/// One `wn sync` process: a fresh direct client syncs once and exits.
async fn one_shot_sync(dir: &std::path::Path, url: &str) -> crate::SyncSummary {
    let app = process_app(dir, url);
    let mut client = app.client("bob").await.unwrap();
    assert!(client.has_in_place_recovery_runner());
    let summary = client.sync().await.unwrap();
    drop(client);
    app.relay_plane.shutdown().await;
    summary
}

use crate::tests::limited_relay as published_relay;

/// A one-shot sync, as `wn sync` runs it, shows a message sent just before
/// it. A fresh client owes the gap since its last sync, so its group's live
/// REQ is fenced until its pass answers that gap. This relay publishes no cap
/// and does not compare, so it cannot prove the second the message was sent
/// in: the pass's sweep stops there, its unit is saturated, and the group is
/// let go in the same pass. The frames the fence then releases are that
/// sync's to read. A sync that returned before reading them lost them with
/// its client, and no number of one-shot syncs showed the message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_shot_syncs_read_what_their_pass_released() {
    let (_relay, url) = published_relay::relay_publishing(None).await;
    let bob_dir = tempfile::tempdir().unwrap();
    let bob = crate::AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();
    let app = process_app(bob_dir.path(), &url);
    let mut client = app.client("bob").await.unwrap();
    client.publish_key_package().await.unwrap();
    client.sync().await.unwrap();
    drop(client);
    app.relay_plane.shutdown().await;

    let (_alice_dir, _alice_app, mut alice) = direct_client_on(url.clone(), true).await;
    let group = alice
        .create_group_with_options(
            "one shot",
            &[bob.account_id_hex.as_str()],
            crate::AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let joined = one_shot_sync(bob_dir.path(), &url).await;
    assert_eq!(joined.joined_groups, std::slice::from_ref(&group));

    alice.send(&group, b"seed from alice").await.unwrap();
    let mut shown = Vec::new();
    for _ in 0..3 {
        let synced = one_shot_sync(bob_dir.path(), &url).await;
        shown.push(
            synced
                .messages
                .into_iter()
                .map(|message| message.plaintext)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(
        shown,
        [vec!["seed from alice".to_owned()], Vec::new(), Vec::new()],
        "the first sync after the send shows it, and only that one"
    );
}

async fn serve_goal_future<T>(
    client: &mut AppClient,
    turns: &mut tokio::sync::mpsc::Receiver<RunnerTurn>,
    future: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return result,
            turn = turns.recv() => turn.unwrap().serve(client).await,
        }
    }
}

/// Failed mandatory goal writes must schedule a bounded local retry, retain
/// the prior status, and recover without a new route/receipt wake (#2862).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_route_goal_writes_retry_without_spinning_or_a_new_wake() {
    for failed_steps in [1, 4] {
        failed_route_goal_writes(failed_steps).await;
    }
}

async fn failed_route_goal_writes(failed_steps: usize) {
    use crate::client::recovery_coverage::scenario_tests::fixture_on;
    let Fixture {
        mut client,
        storage,
        _dir,
        _pump,
        relay: _relay,
        ..
    } = fixture_on(
        vec!["wss://a.example".into()],
        true,
        None,
        Some(Duration::from_secs(120)),
    )
    .await;
    let ledger = storage.app_storage();
    restart_goal_survey(&mut client).await;
    let now = unix_now_seconds();
    for route in client.recovery_runner_routes() {
        for relay in route.required.iter().chain(&route.best_effort) {
            ledger
                .record_recovery_coverage(
                    &[RecoveryCoverageSlice {
                        route: &route.route,
                        relay,
                        since_seconds: 0,
                        until_seconds: now + DAY,
                        proof: RecoveryCoverageProof::Comparison,
                    }],
                    now,
                )
                .unwrap();
        }
    }
    let mut account = client.build_recovery_runner().await;
    let group = client
        .create_group("goal write failure", &[])
        .await
        .unwrap();
    let route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap()
        .route;
    let previous_status = client.routing.recovery_runner_catching_up_now();
    let faults = fault_connection(&client);
    faults
        .execute_batch(
            "CREATE TRIGGER fail_route_goal BEFORE INSERT ON account_recovery_coverage_goals
             BEGIN SELECT RAISE(FAIL, 'route goal write failed'); END;",
        )
        .unwrap();
    let mut wake = wake(&client);
    for _ in 0..failed_steps {
        let before = unix_now_seconds();
        let step = serve_goal_future(
            &mut client,
            &mut account.turns,
            Box::pin(account.runner.step()),
        )
        .await;
        let super::super::Step::Idle {
            next_due: Some(due),
        } = step
        else {
            panic!("a failed goal write must schedule a local retry, not report no debt");
        };
        assert!(due > before, "persistent failure must not spin");
        assert!(
            due <= unix_now_seconds() + 60,
            "use the bounded local retry policy"
        );
        assert!(!woken(&mut wake), "failed preparation must not self-wake");
        assert!(client.routing.recovery_runner_catching_up_now() == previous_status);
        assert_eq!(ledger.recovery_coverage_goal(&route).unwrap(), None);
    }
    faults
        .execute_batch("DROP TRIGGER fail_route_goal")
        .unwrap();
    assert!(
        !woken(&mut wake),
        "removing the fault supplied no unrelated wake"
    );
    let host = account.runner.host.clone();
    let survey = serve_goal_future(
        &mut client,
        &mut account.turns,
        host.debt_turn(|turn| {
            super::super::select::survey(
                turn,
                &RecoveryRunnerPolicy::default(),
                &super::super::admission::Stalled::default(),
            )
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        survey
            .candidates
            .iter()
            .any(|candidate| candidate.key.route == route)
    );
    assert!(ledger.recovery_coverage_goal(&route).unwrap().is_some());
    host.surveyed(survey.catching_up);
    assert!(
        client
            .account_recovery_status()
            .unwrap()
            .catching_up_group_ids_hex
            .contains(&hex::encode(group.as_slice()))
    );
}

/// An unavailable stored Welcome is a preparation failure, not proof that
/// the copy has no hint: a broad goal could never narrow after recovery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_welcome_metadata_never_widens_the_goal() {
    use crate::client::recovery_coverage::scenario_tests::fixture_on;
    use cgka_traits::storage::{GroupStorage, StorageError};
    let Fixture {
        mut client,
        storage,
        group,
        _dir,
        _pump,
        relay: _relay,
    } = fixture_on(
        vec!["wss://a.example".into()],
        true,
        None,
        Some(Duration::from_secs(120)),
    )
    .await;
    let ledger = storage.app_storage();
    let route = group_routes(&client).pop().unwrap();
    // Account-owned native ranges now create goals immediately. This fixture
    // starts the route-goal preparation contract with no prior goal.
    fault_connection(&client)
        .execute("DELETE FROM account_recovery_coverage_goals", [])
        .unwrap();
    assert_eq!(ledger.recovery_coverage_goal(&route).unwrap(), None);
    let welcome_at = unix_now_seconds() - 60 * 60;
    let mut record = storage.get_group(&group).unwrap();
    record.local_copy_welcome_created_at = Some(cgka_traits::transport::Timestamp(welcome_at));
    storage.put_group(&record).unwrap();
    let faults = fault_connection(&client);
    faults
        .execute(
            "UPDATE cgka_groups SET record = x'ff' WHERE id = ?1",
            [group.as_slice()],
        )
        .unwrap();
    let mut account = client.build_recovery_runner().await;
    let host = account.runner.host.clone();
    let read_route = route.clone();
    let result = serve_goal_future(
        &mut client,
        &mut account.turns,
        host.debt_turn(move |turn| turn.app.recovery_coverage_goal(&read_route)),
    )
    .await
    .unwrap();
    assert!(
        matches!(result, Err(StorageError::Serialization(_))),
        "unreadable metadata must fail preparation"
    );
    assert_eq!(ledger.recovery_coverage_goal(&route).unwrap(), None);

    let mut wake = wake(&client);
    storage.put_group(&record).unwrap();
    assert!(
        !woken(&mut wake),
        "restoring metadata emits no routing wake"
    );
    let goal = serve_goal_future(
        &mut client,
        &mut account.turns,
        host.debt_turn(move |turn| turn.app.recovery_coverage_goal(&route)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(goal, Some(welcome_at - 15 * 60));
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
    // A loss owes the last hour: the quiet group's live REQ, which its relay
    // answered with nothing, already proved it.
    storage
        .uncover_recovery_coverage(&group_routes(&client), unix_now_seconds() - HOUR)
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

/// Fresh epoch-gap evidence must create durable work even if the route was
/// already swept. A failed handoff retries as one transaction, and polling an
/// unchanged obligation must not erase the replacement proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_epoch_gap_reopens_covered_history_once_and_atomically() {
    use crate::client::recovery_coverage::scenario_tests::{fixture_on, relay, routes};
    let fixture = fixture_on(vec![relay()], true, Some(1), None).await;
    let client = &fixture.client;
    let app = fixture.storage.app_storage();
    let routes = routes(client);
    let group_route = routes
        .iter()
        .find(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .unwrap();
    let now = unix_now_seconds();
    let since = now - 2 * HOUR;
    app.widen_recovery_coverage_goals(std::slice::from_ref(group_route), since)
        .unwrap();
    let relay = relay();
    let cover = || {
        for route in &routes {
            app.record_recovery_coverage(
                &[RecoveryCoverageSlice {
                    route,
                    relay: &relay,
                    since_seconds: since,
                    until_seconds: now,
                    proof: RecoveryCoverageProof::SweepSlice,
                }],
                now,
            )
            .unwrap();
        }
    };
    cover();
    let mut wake = client.routing.recovery_runner_wake().subscribe();
    let intent = StoredEpochBackfillIntent {
        group_id_hex: hex::encode(fixture.group.as_slice()),
        stalled_epoch: 0,
    };
    let faults = fault_connection(client);
    faults
        .execute_batch(
            "CREATE TRIGGER fail_gap_uncover BEFORE INSERT ON account_recovery_coverage_uncovers
        BEGIN SELECT RAISE(ABORT, 'injected epoch-gap uncover'); END;",
        )
        .unwrap();
    match client.arm_epoch_gap_recovery(std::slice::from_ref(&intent)) {
        Err(crate::AppError::Storage(cgka_traits::storage::StorageError::Backend(message))) => {
            assert!(message.contains("injected epoch-gap uncover"));
        }
        other => panic!("expected injected epoch-gap uncover failure, got {other:?}"),
    }
    assert!(
        !app.pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.cause == RecoveryCause::EpochGap)
    );
    assert!(
        app.recovery_coverage_covers(group_route, std::slice::from_ref(&relay), since, now)
            .unwrap()
    );
    assert!(
        !woken(&mut wake),
        "a rolled-back arm does not wake the runner"
    );
    faults
        .execute_batch("DROP TRIGGER fail_gap_uncover")
        .unwrap();
    let prior = app.recovery_coverage_mark().unwrap();
    client
        .arm_epoch_gap_recovery(std::slice::from_ref(&intent))
        .unwrap();
    assert!(woken(&mut wake));
    assert!(
        !app.recovery_coverage_covers(group_route, std::slice::from_ref(&relay), since, now)
            .unwrap()
    );
    assert!(
        app.recovery_coverage_covers(
            &TransportReconciliationRoute::Inbox,
            std::slice::from_ref(&relay),
            since,
            now
        )
        .unwrap()
    );
    assert!(app.recovery_coverage_goal(group_route).unwrap().unwrap() <= since);
    // A quantum already running before the arm cannot certify over it.
    app.record_recovery_coverage_since(
        &[RecoveryCoverageSlice {
            route: group_route,
            relay: &relay,
            since_seconds: since,
            until_seconds: now,
            proof: RecoveryCoverageProof::SweepSlice,
        }],
        now,
        prior,
    )
    .unwrap();
    assert!(
        !app.recovery_coverage_covers(group_route, std::slice::from_ref(&relay), since, now)
            .unwrap()
    );
    cover();
    let mark = app.recovery_coverage_mark().unwrap();
    client
        .arm_epoch_gap_recovery(std::slice::from_ref(&intent))
        .unwrap();
    assert_eq!(app.recovery_coverage_mark().unwrap(), mark);
    assert!(!woken(&mut wake));
    assert!(
        app.recovery_coverage_covers(group_route, std::slice::from_ref(&relay), since, now)
            .unwrap()
    );
    let newer = StoredEpochBackfillIntent {
        stalled_epoch: 1,
        ..intent
    };
    client.arm_epoch_gap_recovery(&[newer]).unwrap();
    assert!(woken(&mut wake));
    assert!(
        !app.recovery_coverage_covers(group_route, std::slice::from_ref(&relay), since, now)
            .unwrap()
    );
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
    client.settle_recovery_route_changes(&storage, now).unwrap();

    // Emptied while it may be waiting to hydrate, then back.
    client.routing.replace_group_routes(&group, Vec::new());
    client.settle_recovery_route_changes(&storage, now).unwrap();
    client
        .routing
        .replace_group_routes(&group, installed.clone());
    client.settle_recovery_route_changes(&storage, now).unwrap();
    assert!(matches!(state(&storage), RecoveryUnitState::Broken(_)));

    // Dropped and restored within one command.
    let mut moved = installed.clone();
    moved[0].endpoints = vec![TransportEndpoint("wss://other.example".to_owned())];
    client.routing.replace_group_routes(&group, moved.clone());
    client
        .routing
        .replace_group_routes(&group, installed.clone());
    client.settle_recovery_route_changes(&storage, now).unwrap();
    assert!(matches!(state(&storage), RecoveryUnitState::Broken(_)));
    assert_eq!(storage.parked_recovery_routes().unwrap().len(), 1);

    // Dropped for good: the group's route goes on without the relay.
    client.routing.replace_group_routes(&group, moved);
    client.settle_recovery_route_changes(&storage, now).unwrap();
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
    client.settle_recovery_route_changes(&storage, now).unwrap();
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

/// A repair whose request settles well past its deadline, as an interrupted
/// one may for its grace, ends on the deadline: its caller never trips the
/// stop that only a cancel may, so it is not `Cancelled`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_past_its_deadline_is_never_cancelled_by_its_caller() {
    let (_dir, _relay, _app, mut client) = direct_client(false).await;
    let bound = PassBound::within(Duration::from_millis(100));
    let (_sender, mut turns) = tokio::sync::mpsc::channel::<RunnerTurn>(1);
    let ends = bound.clone();
    let repair = async move {
        tokio::time::sleep_until(ends.deadline + Duration::from_millis(400)).await;
        Some(if ends.stop.is_cancelled() {
            RepairEnd::Cancelled
        } else {
            RepairEnd::Deadline
        })
    };
    let served = serve_repair(&mut client, repair, &mut turns, &bound, &|| false).await;
    assert!(served.answered);
    assert!(matches!(served.end, RepairEnd::Deadline));
    assert!(!bound.stop.is_cancelled());
}

/// A cancel that comes as the runner reads its verdict, before the caller
/// trips the stop, as a spawned runner's may on another thread, still ends
/// the repair `Cancelled`: the caller decides that first, as today's path
/// does, over the covered window the runner answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_during_the_verdict_beats_the_covered_window_the_runner_answered() {
    let (_dir, _relay, _app, mut client) = direct_client(false).await;
    let bound = PassBound::within(Duration::from_secs(60));
    let (_sender, mut turns) = tokio::sync::mpsc::channel::<RunnerTurn>(1);
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let repair = async {
        // The verdict turn: covered, with the stop not yet tripped.
        cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        Some(RepairEnd::Covered)
    };
    let served = serve_repair(&mut client, repair, &mut turns, &bound, &|| {
        cancelled.load(std::sync::atomic::Ordering::SeqCst)
    })
    .await;
    assert!(served.answered);
    assert!(matches!(served.end, RepairEnd::Cancelled));
}

/// A cancel that comes after the deadline armed the caller's backstop still
/// trips the stop, so the runner's quantum in flight is preempted then, and
/// the repair is `Cancelled`, not the `Deadline` the runner would answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_after_the_deadline_armed_the_backstop_still_preempts() {
    let (_dir, _relay, _app, mut client) = direct_client(false).await;
    let bound = PassBound::within(Duration::ZERO);
    let (_sender, mut turns) = tokio::sync::mpsc::channel::<RunnerTurn>(1);
    let ends = bound.clone();
    let repair = async move {
        // Runs on past its deadline, as a quantum in its interrupt grace may,
        // until the stop or well inside the backstop.
        tokio::select! {
            () = ends.stop.cancelled() => Some(RepairEnd::Cancelled),
            () = tokio::time::sleep(Duration::from_millis(600)) => Some(RepairEnd::Deadline),
        }
    };
    let cancel_at = tokio::time::Instant::now() + Duration::from_millis(150);
    let served = serve_repair(&mut client, repair, &mut turns, &bound, &|| {
        tokio::time::Instant::now() >= cancel_at
    })
    .await;
    assert!(bound.stop.is_cancelled(), "the late cancel trips the stop");
    assert!(served.answered);
    assert!(matches!(served.end, RepairEnd::Cancelled));
}

/// A runner whose turns come back to back, each waiting for the last, as
/// admission's do, keeps its caller's turn arm ready; its cancel is still
/// seen, and the runner ends on the stop it trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_of_turns_never_starves_a_repairs_cancel() {
    let (_dir, _relay, _app, mut client) = direct_client(false).await;
    let bound = PassBound::within(Duration::from_secs(60));
    let (sender, mut turns) = tokio::sync::mpsc::channel(1);
    let stop = bound.stop.clone();
    let repair = async move {
        while !stop.is_cancelled() {
            let (done, served) = tokio::sync::oneshot::channel();
            let turn = RunnerTurn {
                run: Box::new(move |_| {
                    Box::pin(async move {
                        let _ = done.send(());
                    })
                }),
                ingests: false,
            };
            if sender.send(turn).await.is_err() || served.await.is_err() {
                return None;
            }
        }
        Some(RepairEnd::Cancelled)
    };
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let served = tokio::time::timeout(Duration::from_secs(10), async {
        cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        serve_repair(&mut client, repair, &mut turns, &bound, &|| {
            cancelled.load(std::sync::atomic::Ordering::SeqCst)
        })
        .await
    })
    .await
    .expect("the cancel is seen between turns");
    assert!(served.answered);
    assert!(matches!(served.end, RepairEnd::Cancelled));
}

/// The app hands loss to durable debt before releasing the plane's cursor
/// fence. A failure after plane acknowledgment restores that fence and rolls
/// back both causes' reclamation; retry never certifies the missing history.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runner_loss_handoff_restores_the_guard_after_reclaim_failure() {
    use crate::client::recovery_coverage::scenario_tests::fixture_on;
    use storage_sqlite::RecoveryLossCause;
    let Fixture {
        mut client,
        storage,
        _dir,
        _pump,
        relay: _relay,
        ..
    } = fixture_on(
        vec!["wss://a.example".into()],
        true,
        None,
        Some(Duration::from_secs(120)),
    )
    .await;
    let app = storage.app_storage();
    assert!(!app.recovery_conversion_pending().unwrap());
    let route = group_routes(&client).pop().unwrap();
    let since = unix_now_seconds() - 100;
    for (cause, token, count) in [
        (RecoveryLossCause::Queue, 77, 2),
        (RecoveryLossCause::NotificationConsumer, 78, 0),
    ] {
        app.record_account_recovery_loss_routed(
            "alice",
            cause,
            token,
            count,
            unix_now_seconds(),
            Some(since),
            Some(&[(route.clone(), since)]),
        )
        .unwrap();
    }
    client.synchronize_recovery_loss(&app).unwrap();
    assert_eq!(app.converted_recovery_loss().unwrap().len(), 2);
    assert!(
        app.pending_recovery_demands()
            .unwrap()
            .iter()
            .all(|demand| !matches!(
                demand.cause,
                RecoveryCause::QueueLoss
                    | RecoveryCause::NotificationLoss
                    | RecoveryCause::SubscriptionReplay
                    | RecoveryCause::IncrementalHistory
                    | RecoveryCause::ExplicitHistory
            ))
    );
    // Same durable-marker adoption boundary the plane uses on reopen.
    client.adapter.start_delivery_overflow_recovery(77);
    assert!(client.adapter.delivery_loss_blocks_cursor());
    let faults = fault_connection(&client);
    faults
        .execute_batch(
            "CREATE TRIGGER fail_runner_loss_reclaim BEFORE DELETE ON
        account_delivery_loss_evidence WHEN OLD.cause = 1
        BEGIN SELECT RAISE(ABORT, 'injected runner loss reclaim'); END;",
        )
        .unwrap();
    match client.finish_runner_loss_import() {
        Err(crate::AppError::Storage(cgka_traits::storage::StorageError::Backend(message))) => {
            assert!(message.contains("injected runner loss reclaim"))
        }
        other => panic!("expected injected runner loss reclaim failure, got {other:?}"),
    }
    assert!(
        client.delivery_loss_blocks_cursor(),
        "failed reclaim restores the guard"
    );
    assert!(
        client
            .adapter
            .pending_delivery_overflow_generation()
            .is_some()
    );
    assert_eq!(
        app.converted_recovery_loss().unwrap().len(),
        2,
        "the earlier cause's reclamation rolls back too"
    );
    assert_eq!(
        app.recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
            .unwrap()
            .len(),
        1
    );
    faults
        .execute_batch("DROP TRIGGER fail_runner_loss_reclaim")
        .unwrap();
    assert!(client.finish_runner_loss_import().unwrap());
    assert!(!client.delivery_loss_blocks_cursor());
    assert!(app.converted_recovery_loss().unwrap().is_empty());
    for cause in [
        RecoveryLossCause::Queue,
        RecoveryLossCause::NotificationConsumer,
    ] {
        assert!(
            app.recovery_loss_watermarks("alice", cause)
                .unwrap()
                .is_empty()
        );
    }
    assert!(app.recovery_coverage_goal(&route).unwrap().unwrap() <= since);
    assert!(
        app.recovery_coverage_ranges(&route, "wss://a.example")
            .unwrap()
            .is_empty(),
        "handoff is debt, never recovered coverage"
    );
}
