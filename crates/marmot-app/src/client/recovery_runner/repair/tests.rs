//! Explicit repair through the account's runner, a directly owned client's
//! in-place one or a worker's spawned one, with today's verdicts: a re-arm at
//! a step boundary, then passes until the window is covered
//! (`BelowRetentionWindow`), the runner can serve nothing (`CoverageUnproven`),
//! the budget ends (`Deadline`) or the caller stops waiting (`Cancelled`).
//! With the gate off the repair keeps today's path.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nostr_relay_builder::prelude::{BoxedFuture, Filter as RelayFilter, PolicyResult, QueryPolicy};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use storage_sqlite::{
    RecoveryCoverageProof, RecoveryCoverageRange, RecoveryCoverageSlice, RecoveryStagedSlice,
    RecoveryUnitOutcome, RecoveryUnitState, SqliteAppStorage, TransportReconciliationRoute,
};

use super::super::RecoveryRunnerPolicy;
use super::super::host::SpawnedRunner;
use crate::client::AppClient;
use crate::{AppError, FullHistoryRepairIncompleteReason as Reason, unix_now_seconds};

const DAY: u64 = 24 * 60 * 60;

/// What a relay does with a bounded history request (a sweep's slice carries
/// `until`, a live REQ does not).
#[derive(Clone, Debug, Default)]
struct Sweeps {
    /// Hold it until released, and say when one arrives.
    hold: bool,
    /// Hold only the first one, say when it arrives, and refuse it once
    /// released.
    refuse_first: bool,
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    /// Requests held so far.
    held: Arc<std::sync::atomic::AtomicUsize>,
}

impl QueryPolicy for Sweeps {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a std::net::SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if query.until.is_none() || query.ids.is_some() {
                return PolicyResult::Accept;
            }
            if self.refuse_first {
                if self.held.fetch_add(1, Ordering::SeqCst) > 0 {
                    return PolicyResult::Accept;
                }
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                self.reached.notify_one();
                released.await;
                return PolicyResult::Reject("restricted: held for the test".to_owned());
            }
            if self.hold {
                self.held.fetch_add(1, Ordering::SeqCst);
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

/// One account with one group on a local relay whose sweeps `sweeps`
/// governs, its client opened directly with the gate as given.
async fn client(
    sweeps: &Sweeps,
    gate: bool,
) -> (
    tempfile::TempDir,
    LocalRelay,
    AppClient,
    SqliteAppStorage,
    TransportReconciliationRoute,
) {
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(sweeps.clone()));
    relay.run().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        relay.url().await.to_string(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    let app = if gate {
        app.with_recovery_runner_owning_debt()
    } else {
        app
    };
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("repair", &[]).await.unwrap();
    let route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap()
        .route;
    let storage = app.account_storage("alice").unwrap().app_storage();
    (dir, relay, client, storage, route)
}

fn reason(result: Result<crate::SyncSummary, crate::ClassifiedSyncFailure>) -> Reason {
    match result.map_err(|failure| failure.source) {
        Err(AppError::FullHistoryRepairIncomplete { reason, .. }) => reason,
        other => panic!("an incomplete repair, not {other:?}"),
    }
}

fn charged(storage: &SqliteAppStorage) -> u64 {
    storage
        .recovery_account_usage(unix_now_seconds())
        .unwrap()
        .attempts
}

/// The inbox owes nothing on its relays, so only the group's debt runs.
fn cover_inbox(client: &AppClient, storage: &SqliteAppStorage) {
    let now = unix_now_seconds();
    for route in client
        .recovery_runner_routes()
        .into_iter()
        .filter(|route| route.route == TransportReconciliationRoute::Inbox)
    {
        for relay in &route.required {
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

/// A repair re-arms a parked route, so its notice goes, then serves the
/// whole retained window: covered on every relay, it ends below the window,
/// as today, never in success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_re_arms_and_covers_the_window_then_ends_below_it() {
    let sweeps = Sweeps::default();
    let (_dir, _relay, mut client, storage, route) = client(&sweeps, true).await;
    assert!(client.repairs_through_runner(None));
    let relay = client
        .recovery_runner_routes()
        .into_iter()
        .find(|candidate| candidate.route == route)
        .unwrap()
        .required
        .remove(0);
    let now = unix_now_seconds();
    storage
        .begin_recovery_unit_attempt(&route, &relay, None, now)
        .unwrap();
    storage
        .settle_recovery_unit(
            &route,
            &relay,
            RecoveryUnitOutcome::Refused,
            &RecoveryRunnerPolicy::default().unit,
            now,
        )
        .unwrap();
    assert_eq!(client.history_notices().unwrap().len(), 1);

    let result = client
        .repair_full_history_cancellable(&|| false, None)
        .await;
    assert_eq!(reason(result), Reason::BelowRetentionWindow);
    assert!(client.history_notices().unwrap().is_empty());
    let floor = unix_now_seconds() - storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS;
    for candidate in client.recovery_runner_routes() {
        for relay in &candidate.required {
            assert_eq!(
                storage
                    .recovery_unit(&candidate.route, relay)
                    .unwrap()
                    .unwrap()
                    .state,
                RecoveryUnitState::Active
            );
            assert!(
                storage
                    .recovery_coverage_goal(&candidate.route)
                    .unwrap()
                    .is_some_and(|goal| goal <= floor + 60),
                "the goal reaches the retention floor"
            );
        }
    }
}

/// A unit backing off after an answer without progress is served at once: a
/// repair re-arms it too, rather than ending unproven before it retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_serves_a_unit_that_was_backing_off() {
    let (_dir, _relay, mut client, storage, route) = client(&Sweeps::default(), true).await;
    let relay = client
        .recovery_runner_routes()
        .into_iter()
        .find(|candidate| candidate.route == route)
        .unwrap()
        .required
        .remove(0);
    let now = unix_now_seconds();
    storage
        .begin_recovery_unit_attempt(&route, &relay, None, now)
        .unwrap();
    let backing_off = storage
        .settle_recovery_unit(
            &route,
            &relay,
            RecoveryUnitOutcome::NoProgress,
            &RecoveryRunnerPolicy::default().unit,
            now,
        )
        .unwrap();
    assert!(backing_off.next_attempt_at_seconds > now);

    let result = client
        .repair_full_history_cancellable(&|| false, None)
        .await;
    assert_eq!(reason(result), Reason::BelowRetentionWindow);
}

/// A unit that broke during the repair leaves its parked spans out of its
/// debt; that is never a covered window. Here the inbox's relay refused it,
/// as one that will not compare does, while the group is covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_inbox_is_never_a_covered_window() {
    let (_dir, _relay, client, storage, route) = client(&Sweeps::default(), true).await;
    let now = unix_now_seconds();
    let routes = client.recovery_runner_routes();
    storage
        .widen_recovery_coverage_goals(
            &routes
                .iter()
                .map(|route| route.route.clone())
                .collect::<Vec<_>>(),
            now - DAY,
        )
        .unwrap();
    for candidate in &routes {
        for relay in &candidate.required {
            if candidate.route == route {
                storage
                    .record_recovery_coverage(
                        &[RecoveryCoverageSlice {
                            route: &candidate.route,
                            relay,
                            since_seconds: 0,
                            until_seconds: now + DAY,
                            proof: RecoveryCoverageProof::Comparison,
                        }],
                        now + DAY,
                    )
                    .unwrap();
            } else {
                storage
                    .begin_recovery_unit_attempt(&candidate.route, relay, None, now)
                    .unwrap();
                storage
                    .settle_recovery_unit(
                        &candidate.route,
                        relay,
                        RecoveryUnitOutcome::Refused,
                        &RecoveryRunnerPolicy::default().unit,
                        now,
                    )
                    .unwrap();
                assert!(
                    storage
                        .recovery_unit_debt(&candidate.route, relay, now)
                        .unwrap()
                        .is_empty(),
                    "its parked spans are out of its debt"
                );
            }
        }
    }
    assert!(
        routes
            .iter()
            .any(|candidate| candidate.route == TransportReconciliationRoute::Inbox)
    );
    assert!(!client.repaired_window(&storage, now).await.unwrap());
}

/// Staging covers what a sweep fetched before the engine admits it. An event
/// the engine kept no trace of stays staged, so its route is no covered
/// window however much the ledger proves, as today's repair does not
/// certify a window with unadmitted work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unadmitted_staged_event_is_never_a_covered_window() {
    let (_dir, _relay, client, storage, route) = client(&Sweeps::default(), true).await;
    let now = unix_now_seconds();
    let routes = client.recovery_runner_routes();
    storage
        .widen_recovery_coverage_goals(
            &routes
                .iter()
                .map(|route| route.route.clone())
                .collect::<Vec<_>>(),
            now - DAY,
        )
        .unwrap();
    for candidate in &routes {
        for relay in &candidate.required {
            storage
                .record_recovery_coverage(
                    &[RecoveryCoverageSlice {
                        route: &candidate.route,
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
    assert!(client.repaired_window(&storage, now).await.unwrap());

    let relay = routes
        .iter()
        .find(|candidate| candidate.route == route)
        .unwrap()
        .required[0]
        .clone();
    let staged = storage
        .stage_recovery_slice(
            &RecoveryStagedSlice {
                route: &route,
                relay: &relay,
                events: &[unadmitted(&route, now - 60)],
                fetched_bytes: 0,
                covered: &[RecoveryCoverageRange {
                    since_seconds: now - DAY,
                    until_seconds: now,
                }],
                proof: RecoveryCoverageProof::SweepSlice,
                mark: storage.recovery_coverage_mark().unwrap(),
            },
            now + DAY,
        )
        .unwrap();
    assert_eq!(staged.staged, 1);
    assert!(
        storage
            .recovery_unit_debt(&route, &relay, now)
            .unwrap()
            .is_empty(),
        "the ledger covers the staged second"
    );
    assert!(!client.repaired_window(&storage, now).await.unwrap());
}

/// A group message on `route` the engine has never seen.
fn unadmitted(route: &TransportReconciliationRoute, at: u64) -> cgka_traits::TransportDelivery {
    use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
    let TransportReconciliationRoute::Group(transport_group_id) = route else {
        panic!("a group route");
    };
    let at = Timestamp(at);
    let source = TransportSource("nostr".to_owned());
    cgka_traits::TransportDelivery {
        account_id: cgka_traits::MemberId::new(vec![1; 32]),
        group_id_hint: None,
        message: TransportMessage {
            id: cgka_traits::MessageId::new(vec![9; 32]),
            payload: vec![9; 32],
            timestamp: at,
            causal_deps: Vec::new(),
            source: source.clone(),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: transport_group_id.to_vec(),
            },
        },
        received_at: at,
        source: cgka_traits::TransportDeliverySource {
            transport: source,
            plane: cgka_traits::TransportDeliveryPlane::Group,
            endpoint: None,
            subscription_id: Some("recovery".to_owned()),
            wire: None,
        },
    }
}

/// With its relay gone the runner can serve nothing: the first pass finds
/// the relay unreachable, and the next serves nothing while it cools down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_the_runner_cannot_serve_is_coverage_unproven() {
    let (_dir, relay, mut client, _, _) = client(&Sweeps::default(), true).await;
    relay.shutdown();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        client.repair_full_history_cancellable(&|| false, None),
    )
    .await
    .expect("the repair ends within its budget");
    assert_eq!(reason(result), Reason::CoverageUnproven);
}

/// The caller stops waiting mid-quantum: the repair is cancelled, and the
/// runner ends it on its stop, so the held request is interrupted and its
/// quantum settles unanswered, giving its attempt back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_repair_gives_its_open_attempt_back() {
    let sweeps = Sweeps {
        hold: true,
        ..Sweeps::default()
    };
    let (_dir, _relay, mut client, storage, _) = client(&sweeps, true).await;
    cover_inbox(&client, &storage);
    let before = charged(&storage);
    let stop = Arc::new(AtomicBool::new(false));
    let held = {
        let (sweeps, stop) = (sweeps.clone(), stop.clone());
        tokio::spawn(async move {
            sweeps.reached.notified().await;
            stop.store(true, Ordering::SeqCst);
        })
    };
    let cancelled = || stop.load(Ordering::SeqCst);
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        client.repair_full_history_cancellable(&cancelled, None),
    )
    .await
    .expect("a cancelled repair returns");
    held.await.unwrap();
    assert_eq!(reason(result), Reason::Cancelled);
    assert_eq!(charged(&storage), before, "the open attempt was given back");
    sweeps.release.notify_waiters();
}

/// The budget ends while a sweep waits on its relay: the deadline, not an
/// unproven verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_whose_budget_ends_mid_quantum_meets_its_deadline() {
    let sweeps = Sweeps {
        hold: true,
        ..Sweeps::default()
    };
    let (_dir, _relay, mut client, storage, _) = client(&sweeps, true).await;
    cover_inbox(&client, &storage);
    let result = client
        .repair_full_history_through_runner(&|| false, Duration::from_secs(2), None)
        .await;
    assert_eq!(reason(result), Reason::Deadline);
    sweeps.release.notify_waiters();
}

/// The worker's runner takes a repair only once its own step ends. One waiting
/// on a credit that other accounts hold still leaves the repair to its
/// budget: the deadline, never a wait past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_behind_a_step_waiting_on_a_credit_meets_its_deadline() {
    use crate::runtime::account_worker::recovery_credits::{
        hold_all_credits_for_test, private_recovery_credit_pool_for_test,
    };
    let (_dir, _relay, mut client, storage, route) = client(&Sweeps::default(), true).await;
    cover_inbox(&client, &storage);
    storage
        .widen_recovery_coverage_goals(std::slice::from_ref(&route), unix_now_seconds() - DAY)
        .unwrap();
    client.recovery_credits = private_recovery_credit_pool_for_test();
    let _held = hold_all_credits_for_test(&client.recovery_credits);
    let mut spawned = client.spawn_recovery_runner().await.unwrap();
    // Its turns until it waits on a credit, after which it sends none.
    while let Ok(turn) = tokio::time::timeout(Duration::from_millis(500), spawned.next_turn()).await
    {
        turn.serve(&mut client).await;
    }

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        client.repair_full_history_through_runner(
            &|| false,
            Duration::from_secs(2),
            Some(&mut spawned),
        ),
    )
    .await
    .expect("the repair keeps to its budget");
    assert_eq!(reason(result), Reason::Deadline);
    spawned.stop(&mut client).await;
}

/// Serve `spawned`'s turns on `client` until nothing arrives for a while,
/// and return how many of its requests the relay held meanwhile.
async fn serve_until_quiet(
    client: &mut AppClient,
    spawned: &mut SpawnedRunner,
    sweeps: &Sweeps,
) -> usize {
    while let Ok(turn) = tokio::time::timeout(Duration::from_millis(500), spawned.next_turn()).await
    {
        turn.serve(client).await;
    }
    sweeps.held.load(Ordering::SeqCst)
}

/// A worker repair cancelled mid-quantum ends its pass before it answers:
/// the held request is interrupted and its quantum settles on a turn the
/// caller serves, so its attempt is back once the repair returns. The runner
/// is not shut down; it answers the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_worker_repair_settles_its_quantum_before_it_answers() {
    let sweeps = Sweeps {
        hold: true,
        ..Sweeps::default()
    };
    let (_dir, _relay, mut client, storage, _) = client(&sweeps, true).await;
    cover_inbox(&client, &storage);
    let mut spawned = client.spawn_recovery_runner().await.unwrap();
    assert_eq!(
        serve_until_quiet(&mut client, &mut spawned, &sweeps).await,
        0,
        "nothing is owed before the repair"
    );
    let before = charged(&storage);
    let stop = Arc::new(AtomicBool::new(false));
    let held = {
        let (sweeps, stop) = (sweeps.clone(), stop.clone());
        tokio::spawn(async move {
            sweeps.reached.notified().await;
            stop.store(true, Ordering::SeqCst);
        })
    };
    let cancelled = || stop.load(Ordering::SeqCst);
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        client.repair_full_history_through_runner(
            &cancelled,
            Duration::from_secs(60),
            Some(&mut spawned),
        ),
    )
    .await
    .expect("a cancelled repair returns");
    held.await.unwrap();
    assert_eq!(reason(result), Reason::Cancelled);
    assert_eq!(
        charged(&storage),
        before,
        "the held request settled before the repair answered"
    );

    let handle = spawned.handle().clone();
    let pass = handle.run_pass(Duration::from_secs(1));
    tokio::pin!(pass);
    let report = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                biased;
                report = &mut pass => break report,
                turn = spawned.next_turn() => turn.serve(&mut client).await,
            }
        }
    })
    .await
    .expect("the runner answers a pass");
    assert!(report.is_some(), "the runner was not shut down");
    sweeps.release.notify_waiters();
    spawned.stop(&mut client).await;
}

/// A worker repair requested while the runner's own quantum waits on its
/// relay re-arms only once that quantum has settled. Here the relay refuses
/// the held request, parking the unit; a re-arm before that settle would be
/// undone by it, and the repair could not serve the unit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_repair_re_arms_after_the_quantum_in_flight_settles() {
    let sweeps = Sweeps {
        refuse_first: true,
        ..Sweeps::default()
    };
    let (_dir, _relay, mut client, storage, route) = client(&sweeps, true).await;
    cover_inbox(&client, &storage);
    storage
        .widen_recovery_coverage_goals(std::slice::from_ref(&route), unix_now_seconds() - DAY)
        .unwrap();
    let relay = client
        .recovery_runner_routes()
        .into_iter()
        .find(|candidate| candidate.route == route)
        .unwrap()
        .required
        .remove(0);
    let mut spawned = client.spawn_recovery_runner().await.unwrap();
    let reached = sweeps.reached.notified();
    tokio::pin!(reached);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                biased;
                () = &mut reached => break,
                turn = spawned.next_turn() => turn.serve(&mut client).await,
            }
        }
    })
    .await
    .expect("the runner's own quantum reaches the relay");
    let release = {
        let sweeps = sweeps.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sweeps.release.notify_waiters();
        })
    };
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        client.repair_full_history_through_runner(
            &|| false,
            Duration::from_secs(30),
            Some(&mut spawned),
        ),
    )
    .await
    .expect("the repair ends within its budget");
    release.await.unwrap();
    assert_eq!(reason(result), Reason::BelowRetentionWindow);
    assert_eq!(
        storage
            .recovery_unit(&route, &relay)
            .unwrap()
            .unwrap()
            .state,
        RecoveryUnitState::Active
    );
    spawned.stop(&mut client).await;
}

/// A caller already cancelled re-arms nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_cancelled_before_it_starts_re_arms_nothing() {
    let (_dir, _relay, mut client, storage, _) = client(&Sweeps::default(), true).await;
    let units = storage.recovery_units().unwrap().len();
    let result = client.repair_full_history_cancellable(&|| true, None).await;
    assert_eq!(reason(result), Reason::Cancelled);
    assert_eq!(storage.recovery_units().unwrap().len(), units);
}

/// With the gate off a repair keeps today's path: no runner, no re-arm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_with_the_gate_off_runs_no_runner() {
    let (_dir, _relay, mut client, storage, _) = client(&Sweeps::default(), false).await;
    assert!(!client.repairs_through_runner(None));
    let _ = client
        .repair_full_history_cancellable(&|| false, None)
        .await;
    assert!(storage.recovery_units().unwrap().is_empty());
}
