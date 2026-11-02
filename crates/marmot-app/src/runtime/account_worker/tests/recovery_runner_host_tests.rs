//! The account worker runs its recovery runner only with the internal
//! `runner_owns_debt` gate on: the runner spawns with the worker, serves the
//! account's debt over its own relay pool, answers a pass, stops with
//! `shutdown_and_close` even while a quantum waits on its relay, gives a
//! preempted quantum's attempt back across a reconnect, serves an explicit
//! repair, one queued during startup too, and announces what it catches up,
//! across a reconnect too. With the gate off nothing spawns and nothing is
//! announced.

use super::*;
use crate::runtime::account_worker::recovery_credits::{MAX_CONCURRENT_JOBS, available_credits};
use nostr_relay_builder::prelude::{
    BoxedFuture, Filter as RelayFilter, PolicyResult, QueryPolicy, SingleLetterTag,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use storage_sqlite::TransportReconciliationRoute;

const HOUR: u64 = 60 * 60;
const SETTLE: Duration = Duration::from_secs(30);

/// Holds every bounded history request for the armed group route until
/// released: a sweep's slice carries `until`, a live REQ does not.
#[derive(Clone, Debug, Default)]
struct HeldSweep {
    route: Arc<Mutex<Option<String>>>,
    release: Arc<tokio::sync::Notify>,
    /// The earliest `since` a held request asked from.
    oldest_since: Arc<AtomicU64>,
    /// Requests it has held.
    held: Arc<AtomicUsize>,
}

impl HeldSweep {
    fn arm(&self, route: &str) {
        self.oldest_since.store(u64::MAX, Ordering::SeqCst);
        *self.route.lock().unwrap() = Some(route.to_owned());
    }

    fn release(&self) {
        *self.route.lock().unwrap() = None;
        self.release.notify_waiters();
    }
}

struct ReleaseOnDrop(HeldSweep);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl QueryPolicy for HeldSweep {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a std::net::SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let released = self.release.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            let held = self.route.lock().unwrap().as_ref().is_some_and(|route| {
                query.until.is_some()
                    && query.ids.is_none()
                    && query
                        .generic_tags
                        .get(&SingleLetterTag::from_char('h').expect("h is a valid tag"))
                        .is_some_and(|values| values.contains(route))
            });
            if held {
                let since = query.since.map_or(0, |since| since.as_secs());
                self.oldest_since.fetch_min(since, Ordering::SeqCst);
                self.held.fetch_add(1, Ordering::SeqCst);
                released.await;
            }
            PolicyResult::Accept
        })
    }
}

/// One account with one group on `url`, whose route owes the last hour, and
/// the runtime that serves it with the gate as given.
struct GatedWorker {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    runtime: super::super::super::MarmotAppRuntime,
    label: String,
    route: TransportReconciliationRoute,
    route_hex: String,
    group: GroupId,
    credits: Arc<super::super::recovery_credits::RecoveryCreditPool>,
}

impl GatedWorker {
    async fn start(url: &str, gate: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let config =
            crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
        let app = MarmotApp::with_relay_and_config(dir.path(), url.to_owned(), config.clone());
        let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        let group = runtime
            .create_group_with_options(
                &account.label,
                "runner host",
                &[],
                AppCreateGroupOptions {
                    relays: Some(vec![url.to_owned()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let route_hex = app
            .group(&account.label, &hex::encode(&group))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex;
        let route = TransportReconciliationRoute::Group(
            hex::decode(&route_hex).unwrap().try_into().unwrap(),
        );
        runtime.shutdown_and_close().await.unwrap();

        // A closed runtime closes its app; the next one opens its own.
        let app = MarmotApp::with_relay_and_config(dir.path(), url.to_owned(), config);
        app.account_storage(&account.label)
            .unwrap()
            .app_storage()
            .widen_recovery_coverage_goals(
                std::slice::from_ref(&route),
                crate::unix_now_seconds() - HOUR,
            )
            .unwrap();
        let app = if gate {
            app.with_recovery_runner_owning_debt()
        } else {
            app
        };
        let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
        let credits = runtime
            .shared_services()
            .use_private_recovery_credit_pool_for_test();
        runtime.reconcile_accounts().await.unwrap();
        Self {
            _dir: dir,
            app,
            runtime,
            label: account.label,
            route,
            route_hex,
            group,
            credits,
        }
    }

    /// Lose the group route's last day, as a loss import would.
    fn lose_a_day(&self) {
        self.app
            .account_storage(&self.label)
            .unwrap()
            .app_storage()
            .uncover_recovery_coverage(
                std::slice::from_ref(&self.route),
                crate::unix_now_seconds() - 24 * HOUR,
            )
            .unwrap();
    }

    fn group_hex(&self) -> String {
        hex::encode(self.group.as_slice())
    }

    /// When the runner last began a quantum on the group's unit, if ever.
    fn served_at(&self) -> Option<u64> {
        self.app
            .account_storage(&self.label)
            .unwrap()
            .app_storage()
            .recovery_units()
            .unwrap()
            .into_iter()
            .filter(|unit| unit.route == self.route)
            .filter_map(|unit| unit.last_served_at_seconds)
            .max()
    }

    async fn served_after(&self, at: u64) {
        timeout(SETTLE, async {
            while self.served_at().is_none_or(|served| served < at) {
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the runner serves the group's debt");
    }

    /// Ask the worker's runner for one pass, off the worker.
    async fn pass(&self) -> oneshot::Receiver<Option<crate::client::recovery_runner::PassReport>> {
        let (respond, report) = oneshot::channel();
        self.runtime
            .accounts()
            .worker_commands(&self.label)
            .await
            .unwrap()
            .send(AccountWorkerCommand::RecoveryRunnerPassForTest {
                budget: Duration::from_secs(10),
                respond,
            })
            .await
            .unwrap();
        report
    }
}

/// With the gate off the worker spawns no runner: a pass finds none, the
/// group's owed hour is never served by one, lost history announces no
/// recovery status, and the status shows nothing catching up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_spawns_no_runner_with_the_gate_off() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let worker = GatedWorker::start(&url, false).await;
    let mut events = worker.runtime.subscribe();
    timeout(SETTLE, worker.runtime.catch_up_accounts())
        .await
        .unwrap()
        .unwrap();
    assert!(worker.pass().await.await.unwrap().is_none());
    assert!(worker.served_at().is_none());
    worker.lose_a_day();
    assert!(worker.pass().await.await.unwrap().is_none());
    assert_eq!(
        worker
            .runtime
            .account_recovery_status(&worker.label)
            .await
            .unwrap(),
        crate::AccountRecoveryStatus::default()
    );
    worker.runtime.shutdown_and_close().await.unwrap();
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, MarmotAppEvent::RecoveryStatusChanged { .. }),
            "no status is announced with the gate off"
        );
    }
}

/// With the gate on the runner's survey is the account's recovery status:
/// lost history puts the group in it, announced once per change, and once
/// served it leaves again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_workers_runner_announces_what_it_catches_up() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let hold = HeldSweep::default();
    let _release = ReleaseOnDrop(hold.clone());
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(hold.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let started = crate::unix_now_seconds();
    let worker = GatedWorker::start(&url, true).await;
    worker.served_after(started).await;
    timeout(SETTLE, worker.pass().await).await.unwrap().unwrap();
    let group_hex = worker.group_hex();
    let status = || async {
        worker
            .runtime
            .account_recovery_status(&worker.label)
            .await
            .unwrap()
    };
    let mut events = worker.runtime.subscribe();

    // Lose a day whose sweep the relay holds, and ask for the pass that
    // finds it: the group is catching up.
    hold.arm(&worker.route_hex);
    worker.lose_a_day();
    let _pass = worker.pass().await;
    let announced = |events: &mut broadcast::Receiver<MarmotAppEvent>| {
        let mut announced = false;
        while let Ok(event) = events.try_recv() {
            announced |= matches!(event, MarmotAppEvent::RecoveryStatusChanged { .. });
        }
        announced
    };
    timeout(SETTLE, async {
        while !status()
            .await
            .catching_up_group_ids_hex
            .contains(&group_hex)
        {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the group's newly owed day is catching up");
    timeout(SETTLE, async {
        while !announced(&mut events) {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the change is announced");

    hold.release();
    timeout(SETTLE, async {
        while status()
            .await
            .catching_up_group_ids_hex
            .contains(&group_hex)
        {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the served day leaves the status");
    timeout(SETTLE, async {
        while !announced(&mut events) {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("so is its leaving");
    worker.runtime.shutdown_and_close().await.unwrap();
}

/// A reconnect gives the worker a new client, which keeps its own record of
/// what the runner catches up: the new runner's survey is announced too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnected_workers_runner_still_announces_what_it_catches_up() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let hold = HeldSweep::default();
    let _release = ReleaseOnDrop(hold.clone());
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(hold.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let started = crate::unix_now_seconds();
    let worker = GatedWorker::start(&url, true).await;
    worker.served_after(started).await;
    timeout(SETTLE, worker.pass().await).await.unwrap().unwrap();
    let held = |count: usize| {
        let hold = hold.clone();
        async move {
            timeout(SETTLE, async {
                while hold.held.load(Ordering::SeqCst) < count {
                    sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("a sweep of the owed day reaches the relay");
        }
    };

    // Lose a day whose sweep the relay holds: the runner, stuck in that
    // quantum, surveys no more once the change is announced.
    hold.arm(&worker.route_hex);
    worker.lose_a_day();
    let mut events = worker.runtime.subscribe();
    let _pass = worker.pass().await;
    held(1).await;
    let announced = |events: &mut broadcast::Receiver<MarmotAppEvent>| {
        let mut announced = false;
        while let Ok(event) = events.try_recv() {
            announced |= matches!(event, MarmotAppEvent::RecoveryStatusChanged { .. });
        }
        announced
    };
    timeout(SETTLE, async {
        while !announced(&mut events) {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the change is announced");

    // The reconnect's client starts knowing nothing; its runner's first
    // survey finds the day still owed, and that is announced.
    worker
        .runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    held(2).await;
    timeout(SETTLE, async {
        while !announced(&mut events) {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the new runner's survey is announced");
    let group_hex = worker.group_hex();
    assert!(
        worker
            .runtime
            .account_recovery_status(&worker.label)
            .await
            .unwrap()
            .catching_up_group_ids_hex
            .contains(&group_hex)
    );
    hold.release();
    timeout(SETTLE, worker.runtime.shutdown_and_close())
        .await
        .unwrap()
        .unwrap();
}

/// With the gate on an explicit repair runs through the worker's runner,
/// which the worker keeps serving meanwhile: the retained window covered, it
/// ends below it, as today.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_workers_runner_serves_an_explicit_repair() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let started = crate::unix_now_seconds();
    let worker = GatedWorker::start(&url, true).await;
    worker.served_after(started).await;
    let repaired = timeout(
        Duration::from_secs(90),
        worker.runtime.repair_full_history(&worker.label),
    )
    .await
    .expect("the repair ends within its budget");
    assert_eq!(
        repaired.unwrap_err().full_history_repair_incomplete(),
        Some((
            crate::FullHistoryRepairIncompleteReason::BelowRetentionWindow,
            false
        ))
    );
    let floor = crate::unix_now_seconds() - storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS;
    assert!(
        worker
            .app
            .account_storage(&worker.label)
            .unwrap()
            .app_storage()
            .recovery_coverage_goal(&worker.route)
            .unwrap()
            .is_some_and(|goal| goal <= floor + 60),
        "the repair owed the whole retained window"
    );
    worker.runtime.shutdown_and_close().await.unwrap();
}

/// A repair queued while the worker's initial catch-up runs replays after it
/// through the worker's runner, spawned before the replay: it re-arms the
/// group's retired unit, which today's comparison job would leave retired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_queued_during_startup_goes_through_the_runner() {
    use crate::client::recovery_runner::RecoveryRunnerPolicy;
    use storage_sqlite::{RecoveryUnitOutcome, RecoveryUnitState};

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let started = crate::unix_now_seconds();
    let worker = GatedWorker::start(&url, true).await;
    worker.served_after(started).await;
    worker.runtime.shutdown_and_close().await.unwrap();

    // Retire the group's unit, as a dismissed notice does.
    let app = MarmotApp::with_relay_and_config(
        worker._dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    )
    .with_recovery_runner_owning_debt();
    let storage = app.account_storage(&worker.label).unwrap().app_storage();
    let relay_url = storage
        .recovery_units()
        .unwrap()
        .into_iter()
        .find(|unit| unit.route == worker.route)
        .expect("the first run served the group")
        .relay;
    let now = crate::unix_now_seconds();
    storage
        .begin_recovery_unit_attempt(&worker.route, &relay_url, None, now)
        .unwrap();
    storage
        .settle_recovery_unit(
            &worker.route,
            &relay_url,
            RecoveryUnitOutcome::Refused,
            &RecoveryRunnerPolicy::default().unit,
            now,
        )
        .unwrap();
    let revision = storage
        .parked_recovery_routes()
        .unwrap()
        .into_iter()
        .find(|parked| parked.route == worker.route)
        .unwrap()
        .revision;
    assert!(
        storage
            .dismiss_recovery_route_park(&worker.route, revision)
            .unwrap()
    );
    let state = || {
        storage
            .recovery_unit(&worker.route, &relay_url)
            .unwrap()
            .unwrap()
            .state
    };
    assert_eq!(state(), RecoveryUnitState::Retired);

    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    let _credits = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    let startup = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_startup_sync_barrier(startup.clone());
    runtime.reconcile_accounts().await.unwrap();
    timeout(SETTLE, startup.wait())
        .await
        .expect("the worker reaches its initial catch-up");
    let commands = runtime
        .accounts()
        .worker_commands(&worker.label)
        .await
        .unwrap();
    let (respond, repaired) = oneshot::channel();
    commands
        .send(AccountWorkerCommand::RepairFullHistory { respond })
        .await
        .unwrap();
    // A snapshot reply proves the repair entered startup replay before it.
    let (respond, snapshot) = oneshot::channel();
    commands
        .send(AccountWorkerCommand::QuarantinedGroups { respond })
        .await
        .unwrap();
    timeout(SETTLE, snapshot).await.unwrap().unwrap().unwrap();
    timeout(SETTLE, startup.wait()).await.unwrap();

    let repaired = timeout(Duration::from_secs(90), repaired)
        .await
        .expect("the repair ends within its budget")
        .unwrap()
        .map_err(crate::AppError::AccountCatchUp);
    assert_eq!(
        repaired.unwrap_err().full_history_repair_incomplete(),
        Some((
            crate::FullHistoryRepairIncompleteReason::BelowRetentionWindow,
            false
        ))
    );
    assert_eq!(
        state(),
        RecoveryUnitState::Active,
        "the runner re-armed the retired unit"
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// With the gate on the worker's runner serves the group's owed hour over the
/// account's relay pool and answers a pass, and every credit it took is back
/// once it has stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_workers_runner_serves_debt_and_answers_a_pass() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let started = crate::unix_now_seconds();
    let worker = GatedWorker::start(&url, true).await;
    worker.served_after(started).await;
    let report = timeout(SETTLE, worker.pass().await)
        .await
        .expect("the pass ends within its budget")
        .unwrap();
    assert!(report.is_some(), "the worker's runner answers a pass");
    worker.runtime.shutdown_and_close().await.unwrap();
    assert_eq!(available_credits(&worker.credits), MAX_CONCURRENT_JOBS);
}

/// `shutdown_and_close` stops the runner while its quantum waits on a relay
/// that never answers: the close returns, the pass waiting on that quantum
/// ends, and the quantum's credit is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_and_close_stops_the_runner_mid_quantum() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let hold = HeldSweep::default();
    let _release = ReleaseOnDrop(hold.clone());
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(hold.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let started = crate::unix_now_seconds();
    let worker = GatedWorker::start(&url, true).await;
    worker.served_after(started).await;

    // Owe an earlier day, and ask for the pass that sweeps it into the hold.
    hold.arm(&worker.route_hex);
    worker
        .app
        .account_storage(&worker.label)
        .unwrap()
        .app_storage()
        .widen_recovery_coverage_goals(
            std::slice::from_ref(&worker.route),
            crate::unix_now_seconds() - 24 * HOUR,
        )
        .unwrap();
    let pass = worker.pass().await;
    timeout(SETTLE, async {
        while hold.oldest_since.load(Ordering::SeqCst) >= started - HOUR {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the pass's sweep of the newly owed day reaches the relay");
    assert!(
        available_credits(&worker.credits) < MAX_CONCURRENT_JOBS,
        "the quantum holds its credit"
    );

    timeout(SETTLE, worker.runtime.shutdown_and_close())
        .await
        .expect("shutdown does not wait on the held quantum")
        .unwrap();
    let _ended = timeout(SETTLE, pass)
        .await
        .expect("the pass ends with its runner");
    assert_eq!(available_credits(&worker.credits), MAX_CONCURRENT_JOBS);
}

/// A reconnect stops the worker's runner mid-quantum while storage is open:
/// the preempted quantum, which had made no progress, gives its attempt back
/// before the next runner begins its own on the same debt, so the account is
/// charged once for the two. The inbox owes the reconnect's gap too, and is
/// charged its own attempt when its comparison runs first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_mid_quantum_gives_the_preempted_attempt_back() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let hold = HeldSweep::default();
    let _release = ReleaseOnDrop(hold.clone());
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(hold.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let started = crate::unix_now_seconds();
    let worker = GatedWorker::start(&url, true).await;
    worker.served_after(started).await;
    // A pass waits for the step in flight, so what the account owed at start
    // is served first.
    timeout(SETTLE, worker.pass().await)
        .await
        .expect("the pass ends within its budget")
        .unwrap();
    let storage = worker
        .app
        .account_storage(&worker.label)
        .unwrap()
        .app_storage();
    let charged = || {
        storage
            .recovery_account_usage(crate::unix_now_seconds())
            .unwrap()
            .attempts
    };
    let held = |count: usize| {
        let hold = hold.clone();
        async move {
            timeout(SETTLE, async {
                while hold.held.load(Ordering::SeqCst) < count {
                    sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("a sweep of the owed day reaches the relay");
        }
    };

    // Lose the last day, as a loss import would, and ask for the pass that
    // sweeps it into the hold: its first request waits there.
    hold.arm(&worker.route_hex);
    storage
        .uncover_recovery_coverage(
            std::slice::from_ref(&worker.route),
            crate::unix_now_seconds() - 24 * HOUR,
        )
        .unwrap();
    let _pass = worker.pass().await;
    held(1).await;
    let in_flight = charged();
    let inbox_served = || {
        storage
            .recovery_units()
            .unwrap()
            .into_iter()
            .filter(|unit| unit.route == TransportReconciliationRoute::Inbox)
            .filter_map(|unit| unit.last_served_at_seconds)
            .max()
    };
    // Serves stamp whole seconds, and the runner serves nothing while its
    // quantum is held: reconnect in a later second than any serve so far.
    let before = crate::unix_now_seconds();
    while crate::unix_now_seconds() == before {
        sleep(Duration::from_millis(25)).await;
    }
    let reconnected_at = crate::unix_now_seconds();

    worker
        .runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    held(2).await;
    let inbox = u64::from(inbox_served().is_some_and(|served| served >= reconnected_at));
    assert_eq!(
        charged(),
        in_flight + inbox,
        "the preempted attempt was given back before the next one began"
    );
    hold.release();
    timeout(SETTLE, worker.runtime.shutdown_and_close())
        .await
        .unwrap()
        .unwrap();
}
