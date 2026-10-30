//! The account worker runs its recovery runner only with the internal
//! `runner_owns_debt` gate on: the runner spawns with the worker, serves the
//! account's debt over its own relay pool, answers a pass, and stops with
//! `shutdown_and_close` even while a quantum waits on its relay. With the gate
//! off nothing spawns.

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
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    held: Arc<AtomicUsize>,
    /// The earliest `since` a held request asked from.
    oldest_since: Arc<AtomicU64>,
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
                self.entered.notify_one();
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
            credits,
        }
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

/// With the gate off the worker spawns no runner: a pass finds none, and the
/// group's owed hour is never served by one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_spawns_no_runner_with_the_gate_off() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let worker = GatedWorker::start(&url, false).await;
    timeout(SETTLE, worker.runtime.catch_up_accounts())
        .await
        .unwrap()
        .unwrap();
    assert!(worker.pass().await.await.unwrap().is_none());
    assert!(worker.served_at().is_none());
    worker.runtime.shutdown_and_close().await.unwrap();
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
    let entered = hold.entered.notified();
    let pass = worker.pass().await;
    timeout(SETTLE, entered)
        .await
        .expect("the pass's quantum reaches the relay");
    assert!(
        hold.oldest_since.load(Ordering::SeqCst) < started - HOUR,
        "the held request sweeps the newly owed day"
    );
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
