//! The account's runner host (mdk#2660 phase 4, PR 5a), dormant behind the
//! internal `runner_owns_debt` gate
//! ([`MarmotApp::recovery_runner_owns_debt`](crate::MarmotApp)).
//!
//! Turns run on whoever owns the account's [`AppClient`]: the account worker
//! serves them between its other arms ([`SpawnedRunner`]), and a directly
//! owned client serves them while its `sync()` or `next_event()` runs one pass
//! in place ([`RunnerSeat`]). A turn is a closure sent to that owner, run
//! against the client and answered through a oneshot. A turn nobody serves
//! answers `None`, which stops the runner. Caps reads, sweeps over the
//! account's relay pool and event routing run off the worker, on handles that
//! hold no storage.
//!
//! The runner never trusts a wake: every bump (`AppTransportRouting`'s
//! sender) only makes it read the ledger again.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportDelivery, TransportEndpoint};
use nostr::prelude::{Event, RelayUrl};
use storage_sqlite::SqliteAppStorage;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use transport_nostr::MarmotRelayPlane;
use transport_nostr_adapter::compare::CompareRelay;
use transport_nostr_adapter::sweep::{RelayCaps, SdkSweepRelay, SweepRelay};
use transport_nostr_adapter::{NostrRelayEvent, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

use super::{
    Admitted, DebtTurn, PassReport, RecoveryRunner, RecoveryRunnerHandle, RecoveryRunnerPolicy,
    RunnerHost, TARGET, WorkerTurn,
};
use crate::client::sync::{RecoveredDelivery, TRANSPORT_RECONCILIATION_QUANTUM};
use crate::client::{AppClient, InventoryWrite};
use crate::relay_caps::RelayCapsCache;

/// How long a stopping worker waits for its runner to wind down before it
/// aborts the task. The runner holds no storage, so an abort loses nothing.
const STOP_WAIT: Duration = Duration::from_secs(1);

type ClientFuture<'c, T> = Pin<Box<dyn Future<Output = T> + Send + 'c>>;

/// One runner turn, waiting for the account's client. Not `Debug`.
pub(crate) struct RunnerTurn(
    Box<dyn for<'c> FnOnce(&'c mut AppClient) -> ClientFuture<'c, ()> + Send>,
);

impl RunnerTurn {
    /// Run the turn on `client`, the account's own.
    pub(crate) async fn serve(self, client: &mut AppClient) {
        (self.0)(client).await;
    }
}

/// What one account gives its runner.
pub(crate) struct AccountRunnerHost {
    turns: mpsc::Sender<RunnerTurn>,
    relay_caps: RelayCapsCache,
    allow_loopback: bool,
    relay_plane: MarmotRelayPlane,
    account_id: MemberId,
    /// The account's relay pool, read when the runner is built.
    relay_client: Option<NostrSdkRelayClient>,
}

impl AccountRunnerHost {
    /// Send `run` to the client's owner and wait for its answer. `None` once
    /// nobody serves the account's turns, or when `run` answers nothing.
    async fn on_client<T, F>(&self, run: F) -> Option<T>
    where
        T: Send + 'static,
        F: for<'c> FnOnce(&'c mut AppClient) -> ClientFuture<'c, Option<T>> + Send + 'static,
    {
        let (reply, answer) = oneshot::channel();
        let turn = RunnerTurn(Box::new(move |client| {
            Box::pin(async move {
                if let Some(value) = run(client).await {
                    let _ = reply.send(value);
                }
            })
        }));
        self.turns.send(turn).await.ok()?;
        answer.await.ok()
    }

    fn sdk_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Option<SdkSweepRelay> {
        let endpoint = RelayUrl::parse(relay).ok()?;
        Some(SdkSweepRelay::new(
            self.relay_client.as_ref()?,
            endpoint,
            caps,
            request_timeout,
        ))
    }
}

#[async_trait]
impl RunnerHost for AccountRunnerHost {
    async fn turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&WorkerTurn<'_>) -> T + Send + 'static,
        T: Send + 'static,
    {
        self.on_client(move |client| {
            Box::pin(async move {
                let app = runner_storage(client)?;
                Some(turn(&WorkerTurn {
                    app: &app,
                    now: unix_now(),
                }))
            })
        })
        .await
    }

    async fn debt_turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&DebtTurn<'_>) -> T + Send + 'static,
        T: Send + 'static,
    {
        self.on_client(move |client| {
            Box::pin(async move {
                let app = runner_storage(client)?;
                let now = unix_now();
                let tails = client.recovery_runner_live_tails(&app, now).await;
                let routes = client.recovery_runner_routes();
                // The live counts and the fences they raise come with PR 5c.
                Some(turn(&DebtTurn {
                    app: &app,
                    routes: &routes,
                    now,
                    tails: &*tails,
                    live_counts: &[],
                }))
            })
        })
        .await
    }

    async fn relay_caps(&self, relay: &str) -> Option<RelayCaps> {
        let caps = self.relay_caps.caps(relay, self.allow_loopback).await;
        // The cache folds an unknown read into the default caps. Read those as
        // unknown, which is never evidence of a change, until the read tells
        // them apart (PR 5b).
        (caps != RelayCaps::default()).then_some(caps)
    }

    fn sweep_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Option<Box<dyn SweepRelay>> {
        Some(Box::new(self.sdk_relay(relay, caps, request_timeout)?))
    }

    fn compare_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Option<Box<dyn CompareRelay>> {
        Some(Box::new(self.sdk_relay(relay, caps, request_timeout)?))
    }

    async fn deliveries(&self, relay: &str, event: Event) -> Vec<TransportDelivery> {
        let Ok(event) = NostrTransportEvent::from_nostr_event(&event) else {
            return Vec::new();
        };
        let fetched = NostrRelayEvent {
            endpoint: TransportEndpoint(relay.to_owned()),
            subscription_id: None,
            event,
        };
        self.relay_plane
            .recovered_deliveries_for_account(&self.account_id, fetched)
            .await
            .unwrap_or_else(|_| {
                tracing::debug!(
                    target: TARGET,
                    method = "deliveries",
                    "recovery runner could not route a fetched event"
                );
                Vec::new()
            })
    }

    async fn admit_staged(
        &self,
        delivery: TransportDelivery,
    ) -> Option<Result<Admitted, &'static str>> {
        self.on_client(move |client| Box::pin(async move { Some(admit(client, &delivery).await) }))
            .await
    }

    fn now_seconds(&self) -> u64 {
        unix_now()
    }
}

/// Admit one staged delivery through the account's recovered-ingest path. An
/// event the account holds, or now persisted, is kept; one the engine kept no
/// trace of, or refused for its group's resources, stays fetchable.
async fn admit(
    client: &mut AppClient,
    delivery: &TransportDelivery,
) -> Result<Admitted, &'static str> {
    let (summary, settled, _) = client
        .admit_recovered_delivery(delivery, InventoryWrite::Immediate)
        .await
        .map_err(|error| error.privacy_safe_kind())?;
    client.pending_applied_sync_summary.merge(summary);
    Ok(match settled {
        RecoveredDelivery::AlreadyHeld
        | RecoveredDelivery::Ingested {
            unpersisted: false,
            refused_group: None,
        } => Admitted::Kept,
        RecoveredDelivery::Ingested { .. } => Admitted::NoTrace,
    })
}

/// The account's app storage for one turn. `None` once it is closed, which
/// stops the runner.
fn runner_storage(client: &AppClient) -> Option<SqliteAppStorage> {
    match client.app.account_storage(&client.state.label) {
        Ok(storage) => Some(storage.app_storage()),
        Err(error) => {
            tracing::debug!(
                target: TARGET,
                method = "runner_turn",
                error_kind = error.privacy_safe_kind(),
                "recovery runner turn found no account storage"
            );
            None
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The account's runner before its owner serves it.
struct AccountRunner {
    runner: RecoveryRunner<AccountRunnerHost>,
    handle: RecoveryRunnerHandle,
    turns: mpsc::Receiver<RunnerTurn>,
}

impl AppClient {
    /// Build the account's runner over this client, woken by its routing's
    /// chokepoint bumps. Its turns wait until this client's owner serves them.
    async fn build_recovery_runner(&self) -> AccountRunner {
        let (turns_tx, turns) = mpsc::channel(1);
        let account_id = self.adapter.account_id().clone();
        let host = AccountRunnerHost {
            turns: turns_tx,
            relay_caps: self.app.relay_caps.clone(),
            allow_loopback: self.app.config.allow_loopback_relay_endpoints,
            relay_client: self
                .relay_plane
                .account_history_relay_client(&account_id)
                .await,
            relay_plane: self.relay_plane.clone(),
            account_id,
        };
        let (runner, handle) = RecoveryRunner::waking_on(
            Arc::new(host),
            RecoveryRunnerPolicy::default(),
            self.recovery_credits.clone(),
            self.routing.recovery_runner_wake(),
        );
        AccountRunner {
            runner,
            handle,
            turns,
        }
    }

    /// Spawn the account's runner, for the account worker to serve. Only
    /// with the internal `runner_owns_debt` gate on.
    pub(crate) async fn spawn_recovery_runner(&self) -> Option<SpawnedRunner> {
        if !self.app.recovery_runner_owns_debt() {
            return None;
        }
        let AccountRunner {
            runner,
            handle,
            turns,
        } = self.build_recovery_runner().await;
        Some(SpawnedRunner {
            task: runner.spawn(),
            handle,
            turns,
        })
    }

    /// Give a directly owned client its in-place runner. Only with the
    /// internal `runner_owns_debt` gate on.
    pub(crate) async fn seat_recovery_runner_in_place(&mut self) {
        if self.app.recovery_runner_owns_debt() {
            self.seat_in_place().await;
        }
    }

    async fn seat_in_place(&mut self) {
        self.recovery_runner = RunnerSeat::InPlace(Some(Box::new(InPlaceRunner::from(
            self.build_recovery_runner().await,
        ))));
    }

    /// One explicit pass of a directly owned client's runner, within the
    /// explicit job's budget: each unit due now runs once, and its turns run
    /// on this client while the pass waits for them. `None` without an
    /// in-place runner.
    pub(crate) async fn run_recovery_runner_pass(&mut self) -> Option<PassReport> {
        let mut seat = match &mut self.recovery_runner {
            RunnerSeat::Absent => return None,
            RunnerSeat::InPlace(seat) => match seat.take() {
                Some(seat) => seat,
                // A pass dropped mid-way took its runner with it.
                None => Box::new(InPlaceRunner::from(self.build_recovery_runner().await)),
            },
        };
        #[cfg(test)]
        {
            seat.passes += 1;
        }
        let report = {
            let InPlaceRunner { runner, turns, .. } = &mut *seat;
            let pass = runner.run_pass(TRANSPORT_RECONCILIATION_QUANTUM);
            tokio::pin!(pass);
            loop {
                tokio::select! {
                    biased;
                    report = &mut pass => break report,
                    Some(turn) = turns.recv() => turn.serve(self).await,
                }
            }
        };
        self.recovery_runner = RunnerSeat::InPlace(Some(seat));
        Some(report)
    }

    /// Whether this directly owned client runs a recovery runner in place.
    pub(crate) fn has_in_place_recovery_runner(&self) -> bool {
        matches!(self.recovery_runner, RunnerSeat::InPlace(_))
    }

    /// Wake the account's runner: its debt or retry state may have changed.
    /// It reads them again; nothing rides on the bump.
    pub(crate) fn wake_recovery_runner(&self) {
        self.routing.wake_recovery_runner();
    }
}

/// Where a client's runner lives.
#[derive(Default)]
pub(crate) enum RunnerSeat {
    /// No in-place runner: the gate is off, or the account worker runs the
    /// account's runner as its own task.
    #[default]
    Absent,
    /// A directly owned client's runner, run one pass at a time. Empty while
    /// a pass runs.
    InPlace(Option<Box<InPlaceRunner>>),
}

/// A directly owned client's runner. Not `Debug`.
pub(crate) struct InPlaceRunner {
    runner: RecoveryRunner<AccountRunnerHost>,
    turns: mpsc::Receiver<RunnerTurn>,
    /// Keeps its hints sender alive for later steering.
    _handle: RecoveryRunnerHandle,
    /// Passes started on this runner.
    #[cfg(test)]
    passes: u32,
}

impl From<AccountRunner> for InPlaceRunner {
    fn from(built: AccountRunner) -> Self {
        Self {
            runner: built.runner,
            turns: built.turns,
            _handle: built.handle,
            #[cfg(test)]
            passes: 0,
        }
    }
}

/// A worker account's runner task. The worker serves its turns
/// ([`Self::next_turn`]) and stops it on its way out; dropping it aborts the
/// task.
pub(crate) struct SpawnedRunner {
    handle: RecoveryRunnerHandle,
    task: JoinHandle<()>,
    turns: mpsc::Receiver<RunnerTurn>,
}

impl SpawnedRunner {
    /// The next turn the runner sends. Never resolves once its task is gone.
    pub(crate) async fn next_turn(&mut self) -> RunnerTurn {
        match self.turns.recv().await {
            Some(turn) => turn,
            None => std::future::pending().await,
        }
    }

    /// Wake it, steer it, or wait for one pass of it, off the worker.
    pub(crate) fn handle(&self) -> &RecoveryRunnerHandle {
        &self.handle
    }

    /// Stop the runner: a quantum in flight is preempted, a turn it waits on
    /// answers `None`, and the task gets a moment to end before it is
    /// aborted.
    pub(crate) async fn stop(mut self) {
        self.handle.shutdown();
        self.turns.close();
        while self.turns.try_recv().is_ok() {}
        let _ = tokio::time::timeout(STOP_WAIT, &mut self.task).await;
    }
}

impl Drop for SpawnedRunner {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.task.abort();
    }
}

/// The worker's runner, if it has one: the next turn its runner sends.
/// Never resolves without one.
pub(crate) async fn next_runner_turn(runner: &mut Option<SpawnedRunner>) -> RunnerTurn {
    match runner {
        Some(runner) => runner.next_turn().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
