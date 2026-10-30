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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportDelivery, TransportEndpoint};
use nostr::prelude::{Event, RelayUrl};
use storage_sqlite::{RecoveryUnitPolicy, SqliteAppStorage};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use transport_nostr::MarmotRelayPlane;
use transport_nostr_adapter::compare::CompareRelay;
use transport_nostr_adapter::sweep::{RelayCaps, SdkSweepRelay, SweepRelay};
use transport_nostr_adapter::{NostrRelayEvent, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

use super::{
    Admitted, DebtTurn, OpenAttempts, PassReport, RecoveryRunner, RecoveryRunnerHandle,
    RecoveryRunnerPolicy, RunnerHost, TARGET, WorkerTurn,
};
use crate::MarmotApp;
use crate::client::sync::{RecoveredDelivery, TRANSPORT_RECONCILIATION_QUANTUM};
use crate::client::{AppClient, InventoryWrite};
use crate::relay_caps::RelayCapsCache;

/// How long a stopping worker serves its runner's last turns, the preempted
/// quantum's settlement among them, before it aborts the task. The runner
/// holds no storage, so an abort loses nothing durable, and an attempt it
/// left unsettled is refunded ([`OpenAttemptRefund`]).
const STOP_WAIT: Duration = Duration::from_secs(1);

type ClientFuture<'c, T> = Pin<Box<dyn Future<Output = T> + Send + 'c>>;
type ClientTurn = Box<dyn for<'c> FnOnce(&'c mut AppClient) -> ClientFuture<'c, ()> + Send>;

/// One runner turn, waiting for the account's client. Not `Debug`.
pub(crate) struct RunnerTurn {
    run: ClientTurn,
    /// It ingests a staged delivery, so it may leave effects to publish.
    ingests: bool,
}

impl RunnerTurn {
    /// Run the turn on `client`, the account's own.
    pub(crate) async fn serve(self, client: &mut AppClient) {
        (self.run)(client).await;
    }
}

/// What one account gives its runner.
pub(crate) struct AccountRunnerHost {
    turns: mpsc::Sender<RunnerTurn>,
    relay_caps: RelayCapsCache,
    allow_loopback: bool,
    relay_plane: MarmotRelayPlane,
    account_id: MemberId,
    /// The account's relay pool. An account whose transport has not
    /// registered yet has none, so each debt turn looks again until it does.
    relay_client: Mutex<Option<NostrSdkRelayClient>>,
}

impl AccountRunnerHost {
    /// Send `run` to the client's owner and wait for its answer. `None` once
    /// nobody serves the account's turns, or when `run` answers nothing.
    async fn on_client<T, F>(&self, ingests: bool, run: F) -> Option<T>
    where
        T: Send + 'static,
        F: for<'c> FnOnce(&'c mut AppClient) -> ClientFuture<'c, Option<T>> + Send + 'static,
    {
        let (reply, answer) = oneshot::channel();
        let turn = RunnerTurn {
            run: Box::new(move |client| {
                Box::pin(async move {
                    if let Some(value) = run(client).await {
                        let _ = reply.send(value);
                    }
                })
            }),
            ingests,
        };
        self.turns.send(turn).await.ok()?;
        answer.await.ok()
    }

    fn relay_client(&self) -> std::sync::MutexGuard<'_, Option<NostrSdkRelayClient>> {
        self.relay_client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Look for the account's relay pool if the runner has none yet. It
    /// reads the plane's account contexts and dials nothing.
    async fn find_relay_client(&self) {
        if self.relay_client().is_some() {
            return;
        }
        let found = self
            .relay_plane
            .account_history_relay_client(&self.account_id)
            .await;
        if found.is_some() {
            *self.relay_client() = found;
        }
    }

    fn sdk_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Option<SdkSweepRelay> {
        let endpoint = RelayUrl::parse(relay).ok()?;
        Some(SdkSweepRelay::new(
            self.relay_client().as_ref()?,
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
        self.on_client(false, move |client| {
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
        // Every quantum begins in a debt turn, so its sweep finds the pool
        // once the account's transport has registered one.
        self.find_relay_client().await;
        self.on_client(false, move |client| {
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

    async fn deliveries(&self, relay: &str, event: Event) -> Option<Vec<TransportDelivery>> {
        let Ok(event) = NostrTransportEvent::from_nostr_event(&event) else {
            return Some(Vec::new());
        };
        let fetched = NostrRelayEvent {
            endpoint: TransportEndpoint(relay.to_owned()),
            subscription_id: None,
            event,
        };
        // The adapter routes by the subscriptions it has installed, which
        // trail the routes a debt turn read: a valid event from a relay the
        // account was just given routes nowhere until they catch up.
        match self
            .relay_plane
            .recovered_deliveries_for_account(&self.account_id, fetched)
            .await
        {
            Ok(deliveries) if deliveries.is_empty() => {
                tracing::debug!(
                    target: TARGET,
                    method = "deliveries",
                    "recovery runner fetched an event no installed subscription routes yet"
                );
                None
            }
            Ok(deliveries) => Some(deliveries),
            // Only an invalid event fails to route.
            Err(_) => {
                tracing::debug!(
                    target: TARGET,
                    method = "deliveries",
                    "recovery runner dropped an invalid fetched event"
                );
                Some(Vec::new())
            }
        }
    }

    async fn admit_staged(
        &self,
        delivery: TransportDelivery,
    ) -> Option<Result<Admitted, &'static str>> {
        self.on_client(true, move |client| {
            Box::pin(async move { Some(admit(client, &delivery).await) })
        })
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

/// Refunds the attempts a runner left unsettled when its owner lets go of
/// it: after a stop, an abort, or a dropped in-place pass. Its owner serves no
/// more of the runner's turns by then, so what is left will never settle. It
/// writes only to storage already open, so once `shutdown_and_close` has
/// closed storage it refunds nothing.
struct OpenAttemptRefund {
    open: OpenAttempts,
    app: MarmotApp,
    label: String,
    policy: RecoveryUnitPolicy,
}

impl Drop for OpenAttemptRefund {
    fn drop(&mut self) {
        if self.open.is_empty() {
            return;
        }
        if let Some(storage) = self.app.open_account_storage(&self.label) {
            self.open
                .refund(&storage.app_storage(), &self.policy, unix_now());
        }
    }
}

/// The account's runner before its owner serves it.
struct AccountRunner {
    runner: RecoveryRunner<AccountRunnerHost>,
    handle: RecoveryRunnerHandle,
    turns: mpsc::Receiver<RunnerTurn>,
    refund: OpenAttemptRefund,
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
            relay_client: Mutex::new(
                self.relay_plane
                    .account_history_relay_client(&account_id)
                    .await,
            ),
            relay_plane: self.relay_plane.clone(),
            account_id,
        };
        let policy = RecoveryRunnerPolicy::default();
        let (runner, handle) = RecoveryRunner::waking_on(
            Arc::new(host),
            policy,
            self.recovery_credits.clone(),
            self.routing.recovery_runner_wake(),
        );
        let refund = OpenAttemptRefund {
            open: runner.open_attempts(),
            app: self.app.clone(),
            label: self.state.label.clone(),
            policy: policy.unit,
        };
        AccountRunner {
            runner,
            handle,
            turns,
            refund,
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
            refund,
        } = self.build_recovery_runner().await;
        Some(SpawnedRunner {
            task: runner.spawn(),
            handle,
            turns,
            _refund: refund,
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
                // A pass dropped mid-way took its runner with it, and refunded
                // the attempt it left open.
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

/// A directly owned client's runner. Not `Debug`. Dropped mid-pass, it
/// refunds the attempt its pass left open.
pub(crate) struct InPlaceRunner {
    runner: RecoveryRunner<AccountRunnerHost>,
    turns: mpsc::Receiver<RunnerTurn>,
    /// Keeps its hints sender alive for later steering.
    _handle: RecoveryRunnerHandle,
    _refund: OpenAttemptRefund,
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
            _refund: built.refund,
            #[cfg(test)]
            passes: 0,
        }
    }
}

/// A worker account's runner task. The worker serves its turns
/// ([`Self::next_turn`]) and stops it on its way out; dropping it aborts the
/// task and refunds the attempts it left open.
pub(crate) struct SpawnedRunner {
    handle: RecoveryRunnerHandle,
    task: JoinHandle<()>,
    turns: mpsc::Receiver<RunnerTurn>,
    /// Declared last: it drops after the task is aborted.
    _refund: OpenAttemptRefund,
}

impl SpawnedRunner {
    /// The next turn the runner sends. Never resolves once its task is gone.
    pub(crate) async fn next_turn(&mut self) -> RunnerTurn {
        match self.turns.recv().await {
            Some(turn) => turn,
            None => std::future::pending().await,
        }
    }

    /// A turn the runner has already sent, if any.
    pub(crate) fn ready_turn(&mut self) -> Option<RunnerTurn> {
        self.turns.try_recv().ok()
    }

    /// Wake it, steer it, or wait for one pass of it, off the worker.
    pub(crate) fn handle(&self) -> &RecoveryRunnerHandle {
        &self.handle
    }

    /// Stop the runner while `client`, the account's own, is still open. A
    /// quantum in flight is preempted and settles on it: its storage turns
    /// are served until the task ends or [`STOP_WAIT`] passes, and a turn
    /// already sent by then is still served, so a settle that came in time
    /// keeps its verdict and its bytes. Then the turns close and the task is
    /// aborted, and an attempt it left unsettled is refunded as `Unanswered`:
    /// a slow cancel loses only the relay's verdict and the bytes it read
    /// meanwhile. An admission is refused, so nothing is ingested after the
    /// worker's last publication; its event stays staged for the next runner.
    /// A full shutdown (`shutdown_and_close`) refunds only if storage is still
    /// open when the runner stops; once it is closed nothing settles or is
    /// refunded, and the attempt stays charged until it ages out of the hour.
    pub(crate) async fn stop(self, client: &mut AppClient) {
        self.stop_by(client, tokio::time::Instant::now() + STOP_WAIT)
            .await;
    }

    async fn stop_by(mut self, client: &mut AppClient, deadline: tokio::time::Instant) {
        self.handle.shutdown();
        loop {
            tokio::select! {
                biased;
                _ = &mut self.task => break,
                () = tokio::time::sleep_until(deadline) => break,
                Some(turn) = self.turns.recv() => Self::serve_stopping(turn, client).await,
            }
        }
        // Closed first, so what is served here is what came by the deadline.
        self.turns.close();
        while let Ok(turn) = self.turns.try_recv() {
            Self::serve_stopping(turn, client).await;
        }
    }

    /// Serve a stopping runner's storage turn; refuse an admission.
    async fn serve_stopping(turn: RunnerTurn, client: &mut AppClient) {
        if !turn.ingests {
            turn.serve(client).await;
        }
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
