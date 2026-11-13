//! The recovery runner (mdk#2660 phase 4): one task per account that owns
//! history recovery scheduling over the coverage ledger and its durable retry
//! state.
//!
//! It owns every history fetch since PR 5g. The account worker spawns it and
//! stops it with the worker, and a directly owned client runs it in place for
//! one pass from `sync()` and `next_event()` ([`host`]).
//!
//! One step:
//!
//! 1. **Select** (worker turn): read the live tails, the ledger and the retry
//!    state, and pick one unit ([`select`]). Nothing is written.
//! 2. **Credit** (off the worker): wait for one of the process's recovery
//!    credits. The pool is FIFO, so accounts take turns, and an account holds
//!    at most one at a time.
//! 3. **Begin**: read the relay's NIP-11 caps (off the worker), then, in a
//!    worker turn, record known caps, read the tails again, plan the unit's
//!    owed ranges from its ledger cursor, read the un-cover mark and record the
//!    attempt. Nothing read before the credit wait is planned on.
//! 4. **Quantum** (off the worker): `run_sweep` on that (route, relay) for
//!    each owed range, oldest first, under one deadline ([`quantum`]), or a
//!    NIP-77 comparison of those ranges ([`compare`]).
//! 5. **Stage** (one worker turn per proven slice or compared window): its
//!    events to staging and its coverage to the ledger in one transaction,
//!    through the mark.
//! 6. **Settle** (worker turn): map the quantum's end to the outcome table and
//!    apply it; then the credit is released.
//!
//! Debt units are one per (route, required relay) (decision 3), plus one
//! attempt per new debt on each best-effort relay. A group unit compares
//! instead of sweeping when its relay compares and the account already holds
//! events in the owed ranges. The account inbox is only ever compared: many
//! inbox relays restrict who may read gift wraps, so a short page proves
//! nothing there, and an inbox relay that will not compare refuses its unit.
//! Once no debt unit is eligible, re-check units ([`recheck`]) compare each
//! required NIP-77 relay's covered and retired ranges again, on their own
//! schedule.
//!
//! Each step first admits what staging may release ([`admission`]): per MLS
//! group, and for the inbox, oldest first, up to its admission frontier. The
//! same reads hold back a relay staging is full for, block every unit of a
//! group admission cannot drain, and serve fenced groups first.
//!
//! Live tails are a query, never a stored value ([`tails`]): the select and
//! begin turns each read them fresh, and nothing keeps an answer across an
//! await, a quantum or a wake.
//!
//! Logs carry aggregates only: no route, relay, group or account identity.
#![cfg_attr(not(test), allow(dead_code))]

mod admission;
pub(crate) mod audit;
mod compare;
mod epoch_gap;
pub(crate) mod host;
mod open_attempts;
mod policy;
pub(crate) mod post_join;
mod quantum;
mod recheck;
mod repair;
mod select;
mod tails;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportDelivery;
use cgka_traits::storage::{StorageError, StorageResult};
use marmot_forensics::{AuditEventKind, RecoveryRunnerCap, RecoveryRunnerChange};
use nostr::prelude::Event;
use storage_sqlite::{
    RecoveryRelayCaps, RecoveryUnitOutcome, SqliteAppStorage, TransportReconciliationRoute,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use transport_nostr_adapter::compare::CompareRelay;
use transport_nostr_adapter::sweep::{RelayCaps, SweepEnd, SweepRelay, SweepRoute};

pub(crate) use admission::{Admitted, LiveCount, LiveFence};
pub(crate) use policy::RecoveryRunnerPolicy;
pub(crate) use tails::LiveTailRead;

use crate::AppError;
use crate::runtime::account_worker::recovery_credits::{self, RecoveryCreditPool};
use open_attempts::AttemptKind;
pub(crate) use open_attempts::OpenAttempts;
use select::{Candidate, Memory, Pick};

const TARGET: &str = "marmot_app::recovery_runner";

/// A route the account currently subscribes, with the relays it is fetched
/// from, spelled as the ledger spells them (`transport_nostr::canonical_relay`).
/// Not `Debug`: it carries the route and the relays.
#[derive(Clone)]
pub(crate) struct RunnerRoute {
    pub(crate) route: TransportReconciliationRoute,
    /// The MLS group it carries, shared by a group's current and retained
    /// routes; `None` when the route is its own group.
    pub(crate) group_id: Option<Vec<u8>>,
    /// The relays that owe the route its history (decision 3): its operated
    /// relays when it lists any, otherwise all of them.
    pub(crate) required: Vec<String>,
    /// Its other relays: one attempt per new debt, never charged, broken or
    /// noticed.
    pub(crate) best_effort: Vec<String>,
    /// Its group's local copy is Unrecoverable (the engine froze it). The
    /// route is suspended: its units and re-checks are not scheduled,
    /// charged, broken or noticed while its debt keeps accruing, since a
    /// fetch would only fill the group's deferred input with ciphertext the
    /// copy cannot open.
    pub(crate) unrecoverable: bool,
    /// Its group has a conversation window open: the survey hints its route
    /// into the window class.
    pub(crate) window: bool,
    /// A retained prior route's goal ends here: its switch plus the
    /// clock-skew allowance. Members that had not applied the switch by then
    /// still send there, and its live subscription delivers that; nothing
    /// later is owed. `None` for a current route.
    pub(crate) goal_until: Option<u64>,
}

impl RunnerRoute {
    /// Each relay once, with whether it is best effort.
    fn relays(&self) -> impl Iterator<Item = (&str, bool)> {
        self.required
            .iter()
            .map(|relay| (relay.as_str(), false))
            .chain(
                self.best_effort
                    .iter()
                    .filter(|relay| !self.required.contains(relay))
                    .map(|relay| (relay.as_str(), true)),
            )
    }

    /// Whether its group is suspended (Unrecoverable): its units are not
    /// scheduled, charged, broken or noticed.
    pub(crate) fn suspended(&self) -> bool {
        select::suspended(self)
    }
}

/// Routes the caller wants served first. Not `Debug`: it carries routes.
#[derive(Clone, Default)]
pub(crate) struct PriorityHints {
    /// Groups whose live frames are held behind a fence. Each survey adds
    /// every route of each group its own fences hold.
    pub(crate) held: BTreeSet<TransportReconciliationRoute>,
    /// Groups with an open conversation window. Each survey adds the routes
    /// whose group has one open.
    pub(crate) window: BTreeSet<TransportReconciliationRoute>,
}

/// One (route, relay) the runner serves. Not `Debug`: it carries both.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnitKey {
    pub(crate) route: TransportReconciliationRoute,
    pub(crate) relay: String,
}

/// What a worker turn sees.
pub(crate) struct WorkerTurn<'a> {
    pub(crate) app: &'a SqliteAppStorage,
    /// Unix seconds, as of this turn.
    pub(crate) now: u64,
    /// Records one row into the account's audit recorder, which drops it
    /// unless it records v5: about the MLS group given, or account-scoped.
    pub(crate) audit: audit::AuditHook<'a>,
}

/// What a turn that reads debt sees: the account's current routes, and the
/// live tails and live counts read for this turn alone.
#[derive(Clone, Copy)]
pub(crate) struct DebtTurn<'a> {
    pub(crate) app: &'a SqliteAppStorage,
    /// The account's current routes, as of this turn.
    pub(crate) routes: &'a [RunnerRoute],
    /// The account's public key: its inbox's `#p` on the wire.
    pub(crate) inbox: [u8; 32],
    pub(crate) now: u64,
    pub(crate) tails: &'a dyn LiveTailRead,
    /// The open live REQs' counts, for the fence.
    pub(crate) live_counts: &'a [LiveCount],
    /// As [`WorkerTurn::audit`]. The host may still fail the turn after its
    /// closure returns (its fence read), and the runner then runs it again,
    /// so a row is written where what it records is committed or stored,
    /// never left for the runner to store once the turn answers.
    pub(crate) audit: audit::AuditHook<'a>,
    /// Whether the recorder keeps v5 rows, so a fetch's row is worth the
    /// reads that describe it.
    pub(crate) audits: bool,
}

impl DebtTurn<'_> {
    /// The last second `relay` owes `route` this turn: the second before its
    /// live tail, and never past a retained route's goal.
    pub(in crate::client) fn owed_until(&self, route: &RunnerRoute, relay: &str) -> u64 {
        self.checked_until(route)
            .min(self.tails.owed_until(&route.route, relay, self.now))
    }

    /// The last second a re-check of `route` passes over: now, or a retained
    /// route's goal end.
    pub(in crate::client) fn checked_until(&self, route: &RunnerRoute) -> u64 {
        route
            .goal_until
            .map_or(self.now, |until| until.min(self.now))
    }
}

/// What one account gives its runner. Turns run on whoever owns the account's
/// client, the account worker or a directly owned client's pass ([`host`]),
/// and must stay short: storage reads and writes, no awaiting. Everything else
/// runs off the worker.
#[async_trait]
pub(crate) trait RunnerHost: Send + Sync + 'static {
    /// Run `turn` on the worker. `None` once the worker is gone.
    async fn turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&WorkerTurn<'_>) -> T + Send + 'static,
        T: Send + 'static;

    /// Run `turn` on the worker with the live tails and live counts read at
    /// its start ([`AppClient::recovery_runner_live_tails`](crate::client::AppClient)).
    /// Preparation errors are returned without calling `turn`, through the
    /// same local-failure handling as its storage reads. `None` means stopped.
    async fn debt_turn<T, F>(&self, turn: F) -> Option<StorageResult<T>>
    where
        F: FnOnce(&DebtTurn<'_>) -> StorageResult<T> + Send + 'static,
        T: Send + 'static;

    /// The relay's NIP-11 caps (`MarmotApp::relay_caps`); `None` when unknown.
    /// An unknown read is never evidence of a change.
    async fn relay_caps(&self, relay: &str) -> Option<RelayCaps>;

    /// A sweep relay over the account's relay client (`SdkSweepRelay`), for
    /// an endpoint already in its pool; `None` when it is not there.
    fn sweep_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Option<Box<dyn SweepRelay>>;

    /// A comparison relay over the account's relay client (`SdkSweepRelay`
    /// too), for an endpoint already in its pool; `None` when it is not there.
    fn compare_relay(
        &self,
        relay: &str,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Option<Box<dyn CompareRelay>>;

    /// Route one fetched event to this account (the adapter's
    /// `reconciled_deliveries`). An invalid event routes nowhere and is
    /// dropped. `None` when a valid event routes to nothing yet: the account's
    /// installed subscriptions lag its routes, so its slice stays owed.
    async fn deliveries(&self, relay: &str, event: Event) -> Option<Vec<TransportDelivery>>;

    /// Hand one bounded batch to the account's recovered-ingest path in one
    /// worker command. Return only the attempted prefix, stopping on a hold,
    /// failure, self-removal or effects needing publication. `None` once the
    /// worker is gone; an error is its privacy-safe kind.
    async fn admit_staged(
        &self,
        deliveries: Vec<TransportDelivery>,
    ) -> Option<Vec<Result<Admitted, &'static str>>>;

    /// Unix seconds.
    fn now_seconds(&self) -> u64;

    /// The account relay pool's connection generations, by relay
    /// (`NostrSdkRelayClient::relay_connections`): a relay whose generation
    /// moves has connected again. `None` while the account has no pool.
    fn relay_connections(&self) -> Option<watch::Receiver<BTreeMap<String, u64>>> {
        None
    }
    /// Whether the account's relay plane has begun shutting down. Its
    /// teardown drops the requests in flight, which then read as unreachable
    /// relays, and it runs alongside the worker's runner stop.
    fn transport_stopping(&self) -> bool {
        false
    }
    /// What the last survey found still catching up, for the account's
    /// recovery status. Called after every survey; the host keeps the last.
    fn surveyed(&self, catching_up: BTreeSet<UnitKey>);
}

/// A quantum the relay plane's shutdown cut is preempted, not refused: the
/// teardown that dropped its request in flight is this process's, and the
/// worker's runner stop it races would have settled it as a preemption
/// (`SweepEnd::Cancelled`). Settling it as the relay's `Unreachable` verdict
/// would hold the unit back for the unreachable retry delay in the next
/// process that serves the account.
fn preempted_by_transport_stop<H: RunnerHost + ?Sized>(
    host: &H,
    mut report: quantum::QuantumReport,
) -> quantum::QuantumReport {
    if matches!(report.end, SweepEnd::Unreachable(_)) && host.transport_stopping() {
        report.end = SweepEnd::Cancelled;
    }
    report
}

/// One quantum's result. Not `Debug`: it carries its unit.
pub(crate) struct QuantumSummary {
    pub(crate) key: UnitKey,
    pub(crate) best_effort: bool,
    pub(crate) outcome: RecoveryUnitOutcome,
    /// A re-check quantum rather than debt.
    pub(crate) recheck: bool,
}

/// What one step did. Not `Debug`.
pub(crate) enum Step {
    Ran(QuantumSummary),
    /// The unit it picked owed nothing, or was no longer eligible, once it
    /// began. Nothing was charged.
    Raced,
    /// Nothing is eligible: wait for a wake, or until `next_due` (unix seconds).
    Idle {
        next_due: Option<u64>,
    },
    /// The runner was shut down, or its worker is gone.
    Stopped,
}

/// What an explicit pass did, in aggregate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PassReport {
    pub(crate) quanta: u32,
    pub(crate) advanced: u32,
}

/// Account breaker pauses since the process started, across its accounts.
static ACCOUNT_PAUSES: AtomicU64 = AtomicU64::new(0);
/// Events re-checks have found inside history already covered, likewise.
static LATE_FINDINGS: AtomicU64 = AtomicU64::new(0);

/// The runners' aggregate counts since the process started, across its
/// accounts. Counts only, privacy-safe. The breaker's audit row carries them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecoveryRunnerCounts {
    pub(crate) account_pauses: u64,
    pub(crate) late_findings: u64,
}

pub(crate) fn recovery_runner_counts() -> RecoveryRunnerCounts {
    RecoveryRunnerCounts {
        account_pauses: ACCOUNT_PAUSES.load(Ordering::Relaxed),
        late_findings: LATE_FINDINGS.load(Ordering::Relaxed),
    }
}

/// Wake signals other than the coalescing watch, and the runner's aggregate
/// counts.
#[derive(Default)]
struct Signals {
    /// Relays that reconnected since the runner last looked.
    reconnected: Mutex<BTreeSet<String>>,
    /// Events re-checks found inside ranges already covered by this runner.
    /// The process total is [`recovery_runner_counts`].
    late_findings: AtomicU64,
}

/// The relay pool's connection feed and the generations the runner has
/// already seen on it.
struct Connections {
    feed: watch::Receiver<BTreeMap<String, u64>>,
    seen: BTreeMap<String, u64>,
}

impl Connections {
    /// The relays whose generation moved since the last look, canonical.
    fn moved(&mut self) -> Vec<String> {
        let current = self.feed.borrow_and_update().clone();
        let moved = current
            .iter()
            .filter(|&(relay, connection)| self.seen.get(relay) != Some(connection))
            .map(|(relay, _)| transport_nostr::canonical_relay(relay))
            .collect();
        self.seen = current;
        moved
    }

    /// Resolves when the feed publishes, or never once its pool is gone.
    async fn published(connections: &mut Option<Self>) {
        let Some(open) = connections else {
            return std::future::pending().await;
        };
        if open.feed.changed().await.is_err() {
            *connections = None;
        }
    }
}

/// When an explicit pass or repair must end: at its deadline, counted from
/// the caller's request, or once the caller trips `stop`, which only its
/// cancel does, so the two ends stay apart. The runner ends on it wherever
/// it would end on its pass deadline, preempting a quantum in flight, and
/// settles what it ran.
#[derive(Clone)]
pub(crate) struct PassBound {
    pub(crate) deadline: Instant,
    pub(crate) stop: CancellationToken,
    /// An explicit repair checks through its request time even inside a live
    /// tail. Ordinary passes keep the account's healthy-tail authority.
    repair_until: Option<u64>,
}

impl PassBound {
    /// A bound only its deadline ends.
    pub(crate) fn within(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
            stop: CancellationToken::new(),
            repair_until: None,
        }
    }

    fn ended(&self) -> bool {
        self.stop.is_cancelled() || Instant::now() >= self.deadline
    }

    async fn reached(&self) {
        tokio::select! {
            () = tokio::time::sleep_until(self.deadline) => {}
            () = self.stop.cancelled() => {}
        }
    }
}

/// How a runner-owned explicit repair ended ([`RecoveryRunner::repair`]).
/// Not `Debug`.
pub(crate) enum RepairEnd {
    /// Every current route's window is covered and admitted on each of its
    /// required relays ([`repair::repaired`]).
    Covered,
    /// A pass within the bound served nothing, and the window is not covered.
    Unproven,
    /// The bound's deadline came first.
    Deadline,
    /// The caller tripped the bound's stop.
    Cancelled,
    /// The runner was shut down, or its worker is gone.
    Stopped,
    /// The re-arm or the verdict could not use storage.
    Failed(cgka_traits::storage::StorageError),
}

/// One explicit request a spawned runner owes a caller, served between its
/// own steps.
enum Request {
    Pass {
        bound: PassBound,
        reply: oneshot::Sender<PassReport>,
    },
    Repair {
        bound: PassBound,
        reply: oneshot::Sender<RepairEnd>,
    },
}

/// Requests a spawned runner holds before it serves them.
const PASS_REQUESTS: usize = 4;

/// The caller's side of a runner: wake it, steer it, ask it for a pass, stop
/// it.
#[derive(Clone)]
pub(crate) struct RecoveryRunnerHandle {
    wake: watch::Sender<u64>,
    hints: watch::Sender<PriorityHints>,
    passes: mpsc::Sender<Request>,
    signals: Arc<Signals>,
    cancel: CancellationToken,
}

impl RecoveryRunnerHandle {
    /// Debt or retry state changed: a loss import, a goal change, routes or
    /// relays added or removed, a re-arm, a dismissal, a rejoin. Coalesces.
    pub(crate) fn bump(&self) {
        self.wake
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Replace the priority hints and wake the runner.
    pub(crate) fn set_hints(&self, hints: PriorityHints) {
        self.hints.send_replace(hints);
    }

    /// The relay plane reconnected `relay`: its cooldown ends, its caps are
    /// read again, and the next selection reads fresh tails.
    pub(crate) fn relay_reconnected(&self, relay: &str) {
        self.signals
            .reconnected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(relay.to_owned());
        self.bump();
    }

    /// Stop the runner. A quantum in flight is cancelled and settled as
    /// preempted.
    pub(crate) fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// Have the spawned task run one explicit pass ([`RecoveryRunner::run_pass`])
    /// once its current step ends, within what is left then of `budget`, and
    /// wait for its report. `None` once the runner has stopped. Never await
    /// this on the account worker: the pass runs worker turns.
    pub(crate) async fn run_pass(&self, budget: Duration) -> Option<PassReport> {
        let (reply, report) = oneshot::channel();
        let bound = PassBound::within(budget);
        self.passes
            .send(Request::Pass { bound, reply })
            .await
            .ok()?;
        report.await.ok()
    }

    /// Have the spawned task serve one explicit repair
    /// ([`RecoveryRunner::repair`]) once its current step ends, and wait for
    /// how it ended. `None` once the runner has stopped. Never await this on
    /// the account worker: the repair runs worker turns.
    pub(crate) async fn repair(&self, bound: PassBound) -> Option<RepairEnd> {
        let (reply, end) = oneshot::channel();
        self.passes
            .send(Request::Repair { bound, reply })
            .await
            .ok()?;
        end.await.ok()
    }

    /// Events re-checks have found inside ranges already covered, since the
    /// runner was built. An aggregate count, privacy-safe.
    pub(crate) fn late_findings(&self) -> u64 {
        self.signals.late_findings.load(Ordering::Relaxed)
    }
}

/// An audit row and the MLS group it is about, if any.
type AuditRow = (Option<Vec<u8>>, AuditEventKind);

/// One account's runner.
pub(crate) struct RecoveryRunner<H> {
    host: Arc<H>,
    policy: RecoveryRunnerPolicy,
    credits: Arc<RecoveryCreditPool>,
    signals: Arc<Signals>,
    wake: watch::Receiver<u64>,
    hints: watch::Receiver<PriorityHints>,
    passes: mpsc::Receiver<Request>,
    cancel: CancellationToken,
    memory: Memory,
    admission: admission::Memory,
    /// Surveys that failed in a row, for the runner's own local backoff.
    survey_failures: u32,
    /// Reconnect writes that failed in a row, likewise.
    reconnect_failures: u32,
    /// The relay pool's connection feed, once the host has a pool.
    connections: Option<Connections>,
    /// The account breaker's pause last reported, so each pause logs once.
    reported_pause: Option<u64>,
    /// Attempts begun and not settled, for its owner to refund on a stop.
    open: OpenAttempts,
    /// Begins abandoned as raced, coalesced per route for the audit.
    races: audit::Races,
    /// Raced rows whose window closed, for the next survey turn to write: no
    /// turn is awaited only to write a row. The survey drains them inside its
    /// turn, so a turn whose preparation fails leaves them for the retry.
    unwritten_races: Arc<Mutex<Vec<AuditRow>>>,
    /// The routes the last survey found suspended, for the audit; `None`
    /// before the first, and while the recorder keeps no rows. The survey
    /// updates it inside its turn, where it writes the rows for the change,
    /// so a turn that fails after them writes none of them again.
    suspended: Arc<Mutex<Option<BTreeSet<TransportReconciliationRoute>>>>,
}

impl<H: RunnerHost> RecoveryRunner<H> {
    pub(crate) fn new(
        host: Arc<H>,
        policy: RecoveryRunnerPolicy,
        credits: Arc<RecoveryCreditPool>,
    ) -> (Self, RecoveryRunnerHandle) {
        Self::waking_on(host, policy, credits, watch::channel(0).0)
    }

    /// As [`Self::new`], also woken by every bump of `wake`: the account's
    /// chokepoints bump the sender its routing holds, whoever owns the runner.
    pub(crate) fn waking_on(
        host: Arc<H>,
        policy: RecoveryRunnerPolicy,
        credits: Arc<RecoveryCreditPool>,
        wake: watch::Sender<u64>,
    ) -> (Self, RecoveryRunnerHandle) {
        let (hints_tx, hints) = watch::channel(PriorityHints::default());
        let (passes_tx, passes) = mpsc::channel(PASS_REQUESTS);
        let signals = Arc::new(Signals::default());
        let cancel = CancellationToken::new();
        let runner = Self {
            host,
            policy,
            credits,
            signals: signals.clone(),
            wake: wake.subscribe(),
            hints,
            passes,
            cancel: cancel.clone(),
            memory: Memory::default(),
            admission: admission::Memory::default(),
            survey_failures: 0,
            reconnect_failures: 0,
            connections: None,
            reported_pause: None,
            open: OpenAttempts::default(),
            races: audit::Races::default(),
            unwritten_races: Arc::default(),
            suspended: Arc::default(),
        };
        let handle = RecoveryRunnerHandle {
            wake,
            hints: hints_tx,
            passes: passes_tx,
            signals,
            cancel,
        };
        (runner, handle)
    }

    /// The attempts it has begun and not settled, for its owner to refund
    /// once it has stopped ([`OpenAttempts::refund`]).
    pub(crate) fn open_attempts(&self) -> OpenAttempts {
        self.open.clone()
    }

    /// Run the account's task until it is shut down or its worker is gone.
    pub(crate) fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run())
    }

    async fn run(mut self) {
        loop {
            if let Ok(request) = self.passes.try_recv() {
                self.serve(request).await;
                continue;
            }
            self.wake.borrow_and_update();
            self.hints.borrow_and_update();
            let next_due = match self.step().await {
                Step::Stopped => break,
                Step::Ran(_) | Step::Raced => continue,
                Step::Idle { next_due } => self.retry_reconnects_by(next_due),
            };
            let sleep =
                next_due.map(|at| Duration::from_secs(at.saturating_sub(self.host.now_seconds())));
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => break,
                Some(request) = self.passes.recv() => self.serve(request).await,
                changed = self.wake.changed() => if changed.is_err() { break },
                changed = self.hints.changed() => if changed.is_err() { break },
                () = Connections::published(&mut self.connections) => {}
                () = sleep_for(sleep) => {}
            }
        }
        tracing::debug!(target: TARGET, method = "run", "recovery runner stopped");
    }

    /// One caller's explicit request on the spawned task.
    async fn serve(&mut self, request: Request) {
        match request {
            Request::Pass { bound, reply } => {
                let _ = reply.send(self.run_pass_within(&bound).await);
            }
            Request::Repair { bound, reply } => {
                let _ = reply.send(self.repair(&bound).await);
            }
        }
    }

    /// Read ordinary debt, except that an explicit repair's bounded request
    /// also visits the historical part of a healthy live subscription. Its
    /// authority returns unchanged as soon as that request ends or is dropped.
    async fn debt_turn<T, F>(&self, pass: Option<&PassBound>, run: F) -> Option<StorageResult<T>>
    where
        F: FnOnce(&DebtTurn<'_>) -> StorageResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let until = pass.and_then(|bound| bound.repair_until);
        self.host
            .debt_turn(move |turn| {
                if let Some(until) = until {
                    let tails = repair::RepairTails(until);
                    run(&DebtTurn {
                        tails: &tails,
                        ..*turn
                    })
                } else {
                    run(turn)
                }
            })
            .await
    }

    /// One step: admit, then select, credit, begin, quantum, stage, settle.
    pub(crate) async fn step(&mut self) -> Step {
        self.step_within(None, true).await
    }

    /// One explicit pass in place, as a directly owned client's `sync()` and
    /// `next_event()` will run it after the switch-over: each unit due now runs
    /// once, in the runner's order, until every one has run or `budget` is
    /// spent. A unit it does not reach keeps its debt. A quantum the budget
    /// cuts gives its request in flight up to the sweep's interrupt grace
    /// (`INTERRUPT_GRACE`) to report what it read.
    pub(crate) async fn run_pass(&mut self, budget: Duration) -> PassReport {
        self.run_pass_within(&PassBound::within(budget)).await
    }

    /// As [`Self::run_pass`], until `bound` ends.
    async fn run_pass_within(&mut self, bound: &PassBound) -> PassReport {
        self.memory.new_round();
        let mut report = PassReport::default();
        while !bound.ended() {
            match self.step_within(Some(bound), false).await {
                Step::Ran(summary) => {
                    report.quanta += 1;
                    if summary.outcome == RecoveryUnitOutcome::Advanced {
                        report.advanced += 1;
                    }
                }
                Step::Raced => {}
                // A bounded admission batch yielded with more immediate work.
                // Give it another scheduling step within this caller's bound.
                Step::Idle { next_due: Some(at) } if at <= self.host.now_seconds() => {}
                Step::Idle { .. } | Step::Stopped => break,
            }
        }
        report
    }

    async fn step_within(&mut self, pass: Option<&PassBound>, new_round: bool) -> Step {
        if self.cancel.is_cancelled() {
            return Step::Stopped;
        }
        self.note_reconnects();
        if let Some(step) = self.take_reconnects(pass).await {
            return step;
        }
        let admission::Drained {
            due: admission_due,
            stalled,
        } = match self.admit(pass).await {
            Ok(drained) => drained,
            Err(step) => return step,
        };
        let policy = self.policy;
        let suspended = Arc::clone(&self.suspended);
        let races = Arc::clone(&self.unwritten_races);
        let (mut survey, epoch_gap_due) = match self
            .debt_turn(pass, move |turn| {
                // Each row is written where what it records is: whatever
                // fails later in the turn, none of them is written again.
                let races =
                    std::mem::take(&mut *races.lock().unwrap_or_else(PoisonError::into_inner));
                let mut suspended = suspended.lock().unwrap_or_else(PoisonError::into_inner);
                if turn.audits {
                    for (group, row) in races {
                        (turn.audit)(group.as_deref(), row);
                    }
                    audit::suspensions(turn, &mut suspended);
                } else {
                    // The recorder keeps no rows: the first survey once it
                    // does records every route it finds suspended.
                    *suspended = None;
                }
                let due = epoch_gap::advance(turn, &policy, &stalled)?.next_due;
                let survey = select::survey(turn, &policy, &stalled)?;
                Ok((survey, due))
            })
            .await
        {
            None => return Step::Stopped,
            Some(Ok(surveyed)) => {
                self.survey_failures = 0;
                surveyed
            }
            Some(Err(error)) => {
                self.survey_failures = self.survey_failures.saturating_add(1);
                log_failure("survey", error);
                let hold = policy.local_failure_backoff_seconds(self.survey_failures);
                return Step::Idle {
                    next_due: sooner(
                        Some(self.host.now_seconds().saturating_add(hold)),
                        admission_due,
                    ),
                };
            }
        };
        let admission_due = sooner(admission_due, epoch_gap_due);
        self.host.surveyed(std::mem::take(&mut survey.catching_up));
        let now = self.host.now_seconds();
        if let Some(step) = self.report_pause(survey.paused_until, now).await {
            return step;
        }
        let mut hints = self.hints.borrow().clone();
        hints.held.append(&mut survey.fenced);
        hints.window.append(&mut survey.window);
        // A wake-collection process fetches only what its live input waits
        // on: the units of every route of a group whose frames a fence holds.
        // Other debt waits for an Advance process or an explicit repair.
        if !self.policy.fetches_unasked && pass.is_none_or(|bound| bound.repair_until.is_none()) {
            survey
                .candidates
                .retain(|candidate| hints.held.contains(&candidate.key.route));
            survey
                .rechecks
                .retain(|candidate| hints.held.contains(&candidate.key.route));
        }
        let candidate = match select::pick(survey, &mut self.memory, &hints, now, new_round) {
            Pick::Unit(candidate) => candidate,
            Pick::Idle { next_due } => {
                return Step::Idle {
                    next_due: sooner(next_due, admission_due),
                };
            }
        };
        let credit = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Step::Stopped,
            () = pass_end(pass) => return Step::Idle { next_due: None },
            credit = recovery_credits::acquire_recovery_credit(&self.credits) => credit,
        };
        let fenced = hints.held.contains(&candidate.key.route);
        let step = self.quantum(candidate, pass, fenced).await;
        drop(credit);
        step
    }

    /// Begin, run, stage and settle one quantum on `candidate`, holding a
    /// credit. `fenced` says a fence holds its group's live frames.
    async fn quantum(
        &mut self,
        candidate: Candidate,
        pass: Option<&PassBound>,
        fenced: bool,
    ) -> Step {
        if candidate.recheck {
            return self.recheck(candidate, pass).await;
        }
        let policy = self.policy;
        let caps = match self
            .bounded(pass, self.host.relay_caps(&candidate.key.relay))
            .await
        {
            Ok(caps) => caps,
            Err(step) => return step,
        };
        let key = candidate.key.clone();
        let best_effort = candidate.best_effort;
        let compares = self.memory.compares(&key.relay);
        let open = self.open.clone();
        let repair = pass.is_some_and(|bound| bound.repair_until.is_some());
        let (plan, fetch_audit) = match self
            .debt_turn(pass, move |turn| {
                let plan = select::begin(turn, &key, best_effort, caps, compares, &policy);
                // A best-effort relay is charged nothing.
                if let Ok(Some(plan)) = &plan
                    && !plan.best_effort
                {
                    open.begun(&plan.key, AttemptKind::Debt);
                }
                Ok(plan?.map(|plan| {
                    let fetch_audit = turn
                        .routes
                        .iter()
                        .find(|route| turn.audits && route.route == key.route)
                        .and_then(|route| {
                            audit::FetchAudit::new(
                                route,
                                &key.relay,
                                best_effort,
                                plan.compare.is_some(),
                                audit::debt_purpose(turn, route, repair, fenced),
                                !best_effort && audit::probing(plan.prior.as_ref()),
                                &plan.ranges,
                            )
                        });
                    (plan, fetch_audit)
                }))
            })
            .await
        {
            None => return Step::Stopped,
            Some(Ok(Some(begun))) => begun,
            Some(Ok(None)) => return self.raced(&candidate),
            Some(Err(error)) => {
                log_failure("begin", error);
                let outcome = RecoveryUnitOutcome::LocalFailure;
                let now = self.host.now_seconds();
                self.memory
                    .settled(&candidate, None, outcome, now, &self.policy);
                return Step::Ran(QuantumSummary {
                    key: candidate.key,
                    best_effort,
                    outcome,
                    recheck: false,
                });
            }
        };
        let started = Instant::now();
        let deadline = started + policy.quantum;
        let ranges = plan.ranges.len();
        tracing::debug!(target: TARGET, method = "attempt_started",
            recheck = false, best_effort, ranges);

        // The pass's end preempts the quantum as shutdown does. The sweep's
        // own deadline stays the quantum's, so a cut pass reads as a
        // preemption, never as the relay's verdict.
        let preempt = self.cancel.child_token();
        let (report, facts) = {
            let host = &*self.host;
            let run = async {
                match &plan.compare {
                    Some(compared) => {
                        let (report, facts) =
                            compare::run(host, compared, deadline, &preempt, &policy).await;
                        (report, Some(facts))
                    }
                    None => {
                        let caps = plan.caps.unwrap_or_default();
                        let report =
                            quantum::run(host, &plan, caps, deadline, &preempt, &policy).await;
                        (report, None)
                    }
                }
            };
            tokio::pin!(run);
            tokio::select! {
                ran = &mut run => ran,
                () = pass_end(pass) => {
                    preempt.cancel();
                    run.await
                }
            }
        };
        let report = preempted_by_transport_stop(&*self.host, report);
        if let (Some(compared), Some(facts)) = (&plan.compare, facts)
            && compare::would_not_compare(compared, facts.end)
        {
            self.memory.would_not_compare(&candidate.key.relay);
        }
        let open = self.open.clone();
        let fetched = audit::FetchResult {
            outcome: RecoveryUnitOutcome::LocalFailure,
            end: facts.map_or(audit::sweep_end(report.end), |facts| {
                audit::compare_end(facts.end)
            }),
            duration_ms: elapsed_ms(started),
            late_findings: 0,
            raced: self.races.take(&candidate.key.route),
        };
        let group = candidate.group_id.clone();
        let outcome = match self
            .host
            .turn(move |turn| {
                let settled = quantum::settle(turn, &plan, &report, &policy);
                // A settle that failed left its charge for a stop to refund.
                if settled.is_ok() {
                    open.settled(&plan.key);
                }
                let outcome = settled.as_ref().ok().map(|(outcome, _)| *outcome);
                if let Some(fetch_audit) = fetch_audit {
                    let outcome = outcome.unwrap_or(fetched.outcome);
                    fetch_audit.record(
                        turn.audit,
                        &report,
                        audit::FetchResult { outcome, ..fetched },
                    );
                }
                if let Ok((_, Some(after))) = &settled {
                    audit::unit_changed(turn.audit, group.as_deref(), plan.prior.as_ref(), after);
                }
                settled.map(|(outcome, _)| outcome)
            })
            .await
        {
            None => return Step::Stopped,
            Some(Ok(outcome)) => outcome,
            Some(Err(error)) => {
                log_failure("settle", error);
                RecoveryUnitOutcome::LocalFailure
            }
        };
        let now = self.host.now_seconds();
        self.memory
            .settled(&candidate, Some(&report), outcome, now, &self.policy);
        tracing::debug!(
            target: TARGET,
            method = "quantum",
            outcome = outcome_label(outcome),
            end = facts.map_or(quantum::end_label(report.end), |facts| facts.end.label()),
            compared = facts.is_some(),
            best_effort,
            ranges,
            requests = report.requests,
            answers = report.answers,
            newly_covered_seconds = report.newly_covered_seconds,
            proved_events = report.proved_events,
        );
        Step::Ran(QuantumSummary {
            key: candidate.key,
            best_effort,
            outcome,
            recheck: false,
        })
    }

    /// Begin, run, stage and settle one re-check quantum on `candidate`,
    /// holding a credit.
    async fn recheck(&mut self, candidate: Candidate, pass: Option<&PassBound>) -> Step {
        let policy = self.policy;
        let caps = match self
            .bounded(pass, self.host.relay_caps(&candidate.key.relay))
            .await
        {
            Ok(caps) => caps,
            Err(step) => return step,
        };
        let key = candidate.key.clone();
        let open = self.open.clone();
        let (plan, fetch_audit) = match self
            .debt_turn(pass, move |turn| {
                let plan = recheck::begin(turn, &key, caps, &policy);
                if let Ok(Some(plan)) = &plan {
                    open.begun(&plan.compare.key, AttemptKind::Recheck);
                }
                Ok(plan?.map(|plan| {
                    let ranges = plan
                        .compare
                        .ranges
                        .iter()
                        .map(|planned| planned.range)
                        .collect::<Vec<_>>();
                    let fetch_audit = turn
                        .routes
                        .iter()
                        .find(|route| route.route == key.route)
                        .and_then(|route| {
                            audit::FetchAudit::new(
                                route,
                                &key.relay,
                                false,
                                true,
                                marmot_forensics::RecoveryRunnerPurpose::Recheck,
                                false,
                                &ranges,
                            )
                        });
                    (plan, fetch_audit)
                }))
            })
            .await
        {
            None => return Step::Stopped,
            Some(Ok(Some(begun))) => begun,
            Some(Ok(None)) => return self.raced(&candidate),
            Some(Err(error)) => {
                log_failure("recheck_begin", error);
                let outcome = RecoveryUnitOutcome::LocalFailure;
                let now = self.host.now_seconds();
                self.memory
                    .recheck_settled(&candidate.key, false, outcome, now, &self.policy);
                return Step::Ran(QuantumSummary {
                    key: candidate.key,
                    best_effort: false,
                    outcome,
                    recheck: true,
                });
            }
        };
        let started = Instant::now();
        let deadline = started + policy.quantum;
        let ranges = plan.compare.ranges.len();
        tracing::debug!(target: TARGET, method = "attempt_started",
            recheck = true, best_effort = false, ranges);

        let preempt = self.cancel.child_token();
        let (report, facts) = {
            let run = compare::run(&*self.host, &plan.compare, deadline, &preempt, &policy);
            tokio::pin!(run);
            tokio::select! {
                ran = &mut run => ran,
                () = pass_end(pass) => {
                    preempt.cancel();
                    run.await
                }
            }
        };
        let report = preempted_by_transport_stop(&*self.host, report);
        if compare::would_not_compare(&plan.compare, facts.end) {
            self.memory.would_not_compare(&candidate.key.relay);
        }
        let open = self.open.clone();
        let fetched = audit::FetchResult {
            outcome: RecoveryUnitOutcome::LocalFailure,
            end: audit::compare_end(facts.end),
            duration_ms: elapsed_ms(started),
            late_findings: facts.late,
            raced: self.races.take(&candidate.key.route),
        };
        let settled = match self
            .host
            .turn(move |turn| {
                let settled = recheck::settle(turn, &plan, &report, &facts, &policy);
                // A failed progress write after a committed settle leaves the
                // key open too; its refund finds the attempt settled and
                // changes nothing.
                if settled.is_ok() {
                    open.settled(&plan.compare.key);
                }
                if let Some(fetch_audit) = fetch_audit {
                    let outcome = settled
                        .as_ref()
                        .map_or(fetched.outcome, |settled| settled.outcome);
                    fetch_audit.record(
                        turn.audit,
                        &report,
                        audit::FetchResult { outcome, ..fetched },
                    );
                }
                settled
            })
            .await
        {
            None => return Step::Stopped,
            Some(Ok(settled)) => settled,
            Some(Err(error)) => {
                log_failure("recheck_settle", error);
                recheck::RecheckSettled {
                    outcome: RecoveryUnitOutcome::LocalFailure,
                    complete: false,
                    moved: false,
                }
            }
        };
        let now = self.host.now_seconds();
        self.memory.recheck_settled(
            &candidate.key,
            settled.moved,
            settled.outcome,
            now,
            &self.policy,
        );
        self.signals
            .late_findings
            .fetch_add(facts.late, Ordering::Relaxed);
        LATE_FINDINGS.fetch_add(facts.late, Ordering::Relaxed);
        tracing::debug!(
            target: TARGET,
            method = "recheck",
            outcome = outcome_label(settled.outcome),
            end = facts.end.label(),
            complete = settled.complete,
            ranges,
            requests = report.requests,
            answers = report.answers,
            proved_seconds = report.proved_seconds,
            late_findings = facts.late,
        );
        Step::Ran(QuantumSummary {
            key: candidate.key,
            best_effort: false,
            outcome: settled.outcome,
            recheck: true,
        })
    }

    /// The begin turn found `candidate` owing nothing, or no longer eligible:
    /// count the race on its route. When this race ends the route's window
    /// ([`audit::Races`]), the coalesced row waits for the next survey turn;
    /// a row a stop loses changes nothing else.
    fn raced(&mut self, candidate: &Candidate) -> Step {
        let route = &candidate.key.route;
        if let Some(row) = self.races.raced(route, self.host.now_seconds()) {
            self.unwritten_races
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((candidate.group_id.clone(), row));
        }
        Step::Raced
    }

    /// Handle relay reconnects: each one's cooldown ends and its caps are read
    /// again (a known change re-arms the units planned with other caps). The
    /// survey that follows reads fresh tails, so a reconnect's new tail, which
    /// starts at its EOSE, leaves the downtime owed as ordinary sweep debt.
    /// A shutdown or the pass's end during a caps read leaves that relay
    /// and the rest for the next step. Returns the step to end with, if any.
    async fn take_reconnects(&mut self, pass: Option<&PassBound>) -> Option<Step> {
        let mut relays = std::mem::take(&mut *self.reconnected());
        while let Some(relay) = relays.pop_first() {
            let caps = match self.bounded(pass, self.host.relay_caps(&relay)).await {
                Ok(caps) => caps.map(recovery_caps),
                Err(step) => {
                    relays.insert(relay);
                    self.reconnected().append(&mut relays);
                    return Some(step);
                }
            };
            let written = relay.clone();
            let policy = self.policy;
            let recorded = self
                .host
                .turn(move |turn| {
                    turn.app
                        .record_recovery_relay_reconnected(&written, &policy.unit, turn.now)?;
                    if caps.is_some() {
                        let rearmed = turn
                            .app
                            .record_recovery_relay_caps(&written, caps, turn.now)?;
                        audit::rearmed(
                            turn.audit,
                            RecoveryRunnerChange::CapsRearmed,
                            Some(&written),
                            rearmed as u64,
                        );
                    }
                    Ok::<_, cgka_traits::storage::StorageError>(())
                })
                .await;
            match recorded {
                None => return Some(Step::Stopped),
                Some(Err(error)) => {
                    // Retried on the local-failure backoff (`retry_reconnects_by`).
                    log_failure("relay_reconnected", error);
                    self.reconnect_failures = self.reconnect_failures.saturating_add(1);
                    self.reconnected().insert(relay);
                }
                Some(Ok(())) => {
                    self.reconnect_failures = 0;
                    self.memory.relay_reconnected(&relay);
                }
            }
        }
        None
    }

    /// Add the relays the pool has connected again since the last look to
    /// the reconnects. The first look, once the host has a pool, only takes
    /// the generations it publishes then: a connection made before it ends
    /// no cooldown, as one made before the runner was built never did.
    fn note_reconnects(&mut self) {
        let moved = match self.connections.as_mut() {
            Some(connections) => connections.moved(),
            None => {
                self.connections = self.host.relay_connections().map(|feed| {
                    let mut connections = Connections {
                        feed,
                        seen: BTreeMap::new(),
                    };
                    connections.moved();
                    connections
                });
                return;
            }
        };
        if !moved.is_empty() {
            self.reconnected().extend(moved);
        }
    }

    /// When an idle task wakes: at `next_due`, or sooner while a reconnect
    /// waits to be recorded, on the local-failure backoff. Its relay's units
    /// may all be cooling or broken, waiting for exactly that write.
    fn retry_reconnects_by(&self, next_due: Option<u64>) -> Option<u64> {
        if self.reconnected().is_empty() {
            return next_due;
        }
        let retry = self.host.now_seconds().saturating_add(
            self.policy
                .local_failure_backoff_seconds(self.reconnect_failures),
        );
        Some(next_due.map_or(retry, |due| due.min(retry)))
    }

    fn reconnected(&self) -> std::sync::MutexGuard<'_, BTreeSet<String>> {
        self.signals
            .reconnected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Await `read` off the worker unless the runner shuts down or the pass
    /// ends first.
    async fn bounded<T>(
        &self,
        pass: Option<&PassBound>,
        read: impl std::future::Future<Output = T>,
    ) -> Result<T, Step> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(Step::Stopped),
            () = pass_end(pass) => Err(Step::Idle { next_due: None }),
            value = read => Ok(value),
        }
    }

    /// The account breaker: a cap pauses the runner until the window rolls,
    /// and changes no unit. Each pause is reported once, as a bug signal: a
    /// warning, the process count, and an audit row with the hour's usage
    /// read in a worker turn. A failed turn loses only the row. Returns the
    /// step to end with, if any.
    async fn report_pause(&mut self, paused_until: Option<u64>, now: u64) -> Option<Step> {
        let Some(until) = paused_until else {
            self.reported_pause = None;
            return None;
        };
        if self.reported_pause == Some(until) {
            return None;
        }
        self.reported_pause = Some(until);
        let pauses = ACCOUNT_PAUSES
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let paused_for_secs = until.saturating_sub(now);
        tracing::warn!(
            target: TARGET,
            method = "account_breaker",
            paused_for_seconds = paused_for_secs,
            "recovery paused at the account's hourly cap"
        );
        let unit = self.policy.unit;
        let recorded = self
            .host
            .turn(move |turn| {
                let usage = turn.app.recovery_account_usage(turn.now)?;
                let cap = match (
                    usage.attempts >= unit.max_attempts_per_hour,
                    usage.event_bytes >= unit.max_event_bytes_per_hour,
                ) {
                    (true, true) => RecoveryRunnerCap::Both,
                    (true, false) => RecoveryRunnerCap::Attempts,
                    (false, true) => RecoveryRunnerCap::EventBytes,
                    // A refund since the survey lifted the pause already.
                    (false, false) => return Ok(()),
                };
                (turn.audit)(
                    None,
                    AuditEventKind::RecoveryRunnerPaused {
                        cap,
                        attempts: usage.attempts,
                        event_bytes: usage.event_bytes,
                        paused_for_secs,
                        pauses,
                        late_findings: LATE_FINDINGS.load(Ordering::Relaxed),
                    },
                );
                Ok::<_, StorageError>(())
            })
            .await;
        match recorded {
            None => Some(Step::Stopped),
            Some(Err(error)) => {
                log_failure("account_breaker", error);
                None
            }
            Some(Ok(())) => None,
        }
    }
}

/// What `route` asks relays for: its group's `#h`, or the account inbox's
/// gift wraps by `inbox`, the account's key.
fn fetch_route(route: &TransportReconciliationRoute, inbox: [u8; 32]) -> SweepRoute {
    match route {
        TransportReconciliationRoute::Group(nostr_group_id) => SweepRoute::Group {
            nostr_group_id: *nostr_group_id,
        },
        TransportReconciliationRoute::Inbox => SweepRoute::Inbox { pubkey: inbox },
    }
}

fn recovery_caps(caps: RelayCaps) -> RecoveryRelayCaps {
    RecoveryRelayCaps {
        max_limit: caps.max_limit,
        negentropy: caps.negentropy,
    }
}

/// The earlier of two optional due times.
fn sooner(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (due, None) | (None, due) => due,
    }
}

async fn sleep_for(duration: Option<Duration>) {
    match duration {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}

/// Milliseconds since `started`, for an audit row.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Once `pass` ends; never without one.
async fn pass_end(pass: Option<&PassBound>) {
    match pass {
        Some(pass) => pass.reached().await,
        None => std::future::pending().await,
    }
}

fn outcome_label(outcome: RecoveryUnitOutcome) -> &'static str {
    match outcome {
        RecoveryUnitOutcome::Advanced => "advanced",
        RecoveryUnitOutcome::NothingOwed => "nothing_owed",
        RecoveryUnitOutcome::NoProgress => "no_progress",
        RecoveryUnitOutcome::Unreachable => "unreachable",
        RecoveryUnitOutcome::RateLimited => "rate_limited",
        RecoveryUnitOutcome::Refused => "refused",
        RecoveryUnitOutcome::Unanswered => "unanswered",
        RecoveryUnitOutcome::LocalFailure => "local_failure",
    }
}

fn log_failure(method: &'static str, error: StorageError) {
    tracing::warn!(
        target: TARGET,
        method = method,
        error_kind = AppError::from(error).privacy_safe_kind(),
        "recovery runner turn failed"
    );
}
