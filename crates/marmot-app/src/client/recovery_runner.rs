//! The recovery runner (mdk#2660 phase 4): one task per account that owns
//! history recovery scheduling over the coverage ledger and its durable retry
//! state.
//!
//! It is built but not started. No production path constructs, wakes or reads
//! it until the switch-over (PR 5), so the comparison owner in `recovery.rs`
//! keeps every behavior and the ledger stays in shadow mode. Tests construct
//! and drive it.
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
//! Debt units are one per (group route, required relay) (decision 3), plus
//! one attempt per new debt on each best-effort relay. A unit compares instead
//! of sweeping when its relay compares and the account already holds events
//! in the owed ranges. Once no debt unit is eligible, re-check units
//! ([`recheck`]) compare each required NIP-77 relay's covered and retired
//! ranges again, on their own schedule.
//!
//! Each step first admits what staging may release ([`admission`]): per MLS
//! group, oldest first, up to its admission frontier. The same reads hold back
//! a relay staging is full for, block every unit of a group admission cannot
//! drain, and serve fenced groups first.
//!
//! Live tails are a query, never a stored value ([`tails`]): the select and
//! begin turns each read them fresh, and nothing keeps an answer across an
//! await, a quantum or a wake.
//!
//! Logs carry aggregates only: no route, relay, group or account identity.
#![cfg_attr(not(test), allow(dead_code))]

mod admission;
mod compare;
mod policy;
mod quantum;
mod recheck;
mod select;
mod tails;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportDelivery;
use nostr::prelude::Event;
use storage_sqlite::{
    RecoveryRelayCaps, RecoveryUnitOutcome, SqliteAppStorage, TransportReconciliationRoute,
};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use transport_nostr_adapter::compare::CompareRelay;
use transport_nostr_adapter::sweep::{RelayCaps, SweepRelay};

pub(crate) use admission::{Admitted, LiveCount, LiveFence};
pub(crate) use policy::RecoveryRunnerPolicy;
pub(crate) use tails::LiveTailRead;

use crate::AppError;
use crate::runtime::account_worker::recovery_credits::{self, RecoveryCreditPool};
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
}

/// Routes the caller wants served first. Not `Debug`: it carries routes.
#[derive(Clone, Default)]
pub(crate) struct PriorityHints {
    /// Groups whose live frames are held behind a fence. Each survey adds
    /// the routes its own fences hold.
    pub(crate) held: BTreeSet<TransportReconciliationRoute>,
    /// Groups with an open conversation window (PR 5 feeds this).
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
}

/// What a turn that reads debt sees: the account's current routes, and the
/// live tails and live counts read for this turn alone.
pub(crate) struct DebtTurn<'a> {
    pub(crate) app: &'a SqliteAppStorage,
    /// The account's current routes, as of this turn.
    pub(crate) routes: &'a [RunnerRoute],
    pub(crate) now: u64,
    pub(crate) tails: &'a dyn LiveTailRead,
    /// The open live REQs' counts, for the fence.
    pub(crate) live_counts: &'a [LiveCount],
}

/// What one account gives its runner. Turns run on the account worker (PR 5
/// sends each as a worker command) and must stay short: storage reads and
/// writes, no awaiting. Everything else runs off the worker.
#[async_trait]
pub(crate) trait RunnerHost: Send + Sync + 'static {
    /// Run `turn` on the worker. `None` once the worker is gone.
    async fn turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&WorkerTurn<'_>) -> T + Send + 'static,
        T: Send + 'static;

    /// Run `turn` on the worker with the live tails and live counts read at
    /// its start ([`AppClient::recovery_runner_live_tails`](crate::client::AppClient)).
    async fn debt_turn<T, F>(&self, turn: F) -> Option<T>
    where
        F: FnOnce(&DebtTurn<'_>) -> T + Send + 'static,
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
    /// `reconciled_deliveries`); nothing when it routes nowhere or is invalid.
    async fn deliveries(&self, relay: &str, event: Event) -> Vec<TransportDelivery>;

    /// Hand one staged delivery to the account's recovered-ingest path, as
    /// one worker command. `None` once the worker is gone; an error is its
    /// privacy-safe kind.
    async fn admit_staged(
        &self,
        delivery: TransportDelivery,
    ) -> Option<Result<Admitted, &'static str>>;

    /// Unix seconds.
    fn now_seconds(&self) -> u64;
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

/// Wake signals other than the coalescing watch, and the runner's aggregate
/// counts.
#[derive(Default)]
struct Signals {
    /// Relays that reconnected since the runner last looked.
    reconnected: Mutex<BTreeSet<String>>,
    /// Events re-checks found inside ranges already covered (PR 5 exports it).
    late_findings: AtomicU64,
}

/// The caller's side of a runner: wake it, steer it, stop it.
pub(crate) struct RecoveryRunnerHandle {
    wake: watch::Sender<u64>,
    hints: watch::Sender<PriorityHints>,
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

    /// Events re-checks have found inside ranges already covered, since the
    /// runner was built. An aggregate count, privacy-safe.
    pub(crate) fn late_findings(&self) -> u64 {
        self.signals.late_findings.load(Ordering::Relaxed)
    }
}

/// One account's runner.
pub(crate) struct RecoveryRunner<H> {
    host: Arc<H>,
    policy: RecoveryRunnerPolicy,
    credits: Arc<RecoveryCreditPool>,
    signals: Arc<Signals>,
    wake: watch::Receiver<u64>,
    hints: watch::Receiver<PriorityHints>,
    cancel: CancellationToken,
    memory: Memory,
    admission: admission::Memory,
    /// Surveys that failed in a row, for the runner's own local backoff.
    survey_failures: u32,
    /// Reconnect writes that failed in a row, likewise.
    reconnect_failures: u32,
    /// The account breaker's pause last reported, so each pause logs once.
    reported_pause: Option<u64>,
}

impl<H: RunnerHost> RecoveryRunner<H> {
    pub(crate) fn new(
        host: Arc<H>,
        policy: RecoveryRunnerPolicy,
        credits: Arc<RecoveryCreditPool>,
    ) -> (Self, RecoveryRunnerHandle) {
        let (wake_tx, wake) = watch::channel(0);
        let (hints_tx, hints) = watch::channel(PriorityHints::default());
        let signals = Arc::new(Signals::default());
        let cancel = CancellationToken::new();
        let runner = Self {
            host,
            policy,
            credits,
            signals: signals.clone(),
            wake,
            hints,
            cancel: cancel.clone(),
            memory: Memory::default(),
            admission: admission::Memory::default(),
            survey_failures: 0,
            reconnect_failures: 0,
            reported_pause: None,
        };
        let handle = RecoveryRunnerHandle {
            wake: wake_tx,
            hints: hints_tx,
            signals,
            cancel,
        };
        (runner, handle)
    }

    /// Run the account's task until it is shut down or its worker is gone.
    pub(crate) fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run())
    }

    async fn run(mut self) {
        loop {
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
                changed = self.wake.changed() => if changed.is_err() { break },
                changed = self.hints.changed() => if changed.is_err() { break },
                () = sleep_for(sleep) => {}
            }
        }
        tracing::debug!(target: TARGET, method = "run", "recovery runner stopped");
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
        let deadline = Instant::now() + budget;
        self.memory.new_round();
        let mut report = PassReport::default();
        while Instant::now() < deadline {
            match self.step_within(Some(deadline), false).await {
                Step::Ran(summary) => {
                    report.quanta += 1;
                    if summary.outcome == RecoveryUnitOutcome::Advanced {
                        report.advanced += 1;
                    }
                }
                Step::Raced => {}
                Step::Idle { .. } | Step::Stopped => break,
            }
        }
        report
    }

    async fn step_within(&mut self, pass_deadline: Option<Instant>, new_round: bool) -> Step {
        if self.cancel.is_cancelled() {
            return Step::Stopped;
        }
        if let Some(step) = self.take_reconnects(pass_deadline).await {
            return step;
        }
        let admission::Drained {
            due: admission_due,
            stalled,
        } = match self.admit(pass_deadline).await {
            Ok(drained) => drained,
            Err(step) => return step,
        };
        let policy = self.policy;
        let mut survey = match self
            .host
            .debt_turn(move |turn| select::survey(turn, &policy, &stalled))
            .await
        {
            None => return Step::Stopped,
            Some(Ok(survey)) => {
                self.survey_failures = 0;
                survey
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
        let now = self.host.now_seconds();
        self.report_pause(survey.paused_until, now);
        let mut hints = self.hints.borrow().clone();
        hints.held.append(&mut survey.fenced);
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
            () = sleep_until(pass_deadline) => return Step::Idle { next_due: None },
            credit = recovery_credits::acquire_recovery_credit(&self.credits) => credit,
        };
        let step = self.quantum(candidate, pass_deadline).await;
        drop(credit);
        step
    }

    /// Begin, run, stage and settle one quantum on `candidate`, holding a
    /// credit.
    async fn quantum(&mut self, candidate: Candidate, pass_deadline: Option<Instant>) -> Step {
        if candidate.recheck {
            return self.recheck(candidate, pass_deadline).await;
        }
        let policy = self.policy;
        let caps = match self
            .bounded(pass_deadline, self.host.relay_caps(&candidate.key.relay))
            .await
        {
            Ok(caps) => caps,
            Err(step) => return step,
        };
        let key = candidate.key.clone();
        let best_effort = candidate.best_effort;
        let compares = self.memory.compares(&key.relay);
        let plan = match self
            .host
            .debt_turn(move |turn| select::begin(turn, &key, best_effort, caps, compares, &policy))
            .await
        {
            None => return Step::Stopped,
            Some(Ok(Some(plan))) => plan,
            Some(Ok(None)) => return Step::Raced,
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
        let deadline = Instant::now() + policy.quantum;
        let ranges = plan.ranges.len();
        // The pass deadline preempts the quantum as shutdown does. The sweep's
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
                        let caps = caps.unwrap_or_default();
                        let report =
                            quantum::run(host, &plan, caps, deadline, &preempt, &policy).await;
                        (report, None)
                    }
                }
            };
            tokio::pin!(run);
            tokio::select! {
                ran = &mut run => ran,
                () = sleep_until(pass_deadline) => {
                    preempt.cancel();
                    run.await
                }
            }
        };
        if facts.is_some_and(|facts| compare::would_not_compare(facts.end)) {
            self.memory.would_not_compare(&candidate.key.relay);
        }
        let outcome = match self
            .host
            .turn(move |turn| quantum::settle(turn, &plan, &report, &policy))
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
    async fn recheck(&mut self, candidate: Candidate, pass_deadline: Option<Instant>) -> Step {
        let policy = self.policy;
        let caps = match self
            .bounded(pass_deadline, self.host.relay_caps(&candidate.key.relay))
            .await
        {
            Ok(caps) => caps,
            Err(step) => return step,
        };
        let key = candidate.key.clone();
        let plan = match self
            .host
            .debt_turn(move |turn| recheck::begin(turn, &key, caps, &policy))
            .await
        {
            None => return Step::Stopped,
            Some(Ok(Some(plan))) => plan,
            Some(Ok(None)) => return Step::Raced,
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
        let deadline = Instant::now() + policy.quantum;
        let ranges = plan.compare.ranges.len();
        let preempt = self.cancel.child_token();
        let (report, facts) = {
            let run = compare::run(&*self.host, &plan.compare, deadline, &preempt, &policy);
            tokio::pin!(run);
            tokio::select! {
                ran = &mut run => ran,
                () = sleep_until(pass_deadline) => {
                    preempt.cancel();
                    run.await
                }
            }
        };
        if compare::would_not_compare(facts.end) {
            self.memory.would_not_compare(&candidate.key.relay);
        }
        let settled = match self
            .host
            .turn(move |turn| recheck::settle(turn, &plan, &report, &facts, &policy))
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

    /// Handle relay reconnects: each one's cooldown ends and its caps are read
    /// again (a known change re-arms the units planned with other caps). The
    /// survey that follows reads fresh tails, so a reconnect's new tail, which
    /// starts at its EOSE, leaves the downtime owed as ordinary sweep debt.
    /// A shutdown or the pass deadline during a caps read leaves that relay
    /// and the rest for the next step. Returns the step to end with, if any.
    async fn take_reconnects(&mut self, pass_deadline: Option<Instant>) -> Option<Step> {
        let mut relays = std::mem::take(&mut *self.reconnected());
        while let Some(relay) = relays.pop_first() {
            let caps = match self
                .bounded(pass_deadline, self.host.relay_caps(&relay))
                .await
            {
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
                        turn.app
                            .record_recovery_relay_caps(&written, caps, turn.now)?;
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
    /// deadline comes first.
    async fn bounded<T>(
        &self,
        pass_deadline: Option<Instant>,
        read: impl std::future::Future<Output = T>,
    ) -> Result<T, Step> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(Step::Stopped),
            () = sleep_until(pass_deadline) => Err(Step::Idle { next_due: None }),
            value = read => Ok(value),
        }
    }

    /// The account breaker: a cap pauses the runner until the window rolls,
    /// and changes no unit. Each pause is reported once, as a bug signal.
    fn report_pause(&mut self, paused_until: Option<u64>, now: u64) {
        match paused_until {
            Some(until) if self.reported_pause != Some(until) => {
                self.reported_pause = Some(until);
                tracing::warn!(
                    target: TARGET,
                    method = "account_breaker",
                    paused_for_seconds = until.saturating_sub(now),
                    "recovery paused at the account's hourly cap"
                );
            }
            Some(_) => {}
            None => self.reported_pause = None,
        }
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

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
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

fn log_failure(method: &'static str, error: cgka_traits::storage::StorageError) {
    tracing::warn!(
        target: TARGET,
        method = method,
        error_kind = AppError::from(error).privacy_safe_kind(),
        "recovery runner turn failed"
    );
}
