//! Explicit repair through the runner (mdk#2660 phase 4, plan row 6), behind
//! the internal `runner_owns_debt` gate: one request the account's runner
//! owns from start to verdict, judged from the ledger with today's verdicts.
//!
//! - **The request.** The caller refreshes its routes, then hands the runner
//!   one repair ([`RecoveryRunner::repair`]) under a [`PassBound`]: the
//!   repair's deadline and a stop the caller trips on cancel. A spawned
//!   runner takes it between its own steps; an in-place one runs it as the
//!   caller's future. Either way the caller only serves the runner's turns
//!   meanwhile ([`AppClient::repair_through_recovery_runner`]).
//! - **The re-arm**, the request's first debt turn, at a step boundary: every
//!   current route's goal widens to the retention floor, and every unit is
//!   re-armed (`rearm_all_recovery_units`): active with a fresh budget, every
//!   parked and retired span owed again, every re-check due. The runner's own
//!   holds go too. No quantum is in flight, so no settle can undo it. The
//!   parked routes' notices go with their parks.
//! - **The passes.** Each pass serves every due unit once, until the bound
//!   ends. Its end preempts a quantum in flight as the pass deadline does: the
//!   request interrupts and settles, so what it read is charged.
//! - **The verdict**, a debt turn after each pass: every current route's
//!   window covered and admitted on each of its required relays, none of
//!   whose units broke or was dismissed since, and re-checked since the
//!   re-arm on each that compares ([`repaired`]), is `BelowRetentionWindow`:
//!   what is left lies below the window, where no pass can search. The repair
//!   never succeeds outright, as today. Otherwise the caller or the budget
//!   ends it (`Cancelled`, `Deadline`), or a pass that served nothing within
//!   the bound means the runner can do no more now (`CoverageUnproven`). As
//!   today, the caller's cancel wins even over a covered window, and a
//!   covered window over the deadline ([`verdict_end`]). The
//!   repair keeps no request of its own: the re-arm and the goals are what
//!   the runner serves.

use std::time::Duration;

use cgka_traits::storage::StorageResult;
use marmot_observability::SyncFailureStage;
use storage_sqlite::{RecoveryUnitState, TRANSPORT_RECONCILIATION_RETENTION_SECS};
use tokio::time::Instant;

use super::compare::recorded_caps;
use super::host::SpawnedRunner;
use super::{DebtTurn, PassBound, RecoveryRunner, RepairEnd, RunnerHost, TARGET};
use crate::client::AppClient;
use crate::client::sync::incomplete_full_history_repair;
use crate::{
    AppError, ClassifiedSyncFailure, FullHistoryRepairIncompleteReason as Reason, SyncSummary,
};

impl AppClient {
    /// Whether explicit repair runs through a runner: `spawned`, the worker's,
    /// or this client's in-place one. Only with the internal `runner_owns_debt`
    /// gate on.
    pub(crate) fn repairs_through_runner(&self, spawned: Option<&SpawnedRunner>) -> bool {
        spawned.is_some() || self.has_in_place_recovery_runner()
    }

    /// Hand the account's runner one explicit repair within `timeout`, until
    /// `cancelled` says so, and serve its turns meanwhile. Never `Ok`, as
    /// today: a covered window is `BelowRetentionWindow`.
    pub(crate) async fn repair_full_history_through_runner(
        &mut self,
        cancelled: &(dyn Fn() -> bool + Sync),
        timeout: Duration,
        spawned: Option<&mut SpawnedRunner>,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let bound = PassBound::within(timeout);
        let state_persist = |summary: SyncSummary, error: AppError| {
            ClassifiedSyncFailure::at_stage(summary, error, SyncFailureStage::StatePersist)
        };
        if cancelled() {
            return Err(self.incomplete_repair(Reason::Cancelled));
        }
        if self
            .refresh_sync_routes()
            .map_err(|error| state_persist(SyncSummary::default(), error))?
        {
            // The live subscriptions follow the route change later; the runner
            // reads the refreshed routes without touching them.
            self.pending_runtime_group_subscription_refresh = true;
        }
        let reason = match self
            .repair_through_recovery_runner(spawned, bound, cancelled)
            .await
        {
            RepairEnd::Covered => Reason::BelowRetentionWindow,
            RepairEnd::Unproven => Reason::CoverageUnproven,
            RepairEnd::Deadline => Reason::Deadline,
            // The runner is gone with its worker, as when the caller stops.
            RepairEnd::Cancelled | RepairEnd::Stopped => Reason::Cancelled,
            RepairEnd::Failed(error) => {
                return Err(state_persist(
                    self.take_pending_applied_sync_summary(),
                    error.into(),
                ));
            }
        };
        Err(self.incomplete_repair(reason))
    }

    fn incomplete_repair(&mut self, reason: Reason) -> ClassifiedSyncFailure {
        incomplete_full_history_repair(
            self.take_pending_applied_sync_summary(),
            reason,
            self.delivery_loss_blocks_cursor(),
        )
    }

    /// [`repaired`] over this client's routes and live tails, as a debt turn
    /// would read it.
    #[cfg(test)]
    pub(super) async fn repaired_window(
        &self,
        app: &storage_sqlite::SqliteAppStorage,
        requested: u64,
    ) -> StorageResult<bool> {
        let now = super::host::unix_now();
        let tails = self.recovery_runner_live_tails(app, now).await;
        let routes = self.recovery_runner_routes();
        repaired(
            &DebtTurn {
                app,
                routes: &routes,
                inbox: [0; 32],
                now,
                tails: &*tails,
                live_counts: &[],
            },
            requested,
        )
    }
}

impl<H: RunnerHost> RecoveryRunner<H> {
    /// Serve one explicit repair at this step boundary: re-arm, then passes
    /// until the ledger shows the window repaired, a pass serves nothing, or
    /// `bound` ends. Nothing else this runner does interleaves: its own steps
    /// wait until the repair ends. A repair taken after its bound ended
    /// re-arms nothing.
    pub(crate) async fn repair(&mut self, bound: &PassBound) -> RepairEnd {
        if bound.stop.is_cancelled() {
            return RepairEnd::Cancelled;
        }
        if Instant::now() >= bound.deadline {
            return RepairEnd::Deadline;
        }
        let requested = match self.host.debt_turn(rearm).await {
            None => return RepairEnd::Stopped,
            Some(Err(error)) => return RepairEnd::Failed(error),
            Some(Ok(requested)) => requested,
        };
        self.memory.rearmed();
        loop {
            let report = self.run_pass_within(bound).await;
            if self.cancel.is_cancelled() {
                return RepairEnd::Stopped;
            }
            let covered = match self
                .host
                .debt_turn(move |turn| repaired(turn, requested))
                .await
            {
                None => return RepairEnd::Stopped,
                Some(Err(error)) => return RepairEnd::Failed(error),
                Some(Ok(covered)) => covered,
            };
            if let Some(end) = verdict_end(bound, covered, report.quanta > 0) {
                return end;
            }
        }
    }
}

/// How a repair ends after a pass and its verdict, in today's order: the
/// caller's cancel, even over a covered window; then a covered window, even
/// past the deadline, as a pass that finished is judged on its routes; then
/// the deadline; then a pass that served nothing. `None` runs another pass.
fn verdict_end(bound: &PassBound, covered: bool, served: bool) -> Option<RepairEnd> {
    if bound.stop.is_cancelled() {
        Some(RepairEnd::Cancelled)
    } else if covered {
        Some(RepairEnd::Covered)
    } else if Instant::now() >= bound.deadline {
        Some(RepairEnd::Deadline)
    } else if !served {
        Some(RepairEnd::Unproven)
    } else {
        None
    }
}

/// The re-arm: every current route's goal widens to the retention floor,
/// then every unit is re-armed. Goals first: a re-arm that lands without them
/// owes no less. Returns when, the second every re-check must complete after.
fn rearm(turn: &DebtTurn<'_>) -> StorageResult<u64> {
    let routes = turn
        .routes
        .iter()
        .map(|route| route.route.clone())
        .collect::<Vec<_>>();
    turn.app.widen_recovery_coverage_goals(
        &routes,
        turn.now
            .saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS),
    )?;
    let rearmed = turn.app.rearm_all_recovery_units()?;
    tracing::debug!(
        target: TARGET,
        method = "repair",
        routes = routes.len(),
        rearmed = rearmed,
        "explicit repair re-armed every recovery unit"
    );
    Ok(turn.now)
}

/// Whether every current route's window is covered on each of its required
/// relays, up to their live tails, and re-checked since `requested` on each
/// whose recorded caps show NIP-77. A cap-only relay's count proofs cover,
/// but it is never re-checked (decision 2). A unit that broke or was
/// dismissed since the re-arm never is: its parked and retired spans are left
/// out of its debt, not covered. Nor is a route with staged events: staging
/// covers what it fetched, but the engine has not admitted them (each step
/// admits first, so a finished pass left them staged only because the engine
/// kept no trace of one).
pub(super) fn repaired(turn: &DebtTurn<'_>, requested: u64) -> StorageResult<bool> {
    let app = turn.app;
    let staged = app.staged_recovery_routes()?;
    for route in turn.routes {
        if staged.contains(&route.route) {
            return Ok(false);
        }
        for relay in &route.required {
            let unit = app.recovery_unit(&route.route, relay)?;
            if unit
                .as_ref()
                .is_some_and(|unit| unit.state != RecoveryUnitState::Active)
            {
                return Ok(false);
            }
            let owed_until = turn.tails.owed_until(&route.route, relay, turn.now);
            if !app
                .recovery_unit_debt(&route.route, relay, owed_until)?
                .is_empty()
            {
                return Ok(false);
            }
            if recorded_caps(app, relay)?.is_some()
                && !unit
                    .and_then(|unit| unit.recheck.completed_at_seconds)
                    .is_some_and(|at| at >= requested)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
