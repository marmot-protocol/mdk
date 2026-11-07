//! Bounded return visits authorized by unresolved durable epoch-gap demand.
//!
//! Reopening a retained goal lets the ordinary runner resume from its ledger
//! cursor. A visit advances this separate durable backoff only after each source
//! is covered or has failed off the admission frontier, at least one required
//! source completed its sweep, and the group's releasable staging drained. Failure never certifies
//! coverage; partial sweep progress cannot forgive the budget. Healthy periodic
//! re-checks remain NIP-77-only.

use cgka_traits::storage::StorageResult;
use storage_sqlite::{RecoveryCause, RecoveryEligibility, TRANSPORT_RECONCILIATION_RETENTION_SECS};

use super::admission::{Admission, Stalled};
use super::{DebtTurn, RecoveryRunnerPolicy, sooner};

/// A newly opened visit needs ordinary debt selection before more admission;
/// otherwise ready local history can keep draining in bounded worker batches.
#[derive(Default)]
pub(super) struct Advanced {
    pub(super) next_due: Option<u64>,
    pub(super) started: bool,
}

/// Prepare due return visits and report the earliest future one. This runs in
/// the existing runner's short worker turn, before selecting ordinary debt.
pub(super) fn advance(
    turn: &DebtTurn<'_>,
    policy: &RecoveryRunnerPolicy,
    stalled: &Stalled,
) -> StorageResult<Advanced> {
    let app = turn.app;
    let mut admission = Admission::new(turn);
    let mut next = None;
    let mut started = false;
    let floor = turn
        .now
        .saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS);
    // Only a park stops visits. The old owner's capacity and capability waits
    // have no releaser under the runner, so an upgraded gap in one is visited
    // like a ready one; admission's hold below is what keeps a group it cannot
    // drain from being swept.
    for demand in app
        .pending_recovery_demands()?
        .into_iter()
        .filter(|demand| {
            demand.cause == RecoveryCause::EpochGap
                && demand.eligibility != RecoveryEligibility::NeedsDeepRepair
        })
    {
        let routes = turn
            .routes
            .iter()
            .filter(|route| route.group_id.is_some() && route.group_id == demand.group_id)
            .collect::<Vec<_>>();
        // Route hydration/lifecycle and admission wake the same runner. Neither
        // an absent source nor a suspended copy grants an automatic visit.
        if routes.is_empty()
            || routes
                .iter()
                .any(|route| route.suspended() || stalled.holds(route) || route.required.is_empty())
        {
            continue;
        }
        let floors = routes
            .iter()
            .map(|route| {
                Ok((
                    route.route.clone(),
                    app.recovery_coverage_goal(&route.route)?
                        .unwrap_or(floor)
                        .max(floor),
                ))
            })
            .collect::<StorageResult<Vec<_>>>()?;
        let state = app.recovery_epoch_gap_retry(demand.ticket)?;
        if state.is_some_and(|state| state.exhausted) {
            app.begin_recovery_epoch_gap_retry(demand.ticket, &floors, turn.now)?;
            continue;
        }

        if let Some(state) = state.filter(|state| state.in_progress) {
            let mut complete = true;
            let mut answered = false;
            for route in &routes {
                let since = app
                    .recovery_coverage_goal(&route.route)?
                    .unwrap_or(floor)
                    .max(floor);
                for relay in &route.required {
                    let covered = app.recovery_coverage_covers(
                        &route.route,
                        std::slice::from_ref(relay),
                        since,
                        turn.owed_until(route, relay),
                    )?;
                    answered |= covered;
                    if !covered && !admission.source_left_frontier(route, relay)? {
                        complete = false;
                    }
                }
                if admission.ready_for(route)? {
                    complete = false;
                }
            }
            // The host cleared genuinely resolved epochs before this turn.
            // Only this group's releasable history postpones completion;
            // unrelated staging cannot starve its next visit. Failed sources
            // do not obstruct a healthy sweep, but an outage with no completed
            // source leaves this visit in progress across backoff and restart.
            if !complete || !answered {
                continue;
            }
            let exhausted = state.visits >= u64::from(policy.unit.break_after_no_progress);
            let shift = state.visits.saturating_sub(1).min(63) as u32;
            let delay = policy
                .unit
                .backoff_base_seconds
                .saturating_mul(1_u64 << shift)
                .min(policy.unit.backoff_cap_seconds);
            if app.finish_recovery_epoch_gap_retry(
                demand.ticket,
                state.visits,
                turn.now,
                delay,
                exhausted,
            )? && !exhausted
            {
                next = sooner(next, Some(turn.now.saturating_add(delay)));
            }
        } else {
            if let Some(state) = state
                && state.next_retry_at_seconds > turn.now
            {
                next = sooner(next, Some(state.next_retry_at_seconds));
                continue;
            }
            started |= app.begin_recovery_epoch_gap_retry(demand.ticket, &floors, turn.now)?;
        }
    }
    Ok(Advanced {
        next_due: next,
        started,
    })
}
