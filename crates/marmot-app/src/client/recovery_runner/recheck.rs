//! Re-check units (decision 5 of mdk#2660's phase 4 plan): one resumable
//! pass per (group route, required relay) over the unit's covered and retired
//! ranges inside the route's complete inventory window, by NIP-77 comparison
//! with what the account holds there.
//!
//! - The window is `transport_reconciliation_inventory`'s: the retention
//!   window, raised past whatever the inventory compacted away. Automatic
//!   late-publication repair is guaranteed only inside it, as for the
//!   comparison job. Below its floor the account's held set is incomplete,
//!   so a comparison would fetch what the account holds; nothing there is
//!   re-checked, and an epoch gap's bound below it is raised to it.
//!
//! - Only a required relay whose recorded caps show NIP-77 is re-checked. A
//!   cap-only relay's count proofs cannot re-check anything (decision 2), and
//!   a best-effort relay is never re-checked.
//! - A pass falls due 6 h after the last full one, and at once when its state
//!   says so: a unit no pass has finished yet, an epoch gap
//!   (`make_recovery_recheck_due` from the gap's bound, which PR 5 calls),
//!   explicit repair (`rearm_all_recovery_units`), or a relay that answers or
//!   reconnects after a cooldown longer than an hour (storage makes its
//!   re-checks due in the write that ends the cooldown).
//! - The runner picks one only when no debt unit is eligible (`select::pick`).
//! - Each quantum resumes where the pass got to, and settlement records where
//!   that now is. A failed or cut quantum un-covers nothing: the pass resumes
//!   from its position, held back in memory while it moves nowhere.
//! - What a re-check finds inside a range covered when planned arrived late:
//!   it is staged as any fetched history is, and counted in the runner's
//!   aggregate late-findings count. So a re-check waits while its relay is at
//!   a staging bound, with no exemption at the frontier it never moves, and
//!   while admission cannot drain its group ([`super::admission`]).
//!
//! A re-check never touches the unit's retry state
//! (`settle_recovery_recheck`): its ranges are not debt.

use std::collections::BTreeMap;

use cgka_traits::storage::StorageResult;
use storage_sqlite::{
    RecoveryCoverageProof, RecoveryRecheckPass, RecoveryStagedSlice, RecoveryUnitOutcome,
    SqliteAppStorage, TRANSPORT_RECONCILIATION_RETENTION_SECS, TransportReconciliationRoute,
};
use transport_nostr_adapter::compare::CompareEnd;
use transport_nostr_adapter::sweep::{RelayCaps, SweepRange};

use super::admission::{Admission, Stalled};
use super::compare::{CompareFacts, ComparePlan, PlannedRange, local_items, recorded_caps};
use super::quantum::{QuantumReport, classify};
use super::select::{Candidate, cooldown_until, suspended, sweepable};
use super::{DebtTurn, RecoveryRunnerPolicy, UnitKey, WorkerTurn, recovery_caps};

/// One re-check quantum's plan. Not `Debug`: it carries its unit.
pub(super) struct RecheckPlan {
    pub(super) compare: ComparePlan,
    /// The pass as the begin turn read it. Settlement records progress only
    /// under its revision: a pass made due during the quantum (an epoch gap,
    /// explicit repair, a long cooldown) runs again as requested.
    pub(super) pass: RecoveryRecheckPass,
}

/// What settling a re-check quantum did.
#[derive(Clone, Copy, Debug)]
pub(super) struct RecheckSettled {
    pub(super) outcome: RecoveryUnitOutcome,
    /// The pass finished.
    pub(super) complete: bool,
    /// The pass moved on: it finished or certified a window.
    pub(super) moved: bool,
}

/// When the unit's pass falls due.
fn due_at(pass: RecoveryRecheckPass, policy: &RecoveryRunnerPolicy) -> u64 {
    match pass {
        // A pass that got somewhere resumes at once.
        RecoveryRecheckPass {
            position_seconds: Some(_),
            ..
        }
        | RecoveryRecheckPass {
            completed_at_seconds: None,
            ..
        } => 0,
        RecoveryRecheckPass {
            completed_at_seconds: Some(at),
            ..
        } => at.saturating_add(policy.recheck_interval_seconds),
    }
}

/// Every re-check unit of the current routes, each with when its pass falls
/// due. A due pass with nothing left to check is left out. A unit of a group
/// admission cannot drain (`stalled`), or whose relay staging holds back, is
/// blocked: what a re-check finds is staged like any fetched history.
/// Writes nothing.
pub(super) fn survey(
    turn: &DebtTurn<'_>,
    policy: &RecoveryRunnerPolicy,
    stalled: &Stalled,
    admission: &mut Admission<'_>,
) -> StorageResult<Vec<Candidate>> {
    let app = turn.app;
    let now = turn.now;
    let floor = now.saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS);
    let mut caps = BTreeMap::new();
    let mut cooldowns = BTreeMap::new();
    let mut candidates = Vec::new();
    for route in sweepable(turn.routes) {
        for (relay, best_effort) in route.relays() {
            if best_effort {
                continue;
            }
            if !match caps.get(relay) {
                Some(compares) => *compares,
                None => {
                    let compares = recorded_caps(app, relay)?.is_some();
                    caps.insert(relay.to_owned(), compares);
                    compares
                }
            } {
                continue;
            }
            let key = UnitKey {
                route: route.route.clone(),
                relay: relay.to_owned(),
            };
            let unit = app.recovery_unit(&key.route, relay)?;
            let pass = unit.as_ref().map(|unit| unit.recheck).unwrap_or_default();
            let due = due_at(pass, policy);
            let start = floor.max(pass.position_seconds.unwrap_or(0));
            let to_check = if due <= now {
                let seconds = ranges_to_check(app, &key, start, turn.checked_until(route))?
                    .iter()
                    .map(|planned| planned.range.until - planned.range.since + 1)
                    .fold(0u64, u64::saturating_add);
                if seconds == 0 && pass.position_seconds.is_none() {
                    continue;
                }
                seconds
            } else {
                0
            };
            let cooldown = cooldown_until(app, &mut cooldowns, relay, now)?;
            let held_back =
                stalled.holds(route) || admission.backpressured(&key, &policy.staging, false)?;
            candidates.push(Candidate {
                key,
                best_effort: false,
                owed_seconds: to_check,
                position: start,
                last_served_at: unit.as_ref().and_then(|unit| unit.last_served_at_seconds),
                due_at: due.max(cooldown.unwrap_or(0)),
                blocked: suspended(route) || held_back,
                recheck: true,
            });
        }
    }
    Ok(candidates)
}

/// The unit's covered and retired ranges from `since` through `until`, each
/// merged with what it touches, oldest first. A retired second that is also
/// covered counts as covered.
fn ranges_to_check(
    app: &SqliteAppStorage,
    key: &UnitKey,
    since: u64,
    until: u64,
) -> StorageResult<Vec<PlannedRange>> {
    let clip = |from: u64, to: u64| {
        let (from, to) = (from.max(since), to.min(until));
        (from <= to).then_some((from, to))
    };
    let covered = merged(
        app.recovery_coverage_ranges(&key.route, &key.relay)?
            .iter()
            .filter_map(|proved| clip(proved.range.since_seconds, proved.range.until_seconds))
            .collect(),
    );
    let retired = merged(
        app.recovery_unit_spans(&key.route, &key.relay)?
            .iter()
            .filter(|span| span.retired.is_some())
            .filter_map(|span| clip(span.range.since_seconds, span.range.until_seconds))
            .collect(),
    );
    let mut ranges = covered
        .iter()
        .map(|&(since, until)| PlannedRange {
            range: SweepRange { since, until },
            covered: true,
        })
        .collect::<Vec<_>>();
    for (since, until) in retired {
        let mut next = since;
        for &(covered_since, covered_until) in &covered {
            if covered_until < next || covered_since > until {
                continue;
            }
            if covered_since > next {
                ranges.push(PlannedRange {
                    range: SweepRange {
                        since: next,
                        until: covered_since - 1,
                    },
                    covered: false,
                });
            }
            next = covered_until.saturating_add(1);
        }
        if next <= until {
            ranges.push(PlannedRange {
                range: SweepRange { since: next, until },
                covered: false,
            });
        }
    }
    ranges.sort_by_key(|planned| planned.range.since);
    Ok(ranges)
}

/// `ranges` merged where they overlap or touch, oldest first.
fn merged(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (since, until) in ranges {
        match out.last_mut() {
            Some(last) if since <= last.1.saturating_add(1) => last.1 = last.1.max(until),
            _ => out.push((since, until)),
        }
    }
    out
}

/// Plan the re-check quantum on `key` and record the attempt, or `None` when
/// it is not due or no longer eligible. A due pass with nothing left to check
/// is recorded complete. `caps` are the relay's NIP-11 caps as just read;
/// known ones are recorded first, as for a debt unit.
pub(super) fn begin(
    turn: &DebtTurn<'_>,
    key: &UnitKey,
    caps: Option<RelayCaps>,
    policy: &RecoveryRunnerPolicy,
) -> StorageResult<Option<RecheckPlan>> {
    let app = turn.app;
    let now = turn.now;
    let TransportReconciliationRoute::Group(nostr_group_id) = key.route else {
        return Ok(None);
    };
    let Some(route) = sweepable(turn.routes).find(|route| {
        route.route == key.route
            && !suspended(route)
            && route
                .relays()
                .any(|(relay, best_effort)| relay == key.relay && !best_effort)
    }) else {
        return Ok(None);
    };
    if let Some(read) = caps.map(recovery_caps) {
        app.record_recovery_relay_caps(&key.relay, Some(read), now)?;
    }
    if app
        .recovery_account_paused_until(&policy.unit, now)?
        .is_some_and(|until| until > now)
        || cooldown_until(app, &mut BTreeMap::new(), &key.relay, now)?.is_some()
    {
        return Ok(None);
    }
    let Some(caps) = recorded_caps(app, &key.relay)? else {
        return Ok(None);
    };
    let unit = app.recovery_unit(&key.route, &key.relay)?;
    let pass = unit.as_ref().map(|unit| unit.recheck).unwrap_or_default();
    if due_at(pass, policy) > now
        || Admission::new(turn).backpressured(key, &policy.staging, false)?
    {
        return Ok(None);
    }
    // Below the inventory's floor the account's held set is incomplete, so a
    // comparison there would fetch what it holds.
    let inventory = app.transport_reconciliation_inventory(&key.route, now)?;
    let start = now
        .saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS)
        .max(inventory.since)
        .max(pass.position_seconds.unwrap_or(0));
    let ranges = ranges_to_check(app, key, start, turn.checked_until(route))?;
    let (Some(first), Some(last)) = (ranges.first(), ranges.last()) else {
        app.record_recovery_recheck(&key.route, &key.relay, pass.revision, start, true, now)?;
        return Ok(None);
    };
    let local = local_items(
        app,
        &key.route,
        &inventory.items,
        first.range.since,
        last.range.until,
    )?;
    let mark = app.recovery_coverage_mark()?;
    // The unit's planned caps are its debt's: a re-check keeps them.
    app.begin_recovery_unit_attempt(
        &key.route,
        &key.relay,
        unit.as_ref().and_then(|unit| unit.planned_caps),
        now,
    )?;
    Ok(Some(RecheckPlan {
        compare: ComparePlan {
            key: key.clone(),
            nostr_group_id,
            best_effort: false,
            caps,
            ranges,
            local,
            mark,
            recheck: true,
        },
        pass,
    }))
}

/// Settle a re-check quantum: charge the bytes no staged batch charged,
/// report its outcome to the relay and the account, and record how far the
/// pass got, unless its pass was made due again meanwhile.
pub(super) fn settle(
    turn: &WorkerTurn<'_>,
    plan: &RecheckPlan,
    report: &QuantumReport,
    facts: &CompareFacts,
    policy: &RecoveryRunnerPolicy,
) -> StorageResult<RecheckSettled> {
    let key = &plan.compare.key;
    // A re-check's ranges are not debt: a finished pass is an answer.
    let outcome = classify(
        report.end,
        report.answers > 0,
        report.rate_limited,
        report.newly_covered_seconds,
        report.stop,
        true,
    );
    if report.unstaged_bytes > 0 {
        turn.app.stage_recovery_slice(
            &RecoveryStagedSlice {
                route: &key.route,
                relay: &key.relay,
                events: &[],
                fetched_bytes: report.unstaged_bytes,
                covered: &[],
                proof: RecoveryCoverageProof::Recheck,
                mark: plan.compare.mark,
            },
            turn.now,
        )?;
    }
    turn.app
        .settle_recovery_recheck(&key.route, &key.relay, outcome, &policy.unit, turn.now)?;
    let complete = facts.end == CompareEnd::Finished && report.stop.is_none();
    let moved = complete || facts.checked_through.is_some();
    if moved {
        turn.app.record_recovery_recheck(
            &key.route,
            &key.relay,
            plan.pass.revision,
            facts.checked_through.unwrap_or(0),
            complete,
            turn.now,
        )?;
    }
    Ok(RecheckSettled {
        outcome,
        complete,
        moved,
    })
}
