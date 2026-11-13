//! The runner's v5 audit rows (mdk#2660 phase 4): what it fetched for each
//! group, what it gave up on, and what made it stop or start again.
//!
//! Rows are written through the turn's audit hook ([`super::WorkerTurn`],
//! [`super::DebtTurn`]), never awaited, and the recorder drops them unless it
//! records v5. They carry the group (hashed to `group_ref`), the route's
//! one-way ledger tag (hashed to `obligation_ref`, the reference older
//! producers' `unproven_history` notice rows carried), the relay (hashed to `endpoint_ref`),
//! closed enums and counts. Volume follows real work: one row per quantum
//! that began, one per unit or route transition, and abandoned begins
//! coalesced per route ([`Races`]). Surveys and catching-up flips write none.

use std::collections::{BTreeMap, BTreeSet};

use marmot_forensics::{
    AuditEventKind, RECOVERY_RUNNER_RACED_WINDOW_SECS, RecoveryRunnerBreak, RecoveryRunnerChange,
    RecoveryRunnerFetch, RecoveryRunnerFetchEnd, RecoveryRunnerOutcome, RecoveryRunnerPurpose,
    RecoveryRunnerRoute,
};
use nostr::prelude::RelayUrl;
use storage_sqlite::{
    RecoveryCause, RecoveryRouteRemainder, RecoveryUnit, RecoveryUnitBreak, RecoveryUnitOutcome,
    RecoveryUnitState, SqliteAppStorage, TransportReconciliationRoute,
};
use transport_nostr_adapter::compare::CompareEnd;
use transport_nostr_adapter::sweep::{SweepEnd, SweepRange, UnreachableKind};

use super::quantum::QuantumReport;
use super::{DebtTurn, RunnerRoute};
use crate::history_notices::ledger_route_tag;

/// The audit hook's signature: the MLS group a row is about, if any, and the
/// row.
pub(crate) type AuditHook<'a> = &'a dyn Fn(Option<&[u8]>, AuditEventKind);

pub(super) fn route_kind(route: &TransportReconciliationRoute) -> RecoveryRunnerRoute {
    match route {
        TransportReconciliationRoute::Inbox => RecoveryRunnerRoute::Inbox,
        TransportReconciliationRoute::Group(_) => RecoveryRunnerRoute::Group,
    }
}

/// The route's one-way ledger tag, as older producers' `unproven_history`
/// notice rows carried it.
pub(super) fn route_tag(route: &TransportReconciliationRoute) -> String {
    hex::encode(ledger_route_tag(route))
}

/// The relay as the Nostr owner spells endpoints for v5 (`RelayUrl`), so its
/// `endpoint_ref` joins other rows'. The ledger's spelling drops a trailing
/// slash.
pub(super) fn relay_url(relay: &str) -> String {
    RelayUrl::parse(relay).map_or_else(|_| relay.to_owned(), |url| url.to_string())
}

pub(super) fn outcome(outcome: RecoveryUnitOutcome) -> RecoveryRunnerOutcome {
    match outcome {
        RecoveryUnitOutcome::Advanced => RecoveryRunnerOutcome::Advanced,
        RecoveryUnitOutcome::NothingOwed => RecoveryRunnerOutcome::NothingOwed,
        RecoveryUnitOutcome::NoProgress => RecoveryRunnerOutcome::NoProgress,
        RecoveryUnitOutcome::Unreachable => RecoveryRunnerOutcome::Unreachable,
        RecoveryUnitOutcome::RateLimited => RecoveryRunnerOutcome::RateLimited,
        RecoveryUnitOutcome::Refused => RecoveryRunnerOutcome::Refused,
        RecoveryUnitOutcome::Unanswered => RecoveryRunnerOutcome::Unanswered,
        RecoveryUnitOutcome::LocalFailure => RecoveryRunnerOutcome::LocalFailure,
    }
}

fn unreachable(kind: UnreachableKind) -> RecoveryRunnerFetchEnd {
    match kind {
        UnreachableKind::TimedOut => RecoveryRunnerFetchEnd::TimedOut,
        UnreachableKind::Disconnected => RecoveryRunnerFetchEnd::Disconnected,
    }
}

/// A sweep's end, by `quantum::end_label`'s names.
pub(super) fn sweep_end(end: SweepEnd) -> RecoveryRunnerFetchEnd {
    match end {
        SweepEnd::Finished => RecoveryRunnerFetchEnd::Finished,
        SweepEnd::DeadlineReached => RecoveryRunnerFetchEnd::Deadline,
        SweepEnd::Cancelled => RecoveryRunnerFetchEnd::Cancelled,
        SweepEnd::SaturatedSecond { .. } => RecoveryRunnerFetchEnd::SaturatedSecond,
        SweepEnd::InconclusiveSecond { .. } => RecoveryRunnerFetchEnd::InconclusiveSecond,
        SweepEnd::RateLimited => RecoveryRunnerFetchEnd::RateLimited,
        SweepEnd::Refused(_) => RecoveryRunnerFetchEnd::Refused,
        SweepEnd::Unreachable(kind) => unreachable(kind),
        SweepEnd::SinkFailed => RecoveryRunnerFetchEnd::SinkFailed,
        SweepEnd::StoreFailed => RecoveryRunnerFetchEnd::StoreFailed,
    }
}

/// A comparison's end, by `CompareEnd::label`'s names.
pub(super) fn compare_end(end: CompareEnd) -> RecoveryRunnerFetchEnd {
    match end {
        CompareEnd::Finished => RecoveryRunnerFetchEnd::Finished,
        CompareEnd::DeadlineReached => RecoveryRunnerFetchEnd::Deadline,
        CompareEnd::Cancelled => RecoveryRunnerFetchEnd::Cancelled,
        CompareEnd::BudgetSpent => RecoveryRunnerFetchEnd::BudgetSpent,
        CompareEnd::Withheld => RecoveryRunnerFetchEnd::Withheld,
        CompareEnd::SaturatedWindow { .. } => RecoveryRunnerFetchEnd::SaturatedWindow,
        CompareEnd::RateLimited => RecoveryRunnerFetchEnd::RateLimited,
        CompareEnd::Refused(_) => RecoveryRunnerFetchEnd::Refused,
        CompareEnd::Unsupported => RecoveryRunnerFetchEnd::Unsupported,
        CompareEnd::Unreachable(kind) => unreachable(kind),
        CompareEnd::SinkFailed => RecoveryRunnerFetchEnd::SinkFailed,
    }
}

fn break_reason(reason: RecoveryUnitBreak) -> RecoveryRunnerBreak {
    match reason {
        RecoveryUnitBreak::NoProgress => RecoveryRunnerBreak::NoProgress,
        RecoveryUnitBreak::Refused => RecoveryRunnerBreak::Refused,
    }
}

/// What the begin turn knew about one quantum, for its row. Not `Debug`: it
/// carries the group, the route and the relay.
pub(super) struct FetchAudit {
    group: Option<Vec<u8>>,
    route: TransportReconciliationRoute,
    retained_route: bool,
    relay: String,
    best_effort: bool,
    fetch: RecoveryRunnerFetch,
    purpose: RecoveryRunnerPurpose,
    probe: bool,
    ranges: u64,
    owed_secs: u64,
    owed_since_secs: u64,
    owed_until_secs: u64,
}

/// What the quantum did, for its row.
pub(super) struct FetchResult {
    pub(super) outcome: RecoveryUnitOutcome,
    pub(super) end: RecoveryRunnerFetchEnd,
    pub(super) duration_ms: u64,
    pub(super) late_findings: u64,
    pub(super) raced: u64,
}

impl FetchAudit {
    /// A quantum the begin turn planned over `ranges` on `relay` of `route`.
    /// `None` without a range: nothing to fetch, no row.
    pub(super) fn new(
        route: &RunnerRoute,
        relay: &str,
        best_effort: bool,
        compares: bool,
        purpose: RecoveryRunnerPurpose,
        probe: bool,
        ranges: &[SweepRange],
    ) -> Option<Self> {
        let mut spans = ranges
            .iter()
            .map(|range| (range.since, range.until))
            .collect::<Vec<_>>();
        spans.sort_unstable();
        let (owed_since_secs, _) = *spans.first()?;
        let owed_until_secs = spans.iter().map(|(_, until)| *until).max()?;
        // Seconds the ranges hold, each once.
        let mut owed_secs = 0u64;
        let mut next = owed_since_secs;
        for (since, until) in spans {
            let since = since.max(next);
            if since <= until {
                owed_secs = owed_secs.saturating_add(until - since + 1);
                next = until.saturating_add(1);
            }
        }
        Some(Self {
            group: route.group_id.clone(),
            route: route.route.clone(),
            retained_route: route.goal_until.is_some(),
            relay: relay.to_owned(),
            best_effort,
            fetch: if compares {
                RecoveryRunnerFetch::Compare
            } else {
                RecoveryRunnerFetch::Sweep
            },
            purpose,
            probe,
            ranges: ranges.len() as u64,
            owed_secs,
            owed_since_secs,
            owed_until_secs,
        })
    }

    /// Write the quantum's row.
    pub(super) fn record(self, audit: AuditHook<'_>, report: &QuantumReport, result: FetchResult) {
        let kind = AuditEventKind::RecoveryRunnerFetched {
            route_kind: route_kind(&self.route),
            obligation_id: route_tag(&self.route),
            retained_route: self.retained_route,
            relay_url: relay_url(&self.relay),
            best_effort: self.best_effort,
            fetch: self.fetch,
            purpose: self.purpose,
            probe: self.probe,
            ranges: self.ranges,
            owed_secs: self.owed_secs,
            owed_since_secs: self.owed_since_secs,
            owed_until_secs: self.owed_until_secs,
            outcome: outcome(result.outcome),
            end: result.end,
            duration_ms: result.duration_ms,
            requests: u64::from(report.requests),
            answers: u64::from(report.answers),
            newly_covered_secs: report.newly_covered_seconds,
            proved_secs: report.proved_seconds,
            events_fetched: report.events_fetched,
            events_staged: report.events_staged,
            late_findings: result.late_findings,
            raced: result.raced,
        };
        audit(self.group.as_deref(), kind);
    }
}

/// What a debt quantum on `route` is for, most specific first. `repair` and
/// `fenced` are the runner's own; a post-join collection is the tails', and
/// an epoch-gap visit is read from storage. A failed audit-only read reads
/// as no visit.
pub(super) fn debt_purpose(
    turn: &DebtTurn<'_>,
    route: &RunnerRoute,
    repair: bool,
    fenced: bool,
) -> RecoveryRunnerPurpose {
    if repair {
        RecoveryRunnerPurpose::Repair
    } else if turn.tails.collecting(&route.route) {
        RecoveryRunnerPurpose::PostJoinCollection
    } else if visiting_epoch_gap(turn.app, route) {
        RecoveryRunnerPurpose::EpochGapVisit
    } else if fenced {
        RecoveryRunnerPurpose::Fenced
    } else {
        RecoveryRunnerPurpose::Debt
    }
}

/// Whether the route's group has an epoch-gap return visit in progress.
fn visiting_epoch_gap(app: &SqliteAppStorage, route: &RunnerRoute) -> bool {
    let Some(group) = route.group_id.as_deref() else {
        return false;
    };
    let Ok(demands) = app.pending_recovery_demands() else {
        return false;
    };
    demands.into_iter().any(|demand| {
        demand.cause == RecoveryCause::EpochGap
            && demand.group_id.as_deref() == Some(group)
            && app
                .recovery_epoch_gap_retry(demand.ticket)
                .is_ok_and(|state| state.is_some_and(|state| state.in_progress))
    })
}

/// Whether the unit, as the begin turn read it, holds a probe.
pub(super) fn probing(unit: Option<&RecoveryUnit>) -> bool {
    unit.is_some_and(|unit| matches!(unit.state, RecoveryUnitState::Broken(_)) && unit.probe)
}

/// The unit's transition across one settled quantum, if it broke, failed a
/// probe or re-armed.
pub(super) fn unit_changed(
    audit: AuditHook<'_>,
    group: Option<&[u8]>,
    before: Option<&RecoveryUnit>,
    after: &RecoveryUnit,
) {
    let was_broken = before.is_some_and(|unit| matches!(unit.state, RecoveryUnitState::Broken(_)));
    let change = match after.state {
        RecoveryUnitState::Broken(reason) if !was_broken => {
            Some((RecoveryRunnerChange::Broken, Some(reason)))
        }
        RecoveryUnitState::Broken(reason) if probing(before) && !after.probe => {
            Some((RecoveryRunnerChange::ProbeFailed, Some(reason)))
        }
        RecoveryUnitState::Active | RecoveryUnitState::Retired if was_broken => {
            Some((RecoveryRunnerChange::Rearmed, None))
        }
        _ => None,
    };
    let Some((change, reason)) = change else {
        return;
    };
    audit(
        group,
        AuditEventKind::RecoveryRunnerChanged {
            change,
            route_kind: Some(route_kind(&after.route)),
            obligation_id: Some(route_tag(&after.route)),
            relay_url: Some(relay_url(&after.relay)),
            break_reason: reason.map(break_reason),
            park_revision: reason.and(after.park).map(|park| park.revision),
            units: None,
            remainder_since_secs: None,
            remainder_until_secs: None,
        },
    );
}

/// An aggregate change: `units` units re-armed or reopened on `relay`, or on
/// every relay without one. Nothing when there were none.
pub(crate) fn rearmed(
    audit: AuditHook<'_>,
    change: RecoveryRunnerChange,
    relay: Option<&str>,
    units: u64,
) {
    if units == 0 {
        return;
    }
    audit(
        None,
        AuditEventKind::RecoveryRunnerChanged {
            change,
            route_kind: None,
            obligation_id: None,
            relay_url: relay.map(relay_url),
            break_reason: None,
            park_revision: None,
            units: Some(units),
            remainder_since_secs: None,
            remainder_until_secs: None,
        },
    );
}

/// A route-level change on `route`, without a relay: `units` for a
/// retirement. The caller writes it with the route's group.
pub(crate) fn route_change(
    route: &TransportReconciliationRoute,
    change: RecoveryRunnerChange,
    units: Option<u64>,
) -> AuditEventKind {
    AuditEventKind::RecoveryRunnerChanged {
        change,
        route_kind: Some(route_kind(route)),
        obligation_id: Some(route_tag(route)),
        relay_url: None,
        break_reason: None,
        park_revision: None,
        units,
        remainder_since_secs: None,
        remainder_until_secs: None,
    }
}

/// What a retention prune did to a route's parked remainder, by comparing
/// the remainders before it with those after: one row per route that gained
/// or widened one, with `group` naming each route's group.
pub(crate) fn remainders_changed(
    audit: AuditHook<'_>,
    group: impl Fn(&TransportReconciliationRoute) -> Option<Vec<u8>>,
    before: &[RecoveryRouteRemainder],
    after: &[RecoveryRouteRemainder],
) {
    for remainder in after {
        let change = match before.iter().find(|old| old.route == remainder.route) {
            None => RecoveryRunnerChange::RemainderParked,
            Some(old) if old.range != remainder.range || old.revision != remainder.revision => {
                RecoveryRunnerChange::RemainderWidened
            }
            Some(_) => continue,
        };
        audit(
            group(&remainder.route).as_deref(),
            AuditEventKind::RecoveryRunnerChanged {
                change,
                route_kind: Some(route_kind(&remainder.route)),
                obligation_id: Some(route_tag(&remainder.route)),
                relay_url: None,
                break_reason: None,
                park_revision: Some(remainder.revision),
                units: None,
                remainder_since_secs: Some(remainder.range.since_seconds),
                remainder_until_secs: Some(remainder.range.until_seconds),
            },
        );
    }
}

/// Record the routes whose suspension changed since `last`: each newly
/// suspended route, and each route still current that is no longer; then
/// make `last` the suspended routes now. Before the first survey `last` is
/// `None`, so a process records every route it finds suspended once.
pub(super) fn suspensions(
    turn: &DebtTurn<'_>,
    last: &mut Option<BTreeSet<TransportReconciliationRoute>>,
) {
    let before = last.as_ref();
    let mut now = BTreeSet::new();
    for route in turn.routes {
        let was = before.is_some_and(|before| before.contains(&route.route));
        let change = match (route.suspended(), was) {
            (true, false) => Some(RecoveryRunnerChange::Suspended),
            (false, true) => Some(RecoveryRunnerChange::Resumed),
            _ => None,
        };
        if let Some(change) = change {
            (turn.audit)(
                route.group_id.as_deref(),
                route_change(&route.route, change, None),
            );
        }
        if route.suspended() {
            now.insert(route.route.clone());
        }
    }
    *last = Some(now);
}

/// Begins abandoned as raced, coalesced per route: a race counts into its
/// route's open window, and the race that finds the window at least
/// [`RECOVERY_RUNNER_RACED_WINDOW_SECS`] old writes one row for it. A route's
/// next fetch row takes whatever its open window holds. A restart forgets
/// open windows.
#[derive(Default)]
pub(super) struct Races {
    open: BTreeMap<TransportReconciliationRoute, (u64, u64)>,
}

impl Races {
    /// Count one race on `route` at `now`. Returns the row to write when it
    /// ends the route's window.
    pub(super) fn raced(
        &mut self,
        route: &TransportReconciliationRoute,
        now: u64,
    ) -> Option<AuditEventKind> {
        let (count, since) = self.open.entry(route.clone()).or_insert((0, now));
        *count = count.saturating_add(1);
        let window_secs = now.saturating_sub(*since);
        if window_secs < RECOVERY_RUNNER_RACED_WINDOW_SECS {
            return None;
        }
        let raced = *count;
        self.open.remove(route);
        Some(AuditEventKind::RecoveryRunnerRaced {
            route_kind: route_kind(route),
            obligation_id: route_tag(route),
            raced,
            window_secs,
        })
    }

    /// The races `route`'s open window holds, closing it.
    pub(super) fn take(&mut self, route: &TransportReconciliationRoute) -> u64 {
        self.open.remove(route).map_or(0, |(count, _)| count)
    }
}
