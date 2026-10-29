//! Choosing the next unit and planning its quantum.
//!
//! The survey and the begin turn run on the worker and read debt with that
//! turn's live tails. The order runs off the worker over the survey's facts
//! and the runner's memory: the class (held groups, then open conversation
//! windows and the inbox, then everything else, then best-effort relays),
//! then units not yet served this round, then the smallest route debt, then
//! the relay furthest behind on its route, then the least recently served.
//! A class always goes before the next one. Within a class, every eligible
//! unit runs once per round, so a large group is served every round and
//! cannot starve small debts. A held group stays first only until its fence
//! clears, which bounds its debt. A re-check ([`super::recheck`]) runs only
//! when no debt unit is eligible, least recently served first.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::storage::StorageResult;
use storage_sqlite::{
    RecoveryCoverageMark, RecoveryRelayCaps, RecoveryUnitState, SqliteAppStorage,
    TransportReconciliationRoute,
};
use transport_nostr_adapter::sweep::{RelayCaps, SweepRange};

use super::compare::{self, ComparePlan, PlannedRange};
use super::quantum::QuantumReport;
use super::{
    DebtTurn, PriorityHints, RecoveryRunnerPolicy, RunnerRoute, UnitKey, recheck, recovery_caps,
};
use storage_sqlite::RecoveryUnitOutcome;

/// One owing unit, as the survey found it. Not `Debug`: it carries its unit.
#[derive(Clone)]
pub(super) struct Candidate {
    pub(super) key: UnitKey,
    pub(super) best_effort: bool,
    /// Seconds owed after the live tail.
    pub(super) owed_seconds: u64,
    /// The first owed second: where this relay stands on its route.
    pub(super) position: u64,
    pub(super) last_served_at: Option<u64>,
    /// The earliest second it may run: its backoff or its relay's cooldown.
    pub(super) due_at: u64,
    /// It waits for new evidence, not for time: a broken unit without a probe,
    /// a suspended group, or a relay staging holds back.
    pub(super) blocked: bool,
    /// A re-check pass rather than debt: `owed_seconds` are what it still
    /// checks and `position` where it resumes.
    pub(super) recheck: bool,
}

/// Every owing unit of the current routes, read in one debt turn.
pub(super) struct Survey {
    pub(super) candidates: Vec<Candidate>,
    /// Re-check units, due or not.
    pub(super) rechecks: Vec<Candidate>,
    /// The account breaker's pause, while a cap is reached.
    pub(super) paused_until: Option<u64>,
}

pub(super) enum Pick {
    Unit(Candidate),
    Idle { next_due: Option<u64> },
}

/// What the runner keeps in memory between steps. A restart forgets it,
/// which costs order and at most one extra attempt per best-effort relay,
/// never debt.
#[derive(Default)]
pub(super) struct Memory {
    /// Units served in the current round.
    served: BTreeSet<UnitKey>,
    /// Each route's last observed event rate: events over proved seconds.
    rates: BTreeMap<TransportReconciliationRoute, (u64, u64)>,
    /// Units held back after local failures: until when, and the failures in
    /// a row.
    local: BTreeMap<UnitKey, (u64, u32)>,
    /// Each best-effort unit's first owed second at its last attempt that
    /// made no progress. A loss that moves it earlier is new debt; growth at
    /// the newest end, or an un-cover after it, is not.
    best_effort: BTreeMap<UnitKey, u64>,
    /// Relays that would not compare since they last reconnected: their debt
    /// is swept and they are not re-checked.
    uncomparable: BTreeSet<String>,
    /// Re-checks held back after quanta that moved their pass nowhere: until
    /// when, and how many in a row.
    recheck_holds: BTreeMap<UnitKey, (u64, u32)>,
    /// Re-checks served in the current explicit pass.
    rechecks_served: BTreeSet<UnitKey>,
}

impl Memory {
    pub(super) fn new_round(&mut self) {
        self.served.clear();
        self.rechecks_served.clear();
    }

    pub(super) fn relay_reconnected(&mut self, relay: &str) {
        self.best_effort.retain(|key, _| key.relay != relay);
        self.uncomparable.remove(relay);
        self.recheck_holds.retain(|key, _| key.relay != relay);
    }

    /// Whether the relay may compare.
    pub(super) fn compares(&self, relay: &str) -> bool {
        !self.uncomparable.contains(relay)
    }

    /// The relay would not compare (`compare::would_not_compare`).
    pub(super) fn would_not_compare(&mut self, relay: &str) {
        self.uncomparable.insert(relay.to_owned());
    }

    /// Record a settled re-check quantum. An answer that moved its pass clears
    /// the hold; one the runner preempted changes nothing; any other (a
    /// failure, or an answer that moved nothing) is held back on the unit
    /// backoff's doubling.
    pub(super) fn recheck_settled(
        &mut self,
        key: &UnitKey,
        moved: bool,
        outcome: RecoveryUnitOutcome,
        now: u64,
        policy: &RecoveryRunnerPolicy,
    ) {
        use RecoveryUnitOutcome as Outcome;
        match outcome {
            Outcome::Unanswered => {}
            Outcome::Advanced | Outcome::NoProgress | Outcome::NothingOwed if moved => {
                self.recheck_holds.remove(key);
            }
            _ => {
                let failures = self
                    .recheck_holds
                    .get(key)
                    .map_or(0, |(_, failures)| *failures)
                    .saturating_add(1);
                let until = now.saturating_add(policy.recheck_backoff_seconds(failures));
                self.recheck_holds.insert(key.clone(), (until, failures));
            }
        }
    }

    /// Record a settled quantum.
    pub(super) fn settled(
        &mut self,
        candidate: &Candidate,
        report: Option<&QuantumReport>,
        outcome: RecoveryUnitOutcome,
        now: u64,
        policy: &RecoveryRunnerPolicy,
    ) {
        if outcome == RecoveryUnitOutcome::LocalFailure {
            let failures = self
                .local
                .get(&candidate.key)
                .map_or(0, |(_, failures)| *failures)
                .saturating_add(1);
            let until = now.saturating_add(policy.local_failure_backoff_seconds(failures));
            self.local.insert(candidate.key.clone(), (until, failures));
        } else {
            self.local.remove(&candidate.key);
        }
        if let Some(report) = report.filter(|report| report.proved_seconds > 0) {
            self.rates.insert(
                candidate.key.route.clone(),
                (report.proved_events, report.proved_seconds),
            );
        }
        if candidate.best_effort {
            match outcome {
                RecoveryUnitOutcome::Advanced => {
                    self.best_effort.remove(&candidate.key);
                }
                // The runner preempted it, or its own write failed: that was no
                // attempt. A local failure waits out the local hold instead.
                RecoveryUnitOutcome::Unanswered | RecoveryUnitOutcome::LocalFailure => {}
                _ => {
                    self.best_effort
                        .insert(candidate.key.clone(), candidate.position);
                }
            }
        }
    }

    /// The unit's debt in events at the route's last observed rate, or in
    /// seconds when no rate is known or the route was last seen empty.
    fn size(&self, candidate: &Candidate) -> u64 {
        match self.rates.get(&candidate.key.route) {
            Some((events, seconds)) if *events > 0 => {
                let size = u128::from(candidate.owed_seconds) * u128::from(*events)
                    / u128::from((*seconds).max(1));
                u64::try_from(size).unwrap_or(u64::MAX)
            }
            _ => candidate.owed_seconds,
        }
    }
}

/// The routes a sweep can serve: group routes. The inbox stays on NIP-77
/// comparison (PR 6).
pub(super) fn sweepable(routes: &[RunnerRoute]) -> impl Iterator<Item = &RunnerRoute> {
    routes
        .iter()
        .filter(|route| matches!(route.route, TransportReconciliationRoute::Group(_)))
}

/// Whether the route's group is suspended (Unrecoverable). PR 5 fills this
/// from the group's lifecycle; until then every group is eligible.
pub(super) fn suspended(_route: &RunnerRoute) -> bool {
    false
}

/// Whether staging holds this relay back until the group's laggard advances
/// or leaves the admission frontier. PR 4b fills this from the staging bounds;
/// until then nothing is held back.
fn backpressured(
    _app: &SqliteAppStorage,
    _route: &RunnerRoute,
    _relay: &str,
    _policy: &RecoveryRunnerPolicy,
) -> StorageResult<bool> {
    Ok(false)
}

/// When the relay's cooldown ends, if one is running at `now`.
pub(super) fn cooldown_until(
    app: &SqliteAppStorage,
    seen: &mut BTreeMap<String, Option<u64>>,
    relay: &str,
    now: u64,
) -> StorageResult<Option<u64>> {
    if let Some(until) = seen.get(relay) {
        return Ok(*until);
    }
    let until = app
        .recovery_relay_health(relay)?
        .and_then(|health| health.cooldown)
        .map(|(_, until)| until)
        .filter(|until| *until > now);
    seen.insert(relay.to_owned(), until);
    Ok(until)
}

/// Survey every unit of the current routes that owes anything after its live
/// tail. Writes nothing.
pub(super) fn survey(turn: &DebtTurn<'_>, policy: &RecoveryRunnerPolicy) -> StorageResult<Survey> {
    let app = turn.app;
    let now = turn.now;
    let paused_until = app
        .recovery_account_paused_until(&policy.unit, now)?
        .filter(|until| *until > now);
    let mut cooldowns = BTreeMap::new();
    let mut candidates = Vec::new();
    for route in sweepable(turn.routes) {
        for (relay, best_effort) in route.relays() {
            let owed_until = turn.tails.owed_until(&route.route, relay, now);
            let debt = app.recovery_unit_debt(&route.route, relay, owed_until)?;
            let Some(first) = debt.first() else {
                continue;
            };
            let owed_seconds = debt
                .iter()
                .map(|range| range.until_seconds - range.since_seconds + 1)
                .fold(0u64, u64::saturating_add);
            let unit = app.recovery_unit(&route.route, relay)?;
            let (retry_at, broken) = match (&unit, best_effort) {
                // A best-effort relay keeps no retry state.
                (_, true) | (None, false) => (0, false),
                (Some(unit), false) => (
                    unit.next_attempt_at_seconds,
                    matches!(unit.state, RecoveryUnitState::Broken(_)) && !unit.probe,
                ),
            };
            let cooldown = cooldown_until(app, &mut cooldowns, relay, now)?;
            candidates.push(Candidate {
                key: UnitKey {
                    route: route.route.clone(),
                    relay: relay.to_owned(),
                },
                best_effort,
                owed_seconds,
                position: first.since_seconds,
                last_served_at: unit.as_ref().and_then(|unit| unit.last_served_at_seconds),
                due_at: retry_at.max(cooldown.unwrap_or(0)),
                blocked: broken || suspended(route) || backpressured(app, route, relay, policy)?,
                recheck: false,
            });
        }
    }
    Ok(Survey {
        candidates,
        rechecks: recheck::survey(turn, policy)?,
        paused_until,
    })
}

/// The class a unit is served in, first to last.
fn class(candidate: &Candidate, hints: &PriorityHints) -> u8 {
    let route = &candidate.key.route;
    if candidate.best_effort {
        3
    } else if hints.held.contains(route) {
        0
    } else if hints.window.contains(route) || *route == TransportReconciliationRoute::Inbox {
        1
    } else {
        2
    }
}

/// Pick the next unit from `survey`. `new_round` lets a class start a new
/// round once each of its eligible units has been served; without it (an
/// explicit pass) every eligible unit of every class is served once, and then
/// the pick ends.
pub(super) fn pick(
    survey: Survey,
    memory: &mut Memory,
    hints: &PriorityHints,
    now: u64,
    new_round: bool,
) -> Pick {
    if let Some(until) = survey.paused_until {
        return Pick::Idle {
            next_due: Some(until),
        };
    }
    let mut next_due: Option<u64> = None;
    let mut eligible = Vec::new();
    let rechecks = survey.rechecks;
    for candidate in survey.candidates {
        let tried = candidate.best_effort
            && memory.best_effort.get(&candidate.key) == Some(&candidate.position);
        if candidate.blocked || tried {
            continue;
        }
        let held = memory
            .local
            .get(&candidate.key)
            .map_or(0, |(until, _)| *until);
        let due = candidate.due_at.max(held);
        if due > now {
            next_due = Some(next_due.map_or(due, |next| next.min(due)));
            continue;
        }
        eligible.push(candidate);
    }
    if !new_round {
        // An explicit pass serves each unit once, whatever its class.
        eligible.retain(|candidate| !memory.served.contains(&candidate.key));
    }
    if eligible.is_empty() {
        return pick_recheck(rechecks, memory, now, new_round, next_due);
    }
    if new_round {
        // Rounds run within the first class that has an eligible unit: once
        // each of its units has been served, the class starts a new round.
        let first = eligible
            .iter()
            .map(|candidate| class(candidate, hints))
            .min()
            .expect("eligible is not empty");
        eligible.retain(|candidate| class(candidate, hints) == first);
        if eligible
            .iter()
            .all(|candidate| memory.served.contains(&candidate.key))
        {
            for candidate in &eligible {
                memory.served.remove(&candidate.key);
            }
        }
    }
    let mut route_size: BTreeMap<&TransportReconciliationRoute, u64> = BTreeMap::new();
    for candidate in eligible.iter().filter(|candidate| !candidate.best_effort) {
        let size = memory.size(candidate);
        let entry = route_size.entry(&candidate.key.route).or_default();
        *entry = (*entry).max(size);
    }
    let order = |candidate: &Candidate| {
        (
            class(candidate, hints),
            memory.served.contains(&candidate.key),
            route_size
                .get(&candidate.key.route)
                .copied()
                .unwrap_or_else(|| memory.size(candidate)),
            candidate.position,
            candidate.last_served_at,
        )
    };
    let chosen = eligible
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| {
            order(left)
                .cmp(&order(right))
                .then_with(|| left.key.cmp(&right.key))
        })
        .map(|(index, _)| index)
        .expect("eligible is not empty");
    let chosen = eligible.swap_remove(chosen);
    memory.served.insert(chosen.key.clone());
    Pick::Unit(chosen)
}

/// Pick a due re-check, least recently served first, once no debt unit is
/// eligible. `next_due` is the debt's; the re-checks' due times join it.
fn pick_recheck(
    rechecks: Vec<Candidate>,
    memory: &mut Memory,
    now: u64,
    new_round: bool,
    mut next_due: Option<u64>,
) -> Pick {
    let mut eligible = Vec::new();
    for candidate in rechecks {
        if candidate.blocked
            || !memory.compares(&candidate.key.relay)
            || !new_round && memory.rechecks_served.contains(&candidate.key)
        {
            continue;
        }
        let held = memory
            .recheck_holds
            .get(&candidate.key)
            .map_or(0, |(until, _)| *until);
        let due = candidate.due_at.max(held);
        if due > now {
            next_due = Some(next_due.map_or(due, |next| next.min(due)));
            continue;
        }
        eligible.push(candidate);
    }
    let Some(chosen) = eligible.into_iter().min_by(|left, right| {
        (left.last_served_at, &left.key).cmp(&(right.last_served_at, &right.key))
    }) else {
        return Pick::Idle { next_due };
    };
    if !new_round {
        memory.rechecks_served.insert(chosen.key.clone());
    }
    Pick::Unit(chosen)
}

/// What one debt quantum will fetch, planned in the begin turn. Not `Debug`.
pub(super) struct SweepPlan {
    pub(super) key: UnitKey,
    pub(super) nostr_group_id: [u8; 32],
    pub(super) best_effort: bool,
    /// The unit's owed ranges, oldest first, each from its ledger cursor to
    /// its end. None reaches past the live tail as this turn read it.
    pub(super) ranges: Vec<SweepRange>,
    /// The slice width and observed cap the unit last swept with.
    pub(super) delta: u64,
    pub(super) observed_cap: Option<u32>,
    /// The un-cover generation before the fetch: staging subtracts every range
    /// un-covered after it.
    pub(super) mark: RecoveryCoverageMark,
    /// The same ranges compared by NIP-77 instead of swept, when the relay
    /// compares and the account holds events there (`compare::plan_debt`).
    pub(super) compare: Option<ComparePlan>,
}

/// Plan the quantum on `key` and record the attempt, or `None` when it no
/// longer owes anything or is no longer eligible. `caps` are the relay's
/// NIP-11 caps as just read; known ones are recorded first, which re-arms
/// the relay's units that were planned with other caps. `compares` is
/// whether the relay may compare at all.
pub(super) fn begin(
    turn: &DebtTurn<'_>,
    key: &UnitKey,
    best_effort: bool,
    caps: Option<RelayCaps>,
    compares: bool,
    policy: &RecoveryRunnerPolicy,
) -> StorageResult<Option<SweepPlan>> {
    let app = turn.app;
    let now = turn.now;
    let TransportReconciliationRoute::Group(nostr_group_id) = key.route else {
        return Ok(None);
    };
    let current = sweepable(turn.routes).any(|route| {
        route.route == key.route
            && route
                .relays()
                .any(|(relay, effort)| relay == key.relay && effort == best_effort)
    });
    if !current {
        return Ok(None);
    }
    let planned: Option<RecoveryRelayCaps> = caps.map(recovery_caps);
    if planned.is_some() {
        app.record_recovery_relay_caps(&key.relay, planned, now)?;
    }
    if app
        .recovery_account_paused_until(&policy.unit, now)?
        .is_some_and(|until| until > now)
        || cooldown_until(app, &mut BTreeMap::new(), &key.relay, now)?.is_some()
    {
        return Ok(None);
    }
    let unit = app.recovery_unit(&key.route, &key.relay)?;
    if !best_effort
        && unit.as_ref().is_some_and(|unit| {
            unit.next_attempt_at_seconds > now
                || matches!(unit.state, RecoveryUnitState::Broken(_)) && !unit.probe
        })
    {
        return Ok(None);
    }
    let mark = app.recovery_coverage_mark()?;
    let owed_until = turn.tails.owed_until(&key.route, &key.relay, now);
    let mut ranges = Vec::new();
    for debt in app.recovery_unit_debt(&key.route, &key.relay, owed_until)? {
        if let Some(cursor) = app.recovery_unit_cursor(
            &key.route,
            &key.relay,
            debt.since_seconds,
            debt.until_seconds,
        )? {
            ranges.push(SweepRange {
                since: cursor,
                until: debt.until_seconds,
            });
        }
    }
    if ranges.is_empty() {
        return Ok(None);
    }
    let compare = if compares {
        compare::plan_debt(app, key, &ranges, now)?.map(|(caps, local)| ComparePlan {
            key: key.clone(),
            nostr_group_id,
            best_effort,
            caps,
            ranges: ranges
                .iter()
                .map(|&range| PlannedRange {
                    range,
                    covered: false,
                })
                .collect(),
            local,
            mark,
            recheck: false,
        })
    } else {
        None
    };
    if !best_effort {
        app.begin_recovery_unit_attempt(&key.route, &key.relay, planned, now)?;
    }
    Ok(Some(SweepPlan {
        key: key.clone(),
        nostr_group_id,
        best_effort,
        ranges,
        delta: unit
            .as_ref()
            .and_then(|unit| unit.slice_width_seconds)
            .unwrap_or(policy.sweep.initial_delta),
        observed_cap: unit.as_ref().and_then(|unit| unit.observed_cap),
        mark,
        compare,
    }))
}
