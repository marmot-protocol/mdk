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
//! clears, which bounds its debt.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::storage::StorageResult;
use storage_sqlite::{
    RecoveryCoverageMark, RecoveryRelayCaps, RecoveryUnitState, SqliteAppStorage,
    TransportReconciliationRoute,
};
use transport_nostr_adapter::sweep::{RelayCaps, SweepRange};

use super::quantum::QuantumReport;
use super::{DebtTurn, PriorityHints, RecoveryRunnerPolicy, RunnerRoute, UnitKey, recovery_caps};
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
    /// The un-cover generation the survey read; with `position` it names a
    /// best-effort relay's debt.
    pub(super) mark: RecoveryCoverageMark,
}

/// Every owing unit of the current routes, read in one debt turn.
pub(super) struct Survey {
    pub(super) candidates: Vec<Candidate>,
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
    /// Each best-effort unit's debt at its last attempt that made no progress.
    best_effort: BTreeMap<UnitKey, (u64, RecoveryCoverageMark)>,
}

impl Memory {
    pub(super) fn new_round(&mut self) {
        self.served.clear();
    }

    pub(super) fn relay_reconnected(&mut self, relay: &str) {
        self.best_effort.retain(|key, _| key.relay != relay);
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
                // The runner preempted it: that was no attempt.
                RecoveryUnitOutcome::Unanswered => {}
                _ => {
                    self.best_effort
                        .insert(candidate.key.clone(), (candidate.position, candidate.mark));
                }
            }
        }
    }

    /// The unit's debt in events at the route's last observed rate, or in
    /// seconds when no rate is known.
    fn size(&self, candidate: &Candidate) -> u64 {
        match self.rates.get(&candidate.key.route) {
            Some((events, seconds)) => {
                let size = u128::from(candidate.owed_seconds) * u128::from(*events)
                    / u128::from((*seconds).max(1));
                u64::try_from(size).unwrap_or(u64::MAX)
            }
            None => candidate.owed_seconds,
        }
    }
}

/// The routes a sweep can serve: group routes. The inbox stays on NIP-77
/// comparison (PR 6).
fn sweepable(routes: &[RunnerRoute]) -> impl Iterator<Item = &RunnerRoute> {
    routes
        .iter()
        .filter(|route| matches!(route.route, TransportReconciliationRoute::Group(_)))
}

/// Whether the route's group is suspended (Unrecoverable). PR 5 fills this
/// from the group's lifecycle; until then every group is eligible.
fn suspended(_route: &RunnerRoute) -> bool {
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
fn cooldown_until(
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
    let mark = app.recovery_coverage_mark()?;
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
                mark,
            });
        }
    }
    Ok(Survey {
        candidates,
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

/// Pick the next unit from `survey`. `new_round` lets a new round start once
/// every eligible unit has been served; without it (an explicit pass) that
/// ends the pick.
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
    for candidate in survey.candidates {
        let tried = candidate.best_effort
            && memory.best_effort.get(&candidate.key)
                == Some(&(candidate.position, candidate.mark));
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
    if eligible.is_empty() {
        return Pick::Idle { next_due };
    }
    if eligible
        .iter()
        .all(|candidate| memory.served.contains(&candidate.key))
    {
        if !new_round {
            return Pick::Idle { next_due: None };
        }
        memory.new_round();
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

/// What one quantum will fetch, planned in the begin turn. Not `Debug`.
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
}

/// Plan the quantum on `key` and record the attempt, or `None` when it no
/// longer owes anything or is no longer eligible. `caps` are the relay's
/// NIP-11 caps as just read; known ones are recorded first, which re-arms
/// the relay's units that were planned with other caps.
pub(super) fn begin(
    turn: &DebtTurn<'_>,
    key: &UnitKey,
    best_effort: bool,
    caps: Option<RelayCaps>,
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
    }))
}
