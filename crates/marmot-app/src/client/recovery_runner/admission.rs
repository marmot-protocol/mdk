//! Admission from staging (mdk#2660 phase 4, PR 4b).
//!
//! A sweep stages what it proves; admission hands it to the account's
//! recovered-ingest path, so within an MLS group one relay's newer ciphertext
//! never goes ahead of another relay's older history:
//!
//! - **The frontier.** A group's staged events, across its current and
//!   retained routes, are released oldest first by `(created_at, id)` below
//!   its admission frontier: the lowest position among the group's required
//!   relays that still owe it history. A unit's position is the first second
//!   it owes after its live tail.
//! - **Leaving the frontier.** A unit stops holding the frontier once its
//!   last quantum ended without progress (no progress, unreachable, refused),
//!   and while its relay cools down or it is broken or retired. What it
//!   stages later is late input.
//! - **Backpressure.** A relay at a group's staging bound (its events or
//!   bytes for the group), or any relay while the account is at its own, is
//!   not eligible while another unit holds the group's frontier, until that
//!   laggard advances or leaves. A unit at the frontier is never held back,
//!   so the runner never waits on itself. What a route the runner no longer
//!   lists staged is given back, its seconds owed again on that route, so it
//!   never holds the account's bound.
//! - **The fence.** Only capture debt holds a group's live frames: the part
//!   `[since, oldest seen]` of a live REQ's range that its relay's non-empty
//!   count left unproven. An empty count's range is cold-start debt, owed but
//!   never fencing, and so are loss, re-check and epoch-gap debt. A group's
//!   held frames are released below the first second its fencing units still
//!   owe in their capture debt. A unit off the frontier fences nothing until
//!   it is back on it. Each unit keeps every capture range it still owes
//!   durably, so the hold comes back after a restart, when the counts are
//!   gone.
//!
//! Each admission turn ingests at most a few events, one worker command each,
//! so the worker serves commands and live input between them. An event the
//! engine keeps no trace of (refused for resources) stays staged, and its
//! group waits behind it on the local-failure backoff; other groups go on.
//!
//! Nothing runs this before the switch-over (PR 5), which maps the coverage
//! recorder's live count facts into [`LiveCount`] and has the adapter's hold
//! read [`live_fences`] in place of owner capture. Inbox staging (PR 6) is not
//! admitted here.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::storage::StorageResult;
use storage_sqlite::{
    RecoveryCoverageRange, RecoveryStagedUsage, RecoveryUnitState, StagedRecoveryEvent,
    TransportReconciliationRoute,
};
use tokio::time::Instant;

use super::policy::RecoveryStagingBounds;
use super::select::sweepable;
use super::{
    DebtTurn, RecoveryRunner, RecoveryRunnerPolicy, RunnerHost, RunnerRoute, Step, TARGET, UnitKey,
};
use crate::AppError;

/// Staging reads seconds as SQLite integers: a group no unit holds back is
/// read below this.
const NO_FRONTIER: u64 = i64::MAX.unsigned_abs();

/// One live REQ's count on one relay, as the fence reads it. PR 5 maps the
/// coverage recorder's live count facts into these. Not `Debug`: it carries
/// routes and the relay.
#[derive(Clone)]
pub(crate) struct LiveCount {
    /// The routes its filter carries.
    pub(crate) routes: Vec<TransportReconciliationRoute>,
    /// The relay, spelled as the ledger spells it.
    pub(crate) relay: String,
    /// The REQ's `since`.
    pub(crate) since: u64,
    /// The oldest stored event the relay sent before its EOSE; `None` when
    /// it sent none.
    pub(crate) oldest_seen: Option<u64>,
}

impl LiveCount {
    /// What it left unproven: `[since, oldest seen]`. An empty count leaves
    /// no capture debt.
    fn capture(&self) -> Option<RecoveryCoverageRange> {
        let oldest = self.oldest_seen?;
        (oldest >= self.since).then_some(RecoveryCoverageRange {
            since_seconds: self.since,
            until_seconds: oldest,
        })
    }
}

/// How far a fenced group's held live frames may be released. Not `Debug`:
/// it carries routes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LiveFence {
    /// The group's routes.
    pub(crate) routes: Vec<TransportReconciliationRoute>,
    /// Frames sent before this second may be released; the rest wait.
    pub(crate) release_before: u64,
}

/// What the engine did with one staged delivery. PR 5 maps the account's
/// recovered-ingest result into this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// It holds the event, or held it already.
    Kept,
    /// It kept no trace of it (refused for resources, or for a group it does
    /// not know), so the event stays fetchable.
    NoTrace,
}

/// Which group a route belongs to: its MLS group, or the route alone when it
/// names none.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum GroupKey {
    Group(Vec<u8>),
    Route(TransportReconciliationRoute),
}

fn group_key(route: &RunnerRoute) -> GroupKey {
    route
        .group_id
        .clone()
        .map_or_else(|| GroupKey::Route(route.route.clone()), GroupKey::Group)
}

/// One required (route, relay) of a group, as one debt turn reads it.
struct Member {
    key: UnitKey,
    /// The first second it owes after its live tail.
    position: Option<u64>,
    on_frontier: bool,
    /// The capture ranges it keeps durably.
    stored: Vec<RecoveryCoverageRange>,
    /// Its capture ranges that it still owes, and the first second it owes
    /// in them.
    fences: Vec<RecoveryCoverageRange>,
    first_owed: Option<u64>,
}

impl Member {
    /// Below which second it lets its group's live frames go, if it holds
    /// them.
    fn holds_live_frames(&self) -> Option<u64> {
        self.first_owed.filter(|_| self.on_frontier)
    }
}

struct Group {
    routes: Vec<TransportReconciliationRoute>,
    members: Vec<Member>,
}

impl Group {
    fn frontier(&self) -> Option<u64> {
        self.members
            .iter()
            .filter(|member| member.on_frontier)
            .filter_map(|member| member.position)
            .min()
    }

    fn release_before(&self) -> Option<u64> {
        self.members
            .iter()
            .filter_map(Member::holds_live_frames)
            .min()
    }
}

/// The account's groups as one debt turn reads them, each on first use.
pub(super) struct Admission<'t> {
    turn: &'t DebtTurn<'t>,
    /// Each group's routes, and the group of each.
    groups: BTreeMap<GroupKey, Vec<&'t RunnerRoute>>,
    route_groups: BTreeMap<&'t TransportReconciliationRoute, GroupKey>,
    /// The ranges the turn's live counts left unproven, by (route, relay).
    captures: BTreeMap<(&'t TransportReconciliationRoute, &'t str), Vec<RecoveryCoverageRange>>,
    read: BTreeMap<GroupKey, Group>,
    relays_left: BTreeMap<&'t str, bool>,
    /// The ranges each unit keeps fenced, and the account's staging, once
    /// read.
    fenced: Option<BTreeMap<UnitKey, Vec<RecoveryCoverageRange>>>,
    staged: Option<RecoveryStagedUsage>,
}

impl<'t> Admission<'t> {
    pub(super) fn new(turn: &'t DebtTurn<'t>) -> Self {
        let mut groups: BTreeMap<GroupKey, Vec<&RunnerRoute>> = BTreeMap::new();
        let mut route_groups = BTreeMap::new();
        for route in sweepable(turn.routes) {
            let key = group_key(route);
            route_groups.insert(&route.route, key.clone());
            groups.entry(key).or_default().push(route);
        }
        let mut captures: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for count in turn.live_counts {
            if let Some(capture) = count.capture() {
                for route in &count.routes {
                    captures
                        .entry((route, count.relay.as_str()))
                        .or_default()
                        .push(capture);
                }
            }
        }
        Self {
            turn,
            groups,
            route_groups,
            captures,
            read: BTreeMap::new(),
            relays_left: BTreeMap::new(),
            fenced: None,
            staged: None,
        }
    }

    /// Whether staging holds `key` back: its relay is at the group's staging
    /// bound, or the account at its own, while another unit holds the
    /// group's frontier.
    pub(super) fn backpressured(
        &mut self,
        key: &UnitKey,
        bounds: &RecoveryStagingBounds,
    ) -> StorageResult<bool> {
        let Some(group_key) = self.route_groups.get(&key.route).cloned() else {
            return Ok(false);
        };
        let staged = match self.staged {
            Some(staged) => staged,
            None => *self.staged.insert(self.turn.app.staged_recovery_total()?),
        };
        let account_full = staged.bytes >= bounds.account_bytes;
        // No relay's share of a group is at a bound the whole account is
        // under.
        if !account_full && staged.events < bounds.group_events && staged.bytes < bounds.group_bytes
        {
            return Ok(false);
        }
        let group = self.group(&group_key)?;
        let Some(frontier) = group.frontier() else {
            return Ok(false);
        };
        if group.members.iter().any(|member| {
            member.key == *key && member.on_frontier && member.position == Some(frontier)
        }) {
            return Ok(false);
        }
        if account_full {
            return Ok(true);
        }
        let routes = group.routes.clone();
        let usage = self
            .turn
            .app
            .staged_recovery_usage(&routes, Some(&key.relay))?;
        Ok(usage.events >= bounds.group_events || usage.bytes >= bounds.group_bytes)
    }

    /// The routes whose units hold their group's live frames behind a fence:
    /// the runner serves them first.
    pub(super) fn fenced_routes(
        &mut self,
    ) -> StorageResult<BTreeSet<TransportReconciliationRoute>> {
        let mut routes = BTreeSet::new();
        for key in self.fence_groups()? {
            let group = self.group(&key)?;
            routes.extend(
                group
                    .members
                    .iter()
                    .filter(|member| member.holds_live_frames().is_some())
                    .map(|member| member.key.route.clone()),
            );
        }
        Ok(routes)
    }

    fn live_fences(&mut self) -> StorageResult<Vec<LiveFence>> {
        let mut fences = Vec::new();
        for key in self.fence_groups()? {
            let group = self.group(&key)?;
            if let Some(release_before) = group.release_before() {
                fences.push(LiveFence {
                    routes: group.routes.clone(),
                    release_before,
                });
            }
        }
        Ok(fences)
    }

    /// Keep each unit's owed capture ranges, at most `per_unit`, so the fence
    /// survives a restart, and drop ranges nothing owes any more, or those a
    /// relay no longer required keeps.
    fn record_fences(&mut self, per_unit: usize) -> StorageResult<()> {
        let app = self.turn.app;
        for key in self.fence_groups()? {
            let group = self.group(&key)?;
            let changed = group
                .members
                .iter()
                .filter_map(|member| {
                    let fences = bounded(member.fences.clone(), per_unit);
                    (fences != member.stored).then(|| (member.key.clone(), fences))
                })
                .collect::<Vec<_>>();
            for (unit, fences) in changed {
                app.set_recovery_unit_fences(&unit.route, &unit.relay, &fences)?;
            }
        }
        let demoted = self
            .fenced
            .iter()
            .flat_map(BTreeMap::keys)
            .filter(|unit| {
                self.route_groups
                    .get(&unit.route)
                    .and_then(|key| self.read.get(key))
                    .is_some_and(|group| !group.members.iter().any(|member| member.key == **unit))
            })
            .cloned()
            .collect::<Vec<_>>();
        for unit in demoted {
            app.set_recovery_unit_fences(&unit.route, &unit.relay, &[])?;
        }
        Ok(())
    }

    /// Give back what routes the runner no longer lists staged: nothing would
    /// admit it, and it would count against the account's bound for good.
    fn reclaim_unlisted(&mut self) -> StorageResult<()> {
        let app = self.turn.app;
        let unlisted = app
            .staged_recovery_routes()?
            .into_iter()
            .filter(|route| !self.route_groups.contains_key(route))
            .collect::<Vec<_>>();
        if unlisted.is_empty() {
            return Ok(());
        }
        let rows = app.reclaim_staged_recovery_routes(&unlisted)?;
        tracing::debug!(
            target: TARGET,
            method = "reclaim_unlisted",
            routes = unlisted.len(),
            rows = rows,
        );
        Ok(())
    }

    /// Up to `per_turn` staged events below their groups' frontiers, oldest
    /// first, from groups not `held`. Rows that no longer decode are
    /// discarded instead, and nothing is released that turn.
    fn releasable(&mut self, per_turn: usize, held: &BTreeSet<GroupKey>) -> StorageResult<Batch> {
        let app = self.turn.app;
        let staged = app
            .staged_recovery_routes()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let keys = self
            .groups
            .iter()
            .filter(|(key, routes)| {
                !held.contains(*key) && routes.iter().any(|route| staged.contains(&route.route))
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut events = Vec::new();
        let mut undecodable = Vec::new();
        for key in keys {
            let group = self.group(&key)?;
            let before = group.frontier().unwrap_or(NO_FRONTIER);
            let routes = group.routes.clone();
            let read = app.staged_recovery_events(&routes, before, per_turn)?;
            undecodable.extend(read.undecodable);
            events.extend(read.events.into_iter().map(|event| (key.clone(), event)));
        }
        if !undecodable.is_empty() {
            for event_id in &undecodable {
                app.discard_undecodable_staged_recovery_event(event_id)?;
            }
            return Ok(Batch {
                events: Vec::new(),
                discarded: undecodable.len(),
            });
        }
        events.sort_by(|(_, left), (_, right)| order(left).cmp(&order(right)));
        events.truncate(per_turn);
        Ok(Batch {
            events,
            discarded: 0,
        })
    }

    /// The groups a fence may hold: those with a live count's capture or a
    /// unit that keeps a fence.
    fn fence_groups(&mut self) -> StorageResult<BTreeSet<GroupKey>> {
        self.stored_fences()?;
        Ok(self
            .captures
            .keys()
            .map(|(route, _)| *route)
            .chain(
                self.fenced
                    .iter()
                    .flat_map(BTreeMap::keys)
                    .map(|unit| &unit.route),
            )
            .filter_map(|route| self.route_groups.get(route).cloned())
            .collect())
    }

    /// The ranges each unit keeps fenced, read on first use.
    fn stored_fences(&mut self) -> StorageResult<&BTreeMap<UnitKey, Vec<RecoveryCoverageRange>>> {
        if self.fenced.is_none() {
            let mut fenced: BTreeMap<UnitKey, Vec<RecoveryCoverageRange>> = BTreeMap::new();
            for fence in self.turn.app.recovery_unit_fences()? {
                fenced
                    .entry(UnitKey {
                        route: fence.route,
                        relay: fence.relay,
                    })
                    .or_default()
                    .push(fence.range);
            }
            self.fenced = Some(fenced);
        }
        Ok(self.fenced.get_or_insert_default())
    }

    /// The group `key` names, read on first use.
    fn group(&mut self, key: &GroupKey) -> StorageResult<&Group> {
        if !self.read.contains_key(key) {
            let group = self.read_group(key)?;
            self.read.insert(key.clone(), group);
        }
        Ok(&self.read[key])
    }

    fn read_group(&mut self, key: &GroupKey) -> StorageResult<Group> {
        let turn = self.turn;
        let routes = self.groups.get(key).cloned().unwrap_or_default();
        let mut members = Vec::new();
        for route in routes.iter().copied() {
            for relay in route.required.iter().collect::<BTreeSet<_>>() {
                let owed_until = turn.tails.owed_until(&route.route, relay, turn.now);
                let debt = turn
                    .app
                    .recovery_unit_debt(&route.route, relay, owed_until)?;
                let unit = turn.app.recovery_unit(&route.route, relay)?;
                let left = self.relay_left(relay)?
                    || unit.as_ref().is_some_and(|unit| {
                        unit.no_progress > 0 || unit.state != RecoveryUnitState::Active
                    });
                let key = UnitKey {
                    route: route.route.clone(),
                    relay: relay.clone(),
                };
                let stored = self.stored_fences()?.get(&key).cloned().unwrap_or_default();
                let captures = stored
                    .iter()
                    .copied()
                    .chain(
                        self.captures
                            .get(&(&route.route, relay.as_str()))
                            .into_iter()
                            .flatten()
                            .copied(),
                    )
                    .collect();
                let position = debt.first().map(|range| range.since_seconds);
                let (fences, first_owed) = owed(merge(captures), &debt);
                members.push(Member {
                    key,
                    position,
                    on_frontier: position.is_some() && !left,
                    stored,
                    fences,
                    first_owed,
                });
            }
        }
        Ok(Group {
            routes: routes.iter().map(|route| route.route.clone()).collect(),
            members,
        })
    }

    /// Whether the relay's last answer was that it could not be reached, or
    /// it is cooling down: it leaves every frontier.
    fn relay_left(&mut self, relay: &'t str) -> StorageResult<bool> {
        if let Some(left) = self.relays_left.get(relay) {
            return Ok(*left);
        }
        let now = self.turn.now;
        let left = self
            .turn
            .app
            .recovery_relay_health(relay)?
            .is_some_and(|health| {
                health.unreachable_streak > 0
                    || health.cooldown.is_some_and(|(_, until)| until > now)
            });
        self.relays_left.insert(relay, left);
        Ok(left)
    }
}

/// Admission order: `(created_at, id)`.
fn order(event: &StagedRecoveryEvent) -> (u64, &[u8]) {
    (
        event.delivery.message.timestamp.0,
        event.delivery.message.id.as_slice(),
    )
}

/// `ranges` sorted, with overlapping and adjacent ones joined.
fn merge(mut ranges: Vec<RecoveryCoverageRange>) -> Vec<RecoveryCoverageRange> {
    ranges.sort_by_key(|range| (range.since_seconds, range.until_seconds));
    let mut merged: Vec<RecoveryCoverageRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.since_seconds <= last.until_seconds.saturating_add(1) => {
                last.until_seconds = last.until_seconds.max(range.until_seconds);
            }
            _ => merged.push(range),
        }
    }
    merged
}

/// Those of `captures` (sorted, disjoint) that `debt` (sorted) still owes,
/// and the first second owed in them.
fn owed(
    captures: Vec<RecoveryCoverageRange>,
    debt: &[RecoveryCoverageRange],
) -> (Vec<RecoveryCoverageRange>, Option<u64>) {
    let mut first_owed = None;
    let owed = captures
        .into_iter()
        .filter(|capture| {
            let Some(owed) = debt.iter().find(|owed| {
                owed.until_seconds >= capture.since_seconds
                    && owed.since_seconds <= capture.until_seconds
            }) else {
                return false;
            };
            first_owed.get_or_insert(owed.since_seconds.max(capture.since_seconds));
            true
        })
        .collect();
    (owed, first_owed)
}

/// `fences` (sorted, disjoint) with the newest joined into one past
/// `per_unit`, which only ever fences more.
fn bounded(mut fences: Vec<RecoveryCoverageRange>, per_unit: usize) -> Vec<RecoveryCoverageRange> {
    while fences.len() > per_unit.max(1) {
        let Some(newest) = fences.pop() else { break };
        if let Some(last) = fences.last_mut() {
            last.until_seconds = newest.until_seconds;
        }
    }
    fences
}

/// Where each fenced group's held live frames may be released up to, as of
/// `turn`. PR 5's adapter hold reads this in place of owner capture; like the
/// live tails it is a query, never a value to keep across a wait.
pub(crate) fn live_fences(turn: &DebtTurn<'_>) -> StorageResult<Vec<LiveFence>> {
    Admission::new(turn).live_fences()
}

/// One admission turn's events, each with its group. Not `Debug`.
struct Batch {
    events: Vec<(GroupKey, StagedRecoveryEvent)>,
    /// Rows that no longer decode, discarded and owed again.
    discarded: usize,
}

/// Plan one admission turn: give back what unlisted routes staged, record the
/// units' fences, then pick what may be released.
fn plan(
    turn: &DebtTurn<'_>,
    policy: &RecoveryRunnerPolicy,
    held: &BTreeSet<GroupKey>,
) -> StorageResult<Batch> {
    let mut admission = Admission::new(turn);
    admission.reclaim_unlisted()?;
    admission.record_fences(policy.fences_per_unit)?;
    admission.releasable(policy.admission_per_turn, held)
}

/// What admission keeps in memory between turns. A restart forgets it, which
/// costs at most an early retry per held group.
#[derive(Default)]
pub(super) struct Memory {
    /// Groups waiting behind a staged event the engine kept no trace of:
    /// until when, and the tries in a row.
    held: BTreeMap<GroupKey, (u64, u32)>,
    /// Admission turns that failed in a row, and until when admission waits.
    failures: u32,
    paused_until: u64,
}

impl Memory {
    /// The earliest second admission has something to retry.
    fn next_due(&self, now: u64) -> Option<u64> {
        self.held
            .values()
            .map(|(until, _)| *until)
            .chain(std::iter::once(self.paused_until))
            .filter(|due| *due > now)
            .min()
    }

    fn hold(&mut self, group: GroupKey, now: u64, policy: &RecoveryRunnerPolicy) {
        let tries = self
            .held
            .get(&group)
            .map_or(0, |(_, tries)| *tries)
            .saturating_add(1);
        let until = now.saturating_add(policy.local_failure_backoff_seconds(tries));
        self.held.insert(group, (until, tries));
    }

    fn failed(
        &mut self,
        method: &'static str,
        error_kind: &'static str,
        now: u64,
        policy: &RecoveryRunnerPolicy,
    ) -> Option<u64> {
        self.failures = self.failures.saturating_add(1);
        self.paused_until = now.saturating_add(policy.local_failure_backoff_seconds(self.failures));
        tracing::warn!(
            target: TARGET,
            method = method,
            error_kind = error_kind,
            "recovery runner admission failed"
        );
        self.next_due(now)
    }
}

impl<H: RunnerHost> RecoveryRunner<H> {
    /// Admit what staging may release, one turn after another, until a turn
    /// finds nothing. Returns when admission next has something to retry, or
    /// the step to end with.
    pub(super) async fn admit(
        &mut self,
        pass_deadline: Option<Instant>,
    ) -> Result<Option<u64>, Step> {
        loop {
            if self.cancel.is_cancelled() {
                return Err(Step::Stopped);
            }
            if pass_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(Step::Idle { next_due: None });
            }
            let now = self.host.now_seconds();
            if self.admission.paused_until > now {
                return Ok(self.admission.next_due(now));
            }
            let held = self
                .admission
                .held
                .iter()
                .filter(|(_, (until, _))| *until > now)
                .map(|(group, _)| group.clone())
                .collect::<BTreeSet<_>>();
            let policy = self.policy;
            let batch = match self
                .host
                .debt_turn(move |turn| plan(turn, &policy, &held))
                .await
            {
                None => return Err(Step::Stopped),
                Some(Ok(batch)) => batch,
                Some(Err(error)) => {
                    let kind = AppError::from(error).privacy_safe_kind();
                    return Ok(self
                        .admission
                        .failed("admission_plan", kind, now, &self.policy));
                }
            };
            if batch.discarded > 0 {
                continue;
            }
            if batch.events.is_empty() {
                self.admission.failures = 0;
                return Ok(self.admission.next_due(now));
            }
            // In order; an event the engine kept no trace of, or a failure,
            // ends the turn, so nothing newer of its group goes ahead of it.
            let mut tried = Vec::with_capacity(batch.events.len());
            let mut failure = None;
            for (group, event) in batch.events {
                let event_id = event.delivery.message.id.as_slice().to_vec();
                let Some(admitted) = self.host.admit_staged(event.delivery).await else {
                    return Err(Step::Stopped);
                };
                tried.push((group, event_id));
                match admitted {
                    Ok(Admitted::Kept) => {}
                    Ok(Admitted::NoTrace) => break,
                    Err(kind) => {
                        failure = Some(kind);
                        break;
                    }
                }
            }
            let event_ids = tried
                .iter()
                .map(|(_, event_id)| event_id.clone())
                .collect::<Vec<_>>();
            let removed = match self
                .host
                .turn(move |turn| {
                    event_ids
                        .iter()
                        .map(|event_id| {
                            Ok(turn.app.remove_seen_staged_recovery_events(&[event_id])? > 0)
                        })
                        .collect::<StorageResult<Vec<bool>>>()
                })
                .await
            {
                None => return Err(Step::Stopped),
                Some(Ok(removed)) => removed,
                Some(Err(error)) => {
                    let kind = AppError::from(error).privacy_safe_kind();
                    return Ok(self
                        .admission
                        .failed("admission_settle", kind, now, &self.policy));
                }
            };
            // A row whose event is not in the seen index after its ingest
            // stays staged, and its group waits behind it.
            let mut kept_back = BTreeSet::new();
            let mut moved = BTreeSet::new();
            for ((group, _), removed) in tried.into_iter().zip(removed) {
                if removed {
                    moved.insert(group);
                } else {
                    kept_back.insert(group);
                }
            }
            tracing::debug!(
                target: TARGET,
                method = "admit",
                groups_admitted = moved.len(),
                groups_held = kept_back.len(),
            );
            for group in moved.difference(&kept_back) {
                self.admission.held.remove(group);
            }
            for group in kept_back {
                self.admission.hold(group, now, &self.policy);
            }
            if let Some(kind) = failure {
                return Ok(self
                    .admission
                    .failed("admission_ingest", kind, now, &self.policy));
            }
            self.admission.failures = 0;
        }
    }
}
