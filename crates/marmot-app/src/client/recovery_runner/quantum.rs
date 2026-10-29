//! One sweep quantum and its settlement.
//!
//! The quantum walks each planned range oldest first on one (route, relay),
//! all under one deadline, and stops at the first range that does not finish.
//! Its resume point is the ledger's, read in the begin turn: the cursor store
//! keeps only the slice width and the observed cap, which settlement records,
//! so a crash after a slice was staged refetches nothing and a crash before
//! refetches that one slice.
//!
//! Progress is newly covered seconds on the unit's own (route, relay), as the
//! ledger reads before and after each staged slice. Coverage other writers
//! recorded (live traffic, another route, another relay) is not this quantum's
//! progress, so it resets nothing.
//!
//! Every event byte the relay returns is charged to the account's rolling
//! hour, including full replies a halving discards, saturated seconds and
//! duplicates: each staged slice carries what was returned since the last
//! one, and settlement charges the rest. A best-effort relay is never charged.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use cgka_traits::TransportDelivery;
use cgka_traits::storage::StorageResult;
use nostr::prelude::Event;
use storage_sqlite::{
    RecoveryCoverageMark, RecoveryCoverageProof, RecoveryCoverageRange, RecoveryStagedSlice,
    RecoveryUnitOutcome, SqliteAppStorage,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use transport_nostr_adapter::sweep::{
    CoveredSlice, RelayCaps, SecondReply, SliceQuery, SliceReply, SweepCursor, SweepCursorStore,
    SweepEnd, SweepRelay, SweepRequest, SweepRoute, SweepSink, SweepSinkError, SweepStoreError,
    UnreachableKind, run_sweep,
};

use super::select::SweepPlan;
use super::{RecoveryRunnerPolicy, RunnerHost, UnitKey, WorkerTurn};

/// Why staging refused a slice and stopped the sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SinkStop {
    /// The staging transaction failed.
    Local,
    /// The un-cover log no longer reaches the quantum's mark, so its coverage
    /// cannot be recorded. Not the relay's fault: a fresh mark fixes it.
    StaleMark,
    /// The worker is gone.
    WorkerGone,
}

/// What one quantum did, in aggregate.
#[derive(Clone, Copy, Debug)]
pub(super) struct QuantumReport {
    /// How its last sweep call ended; `Finished` when every range finished.
    pub(super) end: SweepEnd,
    pub(super) requests: u32,
    pub(super) answers: u32,
    /// Waits for a `rate-limited:` CLOSED.
    pub(super) rate_limited_waits: u32,
    /// Event bytes the relay returned that no staged slice charged.
    pub(super) unstaged_bytes: u64,
    /// Seconds it newly covered on its own (route, relay).
    pub(super) newly_covered_seconds: u64,
    /// Seconds and events in the slices it proved: the route's rate.
    pub(super) proved_seconds: u64,
    pub(super) proved_events: u64,
    /// The slice width and observed cap it ended with.
    pub(super) delta: u64,
    pub(super) observed_cap: Option<u32>,
    pub(super) stop: Option<SinkStop>,
}

/// The sweep's cursor store. The resume point comes from the ledger, so this
/// only carries the slice width and observed cap between slices.
struct PlannedCursor(Mutex<SweepCursor>);

impl PlannedCursor {
    fn get(&self) -> SweepCursor {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl SweepCursorStore for PlannedCursor {
    async fn load(&self) -> Result<Option<SweepCursor>, SweepStoreError> {
        Ok(Some(self.get()))
    }

    async fn save(&self, cursor: SweepCursor) -> Result<(), SweepStoreError> {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = cursor;
        Ok(())
    }
}

/// The unit's relay, counting the event bytes of every reply it returns.
struct Metered<'a> {
    relay: &'a dyn SweepRelay,
    bytes: &'a AtomicU64,
}

impl Metered<'_> {
    fn count(&self, events: &[Event]) {
        self.bytes.fetch_add(event_bytes(events), Ordering::Relaxed);
    }
}

#[async_trait]
impl SweepRelay for Metered<'_> {
    fn caps(&self) -> RelayCaps {
        self.relay.caps()
    }

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        let reply = self.relay.fetch_slice(query).await;
        if let SliceReply::Answered { events, .. } = &reply {
            self.count(events);
        }
        reply
    }

    async fn fetch_second(&self, route: SweepRoute, second: u64, cap: Option<u32>) -> SecondReply {
        let reply = self.relay.fetch_second(route, second, cap).await;
        if let SecondReply::Complete(events) = &reply {
            self.count(events);
        }
        reply
    }
}

fn event_bytes(events: &[Event]) -> u64 {
    events
        .iter()
        .map(|event| event.as_json().len() as u64)
        .fold(0u64, u64::saturating_add)
}

/// Stages each proven slice in its own worker turn and counts the seconds it
/// newly covered.
struct StageSink<'a, H> {
    host: &'a H,
    plan: &'a SweepPlan,
    /// Bytes the relay returned that no staged slice has charged yet.
    returned_bytes: &'a AtomicU64,
    newly_covered_seconds: u64,
    stop: Option<SinkStop>,
}

#[async_trait]
impl<H: RunnerHost> SweepSink for StageSink<'_, H> {
    async fn admit(
        &mut self,
        slice: CoveredSlice,
        events: Vec<Event>,
    ) -> Result<(), SweepSinkError> {
        let fetched_bytes = if self.plan.best_effort {
            0
        } else {
            self.returned_bytes.swap(0, Ordering::Relaxed)
        };
        let mut deliveries = Vec::with_capacity(events.len());
        for event in events {
            deliveries.extend(self.host.deliveries(&self.plan.key.relay, event).await);
        }
        let key = self.plan.key.clone();
        let mark = self.plan.mark;
        let range = RecoveryCoverageRange {
            since_seconds: slice.since,
            until_seconds: slice.until,
        };
        let staged = self
            .host
            .turn(move |turn| stage(turn, &key, &deliveries, fetched_bytes, range, mark))
            .await;
        let stop = match staged {
            None => SinkStop::WorkerGone,
            Some(Err(error)) => {
                super::log_failure("stage", error);
                SinkStop::Local
            }
            // The transaction committed, bytes included.
            Some(Ok(None)) => SinkStop::StaleMark,
            Some(Ok(Some(newly))) => {
                self.newly_covered_seconds = self.newly_covered_seconds.saturating_add(newly);
                return Ok(());
            }
        };
        if stop != SinkStop::StaleMark {
            // Nothing was written: settlement charges these bytes instead.
            self.returned_bytes
                .fetch_add(fetched_bytes, Ordering::Relaxed);
        }
        self.stop = Some(stop);
        Err(SweepSinkError)
    }
}

/// Stage one proven slice and return the seconds it newly covered on its
/// (route, relay), or `None` when the mark is too old to record it.
fn stage(
    turn: &WorkerTurn<'_>,
    key: &UnitKey,
    deliveries: &[TransportDelivery],
    fetched_bytes: u64,
    range: RecoveryCoverageRange,
    mark: RecoveryCoverageMark,
) -> StorageResult<Option<u64>> {
    let before = uncovered_seconds(turn.app, key, range)?;
    let staged = turn.app.stage_recovery_slice(
        &RecoveryStagedSlice {
            route: &key.route,
            relay: &key.relay,
            events: deliveries,
            fetched_bytes,
            covered: &[range],
            proof: RecoveryCoverageProof::SweepSlice,
            mark,
        },
        turn.now,
    )?;
    if !staged.covered {
        return Ok(None);
    }
    let after = uncovered_seconds(turn.app, key, range)?;
    Ok(Some(before.saturating_sub(after)))
}

/// Seconds of `range` the ledger does not cover on the unit's relay.
fn uncovered_seconds(
    app: &SqliteAppStorage,
    key: &UnitKey,
    range: RecoveryCoverageRange,
) -> StorageResult<u64> {
    let mut covered = app
        .recovery_coverage_ranges(&key.route, &key.relay)?
        .into_iter()
        .map(|proved| {
            (
                proved.range.since_seconds.max(range.since_seconds),
                proved.range.until_seconds.min(range.until_seconds),
            )
        })
        .filter(|(since, until)| since <= until)
        .collect::<Vec<_>>();
    covered.sort_unstable();
    let mut seconds = 0u64;
    let mut next = range.since_seconds;
    for (since, until) in covered {
        let since = since.max(next);
        if since <= until {
            seconds = seconds.saturating_add(until - since + 1);
            next = until.saturating_add(1);
        }
    }
    Ok((range.until_seconds - range.since_seconds + 1).saturating_sub(seconds))
}

/// Run the quantum: each planned range in turn, until one does not finish or
/// the deadline comes.
pub(super) async fn run<H: RunnerHost>(
    host: &H,
    plan: &SweepPlan,
    caps: RelayCaps,
    deadline: Instant,
    cancel: &CancellationToken,
    policy: &RecoveryRunnerPolicy,
) -> QuantumReport {
    let mut report = QuantumReport {
        end: SweepEnd::Finished,
        requests: 0,
        answers: 0,
        rate_limited_waits: 0,
        unstaged_bytes: 0,
        newly_covered_seconds: 0,
        proved_seconds: 0,
        proved_events: 0,
        delta: plan.delta,
        observed_cap: plan.observed_cap,
        stop: None,
    };
    let Some(relay) = host.sweep_relay(&plan.key.relay, caps, policy.request_timeout) else {
        report.end = SweepEnd::Unreachable(UnreachableKind::Disconnected);
        return report;
    };
    let returned_bytes = AtomicU64::new(0);
    let relay = Metered {
        relay: &*relay,
        bytes: &returned_bytes,
    };
    let route = SweepRoute::Group {
        nostr_group_id: plan.nostr_group_id,
    };
    let mut sink = StageSink {
        host,
        plan,
        returned_bytes: &returned_bytes,
        newly_covered_seconds: 0,
        stop: None,
    };
    for range in &plan.ranges {
        let store = PlannedCursor(Mutex::new(SweepCursor {
            next_since: range.since,
            delta: report.delta,
            observed_cap: report.observed_cap,
        }));
        let swept = run_sweep(
            SweepRequest {
                route,
                range: *range,
                deadline: Some(deadline),
                policy: policy.sweep,
            },
            &relay,
            &mut sink,
            &store,
            cancel,
        )
        .await;
        report.requests = report.requests.saturating_add(swept.stats.requests);
        report.answers = report.answers.saturating_add(swept.stats.answers);
        report.rate_limited_waits = report
            .rate_limited_waits
            .saturating_add(swept.stats.rate_limited_waits);
        for slice in &swept.covered {
            report.proved_seconds = report
                .proved_seconds
                .saturating_add(slice.until - slice.since + 1);
            report.proved_events = report.proved_events.saturating_add(u64::from(slice.events));
        }
        let cursor = store.get();
        report.delta = cursor.delta;
        report.observed_cap = cursor.observed_cap;
        report.end = swept.end;
        if swept.end != SweepEnd::Finished {
            break;
        }
    }
    report.newly_covered_seconds = sink.newly_covered_seconds;
    report.stop = sink.stop;
    if !plan.best_effort {
        report.unstaged_bytes = returned_bytes.into_inner();
    }
    report
}

/// The outcome table (section 3 of the plan) for one quantum. `still_owed`
/// says whether the planned ranges still owe anything on this relay; it only
/// matters for a quantum that finished without newly covering anything.
pub(super) fn classify(
    end: SweepEnd,
    answered: bool,
    rate_limited: bool,
    newly_covered_seconds: u64,
    stop: Option<SinkStop>,
    still_owed: bool,
) -> RecoveryUnitOutcome {
    use RecoveryUnitOutcome as Outcome;
    let local = match end {
        SweepEnd::SinkFailed => !matches!(stop, Some(SinkStop::StaleMark | SinkStop::WorkerGone)),
        SweepEnd::StoreFailed => true,
        _ => false,
    };
    if local {
        // A failed local write outranks progress, as in the sweep's own
        // classifier. The slices staged before it stay covered.
        return Outcome::LocalFailure;
    }
    if newly_covered_seconds > 0 {
        // A cut or a cancellation after progress included.
        return Outcome::Advanced;
    }
    match end {
        // A stale mark or a gone worker; a store failure is local, above.
        SweepEnd::SinkFailed | SweepEnd::StoreFailed => Outcome::Unanswered,
        // Every slice was proven, but none newly covered: someone else proved
        // them first, or a loss during the fetch took them back.
        SweepEnd::Finished if still_owed => Outcome::NoProgress,
        SweepEnd::Finished => Outcome::NothingOwed,
        SweepEnd::Cancelled => Outcome::Unanswered,
        // The relay said only `rate-limited:`, and the next wait would have
        // outlasted the quantum: rate limited and never cleared.
        SweepEnd::DeadlineReached if !answered && rate_limited => Outcome::RateLimited,
        SweepEnd::DeadlineReached if !answered => Outcome::Unanswered,
        SweepEnd::DeadlineReached | SweepEnd::SaturatedSecond { .. } => Outcome::NoProgress,
        SweepEnd::RateLimited => Outcome::RateLimited,
        SweepEnd::Refused(_) => Outcome::Refused,
        SweepEnd::Unreachable(_) => Outcome::Unreachable,
    }
}

/// Settle the quantum: charge the bytes no staged slice charged, apply its
/// outcome to the unit's retry state, and record its slicing. A best-effort
/// relay keeps no retry state.
pub(super) fn settle(
    turn: &WorkerTurn<'_>,
    plan: &SweepPlan,
    report: &QuantumReport,
    policy: &RecoveryRunnerPolicy,
) -> StorageResult<RecoveryUnitOutcome> {
    let still_owed = if report.newly_covered_seconds == 0 && report.end == SweepEnd::Finished {
        planned_ranges_owe(turn.app, plan)?
    } else {
        true
    };
    let outcome = classify(
        report.end,
        report.answers > 0,
        report.rate_limited_waits > 0,
        report.newly_covered_seconds,
        report.stop,
        still_owed,
    );
    if plan.best_effort {
        return Ok(outcome);
    }
    let key = &plan.key;
    if report.unstaged_bytes > 0 {
        // A slice that proves nothing: the bytes alone.
        turn.app.stage_recovery_slice(
            &RecoveryStagedSlice {
                route: &key.route,
                relay: &key.relay,
                events: &[],
                fetched_bytes: report.unstaged_bytes,
                covered: &[],
                proof: RecoveryCoverageProof::SweepSlice,
                mark: plan.mark,
            },
            turn.now,
        )?;
    }
    turn.app
        .settle_recovery_unit(&key.route, &key.relay, outcome, &policy.unit, turn.now)?;
    // The slicing only seeds the next quantum's first request, so a failed
    // write costs one resize and never changes the settled outcome.
    if (report.delta, report.observed_cap) != (plan.delta, plan.observed_cap)
        && report.delta > 0
        && report.observed_cap != Some(0)
        && let Err(error) = turn.app.record_recovery_unit_slicing(
            &key.route,
            &key.relay,
            report.delta,
            report.observed_cap,
        )
    {
        super::log_failure("slicing", error);
    }
    Ok(outcome)
}

/// Whether the unit's durable debt still overlaps any planned range.
fn planned_ranges_owe(app: &SqliteAppStorage, plan: &SweepPlan) -> StorageResult<bool> {
    let Some(until) = plan.ranges.iter().map(|range| range.until).max() else {
        return Ok(false);
    };
    let debt = app.recovery_unit_debt(&plan.key.route, &plan.key.relay, until)?;
    Ok(debt.iter().any(|owed| {
        plan.ranges
            .iter()
            .any(|range| owed.since_seconds <= range.until && range.since <= owed.until_seconds)
    }))
}

pub(super) fn end_label(end: SweepEnd) -> &'static str {
    match end {
        SweepEnd::Finished => "finished",
        SweepEnd::DeadlineReached => "deadline",
        SweepEnd::Cancelled => "cancelled",
        SweepEnd::SaturatedSecond { .. } => "saturated_second",
        SweepEnd::RateLimited => "rate_limited",
        SweepEnd::Refused(_) => "refused",
        SweepEnd::Unreachable(_) => "unreachable",
        SweepEnd::SinkFailed => "sink_failed",
        SweepEnd::StoreFailed => "store_failed",
    }
}
