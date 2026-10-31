//! One comparison quantum: NIP-77 comparisons of a unit's planned ranges with
//! what the account holds there, oldest first, each difference fetched by id
//! (`run_comparison`).
//!
//! A debt unit compares instead of sweeping when its relay's caps show
//! NIP-77 and the account already holds events in the owed ranges, from the
//! inventory's floor on ([`plan_debt`]). Otherwise a sweep is cheaper: with
//! nothing held, every id the relay names is fetched anyway. A re-check
//! ([`super::recheck`]) always compares.
//!
//! Each window the comparison certifies is staged with its events and covered
//! through the quantum's mark, as a sweep slice is. What a cut window fetched
//! is staged uncovered: the next quantum's held set includes it, so a large
//! difference finishes over several quanta and nothing is fetched twice. One
//! quantum fetches at most what one relay may stage for a group.
//!
//! The quantum reports through the sweep's [`QuantumReport`], with its end
//! read as the sweep end that settles alike ([`verdict`]), so the outcome
//! table stays `quantum::classify` alone.

use async_trait::async_trait;
use cgka_traits::TransportDelivery;
use cgka_traits::storage::StorageResult;
use nostr::prelude::{Event, EventId};
use storage_sqlite::{
    RecoveryCoverageMark, RecoveryCoverageProof, RecoveryCoverageRange, RecoveryStagedSlice,
    SqliteAppStorage, TransportReconciliationItem, TransportReconciliationRoute,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use transport_nostr_adapter::compare::{
    CompareEnd, ComparePolicy, CompareRequest, CompareSink, LocalItem, run_comparison,
};
use transport_nostr_adapter::sweep::{
    RelayCaps, SweepEnd, SweepRange, SweepRoute, SweepSinkError, UnreachableKind,
};

use super::quantum::{QuantumReport, SinkStop, route_events, uncovered_seconds};
use super::{RecoveryRunnerPolicy, RunnerHost, UnitKey, WorkerTurn};

/// One range a comparison quantum compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PlannedRange {
    pub(super) range: SweepRange,
    /// Covered when planned: what a re-check finds there arrived late.
    pub(super) covered: bool,
}

/// What one comparison quantum compares. Not `Debug`: it carries its unit.
pub(super) struct ComparePlan {
    pub(super) key: UnitKey,
    pub(super) nostr_group_id: [u8; 32],
    pub(super) best_effort: bool,
    /// The relay's caps as last known: the comparison read NIP-77 there.
    pub(super) caps: RelayCaps,
    /// Oldest first.
    pub(super) ranges: Vec<PlannedRange>,
    /// What the account holds in the ranges: its inventory and what any
    /// relay staged, sorted.
    pub(super) local: Vec<LocalItem>,
    /// The un-cover generation before the fetch.
    pub(super) mark: RecoveryCoverageMark,
    /// A re-check: a certified window that found nothing is proved as a
    /// re-check, one that found something as a comparison.
    pub(super) recheck: bool,
}

/// What a comparison quantum adds to its [`QuantumReport`].
#[derive(Clone, Copy, Debug)]
pub(super) struct CompareFacts {
    /// How its last comparison call ended.
    pub(super) end: CompareEnd,
    /// The second after the last window it certified: where a re-check pass
    /// resumes.
    pub(super) checked_through: Option<u64>,
    /// Events staged inside ranges covered when planned.
    pub(super) late: u64,
}

/// A debt unit's comparison plan, when it should compare: its relay's caps
/// as last recorded show NIP-77, the owed ranges start at or after the
/// inventory's floor, and the account holds events in them. `None` sweeps.
pub(super) fn plan_debt(
    app: &SqliteAppStorage,
    key: &UnitKey,
    ranges: &[SweepRange],
    now: u64,
) -> StorageResult<Option<(RelayCaps, Vec<LocalItem>)>> {
    let (Some(first), Some(last)) = (ranges.first(), ranges.last()) else {
        return Ok(None);
    };
    let Some(caps) = recorded_caps(app, &key.relay)? else {
        return Ok(None);
    };
    let inventory = app.transport_reconciliation_inventory(&key.route, now)?;
    if first.since < inventory.since {
        return Ok(None);
    }
    let local = local_items(app, &key.route, &inventory.items, first.since, last.until)?;
    let held = local.iter().any(|item| {
        ranges
            .iter()
            .any(|range| range.since <= item.created_at && item.created_at <= range.until)
    });
    Ok(held.then_some((caps, local)))
}

/// The relay's recorded caps, if they show NIP-77.
pub(super) fn recorded_caps(
    app: &SqliteAppStorage,
    relay: &str,
) -> StorageResult<Option<RelayCaps>> {
    Ok(app
        .recovery_relay_health(relay)?
        .and_then(|health| health.caps)
        .filter(|caps| caps.negentropy)
        .map(|caps| RelayCaps {
            max_limit: caps.max_limit,
            negentropy: true,
        }))
}

/// What the account holds of `route` from `since` through `until`: its
/// inventory and what any relay staged there.
pub(super) fn local_items(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
    inventory: &[TransportReconciliationItem],
    since: u64,
    until: u64,
) -> StorageResult<Vec<LocalItem>> {
    let item = |held: &TransportReconciliationItem| LocalItem {
        created_at: held.created_at,
        id: EventId::from_byte_array(held.event_id),
    };
    let mut local = inventory
        .iter()
        .filter(|held| since <= held.created_at && held.created_at <= until)
        .map(item)
        .collect::<Vec<_>>();
    local.extend(
        app.staged_recovery_items(route, since, until)?
            .iter()
            .map(item),
    );
    local.sort_unstable();
    local.dedup();
    Ok(local)
}

/// The sweep end a comparison end settles as.
fn verdict(end: CompareEnd, first_unproven: u64) -> SweepEnd {
    match end {
        CompareEnd::Finished => SweepEnd::Finished,
        CompareEnd::DeadlineReached => SweepEnd::DeadlineReached,
        // A relay that would not compare taught nothing about the unit: the
        // runner sweeps it from now on (`would_not_compare`).
        CompareEnd::Cancelled | CompareEnd::Unsupported | CompareEnd::Refused(_) => {
            SweepEnd::Cancelled
        }
        // The relay answered and the rest of the window is unproven, as when a
        // sweep meets a saturated second.
        CompareEnd::BudgetSpent | CompareEnd::Withheld => SweepEnd::SaturatedSecond {
            second: first_unproven,
        },
        CompareEnd::SaturatedWindow { second } => SweepEnd::SaturatedSecond { second },
        CompareEnd::RateLimited => SweepEnd::RateLimited,
        CompareEnd::Unreachable(kind) => SweepEnd::Unreachable(kind),
        CompareEnd::SinkFailed => SweepEnd::SinkFailed,
    }
}

/// Stages each batch the comparison hands over in its own worker turn.
struct CompareStage<'a, H> {
    host: &'a H,
    plan: &'a ComparePlan,
    /// The range being compared was covered when planned.
    covered: bool,
    newly_covered_seconds: u64,
    late: u64,
    /// Bytes charged to staged batches.
    staged_bytes: u64,
    /// Bytes of batches that never reached storage, for settlement.
    unstaged_bytes: u64,
    stop: Option<SinkStop>,
}

#[async_trait]
impl<H: RunnerHost> CompareSink for CompareStage<'_, H> {
    async fn admit(
        &mut self,
        window: SweepRange,
        certified: bool,
        events: Vec<Event>,
        fetched_bytes: u64,
    ) -> Result<(), SweepSinkError> {
        let fetched_bytes = if self.plan.best_effort {
            0
        } else {
            fetched_bytes
        };
        let found = !events.is_empty();
        let Some(deliveries) = route_events(self.host, &self.plan.key.relay, events).await else {
            // Nothing was written: settlement charges these bytes instead.
            self.unstaged_bytes = self.unstaged_bytes.saturating_add(fetched_bytes);
            self.stop = Some(SinkStop::Unrouted);
            return Err(SweepSinkError);
        };
        let key = self.plan.key.clone();
        let mark = self.plan.mark;
        let proof = if self.plan.recheck && !found {
            RecoveryCoverageProof::Recheck
        } else {
            RecoveryCoverageProof::Comparison
        };
        let covered = certified.then_some(RecoveryCoverageRange {
            since_seconds: window.since,
            until_seconds: window.until,
        });
        let staged = self
            .host
            .turn(move |turn| stage(turn, &key, &deliveries, fetched_bytes, covered, proof, mark))
            .await;
        let stop = match staged {
            None => SinkStop::WorkerGone,
            Some(Err(error)) => {
                super::log_failure("stage", error);
                SinkStop::Local
            }
            // The transaction committed, bytes and events included.
            Some(Ok(None)) => {
                self.staged_bytes = self.staged_bytes.saturating_add(fetched_bytes);
                SinkStop::StaleMark
            }
            Some(Ok(Some(staged))) => {
                self.staged_bytes = self.staged_bytes.saturating_add(fetched_bytes);
                self.newly_covered_seconds =
                    self.newly_covered_seconds.saturating_add(staged.newly);
                if self.covered {
                    self.late = self.late.saturating_add(staged.events);
                }
                return Ok(());
            }
        };
        if stop != SinkStop::StaleMark {
            // Nothing was written: settlement charges these bytes instead.
            self.unstaged_bytes = self.unstaged_bytes.saturating_add(fetched_bytes);
        }
        self.stop = Some(stop);
        Err(SweepSinkError)
    }
}

/// What staging one batch did.
struct Staged {
    /// Seconds it newly covered on the unit's (route, relay).
    newly: u64,
    /// Events newly staged.
    events: u64,
}

/// Stage one batch: its events, and `covered` through `mark` when the window
/// was certified. `None` when the mark is too old to record the coverage; the
/// events stay staged.
fn stage(
    turn: &WorkerTurn<'_>,
    key: &UnitKey,
    deliveries: &[TransportDelivery],
    fetched_bytes: u64,
    covered: Option<RecoveryCoverageRange>,
    proof: RecoveryCoverageProof,
    mark: RecoveryCoverageMark,
) -> StorageResult<Option<Staged>> {
    let before = covered
        .map(|range| uncovered_seconds(turn.app, key, range))
        .transpose()?;
    let staged = turn.app.stage_recovery_slice(
        &RecoveryStagedSlice {
            route: &key.route,
            relay: &key.relay,
            events: deliveries,
            fetched_bytes,
            covered: covered.as_slice(),
            proof,
            mark,
        },
        turn.now,
    )?;
    let (Some(range), Some(before)) = (covered, before) else {
        return Ok(Some(Staged {
            newly: 0,
            events: staged.staged as u64,
        }));
    };
    if !staged.covered {
        return Ok(None);
    }
    let after = uncovered_seconds(turn.app, key, range)?;
    Ok(Some(Staged {
        newly: before.saturating_sub(after),
        events: staged.staged as u64,
    }))
}

/// Run the quantum: each planned range in turn, until one does not finish,
/// the deadline comes, or the quantum has fetched what it may.
pub(super) async fn run<H: RunnerHost>(
    host: &H,
    plan: &ComparePlan,
    deadline: Instant,
    cancel: &CancellationToken,
    policy: &RecoveryRunnerPolicy,
) -> (QuantumReport, CompareFacts) {
    let mut report = QuantumReport {
        end: SweepEnd::Finished,
        requests: 0,
        answers: 0,
        rate_limited: false,
        unstaged_bytes: 0,
        newly_covered_seconds: 0,
        proved_seconds: 0,
        proved_events: 0,
        delta: 0,
        observed_cap: None,
        stop: None,
    };
    let mut facts = CompareFacts {
        end: CompareEnd::Finished,
        checked_through: None,
        late: 0,
    };
    let Some(relay) = host.compare_relay(&plan.key.relay, plan.caps, policy.request_timeout) else {
        facts.end = CompareEnd::Unreachable(UnreachableKind::Disconnected);
        report.end = SweepEnd::Unreachable(UnreachableKind::Disconnected);
        return (report, facts);
    };
    let route = SweepRoute::Group {
        nostr_group_id: plan.nostr_group_id,
    };
    let limits = policy.compare();
    let mut events_left = limits.max_events;
    let mut bytes_left = limits.max_bytes;
    let mut sink = CompareStage {
        host,
        plan,
        covered: false,
        newly_covered_seconds: 0,
        late: 0,
        staged_bytes: 0,
        unstaged_bytes: 0,
        stop: None,
    };
    for planned in &plan.ranges {
        if events_left == 0 || bytes_left == 0 {
            facts.end = CompareEnd::BudgetSpent;
            report.end = verdict(facts.end, planned.range.since);
            break;
        }
        sink.covered = planned.covered;
        let bytes_before = sink.staged_bytes.saturating_add(sink.unstaged_bytes);
        let compared = run_comparison(
            CompareRequest {
                route,
                range: planned.range,
                local: &plan.local,
                deadline: Some(deadline),
                policy: ComparePolicy {
                    max_events: events_left,
                    max_bytes: bytes_left,
                    ..limits
                },
            },
            &*relay,
            &mut sink,
            cancel,
        )
        .await;
        report.requests = report.requests.saturating_add(compared.stats.requests);
        report.answers = report.answers.saturating_add(compared.stats.answers);
        report.rate_limited = compared.rate_limited;
        sink.unstaged_bytes = sink
            .unstaged_bytes
            .saturating_add(compared.unadmitted_bytes);
        events_left = events_left
            .saturating_sub(usize::try_from(compared.stats.events).unwrap_or(usize::MAX));
        let bytes_read = sink
            .staged_bytes
            .saturating_add(sink.unstaged_bytes)
            .saturating_sub(bytes_before);
        bytes_left = bytes_left.saturating_sub(bytes_read);
        for window in &compared.certified {
            report.proved_seconds = report
                .proved_seconds
                .saturating_add(window.until - window.since + 1);
            report.proved_events = report
                .proved_events
                .saturating_add(u64::from(window.events));
            facts.checked_through = window.until.checked_add(1);
        }
        let first_unproven = compared
            .certified
            .last()
            .map_or(planned.range.since, |window| window.until.saturating_add(1));
        facts.end = compared.end;
        report.end = verdict(compared.end, first_unproven);
        if compared.end != CompareEnd::Finished {
            break;
        }
    }
    report.newly_covered_seconds = sink.newly_covered_seconds;
    report.stop = sink.stop;
    facts.late = sink.late;
    if !plan.best_effort {
        report.unstaged_bytes = sink.unstaged_bytes;
    }
    (report, facts)
}

/// Whether the relay would not compare: it does not speak NIP-77, or it
/// refused a comparison or a fetch by id for good. A comparison is only the
/// cheaper way to cover a range, so the runner sweeps that relay instead until
/// it reconnects, and the sweep's own replies settle the unit.
pub(super) fn would_not_compare(end: CompareEnd) -> bool {
    matches!(end, CompareEnd::Unsupported | CompareEnd::Refused(_))
}
