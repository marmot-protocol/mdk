use crate::RuntimePerformanceOperation as RuntimeOp;
use crate::app_telemetry::runtime::Outcome as TelemetryOutcome;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use cgka_traits::GroupId;
use cgka_traits::MARMOT_APP_EVENT_KIND_POLL;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::transport::TransportEnvelope;
use storage_sqlite::{
    TransportReconciliationItem, TransportReconciliationRoute, clamp_to_max_future_skew,
};
use tokio::time::timeout;
use transport_nostr_adapter::NostrReconciliationItem as AdapterReconciliationItem;

use crate::app_telemetry::{AppPerformanceOperation, SyncFailureStage};
use crate::groups::{
    EventGroupProjection, decode_received_event, event_group_id, fail_if_publish_failed,
    observe_event,
};
use crate::media::media_imeta_tags_are_valid;
use crate::notifications;
use crate::{
    AccountState, AppError, AppMessageProjection, AppPerformanceTelemetry, ClassifiedSyncFailure,
    SDK_DRAIN_WAIT, SDK_FIRST_SYNC_WAIT, SelfMembership, SyncFailure, SyncSummary,
    TRANSPORT_CURSOR_MAX_FUTURE_SKEW, unix_now_seconds,
};
use marmot_forensics::{
    AuditEventContext, EpochBackfillActivationOutcome, EpochBackfillExecutionSeam,
    EpochStallBackfillTrigger,
};

#[cfg(test)]
use marmot_forensics::EpochBackfillCompletionKind;

use super::AppClient;
use super::audit::EpochBackfillTerminalAudit;
use super::epoch_stall::BackfillDecision;
use super::recovery::{AttemptGrant, ExplicitRecoveryPermit};
use crate::config::CursorPersistence;

mod comparison_job;
#[cfg(test)]
pub(crate) use comparison_job::TestComparisonActivityWitness;
pub(crate) use comparison_job::{ComparisonAdmission, ComparisonExecution, ComparisonNetworkJob};

pub(crate) enum PendingRecoverySelection {
    NotPending,
    Deferred,
    Grant(Box<AttemptGrant>),
}

/// Account-wide startup budget for the timestamp-independent correctness pass.
/// Partial progress is durable, so a slow or non-NIP-77 relay cannot hold the
/// account worker indefinitely and the next sync can resume from a smaller
/// difference.
const TRANSPORT_RECONCILIATION_QUANTUM: Duration = Duration::from_secs(10);
/// Four two-second route passes leave margin inside the account-wide quantum.
/// The durable cursor starts the next pass after the rotation prefix the last
/// pass covered, so it must hold at least two routes: see
/// [`order_reconciliation_pass`].
const TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS: usize = 4;

// ponytail: EOSE crosses a separate router task; retain a short quiet window
// until delivery and EOSE can share an ordered receive lane.
const EOSE_QUIET_WAIT: Duration = Duration::from_millis(100);

type OwnedComparisonResult = Result<
    Option<(
        transport_nostr_adapter::NostrReconciliationSummary,
        Vec<transport_nostr_adapter::NostrRelayEvent>,
    )>,
    cgka_traits::TransportAdapterError,
>;

#[cfg(test)]
pub(crate) type TestComparisonResult = OwnedComparisonResult;

/// Scripted comparison results. The network task takes one where it would
/// have called the adapter: the next queued result, so a route the pass never
/// reaches leaves its result queued, or an answer computed for the route.
#[cfg(test)]
#[derive(Clone)]
pub(crate) enum ScriptedComparisons {
    Queue(std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<TestComparisonResult>>>),
    ByRoute(
        std::sync::Arc<dyn Fn(&TransportReconciliationRoute) -> TestComparisonResult + Send + Sync>,
    ),
    /// An answer that arrives only after its own delay.
    Timed(std::sync::Arc<TimedComparison>),
}

#[cfg(test)]
type TimedComparison =
    dyn Fn(&TransportReconciliationRoute) -> (Option<Duration>, TestComparisonResult) + Send + Sync;

#[cfg(test)]
impl ScriptedComparisons {
    /// Answer every compared route, whenever the job compares it.
    pub(crate) fn by_route(
        answer: impl Fn(&TransportReconciliationRoute) -> TestComparisonResult + Send + Sync + 'static,
    ) -> Self {
        Self::ByRoute(std::sync::Arc::new(answer))
    }

    /// Answer each compared route after the delay the script chose for it.
    pub(crate) fn timed(
        answer: impl Fn(&TransportReconciliationRoute) -> (Option<Duration>, TestComparisonResult)
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self::Timed(std::sync::Arc::new(answer))
    }

    /// A timed script's answer and its own delay, decided when the route
    /// starts. Other scripts answer only once the delay has passed.
    pub(crate) fn timed_answer(
        &self,
        route: &TransportReconciliationRoute,
    ) -> Option<(Option<Duration>, TestComparisonResult)> {
        match self {
            Self::Timed(answer) => Some(answer(route)),
            Self::Queue(_) | Self::ByRoute(_) => None,
        }
    }

    pub(crate) fn answer(&self, route: &TransportReconciliationRoute) -> TestComparisonResult {
        match self {
            Self::Queue(queue) => queue
                .lock()
                .unwrap()
                .pop_front()
                .expect("one scripted result per selected comparison route"),
            Self::ByRoute(answer) => answer(route),
            Self::Timed(answer) => answer(route).1,
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Queue(queue) => queue.lock().unwrap().len(),
            Self::ByRoute(_) | Self::Timed(_) => 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
impl FromIterator<TestComparisonResult> for ScriptedComparisons {
    fn from_iter<T: IntoIterator<Item = TestComparisonResult>>(iter: T) -> Self {
        Self::Queue(std::sync::Arc::new(std::sync::Mutex::new(
            iter.into_iter().collect(),
        )))
    }
}

#[cfg(test)]
impl<const N: usize> From<[TestComparisonResult; N]> for ScriptedComparisons {
    fn from(results: [TestComparisonResult; N]) -> Self {
        results.into_iter().collect()
    }
}

/// Overall explicit repair budget. The comparison pass gets the first five
/// sixths of it (50 s of 60 s): a route still comparing then times out and
/// the routes that finished come back. The last sixth is reserved for
/// admitting and checkpointing what they fetched; admission stops at a turn
/// boundary once the whole budget is spent. Leave headroom inside the public
/// worker RPC deadline for setup and cleanup.
const FULL_HISTORY_REPAIR_TIMEOUT: Duration = Duration::from_secs(60);

/// The share of the repair budget reserved for admission, as a divisor.
const FULL_HISTORY_ADMISSION_RESERVE_DIVISOR: u32 = 6;

/// How often an explicit caller's in-place job checks for cancellation while
/// its network task runs.
const RECOVERY_JOB_CANCEL_POLL: Duration = Duration::from_millis(50);

pub(crate) struct FullHistoryRepairControl<'a> {
    started: Instant,
    timeout: Duration,
    cancelled: &'a (dyn Fn() -> bool + Sync),
}

impl FullHistoryRepairControl<'_> {
    pub(crate) fn stopped(&self) -> Option<crate::FullHistoryRepairIncompleteReason> {
        if (self.cancelled)() {
            Some(crate::FullHistoryRepairIncompleteReason::Cancelled)
        } else if self.started.elapsed() >= self.timeout {
            Some(crate::FullHistoryRepairIncompleteReason::Deadline)
        } else {
            None
        }
    }

    /// Only the caller's cancellation discards a pass in flight.
    pub(crate) fn cancelled(&self) -> bool {
        (self.cancelled)()
    }

    /// When the comparison pass must end, leaving the admission reserve.
    pub(crate) fn network_deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.started) + self.network_budget()
    }

    fn network_budget(&self) -> Duration {
        self.timeout - self.timeout / FULL_HISTORY_ADMISSION_RESERVE_DIVISOR
    }

    /// Why a finished repair stopped short: cancellation, or a deadline that
    /// actually cut its comparison pass or admission. A pass that completed
    /// before the cutoff and was admitted after it did not stop short.
    pub(crate) fn verdict(
        &self,
        hit_deadline: bool,
    ) -> Option<crate::FullHistoryRepairIncompleteReason> {
        if (self.cancelled)() {
            Some(crate::FullHistoryRepairIncompleteReason::Cancelled)
        } else if hit_deadline {
            Some(crate::FullHistoryRepairIncompleteReason::Deadline)
        } else {
            None
        }
    }
}

// One ingest or convergence pass can release several previously retained events.
// Their durable identities belong to the events, not to the triggering envelope.
fn event_source_message_id_hex(event: &cgka_traits::engine::GroupEvent, fallback: &str) -> String {
    match event {
        cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. } => {
            hex::encode(message_id.as_slice())
        }
        cgka_traits::engine::GroupEvent::GroupJoined { via_welcome, .. } => {
            hex::encode(via_welcome.as_slice())
        }
        _ => fallback.to_owned(),
    }
}

#[derive(Clone)]
pub(super) enum TransportReconciliationWork {
    Inbox(Vec<cgka_traits::TransportEndpoint>),
    Group(cgka_traits::TransportGroupSubscription),
}

impl TransportReconciliationWork {
    pub(super) fn route(&self) -> Option<TransportReconciliationRoute> {
        match self {
            Self::Inbox(_) => Some(TransportReconciliationRoute::Inbox),
            Self::Group(group) => <[u8; 32]>::try_from(group.transport_group_id.as_slice())
                .ok()
                .map(TransportReconciliationRoute::Group),
        }
    }

    /// The relays this work compares.
    pub(super) fn endpoints(&self) -> &[cgka_traits::TransportEndpoint] {
        match self {
            Self::Inbox(endpoints) => endpoints,
            Self::Group(group) => &group.endpoints,
        }
    }

    /// Whether this route carries history for one of `groups`. The local inbox
    /// carries welcomes, never a group's own epoch history.
    fn repairs_group_in(&self, groups: &HashSet<cgka_traits::GroupId>) -> bool {
        match self {
            Self::Inbox(_) => false,
            Self::Group(group) => groups.contains(&group.group_id),
        }
    }
}

fn nostr_reconciliation_item(item: TransportReconciliationItem) -> AdapterReconciliationItem {
    AdapterReconciliationItem {
        event_id: item.event_id,
        created_at: item.created_at,
    }
}

fn reconciliation_start_after_cursor(
    routes: &[TransportReconciliationRoute],
    cursor: Option<&TransportReconciliationRoute>,
) -> usize {
    cursor
        .and_then(|cursor| routes.iter().position(|route| route > cursor))
        .unwrap_or(0)
}

/// Pick the routes one reconciliation pass reconciles, in the order it
/// reconciles them, and report how far the account-wide rotation may advance.
///
/// The account-wide rotation resumes after the durable cursor so no route is
/// starved. The groups `repairing` names are what an armed epoch-gap intent is
/// missing history for, so they take the front of the pass but never all of it;
/// the rotation fills the remaining budget.
///
/// Priority is a view on one pass; the cursor is durable fairness state over
/// the whole route set, so it advances along the rotated sequence and not along
/// the priority order. The returned route is the end of the longest prefix of
/// that rotated sequence this pass covers: every route up to it is scheduled,
/// so claiming it never claims a route the pass skipped, and because the first
/// rotated route is always scheduled the claim always moves forward. That is
/// what keeps an armed set wider than the pass from pinning the rotation on its
/// own leading routes for as long as it stays armed.
///
/// The first rotated route is scheduled for every `max_routes` of 2 or more:
/// the armed half never fills the pass, so the rotation always keeps the slot
/// its own leading route needs. A one-route pass has no armed slot at all, and
/// then an armed leading route is simply not covered and not claimed.
fn order_reconciliation_pass(
    work: &mut Vec<TransportReconciliationWork>,
    cursor: Option<&TransportReconciliationRoute>,
    repairing: &HashSet<cgka_traits::GroupId>,
    max_routes: usize,
) -> Option<TransportReconciliationRoute> {
    work.sort_unstable_by_key(TransportReconciliationWork::route);
    let route_keys = work
        .iter()
        .filter_map(TransportReconciliationWork::route)
        .collect::<Vec<_>>();
    let start = reconciliation_start_after_cursor(&route_keys, cursor);
    if start > 0 {
        work.rotate_left(start);
    }
    // Re-read the keys after the rotation: this is the order the pass's
    // fairness is measured in, before priority reorders anything.
    let rotation = work
        .iter()
        .filter_map(TransportReconciliationWork::route)
        .collect::<Vec<_>>();
    let (mut armed, rest): (Vec<_>, Vec<_>) = work
        .drain(..)
        .partition(|item| item.repairs_group_in(repairing));
    // Leave the rotation one slot. A device wedged in more groups than the pass
    // holds stays armed for as long as it is wedged, and would otherwise strip
    // every other route — the local inbox included — of its by-id backstop.
    armed.truncate(max_routes.saturating_sub(1));
    work.extend(armed);
    work.extend(rest);
    work.truncate(max_routes);

    // At most `max_routes` long, so a slice lookup beats hashing.
    let scheduled = work
        .iter()
        .filter_map(TransportReconciliationWork::route)
        .collect::<Vec<_>>();
    rotation
        .into_iter()
        .take_while(|route| scheduled.contains(route))
        .last()
}

fn transport_reconciliation_record(
    account_id: &cgka_traits::MemberId,
    delivery: &cgka_traits::TransportDelivery,
) -> Option<(TransportReconciliationRoute, TransportReconciliationItem)> {
    let route = match &delivery.message.envelope {
        TransportEnvelope::Welcome { recipient } if recipient == account_id => {
            TransportReconciliationRoute::Inbox
        }
        TransportEnvelope::GroupMessage { transport_group_id }
            if delivery.group_id_hint.is_some() =>
        {
            TransportReconciliationRoute::Group(
                <[u8; 32]>::try_from(transport_group_id.as_slice()).ok()?,
            )
        }
        _ => return None,
    };
    let event_id = <[u8; 32]>::try_from(delivery.message.id.as_slice()).ok()?;
    Some((
        route,
        TransportReconciliationItem {
            event_id,
            created_at: delivery.message.timestamp.0,
        },
    ))
}

#[cfg(test)]
struct EpochBackfillReplayOutcome {
    duration_ms: u64,
    activation_outcome: EpochBackfillActivationOutcome,
    error_kind: Option<String>,
    completion_kind: Option<EpochBackfillCompletionKind>,
    counts: DrainCounts,
}

/// Result of asking the account owner to service pending recovery demand.
///
/// `Deferred` is intentionally distinct from `NotPending`: existing demand
/// may be waiting for cooldown, local capacity, a process credit, or
/// acquisition capability, so the worker may still return success while
/// retaining the deferred recovery intent and its audit trail.
#[derive(Debug)]
pub(crate) enum EpochBackfillRunOutcome {
    NotPending,
    Deferred,
    /// Every obligation the job selected is satisfied.
    Completed(SyncSummary),
    /// The job ran and admitted whatever it fetched, but some selected debt
    /// stays pending. The summary is real and must still be published.
    Incomplete(SyncSummary),
}

/// The audit and loss guard of one already-reserved recovery job, opened when
/// the job begins and closed through one terminal path.
pub(crate) struct RecoveryExecutionState {
    overflow: Option<crate::relay_plane::AccountDeliveryOverflow>,
    overflow_guard: Option<super::recovery::RecoveryLossAttemptGuard>,
    audit_groups: Vec<([u8; 16], GroupId, u64)>,
    context: AuditEventContext,
    started: Instant,
    counts: DrainCounts,
    activation: EpochBackfillActivationOutcome,
}

/// The public outcome of an explicit full-history repair that did not
/// qualify. Everything the repair admitted stays in the partial summary.
fn incomplete_full_history_repair(
    summary: SyncSummary,
    reason: crate::FullHistoryRepairIncompleteReason,
    delivery_loss_pending: bool,
) -> ClassifiedSyncFailure {
    tracing::debug!(
        target: "marmot_app::history_repair",
        method = "incomplete_full_history_repair",
        error_kind = reason.as_str(),
        "full-history repair remains incomplete"
    );
    ClassifiedSyncFailure::at_stage(
        summary,
        AppError::FullHistoryRepairIncomplete {
            reason,
            delivery_loss_pending,
        },
        SyncFailureStage::RelayReceive,
    )
}

/// Build the per-group terminal audit rows for one backfill execution.
///
/// `epochs_after` is a *reading*, not a fact about the group: a group whose
/// record could not be read is simply absent from the map, exactly like a group
/// that was never armed. Carrying the after-epoch as an `Option` all the way to
/// the row is what keeps the two apart — the alternative, defaulting it to the
/// before-epoch, makes a failed read indistinguishable from a replay that
/// recovered nothing and lets the row assert an observation nobody took.
///
/// Free-standing so the row content is testable without a live client; the
/// caller owns the recorder.
#[cfg(test)]
fn epoch_backfill_terminal_rows(
    pending: &[storage_sqlite::StoredEpochBackfillIntent],
    retry_ordinal: u64,
    epochs_before: &HashMap<cgka_traits::GroupId, u64>,
    epochs_after: &HashMap<cgka_traits::GroupId, u64>,
    outcome: &EpochBackfillReplayOutcome,
) -> Vec<(cgka_traits::GroupId, EpochBackfillTerminalAudit)> {
    pending
        .iter()
        .map(|group| {
            let group_id = cgka_traits::GroupId::new(
                hex::decode(&group.group_id_hex).expect("valid fixture group"),
            );
            // The before-read has its own bail-out in
            // `begin_epoch_backfill_execution`, so an absent entry here can only
            // be the armed stalled epoch this intent was created from.
            let local_epoch_before = epochs_before
                .get(&group_id)
                .copied()
                .unwrap_or(group.stalled_epoch);
            (
                group_id.clone(),
                EpochBackfillTerminalAudit {
                    retry_ordinal,
                    duration_ms: outcome.duration_ms,
                    activation_outcome: outcome.activation_outcome,
                    error_kind: outcome.error_kind.clone(),
                    completion_kind: outcome.completion_kind,
                    deliveries: outcome.counts.deliveries,
                    skipped: outcome.counts.skipped,
                    refused: outcome.counts.refused,
                    local_epoch_before,
                    local_epoch_after: epochs_after.get(&group_id).copied(),
                },
            )
        })
        .collect()
}

/// The cursor a commit chose, from [`AppClient::seal_transport_cursor`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct SealedTransportCursor {
    /// The cursor the commit replaced, restored if its save fails.
    previous: Option<u64>,
    /// What the commit reached on its own; `None` when a fence held it.
    reached: Option<u64>,
}

/// What one delivery's ingest settled, for the two seams that decide whether the
/// delivery may be dropped from the fetch path.
struct DeliveryIngest {
    /// Membership-changing effects landed, so the app projection and the route
    /// table owe a save before anything else can fail.
    routes_dirty: bool,
    /// The engine kept no durable trace of this object, so relay redelivery is
    /// the only path back to it and this delivery must not enter `seen_events`.
    ///
    /// Reported by the engine rather than reconstructed from the outcome:
    /// `Ignored { UnknownGroup }` covers both an object the engine dropped
    /// without a trace and one it durably dedup-marked, and only the engine can
    /// tell them apart. See `Engine::last_ingest_left_object_unpersisted`.
    must_stay_fetchable: bool,
    /// The group a resource refusal was counted against, so a drain can report
    /// *which* groups it fetched history for and could not retain, and so the
    /// audit `refused` count keeps meaning exactly "a local resource bound
    /// rejected this". Only `IngestOutcome::ResourceRefused` names a group, and
    /// it is deliberately narrower than `must_stay_fetchable`: an unknown-group
    /// object was not refused for want of a resource.
    refused_group: Option<cgka_traits::GroupId>,
}

/// How one comparison-fetched delivery settled on admission.
pub(crate) enum RecoveredDelivery {
    AlreadyHeld,
    /// `unpersisted`: the engine kept no durable trace, so the comparison
    /// did not admit it. `refused_group`: a local resource bound refused it.
    Ingested {
        unpersisted: bool,
        refused_group: Option<cgka_traits::GroupId>,
    },
}

/// One compared route: its settlement outcome, and whether the comparison
/// certifies it. A route is certified only when every required endpoint
/// finished the comparison without truncation and every missing event it
/// found was handed to admission. Best-effort endpoints only fetch.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RouteComparison {
    pub(crate) route: TransportReconciliationRoute,
    pub(crate) outcome: storage_sqlite::RecoveryComparisonOutcome,
    pub(crate) certified: bool,
    /// Events the comparison durably admitted. Any is progress, even while
    /// an unsupported required relay withholds the certificate.
    pub(crate) fetched: usize,
    /// Every required relay answered: it finished the comparison, or the
    /// backend cannot compare the route. A pass that answered and neither
    /// certified nor admitted anything is quiet. A failed or timed-out relay,
    /// or a route this pass skipped, did not answer.
    pub(crate) answered: bool,
}

/// What one drain loop saw on the wire.
///
/// `deliveries` counts receives the drain ingested; `skipped` counts those it
/// dropped as a relay echo of this device's own publish or as an event already
/// in the seen index. Keeping the two apart is what lets a field export tell a
/// long drain that was making progress from one a relay held open with traffic
/// carrying no new history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DrainCounts {
    pub(crate) deliveries: u64,
    pub(crate) skipped: u64,
    /// The subset of `deliveries` for which the engine kept no durable trace.
    /// These objects stay fetchable and cannot count as recovery progress.
    /// Includes `refused`, but is deliberately not an audit field: `refused`
    /// retains its narrower resource-bound meaning on the forensic wire.
    pub(crate) unpersisted: u64,
    /// The subset of `deliveries` the engine refused unpersisted. Nested inside
    /// `deliveries` rather than beside it: the receive really was ingested, and
    /// `deliveries` keeps the audit meaning the field exports already depend
    /// on.
    pub(crate) refused: u64,
    /// The groups those refusals were counted against. Recorded at the same
    /// site that increments `refused`, so the three consequences of a refusal —
    /// stays fetchable, does not count as recovery, and re-arms its group after
    /// a fruitless replay — cannot drift apart. Not an audit field: the row
    /// carries the scalar count, and group ids never enter a forensic row.
    pub(crate) refused_groups: std::collections::HashSet<cgka_traits::GroupId>,
}

/// What the convergence scheduler should do next for a group, derived from
/// the engine's durable pass state. Expected collection time is not an error;
/// storage and projection failures are, and they surface as `Err` from
/// [`AppClient::convergence_schedule_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConvergenceScheduleState {
    /// No active pass and no pending inputs: cancel scheduled wakeups.
    Idle,
    /// A pass is collecting or local deferred-peel residence is pending; wake
    /// when the earliest cutoff elapses.
    Collecting { remaining_ms: u64 },
    /// A pass is frozen/resolving or its cutoff already elapsed: run now.
    Ready,
    /// Pending inputs exist but no pass can open yet (epoch not `Stable`, an
    /// admin reservation holds the boundary, or the retained input has no
    /// trigger). Re-check on the fallback delay; only this state counts
    /// toward the unsettled re-arm cap.
    PendingUnopenable,
    /// No convergence work, but durable outbound work remains. A frozen
    /// transport event carries its earliest retry cutoff; queued intents and
    /// local-only acknowledgement cleanup use the scheduler's ordinary delay.
    /// This state is not unsettled convergence and never counts toward the
    /// re-arm cap.
    PendingOutbound { retry_after_ms: Option<u64> },
}

enum SyncCheckpointError {
    BeforePersistence(AppError),
    AfterPersistence(AppError),
}

struct StagedSyncError {
    source: AppError,
    stage: SyncFailureStage,
}

impl StagedSyncError {
    fn new(source: AppError, stage: SyncFailureStage) -> Self {
        Self { source, stage }
    }
}

impl AppClient {
    /// Persist a host connectivity-restored edge into every exact fanout whose
    /// prior attempt was proven unavailable, then schedule its group for an
    /// immediate worker pass. Ambiguous fanouts keep their original clocks.
    pub(crate) fn note_connectivity_restored(&mut self) -> Result<usize, AppError> {
        let mut woken_targets = 0;
        for mut fanout in self.runtime.session().outbound_fanouts()? {
            let woken = fanout.wake_retryable_unavailable_targets();
            if woken == 0 {
                continue;
            }
            let group_id = fanout.group_id().cloned();
            self.runtime.session().put_outbound_fanout(&fanout)?;
            if let Some(group_id) = group_id {
                self.pending_convergence_groups.insert(group_id);
            }
            woken_targets += woken;
        }
        self.app.product_analytics.observe(
            crate::ProductFamily::Connectivity,
            "reconnect",
            if woken_targets > 0 {
                "performed"
            } else {
                "no_work_due"
            },
            crate::ProductUnit::Attempt,
            None,
        );
        Ok(woken_targets)
    }

    pub(crate) fn take_pending_convergence_groups(&mut self) -> Vec<cgka_traits::GroupId> {
        self.pending_convergence_groups.drain().collect()
    }

    /// Engine-derived convergence scheduling state for one group.
    ///
    /// Errors propagate: a storage or engine failure must schedule a retry at
    /// the caller, never read as "no pending work" (the previous
    /// `unwrap_or(false)` wrapper let an error cancel future wakeups).
    /// `prepare_convergence_cutoff_delay_ms` is a command, not a query — it
    /// may open a pass or persist deadline rebasing before reporting.
    pub(crate) fn convergence_schedule_state(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<ConvergenceScheduleState, AppError> {
        if self.is_group_forgotten(group_id)? {
            return Ok(ConvergenceScheduleState::Idle);
        }
        let convergence_delay = self.runtime.prepare_convergence_cutoff_delay_ms(group_id)?;
        match convergence_delay {
            Some(0) => Ok(ConvergenceScheduleState::Ready),
            Some(remaining_ms) => {
                let remaining_ms = self
                    .runtime
                    .deferred_peel_cutoff_delay_ms(group_id)?
                    .map_or(remaining_ms, |deferred| remaining_ms.min(deferred));
                if remaining_ms == 0 {
                    Ok(ConvergenceScheduleState::Ready)
                } else {
                    Ok(ConvergenceScheduleState::Collecting { remaining_ms })
                }
            }
            None => {
                if self.runtime.has_pending_convergence_inputs(group_id)? {
                    Ok(ConvergenceScheduleState::PendingUnopenable)
                } else if self.runtime.has_pending_outbound_fanouts(group_id)? {
                    // Fanout retry is a barrier to staging more outbound work,
                    // including a due SelfRemove and queued local mutations.
                    Ok(ConvergenceScheduleState::PendingOutbound {
                        retry_after_ms: self.runtime.outbound_fanout_retry_delay_ms(group_id)?,
                    })
                } else if self.runtime.has_queued_outbound_intents(group_id)?
                    || (matches!(
                        self.runtime.epoch_state(group_id),
                        Some(cgka_traits::EpochState::Stable { .. })
                    ) && self
                        .runtime
                        .disband_request(group_id)?
                        .is_some_and(|request| {
                            request.status == cgka_traits::DisbandRequestStatus::Pending
                        }))
                {
                    // Acceptance stores a separate durable request, not a queued
                    // outbound intent or convergence input. Keep its wakeup so
                    // the next advance can prepare the closing commit. Existing
                    // convergence and frozen publications retain their precedence;
                    // an unrecoverable group stays paused.
                    Ok(ConvergenceScheduleState::PendingOutbound {
                        retry_after_ms: None,
                    })
                } else {
                    // Only an otherwise idle group may use the lifecycle timer.
                    // It cannot shorten a collecting pass or a fanout retry:
                    // advance_convergence cannot stage the removal behind either.
                    let lifecycle_delay = self
                        .runtime
                        .scheduled_self_remove_auto_commit_delay_ms(group_id)?;
                    let deferred_delay = self.runtime.deferred_peel_cutoff_delay_ms(group_id)?;
                    match lifecycle_delay.into_iter().chain(deferred_delay).min() {
                        Some(0) => Ok(ConvergenceScheduleState::Ready),
                        Some(remaining_ms) => {
                            Ok(ConvergenceScheduleState::Collecting { remaining_ms })
                        }
                        None => Ok(ConvergenceScheduleState::Idle),
                    }
                }
            }
        }
    }

    fn remember_buffered_convergence_outcome(&mut self, outcome: &IngestOutcome) {
        if let IngestOutcome::Buffered { group_id, .. } = outcome {
            self.pending_convergence_groups.insert(group_id.clone());
        }
    }

    /// Retain engine-provided scheduling edges from an effects batch until the
    /// account worker can arm their group timers.
    pub(crate) fn remember_pending_convergence_groups(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        self.pending_convergence_groups
            .extend(effects.pending_convergence.iter().cloned());
    }

    /// Feed one effects batch's epoch-gap recovery evidence to the stall
    /// detector: a resource refusal arms a replay, and an epoch passage or a
    /// convergence reorg reports the activity that can end an unrecovered run.
    ///
    /// Both directions matter, and only this seam carries the second one. A
    /// delivery reports the epoch it was *read* at, which is where the device
    /// already sits; the epochs a fold, a confirmed publish, or a maintenance
    /// tick's own evolution carried it *through* are read at by nothing, so
    /// without the engine's own `EpochChanged` the detector cannot tell a device
    /// that recovered from one that is still stuck (see
    /// [`EpochStallDetector::observe_epoch_passage`](super::epoch_stall::EpochStallDetector::observe_epoch_passage)).
    /// Of the three emitting sites only a convergence reorg spans more than one
    /// epoch; publish-confirm and peer-commit ingest are always adjacent, which
    /// is the case the passage rule is tuned for.
    ///
    /// Events are consumed in engine order, so a passage later in the same batch
    /// supersedes an arm an earlier refusal just made: the durable
    /// `epoch_stall_backfill_armed` row still records that the replay was armed,
    /// while the detector's run counter starts over. That split is intended — the
    /// arm happened and stays on the forensic record, and the run is what the
    /// later evidence contradicts.
    pub(crate) fn observe_recovery_evidence(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        for event in &effects.events {
            use cgka_traits::engine::GroupEvent;
            let transition = match event {
                GroupEvent::GroupStateInvalidated { .. } => Some(("invalidation", "performed")),
                GroupEvent::GroupStateRevalidated { .. } => Some(("revalidation", "success")),
                GroupEvent::GroupUnrecoverable { .. } => Some(("unrecoverable", "failure")),
                GroupEvent::PendingCommitRecovered { .. } => Some(("pending_commit", "success")),
                GroupEvent::GroupHydrationRecovered { .. } => Some(("hydration", "success")),
                _ => None,
            };
            if let Some((operation, outcome)) = transition {
                self.app.product_analytics.observe(
                    crate::ProductFamily::Recovery,
                    operation,
                    outcome,
                    crate::ProductUnit::Transition,
                    None,
                );
            }
            match event {
                cgka_traits::engine::GroupEvent::EpochChanged { group_id, from, to } => {
                    self.epoch_stall.observe_epoch_passage(group_id, *from, *to);
                }
                cgka_traits::engine::GroupEvent::TransportObjectResourceRefused {
                    group_id,
                    ..
                } => {
                    let Ok(record) = self.runtime.group_record(group_id) else {
                        continue;
                    };
                    // A terminal copy has no servable history, so arming here
                    // could only mint a durable intent and a forensic row for
                    // work that is never coming.
                    if record.is_terminal() {
                        continue;
                    }
                    // Recording the recovery intent before the recovery job
                    // acquires any history, and recording an
                    // escalation this arm raises, are both the shared decision
                    // handler's job: a resource-refusal arm counts toward the
                    // same unrecovered run as a deferred-delivery arm, and the
                    // detector raises the run's escalation only once, at
                    // whichever path happens to arm third.
                    let decision = self.epoch_stall.observe_resource_refusal(
                        group_id.clone(),
                        record.epoch,
                        epoch_stall_now_ms(),
                    );
                    self.apply_backfill_decision(
                        group_id,
                        record.epoch.0,
                        decision,
                        EpochStallBackfillTrigger::ResourceRefusal,
                    );
                }
                // A convergence reorg is the third kind of recovery evidence,
                // and the only one that never moves an epoch. Branch selection
                // superseded an authenticated commit this device had applied;
                // when the two branches carry the same epoch number the engine
                // emits no `EpochChanged` for it at all, so without this arm a
                // device that just crossed a fork resolution is indistinguishable
                // from one that saw nothing.
                //
                // Matching the withdrawal rather than its `CommitRolledBack`
                // twin is not a choice about which is better evidence: the
                // engine pushes the pair back to back, once per rolled-back
                // commit, with nothing fallible between them, so the two arms
                // would decide identically and the second would only re-decide
                // what the first already did.
                cgka_traits::engine::GroupEvent::GroupStateInvalidated {
                    group_id,
                    reason:
                        cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
                    ..
                } => {
                    // Deliberately not fed the carried `epoch`: that is the
                    // source epoch of the fork the superseded commit lost, which
                    // sits *behind* where this device is now. The detector's
                    // observed epoch only ever moves forward, and handing it a
                    // backward position would walk the per-epoch suppression
                    // back with it.
                    self.epoch_stall.observe_convergence_reorg(group_id);
                }
                _ => {}
            }
        }
    }

    /// Apply the publish gate to `effects`, observing the same batch's
    /// epoch-gap recovery evidence first.
    ///
    /// Every publishing seam must reach the gate through this rather than
    /// calling `fail_if_publish_failed` directly. A
    /// `TransportObjectResourceRefused` is buffered only after its durable
    /// retention row is already deleted, and an effects batch carries its
    /// events to the app exactly once — so a refusal a pass does not arm on can
    /// never be re-observed. Gating first returns early and drops it for good;
    /// arming first survives the caller's `?` because it is a field mutation
    /// plus a durable audit row, not summary state. The two conditions are
    /// correlated rather than independent: these seams publish, so the failure
    /// and the refusal ride the same effects. An `EpochChanged` passage is
    /// one-shot in the same batch, and losing it costs the opposite mistake —
    /// a device that recovered stays counted as stuck — so it is observed on the
    /// same side of the gate.
    ///
    /// Retained exact fanouts are non-failure effects, but they still require a
    /// worker wake. Remember their engine-provided scheduling edge here so all
    /// direct send operations (messages and group-state changes alike) retry
    /// automatically after temporary transport loss.
    pub(crate) fn observe_recovery_evidence_then_fail_if_publish_failed(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        // Retire released receipts even when this effects batch makes no receipt read.
        self.transport_receipts()?;
        self.observe_recovery_evidence(effects);
        self.remember_pending_convergence_groups(effects);
        let failed_updates = self.invalidate_failed_app_message_projections(effects, None)?;
        self.pending_projection_updates.extend(failed_updates);
        fail_if_publish_failed(effects)
    }

    pub(crate) async fn sync_runtime_groups(&mut self) -> Result<(), AppError> {
        let rebuild_since = self.subscription_rebuild_since()?;
        self.pending_runtime_group_subscription_refresh = true;
        let result = self.sync_runtime_groups_since(rebuild_since).await;
        if result.is_ok() {
            self.pending_runtime_group_subscription_refresh = false;
        }
        result
    }

    async fn sync_runtime_groups_since(
        &mut self,
        rebuild_since: Option<cgka_traits::transport::Timestamp>,
    ) -> Result<(), AppError> {
        self.runtime.sync_transport_groups(rebuild_since).await?;
        self.warm_encrypted_media_epoch_secrets("post_subscription_sync");
        Ok(())
    }

    pub(crate) fn subscription_rebuild_since(
        &self,
    ) -> Result<Option<cgka_traits::transport::Timestamp>, AppError> {
        let since = self
            .relay_plane
            .subscription_rebuild_since(self.checkpointed_transport_timestamp);
        if since.is_some() {
            return Ok(since);
        }
        // Owner construction joins missing-cursor history before exposing the
        // client. Restoring a live tail must remain possible during storage
        // compensation and never perform another demand write or acquisition.
        let lookback = self
            .relay_plane
            .subscription_rebuild_lookback_secs()
            .unwrap_or(120);
        Ok(Some(cgka_traits::transport::Timestamp(
            unix_now_seconds().saturating_sub(lookback),
        )))
    }

    pub(crate) fn delivery_loss_blocks_cursor(&self) -> bool {
        self.delivery_overflow_recovery_pending || self.adapter.delivery_loss_blocks_cursor()
    }

    /// Whether a live ingest may promote the transport cursor with its own
    /// save: the cursor advances, restarts rebuild from it, no loss is
    /// pending, the account has a settled cursor floor, and every account
    /// subscription finished replaying stored history. Relays replay
    /// newest-first, so a promotion mid-replay would leave the rest of the
    /// replay below the restart floor, and all of it would go to the spill.
    ///
    /// An account that has never persisted a cursor has no settled floor, so
    /// a live promotion would spill every older arrival until its first drain
    /// checkpoint, such as the whole history of each group it joins. It holds
    /// no history a restart would re-download, so it waits for that
    /// checkpoint instead, as it did before live promotion existed.
    async fn live_cursor_promotion_ready(&self) -> bool {
        self.app.cursor_persistence() == CursorPersistence::Advance
            && self
                .relay_plane
                .subscription_rebuild_lookback_secs()
                .is_some()
            && !self.delivery_loss_blocks_cursor()
            && self.adapter.transport_cursor_settled()
            && self.adapter.account_subscription_eose().await.complete()
    }

    /// Choose the cursor the next save persists: what this client ingested,
    /// as far as the seal under the router's placement lock allows. That seal
    /// is the commit's only decision point, so nothing observed earlier (the
    /// EOSE read, the queue) can go stale before it. A delivery queued before
    /// the seal caps the commit where a restart still fetches it. One placed
    /// after it, while the save runs, sees the raised floor, and if it falls
    /// below the router spills it instead of queueing it.
    ///
    /// A live ingest seals for its own save and leaves the floor raised. A
    /// drain checkpoint, settled loss or retired notice follows a successful
    /// save with [`Self::settle_transport_cursor`]. Every caller undoes a
    /// failed save with [`Self::abandon_transport_cursor`].
    pub(crate) fn seal_transport_cursor(&mut self) -> SealedTransportCursor {
        #[cfg(test)]
        self.probe_cursor_seal(super::CursorSeal::Before);
        let previous = self.checkpointed_transport_timestamp;
        let reached = self
            .adapter
            .seal_transport_cursor(self.state.last_transport_timestamp);
        self.checkpointed_transport_timestamp = previous.max(reached);
        #[cfg(test)]
        self.probe_cursor_seal(super::CursorSeal::After);
        SealedTransportCursor { previous, reached }
    }

    /// The save that would have persisted a sealed cursor failed, so the
    /// cursor it replaced is still the persisted one. Keep it, and lower the
    /// restart floor the seal raised back to it.
    pub(crate) fn abandon_transport_cursor(&mut self, sealed: SealedTransportCursor) {
        self.checkpointed_transport_timestamp = sealed.previous;
        self.adapter.unseal_transport_cursor(sealed.previous);
    }

    /// A drain checkpoint, settled loss or retired notice saved its sealed
    /// cursor. Only what it reached on its own becomes the settled floor: a
    /// cursor an earlier live promotion left persisted must not, or the router
    /// would stop spilling what only that promotion exposed. A live ingest's
    /// save never settles.
    pub(crate) fn settle_transport_cursor(&self, sealed: SealedTransportCursor) {
        self.adapter.settle_transport_cursor(sealed.reached);
    }

    #[cfg(test)]
    fn probe_cursor_seal(&mut self, point: super::CursorSeal) {
        if let Some(probe) = self
            .cursor_seal_probe
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            probe(point);
        }
    }

    fn observe_delivery_overflow(
        &mut self,
        overflow: crate::relay_plane::AccountDeliveryOverflow,
    ) -> Result<(), AppError> {
        // The router's process-local fence already froze cursor advancement at
        // the omission. Re-observe the same token here so the queued signal is
        // also an idempotent storage boundary before recovery starts.
        let storage = self.app.account_storage(&self.state.label)?;
        storage.synchronize_account_delivery_loss(&self.state.label)?;
        if overflow.dropped > 0 {
            storage.mark_account_delivery_recovery_bounded(
                &self.state.label,
                overflow.marker_token,
                overflow.dropped,
                overflow.earliest_dropped,
            )?;
        }
        if overflow.notification_losses > 0 {
            // The lag's REQ floors bound the loss from below. Each lag mints a
            // fresh token, so a lower floor always imports as new loss with a
            // new obligation revision rather than rewriting a frozen goal.
            storage.record_account_recovery_loss_bounded(
                &self.state.label,
                storage_sqlite::RecoveryLossCause::NotificationConsumer,
                overflow.notification_token,
                0,
                unix_now_seconds(),
                overflow.notification_floor,
            )?;
            storage.synchronize_account_delivery_loss(&self.state.label)?;
            self.adapter.notification_loss_persisted(overflow);
        }
        // A late observation of loss the user already retired rearms nothing.
        // Release its fence as the dismissal would have, never as coverage.
        if self.release_retired_delivery_loss(Some(overflow))? {
            tracing::debug!(
                target: "marmot_app::relay_plane",
                method = "observe_delivery_overflow",
                "observed delivery loss was already retired; cursor fence released",
            );
            return Ok(());
        }
        self.delivery_overflow_recovery_pending = true;
        self.delivery_overflow_recovery_marker_token = Some(overflow.marker_token);
        tracing::warn!(
            target: "marmot_app::relay_plane",
            method = "observe_delivery_overflow",
            queue_depth = overflow.queue_depth,
            dropped = overflow.dropped,
            dropped_bounded = overflow.earliest_dropped.is_some(),
            notification_losses = overflow.notification_losses,
            notification_bounded = overflow.notification_floor.is_some(),
            elapsed_ms = overflow.elapsed_ms,
            "account delivery loss requires comparison recovery",
        );
        Ok(())
    }

    /// Freeze the bounded comparison pass before the grant reaches network I/O.
    /// Receipt synchronization and any inventory compaction happen here; a
    /// compaction that invalidates the reservation makes plan installation fail
    /// conservatively, without executing a stale snapshot.
    /// `every_route` lifts the per-pass route cap for an explicit repair,
    /// whose single pass must reach every route inside its own budget.
    pub(super) fn freeze_recovery_inventory(
        &mut self,
        goals: &mut [([u8; 16], Vec<storage_sqlite::RecoveryScopePlan>)],
        uncompared: &HashSet<([u8; 16], u64)>,
        every_route: bool,
    ) -> Result<
        (
            Vec<super::recovery::FrozenRecoveryInventory>,
            Option<TransportReconciliationRoute>,
        ),
        AppError,
    > {
        let storage = self.app.account_storage(&self.state.label)?;
        let mut work = Vec::new();
        // Certified scopes keep their coverage; passes rotate to the rest.
        for scope in goals.iter().flat_map(|(id, scopes)| {
            scopes
                .iter()
                .filter(move |scope| !uncompared.contains(&(*id, scope.scope_id)))
        }) {
            if scope.admitted_endpoints.is_empty() {
                continue;
            }
            let endpoints = scope
                .admitted_endpoints
                .iter()
                .cloned()
                .map(cgka_traits::TransportEndpoint)
                .collect();
            let candidate = match (scope.route_kind, &scope.group_id, scope.transport_group_id) {
                (0, _, _) => TransportReconciliationWork::Inbox(endpoints),
                (1, Some(group), Some(route)) => {
                    TransportReconciliationWork::Group(cgka_traits::TransportGroupSubscription {
                        group_id: cgka_traits::GroupId::new(group.clone()),
                        transport_group_id: route.to_vec(),
                        endpoints,
                        retained_since: None,
                    })
                }
                _ => continue,
            };
            if !work
                .iter()
                .any(|existing: &TransportReconciliationWork| existing.route() == candidate.route())
            {
                work.push(candidate);
            }
        }
        let cursor = storage.transport_reconciliation_route_cursor()?;
        let rotation_claim = order_reconciliation_pass(
            &mut work,
            cursor.as_ref(),
            &self.armed_epoch_backfill_groups(),
            if every_route {
                usize::MAX
            } else {
                TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
            },
        );
        let receipts = self.transport_receipts()?;
        let mut frozen = Vec::new();
        for work in work {
            let route = work.route().expect("validated recovery route");
            let matches = |scope: &storage_sqlite::RecoveryScopePlan| match route {
                TransportReconciliationRoute::Inbox => scope.route_kind == 0,
                TransportReconciliationRoute::Group(id) => {
                    scope.route_kind == 1 && scope.transport_group_id == Some(id)
                }
            };
            let until = goals
                .iter()
                .flat_map(|(_, scopes)| scopes)
                .filter(|scope| matches(scope))
                .map(|scope| scope.until_seconds)
                .max()
                .unwrap_or_default();
            let mut required = goals
                .iter()
                .flat_map(|(_, scopes)| scopes)
                .filter(|scope| matches(scope))
                .flat_map(|scope| scope.required_endpoints.iter().cloned())
                .collect::<Vec<_>>();
            required.sort();
            required.dedup();
            let inventory = receipts.inventory(&route, until)?;
            for scope in goals
                .iter_mut()
                .flat_map(|(_, scopes)| scopes)
                .filter(|scope| matches(scope))
            {
                // This describes the local comparison floor, never a claim that
                // older debt was served or permission to narrow its goal.
                scope.inventory_floor.get_or_insert(inventory.since);
            }
            if inventory.since <= until {
                frozen.push(super::recovery::FrozenRecoveryInventory {
                    work,
                    route,
                    required,
                    since: inventory.since,
                    until,
                    items: inventory
                        .items
                        .into_iter()
                        .filter(|item| item.created_at <= until)
                        .map(nostr_reconciliation_item)
                        .collect(),
                });
            }
        }
        Ok((frozen, rotation_claim))
    }

    pub(crate) fn has_pending_runtime_group_subscription_refresh(&self) -> bool {
        self.pending_runtime_group_subscription_refresh
    }

    /// Retry an ordinary group-subscription rebuild that was deliberately
    /// moved behind live-ingest visibility. A successful rebuild disarms the
    /// intent; an error leaves it armed so the worker's bounded backoff can
    /// try again without replaying the durable delivery.
    pub(crate) async fn retry_pending_runtime_group_subscription_refresh(
        &mut self,
    ) -> Result<bool, AppError> {
        if !self.pending_runtime_group_subscription_refresh {
            return Ok(false);
        }
        if let Err(error) = self.sync_runtime_groups().await {
            if error.is_account_not_active() {
                // An unexpected notification consumer exit or overlapping
                // account-adapter teardown can retire the activation between
                // durable ingest and this background retry. Re-activation
                // installs both the account inbox and the current complete
                // group set, satisfying the same refresh intent without
                // replaying the delivery.
                self.prepare_transport().await?;
            } else {
                return Err(error);
            }
        }
        self.pending_runtime_group_subscription_refresh = false;
        Ok(false)
    }

    pub(crate) async fn prepare_transport(&mut self) -> Result<(), AppError> {
        self.prepare_transport_with_telemetry(None).await
    }

    pub(crate) async fn prepare_transport_with_telemetry(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), AppError> {
        self.prepare_transport_for_sync(telemetry)
            .await
            .map_err(|(_, error)| error)
    }

    async fn prepare_transport_for_sync(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), (SyncFailureStage, AppError)> {
        // Failed/cancelled activation must retain a retry intent for scheduled work.
        self.pending_runtime_group_subscription_refresh = true;
        // Before any subscription goes out: auth-gated relays (NIP-42)
        // withhold gift-wrapped welcomes from unauthenticated subscribers.
        let activation_started = Instant::now();
        self.relay_plane
            .set_transport_signer(self.adapter.account_id(), self.transport_signer.clone())
            .await
            .map_err(|error| (SyncFailureStage::TransportActivation, error.into()))?;
        let rebuild_since = self
            .subscription_rebuild_since()
            .map_err(|error| (SyncFailureStage::TransportActivation, error))?;
        let activation = self.runtime.activate_transport(rebuild_since).await;
        if let Some(telemetry) = telemetry {
            telemetry.record(
                AppPerformanceOperation::AccountTransportActivation,
                activation_started.elapsed(),
                activation.is_ok(),
            );
        }
        activation
            .map_err(|error| (SyncFailureStage::TransportActivation, AppError::from(error)))?;

        let registration_started = Instant::now();
        let registration = self.sync_runtime_groups().await;
        if let Some(telemetry) = telemetry {
            telemetry.record(
                AppPerformanceOperation::AccountSubscriptionRegistration,
                registration_started.elapsed(),
                registration.is_ok(),
            );
        }
        registration.map_err(|error| (SyncFailureStage::GroupSubscriptionSync, error))
    }

    /// Transport-first startup sync. All authenticated, newly-applied effects
    /// are projected into app state; no historical replay cursor is maintained.
    ///
    /// This compatibility entry point preserves the original [`AppError`]
    /// contract. Call [`Self::sync_with_partial_progress`] when the caller must
    /// report the durably applied prefix of a failed catch-up pass.
    pub async fn sync(&mut self) -> Result<SyncSummary, AppError> {
        match self.sync_inner(None, true).await {
            Ok(summary) => Ok(summary),
            Err(failure) => {
                // Compatibility callers cannot observe a failure summary.
                // Retain any already-checkpointed prefix for their next
                // successful sync instead of consuming it with the error.
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                Err(failure.source)
            }
        }
    }

    /// Synchronize while retaining the durably applied prefix on failure.
    pub async fn sync_with_partial_progress(&mut self) -> Result<SyncSummary, SyncFailure> {
        self.sync_with_classified_partial_progress()
            .await
            .map_err(SyncFailure::from)
    }

    pub(crate) async fn sync_with_classified_partial_progress(
        &mut self,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        match self.sync_inner(None, true).await {
            Ok(summary) => Ok(summary),
            Err(mut failure) => {
                self.drain_epoch_stall_escalations(&mut failure.partial_summary);
                Err(failure)
            }
        }
    }

    pub(crate) async fn sync_with_stage_telemetry(
        &mut self,
        telemetry: &AppPerformanceTelemetry,
        explicit: bool,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        match self.sync_inner(Some(telemetry), explicit).await {
            Ok(summary) => Ok(summary),
            Err(mut failure) => {
                self.drain_epoch_stall_escalations(&mut failure.partial_summary);
                Err(failure)
            }
        }
    }

    pub(crate) async fn sync_automatically_with_partial_progress(
        &mut self,
    ) -> Result<SyncSummary, SyncFailure> {
        self.sync_inner(None, false)
            .await
            .map_err(SyncFailure::from)
    }

    /// One sync: live interest, the live queue, then the recovery job.
    ///
    /// Only startup, a frozen wake or a client with no activation yet installs
    /// live subscriptions, and a route change refreshes them; recovery never
    /// touches them. The live queue drains first, so the job's frozen
    /// inventory already holds what the live subscriptions delivered and
    /// nothing is fetched twice. With recovery debt, an explicit caller then
    /// waits for a process credit, drains once more and runs one job in
    /// place; startup takes a credit only if one is free. Without debt no
    /// credit is taken. Automatic catch-up, such as key-package maintenance,
    /// only drains: the worker's own job serves its debt.
    async fn sync_inner(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
        explicit: bool,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let routing_changed = self.refresh_sync_routes().map_err(|error| {
            ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::StatePersist,
            )
        })?;
        let startup = telemetry.is_some() && !explicit;
        if self.app.cursor_persistence() == CursorPersistence::Frozen
            || startup
            || self.adapter.account_subscription_attempt().await.is_none()
        {
            self.activate_live_transport(telemetry).await?;
        } else if routing_changed || self.pending_runtime_group_subscription_refresh {
            self.refresh_live_group_subscriptions(SyncSummary::default())
                .await?;
        }
        // Network cooldown never withholds already queued input or engine
        // events. Receiving existing subscriptions is not a new acquisition.
        let mut summary = self.sync_sdk_relay().await?;
        use crate::runtime::account_worker::recovery_credits;
        let state_persist = |summary: SyncSummary, error| {
            ClassifiedSyncFailure::at_stage(summary, error, SyncFailureStage::StatePersist)
        };
        // A sync with no recovery debt, or no relay recovery may contact,
        // takes no credit: it would only hold one of the process's two, and
        // the account with it, for a grant it cannot select.
        let wants_job =
            self.app.cursor_persistence() == CursorPersistence::Advance && (explicit || startup);
        if wants_job && let Err(error) = self.request_sync_comparison(telemetry, explicit) {
            return Err(state_persist(summary, error));
        }
        let pending = match self.recovery_pending() {
            Ok(pending) => pending && self.recovery_endpoints_admitted(),
            Err(error) => return Err(state_persist(summary, error)),
        };
        let credit = if !wants_job || !pending {
            None
        } else if explicit {
            Some(recovery_credits::acquire_recovery_credit(&self.recovery_credits).await)
        } else {
            recovery_credits::try_acquire_recovery_credit(&self.recovery_credits)
        };
        let grant = if credit.is_some() {
            // Input that arrived while the credit was pending is ingested
            // before the inventory freezes, so the job does not fetch it again.
            match self.sync_sdk_relay().await {
                Ok(drained) => summary.merge(drained),
                Err(mut failure) => {
                    summary.merge(std::mem::take(&mut failure.partial_summary));
                    failure.partial_summary = summary;
                    return Err(failure);
                }
            }
            match self.select_sync_grant(telemetry, explicit) {
                Ok(grant) => grant,
                Err(error) => return Err(state_persist(summary, error)),
            }
        } else {
            None
        };
        if let (Some(grant), Some(credit)) = (grant, credit) {
            match self.run_recovery_job(grant, credit, None).await {
                Ok(
                    EpochBackfillRunOutcome::Completed(recovered)
                    | EpochBackfillRunOutcome::Incomplete(recovered),
                ) => summary.merge(recovered),
                Ok(EpochBackfillRunOutcome::Deferred | EpochBackfillRunOutcome::NotPending) => {}
                Err(error) => {
                    summary.merge(std::mem::take(&mut self.pending_failed_sync_summary));
                    return Err(ClassifiedSyncFailure::at_stage(
                        summary,
                        error,
                        SyncFailureStage::Unknown,
                    ));
                }
            }
            // A route the job's admission changed is subscribed before this
            // returns: a directly owned client has no worker to refresh it.
            if self.pending_runtime_group_subscription_refresh {
                summary = self.refresh_live_group_subscriptions(summary).await?;
            }
        }
        self.finish_prepared_sync_summary(summary).await
    }

    /// Bring the live group subscriptions up to the current routes. Nothing
    /// else re-subscribes them once the session is active.
    async fn refresh_live_group_subscriptions(
        &mut self,
        summary: SyncSummary,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        self.pending_runtime_group_subscription_refresh = true;
        match self
            .retry_pending_runtime_group_subscription_refresh()
            .await
        {
            Ok(_) => Ok(summary),
            Err(error) => Err(ClassifiedSyncFailure::at_stage(
                summary,
                error,
                SyncFailureStage::GroupSubscriptionSync,
            )),
        }
    }

    /// Reconcile epoch-bounded prior routes before issuing the first relay
    /// subscriptions. This makes retirement deterministic even for a quiet
    /// group that has no new inbound events after restart. Returns whether the
    /// in-memory routing table changed, which obligates a subscription refresh.
    pub(crate) fn refresh_sync_routes(&mut self) -> Result<bool, AppError> {
        let refresh = self.refresh_group_routes()?;
        // A routing-table delta lives in memory and obligates the subscription
        // refresh, not a state write; only route retirement mutates persisted
        // group state.
        if refresh.state_pruned {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        Ok(refresh.routing_changed)
    }

    /// Record a startup or explicit comparison request, then select one grant.
    /// Without a process credit nothing is selected: the durable demand waits
    /// for the worker's next recovery job instead of spending a reservation.
    pub(crate) fn prepare_sync_grant(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
        explicit: bool,
        credit_available: bool,
    ) -> Result<Option<AttemptGrant>, AppError> {
        self.request_sync_comparison(telemetry, explicit)?;
        if !credit_available {
            return Ok(None);
        }
        self.select_sync_grant(telemetry, explicit)
    }

    /// Record a startup or explicit caller's comparison request.
    fn request_sync_comparison(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
        explicit: bool,
    ) -> Result<(), AppError> {
        if self.app.cursor_persistence() == CursorPersistence::Advance
            && (explicit || (telemetry.is_some() && !self.comparison_startup_requested))
        {
            self.request_bounded_comparison()?;
            if !explicit {
                self.comparison_startup_requested = true;
            }
        }
        Ok(())
    }

    /// Select the grant a sync's job runs, under the credit it holds.
    fn select_sync_grant(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
        explicit: bool,
    ) -> Result<Option<AttemptGrant>, AppError> {
        let mut caller = ExplicitRecoveryPermit::default();
        self.authorize_account_recovery(
            explicit.then_some(&mut caller),
            if explicit {
                EpochBackfillExecutionSeam::ExplicitCatchUp
            } else if telemetry.is_some() {
                EpochBackfillExecutionSeam::Startup
            } else {
                EpochBackfillExecutionSeam::Maintenance
            },
        )
    }

    /// Install the session's live subscriptions, floored at the cursor. This
    /// is ordinary live interest, never recovery: recovery compares history
    /// without touching these subscriptions.
    pub(crate) async fn activate_live_transport(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), ClassifiedSyncFailure> {
        if self.app.cursor_persistence() == CursorPersistence::Frozen {
            self.adapter.require_fresh_activation().await;
        }
        self.prepare_transport_for_sync(telemetry)
            .await
            .map_err(|(stage, error)| {
                ClassifiedSyncFailure::at_stage(SyncSummary::default(), error, stage)
            })?;
        let since = self.subscription_rebuild_since().map_err(|error| {
            ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::TransportActivation,
            )
        })?;
        self.record_subscription_rebuild(since.map(|timestamp| timestamp.0))
            .await;
        Ok(())
    }

    /// Startup already activated the live account subscriptions. Drain them
    /// without rebuilding any subscription or replaying the account backlog.
    pub(crate) async fn finish_deferred_comparison_sync(
        &mut self,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let summary = self.sync_sdk_relay().await?;
        self.finish_prepared_sync_summary(summary).await
    }

    pub(crate) async fn finish_prepared_sync_summary(
        &mut self,
        mut summary: SyncSummary,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        // Surface engine events queued without an inbound delivery — most
        // importantly `GroupHydrationQuarantined`, queued during session
        // `open()` hydration (mdk#426). If no relay delivery arrived
        // above, `sync_sdk_relay` never drained the engine, so these would stay
        // buffered and invisible to runtime subscribers until some later
        // unrelated send/ingest. Fold any pending events into this summary.
        let drained = match self.drain_pending_session_events().await {
            Ok(drained) => drained,
            Err(error) => {
                // This composite drain spans engine drain, app-state reads,
                // publish checks, and projection. Its AppError does not retain
                // the inner boundary, so do not infer a stage from the cause.
                return Err(ClassifiedSyncFailure::at_stage(
                    summary,
                    error,
                    SyncFailureStage::Unknown,
                ));
            }
        };
        summary.merge(drained);
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
    }

    /// Drain engine events that were queued without an inbound transport
    /// delivery and project them into a [`SyncSummary`] the same way
    /// `ingest_delivery` does, minus the delivery-specific message decoding.
    ///
    /// This is the no-inbound counterpart to `sync_sdk_relay`: session `open()`
    /// hydration queues `GroupHydrationQuarantined`, and a successful
    /// `retry_hydrate_quarantined_group` queues `GroupHydrationRecovered`. Both
    /// rely on a drain to reach app/runtime subscribers; without an explicit
    /// path they only surface when unrelated relay traffic happens to trigger
    /// one (mdk#426). There is no source delivery here, so events that
    /// reference a not-yet-live (quarantined) group must not abort the drain —
    /// projection lookups are best-effort.
    pub(crate) async fn drain_pending_session_events(&mut self) -> Result<SyncSummary, AppError> {
        if cfg!(feature = "test-policy-overrides")
            && self.app.config.dev_fail_pending_session_event_drain
        {
            return Err(AppError::BlockingTask(
                "injected pending session event drain failure".to_owned(),
            ));
        }
        let effects = self.runtime.drain().await?;
        self.observe_drained_session_events(&effects).await
    }

    /// Project one drained batch of engine events, split from the drain itself
    /// so the projection is exercisable against a given batch of effects.
    pub(crate) async fn observe_drained_session_events(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
        self.observe_recovery_health(effects)?;
        // Retire released receipts even when the drain emitted no app events.
        self.transport_receipts()?;
        // Session open seeds this list from durable queued/convergence input.
        // Preserve that scheduling edge even when hydration emitted no app
        // events; the worker drains this set immediately after startup sync.
        self.remember_pending_convergence_groups(effects);
        // Observe before the publish gate, not after. `drain()` empties the
        // engine's in-memory event buffer one-shot and is these events' only
        // source, and a `TransportObjectResourceRefused` is buffered only after
        // its durable retention row is already deleted — so a refusal this pass
        // does not arm on can never be re-observed. The arm survives the `?`
        // because it is a field mutation plus a durable audit row, not summary
        // state. The two conditions are correlated rather than independent: this
        // drain publishes, so the failure and the refusal ride the same effects.
        self.observe_recovery_evidence(effects);
        let mut summary = SyncSummary::default();
        // `runtime.drain()` also resumes durable outbound fanouts. That work
        // can publish an accepted-pending application message without emitting
        // any engine event, so it must be projected before the eventless fast
        // path or publish-failure gate below. A batch can contain one fanout
        // that succeeded alongside another publish that failed; the successful
        // row must not remain stuck in `Sending` after its fanout is deleted.
        self.remember_published_reports(effects);
        let finalize_updates = self.finalize_published_app_message_source_retention(effects)?;
        let failed_updates = self.invalidate_failed_app_message_projections(effects, None)?;
        if let Err(error) = fail_if_publish_failed(effects) {
            self.pending_projection_updates.extend(finalize_updates);
            self.pending_projection_updates.extend(failed_updates);
            return Err(error);
        }
        summary.projection_updates.extend(finalize_updates);
        summary.projection_updates.extend(failed_updates);
        if effects.events.is_empty() {
            self.drain_epoch_stall_escalations(&mut summary);
            return Ok(summary);
        }
        let display_names = self.display_names_for_events(&effects.events);
        let source_received_at = unix_now_seconds();
        // Hydration replays a stored group's `GroupDisbanded` once ever
        // (`restore_disband_tombstone`), as the belt-and-braces reconciler for a
        // disband whose live-session projection never completed — a crash, or a
        // batch that failed after the engine had already drained the event. So
        // this seam owes the same terminal sweep as the inbound one, which it
        // discharges by running the shared `observe_event_projection_effects`
        // below rather than a copy of it. The durable writes that must not
        // depend on that one replay arriving are reconciled from the guard rows
        // instead, by `sweep_terminal_groups_from_guards` at account open.
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let local_group_deletion_frontiers =
            self.local_group_deletion_frontiers_at_batch_start(effects)?;
        let mut routes_dirty = false;
        let mut gossip_message_ids = HashSet::new();
        for event in &effects.events {
            // A replayed application event has no outer relay envelope, but its
            // durable engine outbox key is stable and unique. Use that key as
            // the synthetic source so a crash can replay several pending
            // events in one drain without colliding on an empty source id.
            let source_message_id_hex = event_source_message_id_hex(event, "");
            let batch_start_frontier = event_group_id(event)
                .and_then(|group_id| {
                    local_group_deletion_frontiers.get(&hex::encode(group_id.as_slice()))
                })
                .copied();
            let crosses_frontier = match batch_start_frontier {
                Some(frontier) => self.local_deleted_group_event_crosses_frontier(
                    event,
                    frontier,
                    &source_message_id_hex,
                    source_received_at,
                )?,
                None => false,
            };
            if !crosses_frontier
                && let Some(changed) =
                    self.suppress_local_deleted_group_event(event, batch_start_frontier)?
            {
                routes_dirty |= changed;
                self.prepare_pending_application_event_ack(event);
                continue;
            }
            let before = self.state.groups.len();
            let previous_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            // Best-effort projection: a quarantined group is not live, so its
            // routing/metadata components may be unavailable. Skip projection
            // rather than propagate — the event must still reach subscribers.
            let group_metadata =
                event_group_id(event).and_then(|group_id| self.runtime.group_record(group_id).ok());
            let group_projection = event_group_id(event).and_then(|group_id| {
                self.event_group_projection_best_effort(group_id, group_metadata.as_ref())
            });
            let projection_started = Instant::now();
            if let Some(message) = observe_event(
                &mut self.state,
                &display_names,
                &mut summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
                source_received_at,
                None,
                self.app.allow_loopback_blob_endpoints(),
            ) {
                match self.project_received_message(message, group_metadata.as_ref(), &mut summary)
                {
                    Ok(Some(gossip_message_id)) => {
                        gossip_message_ids.insert(gossip_message_id);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        self.record_v5_event_projection_failure(
                            std::slice::from_ref(event),
                            &error,
                            projection_started.elapsed(),
                        );
                        return Err(error);
                    }
                }
            }
            let updated_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            if previous_group != updated_group
                && let Some(group_id) = event_group_id(event)
            {
                self.mark_group_projection_dirty(group_id);
            }
            self.audit_observed_group_event(
                event,
                previous_group.as_ref(),
                updated_group.as_ref(),
                &source_message_id_hex,
            );
            #[cfg(test)]
            if previous_group != updated_group
                && let Some(probe) = &mut self.audit_v5_probe
            {
                probe.projected(
                    event,
                    marmot_forensics::v5::UpdateCause::RetainedEventReplay,
                );
            }
            let projected =
                self.observe_event_projection_effects(event, &local_account_id_hex, &mut summary);
            match projected {
                Ok(dirty) => routes_dirty |= dirty,
                Err(error) => {
                    self.record_v5_event_projection_failure(
                        std::slice::from_ref(event),
                        &error,
                        projection_started.elapsed(),
                    );
                    return Err(error);
                }
            }
            let can_ack_application_event = if crosses_frontier {
                self.prepare_local_group_deletion_frontier_clear(
                    event,
                    batch_start_frontier.expect("crossing event has a frontier"),
                )?
            } else {
                true
            };
            if can_ack_application_event {
                self.prepare_pending_application_event_ack(event);
            }
            if self.state.groups.len() != before {
                routes_dirty = true;
            }
        }
        if !gossip_message_ids.is_empty() {
            summary
                .messages
                .retain(|message| !gossip_message_ids.contains(&message.message_id_hex));
        }
        self.clear_terminal_local_group_deletion_frontiers(effects)?;
        // Synthesize durable kind-1210 system rows from the replayed
        // authenticated state changes, the same tail the live seam runs. A
        // replayed event carries no envelope of its own — that is why this seam
        // derives a synthetic source id from the durable outbox key above — so
        // the rows are stamped with `source_received_at`, this drain's
        // observation time, exactly like every other projection in the loop.
        // The row id is derived from the change and its epoch, never from the
        // stamp, so a crash that replays the batch re-upserts the same row.
        summary
            .projection_updates
            .extend(self.project_group_system_rows(&effects.events, source_received_at));
        // Reconcile transport routes once after the batch drains instead of per
        // membership-changing event. This installs a join's current route and
        // retains any still-live address displaced by a routing rotation.
        let routes_changed = self.refresh_group_routes()?.routing_changed;
        if (routes_dirty || routes_changed)
            && let Err(error) = self.sync_runtime_groups().await
        {
            // Retain an explicit retry edge, as the catch-up checkpoint does
            // after its own post-persistence rebuild failure. Neither edge that
            // reached this rebuild survives the failure: `drain()` emptied the
            // engine's event buffer one-shot, so the `routes_dirty` event is
            // gone, and `refresh_group_routes` reports a change only while the
            // in-memory routing table is actually mutating, which it already
            // did. Without this the account keeps stale group subscriptions
            // until unrelated traffic dirties the routes again — traffic those
            // same stale subscriptions are what stop from arriving. The save
            // below owes no arm: when either edge was set the rebuild above
            // already succeeded, and when neither was set nothing is owed.
            self.pending_runtime_group_subscription_refresh = true;
            self.pending_failed_sync_summary.merge(summary);
            return Err(error);
        }
        if let Err(error) = self.save_state_with_pending_local_group_deletion_frontier_clears() {
            // The engine outbox remains unacknowledged. A reopened client will
            // replay it; a retained client instead checkpoints the projected
            // state on its next sync and returns this deferred summary once.
            self.pending_failed_sync_summary.merge(summary);
            return Err(error);
        }
        summary.merge(std::mem::take(&mut self.pending_failed_sync_summary));
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
    }

    /// Observe group events the engine applied as a side effect of an outbound
    /// send and buffer them for the account worker to broadcast.
    ///
    /// A send that lands while inbound convergence input is retained folds the
    /// retained commits before publishing, so its effects can carry peer
    /// `GroupStateChanged` / `EpochChanged` events (e.g. a group rename applied
    /// mid-window). Those events never pass through the inbound ingest or
    /// scheduled-convergence seams, so without this pass they reach no runtime
    /// subscriber: storage shows the new state while chat-list and group-state
    /// subscriptions stay silent. Runs the same observe pipeline as those seams
    /// — state group refresh, push-gossip handling, kind-1210 system-row
    /// synthesis (a deterministic upsert) — and merges the result into
    /// `pending_applied_sync_summary`. The caller persists state afterwards.
    pub(crate) async fn observe_send_applied_effects(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        if effects.events.is_empty() {
            return Ok(());
        }
        let mut summary = SyncSummary::default();
        // Synthetic source identity: these events have no single inbound
        // transport message (see `drain_pending_session_events`).
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let routes_dirty = self
            .observe_account_device_effects(
                effects,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
            )
            .await?;
        let routes_changed = self.refresh_group_routes()?.routing_changed;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.pending_applied_sync_summary.merge(summary);
        Ok(())
    }

    /// Best-effort wrapper over [`Self::observe_send_applied_effects`] for the
    /// outbound send paths: a projection or route-refresh failure here must
    /// not fail a publish that already completed (or mask a publish error on
    /// the failure path), so it is logged rather than propagated.
    pub(crate) async fn observe_send_applied_effects_best_effort(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        if let Err(_err) = self.observe_send_applied_effects(effects).await {
            tracing::warn!(
                target: "marmot_app::messages",
                method = "observe_send_applied_effects",
                error_code = "send_applied_observe_failed",
                "failed to observe group events applied during a send"
            );
        }
    }

    /// Drain the buffered summary of send-applied group events. Called by the
    /// account worker after each command so the events broadcast on the same
    /// seam that published the command's response.
    pub(crate) fn take_pending_applied_sync_summary(&mut self) -> SyncSummary {
        std::mem::take(&mut self.pending_applied_sync_summary)
    }

    /// Build an [`EventGroupProjection`] for `group_id`, returning `None` if any
    /// component lookup fails (e.g. the group is quarantined and not live).
    /// Used by the no-inbound drain path where a missing projection must not
    /// abort processing.
    fn event_group_projection_best_effort<'a>(
        &self,
        group_id: &cgka_traits::GroupId,
        group_metadata: Option<&'a cgka_traits::group::Group>,
    ) -> Option<EventGroupProjection<'a>> {
        #[cfg(test)]
        if self.force_event_group_projection_unavailable {
            return None;
        }
        self.event_group_projection(group_id, group_metadata).ok()
    }

    pub async fn next_event(&mut self) -> Result<SyncSummary, AppError> {
        loop {
            let summary = match self.receive_next_delivery().await? {
                crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) => {
                    self.ingest_received_delivery(*delivery).await?
                }
                // The loss is durable and fences the cursor. A directly owned
                // client has no worker, so its recovery job runs here.
                crate::relay_plane::AccountDeliveryReceive::Overflow(_) => {
                    match self
                        .run_pending_epoch_backfill(EpochBackfillExecutionSeam::Receive)
                        .await?
                    {
                        EpochBackfillRunOutcome::Completed(summary)
                        | EpochBackfillRunOutcome::Incomplete(summary) => summary,
                        EpochBackfillRunOutcome::Deferred | EpochBackfillRunOutcome::NotPending => {
                            SyncSummary::default()
                        }
                    }
                }
            };
            // A directly-owned AppClient has no account-worker scheduler to
            // perform the post-visibility retry. Preserve its historical
            // contract by completing the pending rebuild before handing the
            // summary to its caller; the managed worker uses the lower-level
            // ingest method and owns the background retry instead.
            self.retry_pending_runtime_group_subscription_refresh()
                .await?;
            if summary.joined_groups.is_empty()
                && summary.messages.is_empty()
                && summary.events.is_empty()
                && summary.epoch_stall_escalations.is_empty()
                && self.pending_convergence_groups.is_empty()
                && !self.has_pending_epoch_backfill()
            {
                continue;
            }
            return Ok(summary);
        }
    }

    /// Wait only for the next non-echo, non-duplicate transport delivery.
    ///
    /// The account worker selects this transport-only receive phase against
    /// commands. Once a delivery is returned, it calls
    /// [`Self::ingest_received_delivery`] outside the `select!`, so durable
    /// engine ingest, incidental publish, and app projection cannot be dropped
    /// halfway through when a command arrives.
    pub(crate) async fn receive_next_delivery(
        &mut self,
    ) -> Result<crate::relay_plane::AccountDeliveryReceive, AppError> {
        use crate::relay_plane::AccountDeliveryWait;
        loop {
            // A consumer lag charges notification loss before any control
            // record reaches this queue, and a record may never come: its
            // queue can close during a reopen. Persist the loss now. Without
            // an outstanding record, report the overflow here, like spilled
            // loss below. With one, that record starts recovery once the
            // deliveries queued ahead of it drain, so no attempt starts that
            // could not clear the loss.
            if let Some(loss) = self.adapter.unpersisted_notification_loss() {
                self.observe_delivery_overflow(loss)?;
                if !self.adapter.delivery_overflow_signal_outstanding() {
                    return Ok(crate::relay_plane::AccountDeliveryReceive::Overflow(loss));
                }
            }
            // Spilled rows that became queue loss are already durable and
            // fence the cursor. Report them as an overflow, so every caller
            // starts the same recovery it runs for a router omission.
            if self.delivery_spill.take_recorded_loss() {
                return Ok(crate::relay_plane::AccountDeliveryReceive::Overflow(
                    crate::relay_plane::AccountDeliveryOverflow {
                        marker_token: self
                            .delivery_overflow_recovery_marker_token
                            .unwrap_or_default(),
                        ..Default::default()
                    },
                ));
            }
            // A spilled backlog is always ready. Yield before taking a row, so
            // the worker's lower-priority arms still run between deliveries,
            // and cancellation here loses nothing.
            if self.delivery_spill.pending() {
                tokio::task::yield_now().await;
            }
            let received = match self.take_ready_delivery()? {
                Some(received) => received,
                None if self.delivery_spill.loss_recorded() => continue,
                None => match match self.spill_retry_wait() {
                    // Wake for a deferred spilled row even when nothing else
                    // arrives; a directly owned client has no other timer.
                    Some(delay) => match tokio::time::timeout(
                        delay,
                        self.adapter.receive_account_delivery_or_spill(),
                    )
                    .await
                    {
                        Ok(woke) => woke,
                        Err(_) => continue,
                    },
                    None => self.adapter.receive_account_delivery_or_spill().await,
                } {
                    AccountDeliveryWait::Received(received) => received,
                    AccountDeliveryWait::SpillReady => {
                        self.note_spill_ready();
                        continue;
                    }
                    AccountDeliveryWait::Closed => {
                        if let Some(loss) = self
                            .adapter
                            .unpersisted_notification_loss()
                            .or_else(|| self.adapter.pending_delivery_overflow())
                        {
                            self.observe_delivery_overflow(loss)?;
                        }
                        return Err(AppError::TransportClosed);
                    }
                },
            };
            let delivery = match received {
                crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) => delivery,
                crate::relay_plane::AccountDeliveryReceive::Overflow(overflow) => {
                    self.observe_delivery_overflow(overflow)?;
                    return Ok(crate::relay_plane::AccountDeliveryReceive::Overflow(
                        overflow,
                    ));
                }
            };
            let event_id = hex::encode(delivery.message.id.as_slice());
            if self.transport_receipts()?.contains(&event_id) {
                self.record_durable_transport_reconciliation_delivery(&delivery);
                self.adapter.release_account_delivery(&delivery.message.id);
                self.settle_spilled_delivery();
                continue;
            }
            return Ok(crate::relay_plane::AccountDeliveryReceive::Delivery(
                delivery,
            ));
        }
    }

    pub(crate) async fn ingest_received_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
    ) -> Result<SyncSummary, AppError> {
        self.ingest_received_delivery_inner(delivery)
            .await
            .map_err(|(_, _, _, error, _)| error)
    }

    /// Startup's off-worker comparison may receive a delivery before its
    /// immutable network request completes. Keep the applied prefix visible
    /// on a later checkpoint failure, just as the inline startup drain did.
    pub(crate) async fn ingest_received_delivery_with_partial(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let drain_started = std::time::Instant::now();
        let cursor_before_secs = self.state.last_transport_timestamp;
        match self.ingest_received_delivery_inner(delivery).await {
            Ok(summary) => Ok(summary),
            Err((summary, ingested, routes_dirty, error, stage)) => {
                let counts = DrainCounts {
                    deliveries: u64::from(ingested),
                    ..DrainCounts::default()
                };
                Err(self
                    .finish_failed_sync_drain(
                        summary,
                        routes_dirty,
                        counts,
                        StagedSyncError::new(error, stage),
                        drain_started,
                        cursor_before_secs,
                    )
                    .await)
            }
        }
    }

    async fn ingest_received_delivery_inner(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
    ) -> Result<SyncSummary, (SyncSummary, bool, bool, AppError, SyncFailureStage)> {
        // A spilled delivery gets exactly the live path's one ingest attempt.
        let result = self.ingest_received_delivery_once(delivery, true).await;
        self.settle_spilled_delivery();
        result.map(|(summary, _)| summary)
    }

    /// Admit one delivery a comparison fetched through the ordinary ingest
    /// path, without the live queue. An event the account already holds needs
    /// no ingest.
    pub(crate) async fn admit_recovered_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
    ) -> Result<(SyncSummary, RecoveredDelivery), AppError> {
        let event_id = hex::encode(delivery.message.id.as_slice());
        if self.transport_receipts()?.contains(&event_id) {
            self.record_durable_transport_reconciliation_delivery(&delivery);
            self.adapter.release_account_delivery(&delivery.message.id);
            return Ok((SyncSummary::default(), RecoveredDelivery::AlreadyHeld));
        }
        self.ingest_received_delivery_once(delivery, false)
            .await
            .map_err(|(_, _, _, error, _)| error)
    }

    /// Ingest one delivery and checkpoint it. A live delivery (`live_cursor`)
    /// may also promote the transport cursor with that checkpoint; see
    /// [`Self::seal_transport_cursor`].
    async fn ingest_received_delivery_once(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        live_cursor: bool,
    ) -> Result<
        (SyncSummary, RecoveredDelivery),
        (SyncSummary, bool, bool, AppError, SyncFailureStage),
    > {
        let cursor_before_secs = self.state.last_transport_timestamp;
        let mut summary = SyncSummary::default();
        let message_id = delivery.message.id.clone();
        let event_id = hex::encode(message_id.as_slice());
        let receipts = self.transport_receipts().map_err(|error| {
            (
                SyncSummary::default(),
                false,
                false,
                error,
                SyncFailureStage::StatePersist,
            )
        })?;
        let ingested = Self::ingest_delivery(receipts, delivery, &mut summary)
            .await
            .map_err(|error| {
                // The inline drain did not merge this delivery's staged
                // projection when ingest itself failed.
                (
                    SyncSummary::default(),
                    false,
                    false,
                    error,
                    SyncFailureStage::CgkaIngest,
                )
            })?;
        // The ingest is durable, or dropped on purpose: its delivery must not
        // hold back the cursor the saves below commit. A failed ingest never
        // gets here, so it keeps capping every later commit, including the
        // checkpoint a startup receive runs on that failure.
        self.adapter.release_account_delivery(&message_id);
        let settled = RecoveredDelivery::Ingested {
            unpersisted: ingested.must_stay_fetchable,
            refused_group: ingested.refused_group.clone(),
        };
        if self.delivery_loss_blocks_cursor() {
            // `record_drop` publishes this process-local fence at the exact
            // omission, before marker I/O or the reserved control record can
            // complete. Keep this per-delivery checkpoint on its pre-ingest
            // floor so slow SQLite cannot commit the newest-first prefix ahead
            // of the marker that represents the omitted older delivery.
            self.state.last_transport_timestamp = cursor_before_secs;
        }
        // Mark the delivery seen only after durable ingest succeeds, matching
        // the catch-up drain below. Marking at receive time would let a failed
        // ingest poison the index, so a reused client would silently skip the
        // redelivered event — and an `Ok` the engine refused unpersisted is
        // just as much a not-durable ingest as an `Err` is.
        if !ingested.must_stay_fetchable {
            self.remember_seen_event(event_id);
        }
        let routes_dirty = ingested.routes_dirty;
        let promote = live_cursor && self.live_cursor_promotion_ready().await;
        // A membership-changing ingest is already durable. Persist its app
        // projection before route reconciliation or subscription refresh can
        // fail, matching the catch-up checkpoint below.
        if routes_dirty {
            let sealed = promote.then(|| self.seal_transport_cursor());
            if let Err(error) = self.save_state_with_pending_local_group_deletion_frontier_clears()
            {
                if let Some(sealed) = sealed {
                    self.abandon_transport_cursor(sealed);
                }
                return Err((
                    summary,
                    true,
                    routes_dirty,
                    error,
                    SyncFailureStage::StatePersist,
                ));
            }
        }
        let refresh = match self.refresh_group_routes() {
            Ok(refresh) => refresh,
            Err(error) => {
                return Err((
                    summary,
                    true,
                    routes_dirty,
                    error,
                    SyncFailureStage::StatePersist,
                ));
            }
        };
        // The routes-dirty save above already persisted this delivery's app
        // projection; save again only when that first save did not run, or
        // when route retirement just mutated persisted group state. The
        // routing-table delta lives in memory and obligates a subscription
        // refresh, not a second identical state write.
        if !routes_dirty || refresh.state_pruned {
            // With dirty routes the first save already persisted it.
            let sealed = (promote && !routes_dirty).then(|| self.seal_transport_cursor());
            if let Err(error) = self.save_state_with_pending_local_group_deletion_frontier_clears()
            {
                if let Some(sealed) = sealed {
                    self.abandon_transport_cursor(sealed);
                }
                return Err((
                    summary,
                    true,
                    routes_dirty,
                    error,
                    SyncFailureStage::StatePersist,
                ));
            }
        }
        self.pending_runtime_group_subscription_refresh |= routes_dirty || refresh.routing_changed;
        self.drain_epoch_stall_escalations(&mut summary);
        Ok((summary, settled))
    }

    fn checkpoint_error_stage_and_cursor(
        &self,
        error: &SyncCheckpointError,
        cursor_before_secs: Option<u64>,
    ) -> (SyncFailureStage, Option<u64>) {
        match error {
            SyncCheckpointError::BeforePersistence(_) => {
                (SyncFailureStage::StatePersist, cursor_before_secs)
            }
            SyncCheckpointError::AfterPersistence(_) => (
                SyncFailureStage::GroupSubscriptionSync,
                self.state.last_transport_timestamp,
            ),
        }
    }

    /// Whether this seam must leave a pending intent alone for now.
    ///
    /// Pacing skips automatic attempts outright rather than queueing them:
    /// the intent is already durable and the next seam past the cooldown runs
    /// it. Caller-directed catch-up is exempt: a person asking for a repair is
    /// not a loop.
    #[cfg(test)]
    pub(crate) fn epoch_backfill_retry_is_paced(&self, seam: EpochBackfillExecutionSeam) -> bool {
        if matches!(seam, EpochBackfillExecutionSeam::ExplicitCatchUp) {
            return false;
        }
        !self
            .recovery_owner
            .test_retry_remaining(&self.app.account_storage(&self.state.label).unwrap())
            .is_zero()
    }

    /// Drain the transport for an ordinary floored sync: ingest what is waiting
    /// and return as soon as the relays go quiet. A loss control record ends
    /// the drain once its loss is durable; recovery settles it by comparison.
    async fn sync_sdk_relay(&mut self) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let mut counts = DrainCounts::default();
        let mut summary = SyncSummary::default();
        let mut first_wait = true;
        // Forensic drain accounting: wall-clock span, deliveries actually
        // ingested and receives skipped as echo or duplicate (counted apart, so
        // a long drain that was working is distinguishable from one held open
        // by traffic carrying no new history), and the durable cursor
        // before/after so an analyzer can compare the persisted floor against
        // the ingested `created_at`s.
        let drain_started = std::time::Instant::now();
        let cursor_before_secs = self.state.last_transport_timestamp;
        let mut routes_dirty = false;
        let overflowed = loop {
            let wait = if first_wait {
                SDK_FIRST_SYNC_WAIT
            } else {
                SDK_DRAIN_WAIT
            };
            first_wait = false;
            let receive = async {
                loop {
                    match timeout(EOSE_QUIET_WAIT, self.adapter.receive_account_delivery()).await {
                        Ok(result) => return result,
                        Err(_) if self.adapter.account_subscription_eose().await.complete() => {
                            return Ok(None);
                        }
                        Err(_) => {}
                    }
                }
            };
            let delivery = match timeout(wait, receive).await {
                Ok(Ok(Some(crate::relay_plane::AccountDeliveryReceive::Delivery(delivery)))) => {
                    delivery
                }
                Ok(Ok(Some(crate::relay_plane::AccountDeliveryReceive::Overflow(overflow)))) => {
                    if let Err(error) = self.observe_delivery_overflow(overflow) {
                        // Never checkpoint a cursor learned from the incomplete
                        // prefix unless the durable recovery marker landed
                        // first. Engine/app projection work remains retryable;
                        // the older floor is the safe subscription authority.
                        self.state.last_transport_timestamp = cursor_before_secs;
                        return Err(self
                            .finish_failed_sync_drain(
                                summary,
                                routes_dirty,
                                counts,
                                StagedSyncError::new(error, SyncFailureStage::StatePersist),
                                drain_started,
                                cursor_before_secs,
                            )
                            .await);
                    }
                    break true;
                }
                // A quiet relay is a finished drain.
                Ok(Ok(None)) | Err(_) => break false,
                Ok(Err(error)) => {
                    return Err(self
                        .finish_failed_sync_drain(
                            summary,
                            routes_dirty,
                            counts,
                            StagedSyncError::new(error.into(), SyncFailureStage::RelayReceive),
                            drain_started,
                            cursor_before_secs,
                        )
                        .await);
                }
            };
            // Evaluate before the exclusive receipt borrow; counts.deliveries
            // stays unchanged until admission (duplicates only bump skipped).
            let fail_before_delivery = cfg!(feature = "test-policy-overrides")
                && self
                    .app
                    .config
                    .dev_fail_sync_before_delivery
                    .is_some_and(|limit| counts.deliveries >= limit);
            let receipts = match self.transport_receipts() {
                Ok(receipts) => receipts,
                Err(error) => {
                    return Err(self
                        .finish_failed_sync_drain(
                            summary,
                            routes_dirty,
                            counts,
                            StagedSyncError::new(error, SyncFailureStage::StatePersist),
                            drain_started,
                            cursor_before_secs,
                        )
                        .await);
                }
            };
            let event_id = hex::encode(delivery.message.id.as_slice());
            if receipts.contains(&event_id) {
                self.record_durable_transport_reconciliation_delivery(&delivery);
                self.adapter.release_account_delivery(&delivery.message.id);
                counts.skipped = counts.skipped.saturating_add(1);
                continue;
            }
            if fail_before_delivery {
                return Err(self
                    .finish_failed_sync_drain(
                        summary,
                        routes_dirty,
                        counts,
                        StagedSyncError::new(
                            AppError::BlockingTask("injected catch-up delivery failure".to_owned()),
                            SyncFailureStage::Unknown,
                        ),
                        drain_started,
                        cursor_before_secs,
                    )
                    .await);
            }
            let mut delivery_summary = SyncSummary::default();
            let message_id = delivery.message.id.clone();
            let ingested =
                match Self::ingest_delivery(receipts, *delivery, &mut delivery_summary).await {
                    Ok(ingested) => ingested,
                    Err(error) => {
                        // The failed delivery is still taken, so this
                        // checkpoint stops where a restart fetches it again,
                        // though newest-first replay already remembered a
                        // newer cursor.
                        return Err(self
                            .finish_failed_sync_drain(
                                summary,
                                routes_dirty,
                                counts,
                                StagedSyncError::new(error, SyncFailureStage::CgkaIngest),
                                drain_started,
                                cursor_before_secs,
                            )
                            .await);
                    }
                };
            self.adapter.release_account_delivery(&message_id);
            if ingested.must_stay_fetchable {
                counts.unpersisted = counts.unpersisted.saturating_add(1);
            }
            // The refusal count is keyed on the refusal itself, so the audit
            // row keeps meaning "a local resource bound rejected this" and not
            // the wider "left no durable trace".
            if let Some(group_id) = ingested.refused_group {
                debug_assert!(ingested.must_stay_fetchable);
                counts.refused = counts.refused.saturating_add(1);
                counts.refused_groups.insert(group_id);
            }
            // Same rule as the receive seam above: an object the engine kept no
            // durable trace of must stay fetchable, so the relay re-serves it on
            // a later drain instead of this one skipping it as already seen.
            if !ingested.must_stay_fetchable {
                self.remember_seen_event(event_id);
            }
            counts.deliveries = counts.deliveries.saturating_add(1);
            summary.merge(delivery_summary);
            routes_dirty |= ingested.routes_dirty;
            // A cancelled drain cannot replay an already-applied commit's
            // group effects. Save them before waiting for another delivery.
            if !self.pending_group_projection_updates.is_empty() {
                // Persist group fields without acknowledging replayable output:
                // the caller has not received this drain's summary yet.
                let pending_acks = std::mem::take(&mut self.pending_application_event_acks);
                let saved = self.save_state_with_pending_local_group_deletion_frontier_clears();
                self.pending_application_event_acks = pending_acks;
                if let Err(error) = saved {
                    return Err(self
                        .finish_failed_sync_drain(
                            summary,
                            routes_dirty,
                            counts,
                            StagedSyncError::new(error, SyncFailureStage::StatePersist),
                            drain_started,
                            cursor_before_secs,
                        )
                        .await);
                }
            }
        };

        if !overflowed
            && let Some(overflow) = self
                .adapter
                .unpersisted_notification_loss()
                .or_else(|| self.adapter.pending_delivery_overflow())
        {
            // The queue signal intentionally trails marker persistence, so a
            // quiescence timeout can win while that signal is still pending.
            // Consult the immediate process-local fence before checkpointing.
            self.state.last_transport_timestamp = cursor_before_secs;
            if let Err(error) = self.observe_delivery_overflow(overflow) {
                return Err(self
                    .finish_failed_sync_drain(
                        summary,
                        routes_dirty,
                        counts,
                        StagedSyncError::new(error, SyncFailureStage::StatePersist),
                        drain_started,
                        cursor_before_secs,
                    )
                    .await);
            }
        }

        if let Err(error) = self
            .checkpoint_sync_prefix(&mut summary, routes_dirty, counts.deliveries)
            .await
        {
            let (stage, cursor_after_secs) =
                self.checkpoint_error_stage_and_cursor(&error, cursor_before_secs);
            let (summary, source) = self.checkpoint_failure_summary(summary, error);
            self.record_sync_drain(
                drain_started.elapsed().as_millis() as u64,
                counts,
                cursor_before_secs,
                cursor_after_secs,
            );
            return Err(ClassifiedSyncFailure::at_stage(summary, source, stage));
        }
        self.record_sync_drain(
            drain_started.elapsed().as_millis() as u64,
            counts,
            cursor_before_secs,
            self.state.last_transport_timestamp,
        );
        Ok(summary)
    }

    async fn finish_failed_sync_drain(
        &mut self,
        mut summary: SyncSummary,
        routes_dirty: bool,
        counts: DrainCounts,
        original: StagedSyncError,
        drain_started: std::time::Instant,
        cursor_before_secs: Option<u64>,
    ) -> ClassifiedSyncFailure {
        let (source, stage, cursor_after_secs) = match self
            .checkpoint_sync_prefix(&mut summary, routes_dirty, counts.deliveries)
            .await
        {
            Ok(()) => (
                original.source,
                original.stage,
                self.state.last_transport_timestamp,
            ),
            Err(error) => {
                let (stage, cursor_after_secs) =
                    self.checkpoint_error_stage_and_cursor(&error, cursor_before_secs);
                let (retained_summary, checkpoint_error) =
                    self.checkpoint_failure_summary(summary, error);
                summary = retained_summary;
                (checkpoint_error, stage, cursor_after_secs)
            }
        };
        self.record_sync_drain(
            drain_started.elapsed().as_millis() as u64,
            counts,
            cursor_before_secs,
            cursor_after_secs,
        );
        tracing::debug!(
            target: "marmot_app::history_repair",
            method = "finish_failed_sync_drain",
            failure_stage = stage.as_str(),
            error_kind = source.privacy_safe_kind(),
            error_class = source.sync_error_class().as_str(),
            "sync drain failed"
        );
        ClassifiedSyncFailure::at_stage(summary, source, stage)
    }

    async fn checkpoint_sync_prefix(
        &mut self,
        summary: &mut SyncSummary,
        routes_dirty: bool,
        deliveries: u64,
    ) -> Result<(), SyncCheckpointError> {
        // The checkpoint re-runs `refresh_group_routes` only when the drained
        // prefix could have changed routing: deliveries advance epochs (which
        // gate prior-route pruning) and can mark groups disbanded. With zero
        // deliveries and no dirty routes, engine-visible group state is
        // byte-identical to what the sync-start refresh already read, so the
        // recomputation here would rescan every group only to install the same
        // routing snapshot (mdk#1380).
        let routes_changed = if deliveries > 0 || routes_dirty {
            self.checkpoint_route_refresh_recomputes =
                self.checkpoint_route_refresh_recomputes.saturating_add(1);
            self.refresh_group_routes()
                .map_err(SyncCheckpointError::BeforePersistence)?
                .routing_changed
        } else {
            false
        };
        // Pending queue loss fences the cursor until recovery settles it.
        let sealed =
            (!self.delivery_overflow_recovery_pending).then(|| self.seal_transport_cursor());
        let checkpoint = if cfg!(feature = "test-policy-overrides")
            && self
                .app
                .config
                .dev_fail_sync_before_boundary_save
                .is_some_and(|limit| deliveries > 0 && deliveries > limit)
        {
            Err(AppError::BlockingTask(
                "injected catch-up boundary save failure".to_owned(),
            ))
        } else {
            self.save_state_with_pending_local_group_deletion_frontier_clears()
        };
        if let Err(error) = checkpoint {
            if let Some(sealed) = sealed {
                self.abandon_transport_cursor(sealed);
            }
            return Err(SyncCheckpointError::BeforePersistence(error));
        }
        if let Some(sealed) = sealed {
            self.settle_transport_cursor(sealed);
        }

        summary.merge(std::mem::take(&mut self.pending_failed_sync_summary));

        if routes_dirty || routes_changed {
            match self.sync_runtime_groups().await {
                Ok(()) => self.pending_runtime_group_subscription_refresh = false,
                Err(error) => {
                    // The projection and route checkpoint above are durable.
                    // Retain an explicit retry edge so the worker repairs the
                    // ordinary subscriptions without replaying this prefix or
                    // waiting for another catch-up trigger.
                    self.pending_runtime_group_subscription_refresh = true;
                    return Err(SyncCheckpointError::AfterPersistence(error));
                }
            }
        }
        Ok(())
    }

    fn checkpoint_failure_summary(
        &mut self,
        summary: SyncSummary,
        error: SyncCheckpointError,
    ) -> (SyncSummary, AppError) {
        match error {
            SyncCheckpointError::BeforePersistence(source) => {
                // Message/join projections from this drain are not reportable
                // until their checkpoint commits. Keep one-shot epoch-stall
                // escalations pending here: partial-progress entry points drain
                // them into the failure, while compatibility `sync()` leaves
                // them available for the retained client's next success.
                self.pending_failed_sync_summary.merge(summary);
                (SyncSummary::default(), source)
            }
            SyncCheckpointError::AfterPersistence(source) => (summary, source),
        }
    }

    fn record_transport_reconciliation_item(
        &self,
        route: &TransportReconciliationRoute,
        item: &TransportReconciliationItem,
    ) {
        let recorded = self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| {
                storage
                    .record_transport_reconciliation_item(route, item)
                    .map_err(AppError::from)
            });
        if recorded.is_err() {
            // The event remains absent from the advertised local set, so a
            // later reconciliation safely re-fetches it. Do not fail an
            // ingest the engine already retained merely because this
            // optimization checkpoint failed.
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "record_transport_reconciliation_item",
                "could not persist transport reconciliation item"
            );
        }
    }

    fn record_durable_transport_reconciliation_delivery(
        &self,
        delivery: &cgka_traits::TransportDelivery,
    ) {
        if let Some((route, item)) =
            transport_reconciliation_record(self.adapter.account_id(), delivery)
        {
            // Own relay echoes and seen-index hits are skipped precisely because
            // the event is already durable. Recording them here closes the
            // migration/echo seam without replaying them through the engine.
            self.record_transport_reconciliation_item(&route, &item);
        }
    }

    /// Consume the exclusive receipt view used for admission. The SDK drain
    /// shares it with its duplicate decision, while direct ingestion opens one.
    async fn ingest_delivery(
        receipts: super::receipts::SynchronizedTransportReceipts<'_>,
        delivery: cgka_traits::TransportDelivery,
        summary: &mut SyncSummary,
    ) -> Result<DeliveryIngest, AppError> {
        let client = receipts.into_client();
        #[cfg(test)]
        if client.fail_ingest_of.as_ref() == Some(&delivery.message.id) {
            client.fail_ingest_of = None;
            return Err(AppError::BlockingTask(
                "injected delivery ingest failure".to_owned(),
            ));
        }
        let source_message_id = delivery.message.id.clone();
        let source_message_id_hex = hex::encode(source_message_id.as_slice());
        let outer_transport_at = delivery.message.timestamp.0;
        let source_received_at = delivery.received_at.0;
        let group_id_hint = delivery.group_id_hint.clone();
        let reconciliation_record =
            transport_reconciliation_record(client.adapter.account_id(), &delivery);
        let welcome = matches!(
            &delivery.message.envelope,
            TransportEnvelope::Welcome { .. }
        );
        let probe_receive = if welcome && (client.audit_v5_enabled() || cfg!(test)) {
            client
                .audit_v5_probe
                .as_mut()
                .and_then(|probe| probe.observe(&delivery.message))
        } else {
            None
        };
        client.flush_live_v5_events();
        // Hold the same account policy lock through admission and projection, so a
        // block cannot commit between authenticating the inviter and creating state.
        let policy_lock = client.app.block_update_lock(&client.state.label).await;
        let _welcome_policy_guard = if welcome {
            Some(policy_lock.lock().await)
        } else {
            None
        };
        if welcome {
            let storage = client.app.account_storage(&client.state.label)?;
            if storage.is_blocked_welcome_dismissed(&source_message_id_hex)? {
                return Ok(DeliveryIngest {
                    routes_dirty: false,
                    must_stay_fetchable: false,
                    refused_group: None,
                });
            }
            // Dismissals remain authoritative after unblock. With no current
            // blocks the normal ingress peeler is sufficient.
            if storage.has_blocked_users()? {
                let account = client.app.account_home().account(&client.state.label)?;
                let peeler = transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer_arc(
                    client
                        .app
                        .account_signer_for_summary(&account)?
                        .as_nostr_signer(),
                );
                // The seal's authenticated sender is authoritative, never the outer gift-wrap key.
                // A peel failure proceeds to normal admission, which rejects invalid envelopes.
                if let Ok(peeled) =
                    cgka_traits::peeler::TransportPeeler::peel_welcome(&peeler, &delivery.message)
                        .await
                    && let Some(sender) = peeled.sender
                    && storage.is_user_blocked(&hex::encode(sender.as_slice()))?
                {
                    storage.dismiss_blocked_welcome(&source_message_id_hex)?;
                    return Ok(DeliveryIngest {
                        routes_dirty: false,
                        must_stay_fetchable: false,
                        refused_group: None,
                    });
                }
            }
        }
        let rejoin_offers_before = if welcome {
            Some(client.rejoin_offer_snapshot()?)
        } else {
            None
        };
        let observation = client.app.product_analytics.begin(
            if welcome {
                crate::ProductFamily::Welcome
            } else {
                crate::ProductFamily::MessageProcessing
            },
            if welcome { "process" } else { "receive" },
            crate::ProductUnit::Attempt,
        );
        let telemetry = client.runtime_telemetry.clone();
        let ingest_observation = telemetry.as_ref().map(|t| t.observe(RuntimeOp::Ingest));
        if let (Some(slot), Some(receive)) = (&client.audit_v5_peel_slot, probe_receive.clone()) {
            slot.lock().unwrap().arm(&delivery.message, receive);
        }
        let ingest = client
            .runtime
            .ingest_delivery_with_observer(delivery, |phase, duration, success| {
                if let Some(telemetry) = &telemetry {
                    let operation = match phase {
                        marmot_account::AccountIngestPhase::Engine => RuntimeOp::IngestEngine,
                        marmot_account::AccountIngestPhase::EffectPublication => {
                            RuntimeOp::IngestEffectPublish
                        }
                    };
                    telemetry.record_runtime(
                        operation,
                        duration,
                        if success {
                            TelemetryOutcome::Success
                        } else {
                            TelemetryOutcome::Failure
                        },
                    );
                }
            })
            .await;
        if let (Some(probe), Some(slot)) = (&mut client.audit_v5_probe, &client.audit_v5_peel_slot)
            && let Some(completion) = slot.lock().unwrap().take()
        {
            probe.unwrapped(completion);
        }
        if let (Some(probe), Some(receive), Ok(effects)) =
            (&mut client.audit_v5_probe, probe_receive, &ingest)
            && matches!(effects.outcome, IngestOutcome::Processed)
        {
            // The event is journaled in the join transaction. Only this
            // delivery's exact Welcome may turn it into a join row: the same
            // effects can also drain older application events.
            let mut joins = effects
                .effects
                .events
                .iter()
                .filter_map(|event| match event {
                    cgka_traits::engine::GroupEvent::GroupJoined {
                        group_id,
                        via_welcome,
                        explicitly_confirmed: false,
                        ..
                    } if via_welcome == &source_message_id => Some(group_id),
                    _ => None,
                });
            if let Some(group_id) = joins.next()
                && joins.next().is_none()
                && let Ok(group) = client.runtime.group_record(group_id)
            {
                let initial_join = probe.joined(receive.clone(), &group);
                if initial_join && client.runtime.session().audit_v5_enabled() {
                    let admins = client.runtime.admin_pubkeys(group_id).ok();
                    probe.baseline(
                        &group,
                        admins.as_deref(),
                        marmot_forensics::v5::BaselineReason::Joined,
                        Some(receive.1),
                    );
                }
            }
        }
        client.flush_live_v5_events();
        if let Some(observation) = ingest_observation {
            observation.finish(if ingest.is_ok() {
                TelemetryOutcome::Success
            } else {
                TelemetryOutcome::Failure
            });
        }
        if let Some(observation) = observation {
            observation.finish(match &ingest {
                Ok(effects) => match &effects.outcome {
                    IngestOutcome::Processed => "success",
                    IngestOutcome::Ignored {
                        category:
                            cgka_traits::InputRejectionCategory::Duplicate
                            | cgka_traits::InputRejectionCategory::OwnEcho,
                    } => "duplicate",
                    IngestOutcome::Buffered { .. }
                    | IngestOutcome::TransportDeferred { .. }
                    | IngestOutcome::LocalState { .. } => "deferred",
                    IngestOutcome::ResourceRefused { .. } => "capacity",
                    IngestOutcome::Ignored { .. }
                    | IngestOutcome::Stale { .. }
                    | IngestOutcome::Rejected { .. } => "rejected",
                },
                Err(_) => "failure",
            });
        }
        let effects = ingest?;
        client.observe_recovery_health(&effects.effects)?;
        if let Some(before) = rejoin_offers_before {
            // Account-wide eviction may remove an offer for a different group.
            // Invalidate every changed group's host projection, not just the
            // incoming Welcome's group. This scan reads bounded metadata only.
            client.reconcile_rejoin_offer_changes(before)?;
        }
        let source_released = client
            .transport_receipts()?
            .was_released(&source_message_id_hex);
        let publish_error = fail_if_publish_failed(&effects.effects).err();
        let must_stay_fetchable = effects.left_object_unpersisted || source_released;
        if !must_stay_fetchable && let Some((route, item)) = &reconciliation_record {
            client.record_transport_reconciliation_item(route, item);
            if matches!(
                effects.outcome,
                IngestOutcome::Processed
                    | IngestOutcome::Buffered { .. }
                    | IngestOutcome::TransportDeferred { .. }
                    | IngestOutcome::LocalState { .. }
            ) {
                let progress =
                    client
                        .app
                        .account_storage(&client.state.label)
                        .and_then(|storage| {
                            client
                                .recovery_owner
                                .observe_scoped_admission(
                                    &storage,
                                    route,
                                    item.created_at,
                                    Instant::now(),
                                )
                                .map_err(AppError::from)
                        });
                if progress.is_err() {
                    // Retained input remains valid; a failed retry reset merely
                    // preserves conservative pacing and never authorizes early I/O.
                    tracing::warn!(target: "marmot_app::recovery", method = "observe_scoped_admission",
                        "could not checkpoint recovery admission progress");
                }
            }
        }
        let refused_group = match &effects.outcome {
            IngestOutcome::ResourceRefused { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        client.remember_buffered_convergence_outcome(&effects.outcome);
        client.remember_pending_convergence_groups(&effects.effects);
        client.observe_recovery_evidence(&effects.effects);
        // The cursor is held back only by a resource refusal, which is
        // narrower than `must_stay_fetchable` on purpose.
        //
        // A refusal is this device failing to keep history it was served, at a
        // route it owns, so holding its own `since` floor back is holding back
        // work it must redo. Unknown-route input is not: the engine drops it
        // untraced precisely because #740 forbids letting unknown-route floods
        // consume local resources, and the `since` floor is one of those — an
        // attacker who can mint 445s for routes we do not have could otherwise
        // pin the whole account's floor in the past. Skipping the seen-mark
        // costs nothing and is what actually restores the object: the two
        // permanent drop sites are the seen index, and the unfloored recovery
        // replay re-serves the object once the route resolves.
        //
        // Scope fence: a `TransportDeferred` object *is* durably retained, so it
        // advances the floor here. Whether a retained-but-unapplied object
        // should instead hold the floor back until it converges is the separate
        // since-floor design item, not this seam's call.
        if refused_group.is_none() {
            client.remember_transport_cursor(outer_transport_at);
        }
        client.detect_epoch_stall(
            group_id_hint,
            &source_message_id_hex,
            &effects.outcome,
            cgka_traits::transport::Timestamp(outer_transport_at),
        );
        // A delivery can contain several application events. If projection
        // fails after an earlier event staged its acknowledgement, keep that
        // event in the durable engine outbox so a retained or reopened client
        // can replay its live summary. Recording only candidates absent before
        // this delivery avoids cloning the whole accumulated acknowledgement
        // set on every catch-up step.
        let new_application_event_ack_candidates = effects
            .effects
            .events
            .iter()
            .filter_map(|event| match event {
                cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. } => {
                    Some(message_id.clone())
                }
                cgka_traits::engine::GroupEvent::GroupJoined { via_welcome, .. } => {
                    Some(via_welcome.clone())
                }
                _ => None,
            })
            .filter(|event_id| !client.pending_application_event_acks.contains(event_id))
            .collect::<Vec<_>>();
        let routes_dirty = match client
            .observe_account_device_effects(
                &effects.effects,
                summary,
                &source_message_id_hex,
                source_received_at,
            )
            .await
        {
            Ok(routes_dirty) => routes_dirty,
            Err(error) => {
                for event_id in new_application_event_ack_candidates {
                    client.pending_application_event_acks.remove(&event_id);
                }
                return Err(error);
            }
        };
        // Publishing here is incidental work triggered by the inbound
        // delivery. A hard publish failure may roll that pending commit back,
        // but it must not discard the already-authenticated inbound message or
        // roster effects. They are projected above and the transport cursor is
        // allowed to advance; the failed work remains represented by the
        // engine's rollback/failure effects rather than turning relay
        // redelivery into an AlreadySeen projection hole.
        if let Some(err) = publish_error {
            tracing::warn!(
                target: "marmot_app",
                method = "ingest_delivery",
                error_kind = err.privacy_safe_kind(),
                "incidental auto-publish failed after inbound effects were projected"
            );
        }
        Ok(DeliveryIngest {
            routes_dirty,
            must_stay_fetchable,
            refused_group,
        })
    }

    /// Feed an unavailable group delivery to the epoch-stall detector.
    /// Transport-deferred input arms a backfill after the stalled-epoch
    /// threshold; resource refusal arms it immediately because it directly
    /// proves the fetched history was not fully retained. A deferral whose
    /// engine-reported lineage is fork-side arms on the same threshold and
    /// carries its own trigger — see
    /// [`backfill_trigger_for`](super::epoch_stall::backfill_trigger_for) for
    /// why the label moves and the decision does not. Repeated arming that
    /// never recovers the group escalates onto the next successful sync summary,
    /// the seam every worker surface already publishes. Only observed under
    /// `CursorPersistence::Advance`: a `Frozen` wake-collection pass must not
    /// own recovery, and the main app sees the same evidence on its own next
    /// sync.
    fn detect_epoch_stall(
        &mut self,
        group_id_hint: Option<cgka_traits::GroupId>,
        message_id_hex: &str,
        outcome: &IngestOutcome,
        transport_at: cgka_traits::transport::Timestamp,
    ) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        let Some(group_id) = group_id_hint else {
            return;
        };
        // A group we cannot resolve (unknown or quarantined) has its own recovery
        // surface; do not track it here.
        let Ok(record) = self.runtime.group_record(&group_id) else {
            return;
        };
        // A terminal copy has no servable history, so arming here could only
        // mint a durable intent and a forensic row for work that is never
        // coming. Defense in depth: a removed copy classifies
        // `LocalState { Removed }` and a disbanded one
        // `Ignored { UnknownGroup }`, so both already reach the `Skip` arm
        // below.
        if record.is_terminal() {
            return;
        }
        // A contested fork is eligible local work, not proof of a missing
        // transport object. Independent existing loss/gap obligations survive.
        if crate::client::epoch_stall::backfill_trigger_for(outcome)
            == EpochStallBackfillTrigger::ContestedForkDeferral
        {
            self.epoch_stall
                .observe_group_epoch(&group_id, record.epoch);
            self.pending_convergence_groups.insert(group_id);
            return;
        }
        let now_ms = epoch_stall_now_ms();
        let decision = match outcome {
            // Traffic older than this copy's Welcome is expected after a join,
            // and after a re-add it is most of what the relay serves: the
            // absent stretch was sealed under epochs this copy never entered
            // and never will. Unopenable, but not evidence this device is
            // behind — and a backfill armed from it could only re-fetch more of
            // the same. Land the epoch like every other non-evidence outcome
            // below and stop there. Soft by design: an application message
            // carries its sender's compose time, so a message drained from the
            // offline outbox can look old while being live. Dropping one piece
            // of evidence costs nothing, because every other undecryptable
            // message this device receives still arms.
            IngestOutcome::TransportDeferred { .. }
                if record.transport_message_predates_local_copy(transport_at) =>
            {
                self.epoch_stall
                    .observe_group_epoch(&group_id, record.epoch);
                BackfillDecision::Skip
            }
            IngestOutcome::TransportDeferred { .. } => self.epoch_stall.observe_undecryptable(
                group_id.clone(),
                message_id_hex.to_owned(),
                record.epoch,
                now_ms,
            ),
            IngestOutcome::ResourceRefused { .. } => {
                self.epoch_stall
                    .observe_resource_refusal(group_id.clone(), record.epoch, now_ms)
            }
            // Any other outcome carries no stall evidence, but it does tell the
            // detector where this device now sits. This is a landing position
            // only: the epochs a folded commit carried the device *through* reach
            // the detector as an `EpochChanged` passage, from this same delivery's
            // effects in `observe_recovery_evidence`. The landing report stays
            // because it is the fallback for movement no passage covers — an
            // engine seam that advances a group without emitting `EpochChanged`,
            // or a batch this delivery never sees — and because two landings at
            // different epochs can end a run on their own. Where both fire they
            // agree, since observing an epoch already recorded is a no-op.
            _ => {
                self.epoch_stall
                    .observe_group_epoch(&group_id, record.epoch);
                BackfillDecision::Skip
            }
        };
        self.apply_backfill_decision(
            &group_id,
            record.epoch.0,
            decision,
            crate::client::epoch_stall::backfill_trigger_for(outcome),
        );
    }

    /// Apply an epoch-stall backfill decision: arm the replay, and record an
    /// escalation the detector raises.
    ///
    /// Every site that takes a [`BackfillDecision`] must route it through here.
    /// Callers guard `record.is_terminal()` before deciding — both already hold
    /// the group record, so re-reading it per arm here would buy nothing.
    /// The detector latches `escalated` when it raises
    /// [`BackfillDecision::ArmAndEscalate`], so it raises that decision exactly
    /// once per unrecovered run. That makes reporting exactly-once by
    /// construction rather than by caller discipline: the escalation lands in
    /// `pending_epoch_stall_escalations` instead of on whatever [`SyncSummary`]
    /// the calling pass is building, so a later `?` on that pass cannot drop it
    /// — it rides out on the next seam that returns `Ok` (see
    /// [`Self::drain_epoch_stall_escalations`]).
    pub(crate) fn apply_backfill_decision(
        &mut self,
        group_id: &cgka_traits::GroupId,
        stalled_epoch: u64,
        decision: BackfillDecision,
        trigger: EpochStallBackfillTrigger,
    ) {
        if decision == BackfillDecision::Reassess {
            self.pending_convergence_groups.insert(group_id.clone());
            self.persist_epoch_stall_evidence([group_id]);
        }
        if decision.arms_backfill() {
            let demand_ticket = |client: &Self| {
                client
                    .app
                    .account_storage(&client.state.label)
                    .ok()
                    .and_then(|storage| storage.pending_recovery_demands().ok())
                    .and_then(|demands| {
                        demands.into_iter().find(|demand| {
                            demand.cause == storage_sqlite::RecoveryCause::EpochGap
                                && demand.group_id.as_deref() == Some(group_id.as_slice())
                        })
                    })
                    .map(|demand| demand.ticket)
            };
            let before = demand_ticket(self);
            let buffered_before = self.pending_recovery_arm_writes.get(group_id).copied();
            let durable_intent = storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group_id.as_slice()),
                stalled_epoch,
            };
            let result = self.app.arm_epoch_backfill_intents(
                &self.state.label,
                std::slice::from_ref(&durable_intent),
            );
            match result {
                Ok(()) => {
                    self.pending_recovery_arm_writes.remove(group_id);
                }
                Err(error) => {
                    self.pending_recovery_arm_writes
                        .entry(group_id.clone())
                        .and_modify(|epoch| *epoch = (*epoch).max(stalled_epoch))
                        .or_insert(stalled_epoch);
                    tracing::warn!(target: "marmot_app::epoch_stall", method = "apply_backfill_decision",
                        error_kind = error.privacy_safe_kind(), "recovery demand persistence will be retried before acquisition");
                }
            }
            let after = demand_ticket(self);
            if before != after
                || buffered_before != self.pending_recovery_arm_writes.get(group_id).copied()
            {
                let context = AuditEventContext {
                    operation_id: Some(hex::encode(
                        after
                            .map(|ticket| ticket.id)
                            .unwrap_or_else(rand::random::<[u8; 16]>),
                    )),
                    ..AuditEventContext::default()
                };
                self.record_epoch_stall_backfill_armed(group_id, stalled_epoch, trigger, &context);
            }
            // The arm mark is what paces the next one, so it has to outlive the
            // process: a device wedged for six hours must not buy a re-arm by
            // being force-killed.
            self.persist_epoch_stall_evidence(std::slice::from_ref(group_id));
        }
        if trigger == EpochStallBackfillTrigger::ResourceRefusal {
            let pressure = self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| {
                    Ok(storage.record_recovery_capacity_pressure(
                        group_id.as_slice(),
                        stalled_epoch,
                        self.recovery_owner.logical_now_ms(Instant::now())?,
                    )?)
                });
            if pressure.is_ok() {
                self.pending_recovery_capacity_writes.remove(group_id);
            }
            if let Err(error) = pressure {
                self.pending_recovery_capacity_writes
                    .insert(group_id.clone(), stalled_epoch);
                tracing::warn!(target: "marmot_app::recovery", method = "record_recovery_capacity_pressure",
                    error_kind=error.privacy_safe_kind(), "admission pressure remains pending persistence");
            }
        }
        if let BackfillDecision::ArmAndEscalate { arms } = decision {
            // The replay is armed above regardless: escalating reports that
            // replay alone is not repairing this group, it does not replace the
            // attempt (see EPOCH_STALL_ESCALATION_ARM_THRESHOLD for why
            // reporting is all this decision does).
            self.report_epoch_stall_escalation(
                group_id,
                stalled_epoch,
                arms,
                self.epoch_stall.escalation_arm_threshold(),
                "apply_backfill_decision",
            );
        }
    }

    /// Report that repeated full-history replay is not recovering a group.
    ///
    /// Two rules reach here and the report they produce is deliberately the
    /// same shape, because the claim is the same one: this many armed
    /// full-history replays did not return this group to the tip. An arm run
    /// across moving epochs counts arms
    /// ([`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`]); a group frozen at one epoch
    /// counts the relay-confirmed fruitless completions those arms produced
    /// ([`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`]). The detector latches
    /// `escalated` for the run either way, so a run reports once.
    pub(super) fn report_epoch_stall_escalation(
        &mut self,
        group_id: &cgka_traits::GroupId,
        stalled_epoch: u64,
        arms: u32,
        decided_by_threshold: u32,
        method: &'static str,
    ) {
        // The threshold logged is the one that actually decided, which is not
        // always the arm-run threshold the audit row carries: `method` names the
        // rule and this names the count it reached.
        tracing::warn!(
            target: "marmot_app::epoch_stall",
            method = method,
            arms,
            decided_by_threshold,
            "epoch-gap backfill armed repeatedly without recovering a group; escalating"
        );
        self.record_epoch_stall_backfill_escalated(group_id, stalled_epoch, arms);
        self.pending_epoch_stall_escalations
            .push(crate::EpochStallEscalation {
                group_id: group_id.clone(),
                stalled_epoch,
                arms,
            });
    }

    /// Merge durable arms into their existing retry owners. Counters describe
    /// account-wide replay attempts, so new groups get a fresh queued intent
    /// instead of inheriting another run's EOSE failures or resetting that run.
    ///
    /// Ends by dropping terminal groups. On a hydrated open that is also how a
    /// row for a group no owner holds is retired: this admits it, and the drop
    /// clears it. Before hydration every record reads non-terminal, so the row
    /// survives to the next pass.
    pub(crate) fn restore_persisted_epoch_backfill_intents(
        &mut self,
        _intents: Vec<storage_sqlite::StoredEpochBackfillIntent>,
    ) {
        // Demand is already authoritative in SQL. Hydration does not rebuild
        // an independent execution queue or reset retry cost.
        self.drop_settled_epoch_backfill_intents();
    }

    /// Write the detector's frozen-epoch evidence for `groups` to durable
    /// storage.
    ///
    /// Best-effort like the durable arm marker beside it: losing a row costs
    /// the affected group one more paced attempt after a restart, which is the
    /// same cost the pre-persistence behavior paid every time. Failing the
    /// replay over it would trade a delayed report for a lost one.
    pub(crate) fn persist_epoch_stall_evidence<'groups>(
        &mut self,
        groups: impl IntoIterator<Item = &'groups cgka_traits::GroupId>,
    ) {
        let evidence = groups
            .into_iter()
            .filter_map(|group_id| {
                let evidence = self.epoch_stall.wedge_evidence(group_id)?;
                Some(storage_sqlite::StoredEpochStallEvidence {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    stalled_epoch: evidence.stalled_epoch,
                    fruitless_completions: evidence.fruitless_completions,
                    fruitless_reported: evidence.fruitless_reported,
                    last_arm_at_ms: evidence.last_arm_at_ms,
                })
            })
            .collect::<Vec<_>>();
        match self.app.record_epoch_stall_evidence(
            &self.state.label,
            &evidence,
            self.epoch_stall.fruitless_completion_threshold(),
        ) {
            Ok(changed) => {
                for group_id in changed {
                    self.mark_recovery_status_changed(&group_id);
                }
            }
            Err(error) => {
                tracing::warn!(target: "marmot_app::epoch_stall", method = "persist_epoch_stall_evidence",
                    error_kind = error.privacy_safe_kind(),
                    "recovery evidence and warning remain pending persistence");
            }
        }
    }

    /// Reconcile branch-selection tombstones against the engine's own commit
    /// dispositions, once per account open.
    ///
    /// Same shape, and the same reason, as
    /// [`Self::sweep_terminal_groups_from_guards`]: the engine announces a
    /// branch-selection withdrawal exactly once (on the transition into
    /// `ConvergenceDeferred`) and takes it back exactly once (on re-adoption),
    /// but those announcements travel in the engine's in-memory `events_buf`.
    /// A process death between the convergence apply transaction — which is
    /// where the disposition becomes durable — and this app's projection commit
    /// loses the announcement, and announce-once means no later pass re-derives
    /// it. Before announce-once every later pass re-announced and the
    /// already-invalidated filter turned the repeat into a no-op, which made the
    /// old seam accidentally self-healing; this is the deliberate replacement.
    ///
    /// It can be a total reconciliation rather than a durable queue because both
    /// sides live in the same account database, so the correct tombstone state
    /// is *derivable*, never information the app can lose: a commit parked
    /// `ConvergenceDeferred` owes its rows a withdrawal, and a commit back at
    /// `Processed` owes them a revival. `diverged_branch_selection_withdrawals`
    /// reports only the commits where the two disagree, so a converged account
    /// performs no writes at all.
    ///
    /// Reads no live group state, only durable rows, so — like the terminal
    /// sweep — it runs on deferred opens too. Best-effort per commit: one
    /// failure must not fail account open, and the next open retries it.
    pub(crate) fn reconcile_branch_selection_withdrawals(&mut self) {
        let divergence = match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.diverged_branch_selection_withdrawals()?))
        {
            Ok(divergence) => divergence,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::branch_selection_sweep",
                    method = "reconcile_branch_selection_withdrawals",
                    error_kind = error.privacy_safe_kind(),
                    "could not enumerate branch-selection divergences; skipping the open-time sweep"
                );
                return;
            }
        };
        if divergence.is_empty() {
            return;
        }
        let mut withdrawn = 0_u64;
        let mut revived = 0_u64;
        let mut failed = 0_u64;
        let mut first_error_kind: Option<&'static str> = None;
        for origin_commit_id in &divergence.to_withdraw {
            match self.app.invalidate_timeline_origin_commit(
                &self.state.label,
                origin_commit_id,
                storage_sqlite::BRANCH_SELECTION_WITHDRAWAL_REASON,
            ) {
                Ok(Some(update)) => {
                    withdrawn = withdrawn.saturating_add(1);
                    self.pending_projection_updates.push(update);
                }
                Ok(None) => {}
                Err(error) => {
                    failed = failed.saturating_add(1);
                    first_error_kind.get_or_insert(error.privacy_safe_kind());
                }
            }
        }
        for origin_commit_id in &divergence.to_revive {
            match self
                .app
                .revalidate_timeline_origin_commit(&self.state.label, origin_commit_id)
            {
                Ok(Some(update)) => {
                    revived = revived.saturating_add(1);
                    self.pending_projection_updates.push(update);
                }
                Ok(None) => {}
                Err(error) => {
                    failed = failed.saturating_add(1);
                    first_error_kind.get_or_insert(error.privacy_safe_kind());
                }
            }
        }
        tracing::debug!(
            target: "marmot_app::branch_selection_sweep",
            method = "reconcile_branch_selection_withdrawals",
            withdrawn,
            revived,
            failed,
            "reconciled branch-selection withdrawals against stored commit dispositions"
        );
        // A partial sweep leaves real divergence standing — a live row for a
        // parked commit, or a tombstone over a re-adopted one — and nothing
        // else notices until the next account open re-derives it. Say so above
        // debug, with the first kind observed so the failure has a shape.
        if failed > 0 {
            tracing::warn!(
                target: "marmot_app::branch_selection_sweep",
                method = "reconcile_branch_selection_withdrawals",
                withdrawn,
                revived,
                failed,
                error_kind = first_error_kind.unwrap_or("unknown"),
                "some branch-selection divergences stayed unreconciled; the next account open retries them"
            );
        }
    }

    /// Reconcile every terminal group's durable projection from the guard rows
    /// themselves, once per account open.
    ///
    /// This used to ride the `GroupDisbanded` event arm alone, which worked only
    /// because hydration re-emitted that event on *every* open: the replay was
    /// the reconciler. Now that a guard announces itself once
    /// (`Engine::restore_disband_tombstone`), an event-only sweep would run
    /// exactly once ever — and a process death in the window between the engine
    /// marking the guard at account open and the app committing its projection
    /// would strand the group's held sends at "Sending…" permanently.
    ///
    /// So the sweep reads its input from the immortal guard rows instead of
    /// from an event that fires once. Both writes are idempotent, group-keyed,
    /// and no-ops when clean —
    /// `invalidate_pending_sent_app_events_for_group` returns `None` without
    /// writing when no unresolved send remains, and the token removal is a
    /// `DELETE` of rows that may already be gone — so a steady-state open costs
    /// one indexed read per terminal group and produces no projection churn.
    ///
    /// Best-effort per guard: one unreadable group must not fail account open,
    /// and the next open retries it.
    pub(crate) fn sweep_terminal_groups_from_guards(&mut self) {
        use cgka_traits::storage::DisbandTombstoneStorage;

        let guards = match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.list_disband_tombstones()?))
        {
            Ok(guards) => guards,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::terminal_sweep",
                    method = "sweep_terminal_groups_from_guards",
                    error_kind = error.privacy_safe_kind(),
                    "could not enumerate terminal guards; skipping the open-time sweep"
                );
                return;
            }
        };
        let guard_count = guards.len();
        let mut reconciled = 0_u64;
        let mut failed = 0_u64;
        let mut first_error_kind: Option<&'static str> = None;
        for (group_id, _) in guards {
            let group_id_hex = hex::encode(group_id.as_slice());
            match self
                .app
                .invalidate_timeline_pending_sends_for_group(&self.state.label, &group_id_hex)
            {
                Ok(Some(update)) => {
                    reconciled = reconciled.saturating_add(1);
                    self.pending_projection_updates.push(update);
                }
                Ok(None) => {}
                Err(error) => {
                    failed = failed.saturating_add(1);
                    first_error_kind.get_or_insert(error.privacy_safe_kind());
                }
            }
            // A terminal group never advertises notification destinations
            // again, so every cached peer token is stale by definition.
            if let Err(error) =
                self.app
                    .remove_stale_group_push_tokens(&self.state.label, &group_id_hex, &[])
            {
                failed = failed.saturating_add(1);
                first_error_kind.get_or_insert(error.privacy_safe_kind());
            }
        }
        if reconciled > 0 || failed > 0 {
            tracing::debug!(
                target: "marmot_app::terminal_sweep",
                method = "sweep_terminal_groups_from_guards",
                terminal_groups = guard_count,
                reconciled,
                failed,
                "reconciled terminal group projections from durable guards"
            );
        }
        // Same reasoning as the branch-selection sweep: a guard this open could
        // not reconcile leaves a terminal group's held sends stuck at
        // "Sending…", and only the next open retries it.
        if failed > 0 {
            tracing::warn!(
                target: "marmot_app::terminal_sweep",
                method = "sweep_terminal_groups_from_guards",
                terminal_groups = guard_count,
                reconciled,
                failed,
                error_kind = first_error_kind.unwrap_or("unknown"),
                "some terminal group projections stayed unreconciled; the next account open retries them"
            );
        }
    }

    /// Rebuild the frozen-epoch evidence a previous process gathered.
    pub(crate) fn restore_persisted_epoch_stall_evidence(
        &mut self,
        evidence: Vec<storage_sqlite::StoredEpochStallEvidence>,
    ) {
        let mut malformed = 0_u64;
        let restored = evidence
            .into_iter()
            .filter_map(|entry| {
                let Ok(group_id) = hex::decode(&entry.group_id_hex) else {
                    malformed = malformed.saturating_add(1);
                    return None;
                };
                Some((
                    cgka_traits::GroupId::new(group_id),
                    super::epoch_stall::EpochStallEvidence {
                        stalled_epoch: entry.stalled_epoch,
                        fruitless_completions: entry.fruitless_completions,
                        fruitless_reported: entry.fruitless_reported,
                        last_arm_at_ms: entry.last_arm_at_ms,
                    },
                ))
            })
            .collect::<Vec<_>>();
        if malformed > 0 {
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "restore_persisted_epoch_stall_evidence",
                malformed,
                "ignored malformed durable frozen-epoch recovery evidence"
            );
        }
        self.epoch_stall.restore_wedge_evidence(restored);
    }

    #[cfg(test)]
    fn persist_epoch_backfill_intent(
        &self,
        pending: &[storage_sqlite::StoredEpochBackfillIntent],
    ) -> Result<(), AppError> {
        self.app
            .arm_epoch_backfill_intents(&self.state.label, pending)
    }

    /// End the failed recovery run for a group this device is terminal in:
    /// retire its durable recovery-health rows, drop the in-memory run, and
    /// mark the group's recovery status dirty when the durable clear changed
    /// something.
    ///
    /// The same pair an authenticated rejoin runs, in the same order: durable
    /// first, so a failed clear leaves nothing changed for the next pass to
    /// retry rather than a run memory forgot and storage still remembers.
    ///
    /// Dropping the intent alone leaves the run behind to accumulate
    /// fruitless-completion evidence, and nothing else retires that evidence
    /// row while the group row is kept.
    ///
    /// Returns whether the durable rows are gone. Best-effort either way — the
    /// warn is in here so both callers share it — but a caller holding
    /// something that would strand the evidence row on failure has to be able
    /// to see it, which is what
    /// [`Self::drop_settled_epoch_backfill_intents`] does with the intent row.
    fn retire_terminal_group_recovery(&mut self, group_id: &cgka_traits::GroupId) -> bool {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_terminal_recovery_retire) {
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "retire_terminal_group_recovery",
                error_kind = "injected_terminal_retire_failure",
                "terminal recovery run kept its durable rows and will be retired on a later pass"
            );
            return false;
        }
        match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.retire_terminal_group_recovery(group_id)?))
        {
            Ok(changed) => {
                self.epoch_stall.clear_recovered_group(group_id);
                if changed {
                    self.mark_recovery_status_changed(group_id);
                }
                true
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::epoch_stall",
                    method = "retire_terminal_group_recovery",
                    error_kind = error.privacy_safe_kind(),
                    "terminal recovery run kept its durable rows and will be retired on a later pass"
                );
                false
            }
        }
    }

    /// Drop every armed epoch-gap intent for a group this device is terminal in
    /// (removed, or the group disbanded), clear its durable marker, and retire
    /// its recovery run.
    ///
    /// Such an intent is unservable. `refresh_group_routes` / `refresh_routing`
    /// have already pruned the group's routes, and the replay is account-wide
    /// rather than intent-scoped, so no replay can ever fetch that group's
    /// history. Keeping the intent only spends the one account-wide replay
    /// budget and gathers wedge evidence about a group we left. The host's
    /// recovery warning is already terminality-gated
    /// (`GroupRecoveryStatus::automatic_recovery_failed`); what leaked was the
    /// `EpochStallEscalated` event, its forensic escalation row, and a durable
    /// evidence row nothing else retires while the group row is kept.
    ///
    /// [`super::group_is_terminal`] reads the engine record, so a deferred open
    /// answers `false` for everything before hydration. That makes the
    /// restore-time call an early-out only; the guarantee is the call at the top
    /// of [`Self::run_pending_epoch_backfill`], which runs after hydration.
    ///
    /// Terminal retirement applies to every epoch of the group. Ordinary
    /// completion instead uses the owner's exact obligation revision and scope
    /// tokens, so stale attempts cannot retire newer demand.
    ///
    /// An epoch gap also completes on its own evidence: once the group's local
    /// epoch moves past the stalled one, that exact gap no longer applies. A
    /// later stall arms a new gap at its own epoch.
    fn drop_settled_epoch_backfill_intents(&mut self) {
        let intents = match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.pending_epoch_backfill_intents()?))
        {
            Ok(intents) => intents,
            Err(error) => {
                tracing::warn!(target: "marmot_app::epoch_stall", method = "drop_settled_epoch_backfill_intents",
                    error_kind=error.privacy_safe_kind(), "could not inspect settled recovery demand");
                return;
            }
        };
        let resolved = intents
            .iter()
            .filter(|intent| {
                hex::decode(&intent.group_id_hex)
                    .ok()
                    .and_then(|group| self.local_epoch_for_group(&cgka_traits::GroupId::new(group)))
                    .is_some_and(|epoch| epoch > intent.stalled_epoch)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !resolved.is_empty()
            && let Err(error) = self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| Ok(storage.clear_epoch_backfill_intents(&resolved)?))
        {
            tracing::warn!(target: "marmot_app::epoch_stall", method = "drop_settled_epoch_backfill_intents",
                error_kind=error.privacy_safe_kind(), "could not retire resolved epoch-gap demand");
        }
        let mut terminal = self
            .pending_recovery_arm_writes
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        terminal.extend(self.pending_recovery_capacity_writes.keys().cloned());
        terminal.extend(intents.into_iter().filter_map(|intent| {
            hex::decode(intent.group_id_hex)
                .ok()
                .map(cgka_traits::GroupId::new)
        }));
        terminal.retain(|group| super::group_is_terminal(&self.runtime, group));
        for group in terminal {
            if self.retire_terminal_group_recovery(&group) {
                self.pending_recovery_arm_writes.remove(&group);
                self.pending_recovery_capacity_writes.remove(&group);
            }
        }
    }

    /// Move every recorded escalation onto the summary a seam is about to
    /// return.
    ///
    /// Call this as the LAST step before `Ok(summary)`, at every outermost seam
    /// — the ones whose `Ok` is handed to a caller rather than followed by more
    /// fallible work. Partial-progress sync also calls it on `Err`, moving the
    /// one-shot decision into `SyncFailure::partial_summary` before a managed
    /// worker can discard and rebuild the client. The compatibility `sync()`
    /// path leaves it stashed on failure because its `AppError` contract has no
    /// partial-summary channel. Moving (not copying) keeps delivery exactly
    /// once across either path.
    ///
    /// One nested case needs care: [`Self::drain_pending_session_events`] drains
    /// while nested inside `sync_inner`, so its escalations leave the stash and
    /// ride `summary` from the merge onwards. Nothing fallible may be inserted
    /// between that merge and `sync_inner`'s `Ok` — past the merge they sit on a
    /// local summary again, and a `?` would take them down with the pass. (Which
    /// also makes `sync_inner`'s own call belt-and-braces rather than
    /// load-bearing: the nested drain has already emptied the stash.)
    ///
    /// A run is still forgotten when a caller discards the client outright; the
    /// [`super::epoch_stall`] module header covers that case and what
    /// re-escalating then costs.
    pub(crate) fn drain_epoch_stall_escalations(&mut self, summary: &mut SyncSummary) {
        summary
            .epoch_stall_escalations
            .append(&mut self.pending_epoch_stall_escalations);
    }

    /// Whether an epoch-gap backfill is armed and awaiting its replay. Read by
    /// the account worker to schedule a forensic audit-tracker upload for the
    /// just-recorded `epoch_stall_backfill_armed` row without poking the field.
    pub(crate) fn has_pending_epoch_backfill(&self) -> bool {
        !self.pending_recovery_arm_writes.is_empty()
            || !self.pending_recovery_capacity_writes.is_empty()
            || self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| Ok(!storage.pending_epoch_backfill_intents()?.is_empty()))
                .unwrap_or(true)
    }

    /// Current group-scoped debt, including obligations held by a live grant.
    /// This inspection does not authorize acquisition or infer completion.
    fn armed_epoch_backfill_groups(&self) -> HashSet<cgka_traits::GroupId> {
        self.app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.pending_epoch_backfill_intents()?))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|intent| {
                hex::decode(intent.group_id_hex)
                    .ok()
                    .map(cgka_traits::GroupId::new)
            })
            .collect()
    }

    /// Read a group's current local epoch, or `None` when it cannot be read.
    ///
    /// `None` is deliberately not a claim about the group: it covers a group
    /// that is gone as well as a storage backend that was busy or closed.
    /// Callers must treat it as "unobserved", never as "unchanged". The read
    /// error itself has no audit field to land in, so name its privacy-safe
    /// kind here — that is the difference between chasing a deleted group and
    /// chasing lock contention.
    pub(crate) fn local_epoch_for_group(&self, group_id: &cgka_traits::GroupId) -> Option<u64> {
        match self.runtime.group_record(group_id) {
            Ok(record) => Some(record.epoch.0),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::epoch_stall",
                    method = "local_epoch_for_group",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "local group epoch could not be read; treating it as unobserved"
                );
                None
            }
        }
    }

    /// Select and run one recovery job in place, waiting for a process
    /// credit: the recovery seam of a directly owned client, which has no
    /// worker to run the job for it.
    pub(crate) async fn run_pending_epoch_backfill(
        &mut self,
        seam: EpochBackfillExecutionSeam,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        if !self.recovery_pending()? {
            return Ok(EpochBackfillRunOutcome::NotPending);
        }
        let credit = crate::runtime::account_worker::recovery_credits::acquire_recovery_credit(
            &self.recovery_credits,
        )
        .await;
        match self.select_pending_epoch_backfill(seam)? {
            PendingRecoverySelection::NotPending => Ok(EpochBackfillRunOutcome::NotPending),
            PendingRecoverySelection::Deferred => Ok(EpochBackfillRunOutcome::Deferred),
            PendingRecoverySelection::Grant(grant) => {
                self.run_recovery_job(*grant, credit, None).await
            }
        }
    }

    /// Select one grant for the recovery job. Every caller runs the exact
    /// frozen grant it selected; nothing spends a second reservation.
    pub(crate) fn select_pending_epoch_backfill(
        &mut self,
        seam: EpochBackfillExecutionSeam,
    ) -> Result<PendingRecoverySelection, AppError> {
        self.drop_settled_epoch_backfill_intents();
        if !self.recovery_pending()? {
            return Ok(PendingRecoverySelection::NotPending);
        }
        let mut explicit = ExplicitRecoveryPermit::default();
        let permit = (seam == EpochBackfillExecutionSeam::ExplicitCatchUp).then_some(&mut explicit);
        let Some(grant) = self.authorize_account_recovery(permit, seam)? else {
            return Ok(PendingRecoverySelection::Deferred);
        };
        #[cfg(test)]
        if let Some(witness) = &self.test_recovery_selection_witness {
            witness.lock().unwrap().push(super::TestRecoverySelection {
                seam,
                attempt_serial: grant.reservation.attempt_serial,
                comparison_revision: grant.comparison_revision,
                obligation_count: grant.fence.obligations.len(),
            });
        }
        Ok(PendingRecoverySelection::Grant(Box::new(grant)))
    }

    // Shares the classified failure payload with the job's terminal path.
    #[allow(clippy::result_large_err)]
    fn begin_recovery_execution(
        &mut self,
        grant: &AttemptGrant,
    ) -> Result<RecoveryExecutionState, ClassifiedSyncFailure> {
        let Some(plan) = grant.plan() else {
            return Err(ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                cgka_traits::storage::StorageError::Serialization(
                    "recovery grant has no frozen plan".into(),
                )
                .into(),
                SyncFailureStage::StatePersist,
            ));
        };
        let overflow = self
            .delivery_overflow_recovery_marker_token
            .filter(|_| self.delivery_overflow_recovery_pending)
            .map(|token| self.adapter.start_delivery_overflow_recovery(token));
        let overflow_guard =
            overflow.map(|_| super::recovery::RecoveryLossAttemptGuard::new(self.adapter.clone()));
        let audit_groups = plan
            .iter()
            .filter(|obligation| obligation.cause == storage_sqlite::RecoveryCause::EpochGap)
            .filter_map(|obligation| {
                obligation.group_id.as_ref().and_then(|group| {
                    self.local_epoch_for_group(group)
                        .map(|epoch| (obligation.id, group.clone(), epoch))
                })
            })
            .collect::<Vec<_>>();
        let context = AuditEventContext {
            operation_id: Some(format!("recovery-{}", grant.reservation.attempt_serial)),
            ..AuditEventContext::default()
        };
        let started = Instant::now();
        if !audit_groups.is_empty() {
            self.record_epoch_stall_backfill_started(
                grant.seam,
                grant.reservation.ordinal.saturating_sub(1),
                &context,
            );
        }
        Ok(RecoveryExecutionState {
            overflow,
            overflow_guard,
            audit_groups,
            context,
            started,
            counts: DrainCounts::default(),
            activation: EpochBackfillActivationOutcome::Failed,
        })
    }

    // Preserve the job's classified partial summary and audit terminal.
    #[allow(clippy::result_large_err)]
    fn finish_recovery_execution(
        &mut self,
        grant: &AttemptGrant,
        mut execution: RecoveryExecutionState,
        result: Result<SyncSummary, ClassifiedSyncFailure>,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        if result.is_err() {
            self.abandon_loss_completion().map_err(|error| {
                ClassifiedSyncFailure::at_stage(
                    result
                        .as_ref()
                        .err()
                        .map(|failure| failure.partial_summary.clone())
                        .unwrap_or_default(),
                    error,
                    SyncFailureStage::StatePersist,
                )
            })?;
        }
        for (id, group, before) in execution.audit_groups {
            let after = self.local_epoch_for_group(&group);
            let revision = grant
                .fence
                .obligations
                .iter()
                .find(|(selected, _)| *selected == id)
                .map(|(_, revision)| *revision)
                .unwrap_or(0);
            let qualified = self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| Ok(storage.recovery_obligation_is_satisfied(id, revision)?))
                .unwrap_or(false);
            self.record_epoch_stall_backfill_terminal(
                &group,
                qualified && after.is_some(),
                EpochBackfillTerminalAudit {
                    retry_ordinal: grant.reservation.ordinal.saturating_sub(1),
                    duration_ms: execution.started.elapsed().as_millis() as u64,
                    activation_outcome: execution.activation,
                    completion_kind: None,
                    error_kind: (!qualified).then(|| {
                        result
                            .as_ref()
                            .err()
                            .map(|failure| failure.source.privacy_safe_kind().to_owned())
                            .unwrap_or_else(|| "history_coverage_unproven".into())
                    }),
                    deliveries: execution.counts.deliveries,
                    skipped: execution.counts.skipped,
                    refused: execution.counts.refused,
                    local_epoch_before: before,
                    local_epoch_after: after,
                },
                &execution.context,
            );
        }
        // Qualification/plane acknowledgment is separate from ending the
        // transient acquisition. No EOSE-only outcome may clear the loss guard.
        if let Some(attempt) = execution.overflow {
            let finished = if result.is_ok() {
                self.finish_qualified_recovery_loss(grant, attempt)
                    .map_err(|error| {
                        ClassifiedSyncFailure::at_stage(
                            result.as_ref().ok().cloned().unwrap_or_default(),
                            error,
                            SyncFailureStage::StatePersist,
                        )
                    })?
            } else {
                false
            };
            if !finished {
                self.adapter.fail_delivery_overflow_recovery();
            } else if !self.delivery_loss_blocks_cursor() {
                // Every drained prefix was persisted while the loss fence held
                // the old cursor. Promote the admitted candidate only after the
                // exact live acknowledgment and durable evidence reclamation.
                let sealed = self.seal_transport_cursor();
                if let Err(error) =
                    self.save_state_with_pending_local_group_deletion_frontier_clears()
                {
                    self.abandon_transport_cursor(sealed);
                    return Err(ClassifiedSyncFailure::at_stage(
                        result.as_ref().ok().cloned().unwrap_or_default(),
                        error,
                        SyncFailureStage::StatePersist,
                    ));
                }
                self.settle_transport_cursor(sealed);
            }
        }
        if let Some(guard) = execution.overflow_guard.as_mut() {
            guard.disarm();
        }
        result
    }

    /// Settle a finished comparison: the comparison slot's route outcomes,
    /// then every selected obligation's checkpoint, with the existing revision
    /// fences. Old attempts still cannot clear newer demand.
    async fn settle_recovery_grant(
        &mut self,
        grant: &AttemptGrant,
        counts: &mut DrainCounts,
        comparison_outcomes: Vec<RouteComparison>,
        mut summary: SyncSummary,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let local = self.drain_pending_session_events().await.map_err(|error| {
            ClassifiedSyncFailure::at_stage(summary.clone(), error, SyncFailureStage::Unknown)
        })?;
        summary.merge(local);
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| {
                ClassifiedSyncFailure::at_stage(
                    summary.clone(),
                    error,
                    SyncFailureStage::StatePersist,
                )
            })?;
        let checkpoint = (|| -> Result<(), AppError> {
            storage.synchronize_account_delivery_loss(&self.state.label)?;
            drop(self.transport_receipts()?);
            self.observe_recovery_route_policy()?;
            // An uncertified endpoint's outcome stays Unknown, distinct from
            // Unsupported; eligibility also depends on the cause.
            let outcome = storage_sqlite::RecoveryScopeOutcome::Unknown;
            if let (Some(revision), Some(plan)) =
                (grant.comparison_revision, &grant.comparison_plan)
            {
                use storage_sqlite::RecoveryComparisonOutcome as Comparison;
                let outcomes = plan
                    .routes
                    .iter()
                    .map(|scope| {
                        let route = if scope.route_kind == 0 {
                            TransportReconciliationRoute::Inbox
                        } else {
                            TransportReconciliationRoute::Group(
                                scope.transport_group_id.expect("frozen comparison route"),
                            )
                        };
                        // The slot retries only a route whose required relays did
                        // not answer. An answered route that could not certify, or
                        // whose admission was incomplete or refused, is serviced:
                        // its obligation's own quiet streak retries it until the
                        // obligation parks, and parking ends automatic passes.
                        let observed = comparison_outcomes
                            .iter()
                            .find(|compared| compared.route == route)
                            .map_or(Comparison::ServicedPartial, |compared| {
                                if compared.answered
                                    && compared.outcome == Comparison::TransientFailure
                                {
                                    Comparison::ServicedUnknown
                                } else {
                                    compared.outcome
                                }
                            });
                        (scope.scope_id, observed)
                    })
                    .collect::<Vec<_>>();
                let unsupported = (!outcomes.is_empty()
                    && outcomes.iter().all(|(_, o)| *o == Comparison::Unsupported))
                .then_some(self.adapter.recovery_comparison_capability_key());
                storage.settle_recovery_comparison(
                    revision,
                    grant.reservation.attempt_serial,
                    &outcomes,
                    unsupported,
                )?;
            }
            let mut progressed_any = false;
            let mut explicit_scopes = 0_usize;
            let mut explicit_window_certified = true;
            for obligation in grant.plan().expect("validated executor grant") {
                // A selected group can lack any executable route even though
                // another obligation made the account ready. Preserve that
                // debt until capability/policy changes instead of probing it
                // forever on unrelated account readiness.
                let unroutable = obligation
                    .scopes
                    .iter()
                    .all(|scope| scope.goal.admitted_endpoints.is_empty());
                // Cold-start history has no evidence but comparison. When no
                // compared route had a comparison backend, wait for a
                // capability change instead of spending passes on it.
                let mut compared = obligation.scopes.iter().filter_map(|scope| {
                    let route = match (scope.goal.route_kind, scope.goal.transport_group_id) {
                        (0, _) => TransportReconciliationRoute::Inbox,
                        (1, Some(id)) => TransportReconciliationRoute::Group(id),
                        _ => return None,
                    };
                    comparison_outcomes.iter().find(|c| c.route == route)
                });
                let unsupported = obligation.cause
                    == storage_sqlite::RecoveryCause::IncrementalHistory
                    && compared.clone().next().is_some()
                    && compared.all(|c| {
                        c.outcome == storage_sqlite::RecoveryComparisonOutcome::Unsupported
                    });
                let outcome = if unsupported {
                    storage_sqlite::RecoveryScopeOutcome::Unsupported
                } else if !unroutable {
                    outcome
                } else if obligation
                    .scopes
                    .iter()
                    .all(|scope| scope.goal.route_kind == 2)
                {
                    storage_sqlite::RecoveryScopeOutcome::Unsupported
                } else {
                    storage_sqlite::RecoveryScopeOutcome::Excluded
                };
                let refused = obligation
                    .group_id
                    .as_ref()
                    .map_or(counts.refused > 0, |group| {
                        counts.refused_groups.contains(group)
                    });
                // A maintenance boundary is its own REQ's end of stored events,
                // and known-event demand completes once its exact event is
                // retained. Every other cause, explicit repair included,
                // completes on comparison certificates over the
                // retained-inventory window.
                let comparison_owned = !matches!(
                    obligation.cause,
                    storage_sqlite::RecoveryCause::Maintenance
                        | storage_sqlite::RecoveryCause::KnownEvent
                );
                let mut certified = false;
                let mut fetched = false;
                let mut checkpoints = Vec::with_capacity(obligation.scopes.len());
                // Each compared scope's own pass: quiet only when its required
                // relays answered and it neither certified nor admitted anything.
                let mut progress = Vec::with_capacity(obligation.scopes.len());
                for scope in &obligation.scopes {
                    let route = match (scope.goal.route_kind, scope.goal.transport_group_id) {
                        (0, _) => Some(TransportReconciliationRoute::Inbox),
                        (1, Some(id)) => Some(TransportReconciliationRoute::Group(id)),
                        _ => None,
                    };
                    let compared = route
                        .as_ref()
                        .and_then(|route| comparison_outcomes.iter().find(|c| &c.route == route));
                    fetched |= compared.is_some_and(|compared| compared.fetched > 0);
                    // Every explicit scope counts, compared or not: one this
                    // pass skipped, such as a route with no admitted relay,
                    // keeps the request open.
                    if obligation.cause == storage_sqlite::RecoveryCause::ExplicitHistory {
                        explicit_scopes += 1;
                        explicit_window_certified &= !refused
                            && compared.is_some_and(|compared| compared.certified)
                            && route.as_ref().is_some_and(|route| {
                                grant.inventory.iter().any(|window| {
                                    &window.route == route
                                        && scope.goal.until_seconds <= window.until
                                })
                            });
                    }
                    // A scope this pass did not compare, or already certified
                    // for this goal, keeps the certificates it has.
                    if comparison_owned
                        && !unroutable
                        && scope.goal.known_event_id.is_none()
                        && (compared.is_none()
                            || grant
                                .certified_scopes
                                .contains(&(obligation.id, scope.goal.scope_id)))
                    {
                        continue;
                    }
                    // A comparison proves only the window it compared. A goal
                    // that reaches below the retained-inventory floor, or has
                    // no lower bound, keeps its debt. Cold-start and
                    // incremental history is that window: its floor, raised by
                    // retention or compaction, is the goal's lower bound.
                    // Explicit history has no lower bound, so it never
                    // certifies; a certified window only names what is left.
                    let window_bounded =
                        obligation.cause == storage_sqlite::RecoveryCause::IncrementalHistory;
                    let covers_goal = route.as_ref().is_some_and(|route| {
                        grant.inventory.iter().any(|window| {
                            &window.route == route
                                && (window_bounded
                                    || scope
                                        .goal
                                        .since_seconds
                                        .is_some_and(|since| since >= window.since))
                                && scope.goal.until_seconds <= window.until
                        })
                    });
                    let scope_certified = comparison_owned
                        && !refused
                        && covers_goal
                        && compared.is_some_and(|compared| compared.certified);
                    certified |= scope_certified;
                    progress.push((
                        scope.goal.scope_id,
                        if scope_certified || compared.is_some_and(|compared| compared.fetched > 0)
                        {
                            storage_sqlite::RecoveryPassProgress::Progressed
                        } else if !refused && compared.is_some_and(|compared| compared.answered) {
                            storage_sqlite::RecoveryPassProgress::Quiet
                        } else {
                            storage_sqlite::RecoveryPassProgress::Unserved
                        },
                    ));
                    let retained_known_event = match (&route, scope.goal.known_event_id) {
                        (Some(route), Some(event)) => storage.retained_recovery_event(
                            route,
                            &event,
                            scope.goal.since_seconds,
                            scope.goal.until_seconds,
                        )?,
                        _ => false,
                    };
                    let endpoints = scope
                        .goal
                        .required_endpoints
                        .iter()
                        .map(|endpoint| {
                            let admitted = scope.goal.admitted_endpoints.contains(endpoint);
                            storage_sqlite::RecoveryEndpointCheckpoint {
                                endpoint: endpoint.clone(),
                                outcome: match (admitted, scope_certified) {
                                    (false, _) => storage_sqlite::RecoveryScopeOutcome::Excluded,
                                    (true, true) => storage_sqlite::RecoveryScopeOutcome::Covered,
                                    (true, false) => outcome,
                                },
                                exhaustive: admitted && scope_certified,
                                admission_complete: admitted && scope_certified,
                                first_boundary: false,
                            }
                        })
                        .collect();
                    // Synthetic tests supply independent finite-inventory
                    // certificates; a refused admission cannot be promoted by
                    // this fixture.
                    #[cfg(test)]
                    let endpoints = if counts.refused == 0 {
                        self.test_recovery_evidence
                            .map_or(endpoints, |evidence| evidence(&scope.goal))
                    } else {
                        endpoints
                    };
                    checkpoints.push(storage_sqlite::RecoveryScopeCheckpoint {
                        token: scope.token.clone(),
                        retained_known_event,
                        endpoints,
                    });
                }
                progressed_any |= certified || fetched;
                let eligibility = super::recovery::eligibility_after_comparison(outcome, refused);
                if comparison_owned {
                    storage.checkpoint_recovery_comparison(
                        &grant.fence,
                        grant.reservation.attempt_serial,
                        obligation.id,
                        &checkpoints,
                        eligibility,
                        &progress,
                    )?;
                } else {
                    storage.checkpoint_recovery_obligation(
                        &grant.fence,
                        grant.reservation.attempt_serial,
                        obligation.id,
                        &checkpoints,
                        eligibility,
                    )?;
                }
            }
            self.explicit_history_window_certified =
                explicit_scopes > 0 && explicit_window_certified;
            if progressed_any {
                // New coverage or newly fetched history is progress: the next
                // pass runs at the base delay and the parking streak restarts.
                self.recovery_owner
                    .observe_certified_progress(&storage, grant)?;
            }
            Ok(())
        })();
        checkpoint.map_err(|error| {
            ClassifiedSyncFailure::at_stage(summary.clone(), error, SyncFailureStage::StatePersist)
        })?;
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
    }

    /// Explicit account-wide repair for a host that has independent evidence
    /// its incremental cursor may be incomplete (for example, a long-offline
    /// participant that has no new traffic capable of arming epoch-stall
    /// detection). Unlike the automatic detector path, this is a caller-owned
    /// operation and therefore does not mutate the detector's debounce state.
    #[cfg(test)]
    pub(crate) async fn repair_full_history(
        &mut self,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        self.repair_full_history_cancellable(&|| false).await
    }

    pub(crate) async fn repair_full_history_cancellable(
        &mut self,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        self.repair_full_history_with_control(&FullHistoryRepairControl {
            started: Instant::now(),
            timeout: FULL_HISTORY_REPAIR_TIMEOUT,
            cancelled,
        })
        .await
    }

    /// Run the one recovery job for an explicit caller: every route of the
    /// grant is compared in one pass inside the repair budget, the job is
    /// awaited here, and the repair succeeds only when its explicit history
    /// obligation is certified. It never activates or replays subscriptions.
    async fn repair_full_history_with_control(
        &mut self,
        control: &FullHistoryRepairControl<'_>,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let state_persist = |summary: SyncSummary, error: AppError| {
            ClassifiedSyncFailure::at_stage(summary, error, SyncFailureStage::StatePersist)
        };
        if let Some(reason) = control.stopped() {
            return Err(incomplete_full_history_repair(
                SyncSummary::default(),
                reason,
                self.delivery_loss_blocks_cursor(),
            ));
        }
        if self
            .refresh_sync_routes()
            .map_err(|error| state_persist(SyncSummary::default(), error))?
        {
            // The live subscriptions follow the route change later; recovery
            // compares the refreshed routes without touching them.
            self.pending_runtime_group_subscription_refresh = true;
        }
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| state_persist(SyncSummary::default(), error))?;
        let operation = rand::random::<[u8; 16]>();
        let ticket = storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::ExplicitHistory {
                    operation_id: &operation,
                },
                unix_now_seconds().saturating_mul(1000),
            )
            .map_err(|error| state_persist(SyncSummary::default(), error.into()))?;
        let mut waiter = super::recovery::RecoveryCallerGuard::new(storage.clone(), ticket);
        // An explicit caller waits for its process credit, but never past its
        // own cancellation or budget.
        let credit = {
            use crate::runtime::account_worker::recovery_credits;
            let pool = self.recovery_credits.clone();
            let acquire = recovery_credits::acquire_recovery_credit(&pool);
            tokio::pin!(acquire);
            loop {
                if let Some(reason) = control.stopped() {
                    waiter
                        .detach()
                        .map_err(|error| state_persist(SyncSummary::default(), error.into()))?;
                    return Err(incomplete_full_history_repair(
                        SyncSummary::default(),
                        reason,
                        self.delivery_loss_blocks_cursor(),
                    ));
                }
                tokio::select! {
                    credit = &mut acquire => break credit,
                    () = tokio::time::sleep(RECOVERY_JOB_CANCEL_POLL) => {}
                }
            }
        };
        let mut caller = ExplicitRecoveryPermit::full_history();
        let grant = self
            .authorize_account_recovery(
                Some(&mut caller),
                EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .map_err(|error| state_persist(SyncSummary::default(), error))?;
        self.explicit_history_window_certified = false;
        self.recovery_job_hit_deadline = false;
        let result = match grant {
            Some(grant) => self.run_recovery_job(grant, credit, Some(control)).await,
            None => Ok(EpochBackfillRunOutcome::Deferred),
        };
        let summary = match &result {
            Ok(
                EpochBackfillRunOutcome::Completed(summary)
                | EpochBackfillRunOutcome::Incomplete(summary),
            ) => summary.clone(),
            _ => SyncSummary::default(),
        };
        let qualified = storage
            .recovery_obligation_is_satisfied(ticket.id, ticket.revision)
            .map_err(|error| state_persist(summary.clone(), error.into()))?;
        let reason = control.verdict(self.recovery_job_hit_deadline).unwrap_or(
            if self.explicit_history_window_certified {
                crate::FullHistoryRepairIncompleteReason::BelowRetentionWindow
            } else {
                crate::FullHistoryRepairIncompleteReason::CoverageUnproven
            },
        );
        if result.is_ok()
            && !qualified
            && reason == crate::FullHistoryRepairIncompleteReason::BelowRetentionWindow
        {
            // The pass finished with every route's window certified. What is
            // left lies below the window, where no pass can search, so the
            // request closes: it would otherwise only park into a notice. It
            // is recorded as neither coverage nor a dismissal.
            storage
                .close_explicit_history_request(ticket)
                .map_err(|error| state_persist(summary.clone(), error.into()))?;
        }
        waiter
            .detach()
            .map_err(|error| state_persist(summary.clone(), error.into()))?;
        match result {
            Ok(_) if qualified => Ok(summary),
            Ok(_) => Err(incomplete_full_history_repair(
                summary,
                reason,
                self.delivery_loss_blocks_cursor(),
            )),
            Err(error) => Err(ClassifiedSyncFailure::at_stage(
                std::mem::take(&mut self.pending_failed_sync_summary),
                error,
                SyncFailureStage::Unknown,
            )),
        }
    }

    pub(crate) async fn advance_convergence_after_runtime_sync(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<SyncSummary, AppError> {
        if self.is_group_forgotten(group_id)? {
            return Ok(SyncSummary::default());
        }
        // The worker retries dirty subscription state before this pass. An
        // unchanged group set requires no account-wide refresh per group.
        let effects = self.runtime.advance_convergence(group_id).await?;
        let mut summary = self
            .finish_scheduled_convergence_effects(group_id, &effects)
            .await?;
        // This seam follows an actual engine evaluation. Projection-only
        // replays of an effects batch must not allocate observation identities.
        if let Err(error) = self.observe_qualified_local_stagnation(group_id) {
            tracing::warn!(target: "marmot_app::recovery", method = "observe_qualified_local_stagnation",
                error_kind=error.privacy_safe_kind(), "qualified local observation remains uncounted");
        }
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
    }

    /// Preserve committed convergence effects before best-effort invite recovery.
    pub(crate) async fn finish_scheduled_convergence_effects(
        &mut self,
        group_id: &cgka_traits::GroupId,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
        let result = self
            .observe_scheduled_convergence_effects(group_id, effects)
            .await;
        self.recover_superseded_invites_best_effort().await;
        result
    }

    /// Project one scheduled convergence batch's effects, split from the
    /// advance itself so the projection is exercisable against a given batch of
    /// effects.
    pub(crate) async fn observe_scheduled_convergence_effects(
        &mut self,
        group_id: &cgka_traits::GroupId,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
        self.observe_recovery_health(effects)?;
        self.remember_pending_convergence_groups(effects);
        // Observe before the publish gate, for the reason spelled out in
        // `observe_drained_session_events`.
        self.observe_recovery_evidence(effects);
        self.remember_published_reports(effects);
        let finalize_updates = self.finalize_published_app_message_source_retention(effects)?;
        let failed_updates = self.invalidate_failed_app_message_projections(effects, None)?;
        // Preserve successful publications in a mixed batch before surfacing
        // an unrelated hard failure. Their durable fanouts are already gone,
        // so a later pass cannot reconstruct this source metadata.
        if let Err(error) = fail_if_publish_failed(effects) {
            self.pending_projection_updates.extend(finalize_updates);
            self.pending_projection_updates.extend(failed_updates);
            return Err(error);
        }
        let publish_new_message_notification =
            effects.published_app_messages.iter().any(|published| {
                let group_id_hex = hex::encode(published.group_id.as_slice());
                self.app
                    .reaction_target(&self.state.label, &group_id_hex, &published.app_event_id)
                    .ok()
                    .flatten()
                    .is_some_and(|message| {
                        matches!(
                            message.kind,
                            MARMOT_APP_EVENT_KIND_CHAT | MARMOT_APP_EVENT_KIND_POLL
                        ) && !message.deleted
                            && !message.invalidated
                    })
            });
        self.refresh_group(group_id);

        let mut summary = SyncSummary::default();
        summary.projection_updates.extend(finalize_updates);
        summary.projection_updates.extend(failed_updates);
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let routes_dirty = self
            .observe_account_device_effects(
                effects,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
            )
            .await?;
        let routes_changed = self.refresh_group_routes()?.routing_changed;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.prune_plaintext_retention_for_group(group_id)?;
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        if publish_new_message_notification {
            self.publish_notification_trigger_best_effort(
                group_id,
                notifications::NotificationTrigger::NewMessage,
            )
            .await;
        }
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
    }

    /// Snapshot each affected group's durable local-delete frontier before any
    /// event in the effects batch mutates projection state. Every event is then
    /// classified against this same authority, independent of batch order.
    fn local_group_deletion_frontiers_at_batch_start(
        &self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<HashMap<String, u64>, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let mut frontiers = HashMap::new();
        let mut seen_group_ids = HashSet::new();
        for event in &effects.events {
            let Some(group_id) = event_group_id(event) else {
                continue;
            };
            let group_id_hex = hex::encode(group_id.as_slice());
            if !seen_group_ids.insert(group_id_hex.clone()) {
                continue;
            }
            if let Some(frontier) = storage.local_group_deletion_frontier(&group_id_hex)? {
                frontiers.insert(group_id_hex, frontier);
            }
        }
        Ok(frontiers)
    }

    fn local_deleted_group_event_crosses_frontier(
        &self,
        event: &cgka_traits::engine::GroupEvent,
        frontier: u64,
        source_message_id_hex: &str,
        source_received_at: u64,
    ) -> Result<bool, AppError> {
        let Some(group_id) = event_group_id(event) else {
            return Ok(false);
        };
        if super::group_is_terminal(&self.runtime, group_id) {
            return Ok(false);
        }
        if matches!(event, cgka_traits::engine::GroupEvent::GroupJoined { .. }) {
            return Ok(true);
        }
        let cgka_traits::engine::GroupEvent::MessageReceived {
            group_id,
            message_id,
            sender,
            epoch,
            payload,
            retention,
            ..
        } = event
        else {
            return Ok(false);
        };
        // One delivery can release buffered effects for several groups, so its
        // outer timestamp is not valid provenance for every event in the batch.
        // The authenticated engine message id resolves to a durable local ingress
        // order. Strict app decoding then prevents malformed or sender-mismatched
        // payloads from resurrecting a deliberately hidden group.
        let sender_hex = hex::encode(sender.as_slice());
        let Some(message) = decode_received_event(
            payload,
            &sender_hex,
            None,
            group_id,
            epoch.0,
            *retention,
            source_message_id_hex,
            source_received_at,
            None,
            self.app.allow_loopback_blob_endpoints(),
        ) else {
            return Ok(false);
        };
        if message.kind != MARMOT_APP_EVENT_KIND_CHAT {
            return Ok(false);
        }
        let group_id_hex = hex::encode(group_id.as_slice());
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .local_group_deletion_message_is_newer_than(&group_id_hex, message_id, frontier)?)
    }

    fn prepare_local_group_deletion_frontier_clear(
        &mut self,
        event: &cgka_traits::engine::GroupEvent,
        frontier: u64,
    ) -> Result<bool, AppError> {
        let Some(group_id) = event_group_id(event) else {
            return Ok(false);
        };
        if !self.adopt_local_deleted_group_prior_routes(group_id)? {
            return Ok(false);
        }
        self.pending_local_group_deletion_frontier_clears
            .entry(hex::encode(group_id.as_slice()))
            .or_insert(frontier);
        Ok(true)
    }

    fn project_received_message(
        &mut self,
        message: crate::ReceivedMessage,
        group_metadata: Option<&cgka_traits::Group>,
        summary: &mut SyncSummary,
    ) -> Result<Option<String>, AppError> {
        if notifications::is_push_gossip_kind(message.kind) {
            let ingest_result = group_metadata
                .map(|group| group.protocol_profile)
                .ok_or_else(|| {
                    AppError::InvalidPushGossip("group profile unavailable for push gossip".into())
                })
                .and_then(|profile| {
                    self.runtime
                        .members(&message.group_id)
                        .map_err(AppError::from)
                        .map(|members| {
                            (
                                profile,
                                members
                                    .into_iter()
                                    .map(|member| hex::encode(member.id.as_slice()))
                                    .collect::<Vec<_>>(),
                            )
                        })
                })
                .and_then(|(profile, active_member_ids)| {
                    self.app.ingest_push_gossip_message(
                        &self.state.label,
                        &message,
                        &active_member_ids,
                        profile,
                    )
                });
            if let Err(err) = ingest_result {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "project_received_message",
                    error_kind = err.privacy_safe_kind(),
                    "ignoring malformed push token gossip",
                );
            }
            return Ok(Some(message.message_id_hex));
        }
        let retains_encrypted_media = message.kind == MARMOT_APP_EVENT_KIND_CHAT
            && media_imeta_tags_are_valid(&message.tags, self.app.allow_loopback_blob_endpoints());
        if let Err(error) = self.app.remember_directory_message_sender(&message) {
            tracing::warn!(
                target: "marmot_app::client",
                method = "project_received_message",
                error_kind = error.privacy_safe_kind(),
                "projecting message without directory enrichment",
            );
        }
        let moderation_grant = message.authority.is_some_and(|a| a.moderation_grant);
        let message_projection = AppMessageProjection {
            authority: message.authority,
            message_id_hex: message.message_id_hex.clone(),
            source_message_id_hex: Some(message.source_message_id_hex.clone()),
            direction: "received".to_owned(),
            group_id_hex: hex::encode(message.group_id.as_slice()),
            sender: message.sender.clone(),
            plaintext: message.plaintext.clone(),
            kind: message.kind,
            tags: message.tags.clone(),
            source_epoch: Some(message.source_epoch),
            retention: message.retention,
            recorded_at: Some(message.recorded_at),
            origin_commit_id: None,
            moderation_grant,
        };
        let projection_update = self.app.record_account_app_event_at(
            &self.state.label,
            &message_projection,
            message.received_at,
        )?;
        if retains_encrypted_media
            && self
                .remember_current_encrypted_media_secret(&message.group_id)
                .is_err()
        {
            tracing::warn!(
                target: "marmot_app::media",
                method = "project_received_message",
                error_code = "encrypted_media_secret_cache_skipped",
                "failed to cache encrypted media source epoch secret",
            );
        }
        summary.projection_updates.push(projection_update);
        self.prune_plaintext_retention_for_group(&message.group_id)?;
        Ok(None)
    }

    fn prepare_pending_application_event_ack(&mut self, event: &cgka_traits::engine::GroupEvent) {
        let event_id = match event {
            cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. } => message_id,
            cgka_traits::engine::GroupEvent::GroupJoined { via_welcome, .. } => via_welcome,
            _ => return,
        };
        self.pending_application_event_acks.insert(event_id.clone());
    }

    pub(crate) fn save_state_with_pending_local_group_deletion_frontier_clears(
        &mut self,
    ) -> Result<(), AppError> {
        self.save_state_with_optional_created_chat_list_row(None)
            .map(|_| ())
    }

    pub(crate) fn save_state_with_created_chat_list_row(
        &mut self,
        group_id: &GroupId,
    ) -> Result<crate::ChatListRow, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        self.save_state_with_optional_created_chat_list_row(Some(&group_id_hex))?
            .ok_or(AppError::UnknownGroup(group_id_hex))
    }

    fn save_state_with_optional_created_chat_list_row(
        &mut self,
        created_group_id_hex: Option<&str>,
    ) -> Result<Option<crate::ChatListRow>, AppError> {
        let checkpoint_started = Instant::now();
        let changed_groups = self.pending_group_projection_updates.len();
        let pending_inputs = self.pending_seen_event_count;
        let pending_acks = self.pending_application_event_acks.len();
        let pending_frontiers = self.pending_local_group_deletion_frontier_clears.len();
        let message_ref = (pending_acks == 1)
            .then(|| self.pending_application_event_acks.iter().next())
            .flatten()
            .and_then(|id| {
                marmot_forensics::v5::EngineMessageRef::from_message_id(id.as_slice()).ok()
            });
        let observation = self
            .runtime_telemetry
            .as_ref()
            .map(|t| t.observe(RuntimeOp::ProjectionCheckpoint));
        let audit_updates = self
            .audit_v5_probe
            .as_ref()
            .map(|probe| {
                probe.pending_updates(&self.state.groups, &self.pending_group_projection_updates)
            })
            .unwrap_or_default();
        let welcome_update_count = audit_updates.len();
        // A Welcome-owned checkpoint can also carry a separately received
        // application ack. Suppress the generic row only when its sole ack
        // identifies the Welcome that owns one of these group projections.
        let only_welcome_ack = self.pending_application_event_acks.iter().all(|ack| {
            let ack_hex = hex::encode(ack.as_slice());
            self.state.groups.iter().any(|group| {
                self.pending_group_projection_updates
                    .contains(&group.group_id_hex)
                    && group.via_welcome_message_id_hex.as_deref() == Some(ack_hex.as_str())
            })
        });
        // This fault exists only in unit-test binaries and occurs before any
        // projection checkpoint write; the engine's join is already committed.
        #[cfg(test)]
        let audit_fail_before_commit = !audit_updates.is_empty()
            && self
                .audit_v5_probe
                .as_mut()
                .is_some_and(|probe| probe.reject_checkpoints);
        #[cfg(not(test))]
        let audit_fail_before_commit = false;
        let mut known_not_committed = audit_fail_before_commit;
        let result = (|| {
            #[cfg(test)]
            if audit_fail_before_commit {
                return Err(AppError::BlockingTask(
                    "injected v5 probe checkpoint failure".into(),
                ));
            }
            let seen_events = match self.transport_receipts() {
                Ok(receipts) => receipts.pending_seen_events(),
                Err(error) => {
                    // This failed before either projection save entry point.
                    // The checkpoint itself therefore did not commit.
                    known_not_committed = true;
                    return Err(error);
                }
            };
            let frontiers_to_clear = self
                .pending_local_group_deletion_frontier_clears
                .iter()
                .map(|(group_id_hex, frontier)| (group_id_hex.clone(), *frontier))
                .collect::<Vec<_>>();
            let application_event_ids_to_ack = self
                .pending_application_event_acks
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            let delta = AccountState {
                label: self.state.label.clone(),
                seen_events,
                last_transport_timestamp: self.checkpointed_transport_timestamp,
                groups: self
                    .state
                    .groups
                    .iter()
                    .filter(|group| {
                        self.pending_group_projection_updates
                            .contains(&group.group_id_hex)
                    })
                    .cloned()
                    .collect(),
            };
            let created_chat_list_row = if let Some(group_id_hex) = created_group_id_hex {
                Some(
                    self.app
                        .save_state_delta_and_refresh_created_chat_list_row(
                            &delta,
                            &frontiers_to_clear,
                            &application_event_ids_to_ack,
                            group_id_hex,
                        )?,
                )
            } else {
                self.app
                .save_state_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
                    &delta,
                    &frontiers_to_clear,
                    &application_event_ids_to_ack,
                )?;
                None
            };
            self.pending_seen_event_count = 0;
            self.pending_group_projection_updates.clear();
            self.pending_local_group_deletion_frontier_clears.clear();
            self.pending_application_event_acks.clear();
            Ok(created_chat_list_row)
        })();
        if let Some(observation) = observation {
            observation.finish_app(&result);
        }
        if let Some(probe) = &mut self.audit_v5_probe {
            probe.finish_checkpoint(audit_updates, result.is_ok(), audit_fail_before_commit);
        }
        self.flush_live_v5_events();
        let welcome_only_checkpoint = result.is_ok()
            && changed_groups != 0
            && welcome_update_count == changed_groups
            && pending_acks <= 1
            && only_welcome_ack
            && pending_inputs <= 1
            && pending_frontiers == 0
            && created_group_id_hex.is_none();
        let has_checkpoint_work = changed_groups != 0
            || pending_inputs != 0
            || pending_acks != 0
            || pending_frontiers != 0
            || created_group_id_hex.is_some();
        if has_checkpoint_work && !welcome_only_checkpoint {
            self.record_v5_app_checkpoint(super::audit_v5_app_update::CheckpointObservation {
                message_ref,
                changed_groups,
                pending_inputs,
                pending_acks,
                pending_frontiers,
                created_row: created_group_id_hex.is_some(),
                error: result.as_ref().err(),
                elapsed: checkpoint_started.elapsed(),
                known_not_committed,
                // The injected checkpoint rejection has a known transaction
                // seam. A receipt setup failure is before that seam, and a
                // storage error can be uncertain; neither proves a stage.
                failure_stage: if audit_fail_before_commit {
                    marmot_forensics::v5::AppUpdateFailureStage::Transaction
                } else {
                    marmot_forensics::v5::AppUpdateFailureStage::Unknown
                },
            });
        }
        result
    }

    /// Terminal disposition for accepted-but-unpublished sends (#1177).
    ///
    /// The engine purges the whole outbound queue at the seams
    /// [`terminates_local_outbound_queue`] names, so every send it still held is
    /// dead; without this sweep those rows derive as `pending` forever, which is
    /// the one place the app cannot tell "still coming" from "never arriving".
    /// Propagate the error rather than swallow it: a silently skipped sweep
    /// leaves exactly the lie this fixes. The sweep ignores already-invalidated
    /// rows, so the batch retry that error triggers is a no-op for anything it
    /// already withdrew — which is also why every observation seam can run it.
    fn invalidate_terminal_pending_sends(
        &self,
        event: &cgka_traits::engine::GroupEvent,
        local_account_id_hex: &str,
        summary: &mut SyncSummary,
    ) -> Result<(), AppError> {
        if let cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id, change, ..
        } = event
            && terminates_local_outbound_queue(change, local_account_id_hex)
            && let Some(projection_update) = self.app.invalidate_timeline_pending_sends_for_group(
                &self.state.label,
                &hex::encode(group_id.as_slice()),
            )?
        {
            summary.projection_updates.push(projection_update);
        }
        Ok(())
    }

    /// The durable app-projection effects one observed [`GroupEvent`] implies,
    /// beyond the in-memory state [`observe_event`] maintains.
    ///
    /// Every seam that observes engine events runs this: live delivery and
    /// send-applied effects through [`Self::observe_account_device_effects`],
    /// and session-history replay through
    /// [`Self::observe_drained_session_events`]. Those seams legitimately differ
    /// in how they build a group projection and in what recovery evidence they
    /// arm, but not in what an event means for the timeline, for membership, or
    /// for a terminal group's notification destinations — so that part lives
    /// here once. It used to be copied into the live seam only, which is how a
    /// crash-replayed departure kept a departed member's push records and left
    /// the account unread aggregate stale.
    ///
    /// Replay-safe by construction, which is what lets the drained seam call it:
    /// hydration replays a stored group's `GroupDisbanded` once after the
    /// settling session, and a crash replays pending application events the live
    /// seam may already have projected. Token removal is a `DELETE` of rows that
    /// may be gone;
    /// `set_group_self_membership` writes an absolute value and no-ops when the
    /// group has no projection row; the queued registration removal is an upsert
    /// keyed on the group; and both invalidation sweeps skip rows they already
    /// withdrew.
    ///
    /// Returns whether the event forces a transport-route refresh.
    pub(crate) fn observe_event_projection_effects(
        &mut self,
        event: &cgka_traits::engine::GroupEvent,
        local_account_id_hex: &str,
        summary: &mut SyncSummary,
    ) -> Result<bool, AppError> {
        let mut routes_dirty = false;
        // Timeline invalidation dispatch: `AppMessageInvalidated` withdraws
        // the delivered source row; `GroupStateInvalidated` withdraws every
        // kind-1210 system row stamped with the superseded commit's
        // `origin_commit_id`. The engine pairs `GroupStateInvalidated`
        // with the commit-rollback seam (`CommitRolledBack` on the
        // stored-convergence path), so that event no longer triggers
        // tombstoning here — the explicit withdrawal event is the single
        // authoritative signal and one rollback produces exactly one
        // projection update.
        if let Some(projection_update) = self
            .app
            .projection_update_for_invalidation_event(&self.state.label, event)?
        {
            summary.projection_updates.push(projection_update);
        }
        if let cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id, change, ..
        } = event
            && let Some((member, membership)) = member_departure(change)
        {
            let group_id_hex = hex::encode(group_id.as_slice());
            let member_id_hex = hex::encode(member.as_slice());
            let _ = self.app.remove_group_push_tokens_for_member(
                &self.state.label,
                &group_id_hex,
                &member_id_hex,
            );
            // Only the local account leaving / being removed suppresses our
            // own unread aggregate for the group; a peer departure must not.
            // The recorded membership distinguishes a voluntary `Left` from
            // an involuntary `Removed` so the chat list can tell them apart.
            // This projection write is the source of truth for the account
            // unread aggregate, so propagate its error (matching the nearby
            // timeline/message projection writes) instead of swallowing it:
            // silently leaving the flag stale would keep
            // `account_unread_total()` returning an inflated badge after a
            // self-removal that sync otherwise reports as successful.
            if member_id_hex.eq_ignore_ascii_case(local_account_id_hex) {
                self.app
                    .set_group_self_membership(&self.state.label, &group_id_hex, membership)?;
                // Terminal for this device's copy, so its transport routes are
                // now stale. Same obligation as the disband arm below: the
                // ingest seam persists this membership write before route
                // reconciliation, and the route teardown reaches the relay in
                // this pass instead of the next one.
                routes_dirty = true;
            }
        }
        if let cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id,
            change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
            ..
        } = event
        {
            routes_dirty = true;
            let group_id_hex = hex::encode(group_id.as_slice());
            // Terminal groups never advertise notification destinations
            // again. Queue the current registration's removal and discard
            // every cached peer token immediately; publishing the removal
            // rumor remains restart-safe in the normal outbox.
            let _ = self.queue_current_push_registration_removal_for_group(group_id);
            let _ = self
                .app
                .remove_stale_group_push_tokens(&self.state.label, &group_id_hex, &[]);
        }
        self.invalidate_terminal_pending_sends(event, local_account_id_hex, summary)?;
        // The local account arriving in a group restores its membership so the
        // group's unread count stops being suppressed. A (re-)join or create is
        // one such arrival; a roster diff that reports this device as
        // `MemberAdded` is the other, and it is the only signal a convergence
        // branch which supersedes our removal ever emits. Same source-of-truth
        // write as the departure path above: propagate the error rather than
        // swallow it. Writing `Member` also clears a preserved voluntary
        // `Left`, which is the intended mdk#1746 behavior on a re-add.
        if let Some(group_id) = self_arrival_group(event, local_account_id_hex) {
            let group_id_hex = hex::encode(group_id.as_slice());
            let restored = self
                .app
                .account_storage(&self.state.label)?
                .restore_group_self_membership(&group_id_hex)?;
            if restored {
                // Keep the worker's next projection save aligned with the same durable
                // arrival; otherwise its old archive intent would undo this transition.
                if let Some(group) = self
                    .state
                    .groups
                    .iter_mut()
                    .find(|g| g.group_id_hex == group_id_hex)
                {
                    group.archived = false;
                    group.self_membership = SelfMembership::Member;
                }
                self.mark_group_projection_dirty(group_id);
            }
            self.app.presentation_signals.wake();
        }
        Ok(routes_dirty)
    }

    fn display_names_for_events(
        &self,
        events: &[cgka_traits::engine::GroupEvent],
    ) -> HashMap<String, String> {
        let senders = events
            .iter()
            .filter_map(|event| match event {
                cgka_traits::engine::GroupEvent::MessageReceived { sender, .. } => {
                    Some(hex::encode(sender.as_slice()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        // Enrichment must not discard effects the engine already consumed.
        match self.app.display_names_for_account_ids(&senders) {
            Ok(names) => names,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "display_names_for_events",
                    error_kind = error.privacy_safe_kind(),
                    "projecting events without display names",
                );
                HashMap::new()
            }
        }
    }

    async fn observe_account_device_effects(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        summary: &mut SyncSummary,
        source_message_id_hex: &str,
        source_received_at: u64,
    ) -> Result<bool, AppError> {
        let started = Instant::now();
        let result = self
            .observe_account_device_effects_inner(
                effects,
                summary,
                source_message_id_hex,
                source_received_at,
            )
            .await;
        if let Err(error) = &result {
            self.record_v5_event_projection_failure(&effects.events, error, started.elapsed());
        }
        result
    }

    async fn observe_account_device_effects_inner(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        summary: &mut SyncSummary,
        source_message_id_hex: &str,
        source_received_at: u64,
    ) -> Result<bool, AppError> {
        let display_names = self.display_names_for_events(&effects.events);
        self.note_superseded_intent_reports(effects);
        // MLS member ids in this design are the Nostr account pubkey hex, so a
        // membership change whose subject matches the local account id hex is
        // the local account leaving / being removed (or, for joins, returning).
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut routes_dirty = false;
        // #760: collect push-gossip ids and strip them from `summary.messages` in
        // ONE pass after the loop. The previous per-message `retain` was O(n) per
        // gossip event → O(n²) over a batch a relay could flood with kind-448s.
        let mut gossip_message_ids: HashSet<String> = HashSet::new();
        let local_group_deletion_frontiers =
            self.local_group_deletion_frontiers_at_batch_start(effects)?;
        for event in &effects.events {
            let event_source = event_source_message_id_hex(event, source_message_id_hex);
            // Effects identify authenticated content, not its enclosing relay
            // event. Even a single event can have been released by a later
            // envelope. Skip the optional skew diagnostic without an explicit
            // origin mapping; never read fallible storage just to emit a warning.
            let event_outer_transport_at = None;
            let batch_start_frontier = event_group_id(event)
                .and_then(|group_id| {
                    local_group_deletion_frontiers.get(&hex::encode(group_id.as_slice()))
                })
                .copied();
            let crosses_frontier = match batch_start_frontier {
                Some(frontier) => self.local_deleted_group_event_crosses_frontier(
                    event,
                    frontier,
                    &event_source,
                    source_received_at,
                )?,
                None => false,
            };
            if !crosses_frontier
                && let Some(changed) =
                    self.suppress_local_deleted_group_event(event, batch_start_frontier)?
            {
                routes_dirty |= changed;
                self.prepare_pending_application_event_ack(event);
                continue;
            }
            let before = self.state.groups.len();
            let previous_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            let group_metadata =
                event_group_id(event).and_then(|group_id| self.runtime.group_record(group_id).ok());
            let group_projection = event_group_id(event)
                .map(|group_id| self.event_group_projection(group_id, group_metadata.as_ref()))
                .transpose()?;
            if let Some(message) = observe_event(
                &mut self.state,
                &display_names,
                summary,
                event,
                group_projection.as_ref(),
                &event_source,
                source_received_at,
                event_outer_transport_at,
                self.app.allow_loopback_blob_endpoints(),
            ) && let Some(gossip_message_id) =
                self.project_received_message(message, group_metadata.as_ref(), summary)?
            {
                gossip_message_ids.insert(gossip_message_id);
            }
            let updated_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            if previous_group != updated_group
                && let Some(group_id) = event_group_id(event)
            {
                self.mark_group_projection_dirty(group_id);
            }
            self.audit_observed_group_event(
                event,
                previous_group.as_ref(),
                updated_group.as_ref(),
                &event_source,
            );
            if previous_group != updated_group
                && let Some(probe) = &mut self.audit_v5_probe
                && (self.runtime.session().audit_v5_enabled() || cfg!(test))
            {
                probe.projected(event, marmot_forensics::v5::UpdateCause::WelcomeJoin);
            }
            routes_dirty |=
                self.observe_event_projection_effects(event, &local_account_id_hex, summary)?;
            if self.state.groups.len() != before {
                routes_dirty = true;
            }
            let can_ack_application_event = if crosses_frontier {
                self.prepare_local_group_deletion_frontier_clear(
                    event,
                    batch_start_frontier.expect("crossing event has a frontier"),
                )?
            } else {
                true
            };
            if can_ack_application_event {
                self.prepare_pending_application_event_ack(event);
                if cfg!(feature = "test-policy-overrides")
                    && self.app.config.dev_fail_ingest_after_application_event_ack
                {
                    return Err(AppError::BlockingTask(
                        "injected failure after application-event acknowledgement".to_owned(),
                    ));
                }
            }
        }
        self.clear_terminal_local_group_deletion_frontiers(effects)?;
        // #760: strip all collected push-gossip messages in one pass.
        if !gossip_message_ids.is_empty() {
            summary
                .messages
                .retain(|candidate| !gossip_message_ids.contains(&candidate.message_id_hex));
        }
        // Synthesize durable kind-1210 system rows from authenticated state
        // changes (peer commits, auto-commits, and scheduled convergence).
        let system_updates = self.project_group_system_rows(&effects.events, source_received_at);
        summary.projection_updates.extend(system_updates);
        Ok(routes_dirty)
    }

    /// Advance the persisted transport cursor from an inbound message unless
    /// this runtime was constructed with
    /// [`CursorPersistence::Frozen`](crate::CursorPersistence), in which case
    /// this is a no-op, or the account route has already recorded a queue
    /// omission whose marker/control record is still in flight.
    ///
    /// `timestamp` is the sender-controlled Nostr `created_at` of the outer
    /// kind-445 event and is never validated upstream. The cursor is a
    /// monotonic-max, persisted value that becomes a relay-level `since` filter
    /// on subscription rebuild and account open, so an unbounded far-future
    /// value would push `since` into the future and silently halt all message
    /// reception across restarts (mdk#182). Clamp the advance to local
    /// wall-clock plus a bounded skew so a hostile or clock-skewed sender can
    /// move the cursor no further than `now + TRANSPORT_CURSOR_MAX_FUTURE_SKEW`.
    fn remember_transport_cursor(&mut self, timestamp: u64) {
        if self.adapter.pending_delivery_overflow().is_some() {
            return;
        }
        self.state.last_transport_timestamp = next_transport_cursor(
            self.app.cursor_persistence(),
            self.state.last_transport_timestamp,
            timestamp,
            unix_now_seconds(),
            TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
        );
    }
}

/// Apply the runtime's [`CursorPersistence`] policy to a candidate inbound
/// timestamp: the policy seam behind `remember_transport_cursor`.
///
/// Under [`CursorPersistence::Frozen`] (the wake-collection posture — see the
/// enum docs in `config.rs` for the full semantics) the cursor is returned
/// unchanged, `None` included: the pass still ingests, decrypts, and projects
/// everything, but the durable `since` floor never ratchets, so `save_state`
/// writes back the loaded value and the storage-side clamp-then-max merge
/// keeps a concurrent `Advance` runtime's progress intact. Deliberate
/// consequences visible in the forensic audit rows: a frozen pass's
/// `sync_drain` records `cursor_before == cursor_after`, and its
/// `subscription_rebuild` rows keep recording the loaded floor — exactly the
/// evidence that a wake pass did not move the floor.
///
/// Under [`CursorPersistence::Advance`] this delegates to
/// [`clamped_transport_cursor`] unchanged.
fn next_transport_cursor(
    policy: crate::CursorPersistence,
    current: Option<u64>,
    candidate: u64,
    now: u64,
    max_future_skew_secs: u64,
) -> Option<u64> {
    match policy {
        crate::CursorPersistence::Frozen => current,
        crate::CursorPersistence::Advance => Some(clamped_transport_cursor(
            current,
            candidate,
            now,
            max_future_skew_secs,
        )),
    }
}

/// Compute the next persisted transport cursor from a candidate inbound
/// timestamp.
///
/// `candidate` is the sender-controlled Nostr `created_at` and is untrusted. It
/// is first clamped to `now + max_future_skew_secs` so a far-future value
/// cannot poison the cursor (which would push the relay `since` filter into the
/// future and silently halt message reception — mdk#182), then folded
/// into the existing monotonic-max cursor. The existing `current` is clamped
/// the same way before the max, so a cursor that was already poisoned before
/// this guard existed is *healed* back down to `now + max_future_skew_secs`
/// here instead of being preserved forever by the monotonic max. A benign
/// in-range timestamp is unaffected; the skew margin tolerates ordinary sender
/// clock drift.
///
/// The clamp itself is [`storage_sqlite::clamp_to_max_future_skew`] — the one
/// definition shared with the save-time durable-cursor merge in
/// `save_account_projection_state`, so ingest and persistence can never
/// disagree on the ceiling.
fn clamped_transport_cursor(
    current: Option<u64>,
    candidate: u64,
    now: u64,
    max_future_skew_secs: u64,
) -> u64 {
    let clamped = clamp_to_max_future_skew(candidate, now, max_future_skew_secs);
    current
        .map(|current| clamp_to_max_future_skew(current, now, max_future_skew_secs).max(clamped))
        .unwrap_or(clamped)
}

/// Classify a group state change that ends a member's participation, returning
/// the departing member alongside how that departure should be recorded for the
/// member: a `MemberLeft` self-removal is a voluntary [`SelfMembership::Left`];
/// a `MemberRemoved` eviction by another member is [`SelfMembership::Removed`].
/// Returns `None` for changes that are not departures.
fn member_departure(
    change: &cgka_traits::engine::GroupStateChange,
) -> Option<(&cgka_traits::MemberId, SelfMembership)> {
    use cgka_traits::engine::GroupStateChange;
    match change {
        GroupStateChange::MemberLeft { member } => Some((member, SelfMembership::Left)),
        GroupStateChange::MemberRemoved { member } => Some((member, SelfMembership::Removed)),
        _ => None,
    }
}

/// Classify an engine event that puts the local account back in a group,
/// returning the group it rejoined. The mirror of [`member_departure`]: a
/// welcome-driven `GroupJoined` and a local `GroupCreated` are arrivals by
/// construction, and a `GroupStateChanged` roster diff is one only when the
/// added member is this device — the case distributed convergence produces when
/// the winning branch supersedes a removal of us (the engine pins that emission
/// in `superseded_self_removal_clears_removed_marker_and_restores_send`). Returns
/// `None` otherwise, so a peer being added changes nothing locally.
fn self_arrival_group<'a>(
    event: &'a cgka_traits::engine::GroupEvent,
    local_account_id_hex: &str,
) -> Option<&'a cgka_traits::GroupId> {
    match event {
        cgka_traits::engine::GroupEvent::GroupJoined { group_id, .. }
        | cgka_traits::engine::GroupEvent::GroupCreated { group_id } => Some(group_id),
        cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id,
            change: cgka_traits::engine::GroupStateChange::MemberAdded { member },
            ..
        } if hex::encode(member.as_slice()).eq_ignore_ascii_case(local_account_id_hex) => {
            Some(group_id)
        }
        _ => None,
    }
}

/// Does this group state change permanently discard the local account's
/// retained outbound work for the group?
///
/// Convergence normally releases a retained intent eventually, which is why a
/// held row truthfully derives as `pending`. Exactly two changes break that
/// promise, and both purge the engine's queue wholesale rather than per intent:
/// a disband tears the group down for everyone, and losing the local copy —
/// evicted (`MemberRemoved`) or departed voluntarily (`MemberLeft`) — discards
/// the queue silently. A peer's departure does neither.
///
/// The self-subject test is shared with the sibling membership write at the same
/// seam, so the two cannot disagree about who left.
fn terminates_local_outbound_queue(
    change: &cgka_traits::engine::GroupStateChange,
    local_account_id_hex: &str,
) -> bool {
    match change {
        cgka_traits::engine::GroupStateChange::GroupDisbanded => true,
        _ => member_departure(change).is_some_and(|(member, _)| {
            hex::encode(member.as_slice()).eq_ignore_ascii_case(local_account_id_hex)
        }),
    }
}

#[cfg(test)]
mod terminal_outbound_queue_tests {
    use super::terminates_local_outbound_queue;
    use cgka_traits::MemberId;
    use cgka_traits::engine::GroupStateChange;

    const SELF: &str = "aa";
    const PEER: &str = "bb";

    fn member(id_hex: &str) -> MemberId {
        MemberId::new(hex::decode(id_hex).unwrap())
    }

    #[test]
    fn a_disband_terminates_the_queue_for_every_member() {
        assert!(terminates_local_outbound_queue(
            &GroupStateChange::GroupDisbanded,
            SELF
        ));
    }

    #[test]
    fn losing_the_local_copy_terminates_the_queue_however_it_was_lost() {
        for change in [
            GroupStateChange::MemberRemoved {
                member: member(SELF),
            },
            GroupStateChange::MemberLeft {
                member: member(SELF),
            },
        ] {
            assert!(
                terminates_local_outbound_queue(&change, SELF),
                "{change:?} discards the local queue"
            );
        }
    }

    #[test]
    fn a_peer_departure_leaves_the_local_queue_alive() {
        // The group carries on without them and our retained sends still
        // deliver, so nothing may be swept.
        for change in [
            GroupStateChange::MemberRemoved {
                member: member(PEER),
            },
            GroupStateChange::MemberLeft {
                member: member(PEER),
            },
            GroupStateChange::MemberAdded {
                member: member(SELF),
            },
            GroupStateChange::AdminAdded {
                member: member(SELF),
            },
        ] {
            assert!(
                !terminates_local_outbound_queue(&change, SELF),
                "{change:?} must not terminate the local queue"
            );
        }
    }

    #[test]
    fn the_self_subject_test_ignores_hex_case() {
        // Member ids reach this comparison as independently encoded hex; the
        // sibling membership write at the same seam is case-insensitive, and a
        // case split here would silently skip the sweep.
        assert!(terminates_local_outbound_queue(
            &GroupStateChange::MemberRemoved {
                member: member("ab"),
            },
            "AB"
        ));
    }
}

#[cfg(test)]
mod membership_change_tests {
    use super::member_departure;
    use crate::SelfMembership;
    use cgka_traits::MemberId;
    use cgka_traits::engine::GroupStateChange;

    #[test]
    fn member_departure_distinguishes_self_leave_from_eviction() {
        let member = MemberId::new(vec![0xaa]);

        // A SelfRemove proposal is a voluntary departure.
        let left = GroupStateChange::MemberLeft {
            member: member.clone(),
        };
        let (subject, membership) = member_departure(&left).expect("MemberLeft is a departure");
        assert_eq!(subject, &member);
        assert_eq!(membership, SelfMembership::Left);

        // An eviction by another member is an involuntary removal.
        let removed = GroupStateChange::MemberRemoved {
            member: member.clone(),
        };
        let (subject, membership) =
            member_departure(&removed).expect("MemberRemoved is a departure");
        assert_eq!(subject, &member);
        assert_eq!(membership, SelfMembership::Removed);
    }

    #[test]
    fn member_departure_ignores_non_departures() {
        let member = MemberId::new(vec![0xaa]);
        let added = GroupStateChange::MemberAdded {
            member: member.clone(),
        };
        let admin = GroupStateChange::AdminAdded { member };
        assert!(member_departure(&added).is_none());
        assert!(member_departure(&admin).is_none());
    }
}

#[cfg(test)]
mod live_cursor_checkpoint_tests {
    use super::SyncSummary;
    use crate::tests::{LiveCursorFixture, inject_epoch_gap_probe, run_composed_app_runtime_test};

    /// Queue a newer delivery ahead of an older one, as relays replay stored
    /// history newest-first, and arm the older one's ingest to fail. Returns
    /// the older probe.
    async fn queue_newest_first_with_a_failing_older(
        fixture: &mut LiveCursorFixture,
    ) -> transport_nostr_peeler::NostrTransportEvent {
        let cursor_before = fixture.cursor_before;
        let older = fixture.probe(cursor_before + 1_000, "older");
        fixture.client.fail_ingest_of = Some(fixture.delivery(older.clone()).await.message.id);
        queue_in_order(
            fixture,
            [fixture.probe(cursor_before + 4_000, "newer"), older.clone()],
        )
        .await;
        older
    }

    /// The cursor a failed ingest's checkpoint persisted still lets a
    /// restart fetch `failed`, and after a stop the account admits it when
    /// the restart's subscriptions serve it again.
    async fn a_stop_still_admits(
        fixture: LiveCursorFixture,
        failed: transport_nostr_peeler::NostrTransportEvent,
    ) {
        let persisted = fixture.persisted();
        assert_eq!(
            persisted,
            Some(failed.created_at + 120),
            "the checkpoint stops where a restart fetches the failed delivery"
        );
        let mut fixture = fixture.reopen().await;
        assert!(
            fixture
                .client
                .subscription_rebuild_since()
                .unwrap()
                .is_some_and(|since| since.0 <= failed.created_at),
            "the restart's subscriptions start at or below it"
        );
        inject_epoch_gap_probe(&fixture.app, failed.clone()).await;
        assert_eq!(fixture.ingest_next_live_delivery().await, failed.id);
        assert!(
            fixture
                .client
                .transport_receipts()
                .unwrap()
                .contains(&failed.id)
        );
    }

    /// Inject `events` in order and wait until the account queue holds them.
    async fn queue_in_order(
        fixture: &LiveCursorFixture,
        events: impl IntoIterator<Item = transport_nostr_peeler::NostrTransportEvent>,
    ) {
        let mut queued = 0;
        for event in events {
            inject_epoch_gap_probe(&fixture.app, event).await;
            queued += 1;
        }
        fixture.wait_for_queue_depth(queued).await;
    }

    /// A delivery stops capping the cursor once its ingest is durable, or
    /// once it is skipped because the account already holds it, in a drain
    /// and on the live path alike, so the cursor still reaches what the
    /// account ingested.
    #[test]
    fn ingested_and_already_held_deliveries_stop_capping_the_cursor() {
        run_composed_app_runtime_test("live-cursor-releases", || async {
            let mut fixture = LiveCursorFixture::open().await;
            let cursor_before = fixture.cursor_before;
            let held = fixture.probe(cursor_before + 1_000, "held");
            queue_in_order(&fixture, [held.clone()]).await;
            fixture.ingest_next_live_delivery().await;
            assert_eq!(fixture.persisted(), Some(cursor_before + 1_000));

            // A drain: newest first, then an older new event, then the held
            // one served again.
            let newest = fixture.probe(cursor_before + 4_000, "newest");
            queue_in_order(
                &fixture,
                [
                    newest.clone(),
                    fixture.probe(cursor_before + 3_000, "older"),
                    held,
                ],
            )
            .await;
            fixture
                .client
                .sync_sdk_relay()
                .await
                .unwrap_or_else(|_| panic!("the drain completes"));
            assert_eq!(
                fixture.persisted(),
                Some(cursor_before + 4_000),
                "the checkpoint passes what the drain ingested or already held"
            );

            // Live: the newest one served again, ahead of a newer arrival.
            queue_in_order(
                &fixture,
                [newest, fixture.probe(cursor_before + 5_000, "live")],
            )
            .await;
            fixture.ingest_next_live_delivery().await;
            assert_eq!(
                fixture.persisted(),
                Some(cursor_before + 5_000),
                "the promotion passes the delivery the receive skipped as held"
            );
        });
    }

    /// A catch-up drain ingests the newer delivery first, so it remembers a
    /// cursor above the older one before that one fails to ingest. The failed
    /// delivery stays taken, so the checkpoint the failure runs is capped
    /// where a restart fetches it again.
    #[test]
    fn a_drain_checkpoint_after_a_failed_older_ingest_still_covers_it() {
        run_composed_app_runtime_test("drain-failed-older-ingest", || async {
            let mut fixture = LiveCursorFixture::open().await;
            let cursor_before = fixture.cursor_before;
            let older = queue_newest_first_with_a_failing_older(&mut fixture).await;
            assert!(
                fixture.client.sync_sdk_relay().await.is_err(),
                "the older delivery's ingest fails the drain"
            );
            assert_eq!(
                fixture.client.state.last_transport_timestamp,
                Some(cursor_before + 4_000),
                "the drain remembered the newer delivery before the failure"
            );
            a_stop_still_admits(fixture, older).await;
        });
    }

    /// The startup receive checkpoints the applied prefix when a delivery
    /// fails to ingest, as the drain does. The newer delivery's live
    /// promotion already stopped at the queued older one, and the failure's
    /// checkpoint must not pass the older one either.
    #[test]
    fn a_startup_receive_checkpoint_after_a_failed_older_ingest_still_covers_it() {
        run_composed_app_runtime_test("startup-failed-older-ingest", || async {
            let mut fixture = LiveCursorFixture::open().await;
            let older = queue_newest_first_with_a_failing_older(&mut fixture).await;
            for expect_failure in [false, true] {
                let received = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    fixture.client.receive_next_delivery(),
                )
                .await
                .expect("a delivery is ready")
                .unwrap();
                let crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) = received
                else {
                    panic!("a live delivery must not produce a control record");
                };
                let result = fixture
                    .client
                    .ingest_received_delivery_with_partial(*delivery)
                    .await;
                assert_eq!(result.is_err(), expect_failure);
                assert_eq!(fixture.persisted(), Some(older.created_at + 120));
            }
            a_stop_still_admits(fixture, older).await;
        });
    }

    /// A drain checkpoint a fence held reaches nothing of its own. The cursor
    /// it re-persists came from an earlier live promotion, so it must not
    /// become the settled floor, or the router would queue what only that
    /// promotion stopped a restart from fetching.
    #[test]
    fn a_fenced_drain_checkpoint_keeps_spilling_what_live_promotion_exposed() {
        run_composed_app_runtime_test("live-cursor-fenced-drain", || async {
            let mut fixture = LiveCursorFixture::open().await;
            let cursor_before = fixture.cursor_before;
            crate::tests::inject_epoch_gap_probe(
                &fixture.app,
                fixture.probe(cursor_before + 4_000, "promoting"),
            )
            .await;
            fixture.wait_for_queue_depth(1).await;
            fixture.ingest_next_live_delivery().await;
            assert_eq!(fixture.persisted(), Some(cursor_before + 4_000));

            let first = fixture
                .delivery(fixture.probe(cursor_before + 1_000, "first"))
                .await;
            let second = fixture
                .delivery(fixture.probe(cursor_before + 1_001, "second"))
                .await;
            // The spill writer has not run yet, so its hand-off fences the
            // drain checkpoint that follows, which a later ingest would
            // otherwise have moved past the live promotion.
            fixture
                .app
                .relay_plane
                .route_account_delivery_for_test(first);
            assert!(fixture.client.adapter.delivery_loss_blocks_cursor());
            fixture.client.state.last_transport_timestamp = Some(cursor_before + 5_000);
            fixture
                .client
                .checkpoint_sync_prefix(&mut SyncSummary::default(), false, 0)
                .await
                .unwrap_or_else(|_| panic!("the checkpoint saves"));
            assert_eq!(fixture.persisted(), Some(cursor_before + 4_000));

            fixture
                .app
                .relay_plane
                .route_account_delivery_for_test(second);
            assert!(
                fixture
                    .client
                    .adapter
                    .try_receive_account_delivery()
                    .is_none(),
                "a delivery only the live promotion exposed is still spilled"
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while fixture
                    .app
                    .relay_plane
                    .relay_health()
                    .await
                    .account_delivery_spilled
                    < 2
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("both deliveries become durable spill rows");
        });
    }

    /// A drain checkpoint moves the cursor as far as a live promotion does.
    /// A delivery that arrives while its save runs, older than the floor that
    /// save commits, must not wait in the queue: a stop before its ingest
    /// would lose it, since the restart re-subscribes above it.
    #[test]
    fn a_delivery_arriving_during_a_drain_checkpoint_save_survives_a_stop() {
        run_composed_app_runtime_test("drain-checkpoint-arrival-during-save", || async {
            let mut fixture = LiveCursorFixture::open().await;
            let cursor_before = fixture.cursor_before;
            // A drained prefix: admitted without promoting, as a drain's
            // ingests are until its checkpoint.
            let drained = fixture
                .delivery(fixture.probe(cursor_before + 4_000, "drained"))
                .await;
            fixture
                .client
                .admit_recovered_delivery(drained)
                .await
                .unwrap();
            assert_eq!(
                fixture.client.state.last_transport_timestamp,
                Some(cursor_before + 4_000)
            );
            assert_eq!(fixture.persisted(), Some(cursor_before));

            let late_at = cursor_before + 1_000;
            let late = fixture.probe(late_at, "late");
            let delivery = fixture.delivery(late.clone()).await;
            fixture.land_during_seal(crate::client::CursorSeal::After, delivery);
            fixture
                .client
                .checkpoint_sync_prefix(&mut SyncSummary::default(), false, 1)
                .await
                .unwrap_or_else(|_| panic!("the checkpoint saves"));

            let persisted = fixture.persisted();
            assert_eq!(persisted, Some(cursor_before + 4_000));
            assert!(
                fixture
                    .app
                    .relay_plane
                    .subscription_rebuild_since(persisted)
                    .is_some_and(|since| since.0 > late_at),
                "the regression needs a restart floor above the late delivery"
            );
            assert!(
                fixture
                    .client
                    .adapter
                    .try_receive_account_delivery()
                    .is_none(),
                "the queue never holds a delivery below the checkpoint's floor"
            );
            fixture.wait_for_spilled(&late.id).await;
            fixture.reopen_and_admit_spilled(&late.id).await;
        });
    }

    /// Before its first cursor an account's restart relies on its
    /// comparison for everything, so the first cursor it persists stops a
    /// restart from fetching any older delivery, however old. One that
    /// arrives while that first checkpoint saves is spilled, and a stop still
    /// admits it.
    #[test]
    fn an_older_arrival_during_an_accounts_first_checkpoint_survives_a_stop() {
        run_composed_app_runtime_test("first-cursor-arrival-during-save", || async {
            let mut fixture = LiveCursorFixture::open_without_cursor().await;
            let cursor_before = fixture.cursor_before;
            let drained = fixture
                .delivery(fixture.probe(cursor_before + 4_000, "drained"))
                .await;
            fixture
                .client
                .admit_recovered_delivery(drained)
                .await
                .unwrap();
            assert_eq!(fixture.persisted(), None);

            let late_at = cursor_before + 1_000;
            let late = fixture.probe(late_at, "late");
            let delivery = fixture.delivery(late.clone()).await;
            fixture.land_during_seal(crate::client::CursorSeal::After, delivery);
            fixture
                .client
                .checkpoint_sync_prefix(&mut SyncSummary::default(), false, 1)
                .await
                .unwrap_or_else(|_| panic!("the checkpoint saves"));

            let persisted = fixture.persisted();
            assert_eq!(persisted, Some(cursor_before + 4_000));
            assert!(
                fixture
                    .app
                    .relay_plane
                    .subscription_rebuild_since(persisted)
                    .is_some_and(|since| since.0 > late_at),
                "the regression needs a restart floor above the late delivery"
            );
            assert!(
                fixture
                    .client
                    .adapter
                    .try_receive_account_delivery()
                    .is_none(),
                "the queue never holds a delivery below the first cursor's floor"
            );
            fixture.wait_for_spilled(&late.id).await;
            fixture.reopen_and_admit_spilled(&late.id).await;
        });
    }

    /// An account that never persisted a cursor does not promote it live: it
    /// would have to spill every older arrival, such as each joined group's
    /// history, until a settled floor exists. Its first drain checkpoint
    /// sets one, capped by what is still queued, and live promotion follows.
    #[test]
    fn a_new_account_promotes_live_only_after_its_first_drain_checkpoint() {
        run_composed_app_runtime_test("first-cursor-live-waits", || async {
            let mut fixture = LiveCursorFixture::open_without_cursor().await;
            let cursor_before = fixture.cursor_before;
            crate::tests::inject_epoch_gap_probe(
                &fixture.app,
                fixture.probe(cursor_before + 4_000, "live"),
            )
            .await;
            fixture.wait_for_queue_depth(1).await;
            fixture.ingest_next_live_delivery().await;
            assert_eq!(
                fixture.client.state.last_transport_timestamp,
                Some(cursor_before + 4_000)
            );
            assert_eq!(
                fixture.persisted(),
                None,
                "no live promotion before a settled floor"
            );

            // Queued before the first seal, below any floor, it caps it.
            crate::tests::inject_epoch_gap_probe(
                &fixture.app,
                fixture.probe(cursor_before + 1_000, "queued"),
            )
            .await;
            fixture.wait_for_queue_depth(1).await;
            fixture
                .client
                .checkpoint_sync_prefix(&mut SyncSummary::default(), false, 0)
                .await
                .unwrap_or_else(|_| panic!("the checkpoint saves"));
            assert_eq!(fixture.persisted(), Some(cursor_before + 1_000 + 120));

            fixture.ingest_next_live_delivery().await;
            assert_eq!(
                fixture.persisted(),
                Some(cursor_before + 4_000),
                "once a settled floor exists the next live ingest promotes"
            );
        });
    }
}

#[cfg(test)]
mod runtime_group_subscription_refresh_tests {
    use std::sync::Arc;

    use super::{SyncCheckpointError, SyncSummary};
    use crate::tests::ScriptedPushRelayClient;
    use crate::{AppPerformanceTelemetry, MarmotApp};
    use marmot_account::AccountHome;

    #[tokio::test]
    async fn catch_up_checkpoint_arms_refresh_after_durable_subscription_failure() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        client.prepare_transport().await.unwrap();
        let telemetry = AppPerformanceTelemetry::default();
        client
            .create_group_with_options_and_telemetry(
                "catch-up retry intent",
                &[],
                crate::AppCreateGroupOptions::default(),
                &telemetry,
            )
            .await
            .unwrap();

        relay.fail_next_subscribe();
        let mut summary = SyncSummary::default();
        let error = client
            .checkpoint_sync_prefix(&mut summary, true, 0)
            .await
            .expect_err("the injected post-checkpoint subscription rebuild must fail");
        assert!(matches!(error, SyncCheckpointError::AfterPersistence(_)));
        assert!(client.has_pending_runtime_group_subscription_refresh());

        assert!(
            !client
                .retry_pending_runtime_group_subscription_refresh()
                .await
                .unwrap()
        );
        assert!(!client.has_pending_runtime_group_subscription_refresh());
    }

    /// The drained seam's subscription rebuild owes the same retry edge.
    ///
    /// Both edges that could re-fire the rebuild are spent by the pass that
    /// failed: `drain()` empties the engine's in-memory event buffer one-shot,
    /// so the `routes_dirty` event is gone, and `refresh_group_routes` reports
    /// `routing_changed` only while the in-memory routing table is actually
    /// mutating. Without an explicit arm the account's ordinary group
    /// subscriptions stay stale until some unrelated delivery happens to dirty
    /// the routes again — and a stale group subscription is exactly what stops
    /// those deliveries from arriving.
    #[tokio::test]
    async fn drained_epilogue_arms_refresh_after_failed_subscription_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        client.prepare_transport().await.unwrap();
        let telemetry = AppPerformanceTelemetry::default();
        // The managed-runtime create, which defers the relay-side subscription
        // install to a later refresh (the worker performs it after replying).
        // The second group is that outstanding install: the drained disband
        // below dirties the routes, and the rebuild it triggers is the one the
        // relay refuses.
        let created = client
            .create_group_with_options_and_telemetry(
                "drained retry intent",
                &[],
                crate::AppCreateGroupOptions::default(),
                &telemetry,
            )
            .await
            .unwrap();
        client
            .create_group_with_options_and_telemetry(
                "drained retry bystander",
                &[],
                crate::AppCreateGroupOptions::default(),
                &telemetry,
            )
            .await
            .unwrap();

        let effects = marmot_account::AccountDeviceEffects {
            events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id: created.group_id,
                epoch: cgka_traits::EpochId(2),
                actor: Some(cgka_traits::MemberId::new(
                    hex::decode(&account.account_id_hex).unwrap(),
                )),
                change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
                origin_commit_id: None,
            }],
            ..Default::default()
        };
        relay.fail_next_subscribe();
        client
            .observe_drained_session_events(&effects)
            .await
            .expect_err("the injected group subscription rebuild must fail the drain");
        assert!(client.has_pending_runtime_group_subscription_refresh());

        // Nothing is left to re-derive the intent from: the drained batch that
        // dirtied the routes is consumed, and the routing table reports no
        // further change, so the armed flag is the only surviving re-fire edge.
        assert!(!client.refresh_group_routes().unwrap().routing_changed);

        let subscriptions_before = relay.subscription_count();
        assert!(
            !client
                .retry_pending_runtime_group_subscription_refresh()
                .await
                .unwrap()
        );
        assert!(!client.has_pending_runtime_group_subscription_refresh());
        assert!(
            relay.subscription_count() > subscriptions_before,
            "the armed retry must actually re-issue the rebuild the drain lost"
        );
    }
}

#[cfg(test)]
mod transport_cursor_tests {
    use super::{clamped_transport_cursor, next_transport_cursor};
    use crate::CursorPersistence;

    const SKEW: u64 = 5 * 60;
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn frozen_policy_never_moves_the_cursor() {
        // A wake-collection runtime ingests but must
        // not ratchet the durable floor. Under `Frozen` the cursor is exactly
        // the loaded value regardless of what the delivery carries — a newer
        // in-range timestamp, an older one, or a far-future one.
        let loaded = Some(NOW - 100);
        assert_eq!(
            next_transport_cursor(CursorPersistence::Frozen, loaded, NOW, NOW, SKEW),
            loaded,
            "a newer in-range delivery must not advance a frozen cursor"
        );
        assert_eq!(
            next_transport_cursor(CursorPersistence::Frozen, loaded, NOW - 500, NOW, SKEW),
            loaded,
            "an older delivery must not move a frozen cursor either"
        );
        // A store that has never advanced stays `None`: `Frozen` means "never
        // advance", not "initialize". The save-time merge treats a `None`
        // in-memory side as "keep stored", so this can never wipe a
        // concurrently-advanced durable cursor.
        assert_eq!(
            next_transport_cursor(CursorPersistence::Frozen, None, NOW, NOW, SKEW),
            None,
            "a frozen cursor that never existed must stay absent"
        );
    }

    #[test]
    fn advance_policy_is_the_unchanged_clamped_monotonic_max() {
        // `Advance` is byte-for-byte the historical behavior: delegate to
        // `clamped_transport_cursor` (monotonic max with the mdk#182
        // future-skew clamp and poison heal, pinned by the tests below).
        assert_eq!(
            next_transport_cursor(CursorPersistence::Advance, Some(NOW - 100), NOW, NOW, SKEW),
            Some(NOW),
            "an in-range delivery advances the cursor under Advance"
        );
        assert_eq!(
            next_transport_cursor(CursorPersistence::Advance, None, NOW, NOW, SKEW),
            Some(NOW),
            "a first delivery initializes the cursor under Advance"
        );
        let poisoned = NOW + 10 * 365 * 24 * 60 * 60;
        assert_eq!(
            next_transport_cursor(CursorPersistence::Advance, Some(NOW), poisoned, NOW, SKEW),
            Some(NOW + SKEW),
            "the future-skew clamp still bounds a hostile created_at"
        );
    }

    #[test]
    fn in_range_timestamp_advances_cursor_unchanged() {
        // A normal present-dated message advances the cursor to its own value.
        assert_eq!(
            clamped_transport_cursor(Some(NOW - 100), NOW, NOW, SKEW),
            NOW
        );
        assert_eq!(clamped_transport_cursor(None, NOW, NOW, SKEW), NOW);
    }

    #[test]
    fn far_future_timestamp_is_clamped_to_now_plus_skew() {
        // A malicious far-future created_at must not move the cursor past
        // now + skew, so the relay `since` filter can never jump into the
        // future and halt reception (mdk#182).
        let poisoned = NOW + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
        assert_eq!(
            clamped_transport_cursor(Some(NOW - 100), poisoned, NOW, SKEW),
            NOW + SKEW
        );
        assert_eq!(
            clamped_transport_cursor(None, poisoned, NOW, SKEW),
            NOW + SKEW
        );
    }

    #[test]
    fn cursor_stays_monotonic_against_older_timestamps() {
        // An older message never rewinds the persisted cursor.
        assert_eq!(
            clamped_transport_cursor(Some(NOW), NOW - 500, NOW, SKEW),
            NOW
        );
    }

    #[test]
    fn timestamp_just_inside_skew_window_is_accepted() {
        let within = NOW + SKEW - 1;
        assert_eq!(
            clamped_transport_cursor(Some(NOW), within, NOW, SKEW),
            within
        );
    }

    #[test]
    fn already_poisoned_cursor_is_healed_down_not_preserved() {
        // A cursor poisoned before this guard existed (a far-future value
        // persisted by a vulnerable version) must not be preserved forever by
        // the monotonic max. When a present-dated message arrives, the stored
        // cursor is clamped back to now + skew and then folded in, so the
        // account recovers to wall-clock instead of staying degraded
        // (mdk#182 — blocking adversarial finding).
        let poisoned = NOW + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
        assert_eq!(
            clamped_transport_cursor(Some(poisoned), NOW, NOW, SKEW),
            NOW + SKEW,
            "a present-dated message must heal a poisoned future cursor down to now + skew"
        );
        // Once wall-clock advances past the healed value, a present-dated
        // message advances the cursor normally, proving the account is no
        // longer stuck in the future.
        let healed = clamped_transport_cursor(Some(poisoned), NOW, NOW, SKEW);
        let later = healed + 1_000;
        assert_eq!(
            clamped_transport_cursor(Some(healed), later, later, SKEW),
            later,
            "after healing, the cursor tracks present-dated messages again"
        );
    }
}

/// Wall clock for the epoch-stall detector's two time gates.
///
/// Wall clock rather than [`Instant`] because both gates have to survive a
/// restart: a device wedged for six hours must not buy a re-arm by being
/// force-killed, and a monotonic clock that restarts at zero would hand it one.
/// Read here rather than inside the detector, which stays I/O-free so its
/// policy can be unit-tested in isolation.
pub(crate) fn epoch_stall_now_ms() -> u64 {
    crate::notifications::unix_now_ms().max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::DrainCounts;
    use super::{
        EpochBackfillReplayOutcome, TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS,
        TransportReconciliationWork, epoch_backfill_terminal_rows, incomplete_full_history_repair,
        order_reconciliation_pass, reconciliation_start_after_cursor,
        transport_reconciliation_record,
    };
    use crate::tests::{
        ScriptedPushRelayClient, armed_group_ids, bounded_epoch_backfill_config,
        client_on_app_relay_plane, make_group_terminal,
    };
    use crate::{MarmotApp, SyncFailureStage, SyncSummary};
    use marmot_account::AccountHome;
    use marmot_forensics::EpochBackfillActivationOutcome;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    /// Contract fixture: provide exhaustive, durably admitted endpoint proof.
    /// Scripted SDK EOSE is deliberately insufficient to produce this proof.
    fn qualify_epoch_obligation(
        storage: &storage_sqlite::SqliteAccountStorage,
        grant: &crate::client::recovery::AttemptGrant,
        group: &cgka_traits::GroupId,
    ) -> bool {
        use storage_sqlite::{
            RecoveryEligibility, RecoveryEndpointCheckpoint, RecoveryScopeCheckpoint,
            RecoveryScopeOutcome,
        };
        let obligation = grant
            .plan()
            .unwrap()
            .iter()
            .find(|obligation| {
                obligation.cause == storage_sqlite::RecoveryCause::EpochGap
                    && obligation.group_id.as_ref() == Some(group)
            })
            .unwrap();
        let checkpoints = obligation
            .scopes
            .iter()
            .map(|scope| RecoveryScopeCheckpoint {
                token: scope.token.clone(),
                retained_known_event: false,
                endpoints: scope
                    .goal
                    .required_endpoints
                    .iter()
                    .map(|endpoint| RecoveryEndpointCheckpoint {
                        endpoint: endpoint.clone(),
                        outcome: RecoveryScopeOutcome::Covered,
                        exhaustive: true,
                        admission_complete: true,
                        first_boundary: false,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        storage
            .checkpoint_recovery_obligation(
                &grant.fence,
                grant.reservation.attempt_serial,
                obligation.id,
                &checkpoints,
                RecoveryEligibility::Retry,
            )
            .unwrap()
    }

    #[tokio::test]
    async fn contested_fork_and_capacity_facts_keep_independent_recovery_demand() {
        use crate::client::epoch_stall::BackfillDecision;
        use cgka_traits::ingest::{DeferralLineage, IngestOutcome};
        use marmot_forensics::{EpochBackfillExecutionSeam, EpochStallBackfillTrigger};
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            bounded_epoch_backfill_config().with_dev_epoch_backfill_retry_backoff_ms(15_000),
        )
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client.create_group("evidence policy", &[]).await.unwrap();
        let epoch = client.runtime.group_record(&group).unwrap().epoch.0;
        let storage = app.account_storage("alice").unwrap();
        let fork = IngestOutcome::TransportDeferred {
            group_id: group.clone(),
            lineage: DeferralLineage::ContestedFork,
        };
        for index in 0..10 {
            client.detect_epoch_stall(
                Some(group.clone()),
                &format!("fork-{index}"),
                &fork,
                cgka_traits::transport::Timestamp(crate::unix_now_seconds()),
            );
        }
        assert!(client.pending_convergence_groups.contains(&group));
        assert!(
            storage.pending_epoch_backfill_intents().unwrap().is_empty(),
            "a pure fork schedules local work without inventing a missing input"
        );
        client.apply_backfill_decision(
            &group,
            epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let grant = client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let retry = storage.recovery_retry_state().unwrap();
        drop(grant);
        client.pending_convergence_groups.clear();
        client.detect_epoch_stall(
            Some(group.clone()),
            "fork-again",
            &fork,
            cgka_traits::transport::Timestamp(crate::unix_now_seconds()),
        );
        assert!(client.pending_convergence_groups.contains(&group));
        assert_eq!(storage.pending_epoch_backfill_intents().unwrap().len(), 1);
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        assert!(
            client
                .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
                .unwrap()
                .is_none()
        );

        // A paced local reassessment can coincide with actual refusal. The
        // local-work decision must not discard the separate pressure fact.
        client.apply_backfill_decision(
            &group,
            epoch,
            BackfillDecision::Reassess,
            EpochStallBackfillTrigger::ResourceRefusal,
        );
        let demand = storage
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == storage_sqlite::RecoveryCause::EpochGap)
            .unwrap();
        assert_eq!(
            demand.eligibility,
            storage_sqlite::RecoveryEligibility::WaitingCapacity
        );
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        assert!(client.pending_convergence_groups.contains(&group));
    }

    /// A commit or retry can release several retained messages in one effects batch.
    /// Each row needs its own source identity, including when no relay envelope
    /// triggered the batch. Replay must remain idempotent across observation seams.
    enum ReleasedBatchObservation {
        Scheduled,
        Send,
        Inbound,
    }

    async fn assert_released_message_batch_projects(observation: ReleasedBatchObservation) {
        use crate::messages::{AppMessageIntent, build_inner_event};
        use crate::{TimelineMessageQuery, unix_now_seconds};
        use cgka_traits::MemberId;
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://batch-projection.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group_id = client.create_group("batch projection", &[]).await.unwrap();
        let mut effects = marmot_account::AccountDeviceEffects::default();
        let mut sources = HashMap::new();
        for index in 0..3 {
            let payload = crate::messages::encode_inner_event(
                &build_inner_event(
                    &AppMessageIntent::Chat {
                        content: format!("released message {index}"),
                    },
                    &account.account_id_hex,
                    unix_now_seconds(),
                )
                .unwrap(),
            )
            .unwrap();
            let sent = client
                .runtime
                .send(cgka_traits::engine::SendIntent::AppMessage {
                    group_id: group_id.clone(),
                    payload: payload.clone(),
                    expected_epoch: None,
                })
                .await
                .unwrap();
            assert!(sent.failures.is_empty());
            sources.insert(
                format!("released message {index}"),
                hex::encode(sent.reports[0].message_id.as_slice()),
            );
            effects
                .events
                .push(cgka_traits::engine::GroupEvent::MessageReceived {
                    authority: None,
                    group_id: group_id.clone(),
                    message_id: sent.reports[0].message_id.clone(),
                    sender: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
                    epoch: client.runtime.group_record(&group_id).unwrap().epoch,
                    payload,
                    retention: None,
                });
        }
        // A corrupt sender profile must not lose any already-ingested message,
        // including during drained-event replay below.
        app.shared_storage()
            .unwrap()
            .put_public_directory_user(&storage_sqlite::PublicDirectoryUserRecord {
                account_id_hex: account.account_id_hex.clone(),
                npub: String::new(),
                profile_json: Some("{".into()),
                relay_lists_json: serde_json::to_string(&crate::AccountRelayListStatus::empty())
                    .unwrap(),
                key_package_json: None,
                event_id_hex: None,
                event_kind: None,
                event_created_at: None,
                follows: Vec::new(),
            })
            .unwrap();
        assert!(
            app.display_names_for_account_ids(std::slice::from_ref(&account.account_id_hex))
                .is_err()
        );
        match observation {
            ReleasedBatchObservation::Scheduled => {
                client
                    .observe_scheduled_convergence_effects(&group_id, &effects)
                    .await
                    .unwrap();
            }
            ReleasedBatchObservation::Send => {
                client.observe_send_applied_effects(&effects).await.unwrap();
            }
            ReleasedBatchObservation::Inbound => {
                // Timestamp diagnostics must not read an unrelated retained row.
                // Corruption there must not prevent these authenticated effects
                // from projecting, including every later event in the batch.
                use cgka_traits::storage::MessageStorage;
                let storage = app.account_storage("alice").unwrap();
                let id = &effects
                    .events
                    .iter()
                    .find_map(|event| match event {
                        cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. } => {
                            Some(message_id.clone())
                        }
                        _ => None,
                    })
                    .unwrap();
                let mut record = storage.get_message(id).unwrap();
                record.payload = vec![0xff];
                storage.put_message(&record).unwrap();
                // Simulate the explicit fetch and SDK notification overlap.
                // Both observations carry the same authenticated event identities.
                for _ in 0..2 {
                    client
                        .observe_account_device_effects(
                            &effects,
                            &mut SyncSummary::default(),
                            &sources["released message 2"],
                            unix_now_seconds(),
                        )
                        .await
                        .unwrap();
                }
            }
        }
        let timeline = app
            .timeline_messages_with_query(
                "alice",
                TimelineMessageQuery {
                    group_id_hex: Some(hex::encode(group_id.as_slice())),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(timeline.messages.len(), 3);
        for message in &timeline.messages {
            assert_eq!(
                message.source_message_id_hex.as_ref(),
                sources.get(&message.plaintext)
            );
        }
        let messages = app.messages("alice").unwrap();
        assert_eq!(messages.len(), 3);
        for index in 0..3 {
            assert!(
                messages
                    .iter()
                    .any(|m| m.plaintext == format!("released message {index}"))
            );
        }
        // Reopen uses the drained-event seam. Its stable identities must agree
        // with live projection, so the same durable events cannot create duplicates.
        client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        let replayed = app.messages("alice").unwrap();
        assert_eq!(replayed.len(), messages.len());
        for (actual, mut expected) in replayed.into_iter().zip(messages) {
            // Re-observation stamps a fresh local receipt time. Stable message
            // identity, insertion order and contents must survive replay even
            // when it crosses a wall-clock second boundary.
            expected.received_at = actual.received_at;
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn scheduled_convergence_projects_every_released_message() {
        assert_released_message_batch_projects(ReleasedBatchObservation::Scheduled).await;
    }

    #[tokio::test]
    async fn send_applied_effects_project_every_released_message() {
        assert_released_message_batch_projects(ReleasedBatchObservation::Send).await;
    }

    #[tokio::test]
    async fn inbound_effects_project_every_released_message() {
        assert_released_message_batch_projects(ReleasedBatchObservation::Inbound).await;
    }

    fn armed_backfill(
        group_id: &cgka_traits::GroupId,
        stalled_epoch: u64,
    ) -> Vec<storage_sqlite::StoredEpochBackfillIntent> {
        vec![storage_sqlite::StoredEpochBackfillIntent {
            group_id_hex: hex::encode(group_id.as_slice()),
            stalled_epoch,
        }]
    }

    #[tokio::test]
    async fn released_receipts_preserve_only_the_surviving_unsaved_tail() {
        use cgka_traits::storage::MessageStorage;
        use cgka_traits::{EpochId, MessageId, MessageRecord, MessageState};

        for (pending_count, released_indices, expected_count) in [
            (3, vec![0, 3], 2),
            (0, vec![0], 0),
            (2, vec![3, 4], 0),
            (5, vec![0, 3], 3),
        ] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
                .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
            let mut client = app.client("alice").await.unwrap();
            let group = client.create_group("seen tail", &[]).await.unwrap();
            let storage = app.account_storage("alice").unwrap();
            let ids = (0..5)
                .map(|i| MessageId::new(vec![i; 32]))
                .collect::<Vec<_>>();
            let ring = ids
                .iter()
                .map(|id| hex::encode(id.as_slice()))
                .collect::<Vec<_>>();
            client.state.seen_events = ring.clone();
            client.seen_events_index = ring.iter().cloned().collect();
            client.pending_seen_event_count = pending_count;
            let expected_tail = ring[5 - pending_count..]
                .iter()
                .filter(|id| !released_indices.iter().any(|index| **id == ring[*index]))
                .cloned()
                .collect::<Vec<_>>();
            for index in &released_indices {
                let raw = MessageRecord {
                    id: ids[*index].clone(),
                    group_id: group.clone(),
                    epoch: EpochId(0),
                    state: MessageState::PeelDeferred,
                    payload: Vec::new(),
                    deferred_peel: None,
                };
                storage.put_message(&raw).unwrap();
                storage.release_message_for_replay(&raw).unwrap();
            }
            client.reconcile_released_transport_receipts().unwrap();
            assert_eq!(client.pending_seen_event_count, expected_count);
            let start = client.state.seen_events.len() - client.pending_seen_event_count;
            assert_eq!(client.state.seen_events[start..], expected_tail);
            assert_eq!(client.seen_events_index.len(), 5 - released_indices.len());
        }
    }

    #[tokio::test]
    async fn released_backfill_restore_preserves_owned_retry_progress_and_merges_new_work() {
        use marmot_forensics::EpochBackfillExecutionSeam;
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://backfill.example",
            bounded_epoch_backfill_config().with_dev_epoch_backfill_retry_backoff_ms(15_000),
        )
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let first = client.create_group("first demand", &[]).await.unwrap();
        let second = client.create_group("second demand", &[]).await.unwrap();
        let buffered = client
            .create_group("failed persistence", &[])
            .await
            .unwrap();
        let added = client
            .create_group("new durable demand", &[])
            .await
            .unwrap();
        let storage = app.account_storage("alice").unwrap();
        let intent =
            |group: &cgka_traits::GroupId, epoch| storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: epoch,
            };
        storage
            .arm_epoch_backfill_intents(&[intent(&first, 5), intent(&second, 7)])
            .unwrap();
        let grant = client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        drop(grant);
        let retry = storage.recovery_retry_state().unwrap();
        client
            .pending_recovery_arm_writes
            .insert(buffered.clone(), 8);
        storage
            .arm_epoch_backfill_intents(&[intent(&added, 3)])
            .unwrap();
        client.restore_persisted_epoch_backfill_intents(
            storage.pending_epoch_backfill_intents().unwrap(),
        );
        assert_eq!(client.pending_recovery_arm_writes.get(&buffered), Some(&8));
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
        // Older observations cannot regress epochs; a new observation joins
        // the existing row without resetting the account's paid retry cost.
        storage
            .arm_epoch_backfill_intents(&[intent(&first, 4), intent(&second, 9), intent(&added, 2)])
            .unwrap();
        assert!(
            client
                .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
                .unwrap()
                .is_none()
        );
        assert!(client.pending_recovery_arm_writes.is_empty());
        let epochs = storage
            .pending_epoch_backfill_intents()
            .unwrap()
            .into_iter()
            .map(|intent| (intent.group_id_hex, intent.stalled_epoch))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            epochs,
            HashMap::from([
                (hex::encode(first.as_slice()), 5),
                (hex::encode(second.as_slice()), 9),
                (hex::encode(buffered.as_slice()), 8),
                (hex::encode(added.as_slice()), 3),
            ])
        );
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);
    }

    #[tokio::test]
    async fn released_backfill_reload_retries_after_consumption_without_reopen() {
        use cgka_traits::storage::MessageStorage;
        use cgka_traits::{EpochId, MessageId, MessageRecord, MessageState};

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("reload failure", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let raw = MessageRecord {
            id: MessageId::new(vec![0xfd; 32]),
            group_id: group.clone(),
            epoch: EpochId(client.group_mls_state(&group).unwrap().epoch),
            state: MessageState::PeelDeferred,
            payload: Vec::new(),
            deferred_peel: None,
        };
        let id_hex = hex::encode(raw.id.as_slice());
        client.seen_events_index.insert(id_hex.clone());
        client.state.seen_events.push(id_hex.clone());
        storage.put_message(&raw).unwrap();
        storage.release_message_for_replay(&raw).unwrap();
        client.fail_next_released_backfill_reload = true;
        assert!(matches!(
            client.reconcile_released_transport_receipts(),
            Err(crate::AppError::Storage(
                cgka_traits::storage::StorageError::Busy(_)
            ))
        ));
        assert!(client.released_backfill_reload_pending);
        assert!(!client.seen_events_index.contains(&id_hex));
        assert!(!client.state.seen_events.contains(&id_hex));
        assert!(
            storage
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert_eq!(storage.pending_epoch_backfill_intents().unwrap().len(), 1);
        assert!(
            client.has_pending_epoch_backfill(),
            "durable demand remains visible even when the advisory reload fails"
        );

        // No new release and no reopen: the same client must retry the read
        // after acknowledgment has already emptied the durable journal.
        assert!(
            client
                .reconcile_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert!(client.has_pending_epoch_backfill());
        assert!(!client.released_backfill_reload_pending);
        let pending = storage.pending_epoch_backfill_intents().unwrap();
        assert_eq!(pending[0].group_id_hex, hex::encode(group.as_slice()));
        assert_eq!(pending[0].stalled_epoch, raw.epoch.0);

        // Successful reload disarms the flag: steady-state empty reconciles
        // must not pay for a full pending-intent read on every delivery.
        client.fail_next_released_backfill_reload = true;
        assert!(
            client
                .reconcile_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert!(client.fail_next_released_backfill_reload);
    }

    #[tokio::test]
    async fn older_backfill_completion_preserves_released_intent_across_reopen() {
        use cgka_traits::storage::MessageStorage;
        use cgka_traits::{EpochId, MessageId, MessageRecord, MessageState};
        use marmot_forensics::EpochBackfillExecutionSeam;
        for epoch_increment in [0, 1] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let app = MarmotApp::with_relay_and_config(
                dir.path(),
                "wss://backfill.example",
                bounded_epoch_backfill_config(),
            )
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
            let mut client = client_on_app_relay_plane(&app, "alice").await;
            let group = client
                .create_group("release during replay", &[])
                .await
                .unwrap();
            let epoch = client.group_mls_state(&group).unwrap().epoch;
            let storage = app.account_storage("alice").unwrap();
            storage
                .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                    group_id_hex: hex::encode(group.as_slice()),
                    stalled_epoch: epoch,
                }])
                .unwrap();
            let grant = client
                .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
                .unwrap()
                .unwrap();
            let raw = MessageRecord {
                id: MessageId::new(vec![0xfe; 32]),
                group_id: group.clone(),
                epoch: EpochId(epoch + epoch_increment),
                state: MessageState::PeelDeferred,
                payload: Vec::new(),
                deferred_peel: None,
            };
            storage.put_message(&raw).unwrap();
            storage.release_message_for_replay(&raw).unwrap();
            client.reconcile_released_transport_receipts().unwrap();
            assert!(
                !qualify_epoch_obligation(&storage, &grant, &group),
                "old qualified coverage cannot clear newly released input"
            );
            let retry = storage.recovery_retry_state().unwrap();
            drop(grant);
            drop(client);
            let mut reopened = client_on_app_relay_plane(&app, "alice").await;
            let pending = storage.pending_epoch_backfill_intents().unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].stalled_epoch, epoch + epoch_increment);
            assert_eq!(
                storage.recovery_retry_state().unwrap().attempt_serial,
                retry.attempt_serial
            );
            let mut permit = crate::client::recovery::ExplicitRecoveryPermit::default();
            let next = reopened
                .authorize_account_recovery(
                    Some(&mut permit),
                    EpochBackfillExecutionSeam::ExplicitCatchUp,
                )
                .unwrap()
                .unwrap();
            assert!(qualify_epoch_obligation(&storage, &next, &group));
            assert!(storage.pending_epoch_backfill_intents().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn older_backfill_completion_still_clears_groups_without_new_work() {
        use marmot_forensics::EpochBackfillExecutionSeam;
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://backfill.example",
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let changed = client
            .create_group("changed obligation", &[])
            .await
            .unwrap();
        let finished = client
            .create_group("compatible obligation", &[])
            .await
            .unwrap();
        let storage = app.account_storage("alice").unwrap();
        let intent =
            |group: &cgka_traits::GroupId, epoch| storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: epoch,
            };
        storage
            .arm_epoch_backfill_intents(&[intent(&changed, 0), intent(&finished, 0)])
            .unwrap();
        let grant = client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        storage
            .arm_epoch_backfill_intents(&[intent(&changed, 1)])
            .unwrap();
        assert!(!qualify_epoch_obligation(&storage, &grant, &changed));
        assert!(
            qualify_epoch_obligation(&storage, &grant, &finished),
            "an unrelated obligation revision cannot erase compatible proof"
        );
        let remaining = storage.pending_epoch_backfill_intents().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].group_id_hex, hex::encode(changed.as_slice()));
        assert_eq!(remaining[0].stalled_epoch, 1);
    }

    #[tokio::test]
    async fn terminal_group_backfill_intents_are_not_rearmed_on_restore() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let live = client.create_group("still a member", &[]).await.unwrap();
        let removed = client.create_group("removed device", &[]).await.unwrap();
        let disbanded = client.create_group("disbanded group", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();

        let mut armed = armed_backfill(&live, 4);
        armed.extend(armed_backfill(&removed, 5));
        armed.extend(armed_backfill(&disbanded, 6));
        client.persist_epoch_backfill_intent(&armed).unwrap();
        make_group_terminal(&client, &removed, false);
        make_group_terminal(&client, &disbanded, true);

        client.restore_persisted_epoch_backfill_intents(
            storage.pending_epoch_backfill_intents().unwrap(),
        );

        assert_eq!(armed_group_ids(&client), vec![live.clone()]);
        let remaining = storage.pending_epoch_backfill_intents().unwrap();
        assert_eq!(
            remaining
                .iter()
                .map(|intent| intent.group_id_hex.clone())
                .collect::<Vec<_>>(),
            vec![hex::encode(live.as_slice())],
            "a group this device is terminal in must not keep a durable recovery marker"
        );
    }

    /// The mixed case, observed through the production entry point. Retry
    /// pacing is the seam's own way of stopping short of a replay, so the drop
    /// is visible without paying for one: the live group survives the pass and
    /// is what the cooldown is still holding.
    #[tokio::test]
    async fn a_backfill_run_drops_every_group_that_became_terminal() {
        use marmot_forensics::EpochBackfillExecutionSeam;

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let live = client.create_group("still a member", &[]).await.unwrap();
        let departed = client.create_group("departed", &[]).await.unwrap();
        let queued_departed = client.create_group("queued departed", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let epoch = client.group_mls_state(&live).unwrap().epoch;

        let mut primary = armed_backfill(&live, epoch);
        primary.extend(armed_backfill(&departed, epoch));
        let queued = armed_backfill(&queued_departed, epoch);
        client.persist_epoch_backfill_intent(&primary).unwrap();
        client.persist_epoch_backfill_intent(&queued).unwrap();
        let grant = client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        drop(grant);
        let retry = storage.recovery_retry_state().unwrap();

        // Both groups turn terminal only after their intents were armed.
        make_group_terminal(&client, &departed, false);
        make_group_terminal(&client, &queued_departed, true);

        assert!(matches!(
            client
                .run_pending_epoch_backfill(EpochBackfillExecutionSeam::Maintenance)
                .await
                .unwrap(),
            crate::EpochBackfillRunOutcome::Deferred
        ));
        assert_eq!(
            armed_group_ids(&client),
            vec![live.clone()],
            "only the group this device is still a member of may stay armed"
        );
        assert_eq!(
            storage.recovery_retry_state().unwrap(),
            retry,
            "terminal cleanup does not forgive the live group's retry cost"
        );
        assert_eq!(
            storage
                .pending_epoch_backfill_intents()
                .unwrap()
                .iter()
                .map(|intent| intent.group_id_hex.clone())
                .collect::<Vec<_>>(),
            vec![hex::encode(live.as_slice())],
            "terminal groups must not keep a durable recovery marker"
        );
    }

    /// The production restore call site is the released-receipt seam, which
    /// already holds an account storage handle. Exercise it end to end so the
    /// durable clear cannot regress into a self-deadlock.
    #[tokio::test]
    async fn released_receipt_restore_retires_a_terminal_group_intent() {
        use cgka_traits::storage::MessageStorage;
        use cgka_traits::{EpochId, MessageId, MessageRecord, MessageState};

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let departed = client.create_group("departed", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let epoch = client.group_mls_state(&departed).unwrap().epoch;
        client
            .persist_epoch_backfill_intent(&armed_backfill(&departed, epoch))
            .unwrap();
        make_group_terminal(&client, &departed, false);

        let raw = MessageRecord {
            id: MessageId::new(vec![0xfc; 32]),
            group_id: departed.clone(),
            epoch: EpochId(epoch),
            state: MessageState::PeelDeferred,
            payload: Vec::new(),
            deferred_peel: None,
        };
        storage.put_message(&raw).unwrap();
        storage.release_message_for_replay(&raw).unwrap();
        client.reconcile_released_transport_receipts().unwrap();

        assert!(
            !client.has_pending_epoch_backfill(),
            "a released receipt must not re-arm a group this device is terminal in"
        );
        assert!(storage.pending_epoch_backfill_intents().unwrap().is_empty());
    }

    /// A wholly-terminal owner must stop reading as pending *before* the
    /// account-wide cooldown gate, or it keeps `has_pending_epoch_backfill`
    /// true for a whole backoff window — which is also what arms `next_event`
    /// summaries and the forensic audit-upload schedule.
    #[tokio::test]
    async fn wholly_terminal_intent_is_not_pending_under_retry_pacing() {
        use marmot_forensics::EpochBackfillExecutionSeam;

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let departed = client.create_group("departed", &[]).await.unwrap();
        let epoch = client.group_mls_state(&departed).unwrap().epoch;
        client
            .persist_epoch_backfill_intent(&armed_backfill(&departed, epoch))
            .unwrap();
        let grant = client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        drop(grant);
        make_group_terminal(&client, &departed, false);

        // Independent account-history demand may still be selected. Terminal
        // retirement must remove this group's debt regardless of that outcome.
        let _ = client
            .run_pending_epoch_backfill(EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap();
        assert!(!client.has_pending_epoch_backfill());
        assert!(!client.has_pending_epoch_backfill());
        assert!(
            app.account_storage("alice")
                .unwrap()
                .pending_epoch_backfill_intents()
                .unwrap()
                .is_empty()
        );
    }

    /// The durable arm can sit at a later epoch than the in-memory intent
    /// holding it, so the clear must not key off the intent's epoch. Retiring
    /// the group's row retires it whatever epoch storage holds.
    #[tokio::test]
    async fn terminal_group_row_clears_whatever_epoch_storage_holds() {
        use marmot_forensics::EpochBackfillExecutionSeam;

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let departed = client.create_group("departed", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();

        client
            .persist_epoch_backfill_intent(&armed_backfill(&departed, 5))
            .unwrap();
        client
            .pending_recovery_arm_writes
            .insert(departed.clone(), 5);
        // A later durable observation supersedes an older failed-write fact.
        // Terminal retirement must remove both without relying on epoch equality.
        storage
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(departed.as_slice()),
                stalled_epoch: 9,
            }])
            .unwrap();
        make_group_terminal(&client, &departed, false);

        // Independent account-history demand may still be selected. Terminal
        // retirement must remove this group's debt regardless of that outcome.
        let _ = client
            .run_pending_epoch_backfill(EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap();
        assert!(!client.has_pending_epoch_backfill());
        assert!(
            storage.pending_epoch_backfill_intents().unwrap().is_empty(),
            "the terminal group keeps no intent at any epoch"
        );
    }

    /// Dropping the intent and retiring the recovery run are two invariants. A
    /// group this device is terminal in must keep neither: an orphaned run goes
    /// on accumulating fruitless-completion evidence, and its durable evidence
    /// row is retired by nothing else.
    #[tokio::test]
    async fn dropping_a_terminal_intent_also_retires_its_recovery_run() {
        use marmot_forensics::{EpochBackfillExecutionSeam, EpochStallBackfillTrigger};

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let departed = client.create_group("departed", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let epoch = client.group_mls_state(&departed).unwrap().epoch;

        // The detector opens the run; `apply_backfill_decision` only consumes
        // the decision it returns.
        let decision = client.epoch_stall.observe_resource_refusal(
            departed.clone(),
            cgka_traits::EpochId(epoch),
            crate::client::sync::epoch_stall_now_ms(),
        );
        client.apply_backfill_decision(
            &departed,
            epoch,
            decision,
            EpochStallBackfillTrigger::ResourceRefusal,
        );
        assert!(
            client.epoch_stall.wedge_evidence(&departed).is_some(),
            "the arm must open a recovery run to retire"
        );
        assert_eq!(
            storage.epoch_stall_evidence().unwrap().len(),
            1,
            "the arm must persist the run's evidence row"
        );

        make_group_terminal(&client, &departed, false);
        // Independent account-history demand may still be selected. Terminal
        // retirement must remove this group's debt regardless of that outcome.
        let _ = client
            .run_pending_epoch_backfill(EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap();
        assert!(!client.has_pending_epoch_backfill());

        assert!(
            client.epoch_stall.wedge_evidence(&departed).is_none(),
            "the in-memory recovery run must be retired with the intent"
        );
        assert!(
            storage.epoch_stall_evidence().unwrap().is_empty(),
            "the durable evidence row must be retired with the intent"
        );
    }

    /// A terminal transition during an authorized attempt invalidates its old
    /// coverage and retires both demand and stall evidence, even without EOSE.
    #[tokio::test]
    async fn a_replay_that_ends_terminal_escalates_nothing_and_leaves_no_evidence() {
        use crate::client::epoch_stall::BackfillDecision;
        use marmot_forensics::{EpochBackfillExecutionSeam, EpochStallBackfillTrigger};
        for (disbanded, admit_prefix) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let dir = tempfile::tempdir().unwrap();
            let relay = Arc::new(ScriptedPushRelayClient::default());
            let (app, mut client, route) = crate::tests::undecryptable_probe_route(
                &dir,
                &relay,
                bounded_epoch_backfill_config(),
            )
            .await;
            let group = route.group_id.clone();
            let epoch = client.group_mls_state(&group).unwrap().epoch;
            let storage = app.account_storage("alice").unwrap();
            let _ = client.epoch_stall.observe_resource_refusal(
                group.clone(),
                cgka_traits::EpochId(epoch),
                super::epoch_stall_now_ms(),
            );
            client.apply_backfill_decision(
                &group,
                epoch,
                BackfillDecision::Arm,
                EpochStallBackfillTrigger::UndecryptableThreshold,
            );
            assert_eq!(storage.epoch_stall_evidence().unwrap().len(), 1);
            let grant = client
                .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
                .unwrap()
                .unwrap();
            let admitted_id = if admit_prefix {
                let delivery = route.probe(
                    crate::unix_now_seconds().saturating_sub(1),
                    "terminal-admitted-prefix",
                );
                let id = hex::encode(delivery.message.id.as_slice());
                client.ingest_received_delivery(delivery).await.unwrap();
                Some(id)
            } else {
                None
            };
            make_group_terminal(&client, &group, disbanded);
            client.drop_settled_epoch_backfill_intents();
            assert!(!qualify_epoch_obligation(&storage, &grant, &group));
            assert!(client.pending_epoch_stall_escalations.is_empty());
            assert!(client.epoch_stall.wedge_evidence(&group).is_none());
            assert!(storage.epoch_stall_evidence().unwrap().is_empty());
            assert!(storage.pending_epoch_backfill_intents().unwrap().is_empty());
            if let Some(id) = admitted_id {
                assert!(
                    app.load_state("alice").unwrap().seen_events.contains(&id),
                    "terminal retirement cannot discard the admitted prefix"
                );
            }
        }
    }

    /// The retry the drop's ordering exists for. A failed durable retire must
    /// leave the intent row behind, because that row is the only thing that
    /// brings the group back through restore into the drop — clearing it anyway
    /// would strand the evidence row with nothing left to retire it.
    #[tokio::test]
    async fn a_failed_retire_keeps_the_intent_row_so_the_next_restore_retries() {
        use marmot_forensics::EpochStallBackfillTrigger;

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let departed = client.create_group("departed", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        let epoch = client.group_mls_state(&departed).unwrap().epoch;

        let decision = client.epoch_stall.observe_resource_refusal(
            departed.clone(),
            cgka_traits::EpochId(epoch),
            crate::client::sync::epoch_stall_now_ms(),
        );
        client.apply_backfill_decision(
            &departed,
            epoch,
            decision,
            EpochStallBackfillTrigger::ResourceRefusal,
        );
        assert_eq!(storage.pending_epoch_backfill_intents().unwrap().len(), 1);
        assert_eq!(storage.epoch_stall_evidence().unwrap().len(), 1);
        make_group_terminal(&client, &departed, false);

        client.fail_next_terminal_recovery_retire = true;
        client.restore_persisted_epoch_backfill_intents(
            storage.pending_epoch_backfill_intents().unwrap(),
        );
        assert!(
            armed_group_ids(&client).contains(&departed),
            "failed retirement must remain visible to the authoritative owner"
        );
        assert_eq!(
            storage.pending_epoch_backfill_intents().unwrap().len(),
            1,
            "a failed retire must keep the intent row that drives the retry"
        );
        assert_eq!(
            storage.epoch_stall_evidence().unwrap().len(),
            1,
            "the evidence row the retire failed on is still there to retire"
        );

        // The next restore re-admits the surviving row and completes both.
        client.restore_persisted_epoch_backfill_intents(
            storage.pending_epoch_backfill_intents().unwrap(),
        );
        assert!(
            storage.pending_epoch_backfill_intents().unwrap().is_empty(),
            "the retried pass clears the intent row"
        );
        assert!(
            storage.epoch_stall_evidence().unwrap().is_empty(),
            "the retried pass retires the durable evidence row"
        );
        assert!(
            client.epoch_stall.wedge_evidence(&departed).is_none(),
            "the retried pass retires the in-memory run"
        );
    }

    fn failed_replay_outcome() -> EpochBackfillReplayOutcome {
        EpochBackfillReplayOutcome {
            duration_ms: 1,
            activation_outcome: EpochBackfillActivationOutcome::Succeeded,
            error_kind: Some("backfill_drain_eose_timeout".to_string()),
            completion_kind: None,
            counts: DrainCounts::default(),
        }
    }

    // "We looked and the group did not move" and "we could not look" are
    // different facts and lead to different investigations. The after-read can
    // fail on its own, so a row that reports `group_advanced: false` for an
    // unread epoch asserts knowledge nobody has — which is what made the
    // failed backfill rows untrustworthy in the field.
    #[test]
    fn an_unread_post_replay_epoch_is_reported_as_unobserved_not_as_no_advance() {
        let group_id = cgka_traits::GroupId::new(vec![7u8; 16]);
        let pending = armed_backfill(&group_id, 4);
        let epochs_before = HashMap::from([(group_id.clone(), 4u64)]);
        let epochs_after = HashMap::new();

        let rows = epoch_backfill_terminal_rows(
            &pending,
            0,
            &epochs_before,
            &epochs_after,
            &failed_replay_outcome(),
        );

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.local_epoch_before, 4);
        assert_eq!(rows[0].1.local_epoch_after, None);
    }

    // The observed case must keep saying exactly what it always said.
    #[test]
    fn an_observed_post_replay_epoch_still_reports_the_reading_it_took() {
        let group_id = cgka_traits::GroupId::new(vec![7u8; 16]);
        let pending = armed_backfill(&group_id, 4);
        let epochs_before = HashMap::from([(group_id.clone(), 4u64)]);
        let epochs_after = HashMap::from([(group_id.clone(), 4u64)]);

        let rows = epoch_backfill_terminal_rows(
            &pending,
            0,
            &epochs_before,
            &epochs_after,
            &failed_replay_outcome(),
        );

        assert_eq!(rows[0].1.local_epoch_after, Some(4));
    }

    /// A device wedged in more groups than one pass holds stays armed for as
    /// long as it is wedged. Its routes must not take the whole pass, or the
    /// durable cursor never advances and every other route — the local inbox
    /// included — loses its by-id backstop for the duration.
    #[test]
    fn an_armed_intent_wider_than_the_pass_still_leaves_the_rotation_a_slot() {
        let mut work = vec![TransportReconciliationWork::Inbox(Vec::new())];
        work.extend((1..=6u8).map(|route| {
            TransportReconciliationWork::Group(cgka_traits::TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(vec![route; 16]),
                transport_group_id: vec![route; 32],
                endpoints: Vec::new(),
                retained_since: None,
            })
        }));
        let armed = (3..=6u8)
            .map(|route| cgka_traits::GroupId::new(vec![route; 16]))
            .collect::<std::collections::HashSet<_>>();

        order_reconciliation_pass(
            &mut work,
            None,
            &armed,
            TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS,
        );

        let armed_routes = work
            .iter()
            .filter(|item| item.repairs_group_in(&armed))
            .count();
        assert_eq!(
            armed_routes,
            TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS - 1,
            "the armed set must leave the rotation one slot"
        );
        assert!(
            matches!(work.last(), Some(TransportReconciliationWork::Inbox(_))),
            "the rotation keeps its slot, so the pass still advances the cursor"
        );
    }
    /// Fairness under repetition. The pass caps how many armed routes it
    /// takes, so a device armed for more groups than that cap must still reach
    /// every armed route over successive passes. Production advances the
    /// durable route cursor to the rotation progress the pass reports, so the
    /// cursor a pass leaves behind is the one it returns.
    #[test]
    fn repeated_passes_reach_every_armed_route_beyond_the_pass_cap() {
        let armed_ids = (3..=6u8)
            .map(|route| cgka_traits::GroupId::new(vec![route; 16]))
            .collect::<Vec<_>>();
        let armed = armed_ids
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let mut cursor: Option<storage_sqlite::TransportReconciliationRoute> = None;
        let mut reached = std::collections::HashSet::new();
        let passes = 16usize;

        for _ in 0..passes {
            // Production rebuilds the work set from the routing snapshot every
            // pass; only the durable cursor carries across passes.
            let mut work = vec![TransportReconciliationWork::Inbox(Vec::new())];
            work.extend((3..=6u8).map(|route| {
                TransportReconciliationWork::Group(cgka_traits::TransportGroupSubscription {
                    group_id: cgka_traits::GroupId::new(vec![route; 16]),
                    transport_group_id: vec![route; 32],
                    endpoints: Vec::new(),
                    retained_since: None,
                })
            }));

            let claim = order_reconciliation_pass(
                &mut work,
                cursor.as_ref(),
                &armed,
                TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS,
            );

            for item in &work {
                if let TransportReconciliationWork::Group(group) = item {
                    reached.insert(group.group_id.clone());
                }
            }
            assert!(
                claim.is_some(),
                "a pass with routes must report rotation progress"
            );
            cursor = claim;
        }

        let starved = armed_ids
            .iter()
            .filter(|group_id| !reached.contains(*group_id))
            .count();
        assert_eq!(
            starved, 0,
            "every armed route must reconcile within {passes} passes, so the cap starves none"
        );
    }

    /// The by-id pass an epoch-gap backfill runs ahead of its drain exists to
    /// fetch history the account is missing. An armed intent names exactly the
    /// groups that history belongs to, and the account-wide rotation lands on
    /// them only by chance, so the pass takes them first and continues the
    /// rotation over everything else.
    #[test]
    fn reconciliation_pass_takes_an_armed_backfill_route_ahead_of_the_rotation() {
        let armed_group = cgka_traits::GroupId::new(vec![0xaa; 16]);
        let mut work = vec![TransportReconciliationWork::Inbox(Vec::new())];
        work.extend((1..=5u8).map(|route| {
            TransportReconciliationWork::Group(cgka_traits::TransportGroupSubscription {
                group_id: if route == 5 {
                    armed_group.clone()
                } else {
                    cgka_traits::GroupId::new(vec![route; 16])
                },
                transport_group_id: vec![route; 32],
                endpoints: Vec::new(),
                retained_since: None,
            })
        }));

        order_reconciliation_pass(
            &mut work,
            None,
            &std::collections::HashSet::from([armed_group.clone()]),
            TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS,
        );

        let selected = work
            .iter()
            .map(|item| match item {
                TransportReconciliationWork::Inbox(_) => None,
                TransportReconciliationWork::Group(group) => Some(group.group_id.clone()),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                Some(armed_group),
                None,
                Some(cgka_traits::GroupId::new(vec![1; 16])),
                Some(cgka_traits::GroupId::new(vec![2; 16])),
            ],
            "the armed route leads the pass and the rotation keeps the rest"
        );
    }

    #[test]
    fn reconciliation_cursor_rotates_past_a_slow_route_and_wraps() {
        let routes = vec![
            storage_sqlite::TransportReconciliationRoute::Inbox,
            storage_sqlite::TransportReconciliationRoute::Group([0x01; 32]),
            storage_sqlite::TransportReconciliationRoute::Group([0x02; 32]),
        ];
        assert_eq!(
            reconciliation_start_after_cursor(&routes, Some(&routes[0])),
            1
        );
        assert_eq!(
            reconciliation_start_after_cursor(&routes, Some(&routes[1])),
            2
        );
        assert_eq!(
            reconciliation_start_after_cursor(&routes, Some(&routes[2])),
            0
        );
    }

    #[test]
    fn durable_skip_record_requires_a_validated_route_hint() {
        let account = cgka_traits::MemberId::new(vec![0x11; 32]);
        let route_id = [0x22; 32];
        let mut delivery = cgka_traits::TransportDelivery {
            account_id: account.clone(),
            group_id_hint: Some(cgka_traits::GroupId::new(vec![0x33; 16])),
            message: cgka_traits::transport::TransportMessage {
                id: cgka_traits::MessageId::new(vec![0x44; 32]),
                payload: vec![0x55],
                timestamp: cgka_traits::transport::Timestamp(1_700_000_000),
                causal_deps: Vec::new(),
                source: cgka_traits::transport::TransportSource("nostr".to_owned()),
                envelope: cgka_traits::transport::TransportEnvelope::GroupMessage {
                    transport_group_id: route_id.to_vec(),
                },
            },
            received_at: cgka_traits::transport::Timestamp(1_700_000_001),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".to_owned()),
                plane: cgka_traits::TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        };

        assert_eq!(
            transport_reconciliation_record(&account, &delivery),
            Some((
                storage_sqlite::TransportReconciliationRoute::Group(route_id),
                storage_sqlite::TransportReconciliationItem {
                    event_id: [0x44; 32],
                    created_at: 1_700_000_000,
                },
            ))
        );
        delivery.group_id_hint = None;
        assert_eq!(transport_reconciliation_record(&account, &delivery), None);
    }

    #[tokio::test]
    async fn eose_shortens_quiet_drain() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        client.sync_runtime_groups().await.unwrap();
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        client.sync_sdk_relay().await.unwrap();
        assert!(started.elapsed() >= crate::SDK_FIRST_SYNC_WAIT);
        assert!(started.elapsed() <= crate::SDK_FIRST_SYNC_WAIT + Duration::from_millis(1));
        for subscription in relay.accepted_subscriptions() {
            for endpoint in subscription.endpoints() {
                app.relay_plane
                    .handle_relay_eose_for_test(endpoint.clone(), subscription.subscription_id())
                    .await;
            }
        }
        assert!(client.adapter.account_subscription_eose().await.complete());
        let started = tokio::time::Instant::now();
        client.sync_sdk_relay().await.unwrap();
        assert!(started.elapsed() >= super::EOSE_QUIET_WAIT);
        assert!(started.elapsed() <= super::EOSE_QUIET_WAIT + Duration::from_millis(1));
    }

    #[tokio::test]
    async fn idle_drain_skips_directory() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        app.shared_storage()
            .unwrap()
            .put_public_directory_user(&storage_sqlite::PublicDirectoryUserRecord {
                account_id_hex: "ab".repeat(32),
                npub: String::new(),
                profile_json: Some("{".into()),
                relay_lists_json: serde_json::to_string(&crate::AccountRelayListStatus::empty())
                    .unwrap(),
                key_package_json: None,
                event_id_hex: None,
                event_kind: None,
                event_created_at: None,
                follows: Vec::new(),
            })
            .unwrap();
        assert!(
            app.directory_entries().is_err(),
            "unrelated profile is corrupt"
        );
        tokio::time::pause();
        let summary = client.sync_sdk_relay().await.unwrap();
        assert!(summary.messages.is_empty());
    }

    #[test]
    fn incomplete_full_history_repair_names_why_it_stayed_incomplete() {
        use crate::FullHistoryRepairIncompleteReason as Reason;
        for reason in [
            Reason::CoverageUnproven,
            Reason::Cancelled,
            Reason::Deadline,
        ] {
            let partial = SyncSummary {
                joined_groups: vec![cgka_traits::GroupId::new(vec![0x42])],
                ..SyncSummary::default()
            };
            let error = incomplete_full_history_repair(partial.clone(), reason, false);
            assert_eq!(error.partial_summary, partial);
            assert!(
                error.source.to_string().contains(reason.as_str()),
                "the caller must be able to distinguish why the repair stayed incomplete",
            );
        }
    }

    #[tokio::test]
    async fn uncertified_full_history_repair_keeps_the_buffered_prefix() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example".to_owned())
            .with_test_relay_client(relay);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let ingested = SyncSummary {
            joined_groups: vec![cgka_traits::GroupId::new(vec![0x42])],
            ..SyncSummary::default()
        };
        client.pending_failed_sync_summary.merge(ingested.clone());

        let failure = client
            .repair_full_history()
            .await
            .expect_err("without a comparison backend nothing certifies full history");

        assert_eq!(
            failure.classification().failure_stage,
            SyncFailureStage::RelayReceive
        );
        assert!(
            failure
                .source
                .to_string()
                .contains("full_history_coverage_unproven")
        );
        // The repair checkpoints nothing of the live tail: the durable prefix
        // stays buffered for the next checkpoint instead of being dropped.
        let mut buffered = failure.partial_summary;
        buffered.merge(std::mem::take(&mut client.pending_failed_sync_summary));
        assert_eq!(buffered, ingested);
    }
}

#[cfg(test)]
mod full_history_tests;

#[cfg(test)]
mod selective_history_acquisition_tests;

#[cfg(test)]
mod retired_loss_observation_tests {
    use std::sync::Arc;

    use crate::client::history_notices::park_recovery_for_test;
    use crate::relay_plane::AccountDeliveryOverflow;
    use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};

    /// A dismissal cannot release the plane while that generation still has
    /// work in flight, such as a queued control record. The later observation
    /// of the same, now retired, loss must release the fence rather than
    /// re-raise it, while genuinely new loss still arms recovery.
    #[tokio::test]
    async fn a_late_observation_of_retired_loss_releases_the_fence_without_rearming() {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        storage
            .mark_account_delivery_recovery("alice", 42, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(42);
        client.adapter.start_delivery_overflow_recovery(42);
        client.adapter.fail_delivery_overflow_recovery();
        let loss = storage
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == storage_sqlite::RecoveryCause::QueueLoss)
            .unwrap()
            .ticket
            .id;
        park_recovery_for_test(&storage, loss);
        let ticket = storage.parked_recovery_obligations().unwrap()[0].ticket;
        assert!(
            storage
                .retire_parked_recovery_obligation(ticket.id, ticket.revision, 1_000)
                .unwrap()
        );
        assert!(client.delivery_loss_blocks_cursor());

        let observed = client.adapter.pending_delivery_overflow().unwrap();
        client.observe_delivery_overflow(observed).unwrap();
        assert!(!client.delivery_overflow_recovery_pending);
        assert!(client.adapter.pending_delivery_overflow().is_none());
        assert!(!client.delivery_loss_blocks_cursor());
        assert!(
            storage
                .account_delivery_recovery("alice")
                .unwrap()
                .is_none()
        );
        assert!(client.history_notices().unwrap().is_empty());

        client
            .observe_delivery_overflow(AccountDeliveryOverflow {
                generation: 9,
                marker_token: 77,
                dropped: 1,
                ..Default::default()
            })
            .unwrap();
        assert!(client.delivery_overflow_recovery_pending);
        assert_eq!(
            storage
                .account_delivery_recovery("alice")
                .unwrap()
                .unwrap()
                .marker_token,
            77,
            "new loss reopens the retired obligation as pending debt"
        );
    }
}
