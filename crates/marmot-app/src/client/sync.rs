use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use cgka_traits::GroupId;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::transport::TransportEnvelope;
use serde::{Deserialize, Serialize};
use storage_sqlite::{
    TransportReconciliationItem, TransportReconciliationRoute, clamp_to_max_future_skew,
};
use tokio::time::timeout;
use transport_nostr_adapter::{
    AccountSubscriptionEose, NostrReconciliationItem as AdapterReconciliationItem,
};
use transport_nostr_peeler::NostrTransportEvent;

use crate::app_telemetry::{AppPerformanceOperation, SyncFailureStage};
use crate::groups::{
    EventGroupProjection, decode_received_event, event_group_id, fail_if_publish_failed,
    observe_event,
};
use crate::media::media_imeta_tags_are_valid;
use crate::notifications;
use crate::{
    AccountState, AppError, AppGroupAdminPolicyComponent, AppMessageProjection,
    AppPerformanceTelemetry, ClassifiedSyncFailure, EPOCH_BACKFILL_EOSE_WAIT,
    EPOCH_BACKFILL_EXECUTION_QUANTUM, EPOCH_BACKFILL_RETRY_BACKOFF,
    EPOCH_BACKFILL_RETRY_BACKOFF_CAP, SDK_DRAIN_WAIT, SDK_FIRST_SYNC_WAIT, SelfMembership,
    SyncFailure, SyncSummary, TRANSPORT_CURSOR_MAX_FUTURE_SKEW, unix_now_seconds,
};
use marmot_forensics::{
    AuditEventContext, EpochBackfillActivationOutcome, EpochBackfillCompletionKind,
    EpochBackfillDeferredReason, EpochBackfillExecutionSeam, EpochStallBackfillTrigger,
};

use super::AppClient;
use super::audit::EpochBackfillTerminalAudit;
use super::epoch_stall::{
    BackfillDecision, EpochBackfillDeferredSnapshot, PendingEpochBackfill,
    PendingEpochBackfillGroup,
};
use crate::config::CursorPersistence;

/// Account-wide startup budget for the timestamp-independent correctness pass.
/// Partial progress is durable, so a slow or non-NIP-77 relay cannot hold the
/// account worker indefinitely and the next sync can resume from a smaller
/// difference.
const TRANSPORT_RECONCILIATION_QUANTUM: Duration = Duration::from_secs(10);
/// Four two-second route passes leave margin inside the account-wide quantum.
/// The durable cursor starts the next pass after the last attempted route.
const TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS: usize = 4;

enum TransportReconciliationWork {
    Inbox(Vec<cgka_traits::TransportEndpoint>),
    Group(cgka_traits::TransportGroupSubscription),
}

impl TransportReconciliationWork {
    fn route(&self) -> Option<TransportReconciliationRoute> {
        match self {
            Self::Inbox(_) => Some(TransportReconciliationRoute::Inbox),
            Self::Group(group) => <[u8; 32]>::try_from(group.transport_group_id.as_slice())
                .ok()
                .map(TransportReconciliationRoute::Group),
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

/// In-flight epoch-gap replay bookkeeping shared by begin/finish helpers.
pub(crate) struct EpochBackfillExecution {
    pub(crate) pending: PendingEpochBackfill,
    pub(crate) epochs_before: HashMap<cgka_traits::GroupId, u64>,
    pub(crate) retry_ordinal: u64,
    pub(crate) eose_unconfirmed_ordinal: u64,
    pub(crate) no_progress_ordinal: u64,
    pub(crate) started: Instant,
}

const EPOCH_BACKFILL_INTENT_JOURNAL_VERSION: u32 = 1;

fn epoch_backfill_retry_deadline_unix_ms(not_before: Option<Instant>) -> Option<u64> {
    let remaining = not_before?.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    Some(
        crate::unix_now_seconds()
            .saturating_mul(1_000)
            .saturating_add(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
    )
}

fn restore_epoch_backfill_retry_deadline(deadline_unix_ms: Option<u64>) -> Option<Instant> {
    let deadline_unix_ms = deadline_unix_ms?;
    let now_unix_ms = crate::unix_now_seconds().saturating_mul(1_000);
    let remaining_ms = deadline_unix_ms.saturating_sub(now_unix_ms);
    if remaining_ms == 0 {
        return None;
    }
    let cap_ms = u64::try_from(EPOCH_BACKFILL_RETRY_BACKOFF_CAP.as_millis()).unwrap_or(u64::MAX);
    let remaining_ms = remaining_ms.min(cap_ms);
    Instant::now().checked_add(Duration::from_millis(remaining_ms))
}

/// App-owned representation stored as one encrypted account-DB blob. Groups
/// are a vector rather than a JSON map because `GroupId` is opaque bytes and
/// JSON object keys must be strings.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedEpochBackfillIntentJournal {
    version: u32,
    pending: Option<PersistedEpochBackfillIntent>,
    active: Option<PersistedEpochBackfillIntent>,
    queued: Vec<PersistedEpochBackfillIntent>,
    /// Wall-clock deadline for the account-wide replay cooldown. Restored as
    /// a remaining `Instant` duration so a restart cannot spin a fruitless
    /// backfill at full speed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_not_before_unix_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedEpochBackfillIntent {
    attempt_id: String,
    groups: Vec<PersistedEpochBackfillGroup>,
    execution_attempts: u32,
    #[serde(default)]
    eose_unconfirmed_attempts: u32,
    #[serde(default)]
    no_progress_attempts: u32,
    last_deferred_audit: Option<PersistedEpochBackfillDeferredSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedEpochBackfillGroup {
    group_id: Vec<u8>,
    stalled_epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedEpochBackfillDeferredSnapshot {
    reason: EpochBackfillDeferredReason,
    retry_ordinal: u64,
    group_epochs: Vec<PersistedEpochBackfillDeferredGroupEpoch>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedEpochBackfillDeferredGroupEpoch {
    group_id: Vec<u8>,
    observed_epoch: Option<u64>,
}

struct EpochBackfillReplayOutcome {
    duration_ms: u64,
    activation_outcome: EpochBackfillActivationOutcome,
    error_kind: Option<String>,
    completion_kind: Option<EpochBackfillCompletionKind>,
    counts: DrainCounts,
    succeeded: bool,
}

struct ReplayedAccountVisibilityOperation {
    operation_id: Vec<u8>,
    source: marmot_account::AccountVisibilitySource,
    effects: marmot_account::AccountDeviceEffects,
}

fn merge_account_visibility_effects(
    target: &mut marmot_account::AccountDeviceEffects,
    source: &marmot_account::AccountDeviceEffects,
) {
    target.events.extend(source.events.iter().cloned());
    target.queued.extend(source.queued.iter().cloned());
    target
        .pending_convergence
        .extend(source.pending_convergence.iter().cloned());
    target.reports.extend(source.reports.iter().cloned());
    target.fanout.extend(source.fanout.iter().cloned());
    target.failures.extend(source.failures.iter().cloned());
    target
        .action_outcomes
        .extend(source.action_outcomes.iter().cloned());
    target
        .published_app_messages
        .extend(source.published_app_messages.iter().cloned());
    target
        .welcome_failures
        .extend(source.welcome_failures.iter().cloned());
    target.pending.extend(source.pending.iter().cloned());
    if source.maintenance_disposition
        == cgka_traits::SendMaintenanceDisposition::PostJoinRotationPendingRetryable
    {
        target.maintenance_disposition = source.maintenance_disposition;
    }
}

/// Result of checking the pending epoch-gap replay queue at one execution seam.
///
/// `Deferred` is intentionally distinct from `NotPending`: explicit catch-up
/// already completed its ordinary floored sync before checking this queue, so
/// the worker may still return success while retaining the deferred recovery
/// intent and its audit trail. Explicit full-history repair instead uses this
/// distinction to try any queued runnable intent before falling back to its
/// ordinary unfloored account-wide replay.
#[derive(Debug)]
enum EpochBackfillFinish {
    Succeeded,
    Failed { preserve_pacing: bool },
}

#[derive(Debug)]
pub(crate) enum EpochBackfillRunOutcome {
    NotPending,
    Deferred,
    Completed(SyncSummary),
    /// The replay ran, ingested whatever it did reach, and stopped without the
    /// relays confirming they had served the account's stored history. The
    /// summary is real and must still be published; the intent stays pending.
    Incomplete(SyncSummary),
}

/// Result of one durable account-delivery overflow recovery attempt.
///
/// An incomplete replay is not a transport failure: its durable marker stays
/// armed, its real summary remains publishable, and a later sync seam retries
/// the unfloored replay. Activation, ingest, and persistence errors remain
/// typed hard failures outside this outcome.
#[derive(Debug)]
pub(crate) enum DeliveryOverflowRecoveryOutcome {
    Completed(SyncSummary),
    Incomplete(SyncSummary),
}

/// What ends a transport drain.
///
/// The two contracts differ only in what silence means, so they share one loop
/// body: see [`AppClient::sync_sdk_relay`] and
/// [`AppClient::backfill_sdk_relay`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainCompletion {
    /// Ordinary sync: a quiet relay is a finished drain. Latency-bound, because
    /// a foreground sync must return in human time.
    Quiescence,
    /// Epoch-gap backfill: the subscription is unfloored, so only
    /// end-of-stored-events proves the history query finished. Silence polls
    /// that gate and spends the passed budget; it never ends the drain by
    /// itself.
    EndOfStoredEvents {
        silence_budget: Duration,
        execution_quantum: Duration,
    },
}

impl DrainCompletion {
    fn execution_quantum(self) -> Option<Duration> {
        match self {
            Self::Quiescence => None,
            Self::EndOfStoredEvents {
                execution_quantum, ..
            } => Some(execution_quantum),
        }
    }
}

/// How a drain ended.
///
/// Ordinary quiescence is complete as soon as the relays go quiet. Backfill
/// contracts can instead yield incomplete at their worker quantum; the EOSE
/// contract also retains its silence-specific unconfirmed verdicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainVerdict {
    /// Every endpoint-scoped attempt in the activation's frozen route snapshot
    /// reached end-of-stored-events and the relays then went quiet: the
    /// account's stored history was served in full.
    Complete,
    /// The silence budget ran out with stored history still unconfirmed, though
    /// some relay did reach end-of-stored-events.
    EoseTimeout,
    /// The silence budget ran out without one relay reaching
    /// end-of-stored-events: the subscriptions were registered but never
    /// served.
    NoRelayEose,
    /// The account-worker quantum ended after at least one novel delivery was
    /// durably retained. The prefix is checkpointed and recovery resumes in a
    /// later quantum without spending the no-progress retry ordinal.
    NovelProgressQuantumYield,
    /// The account-worker quantum ended without durable novel progress. This
    /// includes duplicate/echo-only and all-refused streams.
    NoProgressQuantumYield,
    /// The per-account queue omitted at least one delivery. The durable marker
    /// is armed, but this drain's (possibly floored) subscription cannot close
    /// the gap; the caller must issue a fresh unfloored replay.
    Overflow,
}

impl DrainVerdict {
    /// The audit row's `error_kind` for a drain that did not complete.
    fn error_kind(self) -> Option<&'static str> {
        match self {
            Self::Complete => None,
            Self::EoseTimeout => Some("backfill_drain_eose_timeout"),
            Self::NoRelayEose => Some("backfill_drain_no_relay_eose"),
            Self::NovelProgressQuantumYield => Some("backfill_drain_novel_progress_quantum_yield"),
            Self::NoProgressQuantumYield => Some("backfill_drain_no_progress_quantum_yield"),
            Self::Overflow => Some("account_delivery_queue_overflow"),
        }
    }

    /// What the completed audit row should claim about this drain.
    fn completion_kind(self) -> Option<EpochBackfillCompletionKind> {
        match self {
            Self::Complete => Some(EpochBackfillCompletionKind::EndOfStoredEvents),
            Self::EoseTimeout
            | Self::NoRelayEose
            | Self::Overflow
            | Self::NovelProgressQuantumYield
            | Self::NoProgressQuantumYield => None,
        }
    }

    fn quantum_yield(counts: &DrainCounts) -> Self {
        if counts.durable_deliveries() > 0 {
            Self::NovelProgressQuantumYield
        } else {
            Self::NoProgressQuantumYield
        }
    }

    fn spends_eose_attempt(self) -> bool {
        matches!(self, Self::EoseTimeout | Self::NoRelayEose)
    }

    fn made_novel_progress(self) -> bool {
        self == Self::NovelProgressQuantumYield
    }

    fn made_no_progress(self) -> bool {
        self == Self::NoProgressQuantumYield
    }
}

/// Turn the end-of-stored-events gate into the public outcome of an explicit
/// full-history repair. A quiet unfloored subscription is not proof that the
/// relay served all stored events, so retain everything that was ingested in
/// the partial summary while failing the repair closed.
fn incomplete_full_history_repair(
    summary: SyncSummary,
    verdict: DrainVerdict,
) -> ClassifiedSyncFailure {
    debug_assert_ne!(verdict, DrainVerdict::Complete);
    let error_kind = verdict
        .error_kind()
        .unwrap_or("full_history_repair_unconfirmed");
    ClassifiedSyncFailure::at_stage(
        summary,
        AppError::BlockingTask(format!("full-history repair incomplete: {error_kind}")),
        SyncFailureStage::RelayReceive,
    )
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
    /// on. [`DrainCounts::durable_deliveries`] is the count that answers "did
    /// this drain recover anything".
    pub(crate) refused: u64,
    /// The groups those refusals were counted against. Recorded at the same
    /// site that increments `refused`, so the three consequences of a refusal —
    /// stays fetchable, does not count as recovery, and re-arms its group after
    /// a fruitless replay — cannot drift apart. Not an audit field: the row
    /// carries the scalar count, and group ids never enter a forensic row.
    pub(crate) refused_groups: std::collections::HashSet<cgka_traits::GroupId>,
}

impl DrainCounts {
    /// Deliveries this drain ingested *and* the engine kept. A drain whose
    /// every delivery stayed fetchable recovered nothing, whether a local
    /// resource bound refused it or an unknown-group path kept no trace.
    fn durable_deliveries(&self) -> u64 {
        self.deliveries.saturating_sub(self.unpersisted)
    }
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
    /// No convergence work, but durable queued outbound intents remain. The
    /// scheduled drain regenerates and publishes them (and a failed sync on
    /// that tick triggers transport reactivation), so the wakeup stays armed
    /// on the fallback delay — but a healthy waiting queue is not unsettled
    /// convergence and never counts toward the re-arm cap.
    PendingOutbound,
}

/// A scheduled convergence pass whose durable projection/ACK checkpoint has
/// completed and whose visibility summary has already been removed from the
/// client-owned V2 slot. The worker must publish `summary` before performing
/// either of the remaining best-effort network actions.
pub(crate) struct ScheduledConvergenceVisibility {
    pub(crate) summary: SyncSummary,
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

impl From<&PendingEpochBackfill> for PersistedEpochBackfillIntent {
    fn from(pending: &PendingEpochBackfill) -> Self {
        let mut groups = pending
            .groups
            .iter()
            .map(|(group_id, group)| PersistedEpochBackfillGroup {
                group_id: group_id.as_slice().to_vec(),
                stalled_epoch: group.stalled_epoch,
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| left.group_id.cmp(&right.group_id));
        Self {
            attempt_id: pending.attempt_id.clone(),
            groups,
            execution_attempts: pending.execution_attempts,
            eose_unconfirmed_attempts: pending.eose_unconfirmed_attempts,
            no_progress_attempts: pending.no_progress_attempts,
            last_deferred_audit: pending.last_deferred_audit.as_ref().map(|snapshot| {
                PersistedEpochBackfillDeferredSnapshot {
                    reason: snapshot.reason,
                    retry_ordinal: snapshot.retry_ordinal,
                    group_epochs: snapshot
                        .group_epochs
                        .iter()
                        .map(|(group_id, observed_epoch)| {
                            PersistedEpochBackfillDeferredGroupEpoch {
                                group_id: group_id.as_slice().to_vec(),
                                observed_epoch: *observed_epoch,
                            }
                        })
                        .collect(),
                }
            }),
        }
    }
}

impl TryFrom<PersistedEpochBackfillIntent> for PendingEpochBackfill {
    type Error = AppError;

    fn try_from(persisted: PersistedEpochBackfillIntent) -> Result<Self, Self::Error> {
        if persisted.attempt_id.is_empty() || persisted.groups.is_empty() {
            return Err(AppError::BlockingTask(
                "invalid durable epoch-backfill intent journal".to_owned(),
            ));
        }
        let mut groups = HashMap::with_capacity(persisted.groups.len());
        for group in persisted.groups {
            if group.group_id.is_empty() {
                return Err(AppError::BlockingTask(
                    "invalid durable epoch-backfill intent group".to_owned(),
                ));
            }
            if groups
                .insert(
                    GroupId::new(group.group_id),
                    PendingEpochBackfillGroup {
                        stalled_epoch: group.stalled_epoch,
                    },
                )
                .is_some()
            {
                return Err(AppError::BlockingTask(
                    "duplicate durable epoch-backfill intent group".to_owned(),
                ));
            }
        }
        let last_deferred_audit = persisted
            .last_deferred_audit
            .map(|snapshot| {
                let mut group_epochs = Vec::with_capacity(snapshot.group_epochs.len());
                for group in snapshot.group_epochs {
                    if group.group_id.is_empty() {
                        return Err(AppError::BlockingTask(
                            "invalid durable epoch-backfill deferral group".to_owned(),
                        ));
                    }
                    group_epochs.push((GroupId::new(group.group_id), group.observed_epoch));
                }
                Ok(EpochBackfillDeferredSnapshot {
                    reason: snapshot.reason,
                    retry_ordinal: snapshot.retry_ordinal,
                    group_epochs,
                })
            })
            .transpose()?;
        Ok(Self {
            attempt_id: persisted.attempt_id,
            groups,
            execution_attempts: persisted.execution_attempts,
            eose_unconfirmed_attempts: persisted.eose_unconfirmed_attempts,
            no_progress_attempts: persisted.no_progress_attempts,
            last_deferred_audit,
        })
    }
}

impl AppClient {
    fn persist_epoch_backfill_intent_journal(&mut self) -> Result<(), AppError> {
        let result = (|| {
            let storage = self.app.account_storage(&self.state.label)?;
            if self.pending_epoch_backfill.is_none()
                && self.active_epoch_backfill.is_none()
                && self.queued_epoch_backfills.is_empty()
                && epoch_backfill_retry_deadline_unix_ms(self.epoch_backfill_retry_not_before)
                    .is_none()
            {
                storage.clear_epoch_backfill_intent_journal()?;
                return Ok(());
            }
            let journal = PersistedEpochBackfillIntentJournal {
                version: EPOCH_BACKFILL_INTENT_JOURNAL_VERSION,
                pending: self
                    .pending_epoch_backfill
                    .as_ref()
                    .map(PersistedEpochBackfillIntent::from),
                active: self
                    .active_epoch_backfill
                    .as_ref()
                    .map(PersistedEpochBackfillIntent::from),
                queued: self
                    .queued_epoch_backfills
                    .iter()
                    .map(PersistedEpochBackfillIntent::from)
                    .collect(),
                retry_not_before_unix_ms: epoch_backfill_retry_deadline_unix_ms(
                    self.epoch_backfill_retry_not_before,
                ),
            };
            storage.store_epoch_backfill_intent_journal(&serde_json::to_vec(&journal)?)?;
            Ok(())
        })();
        self.epoch_backfill_intent_journal_dirty = result.is_err();
        result
    }

    /// Retry a failed intent-journal write before any external replay or
    /// before the worker becomes idle. The detector may not emit the same arm
    /// twice, so this explicit obligation is the durable retry source.
    pub(crate) fn ensure_epoch_backfill_intent_journal_persisted(
        &mut self,
    ) -> Result<(), AppError> {
        if self.epoch_backfill_intent_journal_dirty {
            self.persist_epoch_backfill_intent_journal()?;
        }
        Ok(())
    }

    pub(crate) fn restore_epoch_backfill_intent_journal(&mut self) -> Result<(), AppError> {
        let Some(raw) = self
            .app
            .account_storage(&self.state.label)?
            .load_epoch_backfill_intent_journal()?
        else {
            return Ok(());
        };
        let persisted: PersistedEpochBackfillIntentJournal = serde_json::from_slice(&raw)?;
        if persisted.version != EPOCH_BACKFILL_INTENT_JOURNAL_VERSION {
            return Err(AppError::BlockingTask(
                "unsupported durable epoch-backfill intent journal".to_owned(),
            ));
        }
        self.pending_epoch_backfill = persisted.pending.map(TryInto::try_into).transpose()?;
        self.active_epoch_backfill = persisted.active.map(TryInto::try_into).transpose()?;
        self.queued_epoch_backfills = persisted
            .queued
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;
        self.epoch_backfill_retry_not_before =
            restore_epoch_backfill_retry_deadline(persisted.retry_not_before_unix_ms);

        // A process cannot still own the replay represented by an active row.
        // Restore it with the same ordering used by an ordinary failed attempt:
        // a newer primary stays first, and the interrupted intent retries after
        // the already-queued work ahead of it.
        if let Some(interrupted) = self.active_epoch_backfill.take() {
            if self.pending_epoch_backfill.is_none() {
                self.pending_epoch_backfill = Some(interrupted);
            } else {
                self.queued_epoch_backfills.push_back(interrupted);
            }
            self.persist_epoch_backfill_intent_journal()?;
        }
        Ok(())
    }

    fn recover_active_epoch_backfill_after_cancellation(&mut self) -> Result<(), AppError> {
        let Some(interrupted) = self.active_epoch_backfill.take() else {
            return Ok(());
        };
        if self.pending_epoch_backfill.is_none() {
            self.pending_epoch_backfill = Some(interrupted);
        } else {
            self.queued_epoch_backfills.push_back(interrupted);
        }
        self.persist_epoch_backfill_intent_journal()
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
                } else if self.runtime.has_queued_outbound_intents(group_id)? {
                    Ok(ConvergenceScheduleState::PendingOutbound)
                } else {
                    match self.runtime.deferred_peel_cutoff_delay_ms(group_id)? {
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

    fn remember_pending_convergence_groups(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        self.pending_convergence_groups
            .extend(effects.pending_convergence.iter().cloned());
    }

    /// Feed one effects batch's epoch-gap recovery evidence to the stall
    /// detector: a resource refusal arms a replay, and an epoch passage reports
    /// the movement that can end an unrecovered run.
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
    ) -> Result<(), AppError> {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return Ok(());
        }
        for event in &effects.events {
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
                    // Recording the recovery intent before the worker performs
                    // the external full-history replay, and recording an
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
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
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
    /// Recovery evidence only. `remember_pending_convergence_groups` is
    /// deliberately not paired here the way it is at the convergence and inbound
    /// seams: the callers of this gate do not remember pending convergence on
    /// their success paths either, so recording it on the failure path alone
    /// would invent a scheduling contract they do not otherwise hold.
    pub(crate) fn observe_recovery_evidence_then_fail_if_publish_failed(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        self.observe_recovery_evidence(effects)?;
        fail_if_publish_failed(effects)
    }

    pub(crate) async fn sync_runtime_groups(&mut self) -> Result<(), AppError> {
        self.replay_pending_account_visibility().await?;
        let rebuild_since = self.subscription_rebuild_since();
        self.sync_runtime_groups_since(rebuild_since).await
    }

    async fn sync_runtime_groups_since(
        &mut self,
        rebuild_since: Option<cgka_traits::transport::Timestamp>,
    ) -> Result<(), AppError> {
        self.warm_encrypted_media_epoch_secrets("pre_subscription_sync");
        self.runtime.sync_transport_groups(rebuild_since).await?;
        self.warm_encrypted_media_epoch_secrets("post_subscription_sync");
        Ok(())
    }

    pub(crate) fn subscription_rebuild_since(&self) -> Option<cgka_traits::transport::Timestamp> {
        if self.delivery_overflow_recovery_pending {
            None
        } else {
            self.relay_plane
                .subscription_rebuild_since(self.checkpointed_transport_timestamp)
        }
    }

    fn observe_delivery_overflow(
        &mut self,
        overflow: crate::relay_plane::AccountDeliveryOverflow,
    ) -> Result<(), AppError> {
        // The router's process-local fence already froze cursor advancement at
        // the omission. Re-observe the same token here so the queued signal is
        // also an idempotent storage boundary before recovery starts.
        self.app
            .account_storage(&self.state.label)?
            .mark_account_delivery_recovery(
                &self.state.label,
                overflow.marker_token,
                overflow.dropped,
            )?;
        self.delivery_overflow_recovery_pending = true;
        self.delivery_overflow_recovery_marker_token = Some(overflow.marker_token);
        tracing::warn!(
            target: "marmot_app::relay_plane",
            method = "observe_delivery_overflow",
            queue_depth = overflow.queue_depth,
            dropped = overflow.dropped,
            elapsed_ms = overflow.elapsed_ms,
            "account delivery queue overflow requires unfloored recovery",
        );
        Ok(())
    }

    /// Run the timestamp-independent correctness backstop after the ordinary
    /// floored subscriptions are installed and before their deliveries drain.
    /// Each route reconciles against the exact event-id set retained in this
    /// account's SQLCipher database, so traffic in one busy group cannot move
    /// or evict another route's completeness state.
    async fn reconcile_transport_history(&self, reconcile_until: u64) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let routing = self.routing.snapshot();
        let mut work = Vec::with_capacity(routing.group_routes.len().saturating_add(1));
        if !routing.local_inbox_endpoints.is_empty() {
            work.push(TransportReconciliationWork::Inbox(
                routing.local_inbox_endpoints,
            ));
        }
        work.extend(
            routing
                .group_routes
                .into_iter()
                .filter(|route| route.transport_group_id.len() == 32)
                .map(TransportReconciliationWork::Group),
        );
        work.sort_unstable_by_key(TransportReconciliationWork::route);
        let cursor = storage.transport_reconciliation_route_cursor()?;
        let route_keys = work
            .iter()
            .filter_map(TransportReconciliationWork::route)
            .collect::<Vec<_>>();
        let start = reconciliation_start_after_cursor(&route_keys, cursor.as_ref());
        if start > 0 {
            work.rotate_left(start);
        }
        work.truncate(TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS);

        let mut attempted_routes = 0usize;
        let mut routes_failed = 0usize;
        let mut relays_succeeded = 0usize;
        let mut relays_failed = 0usize;
        let mut remote_items = 0usize;
        let mut received_items = 0usize;

        for route_work in work {
            let Some(route) = route_work.route() else {
                continue;
            };
            // Advance before network I/O. Cancellation or process death can
            // defer this route until the next rotation, but cannot pin every
            // subsequent route behind it on each restart.
            storage.advance_transport_reconciliation_route_cursor(&route)?;
            let inventory = storage.transport_reconciliation_inventory(&route, reconcile_until)?;
            if inventory.since > reconcile_until {
                continue;
            }
            let local_items = inventory
                .items
                .into_iter()
                .map(nostr_reconciliation_item)
                .collect::<Vec<_>>();
            attempted_routes += 1;
            let result = match route_work {
                TransportReconciliationWork::Inbox(endpoints) => {
                    self.adapter
                        .reconcile_inbox_history(
                            endpoints,
                            &local_items,
                            inventory.since,
                            reconcile_until,
                        )
                        .await
                }
                TransportReconciliationWork::Group(group) => {
                    self.adapter
                        .reconcile_group_history(
                            group,
                            &local_items,
                            inventory.since,
                            reconcile_until,
                        )
                        .await
                }
            };
            match result {
                Ok(Some(summary)) => {
                    relays_succeeded += summary.relays_succeeded;
                    relays_failed += summary.relays_failed;
                    remote_items += summary.remote_items;
                    received_items += summary.received_items;
                }
                Ok(None) => {}
                Err(_) => routes_failed += 1,
            }
        }

        tracing::info!(
            target: "marmot_app::relay_plane",
            method = "reconcile_transport_history",
            attempted_routes,
            routes_failed,
            relays_succeeded,
            relays_failed,
            remote_items,
            received_items,
            "completed transport set reconciliation"
        );
        Ok(())
    }

    fn clear_delivery_overflow_recovery(&mut self, marker_token: u64) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let cleared = storage.clear_account_delivery_recovery(&self.state.label, marker_token)?;
        if cleared {
            self.delivery_overflow_recovery_pending = false;
            self.delivery_overflow_recovery_marker_token = None;
            return Ok(true);
        }
        // A newer process-local generation won the storage race. Keep its
        // marker authoritative; this replay must not clear or report it.
        let current = storage.account_delivery_recovery(&self.state.label)?;
        self.delivery_overflow_recovery_pending = current.is_some();
        self.delivery_overflow_recovery_marker_token =
            current.map(|recovery| recovery.marker_token);
        Ok(false)
    }

    /// Warm the encrypted-media epoch-secret cache around a subscription sync,
    /// recording the aggregate pass shape so idle steady-state passes are
    /// provably free of authoritative (`MlsGroup::load`) re-checks (mdk#1380).
    fn warm_encrypted_media_epoch_secrets(&mut self, phase: &'static str) {
        let stats = self.cache_current_encrypted_media_epoch_secrets();
        tracing::debug!(
            target: "marmot_app::media",
            method = "warm_encrypted_media_epoch_secrets",
            phase,
            groups_considered = stats.groups_considered,
            skipped_unchanged_epoch = stats.skipped_unchanged_epoch,
            authoritative_checks = stats.authoritative_checks,
            warmed = stats.warmed,
            failures = stats.failures,
            "encrypted media epoch-secret warm pass"
        );
    }

    pub(crate) fn has_pending_runtime_group_subscription_refresh(&self) -> bool {
        self.pending_runtime_group_subscription_refresh
    }

    fn merge_occupied_sync_summary(slot: &mut Option<SyncSummary>, summary: SyncSummary) {
        match slot {
            Some(pending) => pending.merge(summary),
            None => *slot = Some(summary),
        }
    }

    pub(crate) fn install_account_visibility_lease(
        &mut self,
        lease: marmot_account::AccountVisibilityLease,
        batches: Vec<marmot_account::AccountVisibilityBatch>,
        current_operation_id: Option<Vec<u8>>,
    ) {
        let mut staged_batch_ids = self
            .pending_account_visibility_lease
            .take()
            .map(|pending| pending.staged_batch_ids)
            .unwrap_or_default();
        staged_batch_ids.retain(|batch_id| batches.iter().any(|batch| batch.batch_id == *batch_id));
        self.pending_account_visibility_lease = Some(super::PendingAccountVisibilityLease {
            lease,
            batches,
            staged_batch_ids,
            projection_operation_id: current_operation_id,
        });
    }

    /// Project every lower account-effects operation left by an interrupted
    /// caller before accepting new relay or send work. Operations remain
    /// ordered by their first durable row and are dispatched under their
    /// original source; a later command can never lend an older batch its own
    /// delivery metadata, group, or timestamp.
    pub(crate) async fn replay_pending_account_visibility(&mut self) -> Result<bool, AppError> {
        if self.has_staged_account_visibility_batches() {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        let Some(leased) = self.runtime.replay_visibility_leased()? else {
            return Ok(false);
        };
        let batches = leased.batches.clone();
        self.install_account_visibility_lease(leased.lease, leased.batches, None);

        let mut operations = Vec::<ReplayedAccountVisibilityOperation>::new();
        for batch in batches {
            let operation_index = operations
                .iter()
                .position(|operation| operation.operation_id == batch.operation_id);
            let operation = match operation_index {
                Some(index) => &mut operations[index],
                None => {
                    operations.push(ReplayedAccountVisibilityOperation {
                        operation_id: batch.operation_id.clone(),
                        source: batch.source.clone(),
                        effects: marmot_account::AccountDeviceEffects::default(),
                    });
                    operations
                        .last_mut()
                        .expect("just appended visibility operation")
                }
            };
            if operation.source != batch.source {
                return Err(AppError::BlockingTask(
                    "account visibility operation changed source".to_owned(),
                ));
            }
            merge_account_visibility_effects(&mut operation.effects, &batch.effects);
        }

        for operation in operations {
            self.set_account_visibility_projection_operation(Some(operation.operation_id));
            let replayed = match operation.source {
                marmot_account::AccountVisibilitySource::Inbound {
                    delivery,
                    outcome,
                    observed_at,
                } => {
                    self.replay_source_attributed_inbound_visibility(
                        delivery,
                        outcome,
                        &operation.effects,
                        observed_at.0,
                    )
                    .await
                }
                marmot_account::AccountVisibilitySource::Drain { observed_at } => self
                    .replay_source_attributed_drain_visibility(&operation.effects, observed_at.0),
                marmot_account::AccountVisibilitySource::Convergence {
                    group_id,
                    observed_at,
                } => {
                    self.replay_source_attributed_convergence_visibility(
                        &group_id,
                        &operation.effects,
                        observed_at.0,
                    )
                    .await
                }
                marmot_account::AccountVisibilitySource::Maintenance { observed_at } => self
                    .checkpoint_maintenance_effects_at(&operation.effects, observed_at.0)
                    .map(|_| ()),
                marmot_account::AccountVisibilitySource::Outbound {
                    group_id,
                    observed_at,
                    ..
                } => {
                    self.replay_source_attributed_outbound_visibility(
                        group_id.as_ref(),
                        &operation.effects,
                        observed_at.0,
                    )
                    .await
                }
            };
            if let Err(error) = replayed {
                // Do not let a later unrelated local save inherit this
                // operation as its projection authority. Exact completed rows
                // are already staged individually and remain safe to checkpoint;
                // the Header and unfinished record stay durable for replay.
                self.set_account_visibility_projection_operation(None);
                return Err(error);
            }
            // Header is the operation-complete marker. It is intentionally the
            // last row staged, including for an empty drain/no-op maintenance
            // pass, so no generic save can acknowledge an operation whose
            // source-specific tail has not completed.
            self.stage_current_account_visibility_header_batch();
            self.checkpoint_pending_sync_visibility()?;
        }
        self.set_account_visibility_projection_operation(None);
        Ok(true)
    }

    async fn replay_source_attributed_inbound_visibility(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        outcome: IngestOutcome,
        effects: &marmot_account::AccountDeviceEffects,
        observed_at: u64,
    ) -> Result<(), AppError> {
        self.project_account_non_session_visibility_at(effects, observed_at, None)?;
        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        let source_message_id_hex = hex::encode(delivery.message.id.as_slice());
        let ingested = self
            .project_source_attributed_inbound_visibility(
                &outcome,
                effects,
                &display_names,
                &mut summary,
                &source_message_id_hex,
                delivery.received_at.0,
                delivery.message.timestamp.0,
                delivery.group_id_hint.clone(),
                matches!(outcome, IngestOutcome::ResourceRefused { .. }),
            )
            .await?;
        self.retain_uncheckpointed_sync_summary(summary);
        self.remember_uncheckpointed_runtime_group_subscription_refresh(ingested.routes_dirty);
        if !ingested.must_stay_fetchable {
            self.remember_seen_event(source_message_id_hex);
        }
        if ingested.routes_dirty {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        let refresh = self.refresh_group_routes()?;
        if !ingested.routes_dirty || refresh.state_pruned {
            self.remember_uncheckpointed_runtime_group_subscription_refresh(
                refresh.routing_changed,
            );
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        } else {
            self.pending_runtime_group_subscription_refresh |= refresh.routing_changed;
        }
        Ok(())
    }

    fn replay_source_attributed_drain_visibility(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        observed_at: u64,
    ) -> Result<(), AppError> {
        let affected_groups =
            self.project_account_non_session_visibility_at(effects, observed_at, None)?;
        let mut projectable = effects.clone();
        if !projectable.failures.is_empty() {
            tracing::warn!(
                target: "marmot_app",
                method = "replay_account_visibility",
                failure_count = projectable.failures.len(),
                "replaying a completed account operation that reported publish failures"
            );
            projectable.failures.clear();
        }
        self.observe_drained_session_events_staged_at(&projectable, observed_at)?;
        for group_id in affected_groups {
            self.refresh_group(&group_id);
            self.prune_plaintext_retention_for_group(&group_id)?;
        }
        self.checkpoint_pending_sync_visibility()?;
        Ok(())
    }

    async fn replay_source_attributed_convergence_visibility(
        &mut self,
        group_id: &cgka_traits::GroupId,
        effects: &marmot_account::AccountDeviceEffects,
        observed_at: u64,
    ) -> Result<(), AppError> {
        let mut projectable = effects.clone();
        if !projectable.failures.is_empty() {
            tracing::warn!(
                target: "marmot_app",
                method = "replay_account_visibility",
                failure_count = projectable.failures.len(),
                "replaying convergence effects that reported publish failures"
            );
            projectable.failures.clear();
        }
        let visibility = self
            .checkpoint_scheduled_convergence_effects_at(group_id, &projectable, observed_at)
            .await?;
        self.retain_checkpointed_sync_summary(visibility.summary);
        Ok(())
    }

    async fn replay_source_attributed_outbound_visibility(
        &mut self,
        source_group_id: Option<&cgka_traits::GroupId>,
        effects: &marmot_account::AccountDeviceEffects,
        observed_at: u64,
    ) -> Result<(), AppError> {
        let primary_group = source_group_id.cloned().or_else(|| {
            effects
                .events
                .iter()
                .find_map(event_group_id)
                .cloned()
                .or_else(|| {
                    effects
                        .published_app_messages
                        .first()
                        .map(|published| published.group_id.clone())
                })
        });
        let mut projectable = effects.clone();
        if !projectable.failures.is_empty() {
            tracing::warn!(
                target: "marmot_app",
                method = "replay_account_visibility",
                failure_count = projectable.failures.len(),
                "replaying outbound effects that reported publish failures"
            );
            projectable.failures.clear();
        }
        if let Some(group_id) = primary_group {
            let visibility = self
                .checkpoint_scheduled_convergence_effects_at(&group_id, &projectable, observed_at)
                .await?;
            self.retain_checkpointed_sync_summary(visibility.summary);
        } else {
            let affected_groups =
                self.project_account_non_session_visibility_at(effects, observed_at, None)?;
            self.observe_drained_session_events_staged_at(&projectable, observed_at)?;
            for group_id in affected_groups {
                self.refresh_group(&group_id);
                self.prune_plaintext_retention_for_group(&group_id)?;
            }
            self.checkpoint_pending_sync_visibility()?;
        }
        Ok(())
    }

    /// Apply terminal outbound-action tails before any Header acknowledgement.
    ///
    /// Local Leave has no inbound echo of our own SelfRemove, so `Left` is
    /// authorized only by a durable `published: true` action outcome. A failed
    /// or still-attempting fanout must not move membership; restart replay uses
    /// this same projector so crash recovery cannot ACK the Header first.
    fn apply_published_outbound_action_outcomes(
        &self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        for outcome in &effects.action_outcomes {
            match outcome.action {
                marmot_account::AccountVisibilityOutboundAction::Leave => {
                    if !outcome.published {
                        continue;
                    }
                    self.app.set_group_self_membership(
                        &self.state.label,
                        &hex::encode(outcome.group_id.as_slice()),
                        SelfMembership::Left,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn project_account_non_session_visibility_at(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        recorded_at: u64,
        deferred_app_event_id: Option<&str>,
    ) -> Result<HashSet<cgka_traits::GroupId>, AppError> {
        self.apply_published_outbound_action_outcomes(effects)?;
        self.remember_published_reports(effects);
        self.record_welcome_delivery_failures_from_effects_at(effects, recorded_at)?;
        let mut affected_groups = effects
            .events
            .iter()
            .filter_map(event_group_id)
            .cloned()
            .collect::<HashSet<_>>();
        for published in &effects.published_app_messages {
            affected_groups.insert(published.group_id.clone());
            if deferred_app_event_id == Some(published.app_event_id.as_str()) {
                continue;
            }
            if let Some(update) =
                self.finalize_published_app_message_and_queue_notification(published)?
            {
                let mut finalized = SyncSummary::default();
                finalized.projection_updates.push(update);
                self.retain_uncheckpointed_sync_summary(finalized);
            }
        }
        // NonSession is one cumulative row: acknowledge none of it until the
        // complete vector has projected. SessionControl is safe at the same
        // point because `remember_published_reports` retained every convergence
        // wake before this boundary. Header remains the source-handler tail.
        if deferred_app_event_id.is_none() {
            self.stage_current_account_visibility_non_session_batch();
        }
        self.stage_current_account_visibility_record_kind(
            marmot_account::AccountVisibilityRecordKind::SessionControl,
        );
        Ok(affected_groups)
    }

    pub(super) fn project_current_account_non_session_visibility(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        deferred_app_event_id: Option<&str>,
    ) -> Result<HashSet<cgka_traits::GroupId>, AppError> {
        let recorded_at = self.current_account_visibility_observed_at();
        self.project_account_non_session_visibility_at(effects, recorded_at, deferred_app_event_id)
    }

    pub(super) fn current_account_visibility_observed_at(&self) -> u64 {
        let Some(pending) = self.pending_account_visibility_lease.as_ref() else {
            return unix_now_seconds();
        };
        let Some(operation_id) = pending.projection_operation_id.as_ref() else {
            return unix_now_seconds();
        };
        pending
            .batches
            .iter()
            .find(|batch| &batch.operation_id == operation_id)
            .map(|batch| match &batch.source {
                marmot_account::AccountVisibilitySource::Inbound { observed_at, .. }
                | marmot_account::AccountVisibilitySource::Drain { observed_at }
                | marmot_account::AccountVisibilitySource::Convergence { observed_at, .. }
                | marmot_account::AccountVisibilitySource::Maintenance { observed_at }
                | marmot_account::AccountVisibilitySource::Outbound { observed_at, .. } => {
                    observed_at.0
                }
            })
            .unwrap_or_else(unix_now_seconds)
    }

    fn set_account_visibility_projection_operation(&mut self, operation_id: Option<Vec<u8>>) {
        if let Some(pending) = self.pending_account_visibility_lease.as_mut() {
            pending.projection_operation_id = operation_id;
        }
    }

    fn stage_current_account_visibility_record_kind(
        &mut self,
        kind: marmot_account::AccountVisibilityRecordKind,
    ) {
        let Some(pending) = self.pending_account_visibility_lease.as_ref() else {
            return;
        };
        let Some(operation_id) = pending.projection_operation_id.as_ref() else {
            return;
        };
        let batch_ids = pending
            .batches
            .iter()
            .filter(|batch| &batch.operation_id == operation_id)
            .filter(|batch| batch.kind == kind)
            .map(|batch| batch.batch_id.clone())
            .collect::<Vec<_>>();
        let pending = self
            .pending_account_visibility_lease
            .as_mut()
            .expect("visibility lease remains installed");
        for batch_id in batch_ids {
            if !pending.staged_batch_ids.contains(&batch_id) {
                pending.staged_batch_ids.push(batch_id);
            }
        }
    }

    pub(super) fn stage_current_account_visibility_header_batch(&mut self) {
        self.stage_current_account_visibility_record_kind(
            marmot_account::AccountVisibilityRecordKind::Header,
        );
    }

    pub(super) fn stage_current_account_visibility_non_session_batch(&mut self) {
        self.stage_current_account_visibility_record_kind(
            marmot_account::AccountVisibilityRecordKind::NonSession,
        );
    }

    pub(super) fn stage_current_account_visibility_event(
        &mut self,
        event: &cgka_traits::engine::GroupEvent,
    ) {
        let Some(pending) = self.pending_account_visibility_lease.as_ref() else {
            return;
        };
        let Some(operation_id) = pending.projection_operation_id.as_ref() else {
            return;
        };
        let Some(batch_id) = pending
            .batches
            .iter()
            .filter(|batch| &batch.operation_id == operation_id)
            .filter(|batch| {
                matches!(
                    batch.kind,
                    marmot_account::AccountVisibilityRecordKind::Event { .. }
                )
            })
            .filter(|batch| !pending.staged_batch_ids.contains(&batch.batch_id))
            .find(|batch| batch.effects.events.as_slice() == std::slice::from_ref(event))
            .map(|batch| batch.batch_id.clone())
        else {
            return;
        };
        self.pending_account_visibility_lease
            .as_mut()
            .expect("visibility lease remains installed")
            .staged_batch_ids
            .push(batch_id);
    }

    fn has_staged_account_visibility_batches(&self) -> bool {
        self.pending_account_visibility_lease
            .as_ref()
            .is_some_and(|pending| !pending.staged_batch_ids.is_empty())
    }

    /// Retain successfully projected output before its next await or fallible
    /// boundary. Occupancy is explicit so an empty batch that wakes convergence
    /// or epoch backfill is not confused with no pending visibility work.
    pub(super) fn retain_uncheckpointed_sync_summary(&mut self, summary: SyncSummary) {
        Self::merge_occupied_sync_summary(&mut self.pending_uncheckpointed_sync_summary, summary);
    }

    pub(super) fn retain_checkpointed_sync_summary(&mut self, summary: SyncSummary) {
        Self::merge_occupied_sync_summary(&mut self.pending_checkpointed_sync_summary, summary);
    }

    fn remember_uncheckpointed_runtime_group_subscription_refresh(&mut self, dirty: bool) {
        self.pending_uncheckpointed_runtime_group_subscription_refresh |= dirty;
    }

    /// Complete the visibility checkpoint synchronously after the common state
    /// transaction commits. There must be no await between that commit and this
    /// promotion: V1 is protected by engine replay, while V2 is bounded
    /// process-local ownership until an outer caller/worker consumes it.
    fn promote_uncheckpointed_sync_visibility(&mut self) {
        if let Some(summary) = self.pending_uncheckpointed_sync_summary.take() {
            self.retain_checkpointed_sync_summary(summary);
        }
        self.pending_runtime_group_subscription_refresh |=
            std::mem::take(&mut self.pending_uncheckpointed_runtime_group_subscription_refresh);
    }

    /// Take the one bounded, durably checkpointed aggregate. `Some(default)` is
    /// meaningful occupancy for direct `next_event`; callers deciding whether
    /// an empty result is publishable must inspect the summary, not collapse the
    /// option. Epoch-stall escalations join only at this final ownership handoff.
    pub(crate) fn take_pending_checkpointed_sync_summary(&mut self) -> Option<SyncSummary> {
        if self.pending_checkpointed_sync_summary.is_none()
            && self.pending_epoch_stall_escalations.is_empty()
        {
            return None;
        }
        let mut summary = self
            .pending_checkpointed_sync_summary
            .take()
            .unwrap_or_default();
        self.drain_epoch_stall_escalations(&mut summary);
        Some(summary)
    }

    /// Finish a cancellation-retained V1 batch without awaiting relay I/O.
    ///
    /// The engine application-event outbox remains unacknowledged while V1 is
    /// occupied. A managed timeout therefore calls this before its fallback
    /// publication: the common save commits projection + ACK state and promotes
    /// the aggregate to V2 synchronously, while the ordinary subscription
    /// rebuild stays armed for the worker's bounded retry task.
    pub(crate) fn checkpoint_pending_sync_visibility(&mut self) -> Result<bool, AppError> {
        if self.pending_uncheckpointed_sync_summary.is_none()
            && !self.has_staged_account_visibility_batches()
        {
            return Ok(false);
        }
        let refresh = self.refresh_group_routes()?;
        self.remember_uncheckpointed_runtime_group_subscription_refresh(refresh.routing_changed);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        Ok(true)
    }

    fn take_checkpointed_sync_summary_or_default(&mut self) -> SyncSummary {
        let mut summary = self
            .pending_checkpointed_sync_summary
            .take()
            .unwrap_or_default();
        self.drain_epoch_stall_escalations(&mut summary);
        summary
    }

    /// Consume only output an error's plain `partial_summary` can represent.
    /// An occupied empty V2 is a wake edge, not reportable partial progress, so
    /// it stays owned for the next successful/direct/worker seam.
    fn take_reportable_checkpointed_sync_summary_for_failure(&mut self) -> SyncSummary {
        let mut summary = if self
            .pending_checkpointed_sync_summary
            .as_ref()
            .is_some_and(|summary| summary != &SyncSummary::default())
        {
            self.pending_checkpointed_sync_summary
                .take()
                .expect("checked nonempty checkpointed summary")
        } else {
            SyncSummary::default()
        };
        self.drain_epoch_stall_escalations(&mut summary);
        summary
    }

    fn merge_checkpointed_visibility_into_failure(&mut self, failure: &mut ClassifiedSyncFailure) {
        let mut retained = self.take_reportable_checkpointed_sync_summary_for_failure();
        retained.merge(std::mem::take(&mut failure.partial_summary));
        failure.partial_summary = retained;
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
        // A routes-dirty delivery can checkpoint before its first route-table
        // reconciliation. Rebuild the in-memory snapshot here on every retry;
        // otherwise a cancelled/failed refresh could later subscribe the stale
        // snapshot and incorrectly clear the durable retry intent.
        let refresh = self.refresh_group_routes()?;
        if refresh.state_pruned {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        if let Err(error) = self.sync_runtime_groups().await {
            if error.is_account_not_active() {
                // A relay notification gap or overlapping account-adapter
                // teardown can retire the activation between durable ingest
                // and this background retry. Re-activation installs both the
                // account inbox and the current complete group set, satisfying
                // the same refresh intent without replaying the delivery.
                self.prepare_transport().await?;
            } else {
                return Err(error);
            }
        }
        self.pending_runtime_group_subscription_refresh = false;
        Ok(false)
    }

    /// Preserve a direct caller's durable sync output while restoring the
    /// historical ready-on-return subscription guarantee. The summary moves to
    /// client-owned storage before the first retry await, so cancellation cannot
    /// discard output whose engine-outbox acknowledgement already committed.
    async fn finalize_direct_sync_summary(&mut self) -> Result<SyncSummary, AppError> {
        if self.has_pending_runtime_group_subscription_refresh() {
            self.retry_pending_runtime_group_subscription_refresh()
                .await?;
        }
        Ok(self.take_checkpointed_sync_summary_or_default())
    }

    pub(crate) async fn prepare_transport(&mut self) -> Result<(), AppError> {
        self.prepare_transport_with_telemetry(None).await
    }

    pub(crate) async fn prepare_transport_with_telemetry(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), AppError> {
        self.replay_pending_account_visibility().await?;
        self.prepare_transport_for_sync(telemetry)
            .await
            .map_err(|(_, error)| error)
    }

    async fn prepare_transport_for_sync(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), (SyncFailureStage, AppError)> {
        self.ensure_active_signing_account()
            .map_err(|error| (SyncFailureStage::TransportActivation, error))?;
        self.prepare_transport_for_admitted_session(telemetry).await
    }

    pub(crate) async fn prepare_teardown_transport(&mut self) -> Result<(), AppError> {
        self.ensure_teardown_cleanup_account()?;
        self.prepare_transport_for_admitted_session(None)
            .await
            .map_err(|(_, error)| error)?;
        self.ensure_teardown_cleanup_account()
    }

    async fn prepare_transport_for_admitted_session(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), (SyncFailureStage, AppError)> {
        // Before any subscription goes out: auth-gated relays (NIP-42)
        // withhold gift-wrapped welcomes from unauthenticated subscribers.
        let activation_started = Instant::now();
        self.relay_plane
            .set_transport_signer(self.transport_signer.clone())
            .await;
        let rebuild_since = self.subscription_rebuild_since();
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
        match self.sync_inner(None).await {
            Ok(()) => self.finalize_direct_sync_summary().await,
            Err(mut failure) => {
                // Compatibility callers cannot observe a failure summary.
                // Retain any already-checkpointed prefix for their next
                // successful sync instead of consuming it with the error.
                if failure.partial_summary != SyncSummary::default() {
                    self.retain_checkpointed_sync_summary(std::mem::take(
                        &mut failure.partial_summary,
                    ));
                }
                Err(failure.source)
            }
        }
    }

    /// Synchronize while retaining the durably applied prefix on failure.
    pub async fn sync_with_partial_progress(&mut self) -> Result<SyncSummary, SyncFailure> {
        match self.sync_inner(None).await {
            Ok(()) => match self.finalize_direct_sync_summary().await {
                Ok(summary) => Ok(summary),
                Err(source) => {
                    let partial_summary =
                        self.take_reportable_checkpointed_sync_summary_for_failure();
                    Err(SyncFailure::new(partial_summary, source))
                }
            },
            Err(mut failure) => {
                self.merge_checkpointed_visibility_into_failure(&mut failure);
                Err(SyncFailure::from(failure))
            }
        }
    }

    pub(crate) async fn sync_with_classified_partial_progress(
        &mut self,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        match self.sync_inner(None).await {
            Ok(()) => Ok(self.take_checkpointed_sync_summary_or_default()),
            Err(mut failure) => {
                self.merge_checkpointed_visibility_into_failure(&mut failure);
                Err(failure)
            }
        }
    }

    pub(crate) async fn sync_with_stage_telemetry(
        &mut self,
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        match self.sync_inner(Some(telemetry)).await {
            Ok(()) => Ok(self.take_checkpointed_sync_summary_or_default()),
            Err(mut failure) => {
                self.merge_checkpointed_visibility_into_failure(&mut failure);
                Err(failure)
            }
        }
    }

    async fn sync_inner(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), ClassifiedSyncFailure> {
        self.replay_pending_account_visibility()
            .await
            .map_err(|error| {
                ClassifiedSyncFailure::at_stage(
                    SyncSummary::default(),
                    error,
                    SyncFailureStage::StatePersist,
                )
            })?;
        // Reconcile epoch-bounded prior routes before issuing the first relay
        // subscriptions. This makes retirement deterministic even for a quiet
        // group that has no new inbound events after restart.
        let refresh = self.refresh_group_routes().map_err(|error| {
            ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::StatePersist,
            )
        })?;
        // A routing-table delta lives in memory and obligates the subscription
        // refresh below, not a state write; only route retirement mutates
        // persisted group state.
        if refresh.state_pruned {
            self.save_state_with_pending_local_group_deletion_frontier_clears()
                .map_err(|error| {
                    ClassifiedSyncFailure::at_stage(
                        SyncSummary::default(),
                        error,
                        SyncFailureStage::StatePersist,
                    )
                })?;
        }
        let rebuild_since_secs = self
            .subscription_rebuild_since()
            .map(|timestamp| timestamp.0);
        self.prepare_transport_for_sync(telemetry)
            .await
            .map_err(|(stage, error)| {
                ClassifiedSyncFailure::at_stage(SyncSummary::default(), error, stage)
            })?;
        if let Some(reconcile_until) = rebuild_since_secs {
            match timeout(
                TRANSPORT_RECONCILIATION_QUANTUM,
                self.reconcile_transport_history(reconcile_until),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(ClassifiedSyncFailure::at_stage(
                        SyncSummary::default(),
                        error,
                        SyncFailureStage::TransportActivation,
                    ));
                }
                Err(_) => {
                    tracing::warn!(
                        target: "marmot_app::relay_plane",
                        method = "sync_inner",
                        quantum_ms = TRANSPORT_RECONCILIATION_QUANTUM.as_millis() as u64,
                        "transport set reconciliation exceeded its bounded startup quantum; retaining partial progress"
                    );
                }
            }
        }
        // A complete startup/catch-up rebuild satisfies any older deferred
        // refresh intent before this pass starts ingesting new deliveries.
        self.pending_runtime_group_subscription_refresh = false;
        self.pending_uncheckpointed_runtime_group_subscription_refresh = false;
        // Both the inbox/group activation and the group-subscription refresh
        // have now registered on relays; emit the rebuild audit row from the
        // drained registration log before draining inbound deliveries.
        self.record_subscription_rebuild(rebuild_since_secs).await;
        // Drain effects that existed before this relay pass into V1 first. The
        // relay checkpoint below then commits them in the same transaction as
        // any newly received prefix. This deliberately leaves no network await
        // after V1 has been promoted to process-local V2.
        //
        // Session `open()` hydration queues `GroupHydrationQuarantined` without
        // an inbound delivery (mdk#426). Folding those events here keeps them
        // visible even when the later relay drain is quiet.
        if let Err(error) = self.drain_pending_session_events_staged().await {
            return Err(ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::Unknown,
            ));
        }
        let mut counts = DrainCounts::default();
        let drain_verdict = self.sync_sdk_relay(&mut counts).await?;
        if drain_verdict == DrainVerdict::Overflow || self.delivery_overflow_recovery_pending {
            let mut recovered = SyncSummary::default();
            self.recover_delivery_overflow_and_merge(&mut recovered)
                .await?;
            self.retain_checkpointed_sync_summary(recovered);
        }
        #[cfg(test)]
        if let Some((entered, release)) = self.block_after_sync_prefix_checkpoint.take() {
            entered.notify_one();
            release.notified().await;
        }
        Ok(())
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
        self.drain_pending_session_events_staged().await?;
        self.checkpoint_pending_sync_visibility()?;
        Ok(self.take_checkpointed_sync_summary_or_default())
    }

    /// Nested drain used by sync/backfill/repair. It stages visibility V1 but
    /// does not save or take V2: the following relay-prefix checkpoint owns the
    /// one durable commit, so no acknowledged output crosses another await.
    async fn drain_pending_session_events_staged(&mut self) -> Result<(), AppError> {
        // A lower drain creates a new durable source operation before it
        // returns. Finish any older source-attributed suffix first so a replay
        // projection error cannot be hidden behind (or rebound to) that new
        // Drain operation. Replay handlers only project/checkpoint supplied
        // effects; none calls this lower drain entry again.
        self.replay_pending_account_visibility().await?;
        let leased = self.runtime.drain_leased().await?;
        self.install_account_visibility_lease(
            leased.lease,
            leased.batches,
            leased.current_operation_id,
        );
        let effects = leased.effects;
        self.project_current_account_non_session_visibility(&effects, None)?;
        match self.observe_drained_session_events_staged(&effects) {
            Ok(()) => {
                self.stage_current_account_visibility_header_batch();
                Ok(())
            }
            Err(error) => {
                // The observer retains every fully projected event in V1 as it
                // goes. Promote that exact prefix before returning an error so
                // classified sync failure publication cannot overtake it.
                self.checkpoint_pending_sync_visibility()?;
                Err(error)
            }
        }
    }

    /// Project one drained batch of engine events, split from the drain itself
    /// so the projection is exercisable against a given batch of effects.
    #[cfg(test)]
    pub(crate) async fn observe_drained_session_events(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
        // Mirror `drain_pending_session_events_staged`: NonSession owns
        // report/fanout/app-message projection, then events project in order,
        // and Header is staged only after the complete source handler.
        self.project_current_account_non_session_visibility(effects, None)?;
        match self.observe_drained_session_events_staged(effects) {
            Ok(()) => self.stage_current_account_visibility_header_batch(),
            Err(error) => {
                self.checkpoint_pending_sync_visibility()?;
                return Err(error);
            }
        }
        self.checkpoint_pending_sync_visibility()?;
        Ok(self.take_checkpointed_sync_summary_or_default())
    }

    pub(super) fn observe_drained_session_events_staged(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        self.observe_drained_session_events_staged_at(
            effects,
            self.current_account_visibility_observed_at(),
        )
    }

    pub(super) fn observe_drained_session_events_staged_at(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        source_received_at: u64,
    ) -> Result<(), AppError> {
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
        self.observe_recovery_evidence(effects)?;
        let publish_error = fail_if_publish_failed(effects).err();
        if effects.events.is_empty() {
            return match publish_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }
        let display_names = self.app.display_names_by_id()?;
        // Hydration re-emits a stored group's `GroupDisbanded` on every open
        // (`restore_disband_tombstone`), and that replay is the only reconciler
        // left for a disband whose live-session projection never completed — a
        // crash, or a batch that failed after the engine had already drained the
        // event. So this seam owes the same terminal sweep as the inbound one,
        // which it discharges by running the shared
        // `observe_event_projection_effects` below rather than a copy of it.
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let local_group_deletion_frontiers =
            self.local_group_deletion_frontiers_at_batch_start(effects)?;
        let mut routes_dirty = false;
        for event in &effects.events {
            let mut event_summary = SyncSummary::default();
            // A replayed application event has no outer relay envelope, but its
            // durable engine outbox key is stable and unique. Use that key as
            // the synthetic source so a crash can replay several pending
            // events in one drain without colliding on an empty source id.
            let source_message_id_hex = match event {
                cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. } => {
                    hex::encode(message_id.as_slice())
                }
                cgka_traits::engine::GroupEvent::GroupJoined { via_welcome, .. } => {
                    hex::encode(via_welcome.as_slice())
                }
                _ => String::new(),
            };
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
                self.remember_uncheckpointed_runtime_group_subscription_refresh(changed);
                self.retain_uncheckpointed_sync_summary(event_summary);
                self.stage_current_account_visibility_event(event);
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
            if let Some(message) = observe_event(
                &mut self.state,
                &display_names,
                &mut event_summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
                source_received_at,
                None,
                self.app.allow_loopback_blob_endpoints(),
            ) && let Some(gossip_message_id) =
                self.project_received_message(message, group_metadata.as_ref(), &mut event_summary)?
            {
                event_summary
                    .messages
                    .retain(|message| message.message_id_hex != gossip_message_id);
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
            let event_routes_dirty = self.observe_event_projection_effects(
                event,
                &local_account_id_hex,
                &mut event_summary,
            )?;
            routes_dirty |= event_routes_dirty;
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
                self.stage_current_account_visibility_event(event);
            }
            if self.state.groups.len() != before {
                routes_dirty = true;
            }
            self.remember_uncheckpointed_runtime_group_subscription_refresh(
                event_routes_dirty || self.state.groups.len() != before,
            );
            // The event is now fully projected. Move its only summary copy to
            // V1 before the next loop iteration can hit another fallible seam.
            self.retain_uncheckpointed_sync_summary(event_summary);
        }
        self.clear_terminal_local_group_deletion_frontiers(effects)?;
        // Record the routing obligation once after the batch drains instead of
        // reconciling per membership-changing event. The outer checkpoint does
        // the one route refresh and state save for this staged batch.
        self.remember_uncheckpointed_runtime_group_subscription_refresh(routes_dirty);
        match publish_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
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
        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        // Synthetic source identity: these events have no single inbound
        // transport message (see `drain_pending_session_events`).
        let source_message_id_hex = String::new();
        let source_received_at = self.current_account_visibility_observed_at();
        let routes_dirty = match self
            .observe_account_device_effects(
                effects,
                &display_names,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
                None,
            )
            .await
        {
            Ok(routes_dirty) => routes_dirty,
            Err(error) => {
                self.pending_applied_sync_summary.merge(summary);
                return Err(error);
            }
        };
        // Own every fully projected event before route reconciliation or relay
        // I/O can fail/cancel. The worker drains this aggregate after the send,
        // while its ordinary state save commits any staged app-event ACKs.
        self.pending_applied_sync_summary.merge(summary);
        self.pending_runtime_group_subscription_refresh |= routes_dirty;
        let routes_changed = self.refresh_group_routes()?.routing_changed;
        self.pending_runtime_group_subscription_refresh |= routes_changed;
        Ok(())
    }

    /// Best-effort wrapper over [`Self::observe_send_applied_effects`] for the
    /// outbound send paths: a projection or route-refresh failure here must
    /// not fail a publish that already completed (or mask a publish error on
    /// the failure path), so it is logged rather than propagated.
    pub(crate) async fn observe_send_applied_effects_best_effort(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> bool {
        match self.observe_send_applied_effects(effects).await {
            Ok(()) => true,
            Err(_err) => {
                tracing::warn!(
                    target: "marmot_app::messages",
                    method = "observe_send_applied_effects",
                    error_code = "send_applied_observe_failed",
                    "failed to observe group events applied during a send"
                );
                false
            }
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
        let nostr_routing = self.nostr_routing_for_group(group_id).ok()?;
        Some(EventGroupProjection {
            nostr_routing,
            group_metadata,
            profile: self.profile_for_group(group_id),
            admin_policy: self
                .runtime
                .admin_pubkeys(group_id)
                .map(AppGroupAdminPolicyComponent::new)
                .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new())),
            message_retention: self.message_retention_for_group(group_id),
            agent_text_stream: self.agent_text_stream_for_group(group_id),
            avatar_url: self.avatar_url_for_group(group_id),
            encrypted_media: self.encrypted_media_for_group(group_id),
            image: self.image_for_group(group_id),
        })
    }

    /// Finish one direct receive batch after its projection has committed.
    ///
    /// Only batches the historical `next_event` return predicate would expose
    /// occupy the retention slot. That includes an empty summary when pending
    /// convergence or epoch backfill needs to wake the caller. Occupancy is set
    /// before the relay await, so cancellation cannot collapse that meaningful
    /// empty batch back into "nothing pending".
    async fn finalize_direct_next_event_summary(
        &mut self,
        summary: SyncSummary,
    ) -> Result<Option<SyncSummary>, AppError> {
        let should_return = summary != SyncSummary::default()
            || !self.pending_convergence_groups.is_empty()
            || self.has_pending_epoch_backfill();
        if should_return {
            self.retain_checkpointed_sync_summary(summary);
        }

        // A directly-owned AppClient has no account-worker scheduler to perform
        // the post-visibility retry. Preserve its historical readiness contract
        // when possible, but never hide an already-durable returnable batch
        // behind a later relay failure.
        if let Err(error) = self
            .retry_pending_runtime_group_subscription_refresh()
            .await
        {
            return self.direct_next_event_summary_after_refresh_error(error);
        }
        Ok(self.take_pending_checkpointed_sync_summary())
    }

    /// A nonempty committed batch remains more useful than a later route error,
    /// so hand it to the caller and leave the retry armed. An empty batch is only
    /// an internal wake edge; retain its occupied slot and surface the route
    /// error until readiness succeeds, then return that wake exactly once.
    fn direct_next_event_summary_after_refresh_error(
        &mut self,
        error: AppError,
    ) -> Result<Option<SyncSummary>, AppError> {
        if self
            .pending_checkpointed_sync_summary
            .as_ref()
            .is_some_and(|summary| summary != &SyncSummary::default())
        {
            let summary = self
                .take_pending_checkpointed_sync_summary()
                .expect("checked occupied direct next-event summary");
            tracing::warn!(
                target: "marmot_app",
                method = "next_event",
                error_kind = error.privacy_safe_kind(),
                "returning durable receive output while group-subscription refresh remains pending"
            );
            return Ok(Some(summary));
        }
        Err(error)
    }

    pub async fn next_event(&mut self) -> Result<SyncSummary, AppError> {
        loop {
            self.replay_pending_account_visibility().await?;
            // A prior direct ingest can be cancelled (or fail route
            // reconciliation) after projection but before its first save. Do
            // not wait for another delivery: finish that staged checkpoint and
            // promote V1 before any receive await.
            if self.pending_uncheckpointed_sync_summary.is_some() {
                let refresh = self.refresh_group_routes()?;
                self.remember_uncheckpointed_runtime_group_subscription_refresh(
                    refresh.routing_changed,
                );
                self.save_state_with_pending_local_group_deletion_frontier_clears()?;
            }
            // Finish an older durable refresh before accepting another
            // delivery. A retained batch is returned immediately afterward, so
            // relay readiness and app-visible output stay in commit order.
            if self.has_pending_runtime_group_subscription_refresh()
                && let Err(error) = self
                    .retry_pending_runtime_group_subscription_refresh()
                    .await
            {
                match self.direct_next_event_summary_after_refresh_error(error) {
                    Ok(Some(summary)) => return Ok(summary),
                    Ok(None) => unreachable!("refresh failure cannot synthesize no summary"),
                    Err(error) => return Err(error),
                }
            }
            if let Some(summary) = self.take_pending_checkpointed_sync_summary() {
                return Ok(summary);
            }
            let summary = match self.receive_next_delivery().await? {
                crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) => {
                    self.ingest_received_delivery(*delivery).await?
                }
                crate::relay_plane::AccountDeliveryReceive::Overflow(_) => {
                    let mut summary = SyncSummary::default();
                    match self.recover_delivery_overflow_and_merge(&mut summary).await {
                        Ok(()) => summary,
                        Err(mut failure) => {
                            self.merge_checkpointed_visibility_into_failure(&mut failure);
                            self.retain_checkpointed_sync_summary(failure.partial_summary);
                            return Err(failure.source);
                        }
                    }
                }
            };
            // The ingest checkpoint and engine-outbox acknowledgements are
            // already durable. Finalization retains a returnable batch before
            // its first relay await so cancellation cannot strand it on this
            // stack.
            if let Some(summary) = self.finalize_direct_next_event_summary(summary).await? {
                return Ok(summary);
            }
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
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;

        loop {
            let received = self
                .adapter
                .receive_account_delivery()
                .await?
                .ok_or(AppError::TransportClosed)?;
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
            if is_own_relay_echo(&delivery, &local_account_id_hex, &self.seen_events_index) {
                self.record_durable_transport_reconciliation_delivery(&delivery);
                continue;
            }
            if self.seen_events_index.contains(&event_id) {
                self.record_durable_transport_reconciliation_delivery(&delivery);
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
        let cursor_before_secs = self.state.last_transport_timestamp;
        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        let event_id = hex::encode(delivery.message.id.as_slice());
        let ingested = self
            .ingest_delivery(delivery, &display_names, &mut summary)
            .await?;
        if self.adapter.pending_delivery_overflow().is_some() {
            // `record_drop` publishes this process-local fence at the exact
            // omission, before marker I/O or the reserved control record can
            // complete. Keep this per-delivery checkpoint on its pre-ingest
            // floor so slow SQLite cannot commit the newest-first prefix ahead
            // of the marker that represents the omitted older delivery.
            self.state.last_transport_timestamp = cursor_before_secs;
        }
        // `ingest_delivery` has fully projected this delivery. Transfer its
        // only app-visible copy to V1 before the first save/route-refresh
        // boundary, including an occupied empty wake batch.
        self.retain_uncheckpointed_sync_summary(summary);
        self.remember_uncheckpointed_runtime_group_subscription_refresh(ingested.routes_dirty);
        // Mark the delivery seen only after durable ingest succeeds, matching
        // the catch-up drain below. Marking at receive time would let a failed
        // ingest poison the index, so a reused client would silently skip the
        // redelivered event — and an `Ok` the engine refused unpersisted is
        // just as much a not-durable ingest as an `Err` is.
        if !ingested.must_stay_fetchable {
            self.remember_seen_event(event_id);
        }
        let routes_dirty = ingested.routes_dirty;
        // A membership-changing ingest is already durable. Persist its app
        // projection before route reconciliation or subscription refresh can
        // fail, matching the catch-up checkpoint below.
        if routes_dirty {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        let refresh = self.refresh_group_routes()?;
        // The routes-dirty save above already persisted this delivery's app
        // projection; save again only when that first save did not run, or
        // when route retirement just mutated persisted group state. The
        // routing-table delta lives in memory and obligates a subscription
        // refresh, not a second identical state write.
        if !routes_dirty || refresh.state_pruned {
            self.remember_uncheckpointed_runtime_group_subscription_refresh(
                refresh.routing_changed,
            );
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        } else {
            // The first save already checkpointed this batch. A routing-only
            // refresh needs no second state write, so arm its runtime intent
            // directly on the checkpointed side.
            self.pending_runtime_group_subscription_refresh |= refresh.routing_changed;
        }
        Ok(self.take_checkpointed_sync_summary_or_default())
    }

    /// Drain the transport for an ordinary floored sync: ingest what is waiting
    /// and return as soon as the relays go quiet.
    async fn sync_sdk_relay(
        &mut self,
        counts: &mut DrainCounts,
    ) -> Result<DrainVerdict, ClassifiedSyncFailure> {
        self.drain_sdk_relay(counts, DrainCompletion::Quiescence)
            .await
    }

    /// Drain the transport for an epoch-gap backfill: the same ingest, ended by
    /// the relays reporting end-of-stored-events instead of by silence, so a
    /// whole-account history query that is merely slow is not read as one that
    /// had nothing to send.
    async fn backfill_sdk_relay(
        &mut self,
        counts: &mut DrainCounts,
    ) -> Result<DrainVerdict, ClassifiedSyncFailure> {
        let execution_quantum = self.epoch_backfill_execution_quantum();
        let completion = DrainCompletion::EndOfStoredEvents {
            silence_budget: self.epoch_backfill_eose_wait(),
            execution_quantum,
        };
        self.drain_sdk_relay(counts, completion).await
    }

    /// Resolve a durable per-account delivery gap with a fresh, unfloored
    /// account-wide replay. Only EOSE for subscriptions issued by this attempt
    /// can clear the marker, and a second queue overflow during the replay
    /// makes the compare-and-clear fail so another attempt remains required.
    pub(crate) async fn recover_delivery_overflow(
        &mut self,
    ) -> Result<DeliveryOverflowRecoveryOutcome, ClassifiedSyncFailure> {
        if !self.delivery_overflow_recovery_pending {
            return Ok(DeliveryOverflowRecoveryOutcome::Completed(
                SyncSummary::default(),
            ));
        }
        let marker_token = self
            .delivery_overflow_recovery_marker_token
            .ok_or_else(|| {
                ClassifiedSyncFailure::at_stage(
                    SyncSummary::default(),
                    AppError::Transport(cgka_traits::TransportAdapterError::Other(
                        "account delivery overflow marker unavailable".to_owned(),
                    )),
                    SyncFailureStage::StatePersist,
                )
            })?;
        let attempt = self.adapter.start_delivery_overflow_recovery(marker_token);
        let started = Instant::now();
        self.relay_plane
            .set_transport_signer(self.transport_signer.clone())
            .await;
        if let Err(source) = self.runtime.activate_transport(None).await {
            self.adapter.fail_delivery_overflow_recovery();
            return Err(ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                AppError::from(source),
                SyncFailureStage::TransportActivation,
            ));
        }
        if let Err(source) = self.sync_runtime_groups_since(None).await {
            self.adapter.fail_delivery_overflow_recovery();
            return Err(ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                source,
                SyncFailureStage::GroupSubscriptionSync,
            ));
        }
        self.pending_runtime_group_subscription_refresh = false;
        self.pending_uncheckpointed_runtime_group_subscription_refresh = false;
        self.record_subscription_rebuild(None).await;
        let mut counts = DrainCounts::default();
        let verdict = match self
            .drain_sdk_relay(
                &mut counts,
                DrainCompletion::EndOfStoredEvents {
                    silence_budget: self.delivery_overflow_eose_wait(),
                    execution_quantum: self.epoch_backfill_execution_quantum(),
                },
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                self.adapter.fail_delivery_overflow_recovery();
                return Err(error);
            }
        };
        let summary = self.take_checkpointed_sync_summary_or_default();
        if verdict == DrainVerdict::Complete
            && let Some(recovery_elapsed_ms) =
                self.adapter.finish_delivery_overflow_recovery(attempt)
        {
            match self.clear_delivery_overflow_recovery(attempt.marker_token) {
                Ok(true) => self
                    .adapter
                    .record_delivery_overflow_recovery_success(recovery_elapsed_ms),
                Ok(false) => {
                    self.adapter.fail_delivery_overflow_recovery();
                    return Err(ClassifiedSyncFailure::at_stage(
                        summary,
                        AppError::Transport(cgka_traits::TransportAdapterError::Other(
                            "account delivery overflow generation advanced".to_owned(),
                        )),
                        SyncFailureStage::RelayReceive,
                    ));
                }
                Err(source) => {
                    self.adapter.fail_delivery_overflow_recovery();
                    return Err(ClassifiedSyncFailure::at_stage(
                        summary,
                        source,
                        SyncFailureStage::StatePersist,
                    ));
                }
            }
            tracing::info!(
                target: "marmot_app::relay_plane",
                method = "recover_delivery_overflow",
                queue_depth = attempt.queue_depth,
                dropped = attempt.dropped,
                deliveries = counts.deliveries,
                skipped = counts.skipped,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "account delivery overflow recovery completed",
            );
            return Ok(DeliveryOverflowRecoveryOutcome::Completed(summary));
        }

        self.adapter.fail_delivery_overflow_recovery();
        let error_kind = verdict
            .error_kind()
            .unwrap_or("overflow_generation_advanced");
        tracing::warn!(
            target: "marmot_app::relay_plane",
            method = "recover_delivery_overflow",
            error_kind,
            queue_depth = attempt.queue_depth,
            dropped = attempt.dropped,
            deliveries = counts.deliveries,
            skipped = counts.skipped,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "account delivery overflow recovery remains incomplete",
        );
        Ok(DeliveryOverflowRecoveryOutcome::Incomplete(summary))
    }

    async fn recover_delivery_overflow_and_merge(
        &mut self,
        summary: &mut SyncSummary,
    ) -> Result<(), ClassifiedSyncFailure> {
        match self.recover_delivery_overflow().await {
            Ok(
                DeliveryOverflowRecoveryOutcome::Completed(recovered)
                | DeliveryOverflowRecoveryOutcome::Incomplete(recovered),
            ) => {
                summary.merge(recovered);
                Ok(())
            }
            Err(mut failure) => {
                failure.partial_summary.merge(std::mem::take(summary));
                Err(failure)
            }
        }
    }

    /// How long an unconfirmed replay must wait before an automatic seam may
    /// try it again, doubling per attempt to a cap.
    fn epoch_backfill_retry_backoff(&self, retry_ordinal: u64) -> Duration {
        let base = if cfg!(feature = "test-policy-overrides")
            && let Some(ms) = self.app.config.dev_epoch_backfill_retry_backoff_ms
        {
            Duration::from_millis(ms)
        } else {
            EPOCH_BACKFILL_RETRY_BACKOFF
        };
        retry_backoff_for_ordinal(base, retry_ordinal)
    }

    /// Whether this seam must leave a pending intent alone for now.
    ///
    /// The receive seam runs pending recovery after every inbound ingest, so an
    /// intent that keeps failing would re-run the workflow per delivery on the
    /// serial account worker, with user commands queued behind it — and a
    /// failure that reaches the relay drain (outright, or by not confirming
    /// its replay) spends the drain's whole silence budget each time. Pacing
    /// skips those attempts outright rather than queueing them: the intent is
    /// already durable and the next seam past the cooldown runs it.
    /// Caller-directed catch-up is exempt — a person asking for a repair is
    /// not a loop.
    pub(crate) fn epoch_backfill_retry_is_paced(&self, seam: EpochBackfillExecutionSeam) -> bool {
        if matches!(seam, EpochBackfillExecutionSeam::ExplicitCatchUp) {
            return false;
        }
        self.epoch_backfill_retry_not_before
            .is_some_and(|not_before| Instant::now() < not_before)
    }

    /// The silence budget the backfill drain spends waiting on
    /// end-of-stored-events.
    fn epoch_backfill_eose_wait(&self) -> Duration {
        if cfg!(feature = "test-policy-overrides")
            && let Some(ms) = self.app.config.dev_epoch_backfill_eose_wait_ms
        {
            return Duration::from_millis(ms);
        }
        EPOCH_BACKFILL_EOSE_WAIT
    }

    /// The EOSE budget for durable account-delivery overflow repair. It shares
    /// today's configured value with epoch backfill, but remains a distinct
    /// policy seam so either recovery mechanism can be tuned independently.
    fn delivery_overflow_eose_wait(&self) -> Duration {
        self.epoch_backfill_eose_wait()
    }

    /// Maximum wall-clock quantum one backfill drain owns the account worker.
    fn epoch_backfill_execution_quantum(&self) -> Duration {
        if cfg!(feature = "test-policy-overrides")
            && let Some(ms) = self.app.config.dev_epoch_backfill_execution_quantum_ms
        {
            return Duration::from_millis(ms);
        }
        EPOCH_BACKFILL_EXECUTION_QUANTUM
    }

    /// How an epoch-gap backfill drain that stops now should be read, from the
    /// account's current end-of-stored-events progress.
    async fn backfill_drain_verdict(&self) -> DrainVerdict {
        backfill_drain_verdict(self.adapter.account_subscription_eose().await)
    }

    /// Whether the end-of-stored-events gate is already satisfied, polled from
    /// the drain's *delivery* path at most once per [`SDK_DRAIN_WAIT`].
    ///
    /// The receive timeout is where a backfill drain normally consults its
    /// gate, and that timeout never fires while a relay delivers faster than
    /// it. Without this poll a drain whose history the relays had served in
    /// full could not say so until their traffic stopped — it had already won
    /// and kept running anyway, holding the serial account worker.
    ///
    /// Rate-limited because this path is hot: the already-seen prefix of an
    /// unfloored whole-account replay routinely runs to thousands of events,
    /// and every poll reconstructs the account's subscription ids behind a
    /// read lock.
    ///
    /// Deliberately gate-only. The silence budget is reset by the delivery, so
    /// it has nothing to decide on this path. The independent execution quantum
    /// is checked at the next safe loop boundary and yields duplicate-only
    /// traffic without turning the silence timer itself into a progress gate.
    async fn backfill_gate_reports_complete(
        &self,
        completion: DrainCompletion,
        polled_at: &mut Instant,
    ) -> bool {
        if !matches!(completion, DrainCompletion::EndOfStoredEvents { .. })
            || polled_at.elapsed() < SDK_DRAIN_WAIT
        {
            return false;
        }
        *polled_at = Instant::now();
        self.backfill_drain_verdict().await == DrainVerdict::Complete
    }

    async fn drain_sdk_relay(
        &mut self,
        counts: &mut DrainCounts,
        completion: DrainCompletion,
    ) -> Result<DrainVerdict, ClassifiedSyncFailure> {
        // These are local app-state reads before the relay receive loop. They
        // are not failures of the account-worker command boundary.
        let display_names = self.app.display_names_by_id().map_err(|error| {
            ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::Unknown,
            )
        })?;
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)
            .map_err(|source| {
                ClassifiedSyncFailure::at_stage(
                    SyncSummary::default(),
                    AppError::from(source),
                    SyncFailureStage::Unknown,
                )
            })?
            .account_id_hex;
        let mut first_wait = true;
        // Forensic drain accounting: wall-clock span, deliveries actually
        // ingested and receives skipped as echo or duplicate (counted apart, so
        // a long drain that was working is distinguishable from one held open
        // by traffic carrying no new history), and the durable cursor
        // before/after so an analyzer can compare the persisted floor against
        // the ingested `created_at`s.
        let drain_started = std::time::Instant::now();
        let cursor_before_secs = self.state.last_transport_timestamp;
        *counts = DrainCounts::default();
        let mut routes_dirty = false;
        // Every delivery resets the silence budget. The separate wall-clock
        // quantum never resets; it checkpoints long productive replays in
        // pieces and bounds streams that carry only duplicates or echoes.
        let mut silence_started = std::time::Instant::now();
        // Skipped deliveries poll the end-of-stored-events gate, which the
        // receive timeout below cannot reach while a relay delivers faster than
        // `SDK_DRAIN_WAIT`. Held at the same interval as that timeout.
        let mut gate_polled_at = silence_started;

        let mut verdict = loop {
            if completion
                .execution_quantum()
                .is_some_and(|quantum| drain_started.elapsed() >= quantum)
            {
                if matches!(completion, DrainCompletion::EndOfStoredEvents { .. })
                    && self.backfill_drain_verdict().await == DrainVerdict::Complete
                {
                    break DrainVerdict::Complete;
                }
                break DrainVerdict::quantum_yield(counts);
            }
            let mut wait = if first_wait {
                SDK_FIRST_SYNC_WAIT
            } else {
                SDK_DRAIN_WAIT
            };
            if let Some(quantum) = completion.execution_quantum() {
                wait = wait.min(quantum.saturating_sub(drain_started.elapsed()));
            }
            first_wait = false;
            let delivery = match timeout(wait, self.adapter.receive_account_delivery()).await {
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
                                routes_dirty,
                                counts.clone(),
                                StagedSyncError::new(error, SyncFailureStage::StatePersist),
                                drain_started,
                                cursor_before_secs,
                            )
                            .await);
                    }
                    break DrainVerdict::Overflow;
                }
                Ok(Ok(None)) => {
                    break match completion {
                        DrainCompletion::Quiescence => DrainVerdict::Complete,
                        DrainCompletion::EndOfStoredEvents { .. } => {
                            self.backfill_drain_verdict().await
                        }
                    };
                }
                Ok(Err(error)) => {
                    return Err(self
                        .finish_failed_sync_drain(
                            routes_dirty,
                            counts.clone(),
                            StagedSyncError::new(error.into(), SyncFailureStage::RelayReceive),
                            drain_started,
                            cursor_before_secs,
                        )
                        .await);
                }
                Err(_) => match completion {
                    DrainCompletion::Quiescence => break DrainVerdict::Complete,
                    DrainCompletion::EndOfStoredEvents {
                        silence_budget,
                        execution_quantum,
                    } => {
                        let verdict = self.backfill_drain_verdict().await;
                        if verdict == DrainVerdict::Complete {
                            break verdict;
                        }
                        if drain_started.elapsed() >= execution_quantum {
                            break DrainVerdict::quantum_yield(counts);
                        }
                        if silence_started.elapsed() >= silence_budget {
                            break verdict;
                        }
                        continue;
                    }
                },
            };
            // Any delivery proves the stream is alive, including one this drain
            // goes on to skip as an echo or a duplicate.
            silence_started = std::time::Instant::now();
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &self.seen_events_index)
                || self.seen_events_index.contains(&event_id)
            {
                self.record_durable_transport_reconciliation_delivery(&delivery);
                counts.skipped = counts.skipped.saturating_add(1);
                // Liveness, but not progress. It must not outlast the moment
                // the relays confirm they served this account's history.
                if self
                    .backfill_gate_reports_complete(completion, &mut gate_polled_at)
                    .await
                {
                    break DrainVerdict::Complete;
                }
                continue;
            }
            if cfg!(feature = "test-policy-overrides")
                && self
                    .app
                    .config
                    .dev_fail_sync_before_delivery
                    .is_some_and(|limit| counts.deliveries >= limit)
            {
                return Err(self
                    .finish_failed_sync_drain(
                        routes_dirty,
                        counts.clone(),
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
            let ingested = match self
                .ingest_delivery(*delivery, &display_names, &mut delivery_summary)
                .await
            {
                Ok(ingested) => ingested,
                Err(error) => {
                    return Err(self
                        .finish_failed_sync_drain(
                            routes_dirty,
                            counts.clone(),
                            StagedSyncError::new(error, SyncFailureStage::CgkaIngest),
                            drain_started,
                            cursor_before_secs,
                        )
                        .await);
                }
            };
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
            // `ingest_delivery` has fully projected this delivery. Make V1 its
            // sole summary owner before any later receive/checkpoint await.
            self.retain_uncheckpointed_sync_summary(delivery_summary);
            self.remember_uncheckpointed_runtime_group_subscription_refresh(ingested.routes_dirty);
            counts.deliveries = counts.deliveries.saturating_add(1);
            routes_dirty |= ingested.routes_dirty;
            #[cfg(test)]
            if let Some((entered, release)) = self.block_after_sync_delivery_projection.take() {
                entered.notify_one();
                release.notified().await;
            }
        };

        if verdict != DrainVerdict::Overflow
            && let Some(overflow) = self.adapter.pending_delivery_overflow()
        {
            // The queue signal intentionally trails marker persistence, so a
            // quiescence timeout can win while that signal is still pending.
            // Consult the immediate process-local fence before checkpointing.
            self.state.last_transport_timestamp = cursor_before_secs;
            if let Err(error) = self.observe_delivery_overflow(overflow) {
                return Err(self
                    .finish_failed_sync_drain(
                        routes_dirty,
                        counts.clone(),
                        StagedSyncError::new(error, SyncFailureStage::StatePersist),
                        drain_started,
                        cursor_before_secs,
                    )
                    .await);
            }
            verdict = DrainVerdict::Overflow;
        }

        if let Err(source) = self.checkpoint_sync_prefix(routes_dirty, counts.deliveries) {
            self.record_sync_drain(
                drain_started.elapsed().as_millis() as u64,
                counts.clone(),
                cursor_before_secs,
                cursor_before_secs,
            );
            return Err(ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                source,
                SyncFailureStage::StatePersist,
            ));
        }
        self.record_sync_drain(
            drain_started.elapsed().as_millis() as u64,
            counts.clone(),
            cursor_before_secs,
            self.state.last_transport_timestamp,
        );
        Ok(verdict)
    }

    async fn finish_failed_sync_drain(
        &mut self,
        routes_dirty: bool,
        counts: DrainCounts,
        original: StagedSyncError,
        drain_started: std::time::Instant,
        cursor_before_secs: Option<u64>,
    ) -> ClassifiedSyncFailure {
        let (source, stage, cursor_after_secs) =
            match self.checkpoint_sync_prefix(routes_dirty, counts.deliveries) {
                Ok(()) => (
                    original.source,
                    original.stage,
                    self.state.last_transport_timestamp,
                ),
                Err(error) => (error, SyncFailureStage::StatePersist, cursor_before_secs),
            };
        self.record_sync_drain(
            drain_started.elapsed().as_millis() as u64,
            counts,
            cursor_before_secs,
            cursor_after_secs,
        );
        ClassifiedSyncFailure::at_stage(SyncSummary::default(), source, stage)
    }

    fn checkpoint_sync_prefix(
        &mut self,
        routes_dirty: bool,
        deliveries: u64,
    ) -> Result<(), AppError> {
        self.remember_uncheckpointed_runtime_group_subscription_refresh(routes_dirty);
        // The checkpoint re-runs `refresh_group_routes` only when the drained
        // prefix could have changed routing: deliveries advance epochs (which
        // gate prior-route pruning) and can mark groups disbanded. With zero
        // deliveries and no dirty routes, engine-visible group state is
        // byte-identical to what the sync-start refresh already read, so the
        // recomputation here would rescan every group only to install the same
        // routing snapshot (mdk#1380).
        let routes_changed = if deliveries > 0
            || routes_dirty
            || self.pending_uncheckpointed_runtime_group_subscription_refresh
        {
            self.checkpoint_route_refresh_recomputes =
                self.checkpoint_route_refresh_recomputes.saturating_add(1);
            self.refresh_group_routes()?.routing_changed
        } else {
            false
        };
        self.remember_uncheckpointed_runtime_group_subscription_refresh(routes_changed);
        let checkpointed_before = self.checkpointed_transport_timestamp;
        if self.adapter.pending_delivery_overflow().is_none() {
            self.checkpointed_transport_timestamp = self.state.last_transport_timestamp;
        }
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
            self.checkpointed_transport_timestamp = checkpointed_before;
            return Err(error);
        }

        // Projection, cursor, and application-event acknowledgements are now
        // durable, and the common save moved their bounded aggregate to V2.
        // Relay I/O belongs to the direct wrapper or managed scheduler.
        Ok(())
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

    async fn ingest_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
    ) -> Result<DeliveryIngest, AppError> {
        let source_message_id_hex = hex::encode(delivery.message.id.as_slice());
        let outer_transport_at = delivery.message.timestamp.0;
        let source_received_at = delivery.received_at.0;
        let group_id_hint = delivery.group_id_hint.clone();
        let reconciliation_record =
            transport_reconciliation_record(self.adapter.account_id(), &delivery);
        let effects = self.runtime.ingest_delivery_leased(delivery).await?;
        self.install_account_visibility_lease(
            effects.lease,
            effects.batches,
            effects.current_operation_id,
        );
        let must_stay_fetchable = effects.left_object_unpersisted;
        if !must_stay_fetchable && let Some((route, item)) = &reconciliation_record {
            self.record_transport_reconciliation_item(route, item);
        }
        self.project_source_attributed_inbound_visibility(
            &effects.outcome,
            &effects.effects,
            display_names,
            summary,
            &source_message_id_hex,
            source_received_at,
            outer_transport_at,
            group_id_hint,
            must_stay_fetchable,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn project_source_attributed_inbound_visibility(
        &mut self,
        outcome: &IngestOutcome,
        effects: &marmot_account::AccountDeviceEffects,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
        source_message_id_hex: &str,
        source_received_at: u64,
        outer_transport_at: u64,
        group_id_hint: Option<cgka_traits::GroupId>,
        must_stay_fetchable: bool,
    ) -> Result<DeliveryIngest, AppError> {
        let publish_error = fail_if_publish_failed(effects).err();
        let refused_group = match outcome {
            IngestOutcome::ResourceRefused { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        self.remember_buffered_convergence_outcome(outcome);
        self.remember_pending_convergence_groups(effects);
        self.observe_recovery_evidence(effects)?;
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
            self.remember_transport_cursor(outer_transport_at);
        }
        self.detect_epoch_stall(group_id_hint, source_message_id_hex, outcome)?;
        self.project_current_account_non_session_visibility(effects, None)?;
        let routes_dirty = match self
            .observe_account_device_effects(
                effects,
                display_names,
                summary,
                source_message_id_hex,
                source_received_at,
                Some(outer_transport_at),
            )
            .await
        {
            Ok(routes_dirty) => routes_dirty,
            Err(error) => {
                // `observe_account_device_effects` merges only events whose
                // projection and ACK staging fully completed. Move that exact
                // prefix into V1 before the failed delivery unwinds; the sync
                // failure checkpoint will commit it and return it before the
                // AccountError. The incomplete current event keeps no ACK and
                // remains replayable from the engine outbox.
                self.retain_uncheckpointed_sync_summary(std::mem::take(summary));
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
        self.stage_current_account_visibility_header_batch();
        Ok(DeliveryIngest {
            routes_dirty,
            must_stay_fetchable,
            refused_group,
        })
    }

    /// Feed an unavailable group delivery to the epoch-stall detector.
    /// Transport-deferred input arms a backfill after the stalled-epoch
    /// threshold; resource refusal arms it immediately because it directly
    /// proves the fetched history was not fully retained. Repeated arming that
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
    ) -> Result<(), AppError> {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return Ok(());
        }
        let Some(group_id) = group_id_hint else {
            return Ok(());
        };
        // A group we cannot resolve (unknown or quarantined) has its own recovery
        // surface; do not track it here.
        let Ok(record) = self.runtime.group_record(&group_id) else {
            return Ok(());
        };
        let now_ms = epoch_stall_now_ms();
        let decision = match outcome {
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
            match outcome {
                IngestOutcome::TransportDeferred { .. } => {
                    EpochStallBackfillTrigger::UndecryptableThreshold
                }
                IngestOutcome::ResourceRefused { .. } => EpochStallBackfillTrigger::ResourceRefusal,
                _ => EpochStallBackfillTrigger::UndecryptableThreshold,
            },
        )
    }

    /// Apply an epoch-stall backfill decision: arm the replay, and record an
    /// escalation the detector raises.
    ///
    /// Every site that takes a [`BackfillDecision`] must route it through here.
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
    ) -> Result<(), AppError> {
        if decision.arms_backfill() {
            let durable_intent = storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group_id.as_slice()),
                stalled_epoch,
            };
            if let Err(error) = self.app.arm_epoch_backfill_intents(
                &self.state.label,
                std::slice::from_ref(&durable_intent),
            ) {
                tracing::warn!(
                    target: "marmot_app::epoch_stall",
                    method = "apply_backfill_decision",
                    error_kind = error.privacy_safe_kind(),
                    "epoch-gap recovery arm is live in memory but its durable marker will be retried before replay"
                );
            }
            let (attempt_id, record_arm) = {
                let pending = self
                    .pending_epoch_backfill
                    .get_or_insert_with(PendingEpochBackfill::new);
                let record_arm = match pending.groups.get_mut(group_id) {
                    None => {
                        pending.groups.insert(
                            group_id.clone(),
                            PendingEpochBackfillGroup { stalled_epoch },
                        );
                        true
                    }
                    Some(existing) if existing.stalled_epoch != stalled_epoch => {
                        existing.stalled_epoch = stalled_epoch;
                        true
                    }
                    Some(_) => false,
                };
                (pending.attempt_id.clone(), record_arm)
            };
            let context = AuditEventContext {
                operation_id: Some(attempt_id),
                ..AuditEventContext::default()
            };
            // The executable intent, not only its audit evidence, must be
            // durable before the worker can start its external replay.
            if record_arm {
                self.persist_epoch_backfill_intent_journal()?;
                self.record_epoch_stall_backfill_armed(group_id, stalled_epoch, trigger, &context);
            }
            // The arm mark is what paces the next one, so it has to outlive the
            // process: a device wedged for six hours must not buy a re-arm by
            // being force-killed.
            self.persist_epoch_stall_evidence(std::slice::from_ref(group_id));
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
        Ok(())
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
    fn report_epoch_stall_escalation(
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

    pub(crate) fn restore_persisted_epoch_backfill_intents(
        &mut self,
        intents: Vec<storage_sqlite::StoredEpochBackfillIntent>,
    ) -> Result<(), AppError> {
        let mut table_groups = std::collections::HashMap::new();
        let mut malformed = 0_u64;
        for intent in intents {
            let Ok(group_id) = hex::decode(&intent.group_id_hex) else {
                malformed = malformed.saturating_add(1);
                continue;
            };
            table_groups.insert(
                cgka_traits::GroupId::new(group_id),
                PendingEpochBackfillGroup {
                    stalled_epoch: intent.stalled_epoch,
                },
            );
        }
        if malformed > 0 {
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "restore_persisted_epoch_backfill_intents",
                malformed,
                "ignored malformed durable epoch-gap recovery markers"
            );
        }
        // Live engine groups keep their backfill intent even when the app
        // projection is still torn. Locally deleted groups keep a durable
        // frontier and must not re-arm the journal off the protocol record.
        // Snapshot engine/projected IDs once; any storage uncertainty leaves
        // both durable representations unchanged.
        let (live_engine_ids, projected_ids) = self.epoch_backfill_liveness_snapshot()?;
        let journal_restored = self.pending_epoch_backfill.is_some()
            || self.active_epoch_backfill.is_some()
            || !self.queued_epoch_backfills.is_empty();
        let journal_ids = self
            .pending_epoch_backfill
            .iter()
            .chain(self.active_epoch_backfill.iter())
            .chain(self.queued_epoch_backfills.iter())
            .flat_map(|intent| intent.groups.keys().cloned())
            .collect::<Vec<_>>();
        let mut candidates = table_groups.keys().cloned().collect::<HashSet<_>>();
        candidates.extend(journal_ids);
        let mut live = HashSet::new();
        for group_id in &candidates {
            if self.epoch_backfill_group_is_live(group_id, &live_engine_ids, &projected_ids)? {
                live.insert(group_id.clone());
            }
        }
        table_groups.retain(|group_id, _| live.contains(group_id));
        if journal_restored {
            let mut pruned = self.retain_live_epoch_backfill_groups(&live);
            let known = self
                .pending_epoch_backfill
                .iter()
                .chain(self.active_epoch_backfill.iter())
                .chain(self.queued_epoch_backfills.iter())
                .flat_map(|intent| intent.groups.keys().cloned())
                .collect::<HashSet<_>>();
            for (group_id, group) in table_groups {
                if !known.contains(&group_id) {
                    let pending = self
                        .pending_epoch_backfill
                        .get_or_insert_with(PendingEpochBackfill::new);
                    pending.groups.entry(group_id).or_insert(group);
                    pruned = true;
                }
            }
            if pruned {
                self.persist_epoch_backfill_intent_journal()?;
            }
            return Ok(());
        }
        if table_groups.is_empty() {
            return Ok(());
        }
        let mut pending = PendingEpochBackfill::new();
        pending.groups = table_groups;
        self.pending_epoch_backfill = Some(pending);
        Ok(())
    }

    fn retain_live_epoch_backfill_groups(&mut self, live: &HashSet<cgka_traits::GroupId>) -> bool {
        let mut pruned = false;
        let retain = |intent: &mut PendingEpochBackfill| {
            let before = intent.groups.len();
            intent.groups.retain(|group_id, _| live.contains(group_id));
            intent.groups.len() != before
        };
        if let Some(pending) = self.pending_epoch_backfill.as_mut() {
            pruned |= retain(pending);
        }
        if let Some(active) = self.active_epoch_backfill.as_mut() {
            pruned |= retain(active);
        }
        for queued in &mut self.queued_epoch_backfills {
            pruned |= retain(queued);
        }
        if self
            .pending_epoch_backfill
            .as_ref()
            .is_some_and(|intent| intent.groups.is_empty())
        {
            self.pending_epoch_backfill = None;
            pruned = true;
        }
        if self
            .active_epoch_backfill
            .as_ref()
            .is_some_and(|intent| intent.groups.is_empty())
        {
            self.active_epoch_backfill = None;
            pruned = true;
        }
        let queued_before = self.queued_epoch_backfills.len();
        self.queued_epoch_backfills
            .retain(|intent| !intent.groups.is_empty());
        if self.queued_epoch_backfills.len() != queued_before {
            pruned = true;
        }
        if self.pending_epoch_backfill.is_none()
            && let Some(next) = self.queued_epoch_backfills.pop_front()
        {
            self.pending_epoch_backfill = Some(next);
            pruned = true;
        }
        pruned
    }

    pub(crate) fn prune_deleted_epoch_backfill_group(&mut self, group_id: &cgka_traits::GroupId) {
        let group_id_hex = hex::encode(group_id.as_slice());
        if let Ok(intents) = self.app.pending_epoch_backfill_intents(&self.state.label) {
            let stale = intents
                .into_iter()
                .filter(|intent| intent.group_id_hex == group_id_hex)
                .collect::<Vec<_>>();
            if !stale.is_empty() {
                let _ = self
                    .app
                    .clear_epoch_backfill_intents(&self.state.label, &stale);
            }
        }
        let mut live = HashSet::new();
        for intent in self
            .pending_epoch_backfill
            .iter()
            .chain(self.active_epoch_backfill.iter())
            .chain(self.queued_epoch_backfills.iter())
        {
            live.extend(intent.groups.keys().cloned());
        }
        live.remove(group_id);
        if self.retain_live_epoch_backfill_groups(&live) {
            let _ = self.persist_epoch_backfill_intent_journal();
        }
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
        if let Err(error) = self
            .app
            .record_epoch_stall_evidence(&self.state.label, &evidence)
        {
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "persist_epoch_stall_evidence",
                error_kind = error.privacy_safe_kind(),
                "frozen-epoch recovery evidence is live in memory but was not made durable"
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

    fn stored_epoch_backfill_intents(
        pending: &PendingEpochBackfill,
    ) -> Vec<storage_sqlite::StoredEpochBackfillIntent> {
        pending
            .groups
            .iter()
            .map(
                |(group_id, group)| storage_sqlite::StoredEpochBackfillIntent {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    stalled_epoch: group.stalled_epoch,
                },
            )
            .collect()
    }

    fn persist_epoch_backfill_intent(
        &self,
        pending: &PendingEpochBackfill,
    ) -> Result<(), AppError> {
        self.app.arm_epoch_backfill_intents(
            &self.state.label,
            &Self::stored_epoch_backfill_intents(pending),
        )
    }

    fn clear_epoch_backfill_intent(&self, pending: &PendingEpochBackfill) -> Result<(), AppError> {
        self.app.clear_epoch_backfill_intents(
            &self.state.label,
            &Self::stored_epoch_backfill_intents(pending),
        )
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
    fn drain_epoch_stall_escalations(&mut self, summary: &mut SyncSummary) {
        summary
            .epoch_stall_escalations
            .append(&mut self.pending_epoch_stall_escalations);
    }

    /// Whether an epoch-gap backfill is armed and awaiting its replay. Read by
    /// the account worker to schedule a forensic audit-tracker upload for the
    /// just-recorded `epoch_stall_backfill_armed` row without poking the field.
    pub(crate) fn has_pending_epoch_backfill(&self) -> bool {
        self.pending_epoch_backfill.is_some()
            || self.active_epoch_backfill.is_some()
            || !self.queued_epoch_backfills.is_empty()
    }

    fn take_next_pending_epoch_backfill(&mut self) -> Option<PendingEpochBackfill> {
        self.pending_epoch_backfill
            .take()
            .or_else(|| self.queued_epoch_backfills.pop_front())
    }

    fn requeue_failed_epoch_backfill_intent(&mut self, failed: PendingEpochBackfill) {
        match self.pending_epoch_backfill.take() {
            None => self.pending_epoch_backfill = Some(failed),
            Some(current) => {
                self.pending_epoch_backfill = Some(current);
                self.queued_epoch_backfills.push_back(failed);
            }
        }
    }

    fn restore_deferred_epoch_backfill(&mut self, deferred: PendingEpochBackfill) {
        if let Some(next) = self.queued_epoch_backfills.pop_front() {
            self.queued_epoch_backfills.push_back(deferred);
            self.pending_epoch_backfill = Some(next);
        } else {
            self.pending_epoch_backfill = Some(deferred);
        }
    }

    fn epoch_backfill_deferred_snapshot(
        reason: EpochBackfillDeferredReason,
        retry_ordinal: u64,
        pending: &PendingEpochBackfill,
        observed_epochs: &HashMap<cgka_traits::GroupId, u64>,
    ) -> EpochBackfillDeferredSnapshot {
        let mut group_epochs = pending
            .groups
            .keys()
            .map(|group_id| (group_id.clone(), observed_epochs.get(group_id).copied()))
            .collect::<Vec<_>>();
        group_epochs.sort_by(|(left, _), (right, _)| left.as_slice().cmp(right.as_slice()));
        EpochBackfillDeferredSnapshot {
            reason,
            retry_ordinal,
            group_epochs,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_finish_epoch_backfill_execution(
        &mut self,
        execution: EpochBackfillExecution,
        succeeded: bool,
    ) -> Result<(), AppError> {
        self.finish_epoch_backfill_execution(
            execution,
            EpochBackfillActivationOutcome::Succeeded,
            if succeeded {
                None
            } else {
                Some("account_transport".to_string())
            },
            succeeded.then_some(EpochBackfillCompletionKind::EndOfStoredEvents),
            DrainCounts::default(),
            if succeeded {
                EpochBackfillFinish::Succeeded
            } else {
                EpochBackfillFinish::Failed {
                    preserve_pacing: false,
                }
            },
        )
        .map(|_| ())
    }

    /// Complete an execution the way a served end-of-stored-events drain does,
    /// with the delivery counts whose effect on the disarm rule is under test.
    #[cfg(test)]
    pub(crate) fn test_complete_epoch_backfill_execution(
        &mut self,
        execution: EpochBackfillExecution,
        deliveries: u64,
        refused: u64,
    ) {
        self.finish_epoch_backfill_execution(
            execution,
            EpochBackfillActivationOutcome::Succeeded,
            None,
            Some(EpochBackfillCompletionKind::EndOfStoredEvents),
            DrainCounts {
                deliveries,
                skipped: 0,
                refused,
                ..DrainCounts::default()
            },
            EpochBackfillFinish::Succeeded,
        )
        .expect("test epoch-backfill completion must persist its intent journal");
    }

    fn local_epoch_for_group(&self, group_id: &cgka_traits::GroupId) -> Option<u64> {
        self.runtime
            .group_record(group_id)
            .ok()
            .map(|record| record.epoch.0)
    }

    fn epoch_backfill_liveness_snapshot(
        &self,
    ) -> Result<(HashSet<cgka_traits::GroupId>, HashSet<cgka_traits::GroupId>), AppError> {
        #[cfg(test)]
        if self
            .app
            .fail_epoch_backfill_live_group_ids
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(std::io::Error::other(
                "injected epoch-backfill live-group listing failure",
            )
            .into());
        }
        let live_engine_ids = self
            .runtime
            .live_group_ids()?
            .into_iter()
            .collect::<HashSet<_>>();
        let projected_ids = self
            .state
            .groups
            .iter()
            .filter_map(|group| {
                hex::decode(&group.group_id_hex)
                    .ok()
                    .map(cgka_traits::GroupId::new)
            })
            .collect::<HashSet<_>>();
        Ok((live_engine_ids, projected_ids))
    }

    fn epoch_backfill_group_is_live(
        &self,
        group_id: &cgka_traits::GroupId,
        live_engine_ids: &HashSet<cgka_traits::GroupId>,
        projected_ids: &HashSet<cgka_traits::GroupId>,
    ) -> Result<bool, AppError> {
        #[cfg(test)]
        if self
            .app
            .fail_epoch_backfill_deletion_frontier
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(
                std::io::Error::other("injected epoch-backfill deletion-frontier failure").into(),
            );
        }
        if self.has_local_group_deletion_frontier(group_id)? {
            return Ok(false);
        }
        Ok(live_engine_ids.contains(group_id) || projected_ids.contains(group_id))
    }

    fn capture_pending_group_epochs(
        &self,
        pending: &PendingEpochBackfill,
    ) -> HashMap<cgka_traits::GroupId, u64> {
        pending
            .groups
            .keys()
            .filter_map(|group_id| {
                self.local_epoch_for_group(group_id)
                    .map(|epoch| (group_id.clone(), epoch))
            })
            .collect()
    }

    fn epoch_backfill_audit_context(pending: &PendingEpochBackfill) -> AuditEventContext {
        AuditEventContext {
            operation_id: Some(pending.attempt_id.clone()),
            ..AuditEventContext::default()
        }
    }

    pub(crate) fn begin_epoch_backfill_execution(
        &mut self,
        seam: EpochBackfillExecutionSeam,
    ) -> Result<Option<EpochBackfillExecution>, AppError> {
        self.recover_active_epoch_backfill_after_cancellation()?;
        let Some(mut pending) = self.take_next_pending_epoch_backfill() else {
            return Ok(None);
        };
        let retry_ordinal = u64::from(pending.execution_attempts);
        let eose_unconfirmed_ordinal = u64::from(pending.eose_unconfirmed_attempts);
        let no_progress_ordinal = u64::from(pending.no_progress_attempts);
        let epochs_before = self.capture_pending_group_epochs(&pending);
        let context = Self::epoch_backfill_audit_context(&pending);
        if epochs_before.len() != pending.groups.len() {
            let defer_state = Self::epoch_backfill_deferred_snapshot(
                EpochBackfillDeferredReason::GroupEpochUnavailable,
                retry_ordinal,
                &pending,
                &epochs_before,
            );
            if pending.last_deferred_audit != Some(defer_state.clone()) {
                self.record_epoch_stall_backfill_deferred(
                    EpochBackfillDeferredReason::GroupEpochUnavailable,
                    retry_ordinal,
                    &context,
                );
                pending.last_deferred_audit = Some(defer_state);
            }
            self.restore_deferred_epoch_backfill(pending);
            self.persist_epoch_backfill_intent_journal()?;
            return Ok(None);
        }
        pending.last_deferred_audit = None;
        pending.execution_attempts = pending.execution_attempts.saturating_add(1);
        self.active_epoch_backfill = Some(pending.clone());
        if let Err(error) = self.persist_epoch_backfill_intent_journal() {
            self.active_epoch_backfill = None;
            if self.pending_epoch_backfill.is_none() {
                self.pending_epoch_backfill = Some(pending);
            } else {
                self.queued_epoch_backfills.push_front(pending);
            }
            return Err(error);
        }
        self.record_epoch_stall_backfill_started(seam, retry_ordinal, &context);
        Ok(Some(EpochBackfillExecution {
            pending,
            epochs_before,
            retry_ordinal,
            eose_unconfirmed_ordinal,
            no_progress_ordinal,
            started: Instant::now(),
        }))
    }

    fn finish_epoch_backfill_execution(
        &mut self,
        execution: EpochBackfillExecution,
        activation_outcome: EpochBackfillActivationOutcome,
        error_kind: Option<String>,
        completion_kind: Option<EpochBackfillCompletionKind>,
        counts: DrainCounts,
        finish: EpochBackfillFinish,
    ) -> Result<bool, AppError> {
        let (succeeded, preserve_pacing) = match finish {
            EpochBackfillFinish::Succeeded => (true, false),
            EpochBackfillFinish::Failed { preserve_pacing } => (false, preserve_pacing),
        };
        if self
            .active_epoch_backfill
            .as_ref()
            .is_none_or(|active| active.attempt_id != execution.pending.attempt_id)
        {
            return Err(AppError::BlockingTask(
                "epoch-backfill terminal state does not match active intent".to_owned(),
            ));
        }
        let duration_ms = execution.started.elapsed().as_millis() as u64;
        let epochs_after = self.capture_pending_group_epochs(&execution.pending);
        let observed_all_groups = epochs_after.len() == execution.pending.groups.len();
        let succeeded = succeeded && observed_all_groups;
        let error_kind = if !observed_all_groups && error_kind.is_none() {
            Some("group_epoch_unavailable".to_string())
        } else {
            error_kind
        };
        self.record_epoch_backfill_terminal_rows(
            &execution.pending,
            execution.retry_ordinal,
            &execution.epochs_before,
            &epochs_after,
            EpochBackfillReplayOutcome {
                duration_ms,
                activation_outcome,
                error_kind,
                completion_kind,
                counts: counts.clone(),
                succeeded,
            },
        );
        let previous_pending = self.pending_epoch_backfill.clone();
        let previous_active = self.active_epoch_backfill.clone();
        let previous_queued = self.queued_epoch_backfills.clone();
        let previous_retry_not_before = self.epoch_backfill_retry_not_before;
        self.active_epoch_backfill = None;
        let recovered = if !succeeded {
            // Every error exit of `run_pending_epoch_backfill` lands here
            // without ever producing a drain verdict, so none of the
            // verdict-derived pacing rules in that function runs for it. Pace
            // here instead, beside the requeue, which makes the rule structural
            // rather than per-exit: an intent that goes back on the queue is
            // always paced. Unpaced, the receive seam re-enters a whole-account
            // replay on the very next inbound batch, and every attempt that
            // gets as far as the drain spends the full silence budget before
            // failing again. The verdict paths reach this branch too and
            // overwrite the value immediately afterwards with their own richer
            // rule, including clearing it outright for a quantum yield that
            // made novel progress.
            //
            // `retry_ordinal` is the right ordinal for a failure.
            // `begin_epoch_backfill_execution` already burned it, and what it
            // counts is how many times this intent has spent the one
            // account-wide replay budget -- exactly what the cooldown rations.
            // The verdict counters stay untouched: an execution that never
            // reached a verdict is no evidence about whether the relays serve
            // this account's stored history, so inflating
            // `eose_unconfirmed_attempts` would mis-shape the unconfirmed
            // schedule, and inflating `no_progress_attempts` would defeat its
            // reset-on-progress rule. Burning `retry_ordinal` costs nothing
            // beyond a longer wait: no attempt limit degrades or abandons an
            // intent, and a caller-directed repair stays exempt from the
            // cooldown entirely.
            if !preserve_pacing {
                let backoff = self.epoch_backfill_retry_backoff(execution.retry_ordinal);
                self.epoch_backfill_retry_not_before = Some(Instant::now() + backoff);
            }
            self.requeue_failed_epoch_backfill_intent(execution.pending);
            false
        } else if Self::replay_recovered_something(&execution.epochs_before, &epochs_after, &counts)
        {
            self.epoch_stall.mark_replayed();
            if !preserve_pacing {
                self.epoch_backfill_retry_not_before = None;
            }
            true
        } else {
            // Fruitless. An end-of-stored-events completion is the relays saying
            // they served this account's stored history in full and it held nothing
            // that moves these groups — the one piece of evidence a device wedged
            // at an epoch nobody can advance is able to accumulate, and the only
            // completion shape strong enough to count. A drain that gave up
            // unconfirmed proves only that the drain gave up.
            if matches!(
                completion_kind,
                Some(EpochBackfillCompletionKind::EndOfStoredEvents)
            ) {
                let fruitless_threshold = self.epoch_stall.fruitless_completion_threshold();
                let escalations = self
                    .epoch_stall
                    .observe_fruitless_completion(execution.pending.groups.keys());
                for escalation in escalations {
                    self.report_epoch_stall_escalation(
                        &escalation.group_id,
                        escalation.stalled_epoch,
                        escalation.completions,
                        fruitless_threshold,
                        "finish_epoch_backfill_execution",
                    );
                }
                self.persist_epoch_stall_evidence(execution.pending.groups.keys());
            }
            // Withholding `mark_replayed` re-arms bystanders only; the groups this
            // drain actually refused history for latched themselves when they armed,
            // so they need an explicit clear or they can never arm again at this
            // epoch.
            self.epoch_stall
                .rearm_refused_groups(&counts.refused_groups);
            if !preserve_pacing {
                self.epoch_backfill_retry_not_before = Some(
                    Instant::now() + self.epoch_backfill_retry_backoff(execution.retry_ordinal),
                );
            }
            false
        };
        if let Err(error) = self.persist_epoch_backfill_intent_journal() {
            self.pending_epoch_backfill = previous_pending;
            self.active_epoch_backfill = previous_active;
            self.queued_epoch_backfills = previous_queued;
            self.epoch_backfill_retry_not_before = previous_retry_not_before;
            return Err(error);
        }
        Ok(recovered)
    }

    /// Whether a completed replay recovered anything, and has therefore earned
    /// the account-wide disarm.
    ///
    /// [`mark_replayed`](super::epoch_stall::EpochStallDetector::mark_replayed)
    /// latches `fired_at_epoch` for every
    /// *tracked* group, not just the armed one — the right trade when one
    /// full-history replay really did serve every group's history, and a silent
    /// end to all automatic recovery when it served nothing. Two independent
    /// proofs, either of which is enough:
    ///
    /// - the drain ingested at least one delivery the engine *kept*
    ///   ([`DrainCounts::durable_deliveries`]). A delivery can convert into an
    ///   epoch long after this call returns — one field run drained 376
    ///   deliveries and moved its epoch a second *after* the terminal row was
    ///   written — so `epochs_after`, read the moment the drain ends, must never
    ///   second-guess a delivery count. Deliveries parked awaiting convergence
    ///   are recovery in flight. Objects left fetchable are not: the engine
    ///   kept no durable trace, so a drain made entirely of resource refusals
    ///   or unknown-group drops recovered nothing and must not disarm anything.
    ///   A mixed drain still counts — one kept delivery is progress.
    /// - a tracked group's local epoch advanced across the run, which is what a
    ///   zero-delivery replay whose value was letting already-deferred rows
    ///   converge looks like.
    ///
    /// A run that proves neither is fruitless. It is still recorded as the
    /// completed end-of-stored-events attempt it was and still consumes its
    /// intent — the pacing and intent-consumption rules are untouched. What it
    /// must not do is stop the next refusal or undecryptable from arming a fresh
    /// replay.
    fn replay_recovered_something(
        epochs_before: &HashMap<cgka_traits::GroupId, u64>,
        epochs_after: &HashMap<cgka_traits::GroupId, u64>,
        counts: &DrainCounts,
    ) -> bool {
        counts.durable_deliveries() > 0
            || epochs_after.iter().any(|(group_id, after)| {
                epochs_before
                    .get(group_id)
                    .is_some_and(|before| after > before)
            })
    }

    fn record_epoch_backfill_terminal_rows(
        &self,
        pending: &PendingEpochBackfill,
        retry_ordinal: u64,
        epochs_before: &HashMap<cgka_traits::GroupId, u64>,
        epochs_after: &HashMap<cgka_traits::GroupId, u64>,
        outcome: EpochBackfillReplayOutcome,
    ) {
        let context = Self::epoch_backfill_audit_context(pending);
        for group_id in pending.groups.keys() {
            let local_epoch_before = epochs_before
                .get(group_id)
                .copied()
                .unwrap_or(pending.groups[group_id].stalled_epoch);
            let local_epoch_after = epochs_after
                .get(group_id)
                .copied()
                .unwrap_or(local_epoch_before);
            let group_advanced = local_epoch_after > local_epoch_before;
            self.record_epoch_stall_backfill_terminal(
                group_id,
                outcome.succeeded,
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
                    local_epoch_after,
                    group_advanced,
                },
                &context,
            );
        }
    }

    /// Recover any group that stalled below its live epoch during ingest by
    /// replaying the account's full transport history (`since = None`). One replay
    /// re-fetches every group, so the detector collapses simultaneously-stuck
    /// groups into a single replay. A no-op when nothing stalled.
    pub(crate) async fn run_pending_epoch_backfill(
        &mut self,
        seam: EpochBackfillExecutionSeam,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        self.ensure_epoch_backfill_intent_journal_persisted()?;
        self.recover_active_epoch_backfill_after_cancellation()?;
        if !self.has_pending_epoch_backfill() {
            return Ok(EpochBackfillRunOutcome::NotPending);
        }
        // Pacing is account-wide and is checked *before* rotation, so a queued
        // sibling intent waits out the cooldown the primary intent earned
        // instead of rotating forward through `begin_epoch_backfill_execution`.
        // Deliberate: the contended resource is the one account-wide replay
        // budget, not the intent that last spent it, and one full-history replay
        // serves every armed group — rotating here would buy a different
        // group-id on the audit rows and pay a second whole-account drain for
        // it. The wait is bounded by `EPOCH_BACKFILL_RETRY_BACKOFF_CAP`.
        if self.epoch_backfill_retry_is_paced(seam) {
            return Ok(EpochBackfillRunOutcome::Deferred);
        }
        let Some(mut execution) = self.begin_epoch_backfill_execution(seam)? else {
            return Ok(EpochBackfillRunOutcome::Deferred);
        };
        if let Err(error) = self.persist_epoch_backfill_intent(&execution.pending) {
            let terminal_error = error.privacy_safe_kind().to_string();
            self.finish_epoch_backfill_execution(
                execution,
                EpochBackfillActivationOutcome::Failed,
                Some(terminal_error),
                None,
                DrainCounts::default(),
                EpochBackfillFinish::Failed {
                    preserve_pacing: false,
                },
            )?;
            return Err(error);
        }

        match self.runtime.activate_transport(None).await {
            Ok(()) => {
                self.warm_encrypted_media_epoch_secrets("pre_subscription_sync");
                if let Err(err) = self.runtime.sync_transport_groups(None).await {
                    let err: AppError = err.into();
                    let terminal_error = err.privacy_safe_kind().to_string();
                    self.finish_epoch_backfill_execution(
                        execution,
                        EpochBackfillActivationOutcome::Succeeded,
                        Some(terminal_error),
                        None,
                        DrainCounts::default(),
                        EpochBackfillFinish::Failed {
                            preserve_pacing: false,
                        },
                    )?;
                    return Err(err);
                }
                self.warm_encrypted_media_epoch_secrets("post_subscription_sync");
                // This is a complete activation + group-subscription rebuild,
                // so it satisfies both older deferred refresh ownership slots
                // before the replay starts ingesting new history.
                self.pending_runtime_group_subscription_refresh = false;
                self.pending_uncheckpointed_runtime_group_subscription_refresh = false;
                self.record_subscription_rebuild(None).await;
                if let Err(err) = self.drain_pending_session_events_staged().await {
                    let terminal_error = err.privacy_safe_kind().to_string();
                    self.finish_epoch_backfill_execution(
                        execution,
                        EpochBackfillActivationOutcome::Succeeded,
                        Some(terminal_error),
                        None,
                        DrainCounts::default(),
                        EpochBackfillFinish::Failed {
                            preserve_pacing: false,
                        },
                    )?;
                    return Err(err);
                }
                let mut counts = DrainCounts::default();
                let retry_ordinal = execution.retry_ordinal;
                let eose_unconfirmed_ordinal = execution.eose_unconfirmed_ordinal;
                let no_progress_ordinal = execution.no_progress_ordinal;
                let verdict = match self.backfill_sdk_relay(&mut counts).await {
                    Ok(drained) => drained,
                    Err(mut err) => {
                        let terminal_error = err.source.privacy_safe_kind().to_string();
                        if err.partial_summary != SyncSummary::default() {
                            self.retain_checkpointed_sync_summary(std::mem::take(
                                &mut err.partial_summary,
                            ));
                        }
                        self.finish_epoch_backfill_execution(
                            execution,
                            EpochBackfillActivationOutcome::Succeeded,
                            Some(terminal_error),
                            None,
                            counts,
                            EpochBackfillFinish::Failed {
                                preserve_pacing: false,
                            },
                        )?;
                        return Err(err.source);
                    }
                };
                // Activation itself succeeded either way; what the verdict
                // decides is whether the replay it opened actually served this
                // account's stored history. An unconfirmed drain must not
                // disarm the detector, so it is recorded as a failed attempt
                // and its intent stays queued for the next seam.
                let error_kind = verdict.error_kind();
                if verdict.spends_eose_attempt() {
                    execution.pending.eose_unconfirmed_attempts = execution
                        .pending
                        .eose_unconfirmed_attempts
                        .saturating_add(1);
                }
                if verdict.made_no_progress() {
                    execution.pending.no_progress_attempts =
                        execution.pending.no_progress_attempts.saturating_add(1);
                } else {
                    execution.pending.no_progress_attempts = 0;
                }
                if error_kind.is_none()
                    && let Err(error) = self.clear_epoch_backfill_intent(&execution.pending)
                {
                    let terminal_error = error.privacy_safe_kind().to_string();
                    self.finish_epoch_backfill_execution(
                        execution,
                        EpochBackfillActivationOutcome::Succeeded,
                        Some(terminal_error),
                        None,
                        counts,
                        EpochBackfillFinish::Failed {
                            preserve_pacing: false,
                        },
                    )?;
                    return Err(error);
                }
                if let Some(error_kind) = error_kind {
                    tracing::warn!(
                        target: "marmot_app::epoch_stall",
                        method = "run_pending_epoch_backfill",
                        error_kind,
                        retry_ordinal,
                        deliveries = counts.deliveries,
                        skipped = counts.skipped,
                        eose_unconfirmed_ordinal,
                        "epoch-gap backfill drain ended without the relays confirming stored history; retrying later"
                    );
                    self.epoch_backfill_retry_not_before = if verdict.made_novel_progress() {
                        None
                    } else {
                        let pacing_ordinal = if verdict.made_no_progress() {
                            no_progress_ordinal
                        } else {
                            eose_unconfirmed_ordinal
                        };
                        Some(Instant::now() + self.epoch_backfill_retry_backoff(pacing_ordinal))
                    };
                    self.finish_epoch_backfill_execution(
                        execution,
                        EpochBackfillActivationOutcome::Succeeded,
                        Some(error_kind.to_owned()),
                        verdict.completion_kind(),
                        counts.clone(),
                        EpochBackfillFinish::Failed {
                            preserve_pacing: true,
                        },
                    )?;
                    return Ok(EpochBackfillRunOutcome::Incomplete(
                        self.take_checkpointed_sync_summary_or_default(),
                    ));
                }
                // Terminal intent and earned cooldown persist together so a
                // crash cannot re-arm an unpaced retry.
                let _recovered = self.finish_epoch_backfill_execution(
                    execution,
                    EpochBackfillActivationOutcome::Succeeded,
                    None,
                    verdict.completion_kind(),
                    counts.clone(),
                    EpochBackfillFinish::Succeeded,
                )?;
                Ok(EpochBackfillRunOutcome::Completed(
                    self.take_checkpointed_sync_summary_or_default(),
                ))
            }
            Err(err) => {
                let app_err: AppError = err.into();
                let terminal_error = app_err.privacy_safe_kind().to_string();
                self.finish_epoch_backfill_execution(
                    execution,
                    EpochBackfillActivationOutcome::Failed,
                    Some(terminal_error),
                    None,
                    DrainCounts::default(),
                    EpochBackfillFinish::Failed {
                        preserve_pacing: false,
                    },
                )?;
                Err(app_err)
            }
        }
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
        self.repair_full_history_with_intermediate_handoff(|client, summary| {
            // A directly-owned client can keep V2 on itself while the explicit
            // unfloored fallback runs. Cancellation returns the client to its
            // caller with that visibility still owned; the account worker uses
            // the sibling API below to publish the prefix synchronously instead.
            client.retain_checkpointed_sync_summary(summary);
        })
        .await
    }

    /// Run explicit repair while handing any unconfirmed detector-backfill
    /// prefix to the caller before the unfloored fallback crosses another
    /// relay await. The managed worker uses this chokepoint to broadcast V2;
    /// direct callers retain it on the client through [`Self::repair_full_history`].
    pub(crate) async fn repair_full_history_with_intermediate_handoff(
        &mut self,
        mut handoff: impl FnMut(&mut Self, SyncSummary),
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        match self.repair_full_history_inner(&mut handoff).await {
            Ok(()) => Ok(self.take_checkpointed_sync_summary_or_default()),
            Err(mut failure) => {
                self.merge_checkpointed_visibility_into_failure(&mut failure);
                Err(failure)
            }
        }
    }

    async fn repair_full_history_inner(
        &mut self,
        handoff: &mut impl FnMut(&mut Self, SyncSummary),
    ) -> Result<(), ClassifiedSyncFailure> {
        let refresh = self.refresh_group_routes().map_err(|error| {
            ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::StatePersist,
            )
        })?;
        // As in `sync_inner`: save only for persisted-state pruning, not for
        // in-memory routing-table deltas.
        if refresh.state_pruned {
            self.save_state_with_pending_local_group_deletion_frontier_clears()
                .map_err(|error| {
                    ClassifiedSyncFailure::at_stage(
                        SyncSummary::default(),
                        error,
                        SyncFailureStage::StatePersist,
                    )
                })?;
        }
        // Caller-directed repair is a fresh transport preparation, not an
        // assumption that startup ordering already installed the signer and
        // current group subscriptions.
        self.relay_plane
            .set_transport_signer(self.transport_signer.clone())
            .await;
        if self.has_pending_epoch_backfill() {
            // A deferred primary rotates behind queued work. Try each intent
            // that was pending on entry once, so an unavailable group cannot
            // hide a runnable retry. If every intent defers, retain them and
            // fall through to the caller-directed unfloored repair below.
            let pending_intents = usize::from(self.pending_epoch_backfill.is_some())
                .saturating_add(self.queued_epoch_backfills.len());
            for _ in 0..pending_intents {
                match self
                    .run_pending_epoch_backfill(EpochBackfillExecutionSeam::ExplicitCatchUp)
                    .await
                    .map_err(|error| {
                        // The backfill's AppError no longer carries which of
                        // its activation, subscription, drain, or projection
                        // boundaries failed. Keep the cause, but do not invent
                        // a stage from it.
                        ClassifiedSyncFailure::at_stage(
                            SyncSummary::default(),
                            error,
                            SyncFailureStage::Unknown,
                        )
                    })? {
                    EpochBackfillRunOutcome::Completed(summary) => {
                        self.retain_checkpointed_sync_summary(summary);
                        if self.delivery_overflow_recovery_pending {
                            let mut recovered = self.take_checkpointed_sync_summary_or_default();
                            self.recover_delivery_overflow_and_merge(&mut recovered)
                                .await?;
                            self.retain_checkpointed_sync_summary(recovered);
                            if self.delivery_overflow_recovery_pending {
                                let summary = self.take_checkpointed_sync_summary_or_default();
                                return Err(incomplete_full_history_repair(
                                    summary,
                                    DrainVerdict::Overflow,
                                ));
                            }
                        }
                        return Ok(());
                    }
                    // The detector replay did not confirm it served this
                    // account's history, so its intent remains queued and the
                    // caller-directed unfloored repair still has work to do.
                    // Hand off its already-ACKed prefix *before* that second
                    // relay pass: no V2 may remain future-local across it.
                    EpochBackfillRunOutcome::Incomplete(summary) => {
                        handoff(self, summary);
                        break;
                    }
                    EpochBackfillRunOutcome::Deferred => continue,
                    EpochBackfillRunOutcome::NotPending => break,
                }
            }
        }
        self.runtime
            .activate_transport(None)
            .await
            .map_err(|source| {
                ClassifiedSyncFailure::at_stage(
                    SyncSummary::default(),
                    AppError::from(source),
                    SyncFailureStage::TransportActivation,
                )
            })?;
        // Full-history repair must also rebuild every group subscription
        // without the ordinary incremental floor. Using `sync_runtime_groups`
        // here would reapply `last_transport_timestamp`, so retained group
        // events can remain invisible even though the account-wide transport
        // activation above was correctly unfloored.
        self.warm_encrypted_media_epoch_secrets("pre_subscription_sync");
        self.runtime
            .sync_transport_groups(None)
            .await
            .map_err(|error| {
                ClassifiedSyncFailure::at_stage(
                    SyncSummary::default(),
                    error.into(),
                    SyncFailureStage::GroupSubscriptionSync,
                )
            })?;
        self.warm_encrypted_media_epoch_secrets("post_subscription_sync");
        self.pending_runtime_group_subscription_refresh = false;
        self.pending_uncheckpointed_runtime_group_subscription_refresh = false;
        self.record_subscription_rebuild(None).await;
        self.drain_pending_session_events_staged()
            .await
            .map_err(|error| {
                ClassifiedSyncFailure::at_stage(
                    SyncSummary::default(),
                    error,
                    SyncFailureStage::Unknown,
                )
            })?;
        let mut counts = DrainCounts::default();
        let mut verdict = self.backfill_sdk_relay(&mut counts).await?;
        if verdict == DrainVerdict::Overflow || self.delivery_overflow_recovery_pending {
            let mut recovered = self.take_checkpointed_sync_summary_or_default();
            self.recover_delivery_overflow_and_merge(&mut recovered)
                .await?;
            self.retain_checkpointed_sync_summary(recovered);
            verdict = if self.delivery_overflow_recovery_pending {
                DrainVerdict::Overflow
            } else {
                DrainVerdict::Complete
            };
        }
        if verdict == DrainVerdict::Complete {
            Ok(())
        } else {
            Err(incomplete_full_history_repair(
                self.take_checkpointed_sync_summary_or_default(),
                verdict,
            ))
        }
    }

    pub(crate) async fn advance_convergence_after_runtime_sync(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<ScheduledConvergenceVisibility, AppError> {
        // The account worker refreshes transport groups once for the scheduled
        // convergence batch before calling this per-group path.
        let effects = self.runtime.advance_convergence_leased(group_id).await?;
        self.install_account_visibility_lease(
            effects.lease,
            effects.batches,
            effects.current_operation_id,
        );
        self.checkpoint_scheduled_convergence_effects(group_id, &effects.effects)
            .await
    }

    /// Project one scheduled convergence batch's effects, split from the
    /// advance itself so the projection is exercisable against a given batch of
    /// effects.
    #[cfg(test)]
    pub(crate) async fn observe_scheduled_convergence_effects(
        &mut self,
        group_id: &cgka_traits::GroupId,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
        let visibility = self
            .checkpoint_scheduled_convergence_effects(group_id, effects)
            .await?;
        if self.has_pending_runtime_group_subscription_refresh() {
            self.retry_pending_runtime_group_subscription_refresh()
                .await?;
        }
        self.publish_pending_new_message_notifications_best_effort()
            .await;
        Ok(visibility.summary)
    }

    /// Project and durably checkpoint one scheduled convergence batch without
    /// awaiting after V1 is promoted. This is the worker-facing half of the
    /// operation: it returns the only V2 copy immediately so the worker can
    /// publish it before subscription or notification network work.
    pub(super) async fn checkpoint_scheduled_convergence_effects(
        &mut self,
        group_id: &cgka_traits::GroupId,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<ScheduledConvergenceVisibility, AppError> {
        self.checkpoint_scheduled_convergence_effects_at(
            group_id,
            effects,
            self.current_account_visibility_observed_at(),
        )
        .await
    }

    async fn checkpoint_scheduled_convergence_effects_at(
        &mut self,
        group_id: &cgka_traits::GroupId,
        effects: &marmot_account::AccountDeviceEffects,
        source_received_at: u64,
    ) -> Result<ScheduledConvergenceVisibility, AppError> {
        self.remember_pending_convergence_groups(effects);
        // Observe before the publish gate, for the reason spelled out in
        // `observe_drained_session_events`.
        self.observe_recovery_evidence(effects)?;
        let publish_error = fail_if_publish_failed(effects).err();
        let mut affected_groups =
            self.project_account_non_session_visibility_at(effects, source_received_at, None)?;
        affected_groups.insert(group_id.clone());
        affected_groups.extend(effects.events.iter().filter_map(event_group_id).cloned());
        for affected_group in &affected_groups {
            self.refresh_group(affected_group);
        }

        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        let source_message_id_hex = String::new();
        let observe_result = self
            .observe_account_device_effects(
                effects,
                &display_names,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
                None,
            )
            .await;
        self.retain_uncheckpointed_sync_summary(summary);
        let routes_dirty = match observe_result {
            Ok(routes_dirty) => routes_dirty,
            Err(error) => {
                self.checkpoint_pending_sync_visibility()?;
                return Err(error);
            }
        };
        self.remember_uncheckpointed_runtime_group_subscription_refresh(routes_dirty);
        let routes_changed = self.refresh_group_routes()?.routing_changed;
        self.remember_uncheckpointed_runtime_group_subscription_refresh(routes_changed);
        for affected_group in &affected_groups {
            self.prune_plaintext_retention_for_group(affected_group)?;
        }
        self.stage_current_account_visibility_header_batch();
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        if let Some(error) = publish_error {
            return Err(error);
        }
        Ok(ScheduledConvergenceVisibility {
            summary: self.take_checkpointed_sync_summary_or_default(),
        })
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
        if self
            .runtime
            .group_record(group_id)
            .is_ok_and(|group| group.removed || group.disbanded.is_some())
        {
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
        self.app.remember_directory_message_sender(&message)?;
        let moderation_grant = message.kind == MARMOT_APP_EVENT_KIND_DELETE
            && self.delete_moderation_grant(&message.group_id, &message.sender);
        let message_projection = AppMessageProjection {
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

    fn discard_pending_application_event_ack(&mut self, event: &cgka_traits::engine::GroupEvent) {
        let event_id = match event {
            cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. } => message_id,
            cgka_traits::engine::GroupEvent::GroupJoined { via_welcome, .. } => via_welcome,
            _ => return,
        };
        self.pending_application_event_acks.remove(event_id);
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
        let visibility_batch_ids_to_ack = self
            .pending_account_visibility_lease
            .as_ref()
            .map(|pending| pending.staged_batch_ids.clone())
            .unwrap_or_default();
        let seen_start = self
            .state
            .seen_events
            .len()
            .saturating_sub(self.pending_seen_event_count);
        let delta = AccountState {
            label: self.state.label.clone(),
            seen_events: self.state.seen_events[seen_start..].to_vec(),
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
                        &visibility_batch_ids_to_ack,
                        group_id_hex,
                    )?,
            )
        } else {
            self.app
                .save_state_delta_clearing_local_group_deletion_frontiers_and_acking_application_events_and_visibility_batches(
                    &delta,
                    &frontiers_to_clear,
                    &application_event_ids_to_ack,
                    &visibility_batch_ids_to_ack,
                )?;
            None
        };
        self.finish_durably_acknowledged_account_visibility_batches(&visibility_batch_ids_to_ack)?;
        self.pending_seen_event_count = 0;
        self.pending_group_projection_updates.clear();
        self.pending_local_group_deletion_frontier_clears.clear();
        self.pending_application_event_acks.clear();
        // This save is the single visibility checkpoint for every caller that
        // staged projection/ACK state. Promote synchronously after commit and
        // before returning; an intervening unrelated save therefore completes,
        // rather than loses, an older cancelled operation's V1 batch.
        self.promote_uncheckpointed_sync_visibility();
        Ok(created_chat_list_row)
    }

    fn finish_durably_acknowledged_account_visibility_batches(
        &mut self,
        acknowledged_batch_ids: &[Vec<u8>],
    ) -> Result<(), AppError> {
        if acknowledged_batch_ids.is_empty() {
            return Ok(());
        }
        let Some(lease) = self
            .pending_account_visibility_lease
            .as_ref()
            .map(|pending| pending.lease)
        else {
            return Ok(());
        };
        self.runtime
            .forget_durably_acknowledged_visibility_batches(lease, acknowledged_batch_ids)?;
        let Some(pending) = self.pending_account_visibility_lease.as_mut() else {
            return Ok(());
        };
        pending
            .batches
            .retain(|batch| !acknowledged_batch_ids.contains(&batch.batch_id));
        pending
            .staged_batch_ids
            .retain(|batch_id| !acknowledged_batch_ids.contains(batch_id));
        if pending.batches.is_empty() {
            self.pending_account_visibility_lease = None;
        }
        Ok(())
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
    /// hydration re-emits a stored group's `GroupDisbanded` on every open, and a
    /// crash replays pending application events the live seam may already have
    /// projected. Token removal is a `DELETE` of rows that may be gone;
    /// `set_group_self_membership` writes an absolute value and no-ops when the
    /// group has no projection row; the queued registration removal is an upsert
    /// keyed on the group; and both invalidation sweeps skip rows they already
    /// withdrew.
    ///
    /// Returns whether the event forces a transport-route refresh.
    fn observe_event_projection_effects(
        &self,
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
        // A (re-)join or create restores the local account's membership so a
        // re-add after removal un-suppresses the group's unread count. Same
        // source-of-truth write as the departure path above: propagate the
        // error rather than swallow it.
        if let cgka_traits::engine::GroupEvent::GroupJoined { group_id, .. }
        | cgka_traits::engine::GroupEvent::GroupCreated { group_id } = event
        {
            let group_id_hex = hex::encode(group_id.as_slice());
            self.app.set_group_self_membership(
                &self.state.label,
                &group_id_hex,
                SelfMembership::Member,
            )?;
        }
        Ok(routes_dirty)
    }

    async fn observe_account_device_effects(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
        source_message_id_hex: &str,
        source_received_at: u64,
        outer_transport_at: Option<u64>,
    ) -> Result<bool, AppError> {
        // MLS member ids in this design are the Nostr account pubkey hex, so a
        // membership change whose subject matches the local account id hex is
        // the local account leaving / being removed (or, for joins, returning).
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut routes_dirty = false;
        let local_group_deletion_frontiers =
            self.local_group_deletion_frontiers_at_batch_start(effects)?;
        for event in &effects.events {
            // An event may mutate in-memory projection state before a later
            // projection/frontier operation fails. Keep its live summary local
            // until every fallible boundary and its durable engine-outbox ACK
            // have succeeded. On error, callers can checkpoint `summary` as the
            // exact fully-completed prefix without broadcasting the current
            // half-projected event (or replaying it twice after reopen).
            let mut event_summary = SyncSummary::default();
            let batch_start_frontier = event_group_id(event)
                .and_then(|group_id| {
                    local_group_deletion_frontiers.get(&hex::encode(group_id.as_slice()))
                })
                .copied();
            let crosses_frontier = match batch_start_frontier {
                Some(frontier) => self.local_deleted_group_event_crosses_frontier(
                    event,
                    frontier,
                    source_message_id_hex,
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
                self.remember_uncheckpointed_runtime_group_subscription_refresh(changed);
                // An intentionally suppressed event still owns an ACK
                // checkpoint, represented by an empty completed-prefix batch.
                summary.merge(event_summary);
                self.stage_current_account_visibility_event(event);
                continue;
            }
            let before = self.state.groups.len();
            let previous_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            let group_metadata =
                event_group_id(event).and_then(|group_id| self.runtime.group_record(group_id).ok());
            let group_projection = event_group_id(event)
                .map(|group_id| {
                    Ok::<_, AppError>(EventGroupProjection {
                        nostr_routing: self.nostr_routing_for_group(group_id)?,
                        group_metadata: group_metadata.as_ref(),
                        profile: self.profile_for_group(group_id),
                        admin_policy: self
                            .runtime
                            .admin_pubkeys(group_id)
                            .map(AppGroupAdminPolicyComponent::new)
                            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new())),
                        message_retention: self.message_retention_for_group(group_id),
                        agent_text_stream: self.agent_text_stream_for_group(group_id),
                        avatar_url: self.avatar_url_for_group(group_id),
                        encrypted_media: self.encrypted_media_for_group(group_id),
                        image: self.image_for_group(group_id),
                    })
                })
                .transpose()?;
            if let Some(message) = observe_event(
                &mut self.state,
                display_names,
                &mut event_summary,
                event,
                group_projection.as_ref(),
                source_message_id_hex,
                source_received_at,
                outer_transport_at,
                self.app.allow_loopback_blob_endpoints(),
            ) && let Some(gossip_message_id) =
                self.project_received_message(message, group_metadata.as_ref(), &mut event_summary)?
            {
                event_summary
                    .messages
                    .retain(|candidate| candidate.message_id_hex != gossip_message_id);
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
                source_message_id_hex,
            );
            let event_routes_dirty = self.observe_event_projection_effects(
                event,
                &local_account_id_hex,
                &mut event_summary,
            )?;
            routes_dirty |= event_routes_dirty;
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
                    // This injected seam represents an incomplete current event:
                    // leave both its summary and engine ACK out of the completed
                    // prefix so durable replay owns it exactly once.
                    self.discard_pending_application_event_ack(event);
                    return Err(AppError::BlockingTask(
                        "injected failure after application-event acknowledgement".to_owned(),
                    ));
                }
                self.stage_current_account_visibility_event(event);
            }
            self.remember_uncheckpointed_runtime_group_subscription_refresh(
                event_routes_dirty || self.state.groups.len() != before,
            );
            event_summary.projection_updates.extend(
                self.project_group_system_rows(std::slice::from_ref(event), source_received_at),
            );
            summary.merge(event_summary);
        }
        self.clear_terminal_local_group_deletion_frontiers(effects)?;
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

pub(crate) fn is_own_relay_echo(
    delivery: &cgka_traits::TransportDelivery,
    local_account_id_hex: &str,
    known_event_ids: &HashSet<String>,
) -> bool {
    let event_id = hex::encode(delivery.message.id.as_slice());
    if !known_event_ids.contains(&event_id) {
        return false;
    }
    NostrTransportEvent::from_transport_message(&delivery.message)
        .ok()
        .is_some_and(|event| event.pubkey == local_account_id_hex)
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
mod runtime_group_subscription_refresh_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::SyncSummary;
    use crate::client::epoch_stall::BackfillDecision;
    use crate::tests::ScriptedPushRelayClient;
    use crate::{AppPerformanceTelemetry, MarmotApp, MarmotRelayPlane};
    use marmot_account::AccountHome;
    use marmot_forensics::EpochStallBackfillTrigger;
    use tokio::sync::Notify;

    async fn pending_welcome_fixture(
        group_name: &str,
    ) -> (
        tempfile::TempDir,
        Arc<ScriptedPushRelayClient>,
        crate::AppClient,
        crate::AppClient,
        cgka_traits::GroupId,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let endpoint = crate::TransportEndpoint("wss://relay.example".to_owned());
        let mut relay_lists = crate::AccountRelayListStatus::empty();
        relay_lists.nip65.relays = vec![endpoint.0.clone()];
        relay_lists.nip65.read_relays = vec![endpoint.0.clone()];
        relay_lists.nip65.write_relays = vec![endpoint.0.clone()];
        relay_lists.refresh();
        app.write_nip65_route_generation(
            "bob",
            &crate::Nip65RouteGeneration {
                created_at: crate::unix_now_seconds(),
                event_id: "44".repeat(32),
                nip65: relay_lists.nip65.clone(),
            },
        )
        .unwrap();
        app.remember_directory_relay_lists(&bob.account_id_hex, &relay_lists)
            .unwrap();
        app.mark_key_package_cutover_scan_complete("bob").unwrap();
        let plane = MarmotRelayPlane::new(None, relay.clone());
        let mut alice = app
            .client_with_relay_plane("alice", &plane, None)
            .await
            .unwrap();
        let mut bob_client = app
            .client_with_relay_plane("bob", &plane, None)
            .await
            .unwrap();
        bob_client.publish_key_package().await.unwrap();
        bob_client.sync().await.unwrap();
        let group_id = alice
            .create_group(group_name, &[bob.account_id_hex.as_str()])
            .await
            .unwrap();
        (dir, relay, alice, bob_client, group_id)
    }

    #[tokio::test]
    async fn pending_route_refresh_quiesces_and_rotates_post_join_maintenance_subscription() {
        let (_dir, relay, _alice, mut bob_client, group_id) =
            pending_welcome_fixture("post-join maintenance route rotation").await;

        let joined = bob_client.sync().await.unwrap();
        assert_eq!(joined.joined_groups, vec![group_id.clone()]);
        assert!(!bob_client.has_pending_runtime_group_subscription_refresh());

        let route_a = bob_client
            .routing
            .snapshot()
            .group_routes
            .into_iter()
            .find(|route| route.group_id == group_id)
            .expect("the joined group must have an ordinary route");
        bob_client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        let (subscription_a, active_route_a) = bob_client
            .post_join_maintenance_subscriptions
            .get(&group_id)
            .cloned()
            .expect("the CatchUp obligation must install route A maintenance");
        assert_eq!(active_route_a, route_a);

        for endpoint in &route_a.endpoints {
            bob_client
                .relay_plane
                .handle_relay_eose_for_test(endpoint.clone(), subscription_a.clone())
                .await;
        }
        assert_eq!(
            bob_client
                .adapter
                .group_maintenance_any_eose(&subscription_a)
                .await,
            Some(true),
            "route A must hold stale EOSE evidence before the refresh starts",
        );

        // Adapter teardown is local-first. Even if relay-side unsubscribe
        // fails, the client must forget route A so the successful refresh can
        // install route B instead of retaining a dead ownership record.
        relay.fail_next_unsubscribe();
        bob_client.pending_runtime_group_subscription_refresh = true;
        bob_client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        assert!(
            !bob_client
                .post_join_maintenance_subscriptions
                .contains_key(&group_id),
            "a pending ordinary-route refresh must quiesce route A maintenance",
        );
        assert_eq!(
            bob_client
                .adapter
                .group_maintenance_any_eose(&subscription_a)
                .await,
            None,
            "quiescing route A must forget its stale EOSE evidence",
        );
        let status = bob_client.runtime.maintenance_status(&group_id).unwrap();
        let post_join = status
            .obligations
            .iter()
            .find(|obligation| obligation.trigger == cgka_traits::MaintenanceTrigger::PostJoin)
            .expect("the post-join obligation must remain durable while routes refresh");
        assert_eq!(
            post_join.phase,
            cgka_traits::MaintenancePhase::CatchUp,
            "stale route A EOSE must not advance the obligation",
        );

        let mut route_b = route_a;
        route_b.endpoints = vec![crate::TransportEndpoint("wss://relay-b.example".to_owned())];
        assert!(
            bob_client
                .routing
                .replace_group_routes(&group_id, vec![route_b.clone()]),
            "route B must differ from the installed ordinary route",
        );
        bob_client.pending_runtime_group_subscription_refresh = false;
        bob_client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();

        let (subscription_b, active_route_b) = bob_client
            .post_join_maintenance_subscriptions
            .get(&group_id)
            .cloned()
            .expect("the refreshed route must reinstall post-join maintenance");
        assert_eq!(active_route_b, route_b);
        assert_ne!(
            subscription_b, subscription_a,
            "the endpoint change must produce a fresh maintenance subscription id",
        );
        assert_eq!(
            bob_client
                .adapter
                .group_maintenance_any_eose(&subscription_b)
                .await,
            Some(false),
            "route B must start with fresh EOSE state",
        );
    }

    #[tokio::test]
    async fn account_reactivation_reinstalls_same_route_post_join_maintenance_subscription() {
        let (_dir, relay, _alice, mut bob_client, group_id) =
            pending_welcome_fixture("post-join maintenance account reactivation").await;

        let joined = bob_client.sync().await.unwrap();
        assert_eq!(joined.joined_groups, vec![group_id.clone()]);
        bob_client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        let (subscription_before, route_before) = bob_client
            .post_join_maintenance_subscriptions
            .get(&group_id)
            .cloned()
            .expect("the CatchUp obligation must install maintenance");
        let accepted_before = relay
            .accepted_subscriptions()
            .into_iter()
            .filter(|subscription| {
                matches!(
                    subscription,
                    transport_nostr_adapter::NostrSubscription::GroupMaintenance {
                        group_id: subscribed_group,
                        ..
                    } if subscribed_group == &group_id
                )
            })
            .count();

        // Account activation replaces every SDK subscription and clears the
        // adapter's maintenance ownership/EOSE state, while this AppClient and
        // its same-route ephemeral entry survive.
        bob_client.runtime.activate_transport(None).await.unwrap();
        assert_eq!(
            bob_client
                .adapter
                .group_maintenance_any_eose(&subscription_before)
                .await,
            None,
            "reactivation must retire the old adapter registration",
        );
        assert!(
            bob_client
                .post_join_maintenance_subscriptions
                .contains_key(&group_id),
            "the regression requires a surviving same-route client entry",
        );

        bob_client
            .advance_post_join_maintenance_subscriptions()
            .await
            .unwrap();
        let (subscription_after, route_after) = bob_client
            .post_join_maintenance_subscriptions
            .get(&group_id)
            .cloned()
            .expect("maintenance must reinstall after account activation");
        assert_eq!(route_after, route_before);
        assert_eq!(
            subscription_after, subscription_before,
            "same account/group/route intentionally reuses its deterministic id",
        );
        assert_eq!(
            bob_client
                .adapter
                .group_maintenance_any_eose(&subscription_after)
                .await,
            Some(false),
            "the reused id must own a fresh adapter registration",
        );
        let accepted_after = relay
            .accepted_subscriptions()
            .into_iter()
            .filter(|subscription| {
                matches!(
                    subscription,
                    transport_nostr_adapter::NostrSubscription::GroupMaintenance {
                        group_id: subscribed_group,
                        ..
                    } if subscribed_group == &group_id
                )
            })
            .count();
        assert_eq!(
            accepted_after,
            accepted_before + 1,
            "maintenance must be reissued instead of polling a forgotten id",
        );
    }

    #[tokio::test]
    async fn catch_up_checkpoint_defers_subscription_refresh_after_durable_save() {
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
        client
            .checkpoint_sync_prefix(true, 0)
            .expect("a durable checkpoint must not await relay I/O");
        assert!(client.has_pending_runtime_group_subscription_refresh());

        client
            .retry_pending_runtime_group_subscription_refresh()
            .await
            .expect_err("the deferred injected subscription failure must reach the retry");
        assert!(client.has_pending_runtime_group_subscription_refresh());

        assert!(
            !client
                .retry_pending_runtime_group_subscription_refresh()
                .await
                .unwrap()
        );
        assert!(!client.has_pending_runtime_group_subscription_refresh());
    }

    #[tokio::test]
    async fn cancelled_next_event_is_returned_by_following_sync() {
        let (_dir, relay, _alice, mut bob_client, group_id) =
            pending_welcome_fixture("cancelled next-event output").await;

        relay.block_next_subscribe();
        let mut next = Box::pin(bob_client.next_event());
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut next => {
                    panic!("next_event returned before its injected refresh block: {result:?}")
                }
                () = relay.wait_for_blocked_subscribe() => {}
            }
        })
        .await
        .expect("next_event must reach the post-ingest subscription refresh");
        drop(next);
        relay.release_subscribe();

        assert!(bob_client.has_pending_runtime_group_subscription_refresh());
        assert_eq!(
            bob_client
                .pending_checkpointed_sync_summary
                .as_ref()
                .map(|summary| summary.joined_groups.as_slice()),
            Some(std::slice::from_ref(&group_id)),
            "cancellation must retain the already-durable join summary",
        );

        let recovered = tokio::time::timeout(Duration::from_secs(5), bob_client.sync())
            .await
            .expect("the following sync must recover the cancelled next-event output")
            .unwrap();
        assert_eq!(recovered.joined_groups, vec![group_id.clone()]);
        assert!(bob_client.pending_checkpointed_sync_summary.is_none());
        assert!(!bob_client.has_pending_runtime_group_subscription_refresh());
        let next = bob_client.sync().await.unwrap();
        assert!(
            !next.joined_groups.contains(&group_id),
            "the retained summary must be returned exactly once",
        );
    }

    #[tokio::test]
    async fn cancelled_sync_v1_is_checkpointed_by_the_managed_fallback() {
        let (_dir, _relay, _alice, mut bob_client, group_id) =
            pending_welcome_fixture("pre-checkpoint cancellation").await;
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        bob_client.block_after_sync_delivery_projection = Some((entered.clone(), release.clone()));

        let mut sync = Box::pin(bob_client.sync_with_classified_partial_progress());
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut sync => {
                    panic!("sync returned before its pre-checkpoint block: {result:?}")
                }
                () = entered.notified() => {}
            }
        })
        .await
        .expect("sync must retain the projected delivery before checkpointing");
        drop(sync);
        release.notify_one();

        assert_eq!(
            bob_client
                .pending_uncheckpointed_sync_summary
                .as_ref()
                .map(|summary| summary.joined_groups.as_slice()),
            Some(std::slice::from_ref(&group_id)),
        );
        assert!(bob_client.pending_checkpointed_sync_summary.is_none());
        assert!(
            !bob_client.pending_application_event_acks.is_empty(),
            "V1 must retain the matching engine-outbox acknowledgement set",
        );

        // The managed worker's timeout/error fallback synchronously lands the
        // still-staged projection and ACKs before it tries to publish V2.
        assert!(bob_client.checkpoint_pending_sync_visibility().unwrap());
        assert!(bob_client.pending_uncheckpointed_sync_summary.is_none());
        assert_eq!(
            bob_client
                .pending_checkpointed_sync_summary
                .as_ref()
                .map(|summary| summary.joined_groups.as_slice()),
            Some(std::slice::from_ref(&group_id)),
        );
        assert!(bob_client.pending_application_event_acks.is_empty());

        let recovered = bob_client
            .take_pending_checkpointed_sync_summary()
            .expect("the fallback must receive the promoted V2 batch");
        assert_eq!(recovered.joined_groups, vec![group_id]);
        assert!(bob_client.pending_checkpointed_sync_summary.is_none());
        assert!(!bob_client.checkpoint_pending_sync_visibility().unwrap());
        assert!(
            bob_client.sync().await.unwrap().joined_groups.is_empty(),
            "the checkpointed batch must be handed off exactly once",
        );
    }

    #[tokio::test]
    async fn an_escalation_without_a_summary_still_occupies_the_v2_handoff() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let escalation = crate::EpochStallEscalation {
            group_id: cgka_traits::GroupId::new(vec![0x5a; 32]),
            stalled_epoch: 9,
            arms: 3,
        };
        client
            .pending_epoch_stall_escalations
            .push(escalation.clone());

        let summary = client
            .take_pending_checkpointed_sync_summary()
            .expect("an escalation-only handoff must not collapse to None");
        assert_eq!(summary.epoch_stall_escalations, vec![escalation]);
        assert!(client.take_pending_checkpointed_sync_summary().is_none());
    }

    #[tokio::test]
    async fn cancelled_sync_after_prefix_checkpoint_leaves_summary_owned_by_client() {
        let (_dir, _relay, _alice, mut bob_client, group_id) =
            pending_welcome_fixture("post-checkpoint cancellation").await;
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        bob_client.block_after_sync_prefix_checkpoint = Some((entered.clone(), release.clone()));

        let mut sync = Box::pin(bob_client.sync_with_classified_partial_progress());
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut sync => {
                    panic!("sync returned before its post-checkpoint test block: {result:?}")
                }
                () = entered.notified() => {}
            }
        })
        .await
        .expect("sync must checkpoint the relay prefix before returning it");
        drop(sync);
        release.notify_one();

        assert!(bob_client.pending_uncheckpointed_sync_summary.is_none());
        assert_eq!(
            bob_client
                .pending_checkpointed_sync_summary
                .as_ref()
                .map(|summary| summary.joined_groups.as_slice()),
            Some(std::slice::from_ref(&group_id)),
            "V2 must remain client-owned while the post-checkpoint future is cancellable",
        );
        assert!(bob_client.pending_application_event_acks.is_empty());

        let recovered = bob_client.sync().await.unwrap();
        assert_eq!(recovered.joined_groups, vec![group_id]);
        assert!(bob_client.pending_checkpointed_sync_summary.is_none());
    }

    #[tokio::test]
    async fn scheduled_convergence_returns_v2_before_subscription_network_work() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        client.prepare_transport().await.unwrap();
        let group_id = client
            .create_group("convergence visibility handoff", &[])
            .await
            .unwrap();
        client
            .checkpoint_sync_prefix(true, 0)
            .expect("the route change must be checkpointed without relay I/O");
        assert!(client.has_pending_runtime_group_subscription_refresh());

        let visibility = tokio::time::timeout(
            Duration::from_secs(5),
            client.checkpoint_scheduled_convergence_effects(
                &group_id,
                &marmot_account::AccountDeviceEffects::default(),
            ),
        )
        .await
        .expect("the V2 handoff must not await a subscription refresh")
        .unwrap();
        assert_eq!(visibility.summary, SyncSummary::default());
        assert!(client.pending_checkpointed_sync_summary.is_none());
        assert!(
            client.has_pending_runtime_group_subscription_refresh(),
            "the V2 handoff must leave subscription network work for the worker scheduler",
        );
    }

    #[tokio::test]
    async fn cancelled_next_event_retains_an_empty_epoch_backfill_wake_batch() {
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
        let group_id = client
            .create_group_with_options_and_telemetry(
                "empty next-event backfill wake",
                &[],
                crate::AppCreateGroupOptions::default(),
                &telemetry,
            )
            .await
            .unwrap()
            .group_id;
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client
            .apply_backfill_decision(
                &group_id,
                stalled_epoch,
                BackfillDecision::Arm,
                EpochStallBackfillTrigger::UndecryptableThreshold,
            )
            .unwrap();
        assert!(client.has_pending_epoch_backfill());

        client.pending_runtime_group_subscription_refresh = true;
        relay.block_next_subscribe();
        let mut finalize =
            Box::pin(client.finalize_direct_next_event_summary(SyncSummary::default()));
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut finalize => {
                    panic!("empty wake batch finalized before its injected refresh block: {result:?}")
                }
                () = relay.wait_for_blocked_subscribe() => {}
            }
        })
        .await
        .expect("empty wake batch must reach the post-ingest subscription refresh");
        drop(finalize);
        relay.release_subscribe();

        assert_eq!(
            client.pending_checkpointed_sync_summary,
            Some(SyncSummary::default()),
            "occupied retention must distinguish an empty wake batch from no batch",
        );
        assert!(client.has_pending_runtime_group_subscription_refresh());

        relay.fail_next_subscribe();
        tokio::time::timeout(Duration::from_secs(5), client.next_event())
            .await
            .expect("the injected retry failure must return promptly")
            .expect_err("an empty wake batch must not hide a refresh error");
        assert_eq!(
            client.pending_checkpointed_sync_summary,
            Some(SyncSummary::default()),
            "an empty wake batch must remain occupied across retry failure",
        );
        assert!(client.has_pending_runtime_group_subscription_refresh());

        let recovered = tokio::time::timeout(Duration::from_secs(5), client.next_event())
            .await
            .expect("a successful retry must return the retained empty wake batch")
            .unwrap();
        assert_eq!(recovered, SyncSummary::default());
        assert!(client.pending_checkpointed_sync_summary.is_none());
        assert!(!client.has_pending_runtime_group_subscription_refresh());
        assert!(client.has_pending_epoch_backfill());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.next_event())
                .await
                .is_err(),
            "the empty wake batch must be returned exactly once",
        );
    }

    #[tokio::test]
    async fn drained_event_returns_summary_and_defers_subscription_retry() {
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
        let created = client
            .create_group_with_options_and_telemetry(
                "drained-event retry intent",
                &[],
                crate::AppCreateGroupOptions::default(),
                &telemetry,
            )
            .await
            .unwrap();
        // Model a durable engine event replay whose app projection did not
        // survive the prior process. Re-observation restores the group and
        // therefore owes an ordinary subscription rebuild.
        client.state.groups.clear();
        let group_id = created.group_id;
        let joined = cgka_traits::engine::GroupEvent::GroupJoined {
            group_id: group_id.clone(),
            via_welcome: cgka_traits::MessageId::new(vec![0x42; 32]),
            welcomer: None,
        };
        let effects = marmot_account::AccountDeviceEffects {
            events: vec![joined.clone()],
            ..Default::default()
        };

        // A drained projection is visibility-first: the injected relay failure
        // must remain untouched until the explicit background retry.
        relay.fail_next_subscribe();
        let summary = client
            .observe_drained_session_events(&effects)
            .await
            .expect("the durable drained projection must not await relay I/O");
        assert_eq!(summary.joined_groups, vec![group_id]);
        assert_eq!(summary.events, vec![joined]);
        assert!(client.has_pending_runtime_group_subscription_refresh());

        client
            .retry_pending_runtime_group_subscription_refresh()
            .await
            .expect_err("the deferred injected subscription failure must reach the retry");
        assert!(client.has_pending_runtime_group_subscription_refresh());

        assert!(
            !client
                .retry_pending_runtime_group_subscription_refresh()
                .await
                .unwrap()
        );
        assert!(!client.has_pending_runtime_group_subscription_refresh());
    }

    #[tokio::test]
    async fn direct_sync_finalizer_retains_summary_across_refresh_failure() {
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
        let created = client
            .create_group_with_options_and_telemetry(
                "direct sync retained output",
                &[],
                crate::AppCreateGroupOptions::default(),
                &telemetry,
            )
            .await
            .unwrap();
        client.pending_runtime_group_subscription_refresh = true;
        let durable_summary = SyncSummary {
            joined_groups: vec![created.group_id],
            ..Default::default()
        };
        client.retain_checkpointed_sync_summary(durable_summary.clone());

        relay.fail_next_subscribe();
        client
            .finalize_direct_sync_summary()
            .await
            .expect_err("the injected direct subscription finalizer must fail");
        assert_eq!(
            client.pending_checkpointed_sync_summary,
            Some(durable_summary.clone())
        );
        assert!(client.has_pending_runtime_group_subscription_refresh());

        let recovered = client.finalize_direct_sync_summary().await.unwrap();
        assert_eq!(recovered, durable_summary);
        assert!(client.pending_checkpointed_sync_summary.is_none());
        assert!(!client.has_pending_runtime_group_subscription_refresh());
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

/// How an epoch-gap backfill drain that stops now should be read.
///
/// An account holding no subscriptions is deliberately not complete: nothing
/// was subscribed, so nothing can have served its stored history, and a replay
/// that reaches that state recovered nothing.
fn backfill_drain_verdict(eose: AccountSubscriptionEose) -> DrainVerdict {
    if eose.subscriptions == 0 || !eose.any() {
        DrainVerdict::NoRelayEose
    } else if eose.complete() {
        DrainVerdict::Complete
    } else {
        DrainVerdict::EoseTimeout
    }
}

/// Doubling backoff from `base`, capped at [`EPOCH_BACKFILL_RETRY_BACKOFF_CAP`]
/// (or `base` itself when a test override exceeds the cap). Pure so the
/// schedule is table-testable without a client.
fn retry_backoff_for_ordinal(base: Duration, retry_ordinal: u64) -> Duration {
    let doubling = 1_u32 << retry_ordinal.min(8);
    base.saturating_mul(doubling)
        .min(EPOCH_BACKFILL_RETRY_BACKOFF_CAP.max(base))
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
    use super::{
        DrainVerdict, backfill_drain_verdict, incomplete_full_history_repair,
        reconciliation_start_after_cursor, restore_epoch_backfill_retry_deadline,
        retry_backoff_for_ordinal, transport_reconciliation_record,
    };
    use crate::tests::{
        ScriptedPushRelayClient, bounded_epoch_backfill_config, client_on_app_relay_plane,
    };
    use crate::{
        EPOCH_BACKFILL_RETRY_BACKOFF, EPOCH_BACKFILL_RETRY_BACKOFF_CAP, MarmotApp,
        SyncFailureStage, SyncSummary,
    };
    use marmot_account::AccountHome;
    use std::sync::Arc;
    use std::time::Duration;
    use transport_nostr_adapter::AccountSubscriptionEose;

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

    #[test]
    fn the_retry_backoff_doubles_from_its_base_and_caps() {
        // The production schedule the reviewer probed by hand: 15s, 30s, 60s,
        // 120s, 240s, then pinned at the 5-minute cap — and the shift is
        // clamped so absurd ordinals cannot overflow.
        let base = EPOCH_BACKFILL_RETRY_BACKOFF;
        let expect_secs = [15, 30, 60, 120, 240, 300, 300, 300];
        for (ordinal, secs) in expect_secs.iter().enumerate() {
            assert_eq!(
                retry_backoff_for_ordinal(base, ordinal as u64),
                Duration::from_secs(*secs),
                "ordinal {ordinal}"
            );
        }
        assert_eq!(
            retry_backoff_for_ordinal(base, u64::MAX),
            EPOCH_BACKFILL_RETRY_BACKOFF_CAP,
            "the shift clamp must hold for absurd ordinals"
        );
        // A test override larger than the cap stays at its own base rather
        // than being shrunk by the cap.
        let oversized = EPOCH_BACKFILL_RETRY_BACKOFF_CAP * 2;
        assert_eq!(retry_backoff_for_ordinal(oversized, 0), oversized);
    }

    #[test]
    fn restored_epoch_backfill_deadlines_are_capped_and_checked() {
        assert!(restore_epoch_backfill_retry_deadline(None).is_none());
        let now_ms = crate::unix_now_seconds().saturating_mul(1_000);
        assert!(restore_epoch_backfill_retry_deadline(Some(now_ms)).is_none());
        let restored = restore_epoch_backfill_retry_deadline(Some(now_ms.saturating_add(u64::MAX)))
            .expect("a far-future deadline must restore as a capped delay");
        let cap = EPOCH_BACKFILL_RETRY_BACKOFF_CAP + Duration::from_secs(1);
        assert!(
            restored.saturating_duration_since(std::time::Instant::now()) <= cap,
            "restored wall-clock delay must not exceed the retry cap"
        );
    }

    #[test]
    fn drain_verdict_reads_end_of_stored_events_progress() {
        let progress =
            |subscriptions,
             with_eose,
             relay_subscription_attempts,
             relay_subscription_attempts_with_eose| AccountSubscriptionEose {
                subscriptions,
                with_eose,
                relay_subscription_attempts,
                relay_subscription_attempts_with_eose,
            };
        assert_eq!(
            backfill_drain_verdict(progress(2, 2, 2, 2)),
            DrainVerdict::Complete
        );
        assert_eq!(
            backfill_drain_verdict(progress(2, 1, 2, 1)),
            DrainVerdict::EoseTimeout
        );
        assert_eq!(
            backfill_drain_verdict(progress(2, 0, 2, 0)),
            DrainVerdict::NoRelayEose
        );
        assert_eq!(
            backfill_drain_verdict(progress(0, 0, 0, 0)),
            DrainVerdict::NoRelayEose,
            "an account with nothing subscribed cannot have been served"
        );
        assert_eq!(
            backfill_drain_verdict(progress(2, 2, 4, 2)),
            DrainVerdict::EoseTimeout,
            "EOSE on every logical subscription is insufficient while another relay remains uncovered"
        );
    }

    #[test]
    fn explicit_full_history_repair_requires_end_of_stored_events() {
        for verdict in [
            DrainVerdict::NoRelayEose,
            DrainVerdict::EoseTimeout,
            DrainVerdict::NovelProgressQuantumYield,
            DrainVerdict::NoProgressQuantumYield,
            DrainVerdict::Overflow,
        ] {
            let partial = SyncSummary {
                joined_groups: vec![cgka_traits::GroupId::new(vec![0x42])],
                ..SyncSummary::default()
            };
            let error = incomplete_full_history_repair(partial.clone(), verdict);
            assert_eq!(error.partial_summary, partial);
            assert!(
                error
                    .source
                    .to_string()
                    .contains(verdict.error_kind().unwrap()),
                "the caller must be able to distinguish why the repair stayed incomplete",
            );
        }
    }

    #[tokio::test]
    async fn explicit_full_history_repair_preserves_ingested_prefix_without_eose() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let ingested = SyncSummary {
            joined_groups: vec![cgka_traits::GroupId::new(vec![0x42])],
            ..SyncSummary::default()
        };
        client.retain_checkpointed_sync_summary(ingested.clone());

        let failure = client
            .repair_full_history()
            .await
            .expect_err("relay silence cannot prove that full history was served");

        assert_eq!(failure.partial_summary, ingested);
        assert_eq!(
            failure.classification().failure_stage,
            SyncFailureStage::RelayReceive
        );
        let source = failure.source.to_string();
        assert!(
            source.contains("backfill_drain_no_relay_eose")
                || source.contains("backfill_drain_no_progress_quantum_yield"),
            "the public failure must preserve the incomplete-drain cause; actual: {source}"
        );
    }
}
