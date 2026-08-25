use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::{GroupId, TransportAdapter};
use storage_sqlite::clamp_to_max_future_skew;
use tokio::time::timeout;
use transport_nostr_adapter::AccountSubscriptionEose;
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
    AppPerformanceTelemetry, ClassifiedSyncFailure, EPOCH_BACKFILL_EOSE_ATTEMPT_LIMIT,
    EPOCH_BACKFILL_EOSE_WAIT, EPOCH_BACKFILL_RETRY_BACKOFF, EPOCH_BACKFILL_RETRY_BACKOFF_CAP,
    SDK_DRAIN_WAIT, SDK_FIRST_SYNC_WAIT, SelfMembership, SyncFailure, SyncSummary,
    TRANSPORT_CURSOR_MAX_FUTURE_SKEW, unix_now_seconds,
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

/// In-flight epoch-gap replay bookkeeping shared by begin/finish helpers.
pub(crate) struct EpochBackfillExecution {
    pub(crate) pending: PendingEpochBackfill,
    pub(crate) epochs_before: HashMap<cgka_traits::GroupId, u64>,
    pub(crate) retry_ordinal: u64,
    pub(crate) started: Instant,
}

struct EpochBackfillReplayOutcome {
    duration_ms: u64,
    activation_outcome: EpochBackfillActivationOutcome,
    error_kind: Option<String>,
    completion_kind: Option<EpochBackfillCompletionKind>,
    counts: DrainCounts,
    succeeded: bool,
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
pub(crate) enum EpochBackfillRunOutcome {
    NotPending,
    Deferred,
    Completed(SyncSummary),
    /// The replay ran, ingested whatever it did reach, and stopped without the
    /// relays confirming they had served the account's stored history. The
    /// summary is real and must still be published; the intent stays pending.
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
    EndOfStoredEvents(Duration),
    /// Epoch-gap backfill that has spent its end-of-stored-events attempt
    /// budget ([`EPOCH_BACKFILL_EOSE_ATTEMPT_LIMIT`]). Drains exactly like
    /// [`Self::Quiescence`] so an account whose group route has one unreachable
    /// relay can still heal, and reports itself as the weaker claim it is.
    QuiescenceFallback,
}

/// How a drain ended.
///
/// Only [`DrainCompletion::EndOfStoredEvents`] can reach the two incomplete
/// verdicts; a quiescence drain is complete by its own contract as soon as the
/// relays go quiet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainVerdict {
    /// Every live subscription reached end-of-stored-events and the relays then
    /// went quiet: the account's stored history was served in full.
    Complete,
    /// The relays went quiet under the fallback contract, after the gate had
    /// spent its attempt budget. Recovery ran and is not a failure, but nothing
    /// confirms the history was served in full.
    QuiescenceFallback,
    /// The silence budget ran out with stored history still unconfirmed, though
    /// some relay did reach end-of-stored-events.
    EoseTimeout,
    /// The silence budget ran out without one relay reaching
    /// end-of-stored-events: the subscriptions were registered but never
    /// served.
    NoRelayEose,
}

impl DrainVerdict {
    /// The audit row's `error_kind` for a drain that did not complete.
    fn error_kind(self) -> Option<&'static str> {
        match self {
            Self::Complete | Self::QuiescenceFallback => None,
            Self::EoseTimeout => Some("backfill_drain_eose_timeout"),
            Self::NoRelayEose => Some("backfill_drain_no_relay_eose"),
        }
    }

    /// What the completed audit row should claim about this drain, so a
    /// fallback is never read as an end-of-stored-events confirmation.
    fn completion_kind(self) -> Option<EpochBackfillCompletionKind> {
        match self {
            Self::Complete => Some(EpochBackfillCompletionKind::EndOfStoredEvents),
            Self::QuiescenceFallback => Some(EpochBackfillCompletionKind::QuiescenceFallback),
            Self::EoseTimeout | Self::NoRelayEose => None,
        }
    }
}

/// What one drain loop saw on the wire.
///
/// `deliveries` counts receives the drain ingested; `skipped` counts those it
/// dropped as a relay echo of this device's own publish or as an event already
/// in the seen index. Keeping the two apart is what lets a field export tell a
/// long drain that was making progress from one a relay held open with traffic
/// carrying no new history.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DrainCounts {
    pub(crate) deliveries: u64,
    pub(crate) skipped: u64,
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
    ) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
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
                    let decision = self
                        .epoch_stall
                        .observe_resource_refusal(group_id.clone(), record.epoch);
                    self.apply_backfill_decision(
                        group_id,
                        record.epoch.0,
                        decision,
                        EpochStallBackfillTrigger::ResourceRefusal,
                    );
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
    /// Recovery evidence only. `remember_pending_convergence_groups` is
    /// deliberately not paired here the way it is at the convergence and inbound
    /// seams: the callers of this gate do not remember pending convergence on
    /// their success paths either, so recording it on the failure path alone
    /// would invent a scheduling contract they do not otherwise hold.
    pub(crate) fn observe_recovery_evidence_then_fail_if_publish_failed(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        self.observe_recovery_evidence(effects);
        fail_if_publish_failed(effects)
    }

    pub(crate) async fn sync_runtime_groups(&mut self) -> Result<(), AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.warm_encrypted_media_epoch_secrets("pre_subscription_sync");
        self.runtime.sync_transport_groups(rebuild_since).await?;
        self.warm_encrypted_media_epoch_secrets("post_subscription_sync");
        Ok(())
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

    pub(crate) async fn prepare_transport(&mut self) -> Result<(), AppError> {
        self.prepare_transport_with_telemetry(None).await
    }

    async fn prepare_transport_with_telemetry(
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
        // Before any subscription goes out: auth-gated relays (NIP-42)
        // withhold gift-wrapped welcomes from unauthenticated subscribers.
        let activation_started = Instant::now();
        self.relay_plane
            .set_transport_signer(self.transport_signer.clone())
            .await;
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
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
        match self.sync_inner(None).await {
            Ok(summary) => Ok(summary),
            Err(mut failure) => {
                self.drain_epoch_stall_escalations(&mut failure.partial_summary);
                Err(failure)
            }
        }
    }

    pub(crate) async fn sync_with_startup_stage_telemetry(
        &mut self,
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        match self.sync_inner(Some(telemetry)).await {
            Ok(summary) => Ok(summary),
            Err(mut failure) => {
                self.drain_epoch_stall_escalations(&mut failure.partial_summary);
                Err(failure)
            }
        }
    }

    async fn sync_inner(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
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
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp)
            .map(|timestamp| timestamp.0);
        self.prepare_transport_for_sync(telemetry)
            .await
            .map_err(|(stage, error)| {
                ClassifiedSyncFailure::at_stage(SyncSummary::default(), error, stage)
            })?;
        // A complete startup/catch-up rebuild satisfies any older deferred
        // refresh intent before this pass starts ingesting new deliveries.
        self.pending_runtime_group_subscription_refresh = false;
        // Both the inbox/group activation and the group-subscription refresh
        // have now registered on relays; emit the rebuild audit row from the
        // drained registration log before draining inbound deliveries.
        self.record_subscription_rebuild(rebuild_since_secs).await;
        let mut counts = DrainCounts::default();
        let mut summary = self.sync_sdk_relay(&mut counts).await?;
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
        let effects = self.runtime.drain().await?;
        self.observe_drained_session_events(&effects).await
    }

    /// Project one drained batch of engine events, split from the drain itself
    /// so the projection is exercisable against a given batch of effects.
    pub(crate) async fn observe_drained_session_events(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
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
        fail_if_publish_failed(effects)?;
        let mut summary = SyncSummary::default();
        if effects.events.is_empty() {
            self.drain_epoch_stall_escalations(&mut summary);
            return Ok(summary);
        }
        let display_names = self.app.display_names_by_id()?;
        let source_received_at = unix_now_seconds();
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
        let mut gossip_message_ids = HashSet::new();
        for event in &effects.events {
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
                &mut summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
                source_received_at,
                None,
                self.app.allow_loopback_blob_endpoints(),
            ) && let Some(gossip_message_id) =
                self.project_received_message(message, group_metadata.as_ref(), &mut summary)?
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
                &source_message_id_hex,
            );
            routes_dirty |=
                self.observe_event_projection_effects(event, &local_account_id_hex, &mut summary)?;
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
        // Reconcile transport routes once after the batch drains instead of per
        // membership-changing event. This installs a join's current route and
        // retains any still-live address displaced by a routing rotation.
        let routes_changed = self.refresh_group_routes()?.routing_changed;
        if (routes_dirty || routes_changed)
            && let Err(error) = self.sync_runtime_groups().await
        {
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
        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        // Synthetic source identity: these events have no single inbound
        // transport message (see `drain_pending_session_events`).
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let routes_dirty = self
            .observe_account_device_effects(
                effects,
                &display_names,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
                None,
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

    pub async fn next_event(&mut self) -> Result<SyncSummary, AppError> {
        loop {
            let delivery = self.receive_next_delivery().await?;
            let summary = self.ingest_received_delivery(delivery).await?;
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
    ) -> Result<cgka_traits::TransportDelivery, AppError> {
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;

        loop {
            let delivery = self
                .adapter
                .receive()
                .await?
                .ok_or(AppError::TransportClosed)?;
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &self.seen_events_index) {
                continue;
            }
            if self.seen_events_index.contains(&event_id) {
                continue;
            }
            return Ok(delivery);
        }
    }

    pub(crate) async fn ingest_received_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
    ) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        let event_id = hex::encode(delivery.message.id.as_slice());
        let routes_dirty = self
            .ingest_delivery(delivery, &display_names, &mut summary)
            .await?;
        // Mark the delivery seen only after durable ingest succeeds, matching
        // the catch-up drain below. Marking at receive time would let a failed
        // ingest poison the index, so a reused client would silently skip the
        // redelivered event.
        self.remember_seen_event(event_id);
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
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        self.pending_runtime_group_subscription_refresh |= routes_dirty || refresh.routing_changed;
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
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

    /// Drain the transport for an ordinary floored sync: ingest what is waiting
    /// and return as soon as the relays go quiet.
    async fn sync_sdk_relay(
        &mut self,
        counts: &mut DrainCounts,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let (summary, _) = self
            .drain_sdk_relay(counts, DrainCompletion::Quiescence)
            .await?;
        Ok(summary)
    }

    /// Drain the transport for an epoch-gap backfill: the same ingest, ended by
    /// the relays reporting end-of-stored-events instead of by silence, so a
    /// whole-account history query that is merely slow is not read as one that
    /// had nothing to send.
    async fn backfill_sdk_relay(
        &mut self,
        counts: &mut DrainCounts,
        retry_ordinal: u64,
    ) -> Result<(SyncSummary, DrainVerdict), ClassifiedSyncFailure> {
        let completion = if retry_ordinal >= EPOCH_BACKFILL_EOSE_ATTEMPT_LIMIT {
            DrainCompletion::QuiescenceFallback
        } else {
            DrainCompletion::EndOfStoredEvents(self.epoch_backfill_eose_wait())
        };
        self.drain_sdk_relay(counts, completion).await
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
    /// intent that keeps failing to confirm its replay would spend the drain's
    /// whole silence budget per delivery on the serial account worker, with
    /// user commands queued behind it. Pacing skips those attempts outright
    /// rather than queueing them: the intent is already durable and the next
    /// seam past the cooldown runs it. Caller-directed catch-up is exempt — a
    /// person asking for a repair is not a loop.
    fn epoch_backfill_retry_is_paced(&self, seam: EpochBackfillExecutionSeam) -> bool {
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
    /// Deliberately gate-only. The silence budget is not consulted here: it is
    /// reset by the very delivery being skipped, so an elapsed check would be
    /// dead code, and moving that reset below the skip would turn a liveness
    /// signal into a progress gate — cutting off exactly the stuttering long
    /// replays this recovery exists to complete. A relay that streams non-novel
    /// events forever *and* never reports end-of-stored-events therefore still
    /// holds the drain until its traffic stops or the worker is aborted at
    /// shutdown. That residual is tracked, not solved here.
    async fn backfill_gate_reports_complete(
        &self,
        completion: DrainCompletion,
        polled_at: &mut Instant,
    ) -> bool {
        if !matches!(completion, DrainCompletion::EndOfStoredEvents(_))
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
    ) -> Result<(SyncSummary, DrainVerdict), ClassifiedSyncFailure> {
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
        *counts = DrainCounts::default();
        let mut routes_dirty = false;
        // Silence, not total drain time, is what the backfill's budget bounds:
        // every delivery below resets this, so a long replay that keeps making
        // progress is never cut short.
        let mut silence_started = std::time::Instant::now();
        // Skipped deliveries poll the end-of-stored-events gate, which the
        // receive timeout below cannot reach while a relay delivers faster than
        // `SDK_DRAIN_WAIT`. Held at the same interval as that timeout.
        let mut gate_polled_at = silence_started;

        let verdict = loop {
            let wait = if first_wait {
                SDK_FIRST_SYNC_WAIT
            } else {
                SDK_DRAIN_WAIT
            };
            first_wait = false;
            let delivery = match timeout(wait, self.adapter.receive()).await {
                Ok(Ok(Some(delivery))) => delivery,
                Ok(Ok(None)) => {
                    break match completion {
                        DrainCompletion::Quiescence => DrainVerdict::Complete,
                        DrainCompletion::QuiescenceFallback => DrainVerdict::QuiescenceFallback,
                        DrainCompletion::EndOfStoredEvents(_) => {
                            self.backfill_drain_verdict().await
                        }
                    };
                }
                Ok(Err(error)) => {
                    return Err(self
                        .finish_failed_sync_drain(
                            summary,
                            routes_dirty,
                            *counts,
                            StagedSyncError::new(error.into(), SyncFailureStage::RelayReceive),
                            drain_started,
                            cursor_before_secs,
                        )
                        .await);
                }
                Err(_) => match completion {
                    DrainCompletion::Quiescence => break DrainVerdict::Complete,
                    DrainCompletion::QuiescenceFallback => break DrainVerdict::QuiescenceFallback,
                    DrainCompletion::EndOfStoredEvents(budget) => {
                        let verdict = self.backfill_drain_verdict().await;
                        if verdict == DrainVerdict::Complete || silence_started.elapsed() >= budget
                        {
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
                        summary,
                        routes_dirty,
                        *counts,
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
            let delivery_routes_dirty = match self
                .ingest_delivery(delivery, &display_names, &mut delivery_summary)
                .await
            {
                Ok(routes_dirty) => routes_dirty,
                Err(error) => {
                    return Err(self
                        .finish_failed_sync_drain(
                            summary,
                            routes_dirty,
                            *counts,
                            StagedSyncError::new(error, SyncFailureStage::CgkaIngest),
                            drain_started,
                            cursor_before_secs,
                        )
                        .await);
                }
            };
            self.remember_seen_event(event_id);
            counts.deliveries = counts.deliveries.saturating_add(1);
            summary.merge(delivery_summary);
            routes_dirty |= delivery_routes_dirty;
        };

        if let Err(error) = self
            .checkpoint_sync_prefix(&mut summary, routes_dirty, counts.deliveries)
            .await
        {
            let (stage, cursor_after_secs) =
                self.checkpoint_error_stage_and_cursor(&error, cursor_before_secs);
            let (summary, source) = self.checkpoint_failure_summary(summary, error);
            self.record_sync_drain(
                drain_started.elapsed().as_millis() as u64,
                counts.deliveries,
                counts.skipped,
                cursor_before_secs,
                cursor_after_secs,
            );
            return Err(ClassifiedSyncFailure::at_stage(summary, source, stage));
        }
        self.record_sync_drain(
            drain_started.elapsed().as_millis() as u64,
            counts.deliveries,
            counts.skipped,
            cursor_before_secs,
            self.state.last_transport_timestamp,
        );
        Ok((summary, verdict))
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
            counts.deliveries,
            counts.skipped,
            cursor_before_secs,
            cursor_after_secs,
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
            return Err(SyncCheckpointError::BeforePersistence(error));
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

    async fn ingest_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
    ) -> Result<bool, AppError> {
        let source_message_id_hex = hex::encode(delivery.message.id.as_slice());
        let outer_transport_at = delivery.message.timestamp.0;
        let source_received_at = delivery.received_at.0;
        let group_id_hint = delivery.group_id_hint.clone();
        let effects = self.runtime.ingest_delivery(delivery).await?;
        let publish_error = fail_if_publish_failed(&effects.effects).err();
        self.remember_buffered_convergence_outcome(&effects.outcome);
        self.remember_pending_convergence_groups(&effects.effects);
        self.observe_recovery_evidence(&effects.effects);
        self.remember_transport_cursor(outer_transport_at);
        self.detect_epoch_stall(group_id_hint, &source_message_id_hex, &effects.outcome);
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
            .filter(|event_id| !self.pending_application_event_acks.contains(event_id))
            .collect::<Vec<_>>();
        let routes_dirty = match self
            .observe_account_device_effects(
                &effects.effects,
                display_names,
                summary,
                &source_message_id_hex,
                source_received_at,
                Some(outer_transport_at),
            )
            .await
        {
            Ok(routes_dirty) => routes_dirty,
            Err(error) => {
                for event_id in new_application_event_ack_candidates {
                    self.pending_application_event_acks.remove(&event_id);
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
        Ok(routes_dirty)
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
        let decision = match outcome {
            IngestOutcome::TransportDeferred { .. } => self.epoch_stall.observe_undecryptable(
                group_id.clone(),
                message_id_hex.to_owned(),
                record.epoch,
            ),
            IngestOutcome::ResourceRefused { .. } => self
                .epoch_stall
                .observe_resource_refusal(group_id.clone(), record.epoch),
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
        );
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
    ) {
        if decision.arms_backfill() {
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
            // Record the arm decision before the replay side effect runs (the
            // worker seam calls run_pending_epoch_backfill after this returns).
            // Best-effort, fire-and-forget: recording can never block or fail
            // the backfill.
            if record_arm {
                self.record_epoch_stall_backfill_armed(group_id, stalled_epoch, trigger, &context);
            }
        }
        if let BackfillDecision::ArmAndEscalate { arms } = decision {
            // The replay is armed above regardless: escalating reports that
            // replay alone is not repairing this group, it does not replace the
            // attempt (see EPOCH_STALL_ESCALATION_ARM_THRESHOLD for why
            // reporting is all this decision does).
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "apply_backfill_decision",
                arms,
                arm_threshold = self.epoch_stall.escalation_arm_threshold(),
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
        self.pending_epoch_backfill.is_some() || !self.queued_epoch_backfills.is_empty()
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
    ) {
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
            succeeded,
        );
    }

    fn local_epoch_for_group(&self, group_id: &cgka_traits::GroupId) -> Option<u64> {
        self.runtime
            .group_record(group_id)
            .ok()
            .map(|record| record.epoch.0)
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
    ) -> Option<EpochBackfillExecution> {
        let mut pending = self.take_next_pending_epoch_backfill()?;
        let retry_ordinal = u64::from(pending.execution_attempts);
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
            return None;
        }
        pending.last_deferred_audit = None;
        pending.execution_attempts = pending.execution_attempts.saturating_add(1);
        self.record_epoch_stall_backfill_started(seam, retry_ordinal, &context);
        Some(EpochBackfillExecution {
            pending,
            epochs_before,
            retry_ordinal,
            started: Instant::now(),
        })
    }

    fn finish_epoch_backfill_execution(
        &mut self,
        execution: EpochBackfillExecution,
        activation_outcome: EpochBackfillActivationOutcome,
        error_kind: Option<String>,
        completion_kind: Option<EpochBackfillCompletionKind>,
        counts: DrainCounts,
        succeeded: bool,
    ) {
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
                counts,
                succeeded,
            },
        );
        if succeeded {
            self.epoch_stall.mark_replayed();
        } else {
            self.requeue_failed_epoch_backfill_intent(execution.pending);
        }
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
        let Some(execution) = self.begin_epoch_backfill_execution(seam) else {
            return Ok(EpochBackfillRunOutcome::Deferred);
        };

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
                        false,
                    );
                    return Err(err);
                }
                self.warm_encrypted_media_epoch_secrets("post_subscription_sync");
                self.record_subscription_rebuild(None).await;
                let mut counts = DrainCounts::default();
                let retry_ordinal = execution.retry_ordinal;
                let (mut summary, verdict) =
                    match self.backfill_sdk_relay(&mut counts, retry_ordinal).await {
                        Ok(drained) => drained,
                        Err(err) => {
                            let terminal_error = err.source.privacy_safe_kind().to_string();
                            self.finish_epoch_backfill_execution(
                                execution,
                                EpochBackfillActivationOutcome::Succeeded,
                                Some(terminal_error),
                                None,
                                counts,
                                false,
                            );
                            self.pending_failed_sync_summary.merge(err.partial_summary);
                            return Err(err.source);
                        }
                    };
                let drained = match self.drain_pending_session_events().await {
                    Ok(drained) => drained,
                    Err(err) => {
                        let terminal_error = err.privacy_safe_kind().to_string();
                        self.finish_epoch_backfill_execution(
                            execution,
                            EpochBackfillActivationOutcome::Succeeded,
                            Some(terminal_error),
                            None,
                            counts,
                            false,
                        );
                        return Err(err);
                    }
                };
                summary.merge(drained);
                // Activation itself succeeded either way; what the verdict
                // decides is whether the replay it opened actually served this
                // account's stored history. An unconfirmed drain must not
                // disarm the detector, so it is recorded as a failed attempt
                // and its intent stays queued for the next seam.
                let error_kind = verdict.error_kind();
                self.finish_epoch_backfill_execution(
                    execution,
                    EpochBackfillActivationOutcome::Succeeded,
                    error_kind.map(str::to_owned),
                    verdict.completion_kind(),
                    counts,
                    error_kind.is_none(),
                );
                if let Some(error_kind) = error_kind {
                    tracing::warn!(
                        target: "marmot_app::epoch_stall",
                        method = "run_pending_epoch_backfill",
                        error_kind,
                        retry_ordinal,
                        deliveries = counts.deliveries,
                        skipped = counts.skipped,
                        eose_attempt_limit = EPOCH_BACKFILL_EOSE_ATTEMPT_LIMIT,
                        "epoch-gap backfill drain ended without the relays confirming stored history; retrying later"
                    );
                    self.epoch_backfill_retry_not_before =
                        Some(Instant::now() + self.epoch_backfill_retry_backoff(retry_ordinal));
                    return Ok(EpochBackfillRunOutcome::Incomplete(summary));
                }
                self.epoch_backfill_retry_not_before = None;
                Ok(EpochBackfillRunOutcome::Completed(summary))
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
                    false,
                );
                Err(app_err)
            }
        }
    }

    /// Explicit account-wide repair for a host that has independent evidence
    /// its incremental cursor may be incomplete (for example, a long-offline
    /// participant that has no new traffic capable of arming epoch-stall
    /// detection). Unlike the automatic detector path, this is a caller-owned
    /// operation and therefore does not mutate the detector's debounce state.
    pub(crate) async fn repair_full_history(
        &mut self,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
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
                    EpochBackfillRunOutcome::Completed(summary) => return Ok(summary),
                    // The intent's own replay could not confirm it served this
                    // account's history. Retain what it did ingest and fall
                    // through to the caller-directed unfloored repair below
                    // rather than re-running the same intent in a tight loop.
                    EpochBackfillRunOutcome::Incomplete(summary) => {
                        self.pending_failed_sync_summary.merge(summary);
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
        self.record_subscription_rebuild(None).await;
        let mut counts = DrainCounts::default();
        let mut summary = self.sync_sdk_relay(&mut counts).await?;
        let drained = match self.drain_pending_session_events().await {
            Ok(drained) => drained,
            Err(error) => {
                // As above, this composite drain has lost its inner boundary.
                return Err(ClassifiedSyncFailure::at_stage(
                    summary,
                    error,
                    SyncFailureStage::Unknown,
                ));
            }
        };
        summary.merge(drained);
        Ok(summary)
    }

    pub(crate) async fn advance_convergence_after_runtime_sync(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<SyncSummary, AppError> {
        // The account worker refreshes transport groups once for the scheduled
        // convergence batch before calling this per-group path.
        let effects = self.runtime.advance_convergence(group_id).await?;
        self.observe_scheduled_convergence_effects(group_id, &effects)
            .await
    }

    /// Project one scheduled convergence batch's effects, split from the
    /// advance itself so the projection is exercisable against a given batch of
    /// effects.
    pub(crate) async fn observe_scheduled_convergence_effects(
        &mut self,
        group_id: &cgka_traits::GroupId,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
        self.remember_pending_convergence_groups(effects);
        // Observe before the publish gate, for the reason spelled out in
        // `observe_drained_session_events`.
        self.observe_recovery_evidence(effects);
        fail_if_publish_failed(effects)?;
        self.remember_published_reports(effects);
        let finalize_updates = self.finalize_published_app_message_source_retention(effects)?;
        let publish_new_message_notification =
            effects.published_app_messages.iter().any(|published| {
                let group_id_hex = hex::encode(published.group_id.as_slice());
                self.app
                    .reaction_target(&self.state.label, &group_id_hex, &published.app_event_id)
                    .ok()
                    .flatten()
                    .is_some_and(|message| {
                        message.kind == MARMOT_APP_EVENT_KIND_CHAT
                            && !message.deleted
                            && !message.invalidated
                    })
            });
        self.refresh_group(group_id);

        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        summary.projection_updates.extend(finalize_updates);
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let routes_dirty = self
            .observe_account_device_effects(
                effects,
                &display_names,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
                None,
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
        let seen_start = self
            .state
            .seen_events
            .len()
            .saturating_sub(self.pending_seen_event_count);
        let delta = AccountState {
            label: self.state.label.clone(),
            seen_events: self.state.seen_events[seen_start..].to_vec(),
            last_transport_timestamp: self.state.last_transport_timestamp,
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
        // #760: collect push-gossip ids and strip them from `summary.messages` in
        // ONE pass after the loop. The previous per-message `retain` was O(n) per
        // gossip event → O(n²) over a batch a relay could flood with kind-448s.
        let mut gossip_message_ids: HashSet<String> = HashSet::new();
        let local_group_deletion_frontiers =
            self.local_group_deletion_frontiers_at_batch_start(effects)?;
        for event in &effects.events {
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
                summary,
                event,
                group_projection.as_ref(),
                source_message_id_hex,
                source_received_at,
                outer_transport_at,
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
                source_message_id_hex,
            );
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

    /// Advance the persisted transport cursor from an inbound message —
    /// unless this runtime was constructed with
    /// [`CursorPersistence::Frozen`](crate::CursorPersistence), in which case
    /// this is a no-op and the cursor stays at the value loaded from the store.
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

#[cfg(test)]
mod tests {
    use super::{DrainVerdict, backfill_drain_verdict, retry_backoff_for_ordinal};
    use crate::{EPOCH_BACKFILL_RETRY_BACKOFF, EPOCH_BACKFILL_RETRY_BACKOFF_CAP};
    use std::time::Duration;
    use transport_nostr_adapter::AccountSubscriptionEose;

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
    fn drain_verdict_reads_end_of_stored_events_progress() {
        let progress = |subscriptions, with_eose| AccountSubscriptionEose {
            subscriptions,
            with_eose,
        };
        assert_eq!(
            backfill_drain_verdict(progress(2, 2)),
            DrainVerdict::Complete
        );
        assert_eq!(
            backfill_drain_verdict(progress(2, 1)),
            DrainVerdict::EoseTimeout
        );
        assert_eq!(
            backfill_drain_verdict(progress(2, 0)),
            DrainVerdict::NoRelayEose
        );
        assert_eq!(
            backfill_drain_verdict(progress(0, 0)),
            DrainVerdict::NoRelayEose,
            "an account with nothing subscribed cannot have been served"
        );
    }
}
