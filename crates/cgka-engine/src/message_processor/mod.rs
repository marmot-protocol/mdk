//! Inbound ingest and outbound send routing for [`Engine`].
//!
//! Inbound messages are peeled, classified, stored, and either applied or
//! buffered for convergence. Outbound intents are checked against local epoch
//! state and unresolved convergence inputs before any OpenMLS mutation.
//!
//! Classifiable ingest exclusions and local-state blocks return typed ordinary
//! outcomes. `Err` is reserved for storage, peeler, serialization, and
//! OpenMLS failures.

mod ingest;
mod send;
mod store;

pub(crate) use ingest::avatar_component_snapshot;
pub(crate) use send::merge_capabilities;
#[cfg(feature = "test-conformance-snapshot")]
pub(crate) use store::normalized_deferred_peel_lifecycle;

use crate::convergence_input::{ClassifiedConvergenceInput, ConvergenceInputContext};
use crate::engine::{Engine, ScheduledSelfRemoveAutoCommit};
use crate::openmls_projection::decode_openmls_wire_projection;
use cgka_traits::engine::{GroupEvent, GroupStateChange, SendIntent, SendResult};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::{
    InboundResourceLimit, IngestOutcome, InputRejectionCategory, LocalIngestState,
};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{QueuedOutboundIntent, StorageError, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const MAX_CONVERGENCE_REPROCESSING_PASSES: usize = 16;
pub(crate) const SELF_REMOVE_AUTO_COMMIT_JITTER_MIN_MS: u64 = 10;
pub(crate) const SELF_REMOVE_AUTO_COMMIT_JITTER_SPAN_MS: u64 = 40;

/// Retry budget for a `PeelDeferred` row (mdk#339). Each unit is one
/// actual re-peel attempt under a *changed* peel context (the fingerprint
/// gate skips unchanged contexts entirely), so a legitimate future-epoch
/// message would need to trail the group by this many context changes before
/// its retained row is resource-refused and released. The same transport id
/// remains eligible if the transport delivers it again afterwards.
///
/// The fingerprint now also moves on every newly stored commit, so a busy group
/// spends this budget faster than one whose live epoch alone advances. It stays
/// comfortable: a row would have to sit unreadable across 32 distinct commit
/// contexts, and long before that it has fallen outside `max_rewind_commits`
/// (pinned at 5 in v1), where it is terminal on horizon grounds regardless.
/// Spending an attempt per commit is also the intended behavior, not a cost —
/// each new commit is a genuinely new chance for the row to become readable.
pub const MAX_DEFERRED_PEEL_ATTEMPTS: u32 = 32;

/// Maximum local residence for an opaque transport object. This is deliberately
/// conservative: it bounds storage across stable contexts and restarts without
/// turning elapsed time into a protocol-validity claim.
pub const MAX_DEFERRED_PEEL_RESIDENCE_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// Per-group cap on retained `PeelDeferred` rows (mdk#339). Raw
/// transport ids are attacker-controllable (a fresh wrap yields a fresh id),
/// so without a cap a peer flooding undecryptable group-routed events grows
/// the durable store without bound. At the cap, new undecryptable input is
/// dropped unpersisted (transport redelivery is the recovery path once the
/// backlog drains).
pub const MAX_PEEL_DEFERRED_ROWS_PER_GROUP: usize = 256;

/// Per-group cap on retained outbound intents (mdk#1246). Unlike the
/// deferred-peel cap above, these rows are not peer-mintable — every one
/// originates from a local `send` — so this bounds a runaway local sender
/// rather than a flood. It is enforced in `queue_outbound_intent`, the sole
/// insertion point for the queue, so it covers every path that retains: a group
/// resolving a locally staged publication, a `Stable` group whose convergence
/// inputs have not settled, and the offline outbox — `queue_app_message`, which
/// the app calls when the account is not active (mdk#1158). The last is the one
/// a user drives directly: 256 sends into one group across a single offline
/// stretch, and the 257th is refused rather than queued.
///
/// The first of those can hold indefinitely — a publication whose exposure is
/// ambiguous is never rolled back, and the transport fanout row that would
/// retry it is retired at `TRANSPORT_FANOUT_RETENTION_SECS` — so without a cap
/// a programmatic sender grows the durable store without bound while every
/// call still reports `SendResult::Queued`.
///
/// Too low refuses a legitimate burst against a group that would have
/// recovered in seconds; too high lets the queue's marginal durable footprint
/// (each row duplicates an app-projection row the app wrote before the engine
/// was called) grow past what a mobile device can absorb. 256 matches
/// `MAX_PEEL_DEFERRED_ROWS_PER_GROUP` and the other per-scope retention caps in
/// the workspace, and sits far above any plausible human burst across a stall.
///
/// At the cap the send is refused with
/// [`EngineError::QueuedOutboundAtCapacity`](cgka_traits::error::EngineError::QueuedOutboundAtCapacity)
/// so the caller learns its message was not accepted. Retention never silently
/// drops work it already accepted — that is the difference from the
/// deferred-peel cap, which may drop because transport redelivery is its
/// recovery path.
///
/// Capacity is reclaimed on confirmation, not on drain. A drained row is
/// deleted only by `confirm_queued_outbound_intent` — or, for a group-state
/// intent, inside `confirm_published` — so a payload that was prepared and
/// published but never acknowledged still holds its slot and is re-prepared on
/// the next drain. A group whose transport keeps failing therefore sits at the
/// cap: its rows keep being re-attempted, but nothing frees a slot until a
/// publish is accepted by at least one endpoint.
pub const MAX_QUEUED_OUTBOUND_INTENTS_PER_GROUP: usize = 256;

/// Upper bound on `PeelDeferred` rows re-attempted per retry sweep
/// (mdk#339): a large historical backlog is worked through in slices
/// across passes instead of holding a convergence drain hostage, so current
/// events are never blocked behind irrelevant history.
pub(crate) const MAX_DEFERRED_ROWS_PER_SWEEP: usize = 64;

/// Upper bound on candidate branch states materialized as peel contexts in one
/// deferred-peel sweep (`Engine::candidate_branch_peel`).
///
/// A bound is required because nothing else caps the branch COUNT: one extra
/// message posts one extra branch, `max_rewind_commits` bounds a path's LENGTH,
/// and the pass's own `ReplayBudget` grows with the commit count
/// (`commits × (max_rewind + 1) × 4 + 32`), so width alone never exhausts it.
///
/// Each context costs one bounded replay of its branch, and each is then
/// offered to at most [`MAX_DEFERRED_ROWS_PER_SWEEP`] retained rows, so one
/// sweep's worst case is `8 × 64` symmetric AEAD attempts on top of 8 replays —
/// negligible next to the convergence pass itself, and reached only when a
/// contested graph and a deferred backlog coincide.
///
/// Capping is safe because the kept subset is content-derived: candidates are
/// ranked by tip epoch, then by path-digest branch id, so every peer holding
/// the same evidence keeps the same branches. Branch *selection* is not capped
/// — a branch past this prefix can still win a pass, and peels natively once
/// adopted.
pub(crate) const MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS: usize = 8;

/// Per-group deferred-peel retry lifecycle state (mdk#339). Held on the
/// engine in `Engine::deferred_peel`; in-memory by design (see the field doc).
#[derive(Default)]
pub(crate) struct DeferredPeelGroupState {
    /// Peel-context fingerprint recorded after a full zero-progress cycle
    /// over the backlog. While the live context matches, whole sweeps are
    /// skipped — a deferred row can only become peelable when the group
    /// epoch advances or the retained-snapshot set changes.
    gate: Option<[u8; 32]>,
    /// Monotonic sweep counter used to report aggregate sweep progress.
    sweep_count: u64,
    /// Resume offset into the (stable-ordered) deferred-row list for the
    /// bounded sweep.
    cursor: usize,
    /// Whether any row progressed since the cursor last wrapped to 0. The
    /// gate is armed only after a full unproductive cycle, so a bounded
    /// sweep never permanently skips rows it has not attempted.
    cycle_progressed: bool,
    /// Cached count of retained `PeelDeferred` rows backing the flood cap.
    /// Refreshed from storage on every sweep; adjusted at the deferral /
    /// terminal transition sites in between.
    deferred_rows: usize,
    /// Whether `deferred_rows` has been initialized from storage this
    /// session.
    counted: bool,
    /// Whether a cap-exceeded `Rejection` has already been audited for the
    /// current cap-full episode. Raw transport ids are attacker-controlled,
    /// so a sustained flood past the cap would otherwise emit one audit write
    /// per rejected message; this suppresses the repeats until the backlog
    /// drops back below the cap and re-arms.
    cap_rejection_audited: bool,
}

impl DeferredPeelGroupState {
    fn has_capacity(&self) -> bool {
        self.deferred_rows < MAX_PEEL_DEFERRED_ROWS_PER_GROUP
    }

    fn note_row_persisted(&mut self) {
        self.deferred_rows += 1;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaintenanceGate {
    Clear,
    StagedCommit,
    LeaveGated,
}

#[derive(Clone, Copy)]
enum LeaveGateCheck {
    Required,
    DrainComplete,
}

struct AdminReservation {
    available: bool,
}

impl AdminReservation {
    fn load<S: StorageProvider>(
        engine: &Engine<S>,
        group_id: &GroupId,
    ) -> Result<Self, EngineError> {
        let available = engine
            .storage
            .convergence_pass(group_id)?
            .is_some_and(|pass| {
                pass.phase == cgka_traits::ConvergencePassPhase::Completed
                    && pass.fairness_slot_available
            });
        Ok(Self { available })
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn permits(&self, intent: &SendIntent) -> bool {
        !self.available || is_admin_group_state_intent(intent)
    }

    fn consume_if_dormant<S: StorageProvider>(
        &mut self,
        engine: &mut Engine<S>,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        if self.available && !engine.has_unresolved_convergence_inputs(group_id)? {
            // The slot orders local group-state work before an inbound-only
            // follow-up pass. With no such inbound work, normal queue draining
            // proceeds and the dormant slot must not leak into a later pass.
            self.consume(engine, group_id)?;
        }
        Ok(())
    }

    fn observe_hold<S: StorageProvider>(
        &self,
        engine: &mut Engine<S>,
        queued: &[QueuedOutboundIntent],
    ) {
        if self.available
            && queued
                .iter()
                .any(|record| is_admin_group_state_intent(&record.intent))
        {
            // Diagnostic only: the completed-pass boundary is being held for a
            // queued admin group-state intent while retained inbound waits.
            engine.engine_metrics.note_admin_reservation_hold();
        }
    }

    fn consume_attempt<S: StorageProvider>(
        &mut self,
        engine: &mut Engine<S>,
        group_id: &GroupId,
        prepared: bool,
    ) -> Result<(), EngineError> {
        engine
            .engine_metrics
            .note_admin_reservation_attempt(prepared);
        self.consume(engine, group_id)
    }

    fn consume_ungranted<S: StorageProvider>(
        &mut self,
        engine: &mut Engine<S>,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if !self.available {
            return Ok(false);
        }
        self.consume(engine, group_id)?;
        Ok(true)
    }

    fn consume<S: StorageProvider>(
        &mut self,
        engine: &mut Engine<S>,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        engine.consume_convergence_fairness_slot(group_id)?;
        self.available = false;
        Ok(())
    }
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn strict_cutover_rejects_legacy_group_addition(
        &self,
        group_id: &GroupId,
        has_addition: bool,
    ) -> Result<(), EngineError> {
        if has_addition
            && self.new_protocol_profile == cgka_traits::group::ProtocolProfile::Current
            && self.storage.get_group(group_id)?.protocol_profile
                == cgka_traits::group::ProtocolProfile::Legacy
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "LegacyProfile",
                    to: "AddMember",
                    reason: "strict cutover forbids adding members to legacy groups",
                },
            ));
        }
        Ok(())
    }

    /// Inbound pipeline. Never panics; every classifiable stale case returns
    /// a typed `StaleReason` inside `Ok(IngestOutcome::Stale { .. })`.
    pub(crate) async fn do_ingest(
        &mut self,
        msg: TransportMessage,
    ) -> Result<IngestOutcome, EngineError> {
        // Clear a marker left by cancellation/panic in an earlier ingest; only
        // the current call may suppress its own seen-cache insertion.
        self.retryable_unpersisted_ingest_id = None;
        // Durable dedup / own-echo check. Storage is authoritative so a
        // restarted engine can classify replayed transport messages the same
        // way as a hot process.
        if let Some(outcome) = self.recorded_message_outcome(&msg.id)? {
            return Ok(outcome);
        }

        // In-memory fallback for messages produced before the durable record
        // is visible to this path.
        if self.seen_message_ids.contains(&msg.id) {
            return Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate,
            });
        }
        if self.sent_message_ids.contains(&msg.id) {
            let group_id = record_group_id(&msg);
            self.persist_transport_message_for_existing_group(
                &msg,
                &group_id,
                EpochId(0),
                MessageState::Sent,
            )?;
            return Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::OwnEcho,
            });
        }

        let outcome = match &msg.envelope {
            TransportEnvelope::Welcome { recipient } => {
                self.ingest_welcome(&msg, recipient.clone()).await?
            }
            TransportEnvelope::GroupMessage { transport_group_id } => {
                self.ingest_group_message(&msg, transport_group_id.clone())
                    .await?
            }
        };

        let retryable_unpersisted = self
            .retryable_unpersisted_ingest_id
            .take()
            .is_some_and(|id| id == msg.id);
        if !retryable_unpersisted
            && !matches!(outcome, IngestOutcome::Buffered { .. })
            && self.should_remember_ingested_message(&msg.id)?
        {
            self.seen_message_ids.insert(msg.id.clone());
        }
        Ok(outcome)
    }

    pub(crate) async fn do_send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        let group_id = self.validate_send_acceptance(&intent)?;
        // Disband is an intent-persistence operation, not a Commit-preparation
        // operation. It remains acceptable while another staged Commit owns
        // the group and while Unrecoverable is paused.
        if matches!(&intent, SendIntent::Disband { .. }) {
            return self.do_request_disband(group_id);
        }
        if self
            .should_queue_outbound_intent(&group_id, &intent)
            .await?
        {
            return self.queue_outbound_intent(group_id, intent);
        }

        self.do_send_ready(intent).await
    }

    pub(crate) fn do_queue_app_message(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        let intent = SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        };
        self.validate_send_acceptance(&intent)?;
        // Same retention boundary as `send`: a publication this client staged
        // holds the payload, every other non-`Stable` state refuses it.
        //
        // For the two terminal states this is defense in depth —
        // `validate_send_acceptance` above already refused them, `Unrecoverable`
        // through the durable halt sync (which consults the in-memory map first)
        // and `Disbanded` through the write-once tombstone written in the same
        // transaction that purges the queue. Re-checking the epoch state catches
        // a divergence between it and those durable markers rather than trusting
        // one of the two.
        if let Some(state) = self.epoch_manager.state(&group_id)
            && !state.is_stable()
            && !state.is_resolving_local_publish()
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "queue_app_message",
                    reason: "queue_app_message requires Stable or an unresolved local publish",
                },
            ));
        }
        self.queue_outbound_intent(group_id, intent)
    }

    fn validate_send_acceptance(&mut self, intent: &SendIntent) -> Result<GroupId, EngineError> {
        let group_id = send_intent_group_id(intent).clone();
        // A send targeting a seeded-but-unhydrated group promotes it first
        // (mdk#1161); a hydration failure quarantines it and falls through to
        // the gate below as UnknownGroup.
        let _ = self.ensure_hydrated(&group_id);
        // Quarantine gate: a group frozen by hydration quarantine must not
        // stage, queue, or publish anything — a confirm would set_stable and
        // silently un-quarantine it out of band (mdk#364).
        self.ensure_group_live(&group_id)?;
        if self.storage.disband_tombstone(&group_id)?.is_some() {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Disbanded",
                    to: crate::audit_helpers::send_intent_kind_str(intent),
                    reason: "Disbanded is terminal",
                },
            ));
        }
        // Disband has its own durable acceptance gates and intentionally
        // remains available while the ordinary send lifecycle is paused.
        if matches!(intent, SendIntent::Disband { .. }) {
            return Ok(group_id);
        }
        // Strict cutover freezes membership growth in legacy groups. Existing
        // members may continue messaging and applying other group changes, but
        // no add (including a re-add) may be staged or queued.
        if self.new_protocol_profile == cgka_traits::group::ProtocolProfile::Current
            && matches!(intent, SendIntent::Invite { .. })
            && self.storage.get_group(&group_id)?.protocol_profile
                == cgka_traits::group::ProtocolProfile::Legacy
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "LegacyProfile",
                    to: "Invite",
                    reason: "strict cutover forbids adding members to legacy groups",
                },
            ));
        }
        // Terminal gate before queueing: a local copy marked removed (realized
        // self-eviction) must never accept or queue outbound work. Checked
        // again in `do_send_ready` so queued-intent drains for a copy removed
        // after queueing hit the same deterministic error.
        if self.group_record_is_removed(&group_id)? {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Removed",
                    to: crate::audit_helpers::send_intent_kind_str(intent),
                    reason: "local group copy is marked removed (self-evicted)",
                },
            ));
        }
        // mdk#971: durable Unrecoverable halt — sync into memory and refuse
        // outbound work until a verified repair path clears the marker.
        if self.sync_unrecoverable_halt_from_storage(&group_id)? {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Unrecoverable",
                    to: crate::audit_helpers::send_intent_kind_str(intent),
                    reason: "group is Unrecoverable pending verified repair",
                },
            ));
        }
        if self.disbanding_in_progress(&group_id)? {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Disbanding",
                    to: crate::audit_helpers::send_intent_kind_str(intent),
                    reason: "disband requested or awaiting convergence",
                },
            ));
        }
        if !matches!(intent, SendIntent::Leave { .. }) && self.has_leave_send_gate(&group_id)? {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Leaving",
                    to: crate::audit_helpers::send_intent_kind_str(intent),
                    reason: "leave requested",
                },
            ));
        }
        Ok(group_id)
    }

    pub async fn converge_and_drain_queued_outbound_intents(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<Vec<SendResult>, EngineError> {
        // Draining a seeded-but-unhydrated group promotes it first
        // (mdk#1161); a hydration failure quarantines it and the gate below
        // reports UnknownGroup.
        let _ = self.ensure_hydrated(group_id);
        // Quarantined groups vanish from every live surface; convergence and
        // queued-intent drains must not touch their state (mdk#364).
        self.ensure_group_live(group_id)?;
        // A drain can be invoked directly without session-open hydration.
        // Synchronize the durable halt before convergence or queued work can
        // run so restart never bypasses `Unrecoverable`.
        if self.sync_unrecoverable_halt_from_storage(group_id)? {
            return Ok(Vec::new());
        }
        // Terminal: a removed copy must never publish, and the removed-copy
        // gate in `do_send_ready` would turn every queued record into a
        // permanent drain error that the app retries forever. Discard the
        // queue and report nothing to drain. This is the defense-in-depth
        // side; the marker sites (realization, commit-apply seam, convergence
        // reorg) also purge at the moment the copy becomes removed.
        if self.group_record_is_removed(group_id)? {
            self.discard_queued_outbound_intents_for_removed_group(group_id)?;
            return Ok(Vec::new());
        }
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(Vec::new());
        }

        if !self
            .advance_convergence_inputs_until_settled(group_id, now_ms)
            .await?
        {
            return Ok(Vec::new());
        }
        if let Some(result) = self.prepare_pending_disband(group_id).await? {
            return Ok(vec![result]);
        }

        let queued = self.storage.list_queued_outbound_intents(group_id)?;
        let mut drained = Vec::new();
        let mut reservation = AdminReservation::load(self, group_id)?;
        reservation.consume_if_dormant(self, group_id)?;
        reservation.observe_hold(self, &queued);
        // A persisted fairness slot orders one already-queued administrative
        // evolution before automatic SelfRemove or leave-maintenance mutation.
        if !reservation.is_available()
            && self
                .run_drain_maintenance(group_id, now_ms, LeaveGateCheck::Required)
                .await?
                != MaintenanceGate::Clear
        {
            return Ok(Vec::new());
        }
        for record in queued {
            if !reservation.permits(&record.intent) {
                continue;
            }
            if !reservation.is_available()
                && !self
                    .advance_convergence_inputs_until_settled(group_id, now_ms)
                    .await?
            {
                break;
            }
            if !reservation.is_available()
                && self
                    .run_drain_maintenance(group_id, now_ms, LeaveGateCheck::Required)
                    .await?
                    != MaintenanceGate::Clear
            {
                break;
            }
            let result = match self.do_send_ready(record.intent.clone()).await {
                Ok(result) => result,
                Err(_) if reservation.is_available() => {
                    // The protocol grants one preparation attempt, not an
                    // indefinite reservation. Keep the durable intent queued,
                    // consume the slot, and let retained inbound work proceed.
                    reservation.consume_attempt(self, group_id, false)?;
                    break;
                }
                Err(error) => return Err(error),
            };
            let pauses_for_pending_publish = matches!(result, SendResult::GroupEvolution { .. });
            match &result {
                SendResult::ApplicationMessage { msg, .. } | SendResult::Proposal { msg } => {
                    self.queued_intent_by_message
                        .insert(msg.id.clone(), (record.group_id.clone(), record.id.clone()));
                }
                SendResult::GroupEvolution { pending, .. } => {
                    self.queued_intent_by_pending
                        .insert(*pending, (record.group_id.clone(), record.id.clone()));
                }
                SendResult::GroupCreated { .. }
                | SendResult::FoundingGroupCreated { .. }
                | SendResult::NoChange { .. }
                | SendResult::DisbandRequested { .. }
                | SendResult::Queued { .. } => {}
            }
            drained.push(result);
            if reservation.is_available() {
                reservation.consume_attempt(self, group_id, true)?;
                if self.has_unresolved_convergence_inputs(group_id)? {
                    break;
                }
            }
            if pauses_for_pending_publish {
                break;
            }
        }
        if reservation.consume_ungranted(self, group_id)? {
            // No already-queued admin group-state intent was eligible for the
            // fairness attempt. Do not let unrelated app/leave/maintenance
            // work hold the next inbound generation indefinitely.
            if self
                .run_drain_maintenance(group_id, now_ms, LeaveGateCheck::DrainComplete)
                .await?
                == MaintenanceGate::StagedCommit
            {
                return Ok(drained);
            }
        }
        Ok(drained)
    }

    async fn run_drain_maintenance(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
        leave_gate_check: LeaveGateCheck,
    ) -> Result<MaintenanceGate, EngineError> {
        if self
            .stage_due_self_remove_auto_commit(group_id, now_ms)
            .await?
        {
            return Ok(MaintenanceGate::StagedCommit);
        }
        self.try_auto_repropose_leave_request(group_id).await;
        if matches!(leave_gate_check, LeaveGateCheck::Required)
            && self.load_leave_request_state(group_id)?.is_some()
        {
            return Ok(MaintenanceGate::LeaveGated);
        }
        Ok(MaintenanceGate::Clear)
    }

    fn consume_convergence_fairness_slot(&mut self, group_id: &GroupId) -> Result<(), EngineError> {
        if let Some(mut pass) = self.storage.convergence_pass(group_id)? {
            pass.fairness_slot_available = false;
            self.storage.put_convergence_pass(&pass)?;
        }
        // The reservation attempt is over (spec: "the scheduler proceeds").
        // Schedule the group so the next retained inbound generation opens on
        // the next runtime drain instead of one full scheduler cycle later.
        self.schedule_pending_convergence_group(group_id);
        Ok(())
    }

    async fn should_queue_outbound_intent(
        &mut self,
        group_id: &GroupId,
        intent: &SendIntent,
    ) -> Result<bool, EngineError> {
        if let Some(state) = self.epoch_manager.state(group_id)
            && !state.is_stable()
        {
            // A publication this client staged owes its exit to a transport
            // outcome and then a local merge, both of which can take minutes
            // when relays misbehave. Retain application payloads across that
            // window so a stalled group operation cannot make a user's message
            // vanish; the drain re-prepares them from whatever canonical state
            // the group lands on.
            //
            // Group-state intents keep the strict `Stable` requirement: a
            // second staged evolution has no epoch to apply to, and the
            // per-intent guards in `do_send_ready` report that as the illegal
            // transition it is. `Recovering` and the terminal states retain
            // nothing — see `EpochState::is_resolving_local_publish`.
            //
            // The terminal states never reach this branch: `do_send` runs
            // `validate_send_acceptance` first, and its durable halt and
            // tombstone gates already refused them. They are excluded here too
            // because `is_resolving_local_publish` does not match them — the
            // same shape as the `Stable`-only re-check in
            // `converge_and_drain_queued_outbound_intents`.
            return Ok(matches!(intent, SendIntent::AppMessage { .. })
                && state.is_resolving_local_publish());
        }

        let now_ms = self.convergence_now_ms();
        if !self
            .advance_convergence_inputs_until_settled(group_id, now_ms)
            .await?
        {
            return Ok(true);
        }
        self.stage_due_self_remove_auto_commit(group_id, now_ms)
            .await
    }

    pub(crate) fn schedule_pending_convergence_group(&mut self, group_id: &GroupId) {
        self.pending_convergence_groups.insert(group_id.clone());
    }

    pub fn take_regenerated_queued_intent_for_message(
        &mut self,
        message_id: &MessageId,
    ) -> Option<(GroupId, MessageId)> {
        self.queued_intent_by_message.remove(message_id)
    }

    pub fn confirm_regenerated_queued_intent(
        &mut self,
        intent_id: &MessageId,
    ) -> Result<(), EngineError> {
        self.storage.delete_queued_outbound_intent(intent_id)?;
        Ok(())
    }

    pub fn retry_regenerated_queued_intent(&mut self, group_id: &GroupId) {
        self.schedule_pending_convergence_group(group_id);
    }

    pub(crate) fn schedule_self_remove_auto_commit(
        &mut self,
        group_id: &GroupId,
        proposal_id: &MessageId,
        source_epoch: EpochId,
        now_ms: u64,
    ) -> Result<(), EngineError> {
        if self.load_leave_request_state(group_id)?.is_some() {
            return Ok(());
        }
        let due_at_ms =
            now_ms.saturating_add(self.self_remove_auto_commit_jitter_ms(group_id, proposal_id));
        let scheduled = ScheduledSelfRemoveAutoCommit {
            group_id: group_id.clone(),
            proposal_id: proposal_id.clone(),
            source_epoch,
            due_at_ms,
        };
        match self.scheduled_self_remove_auto_commits.get(proposal_id) {
            Some(existing) if existing.due_at_ms <= due_at_ms => {}
            _ => {
                self.scheduled_self_remove_auto_commits
                    .insert(proposal_id.clone(), scheduled);
            }
        }
        self.schedule_pending_convergence_group(group_id);
        Ok(())
    }

    pub(crate) fn drop_self_remove_auto_commit_schedules_for_group(&mut self, group_id: &GroupId) {
        self.scheduled_self_remove_auto_commits
            .retain(|_, scheduled| &scheduled.group_id != group_id);
    }

    /// Rebuild the in-memory jitter edges for durable current-epoch proposal
    /// rows. Replay performs the authenticated SelfRemove/type/authorization
    /// checks before staging; this scan only restores wakeups lost at restart
    /// or after publish rollback.
    pub(crate) fn restore_self_remove_auto_commit_schedules_for_group(
        &mut self,
        group_id: &GroupId,
        source_epoch: EpochId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        let records = self.storage.list_messages(group_id, source_epoch)?;
        self.restore_self_remove_auto_commit_schedules_in_records(
            group_id,
            source_epoch,
            now_ms,
            &records,
        )
    }

    /// [`Self::restore_self_remove_auto_commit_schedules_for_group`] over an
    /// already-fetched record list, so session-open hydration can share one
    /// `list_messages` scan across every work-detection pass (mdk#1161).
    pub(crate) fn restore_self_remove_auto_commit_schedules_in_records(
        &mut self,
        group_id: &GroupId,
        source_epoch: EpochId,
        now_ms: u64,
        records: &[MessageRecord],
    ) -> Result<bool, EngineError> {
        let mut restored = false;
        for record in records {
            if record.epoch != source_epoch
                || !matches!(
                    record.state,
                    MessageState::Created
                        | MessageState::Retryable
                        | MessageState::ConvergenceDeferred
                        | MessageState::Processed
                )
            {
                continue;
            }
            let Some((_message, projection)) = decode_openmls_wire_projection(&record.payload)
            else {
                continue;
            };
            if projection.kind != crate::openmls_projection::OpenMlsContentKind::Proposal
                || projection.source_epoch != Some(source_epoch.0)
            {
                continue;
            }
            self.schedule_self_remove_auto_commit(group_id, &record.id, source_epoch, now_ms)?;
            restored = true;
        }
        Ok(restored)
    }

    fn self_remove_auto_commit_jitter_ms(
        &self,
        group_id: &GroupId,
        proposal_id: &MessageId,
    ) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-selfremove-auto-commit-jitter/v1");
        hasher.update(self.identity.self_id().as_slice());
        hasher.update(group_id.as_slice());
        hasher.update(proposal_id.as_slice());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        SELF_REMOVE_AUTO_COMMIT_JITTER_MIN_MS
            + (u64::from_be_bytes(bytes) % (SELF_REMOVE_AUTO_COMMIT_JITTER_SPAN_MS + 1))
    }

    /// Drive stored OpenMLS inputs to stability, retrying raw transport
    /// records after each stable branch selection. This is the branch-aware
    /// path for future-epoch application messages and deeper branch commits:
    /// opaque transport bytes do not participate in canonicalization until a
    /// selected branch gives the peeler the epoch context needed to unwrap
    /// them.
    pub async fn advance_convergence_inputs_until_settled(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        // Promote a seeded-but-unhydrated group before reading its stored
        // inputs (mdk#1161). A failed promotion quarantines the group and
        // MUST propagate — continuing would read convergence state for a
        // group validation just rejected and could report it settled.
        // Already-quarantined groups keep their pre-existing semantics
        // (`ensure_hydrated` no-ops; converge reports the blocked run).
        self.ensure_hydrated(group_id)?;
        for _ in 0..MAX_CONVERGENCE_REPROCESSING_PASSES {
            if self.has_unresolved_convergence_inputs(group_id)? {
                let result = self
                    .converge_stored_openmls_messages_with_time(
                        group_id,
                        crate::convergence_clock::ConvergenceTime {
                            monotonic_ms: now_ms,
                            wall_ms: self.convergence_now().wall_ms,
                        },
                    )
                    .map_err(|e| EngineError::Backend(format!("converge inputs: {e}")))?;
                if result.convergence_status != crate::canonicalization::ConvergenceStatus::Settled
                {
                    return Ok(false);
                }
                // A completed frozen batch grants one queued user intent before
                // an inbound-only follow-up pass. Retry one deferred-peel sweep
                // first so newly available canonical context is visible. Return
                // to the drain only when that durable slot actually exists.
                let _ = self.retry_deferred_peels(group_id).await?;
                let fairness_slot_available =
                    self.storage
                        .convergence_pass(group_id)?
                        .is_some_and(|pass| {
                            pass.phase == cgka_traits::ConvergencePassPhase::Completed
                                && pass.fairness_slot_available
                        });
                if fairness_slot_available {
                    return Ok(true);
                }
                continue;
            }

            if self.retry_deferred_peels(group_id).await? == 0 {
                return Ok(!self.has_unresolved_convergence_inputs(group_id)?);
            }
        }

        Ok(false)
    }

    pub(crate) fn has_unresolved_convergence_inputs(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if self.has_unresolved_non_record_convergence_state(group_id)? {
            return Ok(true);
        }
        let group = match self.storage.get_group(group_id) {
            Ok(group) => group,
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(EngineError::Storage(e)),
        };
        let (anchor, ceiling) = self.convergence_gate_horizon(group_id, &group)?;
        let records = self.storage.list_messages(group_id, EpochId(anchor))?;
        Ok(self.any_gating_convergence_input(anchor, ceiling, &records))
    }

    /// [`Self::has_unresolved_convergence_inputs`] over an already-fetched
    /// full record list, so session-open hydration can share one
    /// `list_messages` scan across every work-detection pass (mdk#1161).
    pub(crate) fn has_unresolved_convergence_inputs_in_records(
        &self,
        group_id: &GroupId,
        group: &cgka_traits::group::Group,
        records: &[MessageRecord],
    ) -> Result<bool, EngineError> {
        if self.has_unresolved_non_record_convergence_state(group_id)? {
            return Ok(true);
        }
        let (anchor, ceiling) = self.convergence_gate_horizon(group_id, group)?;
        Ok(self.any_gating_convergence_input(anchor, ceiling, records))
    }

    fn has_unresolved_non_record_convergence_state(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if let Some(pass) = self.storage.convergence_pass(group_id)?
            && pass.is_active()
            && self.convergence_pass_gates_outbound(&pass)
        {
            return Ok(true);
        }
        self.disband_candidate_pending(group_id)
    }

    /// The convergence horizon is bounded on BOTH sides (mdk#736). The past
    /// side (`anchor`) drops inputs older than the retained-anchor window.
    /// The future side (`ceiling`) is symmetric: a convergence input more
    /// than `max_rewind_commits` epochs ahead of the current tip cannot chain
    /// from the tip yet (the candidate-path BFS in `openmls_projection` only
    /// extends `source_epoch == tip_epoch`), so it is not *resolvable
    /// convergence work* and must not gate outbound sends. Without the
    /// ceiling, a single member could forge one far-future-epoch (e.g. 2^63)
    /// plaintext message whose buffered `Created` row is never materialized
    /// and never given a terminal disposition, permanently gating every send
    /// for the whole group. The row is left in storage (not dropped here), so
    /// it gates again correctly once the tip advances into `[anchor, ceiling]`.
    fn convergence_gate_horizon(
        &self,
        group_id: &GroupId,
        group: &cgka_traits::group::Group,
    ) -> Result<(u64, u64), EngineError> {
        // Ungated: hydration calls this while the group is still
        // quarantined to decide whether to schedule post-repair
        // convergence. Live send/convergence paths already gate via
        // `ensure_group_live` before reaching here.
        let policy = self
            .convergence_policy_for_group_ungated(group_id)
            .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
        let rewind = policy.convergence.max_rewind_commits;
        Ok((
            group.epoch.0.saturating_sub(rewind),
            group.epoch.0.saturating_add(rewind),
        ))
    }

    fn any_gating_convergence_input(
        &self,
        anchor: u64,
        ceiling: u64,
        records: &[MessageRecord],
    ) -> bool {
        let mut skipped_non_resolvable: usize = 0;
        let mut classified = Vec::new();
        for record in records {
            // Below the anchor: callers fetching via `list_messages(anchor)`
            // never produce such rows; the shared-scan hydration path fetches
            // from epoch 0 and filters here instead.
            if record.epoch.0 < anchor {
                continue;
            }
            if !matches!(
                record.state,
                MessageState::Sent
                    | MessageState::Created
                    | MessageState::Retryable
                    | MessageState::ConvergenceDeferred
                    | MessageState::Processed
            ) {
                continue;
            }
            // Fail OPEN, not closed (mdk#736): a row we cannot decode, is not an
            // openmls-wire payload, or cannot be projected is NOT resolvable
            // convergence work — treating it as "unresolved" would let a single
            // corrupt/garbage row permanently gate sends with no recovery path.
            // Such a row simply does not contribute to the send gate; the
            // convergence horizon (`openmls_projection`) is responsible for
            // assigning it a terminal disposition. Count the skips so sustained
            // abuse (an insider spraying undecodable rows) is visible in audits
            // without spamming a log line per row (mdk#752 review).
            let Some((_message, projection)) = decode_openmls_wire_projection(&record.payload)
            else {
                skipped_non_resolvable += 1;
                continue;
            };
            // Beyond the future horizon: unreachable from the current tip, so
            // not gating work (see the ceiling rationale above).
            if projection.source_epoch.is_some_and(|epoch| epoch > ceiling) {
                continue;
            }
            let Some(source_epoch) = projection.source_epoch else {
                skipped_non_resolvable += 1;
                continue;
            };
            let Some(input) = ClassifiedConvergenceInput::from_projection(
                projection.kind,
                source_epoch,
                record.state,
                projection.message_digest,
            ) else {
                continue;
            };
            classified.push(input);
        }
        let context = ConvergenceInputContext::from_inputs(classified.iter().copied());
        // An unresolved commit always gates because it can advance or replace
        // canonical state. An application message gates only when retained
        // competing commit edges make it a potential branch-selection witness;
        // unresolved delivery by itself does not make group state ambiguous.
        // Proposals remain dependencies and do not gate independently.
        if classified
            .into_iter()
            .any(|input| context.gates_outbound(input))
        {
            return true;
        }
        // Reached only when nothing gates: surface any fail-open skips so an
        // insider spraying undecodable rows (which no longer wedges the gate but
        // still costs a scan) is visible in forensic audits. Aggregate count
        // only — no ids, epochs, or payloads (observability privacy invariant).
        if skipped_non_resolvable > 0 {
            tracing::debug!(
                target: "cgka_engine::message_processor",
                method = "has_unresolved_convergence_inputs",
                skipped_non_resolvable,
                "skipped non-resolvable convergence rows (fail-open)"
            );
        }
        false
    }

    pub fn has_pending_convergence_inputs(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        self.has_unresolved_convergence_inputs(group_id)
    }

    /// Whether durable queued outbound intents exist for this group. Runtime
    /// schedulers must keep a wakeup armed while any remain: the scheduled
    /// drain is what regenerates and publishes them (and, on an inactive
    /// transport, what triggers reactivation).
    pub fn has_queued_outbound_intents(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        Ok(!self
            .storage
            .list_queued_outbound_intents(group_id)?
            .is_empty())
    }

    /// Re-attempt retained `PeelDeferred` rows under the deferred-peel
    /// lifecycle (mdk#339):
    ///
    /// - **Event-driven**: a failed peel can only start succeeding when the
    ///   (epoch, retained-snapshot-set) peel context changes, so after a full
    ///   unproductive cycle over the backlog the context fingerprint gates
    ///   whole sweeps until the context actually changes.
    /// - **Budgeted**: a row that exhausts its retry budget without ever
    ///   peeling is resource-refused and released without terminal
    ///   deduplication instead of retrying forever.
    /// - **Bounded**: at most [`MAX_DEFERRED_ROWS_PER_SWEEP`] rows are
    ///   attempted per sweep (cursor resumes next pass) so a large historical
    ///   backlog never starves current-event processing.
    pub async fn retry_deferred_peels(&mut self, group_id: &GroupId) -> Result<usize, EngineError> {
        // A quarantined group has no epoch_manager entry, so the Stable gate
        // below would fall through and re-ingest its retained rows against
        // the very state validation rejected (mdk#364). The rows replay
        // once repair clears the quarantine.
        if self.quarantined_reason(group_id).is_some() {
            return Ok(0);
        }
        // A seeded-but-unhydrated group holds a provisional Stable entry, so
        // the gate below would fall through and re-ingest retained rows
        // against unvalidated state (mdk#1161). Skip; the sweep after
        // `ensure_hydrated` promotes the group picks the rows up.
        if self.unhydrated_groups.contains(group_id) {
            return Ok(0);
        }
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(0);
        }

        let now = self.convergence_now();
        let mut deferred: Vec<_> = self
            .storage
            .list_messages(group_id, EpochId(0))?
            .into_iter()
            .filter(|record| record.state == MessageState::PeelDeferred)
            .collect();
        if self.normalize_deferred_peel_lifecycles(&mut deferred, now)? {
            // Legacy initialization and restart rebasing are durable writes,
            // so migrate them in the same bounded slices as peel attempts.
            // The pending edge keeps the scheduler advancing the backlog.
            self.schedule_pending_convergence_group(group_id);
            return Ok(0);
        }

        // Residence expiry is independent of peel-context changes. Check it
        // before the fingerprint gate so a permanently stable group can still
        // release opaque local resource state.
        let due = deferred
            .iter()
            .filter(|record| {
                record.deferred_peel.as_ref().is_some_and(|lifecycle| {
                    lifecycle.clock_instance_id == self.convergence_clock_instance_id
                        && now.monotonic_ms >= lifecycle.residence_deadline_monotonic_ms
                })
            })
            .take(MAX_DEFERRED_ROWS_PER_SWEEP)
            .cloned()
            .collect::<Vec<_>>();
        if !due.is_empty() {
            for record in &due {
                self.release_deferred_peel_row(
                    record,
                    InboundResourceLimit::TransportDeferredResidenceBudget,
                    crate::message_disposition::MessageDisposition::ResidenceBudgetRefused,
                )?;
            }
            if deferred.len() > due.len() {
                self.schedule_pending_convergence_group(group_id);
            }
            return Ok(due.len());
        }

        // The full row list is in hand: refresh the flood-cap count, then stop
        // before the context work when there is nothing to sweep. Describing
        // this group's peel context reads storage, so an empty backlog must not
        // pay for it on every drain.
        let total = deferred.len();
        {
            let state = self.deferred_peel.entry(group_id.clone()).or_default();
            state.deferred_rows = total;
            state.counted = true;
        }
        if total == 0 {
            return Ok(0);
        }

        let fingerprint = self.deferred_peel_context_fingerprint(group_id)?;
        if self
            .deferred_peel
            .get(group_id)
            .is_some_and(|state| state.gate == Some(fingerprint))
        {
            // The peel context is unchanged since the last full unproductive
            // cycle: every retained row would fail exactly as before. New
            // deferrals don't clear this gate either — a row is only deferred
            // after failing a live peel against this same context.
            tracing::debug!(
                target: "cgka_engine::message_processor",
                method = "retry_deferred_peels",
                "skipping deferred-peel sweep: peel context unchanged"
            );
            return Ok(0);
        }

        let sweep_started = std::time::Instant::now();
        let (start, retry_budget) = {
            let budget = self.deferred_peel_retry_budget;
            let state = self.deferred_peel.entry(group_id.clone()).or_default();
            state.sweep_count += 1;
            if state.cursor >= total {
                state.cursor = 0;
            }
            if state.cursor == 0 {
                state.cycle_progressed = false;
            }
            (state.cursor, budget)
        };

        // Candidate branch states are part of this group's peel context, not a
        // separate mechanism: post-fork traffic is sealed under the SENDER's
        // branch state, so a rival branch's later commits and app messages are
        // opaque to every device that adopted a different branch. Materializing
        // each candidate branch produces the context that reads its traffic, so
        // depth and app witnesses can be counted over evidence this device has
        // not adopted instead of each committer scoring only its own branch.
        //
        // Empty for an uncontested graph, so a group without competing commits
        // pays only the seeding scan. Nothing read here is trusted: the bytes
        // re-enter through ordinary ingest and only the next pass's OpenMLS
        // replay authenticates them. A peel that fails is silence.
        let peel = self.candidate_branch_peel(group_id)?;
        let sweep = crate::message_processor::ingest::DeferredPeelSweep::over_branches(&peel);

        let end = (start + MAX_DEFERRED_ROWS_PER_SWEEP).min(total);
        let mut progressed = 0usize;
        let mut terminal = 0usize;
        for mut record in deferred[start..end].iter().cloned() {
            let lifecycle = record
                .deferred_peel
                .as_mut()
                .expect("deferred lifecycle normalized before sweep");
            // A restart loses the in-memory group gate, but the durable row
            // still proves this exact context was already attempted.
            if lifecycle.last_context_fingerprint == Some(fingerprint) {
                continue;
            }
            if lifecycle.distinct_context_attempts >= retry_budget {
                self.release_deferred_peel_row(
                    &record,
                    InboundResourceLimit::TransportDeferredRetryBudget,
                    crate::message_disposition::MessageDisposition::RetryBudgetRefused,
                )?;
                terminal += 1;
                continue;
            }
            lifecycle.distinct_context_attempts =
                lifecycle.distinct_context_attempts.saturating_add(1);
            lifecycle.last_context_fingerprint = Some(fingerprint);
            lifecycle.wall_high_water_ms = lifecycle.wall_high_water_ms.max(now.wall_ms);
            // Persist the consumed context before invoking the peeler. A crash
            // may conservatively consume an attempt, but cannot reset it.
            self.storage.put_message(&record)?;

            if self
                .reingest_deferred_peel_row(group_id, &record, sweep)
                .await?
            {
                progressed += 1;
            }
        }

        // One drain over the whole batch. A contested sweep buffered every row
        // it recovered without draining, because those rows are one evidence
        // set and a pass must not freeze on a prefix of it: adjudicating half a
        // fork settles a verdict the other half would have changed, and the
        // losers of that verdict are terminalized before the evidence that
        // would have saved them is even admitted. Uncontested sweeps drained
        // per row on the way in and have nothing left to do here.
        //
        // Same predicate as `drain_policy`, so no row is ever deferred to a
        // drain that does not run. A sweep whose enumeration halted recovers
        // nothing and still drains: the fork is real, and the pass — not this
        // sweep — owns what to do about a fork it cannot enumerate.
        if sweep.is_contested() {
            self.converge_stored_openmls_messages_with_time(group_id, now)
                .map_err(|e| EngineError::Backend(format!("converge swept batch: {e}")))?;
        }

        let queue_depth = {
            let state = self.deferred_peel.entry(group_id.clone()).or_default();
            state.cycle_progressed |= progressed > 0;
            state.cursor = if end >= total { 0 } else { end };
            // Arm the gate only after a full cycle over the backlog made no
            // progress — a bounded sweep must never permanently skip rows it
            // has not attempted under this context.
            if end >= total && !state.cycle_progressed {
                state.gate = Some(fingerprint);
            }
            state.deferred_rows
        };
        tracing::info!(
            target: "cgka_engine::message_processor",
            method = "retry_deferred_peels",
            rows_attempted = (end - start) as u64,
            backlog = total as u64,
            progressed = progressed as u64,
            terminal = terminal as u64,
            contested = peel.contested,
            branch_contexts = peel.contexts.len() as u64,
            queue_depth = queue_depth as u64,
            sweep_duration_ms = sweep_started.elapsed().as_millis() as u64,
            "deferred-peel retry sweep"
        );
        Ok(progressed)
    }

    /// Classify this group's convergence graph as contested or not, and
    /// materialize the candidate branches it offers.
    fn candidate_branch_peel(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::openmls_projection::CandidateBranchPeel, EngineError> {
        let group = self.storage.get_group(group_id)?;
        let policy = self
            .convergence_policy_for_group_ungated(group_id)
            .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
        let max_rewind_commits = policy.convergence.max_rewind_commits;
        crate::openmls_projection::candidate_branch_peel(
            &self.storage,
            group_id,
            group.epoch.0.saturating_sub(max_rewind_commits),
            max_rewind_commits,
            crate::openmls_projection::ReplayProfilePolicy {
                reject_legacy_group_additions: self.new_protocol_profile
                    == cgka_traits::group::ProtocolProfile::Current,
            },
            MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS,
        )
        .map_err(|e| EngineError::Backend(format!("candidate branch peel: {e}")))
    }

    /// Re-ingest one retained raw-transport row and settle its retry lifecycle
    /// from whatever ingest decided. Returns whether the row made progress —
    /// i.e. left the retry lifecycle.
    ///
    /// Split out from the sweep loop so the retire/keep rules read as one
    /// rulebook rather than as control flow; the caller owns retry-budget
    /// accounting.
    async fn reingest_deferred_peel_row(
        &mut self,
        group_id: &GroupId,
        record: &MessageRecord,
        sweep: crate::message_processor::ingest::DeferredPeelSweep<'_>,
    ) -> Result<bool, EngineError> {
        let stored_payload = StoredMessagePayload::decode(&record.payload)
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let Some(msg) = stored_payload.as_raw_transport().cloned() else {
            return Ok(false);
        };
        match self
            .ingest_group_message_from_sweep(&msg, group_id.as_slice().to_vec(), sweep)
            .await
        {
            Ok(IngestOutcome::TransportDeferred { .. }) => Ok(false),
            Ok(IngestOutcome::ResourceRefused {
                resource: InboundResourceLimit::TransportDeferredCapacity,
                ..
            }) => Ok(false),
            Ok(IngestOutcome::LocalState {
                state: LocalIngestState::Quarantined,
            }) => {
                // Defense-in-depth: the gates above should keep this from
                // running for a quarantined group at all, but if a row still
                // classifies Quarantined it must keep its PeelDeferred state —
                // the catch-all arm below would retire the replay buffer.
                Ok(false)
            }
            Ok(IngestOutcome::Buffered { .. } | IngestOutcome::Processed) => {
                // The peeled content now has its own content-derived record;
                // retire the raw transport wrapper so it does not keep
                // re-entering this retry loop as a stale duplicate — but ONLY
                // while it is still awaiting retry. `record` is the pre-ingest
                // sweep snapshot; ingest may have committed a terminal state to
                // this same row during the call (or a convergence rollback may
                // have deleted it). That ingest-committed verdict is
                // authoritative, so re-read the row and retire only a state
                // ingest left awaiting retry (seam parity with
                // `replay_buffered_messages`, 5ae9a440).
                if self.raw_transport_row_awaiting_retry(&record.id)? {
                    self.update_stored_message_state(&record.id, MessageState::Processed)?;
                }
                // Release the flood-cap slot whenever the row leaves the retry
                // lifecycle, whether this arm retired it or ingest already
                // terminalized it.
                self.note_peel_deferred_row_retired(group_id);
                Ok(true)
            }
            Ok(
                IngestOutcome::Stale { .. }
                | IngestOutcome::Ignored { .. }
                | IngestOutcome::LocalState { .. }
                | IngestOutcome::ResourceRefused { .. }
                | IngestOutcome::Rejected { .. },
            ) => {
                // Terminal stale classifications are still successful
                // reclassifications of this raw deferred row. Retire it only
                // while it is still awaiting retry: the reachable case is
                // `SelfEvicted`, where re-ingesting the deferred row against a
                // now-inactive group makes ingest persist it `Failed`
                // (ingest.rs). Relabeling that evicted-on row `Processed` would
                // sweep it back into canonicalization, so re-read the row and
                // never clobber ingest's terminal verdict.
                if self.raw_transport_row_awaiting_retry(&record.id)? {
                    self.update_stored_message_state(&record.id, MessageState::Processed)?;
                }
                // The cap-slot release stays outside the guard: the row has left
                // the retry lifecycle regardless of who terminalized it.
                self.note_peel_deferred_row_retired(group_id);
                Ok(true)
            }
            Err(EngineError::ForkedEpoch {
                group_id: forked_group_id,
                last_stable,
                conflicting_epoch,
            }) => {
                self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                self.note_peel_deferred_row_retired(group_id);
                Err(EngineError::ForkedEpoch {
                    group_id: forked_group_id,
                    last_stable,
                    conflicting_epoch,
                })
            }
            Err(e) => {
                self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                self.note_peel_deferred_row_retired(group_id);
                Err(e)
            }
        }
    }

    /// Return the remaining time until the earliest durable deferred-peel
    /// residence deadline. Legacy rows receive a fresh conservative deadline;
    /// process-local monotonic deadlines are rebased after restart.
    pub fn deferred_peel_cutoff_delay_ms(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<u64>, EngineError> {
        if self.quarantined_reason(group_id).is_some() {
            return Ok(None);
        }
        // A seeded-but-unhydrated group holds a provisional Stable entry, so
        // the state gate below would fall through and persist deferred-peel
        // lifecycle normalization against unvalidated state (mdk#1161). No
        // deadline yet; the scheduler re-asks after hydration promotes it.
        if self.unhydrated_groups.contains(group_id) {
            return Ok(None);
        }
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(None);
        }
        let now = self.convergence_now();
        let mut deferred = self
            .storage
            .list_messages(group_id, EpochId(0))?
            .into_iter()
            .filter(|record| record.state == MessageState::PeelDeferred)
            .collect::<Vec<_>>();
        let normalization_pending = self.normalize_deferred_peel_lifecycles(&mut deferred, now)?;
        let mut earliest = None;
        for record in deferred {
            let deadline = record
                .deferred_peel
                .as_ref()
                .expect("deferred lifecycle normalized")
                .residence_deadline_monotonic_ms;
            let remaining = deadline.saturating_sub(now.monotonic_ms);
            earliest = Some(earliest.map_or(remaining, |current: u64| current.min(remaining)));
        }
        // Finish a legacy/restart migration promptly. Each call persists at
        // most one sweep-sized slice, avoiding an unbounded write burst.
        Ok(normalization_pending.then_some(0).or(earliest))
    }

    /// Fingerprint of everything that can change a deferred peel's outcome:
    /// the group's live epoch, the retained peel-snapshot set, and the stored
    /// commit graph the sweep's candidate branch contexts are derived from.
    /// While all three are unchanged, re-peeling a deferred row is guaranteed
    /// wasted work.
    fn deferred_peel_context_fingerprint(
        &self,
        group_id: &GroupId,
    ) -> Result<[u8; 32], EngineError> {
        let epoch = self.epoch_manager.epoch(group_id).unwrap_or_default();
        let mut names: Vec<String> = self
            .available_past_peel_snapshots(group_id)?
            .into_iter()
            .map(|(snapshot_epoch, name)| format!("{}:{name}", snapshot_epoch.0))
            .collect();
        names.sort();
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-deferred-peel-context/v1");
        hasher.update(epoch.0.to_be_bytes());
        for name in names {
            hasher.update((name.len() as u64).to_be_bytes());
            hasher.update(name.as_bytes());
        }
        // The stored commit graph is part of the peel context too: candidate
        // branch states are derived from it, so a newly retained rival commit
        // adds a readable context even though the live epoch and the retained
        // anchor set are both unchanged. Without this term the gate would stay
        // armed exactly where it must not — on a device holding its own branch
        // while a rival branch's traffic sits unreadable.
        for digest in self.stored_convergence_commit_digests(group_id)? {
            hasher.update(digest);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }

    /// Content digests of the stored commits that can contribute to this
    /// group's convergence graph, in a stable order.
    fn stored_convergence_commit_digests(
        &self,
        group_id: &GroupId,
    ) -> Result<BTreeSet<[u8; 32]>, EngineError> {
        let mut digests = BTreeSet::new();
        for record in self.storage.list_messages(group_id, EpochId(0))? {
            // Share the graph's own membership predicate rather than restating
            // it: this set must describe exactly the commits a pass would build
            // candidate branches from, and a private copy of that match drifts
            // without any test noticing.
            if !crate::openmls_projection::record_state_can_contribute_to_openmls_graph(
                record.state,
            ) {
                continue;
            }
            let Some((_message, projection)) = decode_openmls_wire_projection(&record.payload)
            else {
                continue;
            };
            if projection.kind == crate::openmls_projection::OpenMlsContentKind::Commit {
                digests.insert(projection.message_digest);
            }
        }
        Ok(digests)
    }

    /// Check capacity for one new `PeelDeferred` row, lazily counting the
    /// group's retained rows on first use this session. This deliberately does
    /// not consume a slot: the caller records the row only after its durable
    /// write succeeds, so a storage error cannot leak in-memory capacity.
    pub(crate) fn has_peel_deferred_capacity(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if !self
            .deferred_peel
            .get(group_id)
            .is_some_and(|state| state.counted)
        {
            let count = self
                .storage
                .list_messages(group_id, EpochId(0))?
                .into_iter()
                .filter(|record| record.state == MessageState::PeelDeferred)
                .count();
            let state = self.deferred_peel.entry(group_id.clone()).or_default();
            state.deferred_rows = count;
            state.counted = true;
        }
        let state = self.deferred_peel.entry(group_id.clone()).or_default();
        Ok(state.has_capacity())
    }

    pub(crate) fn note_peel_deferred_row_persisted(&mut self, group_id: &GroupId) {
        self.deferred_peel
            .entry(group_id.clone())
            .or_default()
            .note_row_persisted();
    }

    /// Bookkeeping for a row leaving `PeelDeferred` (applied, reclassified,
    /// invalidated, or terminally failed): release its flood-cap slot and its
    /// attempt-tracking entry. Once the backlog drops back below the cap, the
    /// cap-rejection audit re-arms so a fresh cap-full episode is recorded
    /// once more.
    pub(crate) fn note_peel_deferred_row_retired(&mut self, group_id: &GroupId) {
        if let Some(state) = self.deferred_peel.get_mut(group_id) {
            state.deferred_rows = state.deferred_rows.saturating_sub(1);
            if state.deferred_rows < MAX_PEEL_DEFERRED_ROWS_PER_GROUP {
                state.cap_rejection_audited = false;
            }
        }
    }

    /// Whether a cap-exceeded `Rejection` should be audited now: `true` only
    /// the first time the cap is hit for the current cap-full episode, so a
    /// sustained attacker flood past the cap does not emit one audit write
    /// per rejected message (mdk#339). Re-arms via
    /// [`Self::note_peel_deferred_row_retired`] once the backlog drains.
    pub(crate) fn should_audit_peel_deferred_cap_rejection(&mut self, group_id: &GroupId) -> bool {
        let state = self.deferred_peel.entry(group_id.clone()).or_default();
        if state.cap_rejection_audited {
            return false;
        }
        state.cap_rejection_audited = true;
        true
    }

    /// Discard every queued outbound intent for a group whose local copy is
    /// marked removed. A removed copy must never prepare or publish anything
    /// (member-departure.md, "Realizing removal"), so a durably queued intent
    /// — e.g. one accepted mid-convergence just before the removal was
    /// realized — is terminally unsendable: leaving it queued would make every
    /// later drain re-fail it through the removed-copy send gate forever. The
    /// discard is silent toward the app (the self-removed notification already
    /// carries the user-facing signal); each dropped intent leaves a forensic
    /// `Rejection` audit row plus an aggregate trace line. Returns the number
    /// discarded.
    pub(crate) fn discard_queued_outbound_intents_for_removed_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<usize, EngineError> {
        let queued = self.storage.list_queued_outbound_intents(group_id)?;
        if queued.is_empty() {
            return Ok(0);
        }
        for record in &queued {
            self.storage.delete_queued_outbound_intent(&record.id)?;
            self.audit_group(
                group_id,
                marmot_forensics::AuditEventKind::Rejection {
                    msg_id: hex::encode(record.id.as_slice()),
                    reason: "queued_outbound_intent_discarded_group_removed".to_string(),
                },
            );
        }
        // Privacy-safe: aggregate count only, no group ids or intent contents
        // (observability.md).
        tracing::info!(
            target: "cgka_engine::message_processor",
            method = "discard_queued_outbound_intents_for_removed_group",
            discarded = queued.len(),
            "discarded queued outbound intents for a removed group copy"
        );
        Ok(queued.len())
    }

    fn queue_outbound_intent(
        &mut self,
        group_id: GroupId,
        intent: SendIntent,
    ) -> Result<SendResult, EngineError> {
        let created_at_ms = self.convergence_now_ms();
        let existing_count = self.storage.list_queued_outbound_intents(&group_id)?.len();
        // Refuse before serializing or writing anything: the single durable
        // write on this path is below, so a refusal here leaves nothing to
        // compensate.
        if existing_count >= MAX_QUEUED_OUTBOUND_INTENTS_PER_GROUP {
            return Err(EngineError::QueuedOutboundAtCapacity { group_id });
        }
        let intent_bytes =
            serde_json::to_vec(&intent).map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-queued-outbound-intent/v1");
        hasher.update(group_id.as_slice());
        hasher.update(self.identity.self_id().as_slice());
        hasher.update(created_at_ms.to_be_bytes());
        hasher.update((existing_count as u64).to_be_bytes());
        hasher.update(&intent_bytes);
        let intent_id = MessageId::new(hasher.finalize().to_vec());
        self.storage
            .put_queued_outbound_intent(&QueuedOutboundIntent {
                id: intent_id.clone(),
                group_id: group_id.clone(),
                intent,
                created_at_ms,
            })?;
        // The drain is what releases this row, so writing it and arming the
        // drain are one step — see `has_queued_outbound_intents`. `Stable` is
        // the drain's own precondition: a group held by a publish or a halt
        // gets its arm from the seam that ends the hold
        // (`schedule_drain_for_retained_outbound_intents`), and arming into the
        // hold would only spend the schedule on a drain that returns early.
        if self
            .epoch_manager
            .state(&group_id)
            .is_some_and(EpochState::is_stable)
        {
            self.schedule_pending_convergence_group(&group_id);
        }
        Ok(SendResult::Queued {
            group_id,
            intent_id,
        })
    }

    /// Queue a `GroupStateChanged` event for the application to synthesize into
    /// a durable kind-1210 group system row. `origin_commit_id` carries the
    /// transport id of the commit that produced this change (when attributable),
    /// so the row can be invalidated by origin commit if that commit later loses
    /// a fork. Reorg-driven re-derivations that cannot resolve a single commit
    /// pass `None`.
    pub(crate) fn push_group_state_change(
        &mut self,
        group_id: &GroupId,
        epoch: EpochId,
        actor: Option<MemberId>,
        change: GroupStateChange,
        origin_commit_id: Option<MessageId>,
    ) {
        let full_data = self.recorder.data_mode() == marmot_forensics::AuditDataMode::FullData;
        self.audit_group(
            group_id,
            crate::audit_helpers::group_state_changed_event(
                epoch,
                actor.as_ref(),
                &change,
                origin_commit_id.as_ref(),
                full_data,
            ),
        );
        self.events_buf.push_back(GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch,
            actor,
            change,
            origin_commit_id,
        });
    }

    pub(crate) async fn replay_buffered_messages(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        let records = self.storage.list_messages(group_id, EpochId(0))?;
        for record in records {
            if !matches!(
                record.state,
                MessageState::Created | MessageState::Retryable | MessageState::PeelDeferred
            ) {
                continue;
            }
            let stored_payload = StoredMessagePayload::decode(&record.payload)
                .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
            let Some(msg) = stored_payload.as_raw_transport().cloned() else {
                continue;
            };
            let was_peel_deferred = record.state == MessageState::PeelDeferred;
            match self
                .ingest_group_message(&msg, group_id.as_slice().to_vec())
                .await
            {
                Ok(IngestOutcome::Buffered { .. }) => {
                    if was_peel_deferred {
                        // The content-derived row is now the buffered
                        // convergence witness; retire the raw deferred wrapper
                        // so it leaves the retry lifecycle and frees its cap
                        // slot (mdk#339), mirroring `retry_deferred_peels`.
                        self.update_stored_message_state(&record.id, MessageState::Processed)?;
                        self.note_peel_deferred_row_retired(group_id);
                    } else if self.raw_transport_row_awaiting_retry(&record.id)? {
                        // Keep the row replayable ONLY while ingest itself did
                        // not already resolve it. A peeled message buffered
                        // into convergence retires its own raw wrapper
                        // (`mark_raw_transport_message_processed_if_awaiting_retry`)
                        // — resetting it Retryable here would re-peel it on
                        // every later publish-cycle replay.
                        self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                    }
                }
                Ok(
                    IngestOutcome::TransportDeferred { .. }
                    | IngestOutcome::LocalState {
                        state: LocalIngestState::Quarantined,
                    }
                    | IngestOutcome::Ignored {
                        category: InputRejectionCategory::UnknownGroup,
                    },
                ) => {
                    // Leave the row in its retry state so a later pass re-attempts
                    // it. `TransportDeferred`: still un-peelable.
                    // A terminal-after-peel path inside `ingest_group_message`
                    // (`mark_raw_transport_message_failed_if_awaiting_retry`,
                    // `PeelDeferred`/`Retryable` alike). `Quarantined`: the group
                    // is frozen; the row replays once repair clears it.
                    // `UnknownGroup`: no local group matches yet — `ingest`
                    // deliberately re-buffered the row `Retryable` because a later
                    // welcome may create the group, so terminalizing it here would
                    // drop a recoverable message.
                }
                Ok(_) => {
                    // Terminal reclassification of the raw wrapper: the content-
                    // derived row now carries the real verdict — applied
                    // (`Processed`), a same-epoch fork the incumbent won
                    // (`AlreadyAtEpoch`, content row `EpochInvalidated`), a
                    // duplicate (`Ignored { category: Duplicate }`), our own echo
                    // (`Ignored { category: OwnEcho }`), or our own eviction
                    // (`LocalState { state: Removed }`). Retire the raw wrapper so
                    // it leaves the retry lifecycle instead of being re-peeled on
                    // every subsequent publish-cycle replay — but ONLY while it
                    // is still awaiting retry. `record.state` is the pre-ingest
                    // snapshot; `ingest_group_message` may have already committed
                    // a terminal state to this same row during the call. The
                    // reachable removal case is a buffered peer commit that evicts
                    // our leaf: the next buffered row hits `!is_active`, which
                    // persists that row `Failed` (ingest.rs). That
                    // ingest-committed verdict is authoritative — relabeling an
                    // evicted-on row `Processed` would sweep it back into
                    // canonicalization (`openmls_projection` /
                    // `distributed_convergence` select on `Processed`). Re-read the
                    // row and retire only a state ingest left awaiting retry.
                    if self.raw_transport_row_awaiting_retry(&record.id)? {
                        self.update_stored_message_state(&record.id, MessageState::Processed)?;
                    }
                    // Only a `PeelDeferred` row holds a flood-cap slot (mdk#339);
                    // its accounting tracks the original deferred count, so release
                    // the slot whenever the row leaves the retry lifecycle — whether
                    // this arm retired it or ingest already terminalized it.
                    if was_peel_deferred {
                        self.note_peel_deferred_row_retired(group_id);
                    }
                }
                Err(EngineError::ForkedEpoch {
                    group_id: forked_group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    if was_peel_deferred {
                        self.note_peel_deferred_row_retired(group_id);
                    }
                    return Err(EngineError::ForkedEpoch {
                        group_id: forked_group_id,
                        last_stable,
                        conflicting_epoch,
                    });
                }
                Err(e) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                    if was_peel_deferred {
                        self.note_peel_deferred_row_retired(group_id);
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

fn record_group_id(msg: &TransportMessage) -> GroupId {
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            GroupId::new(transport_group_id.clone())
        }
        TransportEnvelope::Welcome { .. } => GroupId::new(Vec::new()),
    }
}

/// Canonical, content-derived duplicate-detection / replay id for a recovered
/// MLS message.
///
/// Per foundation/wire-envelopes.md and protocol-core/inbound-processing.md the
/// dedup id MUST be stable for the carried protocol bytes and MUST NOT depend on
/// the transport event id. This hashes the peeled MLS wire bytes with the same
/// `SHA-256(mls_bytes)` convention `CommitOrderingKey::from_commit_bytes` uses
/// for fork ordering, so the same MLS message re-wrapped in a fresh transport
/// envelope maps to one id, independent of the outer ephemeral key / nonce.
pub(crate) fn content_dedup_id(mls_bytes: &[u8]) -> MessageId {
    MessageId::new(Sha256::digest(mls_bytes).to_vec())
}

pub(crate) fn route_wrapped_group_message(
    msg: TransportMessage,
    ctx: &cgka_traits::group_context::GroupContextSnapshot,
) -> TransportMessage {
    let Some(transport_group_id) = ctx.transport_group_id().map(ToOwned::to_owned) else {
        return msg;
    };
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage { transport_group_id },
        ..msg
    }
}

fn send_intent_group_id(intent: &SendIntent) -> &GroupId {
    match intent {
        SendIntent::AppMessage { group_id, .. }
        | SendIntent::Invite { group_id, .. }
        | SendIntent::RemoveMembers { group_id, .. }
        | SendIntent::Leave { group_id }
        | SendIntent::SelfUpdate { group_id }
        | SendIntent::UpdateAppComponents { group_id, .. }
        | SendIntent::UpdateGroupData { group_id, .. }
        | SendIntent::EnableDisbanding { group_id }
        | SendIntent::Disband { group_id } => group_id,
    }
}

/// Single classification chokepoint for the convergence.md one-attempt
/// reservation: only an admin-authorized local group-state evolution may hold
/// the completed-pass boundary open (marmot#375). Queued application messages
/// must never park pass admission.
pub(crate) fn is_admin_group_state_intent(intent: &SendIntent) -> bool {
    matches!(
        intent,
        SendIntent::Invite { .. }
            | SendIntent::RemoveMembers { .. }
            | SendIntent::UpdateAppComponents { .. }
            | SendIntent::UpdateGroupData { .. }
            | SendIntent::EnableDisbanding { .. }
            | SendIntent::Disband { .. }
    )
}

#[cfg(test)]
mod deferred_peel_accounting_tests {
    use super::*;

    #[test]
    fn capacity_check_does_not_consume_slot_before_persist() {
        let mut state = DeferredPeelGroupState {
            counted: true,
            ..Default::default()
        };

        assert!(state.has_capacity());
        assert_eq!(
            state.deferred_rows, 0,
            "a failed write must consume no slot"
        );

        state.note_row_persisted();
        assert_eq!(state.deferred_rows, 1);
    }
}
