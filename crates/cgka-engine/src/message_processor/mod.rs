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
pub(crate) use store::transition_staged_invite_welcomes;

use crate::convergence_input::{ClassifiedConvergenceInput, ConvergenceInputContext};
use crate::engine::{Engine, ScheduledSelfRemoveAutoCommit};
use crate::engine_metrics::DeferredPeelCapacityResource;
use crate::openmls_projection::decode_openmls_wire_projection;
use cgka_traits::engine::{GroupEvent, GroupStateChange, SendIntent, SendResult};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::{
    DeferralLineage, InboundResourceLimit, IngestOutcome, InputRejectionCategory, LocalIngestState,
};
use cgka_traits::message::{
    MessageRecord, MessageState, StoredMessagePayload, StoredMessagePayloadCodecError,
};
use cgka_traits::storage::{
    DeferredPeelGeneration, QueuedOutboundIntent, StorageError, StorageProvider,
};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
pub const MAX_PEEL_DEFERRED_ROWS_PER_GROUP: usize = 512;

/// Maximum encoded `PeelDeferred` payload bytes retained for one group.
///
/// Row count alone is not a meaningful storage bound because the opaque
/// transport payload is variable-length. This budget deliberately counts the
/// exact encoded [`StoredMessagePayload`] bytes written to `MessageRecord`, so
/// transport framing overhead is included and every storage backend applies
/// the same policy.
pub const MAX_PEEL_DEFERRED_BYTES_PER_GROUP: usize = 16 * 1024 * 1024;

/// Maximum encoded `PeelDeferred` payload bytes retained across one
/// account-device database.
///
/// The per-group byte budget prevents one routing id from consuming the
/// account, while this wider budget prevents the same flood from being spread
/// across many known groups. One engine owns one account-device database, so
/// this is the natural aggregate resource boundary.
pub const MAX_PEEL_DEFERRED_BYTES_PER_ACCOUNT: usize = 64 * 1024 * 1024;

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
/// was called) grow past what a mobile device can absorb. 256 sits far above
/// any plausible human burst across a stall. This locally originated queue has
/// a different threat model from peer-mintable deferred transport input and is
/// therefore intentionally independent of the deferred-peel limits above.
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
/// published but never acknowledged still holds its slot and stays in flight.
/// A definite retry clears that in-flight association so the next drain
/// re-prepares it. A group whose transport keeps failing therefore sits at the
/// cap: its rows keep being re-attempted, but nothing frees a slot until a
/// publish is accepted by at least one endpoint.
pub const MAX_QUEUED_OUTBOUND_INTENTS_PER_GROUP: usize = 256;

/// Upper bound on `PeelDeferred` rows re-attempted per retry sweep
/// (mdk#339): a large historical backlog is worked through in slices
/// across passes instead of holding a convergence drain hostage, so current
/// events are never blocked behind irrelevant history.
pub(crate) const MAX_DEFERRED_ROWS_PER_SWEEP: usize = 64;

/// Maximum deferred-history work admitted to one foreground outbound
/// preflight (mdk#1176). The time bound is cooperative for synchronous storage
/// and MLS operations already in progress; asynchronous peel waits receive
/// only the deadline remainder.
pub const FOREGROUND_DEFERRED_PEEL_BUDGET_MS: u64 = 250;
/// Maximum deferred-row attempts admitted to one foreground outbound
/// preflight (mdk#1176).
pub const MAX_FOREGROUND_DEFERRED_ROWS: usize = 4;

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
    /// Monotonic sweep counter used to report aggregate sweep progress.
    sweep_count: u64,
    /// Cached count of retained `PeelDeferred` rows backing the flood cap.
    /// Refreshed from storage on every sweep; adjusted at the deferral /
    /// terminal transition sites in between.
    deferred_rows: usize,
    /// Encoded payload bytes held by those rows.
    deferred_bytes: usize,
    /// Exact retained ids and encoded lengths make replacement and retirement
    /// accounting idempotent across nested ingest/replay paths.
    deferred_payload_bytes_by_id: HashMap<MessageId, usize>,
    /// Whether a cap-exceeded `Rejection` has already been audited for the
    /// current cap-full episode. Raw transport ids are attacker-controlled,
    /// so a sustained flood past the cap would otherwise emit one audit write
    /// per rejected message; this suppresses the repeats until the backlog
    /// drops back below the cap and re-arms.
    cap_rejection_audited: bool,
    /// Candidate branch contexts for one exact process-local generation.
    ///
    /// These contexts contain exporter-derived secret material. The cache is
    /// deliberately nested in engine memory: it is never serialized, audited,
    /// logged, or copied into durable generation state, and process restart
    /// drops it naturally.
    candidate_cache: Option<DeferredPeelCandidateCacheEntry>,
    /// Per-row verdicts backing `stored_convergence_commit_edges`: the
    /// stored payload's hash, plus the commit's `(source_epoch, digest)` or
    /// `None` for a row that is not an MLS-wire commit. A row id CAN map to different payload bytes
    /// over its lifetime — `persist_stored_message_payload` overwrites a
    /// same-id row stored under a different payload variant (e.g. RawTransport
    /// re-persisted as OpenMlsWire, #369) — so each reuse revalidates the
    /// cheap payload hash and only then skips the decode + TLS parse. Rebuilt
    /// to the currently listed rows on every use, so it cannot outgrow the
    /// group's stored history.
    commit_digest_memo: HashMap<MessageId, ([u8; 32], Option<CommitEdge>)>,
}

pub(crate) struct PreparedDeferredPeelPayload {
    pub(crate) previous_payload_bytes: Option<usize>,
    pub(crate) encoded_payload: Vec<u8>,
}

/// `(source_epoch, digest)` of one stored commit in the convergence graph.
type CommitEdge = (u64, [u8; 32]);

struct DeferredPeelCandidateCacheEntry {
    context_fingerprint: [u8; 32],
    /// Exact durable barrier generation observed after enumeration. `None` is
    /// also meaningful and must match on reuse.
    durable_generation_fingerprint: Option<[u8; 32]>,
    /// Pending proposals may be folded into candidate replay paths, but merely
    /// staging a proposal cannot change the epoch, exporter secret, or
    /// transport route captured by `GroupContextSnapshot`. If that snapshot
    /// ever gains proposal-dependent state, this cache key must gain the same
    /// dependency.
    peel: Arc<crate::openmls_projection::CandidateBranchPeel>,
}

struct DeferredPeelCandidateEnumerationFailure {
    error: EngineError,
    replay_probe_count: u64,
}

impl DeferredPeelGroupState {
    fn has_capacity(
        &self,
        incoming_rows: usize,
        incoming_bytes: usize,
        row_limit: usize,
        byte_limit: usize,
    ) -> bool {
        (incoming_rows == 0 || self.deferred_rows.saturating_add(incoming_rows) <= row_limit)
            && (incoming_bytes == 0
                || self.deferred_bytes.saturating_add(incoming_bytes) <= byte_limit)
    }

    fn note_row_persisted(&mut self, id: MessageId, payload_bytes: usize) -> Option<usize> {
        let previous = self.deferred_payload_bytes_by_id.insert(id, payload_bytes);
        match previous {
            Some(previous) => {
                self.deferred_bytes = self
                    .deferred_bytes
                    .saturating_sub(previous)
                    .saturating_add(payload_bytes);
            }
            None => {
                self.deferred_rows = self.deferred_rows.saturating_add(1);
                self.deferred_bytes = self.deferred_bytes.saturating_add(payload_bytes);
            }
        }
        previous
    }
}

#[derive(Default)]
pub(crate) struct DeferredPeelAccountState {
    bytes: usize,
    counted: bool,
}

impl DeferredPeelAccountState {
    fn reconcile_group_bytes(&mut self, previous_bytes: usize, current_bytes: usize) {
        if self.counted {
            self.bytes = self
                .bytes
                .saturating_sub(previous_bytes)
                .saturating_add(current_bytes);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeferredPeelWorkStatus {
    Complete,
    Pending,
    BudgetExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdvanceConvergenceStatus {
    Settled,
    Pending,
    ForegroundBudgetExhausted,
}

#[derive(Clone, Copy, Debug)]
struct DeferredPeelWorkResult {
    status: DeferredPeelWorkStatus,
    progressed: usize,
}

impl DeferredPeelWorkResult {
    const fn complete() -> Self {
        Self {
            status: DeferredPeelWorkStatus::Complete,
            progressed: 0,
        }
    }
}

struct ForegroundPeelBudget {
    remaining_time: Duration,
    phase_started: Option<Instant>,
    budget_ms: u64,
    rows_remaining: usize,
}

impl ForegroundPeelBudget {
    fn new(budget_ms: u64, rows: usize) -> Self {
        Self {
            remaining_time: Duration::from_millis(budget_ms),
            phase_started: None,
            budget_ms,
            rows_remaining: rows,
        }
    }

    fn start_phase(&mut self) {
        debug_assert!(self.phase_started.is_none());
        self.phase_started = Some(Instant::now());
    }

    fn finish_phase(&mut self) {
        if let Some(started) = self.phase_started.take() {
            self.remaining_time = self.remaining_time.saturating_sub(started.elapsed());
        }
    }

    fn remaining(&self) -> Option<Duration> {
        let elapsed = self
            .phase_started
            .map_or(Duration::ZERO, |started| started.elapsed());
        let remaining = self.remaining_time.saturating_sub(elapsed);
        (!remaining.is_zero()).then_some(remaining)
    }

    fn exhausted(&self) -> bool {
        self.rows_remaining == 0 || self.remaining().is_none()
    }

    fn consume_row(&mut self) {
        self.rows_remaining = self.rows_remaining.saturating_sub(1);
    }
}

enum DeferredPeelExecution<'a> {
    Foreground(&'a mut ForegroundPeelBudget),
    Background,
}

impl DeferredPeelExecution<'_> {
    fn start_phase(&mut self) {
        if let Self::Foreground(budget) = self {
            budget.start_phase();
        }
    }

    fn finish_phase(&mut self) {
        if let Self::Foreground(budget) = self {
            budget.finish_phase();
        }
    }

    fn row_limit(&self) -> usize {
        match self {
            Self::Foreground(budget) => budget.rows_remaining,
            Self::Background => MAX_DEFERRED_ROWS_PER_SWEEP,
        }
    }

    fn exhausted(&self) -> bool {
        matches!(self, Self::Foreground(budget) if budget.exhausted())
    }

    fn consume_row(&mut self) {
        if let Self::Foreground(budget) = self {
            budget.consume_row();
        }
    }

    fn remaining(&self) -> Option<Duration> {
        match self {
            Self::Foreground(budget) => budget.remaining(),
            Self::Background => None,
        }
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
        self.last_ingest_left_object_unpersisted = false;
        // Durable dedup / own-echo check. Storage is consulted before the hot
        // cache so a restarted engine can classify replayed transport messages
        // the same way as a running process.
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
        // One fact, one place: the flag that suppresses this engine's own
        // seen-cache insertion is also what it reports to callers holding a
        // dedup index of their own.
        self.last_ingest_left_object_unpersisted = retryable_unpersisted;
        if !retryable_unpersisted && self.should_remember_ingested_message(&msg.id)? {
            // Successful group-message peel seams persist exact wrapper ids
            // with their canonical content admission before reaching this
            // epilogue. Keep only the bounded hot-process fallback here: doing
            // a broad durable write would let attacker-controlled malformed
            // wrappers churn the exceptional ingress-marker pool.
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

        let prepare_started = Instant::now();
        let result = self.do_send_ready(intent).await;
        self.engine_metrics.note_outbound_wire_prepare_ms(
            prepare_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        result
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
        // One record read serves this gate and the two terminal gates below.
        let group = self.stored_group_record(&group_id)?;
        if self.new_protocol_profile == cgka_traits::group::ProtocolProfile::Current
            && matches!(intent, SendIntent::Invite { .. })
        {
            // An Invite needs the record to read its profile; an unknown group
            // fails here with the storage error the direct read used to raise.
            let Some(group) = group.as_ref() else {
                return Err(EngineError::Storage(StorageError::NotFound));
            };
            if group.protocol_profile == cgka_traits::group::ProtocolProfile::Legacy {
                return Err(EngineError::InvalidTransition(
                    cgka_traits::engine_state::InvalidTransition {
                        from: "LegacyProfile",
                        to: "Invite",
                        reason: "strict cutover forbids adding members to legacy groups",
                    },
                ));
            }
        }
        // Terminal gate before queueing: a local copy marked removed (realized
        // self-eviction) must never accept or queue outbound work. Checked
        // again in `do_send_ready` so queued-intent drains for a copy removed
        // after queueing hit the same deterministic error.
        if group.as_ref().is_some_and(|group| group.removed) {
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
        if self.sync_unrecoverable_halt_from_record(&group_id, group.as_ref()) {
            // mdk#1177: typed, not `InvalidTransition`. A halted group is a
            // durable condition whose only exit is another member's repair
            // Welcome, so the host has something to tell the user and act on —
            // that is not an engine bug, which is what `InvalidTransition`
            // denotes.
            return Err(EngineError::GroupUnrecoverableRepairRequired { group_id });
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
        if !self.prepare_convergence_input_advance(group_id)? {
            return Ok(Vec::new());
        }

        let has_queued = self.has_queued_outbound_intents(group_id)?;
        let settled = if has_queued {
            self.advance_before_queued_outbound_intents(group_id, now_ms)
                .await?
        } else {
            self.advance_convergence_inputs_until_settled(group_id, now_ms)
                .await?
        };
        if !settled {
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
            // A regenerated intent the host has not yet confirmed or retired
            // is still the host's obligation: re-preparing it would publish
            // the same logical message twice (mdk#1472).
            if self.queued_outbound_intent_in_flight(group_id, &record.id) {
                continue;
            }
            if !reservation.permits(&record.intent) {
                continue;
            }
            if !reservation.is_available()
                && !self
                    .advance_before_queued_outbound_intents(group_id, now_ms)
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
            self.engine_metrics
                .note_queued_outbound_wait_ms(now_ms.saturating_sub(record.created_at_ms));
            let prepare_started = Instant::now();
            let prepared = self.do_send_ready(record.intent.clone()).await;
            self.engine_metrics.note_outbound_wire_prepare_ms(
                prepare_started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            );
            let result = match prepared {
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

    fn prepare_convergence_input_advance(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        // Advancing a seeded-but-unhydrated group promotes it first
        // (mdk#1161); a hydration failure quarantines it and the gate below
        // reports UnknownGroup.
        let _ = self.ensure_hydrated(group_id);
        // Quarantined groups vanish from every live surface; convergence and
        // queued-intent drains must not touch their state (mdk#364).
        self.ensure_group_live(group_id)?;
        // An advance can be invoked directly without session-open hydration.
        // Synchronize the durable halt before convergence or queued work can
        // run so restart never bypasses `Unrecoverable`.
        let group = self.stored_group_record(group_id)?;
        if self.sync_unrecoverable_halt_from_record(group_id, group.as_ref()) {
            return Ok(false);
        }
        // Terminal: a removed copy must never publish, and the removed-copy
        // gate in `do_send_ready` would turn every queued record into a
        // permanent drain error that the app retries forever. Discard the
        // queue and report nothing to drain. This is the defense-in-depth
        // side; the marker sites (realization, commit-apply seam, convergence
        // reorg) also purge at the moment the copy becomes removed.
        if group.is_some_and(|group| group.removed) {
            self.discard_queued_outbound_intents_for_removed_group(group_id)?;
            return Ok(false);
        }
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(false);
        }
        Ok(true)
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
        // Authenticated convergence and every row not yet tested under the
        // current complete peel-context fingerprint are safety-critical even
        // when older outbound work is already queued. The retry path skips
        // rows whose durable fingerprint is unchanged, so an existing queue
        // still outranks historical-only maintenance without broadening that
        // exemption to newly arrived or changed-context rows.
        let mut budget = ForegroundPeelBudget::new(
            self.foreground_deferred_peel_budget_ms,
            self.foreground_deferred_peel_rows,
        );
        match self
            .advance_convergence_inputs_with_execution(
                group_id,
                now_ms,
                DeferredPeelExecution::Foreground(&mut budget),
            )
            .await?
        {
            AdvanceConvergenceStatus::Settled => {}
            AdvanceConvergenceStatus::Pending
            | AdvanceConvergenceStatus::ForegroundBudgetExhausted => return Ok(true),
        }
        self.stage_due_self_remove_auto_commit(group_id, now_ms)
            .await
    }

    /// Settle authenticated input and give current-fingerprint deferred rows
    /// their bounded foreground opportunity before regenerating queued output.
    /// Rows already tested under the unchanged fingerprint are skipped, so
    /// historical-only maintenance remains behind the queue.
    async fn advance_before_queued_outbound_intents(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        let mut budget = ForegroundPeelBudget::new(
            self.foreground_deferred_peel_budget_ms,
            self.foreground_deferred_peel_rows,
        );
        Ok(matches!(
            self.advance_convergence_inputs_with_execution(
                group_id,
                now_ms,
                DeferredPeelExecution::Foreground(&mut budget),
            )
            .await?,
            AdvanceConvergenceStatus::Settled
        ))
    }

    /// Whether a durable queued intent was already regenerated into an
    /// artifact the host has not yet confirmed or retired. The association
    /// lives from regeneration until `confirm_regenerated_queued_intent`,
    /// `retry_regenerated_queued_intent`, or a publish rollback clears it.
    fn queued_outbound_intent_in_flight(&self, group_id: &GroupId, intent_id: &MessageId) -> bool {
        self.queued_intent_by_message
            .values()
            .chain(self.queued_intent_by_pending.values())
            .any(|(queued_group_id, queued_intent_id)| {
                queued_group_id == group_id && queued_intent_id == intent_id
            })
    }

    pub(crate) fn schedule_pending_convergence_group(&mut self, group_id: &GroupId) {
        self.pending_convergence_groups.insert(group_id.clone());
    }

    /// Read the durable queued intent a regenerated artifact carries. The
    /// association is non-destructive: it stays readable until the host
    /// confirms or retries the intent, so a later drain can see the intent
    /// is still in flight and must not regenerate it again (mdk#1472).
    pub fn regenerated_queued_intent_for_message(
        &self,
        message_id: &MessageId,
    ) -> Option<(GroupId, MessageId)> {
        self.queued_intent_by_message.get(message_id).cloned()
    }

    pub fn confirm_regenerated_queued_intent(
        &mut self,
        intent_id: &MessageId,
    ) -> Result<(), EngineError> {
        self.storage.delete_queued_outbound_intent(intent_id)?;
        self.queued_intent_by_message
            .retain(|_, (_, queued_intent_id)| queued_intent_id != intent_id);
        self.queued_intent_by_pending
            .retain(|_, (_, queued_intent_id)| queued_intent_id != intent_id);
        Ok(())
    }

    /// Re-arm a regenerated intent whose publication reached no endpoint.
    /// Clearing the in-flight association lets the next drain regenerate a
    /// fresh artifact; the durable intent row is untouched.
    pub fn retry_regenerated_queued_intent(&mut self, group_id: &GroupId, intent_id: &MessageId) {
        self.queued_intent_by_message
            .retain(|_, (_, queued_intent_id)| queued_intent_id != intent_id);
        self.queued_intent_by_pending
            .retain(|_, (_, queued_intent_id)| queued_intent_id != intent_id);
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
    pub async fn advance_convergence_inputs(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if !self.prepare_convergence_input_advance(group_id)? {
            return Ok(false);
        }
        let now_ms = self.convergence_now_ms();
        self.advance_convergence_inputs_until_settled(group_id, now_ms)
            .await
    }

    /// Drive stored OpenMLS inputs to stability at an explicit monotonic time.
    ///
    /// This lower-level form is used by deterministic harnesses. Hosts should
    /// normally call [`Self::advance_convergence_inputs`] so the engine owns
    /// the convergence clock.
    pub async fn advance_convergence_inputs_until_settled(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        Ok(matches!(
            self.advance_convergence_inputs_with_execution(
                group_id,
                now_ms,
                DeferredPeelExecution::Background,
            )
            .await?,
            AdvanceConvergenceStatus::Settled
        ))
    }

    async fn advance_convergence_inputs_with_execution(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
        mut execution: DeferredPeelExecution<'_>,
    ) -> Result<AdvanceConvergenceStatus, EngineError> {
        let record_outbound_phases = matches!(&execution, DeferredPeelExecution::Foreground(_));
        // Promote a seeded-but-unhydrated group before reading its stored
        // inputs (mdk#1161). A failed promotion quarantines the group and
        // MUST propagate — continuing would read convergence state for a
        // group validation just rejected and could report it settled.
        // Already-quarantined groups keep their pre-existing semantics
        // (`ensure_hydrated` no-ops; converge reports the blocked run).
        self.ensure_hydrated(group_id)?;
        for _ in 0..MAX_CONVERGENCE_REPROCESSING_PASSES {
            let contested_generation_active =
                self.storage.deferred_peel_generation(group_id)?.is_some();
            if self.has_unresolved_convergence_inputs(group_id)? && !contested_generation_active {
                let convergence_started = Instant::now();
                let result = self
                    .converge_stored_openmls_messages_with_time(
                        group_id,
                        crate::convergence_clock::ConvergenceTime {
                            monotonic_ms: now_ms,
                            wall_ms: self.convergence_now().wall_ms,
                        },
                    )
                    .map_err(|e| EngineError::Backend(format!("converge inputs: {e}")))?;
                if record_outbound_phases {
                    self.engine_metrics.note_outbound_required_convergence_ms(
                        convergence_started
                            .elapsed()
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                    );
                }
                if result.convergence_status != crate::canonicalization::ConvergenceStatus::Settled
                {
                    return Ok(AdvanceConvergenceStatus::Pending);
                }
                // A completed frozen batch grants one queued user intent before
                // an inbound-only follow-up pass. Retry one deferred-peel sweep
                // first so newly available canonical context is visible. Return
                // to the drain only when that durable slot actually exists.
                execution.start_phase();
                let peel = self
                    .retry_deferred_peels_with_execution(group_id, &mut execution)
                    .await;
                execution.finish_phase();
                let peel = peel?;
                if peel.status == DeferredPeelWorkStatus::BudgetExhausted {
                    return Ok(AdvanceConvergenceStatus::ForegroundBudgetExhausted);
                }
                let fairness_slot_available =
                    self.storage
                        .convergence_pass(group_id)?
                        .is_some_and(|pass| {
                            pass.phase == cgka_traits::ConvergencePassPhase::Completed
                                && pass.fairness_slot_available
                        });
                if fairness_slot_available && peel.status == DeferredPeelWorkStatus::Complete {
                    return Ok(AdvanceConvergenceStatus::Settled);
                }
                continue;
            }

            execution.start_phase();
            let peel = self
                .retry_deferred_peels_with_execution(group_id, &mut execution)
                .await;
            execution.finish_phase();
            let peel = peel?;
            match peel.status {
                DeferredPeelWorkStatus::BudgetExhausted => {
                    return Ok(AdvanceConvergenceStatus::ForegroundBudgetExhausted);
                }
                DeferredPeelWorkStatus::Pending => continue,
                DeferredPeelWorkStatus::Complete => {
                    if !self.has_unresolved_convergence_inputs(group_id)?
                        && self.storage.deferred_peel_generation(group_id)?.is_none()
                    {
                        return Ok(AdvanceConvergenceStatus::Settled);
                    }
                }
            }
        }

        Ok(AdvanceConvergenceStatus::Pending)
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
        // Indexed fast path: `any_gating_convergence_input` can only report a
        // gate when some retained row is in an outbound-gating state
        // (`ClassifiedConvergenceInput::can_gate_outbound`). This runs on
        // every send, so answer the common no-gating-work case with one
        // existence probe instead of listing and decoding the group's whole
        // retained window.
        if !self.storage.has_messages_in_states(
            group_id,
            &crate::convergence_input::OUTBOUND_GATING_STATES,
            EpochId(anchor),
        )? {
            return Ok(false);
        }
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

    fn note_foreground_deferred_phase(
        &mut self,
        started: Instant,
        budget_ms: Option<u64>,
        rows_attempted: usize,
        backlog: usize,
        outcome: crate::engine_metrics::DeferredPeelMetricOutcome,
    ) {
        if let Some(budget_ms) = budget_ms {
            self.engine_metrics.note_outbound_deferred_peel(
                started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                rows_attempted,
                backlog,
                outcome,
                Some(budget_ms),
            );
        }
    }

    /// Re-attempt retained `PeelDeferred` rows in a scheduler/background
    /// slice. Foreground outbound preflight uses the same lifecycle through
    /// [`Self::retry_deferred_peels_with_execution`] with the stricter
    /// 250 ms/four-attempt budget (mdk#1176).
    pub async fn retry_deferred_peels(&mut self, group_id: &GroupId) -> Result<usize, EngineError> {
        let mut execution = DeferredPeelExecution::Background;
        Ok(self
            .retry_deferred_peels_with_execution(group_id, &mut execution)
            .await?
            .progressed)
    }

    async fn retry_deferred_peels_with_execution(
        &mut self,
        group_id: &GroupId,
        execution: &mut DeferredPeelExecution<'_>,
    ) -> Result<DeferredPeelWorkResult, EngineError> {
        let sweep_started = Instant::now();
        self.engine_metrics.note_deferred_peel_sweep();
        let foreground_budget_ms = match execution {
            DeferredPeelExecution::Foreground(budget) => Some(budget.budget_ms),
            DeferredPeelExecution::Background => None,
        };
        // A quarantined group has no epoch_manager entry, so the Stable gate
        // below would fall through and re-ingest its retained rows against
        // the very state validation rejected (mdk#364). The rows replay
        // once repair clears the quarantine.
        if self.quarantined_reason(group_id).is_some() {
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                0,
                crate::engine_metrics::DeferredPeelMetricOutcome::Completed,
            );
            return Ok(DeferredPeelWorkResult::complete());
        }
        // A seeded-but-unhydrated group holds a provisional Stable entry, so
        // the gate below would fall through and re-ingest retained rows
        // against unvalidated state (mdk#1161). Skip; the sweep after
        // `ensure_hydrated` promotes the group picks the rows up.
        if self.unhydrated_groups.contains(group_id) {
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                0,
                crate::engine_metrics::DeferredPeelMetricOutcome::Completed,
            );
            return Ok(DeferredPeelWorkResult::complete());
        }
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                0,
                crate::engine_metrics::DeferredPeelMetricOutcome::Completed,
            );
            return Ok(DeferredPeelWorkResult::complete());
        }

        let now = self.convergence_now();
        // State-filtered listing: this sweep runs on every drain and the
        // backlog is usually empty, so let the backend's index find the
        // `PeelDeferred` rows instead of decoding the whole retained window.
        let mut deferred = self.storage.list_messages_in_states(
            group_id,
            &[MessageState::PeelDeferred],
            EpochId(0),
        )?;
        if execution.exhausted() {
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                deferred.len(),
                crate::engine_metrics::DeferredPeelMetricOutcome::BudgetExhausted,
            );
            return Ok(DeferredPeelWorkResult {
                status: DeferredPeelWorkStatus::BudgetExhausted,
                progressed: 0,
            });
        }
        let row_limit = execution.row_limit();
        if self.normalize_deferred_peel_lifecycles(&mut deferred, now, row_limit)? {
            // Legacy initialization and restart rebasing are durable writes,
            // so migrate them in the same bounded slices as peel attempts.
            // The pending edge keeps the scheduler advancing the backlog.
            self.schedule_pending_convergence_group(group_id);
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                deferred.len(),
                crate::engine_metrics::DeferredPeelMetricOutcome::NormalizationPending,
            );
            return Ok(DeferredPeelWorkResult {
                status: DeferredPeelWorkStatus::Pending,
                progressed: 0,
            });
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
            .take(row_limit)
            .cloned()
            .collect::<Vec<_>>();
        if !due.is_empty() {
            let mut released = 0usize;
            for record in &due {
                if execution.exhausted() {
                    break;
                }
                execution.consume_row();
                self.release_deferred_peel_row(
                    record,
                    InboundResourceLimit::TransportDeferredResidenceBudget,
                    crate::message_disposition::MessageDisposition::ResidenceBudgetRefused,
                )?;
                released += 1;
            }
            if deferred.len() > released {
                self.schedule_pending_convergence_group(group_id);
            }
            let status = if deferred.len() > released {
                if matches!(execution, DeferredPeelExecution::Foreground(_)) {
                    DeferredPeelWorkStatus::BudgetExhausted
                } else {
                    DeferredPeelWorkStatus::Pending
                }
            } else {
                DeferredPeelWorkStatus::Complete
            };
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                released,
                deferred.len(),
                if status == DeferredPeelWorkStatus::BudgetExhausted {
                    crate::engine_metrics::DeferredPeelMetricOutcome::BudgetExhausted
                } else {
                    crate::engine_metrics::DeferredPeelMetricOutcome::Completed
                },
            );
            return Ok(DeferredPeelWorkResult {
                status,
                progressed: released,
            });
        }

        // The full row list is in hand: refresh the flood-cap count, then stop
        // before the context work when there is nothing to sweep. Describing
        // this group's peel context reads storage, so an empty backlog must not
        // pay for it on every drain.
        let total = deferred.len();
        self.refresh_peel_deferred_group_usage(group_id, &deferred);
        if total == 0 {
            self.invalidate_deferred_peel_candidate_cache(group_id);
            if self.storage.deferred_peel_generation(group_id)?.is_some() {
                self.storage.delete_deferred_peel_generation(group_id)?;
                self.converge_stored_openmls_messages_with_time(group_id, now)
                    .map_err(|error| {
                        EngineError::Backend(format!("converge completed peel generation: {error}"))
                    })?;
            }
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                0,
                crate::engine_metrics::DeferredPeelMetricOutcome::Completed,
            );
            return Ok(DeferredPeelWorkResult::complete());
        }

        let fingerprint = self.deferred_peel_context_fingerprint(group_id)?;
        let unattempted = deferred
            .iter()
            .filter(|record| {
                record
                    .deferred_peel
                    .as_ref()
                    .is_none_or(|lifecycle| lifecycle.last_context_fingerprint != Some(fingerprint))
            })
            .cloned()
            .collect::<Vec<_>>();
        if unattempted.is_empty() {
            self.invalidate_deferred_peel_candidate_cache(group_id);
            if self.storage.deferred_peel_generation(group_id)?.is_some() {
                self.storage.delete_deferred_peel_generation(group_id)?;
                self.converge_stored_openmls_messages_with_time(group_id, now)
                    .map_err(|error| {
                        EngineError::Backend(format!("converge swept batch: {error}"))
                    })?;
            }
            tracing::debug!(
                target: "cgka_engine::message_processor",
                method = "retry_deferred_peels",
                "skipping deferred-peel sweep: peel context unchanged"
            );
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                total,
                crate::engine_metrics::DeferredPeelMetricOutcome::Unchanged,
            );
            return Ok(DeferredPeelWorkResult::complete());
        }

        let retry_budget = self.deferred_peel_retry_budget;
        self.deferred_peel
            .entry(group_id.clone())
            .or_default()
            .sweep_count += 1;

        if execution.exhausted() {
            self.note_foreground_deferred_phase(
                sweep_started,
                foreground_budget_ms,
                0,
                total,
                crate::engine_metrics::DeferredPeelMetricOutcome::BudgetExhausted,
            );
            return Ok(DeferredPeelWorkResult {
                status: DeferredPeelWorkStatus::BudgetExhausted,
                progressed: 0,
            });
        }

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
        let durable_generation_fingerprint = self
            .storage
            .deferred_peel_generation(group_id)?
            .map(|generation| generation.context_fingerprint);
        let cached = self
            .deferred_peel
            .get(group_id)
            .and_then(|state| state.candidate_cache.as_ref())
            .filter(|cached| {
                cached.context_fingerprint == fingerprint
                    && cached.durable_generation_fingerprint == durable_generation_fingerprint
            })
            .map(|cached| Arc::clone(&cached.peel));
        let (peel, candidate_cache_hit) = if let Some(cached) = cached {
            self.engine_metrics.note_deferred_peel_candidate_cache_hit();
            (cached, true)
        } else {
            self.invalidate_deferred_peel_candidate_cache(group_id);
            self.engine_metrics
                .note_deferred_peel_candidate_cache_miss();
            let candidate_enumeration_started = Instant::now();
            let enumerated = match self.candidate_branch_peel(group_id) {
                Ok(peel) => peel,
                Err(failure) => {
                    self.engine_metrics
                        .note_deferred_peel_candidate_enumeration(
                            candidate_enumeration_started
                                .elapsed()
                                .as_millis()
                                .try_into()
                                .unwrap_or(u64::MAX),
                            std::iter::empty(),
                            failure.replay_probe_count,
                        );
                    self.note_foreground_deferred_phase(
                        sweep_started,
                        foreground_budget_ms,
                        0,
                        total,
                        crate::engine_metrics::DeferredPeelMetricOutcome::Error,
                    );
                    return Err(failure.error);
                }
            };
            let candidate_enumeration_ms = candidate_enumeration_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            self.engine_metrics
                .note_deferred_peel_candidate_enumeration(
                    candidate_enumeration_ms,
                    enumerated.contexts.iter().map(|context| context.depth),
                    enumerated.replay_probe_count,
                );
            tracing::info!(
                target: "cgka_engine::message_processor",
                method = "candidate_branch_peel",
                candidate_contexts = enumerated.contexts.len() as u64,
                max_candidate_context_depth = enumerated
                    .contexts
                    .iter()
                    .map(|context| context.depth)
                    .max()
                    .unwrap_or(0),
                replay_probes = enumerated.replay_probe_count,
                candidate_enumeration_ms,
                "deferred-peel candidate enumeration"
            );
            if enumerated.contested {
                self.storage
                    .put_deferred_peel_generation(&DeferredPeelGeneration {
                        group_id: group_id.clone(),
                        context_fingerprint: fingerprint,
                    })?;
            }
            let cached_generation_fingerprint = if enumerated.contested {
                Some(fingerprint)
            } else {
                durable_generation_fingerprint
            };
            let enumerated = Arc::new(enumerated);
            self.deferred_peel
                .entry(group_id.clone())
                .or_default()
                .candidate_cache = Some(DeferredPeelCandidateCacheEntry {
                context_fingerprint: fingerprint,
                durable_generation_fingerprint: cached_generation_fingerprint,
                peel: Arc::clone(&enumerated),
            });
            (enumerated, false)
        };
        tracing::debug!(
            target: "cgka_engine::message_processor",
            method = "candidate_branch_peel_cache",
            cache_hit = candidate_cache_hit,
            "deferred-peel candidate cache lookup"
        );
        let sweep = crate::message_processor::ingest::DeferredPeelSweep::over_branches(&peel);

        let mut progressed = 0usize;
        let mut terminal = 0usize;
        let mut attempted = 0usize;
        let mut timed_out = false;
        let mut contexts_invalidated = false;
        for record in unattempted.into_iter().take(row_limit) {
            if execution.exhausted() {
                timed_out = true;
                break;
            }
            // A row can itself advance or replace canonical state. Those
            // transition sites synchronously invalidate the map entry; do not
            // keep offering the slice's local Arc to later rows after that.
            // Their lifecycle remains untouched for the next fingerprint.
            if !self
                .deferred_peel
                .get(group_id)
                .and_then(|state| state.candidate_cache.as_ref())
                .is_some_and(|cached| Arc::ptr_eq(&cached.peel, &peel))
            {
                contexts_invalidated = true;
                break;
            }
            let lifecycle = record
                .deferred_peel
                .as_ref()
                .expect("deferred lifecycle normalized before sweep");
            if lifecycle.distinct_context_attempts >= retry_budget {
                execution.consume_row();
                attempted += 1;
                self.release_deferred_peel_row(
                    &record,
                    InboundResourceLimit::TransportDeferredRetryBudget,
                    crate::message_disposition::MessageDisposition::RetryBudgetRefused,
                )?;
                terminal += 1;
                continue;
            }
            execution.consume_row();
            attempted += 1;
            let reingest = self.reingest_deferred_peel_row(group_id, &record, sweep);
            let result = if let Some(remaining) = execution.remaining() {
                match tokio::time::timeout(remaining, reingest).await {
                    Ok(result) => result,
                    Err(_) => {
                        timed_out = true;
                        break;
                    }
                }
            } else {
                reingest.await
            };
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    self.note_foreground_deferred_phase(
                        sweep_started,
                        foreground_budget_ms,
                        attempted,
                        total,
                        crate::engine_metrics::DeferredPeelMetricOutcome::Error,
                    );
                    return Err(error);
                }
            };
            if result {
                progressed += 1;
                continue;
            }

            // A definitive no-progress result consumes this distinct context.
            // Timeout/cancellation never reaches here, so it leaves the row
            // unmarked and restart-safe.
            if let Ok(mut retained) = self.storage.get_message(&record.id)
                && retained.state == MessageState::PeelDeferred
            {
                let lifecycle = retained
                    .deferred_peel
                    .as_mut()
                    .expect("deferred lifecycle remains normalized");
                lifecycle.distinct_context_attempts =
                    lifecycle.distinct_context_attempts.saturating_add(1);
                lifecycle.last_context_fingerprint = Some(fingerprint);
                lifecycle.wall_high_water_ms = lifecycle.wall_high_water_ms.max(now.wall_ms);
                self.storage.put_message(&retained)?;
            }
        }

        let final_fingerprint = self.deferred_peel_context_fingerprint(group_id)?;
        if final_fingerprint != fingerprint {
            self.invalidate_deferred_peel_candidate_cache(group_id);
        }
        let remaining = self
            .storage
            .list_messages_in_states(group_id, &[MessageState::PeelDeferred], EpochId(0))?
            .into_iter()
            .filter(|record| {
                record.deferred_peel.as_ref().is_none_or(|lifecycle| {
                    lifecycle.last_context_fingerprint != Some(final_fingerprint)
                })
            })
            .count();
        if let Some(mut generation) = self.storage.deferred_peel_generation(group_id)? {
            if generation.context_fingerprint != final_fingerprint {
                generation.context_fingerprint = final_fingerprint;
                self.storage.put_deferred_peel_generation(&generation)?;
            }
            if remaining == 0 {
                // Clearing before the drain is restart-safe: all recovered
                // content rows are durable, so a crash in between simply lets
                // the next normal convergence wake process the complete set.
                self.storage.delete_deferred_peel_generation(group_id)?;
                self.invalidate_deferred_peel_candidate_cache(group_id);
                self.converge_stored_openmls_messages_with_time(group_id, now)
                    .map_err(|error| {
                        EngineError::Backend(format!("converge swept batch: {error}"))
                    })?;
            }
        }

        let incomplete = timed_out || remaining > 0;
        if incomplete {
            self.schedule_pending_convergence_group(group_id);
        }
        let status = if incomplete {
            if matches!(execution, DeferredPeelExecution::Foreground(_)) {
                DeferredPeelWorkStatus::BudgetExhausted
            } else {
                DeferredPeelWorkStatus::Pending
            }
        } else {
            DeferredPeelWorkStatus::Complete
        };
        let duration_ms = sweep_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        self.note_foreground_deferred_phase(
            sweep_started,
            foreground_budget_ms,
            attempted,
            total,
            if status == DeferredPeelWorkStatus::BudgetExhausted {
                crate::engine_metrics::DeferredPeelMetricOutcome::BudgetExhausted
            } else {
                crate::engine_metrics::DeferredPeelMetricOutcome::Completed
            },
        );
        let queue_depth = self
            .deferred_peel
            .get(group_id)
            .map_or(0, |state| state.deferred_rows) as u64;
        tracing::info!(
            target: "cgka_engine::message_processor",
            method = "retry_deferred_peels",
            rows_attempted = attempted as u64,
            backlog = total as u64,
            progressed = progressed as u64,
            terminal = terminal as u64,
            contested = peel.contested,
            branch_contexts = peel.contexts.len() as u64,
            candidate_cache_hit,
            queue_depth,
            sweep_duration_ms = duration_ms,
            budget_exhausted = status == DeferredPeelWorkStatus::BudgetExhausted,
            contexts_invalidated,
            "deferred-peel retry sweep"
        );
        Ok(DeferredPeelWorkResult { status, progressed })
    }

    /// What the engine can soundly claim about why a transport-deferred object
    /// is unreadable.
    ///
    /// This is a claim about the GROUP, never about the message. At the
    /// deferral point the object failed to decrypt under the live context,
    /// every retained snapshot, and every candidate branch a sweep had
    /// materialized, so nothing observable separates one unreadable object
    /// from another — the per-message discriminator the success path derives
    /// from `recovered_from_candidate_branch` simply does not exist here.
    /// What remains sayable is the shape of the stored commit graph, and that
    /// is the fact deciding which recovery can help: a fork whose rival commit
    /// is already retained cannot be fixed by fetching more relay history,
    /// while a gap whose commit never arrived can — and the second case is
    /// indistinguishable from no fork at all, which is precisely why the
    /// uncontested answer is the one that admits a backfill.
    ///
    /// Uses the sweep's own replay-free contested predicate over the same
    /// retained-anchor window branch enumeration uses, so this label and the
    /// branch work it describes cannot disagree.
    ///
    /// Deliberately unmemoized. A cached verdict would have to be validated
    /// against `deferred_peel_context_fingerprint` to be trustworthy — the
    /// candidate cache beside it is safe precisely because it is self-validating
    /// that way — and that fingerprint folds `stored_convergence_commit_digests`,
    /// which is the same full stored-message scan this probe is. So a correct
    /// cache costs what it saves, while an uncorroborated one buys speed with
    /// exactly the wrong error: a stale verdict here reads `Uncontested` on a
    /// group that has since forked, which is the inversion this whole
    /// discriminator exists to prevent.
    ///
    /// The scan is therefore paid per deferral, and bounded by where it sits.
    /// It runs only after the per-group retained-row cap has admitted the row
    /// (`has_peel_deferred_capacity`), so a flood of attacker-minted
    /// undecryptable input is answered `ResourceRefused` without ever reaching
    /// here; and it runs on the seam that already pays a durable message write
    /// plus a forensic audit write for the same object.
    pub(crate) fn deferral_lineage(
        &mut self,
        group_id: &GroupId,
    ) -> Result<DeferralLineage, EngineError> {
        let group = self.storage.get_group(group_id)?;
        let policy = self
            .convergence_policy_for_group_ungated(group_id)
            .map_err(|error| EngineError::Backend(format!("load convergence policy: {error}")))?;
        let floor = group
            .epoch
            .0
            .saturating_sub(policy.convergence.max_rewind_commits);
        let contested = crate::openmls_projection::commit_edges_are_contested(
            self.stored_convergence_commit_edges(group_id)?
                .into_iter()
                .filter(|(source_epoch, _)| *source_epoch >= floor),
        );
        Ok(if contested {
            DeferralLineage::ContestedFork
        } else {
            DeferralLineage::Uncontested
        })
    }

    /// Classify this group's convergence graph as contested or not, and
    /// materialize the candidate branches it offers.
    fn candidate_branch_peel(
        &self,
        group_id: &GroupId,
    ) -> Result<
        crate::openmls_projection::CandidateBranchPeel,
        DeferredPeelCandidateEnumerationFailure,
    > {
        let group = self.storage.get_group(group_id).map_err(|error| {
            DeferredPeelCandidateEnumerationFailure {
                error: error.into(),
                replay_probe_count: 0,
            }
        })?;
        let policy = self
            .convergence_policy_for_group_ungated(group_id)
            .map_err(|error| DeferredPeelCandidateEnumerationFailure {
                error: EngineError::Backend(format!("load convergence policy: {error}")),
                replay_probe_count: 0,
            })?;
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
        .map_err(|failure| DeferredPeelCandidateEnumerationFailure {
            error: EngineError::Backend(format!("candidate branch peel: {}", failure.error)),
            replay_probe_count: failure.replay_probe_count,
        })
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
            // Still unreadable: the row keeps its place in the retry lifecycle
            // and the caller charges its budget. The verdict's `lineage` is
            // dropped on purpose. There is exactly one lineage site
            // (`Self::deferral_lineage`, reached from the single deferral return
            // in `ingest_group_message_from_sweep`), and it answers about the
            // GROUP's stored commit graph rather than about this row — so a
            // sweep can only ever restate what live ingest already reported for
            // this group, over rows the app's stall detector counted when they
            // first arrived. Routing it out would re-count that evidence, not
            // sharpen it.
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
                self.note_peel_deferred_row_retired(record);
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
                self.note_peel_deferred_row_retired(record);
                Ok(true)
            }
            Err(EngineError::ForkedEpoch {
                group_id: forked_group_id,
                last_stable,
                conflicting_epoch,
            }) => {
                self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                self.note_peel_deferred_row_retired(record);
                Err(EngineError::ForkedEpoch {
                    group_id: forked_group_id,
                    last_stable,
                    conflicting_epoch,
                })
            }
            Err(e) => {
                self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                self.note_peel_deferred_row_retired(record);
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
        let normalization_pending = self.normalize_deferred_peel_lifecycles(
            &mut deferred,
            now,
            MAX_DEFERRED_ROWS_PER_SWEEP,
        )?;
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
        &mut self,
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
        let digests: BTreeSet<[u8; 32]> = self
            .stored_convergence_commit_edges(group_id)?
            .into_iter()
            .map(|(_source_epoch, digest)| digest)
            .collect();
        for digest in digests {
            hasher.update(digest);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }

    /// `(source_epoch, digest)` of the stored commits that can contribute to
    /// this group's convergence graph, in listing order.
    ///
    /// The fingerprint gate computes this set at least twice per sweep and
    /// the deferral-lineage probe once per deferred message, so a row's
    /// decode + TLS parse + digest is remembered in
    /// `DeferredPeelGroupState::commit_digest_memo` and paid once per stored
    /// payload version instead of once per computation. State membership is
    /// re-read from the fresh listing every call, and each reuse revalidates
    /// the payload hash; only the payload verdict is memoized.
    fn stored_convergence_commit_edges(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Vec<CommitEdge>, EngineError> {
        let records = self.storage.list_messages_in_states(
            group_id,
            &crate::openmls_projection::OPENMLS_GRAPH_INPUT_STATES,
            EpochId(0),
        )?;
        let mut memo = std::mem::take(
            &mut self
                .deferred_peel
                .entry(group_id.clone())
                .or_default()
                .commit_digest_memo,
        );
        let mut next_memo = HashMap::with_capacity(records.len());
        let mut edges = Vec::new();
        for record in records {
            // The memo entry is valid only for the payload bytes it was
            // computed from: a same-id row can be overwritten under a
            // different payload variant (RawTransport re-persisted as
            // OpenMlsWire, #369), which must re-classify.
            let payload_hash: [u8; 32] = Sha256::digest(&record.payload).into();
            let verdict = match memo.remove(&record.id) {
                Some((memo_hash, verdict)) if memo_hash == payload_hash => verdict,
                _ => decode_openmls_wire_projection(&record.payload)
                    .filter(|(_message, projection)| {
                        projection.kind == crate::openmls_projection::OpenMlsContentKind::Commit
                    })
                    .and_then(|(_message, projection)| {
                        Some((projection.source_epoch?, projection.message_digest))
                    }),
            };
            if let Some(edge) = verdict {
                edges.push(edge);
            }
            next_memo.insert(record.id, (payload_hash, verdict));
        }
        self.deferred_peel
            .entry(group_id.clone())
            .or_default()
            .commit_digest_memo = next_memo;
        Ok(edges)
    }

    /// Reconstruct exact deferred-peel usage across this account on the first
    /// capacity-sensitive ingest. State-filtered reads avoid decoding unrelated
    /// history, and the result is maintained incrementally for the rest of the
    /// engine incarnation.
    fn ensure_peel_deferred_usage_initialized(&mut self) -> Result<(), EngineError> {
        if self.deferred_peel_account.counted {
            return Ok(());
        }

        let mut account_bytes = 0_usize;
        let mut peak_group_rows = 0_usize;
        let mut peak_group_bytes = 0_usize;
        for group_id in self.storage.list_groups()? {
            let records = self.storage.list_messages_in_states(
                &group_id,
                &[MessageState::PeelDeferred],
                EpochId(0),
            )?;
            let rows = records.len();
            let bytes = records.iter().fold(0_usize, |sum, record| {
                sum.saturating_add(record.payload.len())
            });
            let state = self.deferred_peel.entry(group_id).or_default();
            state.deferred_rows = rows;
            state.deferred_bytes = bytes;
            state.deferred_payload_bytes_by_id = records
                .into_iter()
                .map(|record| {
                    let payload_bytes = record.payload.len();
                    (record.id, payload_bytes)
                })
                .collect();
            account_bytes = account_bytes.saturating_add(bytes);
            peak_group_rows = peak_group_rows.max(rows);
            peak_group_bytes = peak_group_bytes.max(bytes);
        }
        self.deferred_peel_account.bytes = account_bytes;
        self.deferred_peel_account.counted = true;
        self.engine_metrics.note_deferred_peel_usage(
            peak_group_rows,
            peak_group_bytes,
            account_bytes,
        );
        Ok(())
    }

    /// Refresh one group's cached usage from a durable row enumeration. This
    /// also reconciles the account total when it has already been initialized.
    fn refresh_peel_deferred_group_usage(&mut self, group_id: &GroupId, records: &[MessageRecord]) {
        let rows = records.len();
        let bytes = records.iter().fold(0_usize, |sum, record| {
            sum.saturating_add(record.payload.len())
        });
        let state = self.deferred_peel.entry(group_id.clone()).or_default();
        let previous_bytes = state.deferred_bytes;
        state.deferred_rows = rows;
        state.deferred_bytes = bytes;
        state.deferred_payload_bytes_by_id = records
            .iter()
            .map(|record| (record.id.clone(), record.payload.len()))
            .collect();
        // Incremental deferral already charges a group that started retaining
        // rows after the account-wide reconstruction. Always reconcile the
        // cached contribution as a delta; treating that group as previously
        // uncounted would add its bytes a second time on its first sweep.
        self.deferred_peel_account
            .reconcile_group_bytes(previous_bytes, bytes);
        self.engine_metrics
            .note_deferred_peel_usage(rows, bytes, self.deferred_peel_account.bytes);
    }

    /// Check row, per-group byte, and account-wide byte capacity for one
    /// `PeelDeferred` write. `previous_payload_bytes` is present when this is a
    /// replacement of an already-retained id, in which case only growth is
    /// charged and no row slot is consumed.
    pub(crate) fn has_peel_deferred_capacity(
        &mut self,
        group_id: &GroupId,
        previous_payload_bytes: Option<usize>,
        incoming_payload_bytes: usize,
    ) -> Result<bool, EngineError> {
        self.ensure_peel_deferred_usage_initialized()?;
        let incoming_rows = usize::from(previous_payload_bytes.is_none());
        let additional_bytes =
            incoming_payload_bytes.saturating_sub(previous_payload_bytes.unwrap_or_default());
        let state = self.deferred_peel.entry(group_id.clone()).or_default();
        let group_has_capacity = state.has_capacity(
            incoming_rows,
            additional_bytes,
            self.deferred_peel_row_limit,
            self.deferred_peel_group_byte_limit,
        );
        let account_has_capacity = additional_bytes == 0
            || self
                .deferred_peel_account
                .bytes
                .saturating_add(additional_bytes)
                <= self.deferred_peel_account_byte_limit;
        let refusal = if incoming_rows > 0
            && state.deferred_rows.saturating_add(incoming_rows) > self.deferred_peel_row_limit
        {
            Some(DeferredPeelCapacityResource::RowsPerGroup)
        } else if additional_bytes > 0
            && state.deferred_bytes.saturating_add(additional_bytes)
                > self.deferred_peel_group_byte_limit
        {
            Some(DeferredPeelCapacityResource::BytesPerGroup)
        } else if !account_has_capacity {
            Some(DeferredPeelCapacityResource::BytesPerAccount)
        } else {
            None
        };
        if let Some(resource) = refusal {
            self.engine_metrics
                .note_deferred_peel_capacity_refusal(resource);
        }
        Ok(group_has_capacity && account_has_capacity)
    }

    /// Prepare the exact bytes that admission measures and persistence writes.
    /// Encoding bounds are a local retention limit, not an internal drain
    /// failure, so callers translate codec failure to the typed capacity
    /// refusal path.
    pub(crate) fn prepare_deferred_peel_payload(
        &self,
        msg: &TransportMessage,
    ) -> Result<PreparedDeferredPeelPayload, StoredMessagePayloadCodecError> {
        let previous_payload_bytes = self
            .storage
            .get_message(&msg.id)
            .ok()
            .filter(|record| record.state == MessageState::PeelDeferred)
            .map(|record| record.payload.len());
        let encoded_payload = StoredMessagePayload::raw_transport(msg.clone()).encode()?;
        Ok(PreparedDeferredPeelPayload {
            previous_payload_bytes,
            encoded_payload,
        })
    }

    pub(crate) fn peel_deferred_capacity_refused(
        &mut self,
        group_id: &GroupId,
        message_id: &MessageId,
    ) -> IngestOutcome {
        self.retryable_unpersisted_ingest_id = Some(message_id.clone());
        if self.should_audit_peel_deferred_cap_rejection(group_id) {
            self.audit_group(
                group_id,
                marmot_forensics::AuditEventKind::Rejection {
                    msg_id: hex::encode(message_id.as_slice()),
                    reason: crate::message_disposition::MessageDisposition::DeferredCapacityRefused
                        .tag()
                        .to_string(),
                },
            );
        }
        IngestOutcome::ResourceRefused {
            group_id: group_id.clone(),
            resource: InboundResourceLimit::TransportDeferredCapacity,
        }
    }

    pub(crate) fn note_peel_deferred_row_persisted(
        &mut self,
        group_id: &GroupId,
        message_id: &MessageId,
        payload_bytes: usize,
    ) {
        let (group_rows, group_bytes) = {
            let state = self.deferred_peel.entry(group_id.clone()).or_default();
            match state.note_row_persisted(message_id.clone(), payload_bytes) {
                Some(previous) => {
                    if self.deferred_peel_account.counted {
                        self.deferred_peel_account.bytes = self
                            .deferred_peel_account
                            .bytes
                            .saturating_sub(previous)
                            .saturating_add(payload_bytes);
                    }
                }
                None => {
                    if self.deferred_peel_account.counted {
                        self.deferred_peel_account.bytes = self
                            .deferred_peel_account
                            .bytes
                            .saturating_add(payload_bytes);
                    }
                }
            }
            (state.deferred_rows, state.deferred_bytes)
        };
        self.engine_metrics.note_deferred_peel_usage(
            group_rows,
            group_bytes,
            self.deferred_peel_account.bytes,
        );
    }

    /// Drop exporter-bearing candidate contexts for one group. The aggregate
    /// metric deliberately records only that stale work was discarded; the
    /// group, fingerprint, generation, and branch identities never leave
    /// engine memory.
    pub(crate) fn invalidate_deferred_peel_candidate_cache(&mut self, group_id: &GroupId) {
        let invalidated = self
            .deferred_peel
            .get_mut(group_id)
            .is_some_and(|state| state.candidate_cache.take().is_some());
        if invalidated {
            self.engine_metrics
                .note_deferred_peel_candidate_cache_invalidation();
            tracing::debug!(
                target: "cgka_engine::message_processor",
                method = "invalidate_deferred_peel_candidate_cache",
                "invalidated deferred-peel candidate cache"
            );
        }
    }

    /// Bookkeeping for a row leaving `PeelDeferred` (applied, reclassified,
    /// invalidated, or terminally failed): release its flood-cap slot and its
    /// attempt-tracking entry. Once the backlog drops back below the cap, the
    /// cap-rejection audit re-arms so a fresh cap-full episode is recorded
    /// once more.
    pub(crate) fn note_peel_deferred_row_retired(&mut self, record: &MessageRecord) {
        let account_was_full = self.deferred_peel_account.counted
            && self.deferred_peel_account.bytes >= self.deferred_peel_account_byte_limit;
        let local_reopened = if let Some(state) = self.deferred_peel.get_mut(&record.group_id) {
            let Some(payload_bytes) = state.deferred_payload_bytes_by_id.remove(&record.id) else {
                return;
            };
            state.deferred_rows = state.deferred_rows.saturating_sub(1);
            state.deferred_bytes = state.deferred_bytes.saturating_sub(payload_bytes);
            if self.deferred_peel_account.counted {
                self.deferred_peel_account.bytes = self
                    .deferred_peel_account
                    .bytes
                    .saturating_sub(payload_bytes);
            }
            state.deferred_rows < self.deferred_peel_row_limit
                && state.deferred_bytes < self.deferred_peel_group_byte_limit
                && self.deferred_peel_account.bytes < self.deferred_peel_account_byte_limit
        } else {
            false
        };
        let account_reopened = account_was_full
            && self.deferred_peel_account.bytes < self.deferred_peel_account_byte_limit;
        if account_reopened {
            // The account limit is shared by every group. Releasing bytes in
            // one group starts a fresh capacity episode for any other group
            // that was previously refused while the aggregate was full.
            for state in self.deferred_peel.values_mut() {
                state.cap_rejection_audited = false;
            }
        } else if local_reopened && let Some(state) = self.deferred_peel.get_mut(&record.group_id) {
            state.cap_rejection_audited = false;
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
        self.invalidate_deferred_peel_candidate_cache(group_id);
        self.storage.delete_deferred_peel_generation(group_id)?;
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
        let queue_started = Instant::now();
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
        let result = SendResult::Queued {
            group_id,
            intent_id,
        };
        self.engine_metrics.note_outbound_queue_accept_ms(
            queue_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        Ok(result)
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
        self.audit_group(
            group_id,
            crate::audit_helpers::group_state_changed_event(
                epoch,
                actor.as_ref(),
                &change,
                origin_commit_id.as_ref(),
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
        // Only states the loop below can act on; the storage backend skips
        // fetching and decoding terminal/record-only rows entirely, which
        // keeps a re-join from re-parsing the group's whole message history.
        let records = self.storage.list_messages_in_states(
            group_id,
            &[
                MessageState::Created,
                MessageState::Retryable,
                MessageState::PeelDeferred,
            ],
            EpochId(0),
        )?;
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
                        self.note_peel_deferred_row_retired(&record);
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
                        self.note_peel_deferred_row_retired(&record);
                    }
                }
                Err(EngineError::ForkedEpoch {
                    group_id: forked_group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    if was_peel_deferred {
                        self.note_peel_deferred_row_retired(&record);
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
                        self.note_peel_deferred_row_retired(&record);
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
        let mut state = DeferredPeelGroupState::default();

        assert!(state.has_capacity(1, 10, 2, 20));
        assert_eq!(
            state.deferred_rows, 0,
            "a failed write must consume no slot"
        );

        state.note_row_persisted(MessageId::new(vec![1]), 10);
        assert_eq!(state.deferred_rows, 1);
        assert_eq!(state.deferred_bytes, 10);
        assert!(
            state.has_capacity(0, 0, 0, 0),
            "same-size exact-id retries stay eligible after a limit is lowered"
        );
        assert!(!state.has_capacity(0, 1, 0, 0));
    }

    #[test]
    fn first_sweep_of_later_deferring_group_does_not_double_count_account_bytes() {
        let group_a_bytes = 100;
        let group_b_bytes = 25;
        let mut account = DeferredPeelAccountState {
            bytes: group_a_bytes,
            counted: true,
        };

        // Account reconstruction happened while only group A was deferring.
        // Group B starts deferring later and is charged incrementally.
        account.bytes = account.bytes.saturating_add(group_b_bytes);

        // Its first sweep observes the same durable bytes. Reconciliation is
        // replacement, not another addition.
        account.reconcile_group_bytes(group_b_bytes, group_b_bytes);
        assert_eq!(account.bytes, group_a_bytes + group_b_bytes);
    }
}
