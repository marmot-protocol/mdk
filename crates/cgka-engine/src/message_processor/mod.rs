//! Inbound ingest and outbound send routing for [`Engine`].
//!
//! Inbound messages are peeled, classified, stored, and either applied or
//! buffered for convergence. Outbound intents are checked against local epoch
//! state and unresolved convergence inputs before any OpenMLS mutation.
//!
//! Classifiable stale ingest cases return
//! `Ok(IngestOutcome::Stale { .. })` with a typed `StaleReason`. `Err` is
//! reserved for storage, peeler, serialization, and OpenMLS failures.

mod ingest;
mod send;
mod store;

pub(crate) use ingest::avatar_component_snapshot;
pub(crate) use send::merge_capabilities;

use crate::engine::{Engine, ScheduledSelfRemoveAutoCommit};
use crate::openmls_projection::{OpenMlsContentKind, project_mls_message};
use cgka_traits::engine::{GroupEvent, GroupStateChange, SendIntent, SendResult};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::storage::{QueuedOutboundIntent, StorageError, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};

const MAX_CONVERGENCE_REPROCESSING_PASSES: usize = 16;
const SELF_REMOVE_AUTO_COMMIT_JITTER_MIN_MS: u64 = 10;
const SELF_REMOVE_AUTO_COMMIT_JITTER_SPAN_MS: u64 = 40;

/// Retry budget for a `PeelDeferred` row (mdk#339). Each unit is one
/// actual re-peel attempt under a *changed* peel context (the fingerprint
/// gate skips unchanged contexts entirely), so a legitimate future-epoch
/// message would need to trail the group by this many context changes before
/// its retained row goes terminal — and content-level redelivery under a
/// fresh transport id still recovers it afterwards.
pub const MAX_DEFERRED_PEEL_ATTEMPTS: u32 = 32;

/// Per-group cap on retained `PeelDeferred` rows (mdk#339). Raw
/// transport ids are attacker-controllable (a fresh wrap yields a fresh id),
/// so without a cap a peer flooding undecryptable group-routed events grows
/// the durable store without bound. At the cap, new undecryptable input is
/// dropped unpersisted (transport redelivery is the recovery path once the
/// backlog drains).
pub const MAX_PEEL_DEFERRED_ROWS_PER_GROUP: usize = 256;

/// Upper bound on `PeelDeferred` rows re-attempted per retry sweep
/// (mdk#339): a large historical backlog is worked through in slices
/// across passes instead of holding a convergence drain hostage, so current
/// events are never blocked behind irrelevant history.
pub(crate) const MAX_DEFERRED_ROWS_PER_SWEEP: usize = 64;

/// Per-group deferred-peel retry lifecycle state (mdk#339). Held on the
/// engine in `Engine::deferred_peel`; in-memory by design (see the field doc).
#[derive(Default)]
pub(crate) struct DeferredPeelGroupState {
    /// Peel-context fingerprint recorded after a full zero-progress cycle
    /// over the backlog. While the live context matches, whole sweeps are
    /// skipped — a deferred row can only become peelable when the group
    /// epoch advances or the retained-snapshot set changes.
    gate: Option<[u8; 32]>,
    /// Monotonic sweep counter; also the clock behind `sweeps_waited`.
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
    /// Per-row attempt count and first-seen sweep, keyed by the raw
    /// transport message id.
    attempts: std::collections::HashMap<MessageId, DeferredPeelAttempts>,
}

#[derive(Clone, Copy, Default)]
struct DeferredPeelAttempts {
    attempts: u32,
    first_seen_sweep: u64,
}

impl<S: StorageProvider> Engine<S> {
    /// Inbound pipeline. Never panics; every classifiable stale case returns
    /// a typed `StaleReason` inside `Ok(IngestOutcome::Stale { .. })`.
    pub(crate) async fn do_ingest(
        &mut self,
        msg: TransportMessage,
    ) -> Result<IngestOutcome, EngineError> {
        // Durable dedup / own-echo check. Storage is authoritative so a
        // restarted engine can classify replayed transport messages the same
        // way as a hot process.
        if let Some(outcome) = self.recorded_message_outcome(&msg.id)? {
            return Ok(outcome);
        }

        // In-memory fallback for messages produced before the durable record
        // is visible to this path.
        if self.seen_message_ids.contains(&msg.id) {
            return Ok(IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen,
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
            return Ok(IngestOutcome::Stale {
                reason: StaleReason::OwnEcho,
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

        if !matches!(outcome, IngestOutcome::Buffered { .. })
            && self.should_remember_ingested_message(&msg.id)?
        {
            self.seen_message_ids.insert(msg.id.clone());
        }
        Ok(outcome)
    }

    pub(crate) async fn do_send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        let group_id = send_intent_group_id(&intent).clone();
        // Quarantine gate: a group frozen by hydration quarantine must not
        // stage, queue, or publish anything — a confirm would set_stable and
        // silently un-quarantine it out of band (mdk#364).
        self.ensure_group_live(&group_id)?;
        // Terminal gate before queueing: a local copy marked removed (realized
        // self-eviction) must never accept or queue outbound work. Checked
        // again in `do_send_ready` so queued-intent drains for a copy removed
        // after queueing hit the same deterministic error.
        if self.group_record_is_removed(&group_id)? {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Removed",
                    to: crate::audit_helpers::send_intent_kind_str(&intent),
                    reason: "local group copy is marked removed (self-evicted)",
                },
            ));
        }
        if !matches!(intent, SendIntent::Leave { .. }) && self.has_leave_send_gate(&group_id)? {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Leaving",
                    to: crate::audit_helpers::send_intent_kind_str(&intent),
                    reason: "leave requested",
                },
            ));
        }
        if self.should_queue_outbound_intent(&group_id).await? {
            return self.queue_outbound_intent(group_id, intent);
        }

        self.do_send_ready(intent).await
    }

    pub async fn converge_and_drain_queued_outbound_intents(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<Vec<SendResult>, EngineError> {
        // Quarantined groups vanish from every live surface; convergence and
        // queued-intent drains must not touch their state (mdk#364).
        self.ensure_group_live(group_id)?;
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

        if self
            .stage_due_self_remove_auto_commit(group_id, now_ms)
            .await?
        {
            return Ok(Vec::new());
        }

        self.try_auto_repropose_leave_request(group_id).await;
        if self.load_leave_request_state(group_id)?.is_some() {
            return Ok(Vec::new());
        }

        let queued = self.storage.list_queued_outbound_intents(group_id)?;
        let mut drained = Vec::new();
        for record in queued {
            if !self
                .advance_convergence_inputs_until_settled(group_id, now_ms)
                .await?
            {
                break;
            }
            if self
                .stage_due_self_remove_auto_commit(group_id, now_ms)
                .await?
            {
                break;
            }
            self.try_auto_repropose_leave_request(group_id).await;
            if self.load_leave_request_state(group_id)?.is_some() {
                break;
            }
            let result = self.do_send_ready(record.intent.clone()).await?;
            self.storage.delete_queued_outbound_intent(&record.id)?;
            let pauses_for_pending_publish = matches!(result, SendResult::GroupEvolution { .. });
            drained.push(result);
            if pauses_for_pending_publish {
                break;
            }
        }
        Ok(drained)
    }

    async fn should_queue_outbound_intent(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(false);
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
        for _ in 0..MAX_CONVERGENCE_REPROCESSING_PASSES {
            if self.has_unresolved_convergence_inputs(group_id)? {
                let result = self
                    .converge_stored_openmls_messages(group_id, now_ms)
                    .map_err(|e| EngineError::Backend(format!("converge inputs: {e}")))?;
                if result.convergence_status != crate::canonicalization::ConvergenceStatus::Settled
                {
                    return Ok(false);
                }
                if self.has_unresolved_convergence_inputs(group_id)? {
                    return Ok(false);
                }
            }

            if self.retry_deferred_peels(group_id).await? == 0 {
                return Ok(!self.has_unresolved_convergence_inputs(group_id)?);
            }
        }

        Ok(false)
    }

    fn has_unresolved_convergence_inputs(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        // The convergence horizon is bounded on BOTH sides (mdk#736). The past
        // side (`anchor`) drops inputs older than the retained-anchor window.
        // The future side (`ceiling`) is symmetric: a convergence input more
        // than `max_rewind_commits` epochs ahead of the current tip cannot chain
        // from the tip yet (the candidate-path BFS in `openmls_projection` only
        // extends `source_epoch == tip_epoch`), so it is not *resolvable
        // convergence work* and must not gate outbound sends. Without the
        // ceiling, a single member could forge one far-future-epoch (e.g. 2^63)
        // plaintext message whose buffered `Created` row is never materialized
        // and never given a terminal disposition, permanently gating every send
        // for the whole group. The row is left in storage (not dropped here), so
        // it gates again correctly once the tip advances into `[anchor, ceiling]`.
        let (anchor, ceiling) = match self.storage.get_group(group_id) {
            Ok(group) => {
                let policy = self
                    .convergence_policy_for_group(group_id)
                    .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
                let rewind = policy.convergence.max_rewind_commits;
                (
                    group.epoch.0.saturating_sub(rewind),
                    group.epoch.0.saturating_add(rewind),
                )
            }
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(EngineError::Storage(e)),
        };
        let records = self.storage.list_messages(group_id, EpochId(anchor))?;
        for record in records {
            if !matches!(
                record.state,
                MessageState::Created | MessageState::Retryable
            ) {
                continue;
            }
            // Fail OPEN, not closed (mdk#736): a row we cannot decode, is not an
            // openmls-wire payload, or cannot be projected is NOT resolvable
            // convergence work — treating it as "unresolved" would let a single
            // corrupt/garbage row permanently gate sends with no recovery path.
            // Such a row simply does not contribute to the send gate; the
            // convergence horizon (`openmls_projection`) is responsible for
            // assigning it a terminal disposition.
            let Ok(stored_payload) = StoredMessagePayload::decode(&record.payload) else {
                continue;
            };
            let Some(message) = stored_payload.as_openmls_wire() else {
                continue;
            };
            let Ok(projection) = project_mls_message(&message.payload) else {
                continue;
            };
            // Beyond the future horizon: unreachable from the current tip, so
            // not gating work (see the ceiling rationale above).
            if projection.source_epoch.is_some_and(|epoch| epoch > ceiling) {
                continue;
            }
            // A lone uncommitted Proposal does NOT make canonical state
            // ambiguous: commits are the consensus log; a proposal only takes
            // effect once a commit consumes it (convergence.md:7-8). The
            // SelfRemove send-side rule is enforced earlier: remaining members
            // that may commit a SelfRemove stage a pending commit, and the
            // leaver is held by `leaving_groups`.
            //
            // The Proposal record stays in its `Created`/`Retryable` state and
            // continues to contribute to the OpenMLS candidate-path graph, so a
            // later consuming commit still resolves it through convergence; it
            // simply does not count as *unresolved convergence work* for the
            // outbound-send gate. Commits and application messages remain
            // gating: those genuinely leave canonical state ambiguous until
            // convergence settles.
            if matches!(
                projection.kind,
                OpenMlsContentKind::Commit | OpenMlsContentKind::Application
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn has_pending_convergence_inputs(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        self.has_unresolved_convergence_inputs(group_id)
    }

    /// Re-attempt retained `PeelDeferred` rows under the deferred-peel
    /// lifecycle (mdk#339):
    ///
    /// - **Event-driven**: a failed peel can only start succeeding when the
    ///   (epoch, retained-snapshot-set) peel context changes, so after a full
    ///   unproductive cycle over the backlog the context fingerprint gates
    ///   whole sweeps until the context actually changes.
    /// - **Budgeted**: a row that exhausts its retry budget without ever
    ///   peeling goes terminal `Failed` (`permanently_undecryptable`) instead
    ///   of retrying forever.
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
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
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
        let deferred: Vec<_> = self
            .storage
            .list_messages(group_id, EpochId(0))?
            .into_iter()
            .filter(|record| record.state == MessageState::PeelDeferred)
            .collect();
        let total = deferred.len();

        let (sweep_index, start, retry_budget) = {
            let budget = self.deferred_peel_retry_budget;
            let state = self.deferred_peel.entry(group_id.clone()).or_default();
            // The full row list is in hand: refresh the flood-cap count.
            state.deferred_rows = total;
            state.counted = true;
            state.sweep_count += 1;
            if state.cursor >= total {
                state.cursor = 0;
            }
            if state.cursor == 0 {
                state.cycle_progressed = false;
            }
            (state.sweep_count, state.cursor, budget)
        };
        if total == 0 {
            return Ok(0);
        }

        let end = (start + MAX_DEFERRED_ROWS_PER_SWEEP).min(total);
        let mut progressed = 0usize;
        let mut terminal = 0usize;
        for record in &deferred[start..end] {
            // Budget check first: bump this row's attempt count and go
            // terminal once it exceeds the budget without ever peeling.
            let (attempts, first_seen_sweep) = {
                let state = self.deferred_peel.entry(group_id.clone()).or_default();
                let entry =
                    state
                        .attempts
                        .entry(record.id.clone())
                        .or_insert(DeferredPeelAttempts {
                            attempts: 0,
                            first_seen_sweep: sweep_index,
                        });
                entry.attempts += 1;
                (entry.attempts, entry.first_seen_sweep)
            };
            if attempts > retry_budget {
                self.update_stored_message_state(&record.id, MessageState::Failed)?;
                self.audit_group(
                    group_id,
                    crate::audit_helpers::deferred_peel_terminal_event(
                        hex::encode(record.id.as_slice()),
                        Some(record.epoch),
                        crate::message_disposition::MessageDisposition::PermanentlyUndecryptable
                            .tag(),
                        u64::from(attempts.saturating_sub(1)),
                        sweep_index.saturating_sub(first_seen_sweep),
                    ),
                );
                self.note_peel_deferred_row_retired(group_id, &record.id);
                terminal += 1;
                continue;
            }

            let stored_payload = StoredMessagePayload::decode(&record.payload)
                .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
            let Some(msg) = stored_payload.as_raw_transport().cloned() else {
                continue;
            };
            match self
                .ingest_group_message(&msg, group_id.as_slice().to_vec())
                .await
            {
                Ok(IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed,
                }) => {}
                Ok(IngestOutcome::Stale {
                    reason: StaleReason::Quarantined,
                }) => {
                    // Defense-in-depth: the gate above should keep this loop
                    // from running for a quarantined group at all, but if a
                    // row still classifies Quarantined it must keep its
                    // PeelDeferred state — the catch-all arm below would
                    // retire the replay buffer.
                }
                Ok(IngestOutcome::Buffered { .. } | IngestOutcome::Processed) => {
                    // The peeled content now has its own content-derived record;
                    // retire the raw transport wrapper so it does not keep
                    // re-entering this retry loop as a stale duplicate.
                    self.update_stored_message_state(&record.id, MessageState::Processed)?;
                    self.note_peel_deferred_row_retired(group_id, &record.id);
                    progressed += 1;
                }
                Ok(IngestOutcome::Stale { .. }) => {
                    // Terminal stale classifications are still successful
                    // reclassifications of this raw deferred row.
                    self.update_stored_message_state(&record.id, MessageState::Processed)?;
                    self.note_peel_deferred_row_retired(group_id, &record.id);
                    progressed += 1;
                }
                Err(EngineError::ForkedEpoch {
                    group_id: forked_group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    self.note_peel_deferred_row_retired(group_id, &record.id);
                    return Err(EngineError::ForkedEpoch {
                        group_id: forked_group_id,
                        last_stable,
                        conflicting_epoch,
                    });
                }
                Err(e) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                    self.note_peel_deferred_row_retired(group_id, &record.id);
                    return Err(e);
                }
            }
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
            queue_depth = queue_depth as u64,
            sweep_duration_ms = sweep_started.elapsed().as_millis() as u64,
            "deferred-peel retry sweep"
        );
        Ok(progressed)
    }

    /// Fingerprint of everything that can change a deferred peel's outcome:
    /// the group's live epoch and the retained peel-snapshot set. While this
    /// is unchanged, re-peeling a deferred row is guaranteed wasted work.
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
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }

    /// Reserve capacity for one new `PeelDeferred` row, lazily counting the
    /// group's retained rows on first use this session. Returns `false` when
    /// the per-group flood cap is reached — the caller drops the message
    /// unpersisted (mdk#339).
    pub(crate) fn reserve_peel_deferred_slot(
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
        if state.deferred_rows >= MAX_PEEL_DEFERRED_ROWS_PER_GROUP {
            return Ok(false);
        }
        state.deferred_rows += 1;
        Ok(true)
    }

    /// Bookkeeping for a row leaving `PeelDeferred` (applied, reclassified,
    /// invalidated, or terminally failed): release its flood-cap slot and its
    /// attempt-tracking entry. Once the backlog drops back below the cap, the
    /// cap-rejection audit re-arms so a fresh cap-full episode is recorded
    /// once more.
    pub(crate) fn note_peel_deferred_row_retired(
        &mut self,
        group_id: &GroupId,
        msg_id: &MessageId,
    ) {
        if let Some(state) = self.deferred_peel.get_mut(group_id) {
            state.deferred_rows = state.deferred_rows.saturating_sub(1);
            state.attempts.remove(msg_id);
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
        let existing_count = self.storage.list_queued_outbound_intents(&group_id)?.len() as u64;
        let intent_bytes =
            serde_json::to_vec(&intent).map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-queued-outbound-intent/v1");
        hasher.update(group_id.as_slice());
        hasher.update(self.identity.self_id().as_slice());
        hasher.update(created_at_ms.to_be_bytes());
        hasher.update(existing_count.to_be_bytes());
        hasher.update(&intent_bytes);
        let intent_id = MessageId::new(hasher.finalize().to_vec());
        self.storage
            .put_queued_outbound_intent(&QueuedOutboundIntent {
                id: intent_id.clone(),
                group_id: group_id.clone(),
                intent,
                created_at_ms,
            })?;
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
                        self.note_peel_deferred_row_retired(group_id, &record.id);
                    } else {
                        self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                    }
                }
                Ok(IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed | StaleReason::Quarantined,
                }) => {
                    // Still un-peelable, or the group is quarantined: leave the
                    // row deferred. A terminal-after-peel `PeelFailed` already
                    // retired its raw deferred row inside `ingest_group_message`
                    // via `mark_raw_transport_message_failed_if_deferred`.
                }
                Ok(_) => {
                    // Applied (`Processed`) or terminally reclassified
                    // (`AlreadySeen`, `SelfEvicted`, ...): retire a raw
                    // deferred wrapper so it stops holding a cap slot
                    // (mdk#339). Non-deferred rows keep the pre-existing
                    // no-op behavior.
                    if was_peel_deferred {
                        self.update_stored_message_state(&record.id, MessageState::Processed)?;
                        self.note_peel_deferred_row_retired(group_id, &record.id);
                    }
                }
                Err(EngineError::ForkedEpoch {
                    group_id: forked_group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    if was_peel_deferred {
                        self.note_peel_deferred_row_retired(group_id, &record.id);
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
                        self.note_peel_deferred_row_retired(group_id, &record.id);
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
        | SendIntent::UpdateAppComponents { group_id, .. }
        | SendIntent::UpdateGroupData { group_id, .. } => group_id,
    }
}
