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

use crate::engine::Engine;
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

        let queued = self.storage.list_queued_outbound_intents(group_id)?;
        let mut drained = Vec::new();
        for record in queued {
            if !self
                .advance_convergence_inputs_until_settled(group_id, now_ms)
                .await?
            {
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
        Ok(!self
            .advance_convergence_inputs_until_settled(group_id, now_ms)
            .await?)
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
        let anchor = match self.storage.get_group(group_id) {
            Ok(group) => {
                let policy = self
                    .convergence_policy_for_group(group_id)
                    .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
                group
                    .epoch
                    .0
                    .saturating_sub(policy.convergence.max_rewind_commits)
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
            let Ok(stored_payload) = StoredMessagePayload::decode(&record.payload) else {
                return Ok(true);
            };
            let Some(message) = stored_payload.as_openmls_wire() else {
                return Ok(true);
            };
            let Ok(projection) = project_mls_message(&message.payload) else {
                return Ok(true);
            };
            // A lone uncommitted Proposal does NOT make canonical state
            // ambiguous: commits are the consensus log; a proposal only takes
            // effect once a commit consumes it (convergence.md:7-8). So an
            // outstanding Proposal record MUST NOT gate outbound application
            // payloads — otherwise a receiver that ingested, e.g., a standalone
            // AppDataUpdate request-flow proposal or a SelfRemove it is not
            // selected to commit could never send again until (or unless) the
            // consuming commit flows through convergence, which never happens if
            // the committing member is offline (darkmatter#154).
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

    pub async fn retry_deferred_peels(&mut self, group_id: &GroupId) -> Result<usize, EngineError> {
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Ok(0);
        }

        let records = self.storage.list_messages(group_id, EpochId(0))?;
        let mut progressed = 0;
        for record in records {
            if record.state != MessageState::PeelDeferred {
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
                Ok(IngestOutcome::Buffered { .. } | IngestOutcome::Processed) => {
                    // The peeled content now has its own content-derived record;
                    // retire the raw transport wrapper so it does not keep
                    // re-entering this retry loop as a stale duplicate.
                    self.update_stored_message_state(&record.id, MessageState::Processed)?;
                    progressed += 1;
                }
                Ok(IngestOutcome::Stale { .. }) => {
                    // Terminal stale classifications are still successful
                    // reclassifications of this raw deferred row.
                    self.update_stored_message_state(&record.id, MessageState::Processed)?;
                    progressed += 1;
                }
                Err(EngineError::ForkedEpoch {
                    group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    return Err(EngineError::ForkedEpoch {
                        group_id,
                        last_stable,
                        conflicting_epoch,
                    });
                }
                Err(e) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                    return Err(e);
                }
            }
        }
        Ok(progressed)
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
            match self
                .ingest_group_message(&msg, group_id.as_slice().to_vec())
                .await
            {
                Ok(IngestOutcome::Buffered { .. }) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
                }
                Ok(_) => {}
                Err(EngineError::ForkedEpoch {
                    group_id,
                    last_stable,
                    conflicting_epoch,
                }) => {
                    self.update_stored_message_state(&record.id, MessageState::EpochInvalidated)?;
                    return Err(EngineError::ForkedEpoch {
                        group_id,
                        last_stable,
                        conflicting_epoch,
                    });
                }
                Err(e) => {
                    self.update_stored_message_state(&record.id, MessageState::Retryable)?;
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
