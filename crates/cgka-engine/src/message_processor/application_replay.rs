//! Resume already-unwrapped application input after canonical catch-up.
//!
//! A frozen pass can advance beyond its admission ceiling. Applications at
//! that new tip remain retained but cannot open a pass by themselves. Drain
//! them against the stable canonical state, independently of the send gate.

use super::{AdvanceConvergenceStatus, DeferredPeelExecution};
use crate::engine::Engine;
use crate::openmls_projection::{
    OpenMlsContentKind, OpenMlsProjectionError, ReplayProfilePolicy,
    process_current_openmls_application, project_mls_message,
};
use cgka_traits::engine::{AppMessageInvalidationReason, GroupEvent};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::EngineError;
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId};

impl<S: StorageProvider> Engine<S> {
    /// Scheduling work, never a branch-ambiguity/send gate. Future inputs wait
    /// for a state change rather than continuously rearming the worker.
    pub(crate) fn has_pending_canonical_applications(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        Ok(!self.pending_canonical_applications(group_id, 1)?.is_empty())
    }

    fn pending_canonical_applications(
        &self,
        group_id: &GroupId,
        limit: usize,
    ) -> Result<Vec<TransportMessage>, EngineError> {
        if limit == 0 || self.ensure_group_live(group_id).is_err() {
            return Ok(Vec::new());
        }
        if self
            .epoch_manager
            .state(group_id)
            .is_some_and(|state| !matches!(state, EpochState::Stable { .. }))
            || self
                .storage
                .convergence_pass(group_id)?
                .is_some_and(|pass| pass.is_active())
            || self.storage.deferred_peel_generation(group_id)?.is_some()
        {
            return Ok(Vec::new());
        }
        let group = match self.storage.get_group(group_id) {
            Ok(group) => group,
            Err(StorageError::NotFound) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        if group.is_terminal() || group.unrecoverable {
            return Ok(Vec::new());
        }
        let tip = group.epoch.0;
        let mut messages = Vec::new();
        self.storage.visit_messages_in_states(
            group_id,
            &[
                MessageState::Created,
                MessageState::Retryable,
                MessageState::ConvergenceDeferred,
            ],
            // Below-anchor applications still require a terminal invalidation;
            // clipping discovery to the replay horizon would strand those rows.
            EpochId(0),
            &mut |record| {
                if let Some(message) = Self::canonical_application_from_record(&record, tip) {
                    messages.push(message);
                }
                messages.len() < limit
            },
        )?;
        Ok(messages)
    }

    /// Shared with hydration, which already holds the complete record scan.
    pub(crate) fn canonical_application_from_record(
        record: &MessageRecord,
        tip: u64,
    ) -> Option<TransportMessage> {
        if !matches!(
            record.state,
            MessageState::Created | MessageState::Retryable | MessageState::ConvergenceDeferred
        ) {
            return None;
        }
        // Match the convergence work classifier: undecodable rows are not
        // runnable input and must not poison hydration or scheduler polling.
        let payload = StoredMessagePayload::decode(&record.payload).ok()?;
        // Locally authored inputs already have a send-side projection. Their
        // durable stamps remain branch witnesses; encryption-only sender
        // ratchets cannot decrypt them through the inbound drain.
        if payload.own_application_stamp().is_some() {
            return None;
        }
        let message = payload.as_openmls_wire()?;
        let projection = project_mls_message(&message.payload).ok()?;
        (projection.kind == OpenMlsContentKind::Application
            && projection.source_epoch.is_some_and(|epoch| epoch <= tip))
        .then(|| message.clone())
    }

    pub(super) fn drain_canonical_applications(
        &mut self,
        group_id: &GroupId,
        execution: &mut DeferredPeelExecution<'_>,
    ) -> Result<AdvanceConvergenceStatus, EngineError> {
        // Readable applications do not gate a foreground send. The runtime's
        // independent pending-work query keeps the background drain armed.
        if matches!(execution, DeferredPeelExecution::Foreground(_)) {
            return Ok(AdvanceConvergenceStatus::Settled);
        }
        // Discovery and earlier phases may already have spent the allowance.
        // Admit one atomic application operation so a ready group cannot keep
        // rearming without making progress. Subsequent operations stay bounded.
        let messages =
            self.pending_canonical_applications(group_id, execution.row_limit().max(1))?;
        if messages.is_empty() {
            return Ok(AdvanceConvergenceStatus::Settled);
        }
        let tip = self.storage.get_group(group_id)?.epoch.0;
        let policy = self
            .convergence_policy_for_group(group_id)
            .map_err(replay_error)?;
        let profile = ReplayProfilePolicy {
            reject_legacy_group_additions: self.new_protocol_profile
                == cgka_traits::group::ProtocolProfile::Current,
        };
        for (index, message) in messages.into_iter().enumerate() {
            if index != 0 && execution.exhausted() {
                break;
            }
            execution.consume_row();
            let source_epoch = project_mls_message(&message.payload)
                .map_err(replay_error)?
                .source_epoch
                .expect("selected application has an epoch");
            let horizon_reason =
                if source_epoch < tip.saturating_sub(policy.convergence.max_rewind_commits) {
                    Some(AppMessageInvalidationReason::BeyondAnchor)
                } else if tip.saturating_sub(source_epoch) > policy.app_message_past_epoch_limit {
                    Some(AppMessageInvalidationReason::BeyondAppRetention)
                } else {
                    None
                };
            // Ratchet consumption, disposition and durable app output share
            // one commit. A kill before commit leaves the input retryable;
            // a kill afterwards leaves the pending projection recoverable.
            let (events, invalidated) = self
                .storage
                .with_transaction(|storage| {
                    let observations = if horizon_reason.is_none() {
                        process_current_openmls_application(storage, group_id, &message, profile)?
                    } else {
                        Vec::new()
                    };
                    let events = Self::application_replay_events(group_id, &observations)?;
                    let invalidated =
                        if events.is_empty() {
                            Some(horizon_reason.unwrap_or(
                                AppMessageInvalidationReason::UndecryptableInCanonicalState,
                            ))
                        } else {
                            None
                        };
                    storage.update_message_state(
                        &message.id,
                        if invalidated.is_some() {
                            MessageState::EpochInvalidated
                        } else {
                            MessageState::Processed
                        },
                    )?;
                    for event in &events {
                        storage.put_pending_application_event(event)?;
                    }
                    crate::test_crash_hooks::pause_if_requested(
                        "canonical-application-before-commit",
                    );
                    Ok::<_, OpenMlsProjectionError>((events, invalidated))
                })
                .map_err(replay_error)?;
            crate::test_crash_hooks::pause_if_requested("canonical-application-completed-durable");
            if invalidated.is_none() {
                self.seen_message_ids.insert(message.id.clone());
            }
            self.audit_group(
                group_id,
                crate::audit_helpers::message_state_changed_event(
                    hex::encode(message.id.as_slice()),
                    if invalidated.is_some() {
                        MessageState::EpochInvalidated
                    } else {
                        MessageState::Processed
                    },
                    "canonical_application_drain",
                ),
            );
            self.events_buf.extend(events);
            if let Some(reason) = invalidated {
                self.events_buf
                    .push_back(GroupEvent::AppMessageInvalidated {
                        group_id: group_id.clone(),
                        message_id: message.id,
                        epoch: EpochId(source_epoch),
                        reason,
                        decrypted_payload_ref: None,
                    });
            }
        }
        if self.has_pending_canonical_applications(group_id)? {
            self.schedule_pending_convergence_group(group_id);
        }
        // Remaining application work must not withhold a queued outbound
        // intent. The scheduling edge/query above carries it to another turn.
        Ok(AdvanceConvergenceStatus::Settled)
    }
}

fn replay_error(error: OpenMlsProjectionError) -> EngineError {
    EngineError::Backend(format!("canonical application replay: {error}"))
}
