//! Engine entry point for stored-message distributed convergence.

use std::collections::HashSet;

use crate::canonicalization::{
    CanonicalizationPolicy, CanonicalizationResult, CanonicalizationState,
    InvalidatedAppMessageReason, SyncState,
};
use crate::engine::Engine;
use crate::openmls_projection::{
    OpenMlsContentKind, OpenMlsProjectionError, OpenMlsReplayObservation,
    apply_openmls_canonicalization_result, canonicalize_stored_openmls_messages,
    project_mls_message,
};
use cgka_traits::engine::{AppMessageInvalidationReason, GroupEvent};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};

impl<S: StorageProvider> Engine<S> {
    pub fn set_convergence_policy(&mut self, policy: CanonicalizationPolicy) {
        self.convergence_policy = policy;
    }

    pub fn set_group_convergence_policy(
        &mut self,
        group_id: &GroupId,
        policy: CanonicalizationPolicy,
    ) -> Result<(), OpenMlsProjectionError> {
        self.storage
            .put_convergence_policy(group_id, &encode_convergence_policy(&policy)?)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        Ok(())
    }

    pub(crate) fn convergence_policy_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<CanonicalizationPolicy, OpenMlsProjectionError> {
        let Some(policy_bytes) = self
            .storage
            .convergence_policy(group_id)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        else {
            return Ok(self.convergence_policy.clone());
        };
        decode_convergence_policy(&policy_bytes)
    }

    pub fn buffer_openmls_convergence_message(
        &mut self,
        group_id: &GroupId,
        message: TransportMessage,
        now_ms: u64,
    ) -> Result<(), OpenMlsProjectionError> {
        match self.storage.get_message(&message.id) {
            Ok(_) => return Ok(()),
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(OpenMlsProjectionError::Storage(format!("{e:?}"))),
        }

        let projection = project_mls_message(&message.payload)?;
        let Some(source_epoch) = projection.source_epoch else {
            return Ok(());
        };
        if !matches!(
            projection.kind,
            OpenMlsContentKind::Commit
                | OpenMlsContentKind::Proposal
                | OpenMlsContentKind::Application
        ) {
            return Ok(());
        }

        self.storage
            .put_message(&MessageRecord {
                id: message.id.clone(),
                group_id: group_id.clone(),
                epoch: EpochId(source_epoch),
                state: MessageState::Created,
                payload: serde_json::to_vec(&message)
                    .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))?,
            })
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        self.last_convergence_relevant_input_ms
            .insert(group_id.clone(), now_ms);
        Ok(())
    }

    /// Canonicalize retained stored OpenMLS messages and, once the caller's
    /// quiescence window has elapsed, apply the selected branch to storage.
    pub fn converge_stored_openmls_messages(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
        let previous_group = self
            .storage
            .get_group(group_id)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        let previous_tip = self
            .epoch_manager
            .epoch(group_id)
            .unwrap_or(previous_group.epoch);
        let policy = self.convergence_policy_for_group(group_id)?;
        let max_retained_anchor_rewind = policy.convergence.max_rewind_commits;
        let retained_anchor_epoch = previous_tip
            .0
            .saturating_sub(policy.convergence.max_rewind_commits);
        let last_convergence_relevant_input_ms = self
            .last_convergence_relevant_input_ms
            .get(group_id)
            .copied()
            .unwrap_or(0);
        let state = CanonicalizationState {
            current_tip_epoch: previous_tip.0,
            retained_anchor_epoch,
            last_convergence_relevant_input_ms,
            seen_message_ids: self
                .seen_message_ids
                .iter()
                .map(|message_id| hex::encode(message_id.as_slice()))
                .collect(),
        };

        let result = canonicalize_stored_openmls_messages(
            &self.storage,
            group_id,
            state,
            vec![],
            policy,
            now_ms,
        )?;
        if result.sync_state != SyncState::Stable {
            return Ok(result);
        }

        let observations = apply_openmls_canonicalization_result(
            &self.storage,
            group_id,
            &result,
            max_retained_anchor_rewind,
        )?;

        if let Some(selected_tip) = result.selected_tip {
            let selected_tip = EpochId(selected_tip);
            self.epoch_manager
                .set_stable(group_id.clone(), selected_tip);
            self.emit_convergence_events(
                group_id,
                previous_group.members,
                previous_tip,
                selected_tip,
            )?;
        }
        self.emit_application_replay_events(group_id, &observations);
        self.emit_invalidated_app_events(group_id, &result)?;

        self.remember_canonicalization_result_messages(&result);
        Ok(result)
    }

    fn emit_convergence_events(
        &mut self,
        group_id: &GroupId,
        previous_members: Vec<cgka_traits::group::Member>,
        previous_tip: EpochId,
        selected_tip: EpochId,
    ) -> Result<(), OpenMlsProjectionError> {
        if previous_tip != selected_tip {
            self.events_buf.push_back(GroupEvent::EpochChanged {
                group_id: group_id.clone(),
                from: previous_tip,
                to: selected_tip,
            });
        }

        let current_group = self
            .storage
            .get_group(group_id)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        let previous_ids: HashSet<MemberId> = previous_members
            .iter()
            .map(|member| member.id.clone())
            .collect();
        let current_ids: HashSet<MemberId> = current_group
            .members
            .iter()
            .map(|member| member.id.clone())
            .collect();

        for member in current_group.members {
            if !previous_ids.contains(&member.id) {
                self.events_buf.push_back(GroupEvent::MemberAdded {
                    group_id: group_id.clone(),
                    member,
                });
            }
        }
        for member_id in previous_ids.difference(&current_ids) {
            self.events_buf.push_back(GroupEvent::MemberRemoved {
                group_id: group_id.clone(),
                member: member_id.clone(),
            });
        }

        Ok(())
    }

    fn emit_application_replay_events(
        &mut self,
        group_id: &GroupId,
        observations: &[OpenMlsReplayObservation],
    ) {
        for observation in observations {
            let OpenMlsReplayObservation::ApplicationProcessed {
                sender, payload, ..
            } = observation
            else {
                continue;
            };
            self.events_buf.push_back(GroupEvent::MessageReceived {
                group_id: group_id.clone(),
                sender: MemberId::new(sender.clone()),
                payload: payload.clone(),
            });
        }
    }

    fn emit_invalidated_app_events(
        &mut self,
        group_id: &GroupId,
        result: &CanonicalizationResult,
    ) -> Result<(), OpenMlsProjectionError> {
        for invalidated in &result.invalidated_app_messages {
            self.events_buf
                .push_back(GroupEvent::AppMessageInvalidated {
                    group_id: group_id.clone(),
                    message_id: message_id_from_hex(&invalidated.message_id)?,
                    epoch: EpochId(invalidated.epoch),
                    reason: app_invalidation_reason(invalidated.reason),
                    decrypted_payload_ref: invalidated.decrypted_payload_ref.clone(),
                });
        }
        Ok(())
    }

    fn remember_canonicalization_result_messages(&mut self, result: &CanonicalizationResult) {
        for message_id in result
            .accepted_commits
            .iter()
            .chain(&result.accepted_proposals)
            .chain(&result.accepted_app_messages)
        {
            if let Ok(bytes) = hex::decode(message_id) {
                self.seen_message_ids
                    .insert(cgka_traits::types::MessageId::new(bytes));
            }
        }
        for dropped in &result.dropped_messages {
            if dropped.reason == crate::canonicalization::DroppedMessageReason::Malformed {
                continue;
            }
            if let Ok(bytes) = hex::decode(&dropped.message_id) {
                self.seen_message_ids
                    .insert(cgka_traits::types::MessageId::new(bytes));
            }
        }
        for invalidated in &result.invalidated_app_messages {
            if let Ok(bytes) = hex::decode(&invalidated.message_id) {
                self.seen_message_ids
                    .insert(cgka_traits::types::MessageId::new(bytes));
            }
        }
    }
}

fn message_id_from_hex(encoded: &str) -> Result<MessageId, OpenMlsProjectionError> {
    hex::decode(encoded)
        .map(MessageId::new)
        .map_err(|e| OpenMlsProjectionError::Decode(format!("message id {encoded}: {e:?}")))
}

fn app_invalidation_reason(reason: InvalidatedAppMessageReason) -> AppMessageInvalidationReason {
    match reason {
        InvalidatedAppMessageReason::LosingBranch => AppMessageInvalidationReason::LosingBranch,
        InvalidatedAppMessageReason::BeyondAnchor => AppMessageInvalidationReason::BeyondAnchor,
        InvalidatedAppMessageReason::BeyondAppRetention => {
            AppMessageInvalidationReason::BeyondAppRetention
        }
        InvalidatedAppMessageReason::UndecryptableInCanonicalState => {
            AppMessageInvalidationReason::UndecryptableInCanonicalState
        }
    }
}

fn encode_convergence_policy(
    policy: &CanonicalizationPolicy,
) -> Result<Vec<u8>, OpenMlsProjectionError> {
    serde_json::to_vec(policy).map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))
}

fn decode_convergence_policy(
    bytes: &[u8],
) -> Result<CanonicalizationPolicy, OpenMlsProjectionError> {
    serde_json::from_slice(bytes).map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))
}
