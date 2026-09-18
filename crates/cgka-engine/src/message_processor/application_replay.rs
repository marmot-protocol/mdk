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
        let mut fresh = Vec::new();
        let mut parked = Vec::new();
        let mut rival_branch_parked = false;
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
                #[cfg(test)]
                super::application_replay_tests::SCANNED_ROWS
                    .with(|count| count.set(count.get() + 1));
                let parked_row = record.state == MessageState::ConvergenceDeferred;
                match Self::retained_convergence_row(&record, tip) {
                    Some(RetainedConvergenceRow::Application(message)) if parked_row => {
                        if parked.len() < limit {
                            parked.push(message);
                        }
                    }
                    Some(RetainedConvergenceRow::Application(message)) => fresh.push(message),
                    Some(RetainedConvergenceRow::Commit) => {
                        rival_branch_parked |= parked_row;
                    }
                    None => {}
                }
                fresh.len() < limit
            },
        )?;
        // A parked commit is a rival branch a later pass holding deeper
        // evidence can still adopt, and convergence parks that branch's
        // applications alongside it. Draining one against the branch that
        // currently wins would give it the terminal verdict the pass
        // deliberately withheld — and reporting it as pending work would rearm
        // the scheduler forever on a row nothing may dispose of. So the parked
        // set waits while any branch edge is still reconsiderable.
        //
        // Two facts make "a commit is parked" the right question, rather than
        // the broader "a commit is pending", which a single forged
        // beyond-ceiling row could use to hold every parked application out of
        // this drain for as long as the tip stands still:
        //
        // * A commit that still owes a verdict keeps this drain unreachable. A
        //   `Created`/`Retryable` commit inside `[anchor, ceiling]` gates
        //   unconditionally (`ConvergenceInputContext::gates_outbound`,
        //   `CommitEdge => true`), and `advance_convergence_inputs` only reaches
        //   here on its `!has_unresolved_convergence_inputs` arm. Pinned by
        //   `tests/distributed_convergence.rs::a_commit_awaiting_adjudication_is_adjudicated_before_the_application_drain`.
        // * A pass never parks an application without parking its branch's
        //   commits. `handle_app_message`'s park arm requires a materialized,
        //   eligible, non-selected branch, which is exactly when `handle_commit`
        //   answers `NonSelectedEligibleBranch` for that branch's commits. Keep
        //   those two arms in step: an application parked on a branch holding no
        //   parked commit would open this gate.
        //
        // Terminalizing stays with a later pass and the horizon arms below
        // (`BeyondAnchor`, `BeyondAppRetention`). Nothing runs on its own — a
        // parked row opens no pass (`ConvergenceDeferred` is in neither
        // `PASS_OPENING_STATES` nor `OUTBOUND_GATING_STATES`) — so a fork frozen
        // with no further input keeps its parked rows until some other input
        // opens the next pass.
        if !rival_branch_parked {
            fresh.append(&mut parked);
            fresh.truncate(limit);
        }
        Ok(fresh)
    }

    /// Shared with hydration, which already holds the complete record scan.
    pub(crate) fn canonical_application_from_record(
        record: &MessageRecord,
        tip: u64,
    ) -> Option<TransportMessage> {
        match Self::retained_convergence_row(record, tip)? {
            RetainedConvergenceRow::Application(message) => Some(message),
            RetainedConvergenceRow::Commit => None,
        }
    }

    /// What one retained convergence row is to the application drain, decoded
    /// once so a caller never pays for the payload twice.
    fn retained_convergence_row(
        record: &MessageRecord,
        tip: u64,
    ) -> Option<RetainedConvergenceRow> {
        if !matches!(
            record.state,
            MessageState::Created | MessageState::Retryable | MessageState::ConvergenceDeferred
        ) {
            return None;
        }
        // Match the convergence work classifier: undecodable rows are not
        // runnable input and must not poison hydration or scheduler polling.
        let payload = StoredMessagePayload::decode(&record.payload).ok()?;
        let message = payload.as_openmls_wire()?;
        let projection = project_mls_message(&message.payload).ok()?;
        match projection.kind {
            OpenMlsContentKind::Commit => Some(RetainedConvergenceRow::Commit),
            OpenMlsContentKind::Application => {
                // Locally authored inputs already have a send-side projection.
                // Their durable stamps remain branch witnesses; encryption-only
                // sender ratchets cannot decrypt them through the inbound drain.
                if payload.own_application_stamp().is_some() {
                    return None;
                }
                projection
                    .source_epoch
                    .is_some_and(|epoch| epoch <= tip)
                    .then(|| RetainedConvergenceRow::Application(message.clone()))
            }
            OpenMlsContentKind::Proposal
            | OpenMlsContentKind::Welcome
            | OpenMlsContentKind::Other => None,
        }
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

/// A retained convergence row the application drain can act on.
enum RetainedConvergenceRow {
    /// An inbound application whose source epoch the canonical tip has reached.
    Application(TransportMessage),
    /// A branch edge. Parked, it is a rival branch a later pass can adopt.
    Commit,
}

fn replay_error(error: OpenMlsProjectionError) -> EngineError {
    EngineError::Backend(format!("canonical application replay: {error}"))
}
