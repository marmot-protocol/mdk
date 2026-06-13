//! Engine entry point for stored-message distributed convergence.

use std::collections::HashSet;

use crate::canonicalization::{
    CanonicalizationError, CanonicalizationPolicy, CanonicalizationResult, CanonicalizationState,
    ConvergenceStatus, InvalidatedAppMessageReason,
};
use crate::engine::Engine;
use crate::openmls_projection::{
    OpenMlsContentKind, OpenMlsProjectionError, OpenMlsReplayObservation,
    apply_openmls_canonicalization_result, canonicalize_stored_openmls_messages,
    project_mls_message, retain_current_group_epoch_snapshot,
};
use cgka_traits::engine::{AppMessageInvalidationReason, GroupEvent, GroupStateChange};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};

/// Admin pubkeys + avatar component bytes snapshotted on either side of a
/// convergence apply, for the unattributed group-state-change diffs.
type ReorgComponentSnapshot = (Vec<[u8; 32]>, [Option<Vec<u8>>; 2]);

impl<S: StorageProvider> Engine<S> {
    pub fn set_convergence_policy(&mut self, policy: CanonicalizationPolicy) {
        self.convergence_policy = policy;
        self.audit_engine_context();
    }

    pub fn set_group_convergence_policy(
        &mut self,
        group_id: &GroupId,
        policy: CanonicalizationPolicy,
    ) -> Result<(), OpenMlsProjectionError> {
        // Fail fast: never persist a policy that violates the witness-override bound.
        policy
            .validate()
            .map_err(|e| OpenMlsProjectionError::InvalidPolicy(e.to_string()))?;
        self.storage
            .put_convergence_policy(group_id, &encode_convergence_policy(&policy)?)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        let mut context = self
            .audit_group_context_snapshot(group_id)
            .unwrap_or_default();
        context.convergence_max_rewind_commits = Some(policy.convergence.max_rewind_commits);
        self.audit_group(
            group_id,
            marmot_forensics::AuditEventKind::GroupContext {
                reason: "set_group_convergence_policy".to_string(),
                context,
            },
        );
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
            // Validate the in-memory default too, so a bad policy set via
            // `set_convergence_policy` fails closed at read rather than driving
            // branch selection.
            let policy = self.convergence_policy.clone();
            policy
                .validate()
                .map_err(|e| OpenMlsProjectionError::InvalidPolicy(e.to_string()))?;
            return Ok(policy);
        };
        decode_convergence_policy(&policy_bytes)
    }

    pub(crate) fn retain_current_epoch_snapshot_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<(), cgka_traits::error::EngineError> {
        let policy = self.convergence_policy_for_group(group_id).map_err(|e| {
            cgka_traits::error::EngineError::Backend(format!("load convergence policy: {e}"))
        })?;
        retain_current_group_epoch_snapshot(
            &self.storage,
            group_id,
            policy.convergence.max_rewind_commits,
        )
        .map_err(|e| cgka_traits::error::EngineError::Backend(format!("retain anchor: {e}")))
    }

    pub fn buffer_openmls_convergence_message(
        &mut self,
        group_id: &GroupId,
        message: TransportMessage,
        now_ms: u64,
    ) -> Result<(), OpenMlsProjectionError> {
        // Key the convergence store on the content-derived dedup id (SHA-256 of
        // the recovered MLS bytes), not the outer transport id (#238). This
        // keeps the buffered-record identity consistent whether the message
        // arrived through `ingest_group_message` (which already rebinds to the
        // content id) or a direct caller, so a re-wrapped duplicate maps to the
        // same convergence row.
        let content_id = crate::message_processor::content_dedup_id(&message.payload);
        match self.storage.get_message(&content_id) {
            Ok(record) if record.state == MessageState::PeelDeferred => {}
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

        // Rebind the inner stored message id to the content id too: the
        // canonicalization layer reads the inner `TransportMessage.id` as the
        // symbolic message id and feeds it back into `update_message_state` /
        // `get_message`, so it MUST equal the record key.
        let message = TransportMessage {
            id: content_id.clone(),
            ..message
        };
        self.storage
            .put_message(&MessageRecord {
                id: content_id,
                group_id: group_id.clone(),
                epoch: EpochId(source_epoch),
                state: MessageState::Created,
                payload: StoredMessagePayload::openmls_wire(message)
                    .encode()
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
        // A group that has already entered `Unrecoverable` MUST stop applying
        // group-state changes until a verified repair path
        // (spec/protocol-core/group-state.md:50-51,65). Report the halt and
        // leave canonical state untouched.
        if self.epoch_manager.is_unrecoverable(group_id) {
            return Ok(unrecoverable_result(
                self.epoch_manager
                    .epoch(group_id)
                    .map(|e| e.0)
                    .unwrap_or_default(),
            ));
        }

        let previous_group = self
            .storage
            .get_group(group_id)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        // Pre-apply admin/avatar component snapshot, mirroring the direct
        // inbound seam's before-state capture so the reorg path can emit the
        // same profile/admin state-change events. Best-effort: a group whose
        // MLS state isn't loadable just skips those diffs.
        let previous_components = self.reorg_component_snapshot(group_id);
        let previous_name = previous_group.name.clone();
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

        let max_rewind_commits = policy.convergence.max_rewind_commits;
        let result = canonicalize_stored_openmls_messages(
            &self.storage,
            group_id,
            state,
            vec![],
            policy,
            now_ms,
        )?;
        self.audit_group(
            group_id,
            marmot_forensics::AuditEventKind::ConvergenceDecision {
                current_tip_epoch: previous_tip.0,
                candidate_count: result.candidate_count,
                eligible_count: result.eligible_count,
                max_rewind_commits,
                selected_branch_id: result.selected_branch_id.clone(),
                selected_fork_epoch: result.selected_fork_epoch,
                selected_tip_epoch: result.selected_tip,
            },
        );
        if matches!(
            result.convergence_status,
            ConvergenceStatus::Syncing | ConvergenceStatus::Resolving
        ) {
            return Ok(result);
        }

        // retained-history.md:30-31 — a required retained state missing inside
        // the rollback horizon MUST report `MissingRetainedAnchor`, leave
        // canonical group state unchanged, and move the group to
        // `Unrecoverable`. Halt before applying anything.
        if result
            .errors
            .contains(&CanonicalizationError::MissingRetainedAnchor)
        {
            self.epoch_manager.mark_unrecoverable(group_id);
            self.events_buf.push_back(GroupEvent::GroupUnrecoverable {
                group_id: group_id.clone(),
            });
            return Ok(result);
        }
        if result.convergence_status == ConvergenceStatus::Blocked {
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
            // Diagnostic only: classify this applied selection as a forward
            // advance or a post-settle reorg for quiescence tuning. This MUST
            // NOT influence convergence or branch selection — it only observes
            // the branch the engine has already committed to. See
            // relay-delivery-telemetry.md §"Validation: post-settle reorg rate".
            if let (Some(selected_fork_epoch), Some(selected_branch_id)) = (
                result.selected_fork_epoch,
                result.selected_branch_id.as_deref(),
            ) {
                self.engine_metrics.note_applied_selection(
                    group_id,
                    result.convergence_status,
                    selected_fork_epoch,
                    selected_tip.0,
                    selected_branch_id,
                    now_ms,
                );
            }
            self.emit_convergence_events(
                group_id,
                previous_group.members,
                &previous_name,
                previous_components,
                previous_tip,
                selected_tip,
                single_accepted_commit_id(&result),
            )?;
        }
        self.emit_application_replay_events(group_id, &observations);
        self.emit_invalidated_app_events(group_id, &result)?;
        self.emit_rolled_back_commits(group_id, &result)?;

        self.remember_canonicalization_result_messages(&result);
        Ok(result)
    }

    /// Best-effort load of the live MlsGroup's admin set + avatar component
    /// bytes for before/after diffing around a convergence apply. `None` when
    /// the MLS state isn't materialized; the caller skips those diffs rather
    /// than failing convergence over a missing caption.
    fn reorg_component_snapshot(&self, group_id: &GroupId) -> Option<ReorgComponentSnapshot> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                &provider,
            ),
            &mls_gid,
        )
        .ok()
        .flatten()?;
        let admins = crate::app_components::admins_of_group(&mls_group).unwrap_or_default();
        Some((
            admins,
            crate::message_processor::avatar_component_snapshot(&mls_group),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_convergence_events(
        &mut self,
        group_id: &GroupId,
        previous_members: Vec<cgka_traits::group::Member>,
        previous_name: &str,
        previous_components: Option<ReorgComponentSnapshot>,
        previous_tip: EpochId,
        selected_tip: EpochId,
        origin_commit_id: Option<MessageId>,
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
        // `origin_commit_id` is `Some` only when this convergence pass applied a
        // single accepted commit, so the entire previous-tip → selected-tip diff
        // is attributable to it; the rows it synthesizes carry that commit id so
        // they can be tombstoned together if it later loses a fork (see
        // `single_accepted_commit_id` + `emit_rolled_back_commits`). When several
        // commits were applied in one pass the delta cannot be split per-commit,
        // so we fall back to `None` (unattributed) as before. The previous-tip →
        // selected-tip diff is net of commits the direct seam already applied
        // (their effects are part of the "previous" snapshot), so changes already
        // emitted attributed there do not re-emit here as duplicates.
        if let (Some((before_admins, before_avatar)), Some((after_admins, after_avatar))) =
            (previous_components, self.reorg_component_snapshot(group_id))
        {
            for change in crate::group_state_changes::admin_changes(&before_admins, &after_admins) {
                self.push_group_state_change(
                    group_id,
                    selected_tip,
                    None,
                    change,
                    origin_commit_id.clone(),
                );
            }
            for change in crate::group_state_changes::profile_changes(
                Some(previous_name),
                Some(current_group.name.as_str()),
                &before_avatar,
                &after_avatar,
            ) {
                self.push_group_state_change(
                    group_id,
                    selected_tip,
                    None,
                    change,
                    origin_commit_id.clone(),
                );
            }
        }
        let previous_ids: HashSet<MemberId> = previous_members
            .iter()
            .map(|member| member.id.clone())
            .collect();
        let current_ids: HashSet<MemberId> = current_group
            .members
            .iter()
            .map(|member| member.id.clone())
            .collect();

        // Convergence reorg: we reach the canonical branch by replaying stored
        // commits, so the committer that effected each membership delta is not
        // resolved cheaply here. Emit the change unattributed (`actor: None`);
        // the row still renders ("X was added") without a "by Y". The
        // `origin_commit_id` link (when a single commit drove this pass) is
        // independent of `actor` — it ties the row to its origin commit for
        // fork-recovery tombstoning, not to a renderable committer.
        for member in current_group.members {
            if !previous_ids.contains(&member.id) {
                self.push_group_state_change(
                    group_id,
                    selected_tip,
                    None,
                    GroupStateChange::MemberAdded { member: member.id },
                    origin_commit_id.clone(),
                );
            }
        }
        for member_id in previous_ids.difference(&current_ids) {
            self.push_group_state_change(
                group_id,
                selected_tip,
                None,
                GroupStateChange::MemberRemoved {
                    member: member_id.clone(),
                },
                origin_commit_id.clone(),
            );
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
                source_epoch,
                sender,
                payload,
                ..
            } = observation
            else {
                continue;
            };
            self.events_buf.push_back(GroupEvent::MessageReceived {
                group_id: group_id.clone(),
                epoch: cgka_traits::EpochId(*source_epoch),
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
            // `UndecryptableInCanonicalState` is retryable: the message
            // targets a future epoch we cannot peel yet and will be re-fed on
            // a later canonicalize pass. Emitting `AppMessageInvalidated` here
            // would tell the app the message is permanently gone (the client
            // invalidates the timeline source row), so skip it for that reason.
            if invalidated.reason == InvalidatedAppMessageReason::UndecryptableInCanonicalState {
                continue;
            }
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

    /// Emit a [`GroupEvent::CommitRolledBack`] for every commit that this
    /// convergence pass dropped because it lost branch selection
    /// (`InvalidAgainstCandidateState`). This is the convergence-path analog of
    /// the direct seam's [`GroupEvent::ForkRecovered`] commit attribution: a
    /// commit that was previously applied through stored convergence (and so
    /// synthesized kind-1210 group system rows stamped with its `origin_commit_id`)
    /// can later lose a same-epoch fork during a reorg. The app uses
    /// `invalidated_commit_id` to tombstone those origin-linked rows so a losing
    /// branch's "Alice added Bob"-style history does not survive.
    ///
    /// Only `InvalidAgainstCandidateState` drops are reported: malformed /
    /// unsupported-policy commits never produced authenticated state changes,
    /// and the app-side tombstone is a no-op when no row carries the commit id,
    /// so emitting here is idempotent and safe even for commits this client
    /// never applied.
    fn emit_rolled_back_commits(
        &mut self,
        group_id: &GroupId,
        result: &CanonicalizationResult,
    ) -> Result<(), OpenMlsProjectionError> {
        for dropped in &result.dropped_messages {
            if dropped.kind != crate::canonicalization::MessageKind::Commit {
                continue;
            }
            if dropped.reason
                != crate::canonicalization::DroppedMessageReason::InvalidAgainstCandidateState
            {
                continue;
            }
            self.events_buf.push_back(GroupEvent::CommitRolledBack {
                group_id: group_id.clone(),
                invalidated_commit_id: message_id_from_hex(&dropped.message_id)?,
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
            // Skip the retryable reason: a future-epoch app message must stay
            // eligible for a later canonicalize pass. Marking it seen would
            // make canonicalization treat it as `AlreadySeen` and drop it
            // before the awaited commit advances the epoch.
            if invalidated.reason == InvalidatedAppMessageReason::UndecryptableInCanonicalState {
                continue;
            }
            if let Ok(bytes) = hex::decode(&invalidated.message_id) {
                self.seen_message_ids
                    .insert(cgka_traits::types::MessageId::new(bytes));
            }
        }
    }
}

/// The single commit id this convergence pass applied, hex-decoded to a
/// [`MessageId`], or `None` when the pass applied zero or several commits.
///
/// Convergence-synthesized group-state-change rows can only be attributed to a
/// concrete origin commit when exactly one commit was accepted this pass — then
/// the entire previous-tip → selected-tip diff is that commit's effect. With
/// multiple accepted commits the per-commit attribution is ambiguous (the diff
/// is their combined effect), so the rows stay unattributed (`None`) and are
/// re-synthesized fresh from the winning branch on a later convergence pass,
/// matching the pre-existing behavior.
fn single_accepted_commit_id(result: &CanonicalizationResult) -> Option<MessageId> {
    let [only_commit] = result.accepted_commits.as_slice() else {
        return None;
    };
    hex::decode(only_commit).ok().map(MessageId::new)
}

/// Result returned for a group already in `Unrecoverable`: no canonical
/// mutation, `MissingRetainedAnchor` reported, current tip preserved.
fn unrecoverable_result(current_tip: u64) -> CanonicalizationResult {
    CanonicalizationResult {
        previous_tip: current_tip,
        selected_tip: None,
        selected_fork_epoch: None,
        selected_branch_id: None,
        candidate_count: 0,
        eligible_count: 0,
        convergence_status: ConvergenceStatus::Blocked,
        accepted_commits: Vec::new(),
        accepted_proposals: Vec::new(),
        accepted_app_messages: Vec::new(),
        invalidated_app_messages: Vec::new(),
        dropped_messages: Vec::new(),
        already_seen: Vec::new(),
        queued_outbound_intents: Vec::new(),
        publishable_outbound_messages: Vec::new(),
        errors: vec![CanonicalizationError::MissingRetainedAnchor],
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
    let policy: CanonicalizationPolicy = serde_json::from_slice(bytes)
        .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))?;
    // A stored policy that violates the witness-override bound must not drive branch
    // selection; reject it at read time.
    policy
        .validate()
        .map_err(|e| OpenMlsProjectionError::InvalidPolicy(e.to_string()))?;
    Ok(policy)
}
