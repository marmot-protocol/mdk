//! Engine entry point for stored-message distributed convergence.
//!
//! # Removed-marker lifecycle
//!
//! `Group.removed` realizes the local member's own removal
//! (member-departure.md, "Realizing removal"): it is set when an accepted
//! commit on the selected canonical branch removes our leaf — on the direct
//! seam, via `realize_self_eviction`, or in `emit_convergence_events` here —
//! and it clears in exactly two ways: an authenticated re-join
//! (`do_join_welcome`), or branch selection superseding the removal that set
//! it. A superseded removal was never canonically applied, so it "MUST NOT
//! remain visible to the application as a completed change" (convergence.md,
//! "Applying the selected branch"); member-departure.md's "terminal for that
//! group copy" rule presumes the removal stays canonical (clarification
//! tracked in marmot-protocol/marmot#220). A supersession reorg normally
//! restores the pre-removal record wholesale from the retained anchor (the
//! anchor predates the marker write); the explicit reconciliation in
//! `emit_convergence_events` is the state-derived inverse of
//! `realize_self_eviction` for markers no anchor restore can see, and it
//! clears only when the canonical roster AND the live MLS state both record
//! our active membership. Outbound intents purged at realization stay purged
//! — the app re-issues sends against the reopened send gate.

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
use std::sync::atomic::{AtomicU64, Ordering};

use cgka_traits::engine::{
    AppMessageInvalidationReason, GroupEvent, GroupStateChange, GroupStateInvalidationReason,
};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use marmot_forensics::{AuditConvergenceContext, AuditEventContext, ConvergencePhase};
use sha2::{Digest, Sha256};

/// Process-wide monotonic counter making each convergence run id unique even
/// when two runs share a group and tip epoch.
static CONVERGENCE_RUN_SEQ: AtomicU64 = AtomicU64::new(0);

/// Opaque, stable-per-run convergence run id. Salted hash so it never embeds the
/// plaintext group id (mirrors the fork-recovery snapshot-name precedent).
fn convergence_run_id(group_id: &GroupId, current_tip_epoch: u64) -> String {
    let seq = CONVERGENCE_RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(b"cgka-engine-convergence-run/v1");
    hasher.update(group_id.as_slice());
    hasher.update(current_tip_epoch.to_be_bytes());
    hasher.update(seq.to_be_bytes());
    format!("conv-{}", hex::encode(&hasher.finalize()[..8]))
}

/// Build an audit context carrying the convergence run id and lifecycle phase.
fn convergence_run_context(run_id: &str, phase: ConvergencePhase) -> AuditEventContext {
    AuditEventContext {
        convergence: Some(AuditConvergenceContext {
            run_id: run_id.to_string(),
            phase: Some(phase),
            inferred: None,
        }),
        ..AuditEventContext::default()
    }
}

/// Admin pubkeys, avatar component bytes, and message retention snapshotted on
/// either side of a convergence apply, for unattributed group-state-change diffs.
type ReorgComponentSnapshot = (Vec<[u8; 32]>, [Option<Vec<u8>>; 2], Option<u64>);

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

    /// Hex-encoded `seen_message_ids` snapshot for the convergence
    /// `CanonicalizationState`, cached by the seen-set generation (#636). A
    /// convergence drain calls `converge_stored_openmls_messages` up to 16 times;
    /// re-hex-encoding the whole (up to 100k-entry) set every pass was pure heap
    /// churn. The cache is rebuilt only when the set changed since it was last
    /// encoded, so a settled multi-pass drain encodes it at most once.
    fn seen_message_ids_hex_for_convergence(&mut self) -> std::collections::BTreeSet<String> {
        let generation = self.seen_message_ids.generation();
        if let Some((cached_generation, snapshot)) = &self.seen_message_ids_hex_cache
            && *cached_generation == generation
        {
            return snapshot.clone();
        }
        let snapshot: std::collections::BTreeSet<String> = self
            .seen_message_ids
            .iter()
            .map(|message_id| hex::encode(message_id.as_slice()))
            .collect();
        self.seen_message_ids_hex_cache = Some((generation, snapshot.clone()));
        snapshot
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
            let epoch = self
                .epoch_manager
                .epoch(group_id)
                .map(|e| e.0)
                .unwrap_or_default();
            self.audit_group(
                group_id,
                marmot_forensics::AuditEventKind::ConvergenceRunState {
                    phase: ConvergencePhase::Unrecoverable,
                    current_tip_epoch: Some(epoch),
                    retained_anchor_horizon: None,
                    reason: Some("already_unrecoverable".to_string()),
                    error_kind: None,
                },
            );
            return Ok(unrecoverable_result(epoch));
        }

        // A hydration-quarantined group is frozen until explicit repair: no
        // canonicalization pass may read or mutate its state, and no
        // set_stable may re-activate it out of band (mdk#364). Report a
        // blocked run and leave everything untouched; retained inputs replay
        // once repair clears the quarantine.
        if self.quarantined_reason(group_id).is_some() {
            let epoch = self
                .epoch_manager
                .epoch(group_id)
                .map(|e| e.0)
                .unwrap_or_default();
            self.audit_group(
                group_id,
                marmot_forensics::AuditEventKind::ConvergenceRunState {
                    phase: ConvergencePhase::Blocked,
                    current_tip_epoch: Some(epoch),
                    retained_anchor_horizon: None,
                    reason: Some("group_quarantined".to_string()),
                    error_kind: None,
                },
            );
            return Ok(quarantined_result(epoch));
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
            // #636: reuse the cached hex snapshot across the up-to-16 passes of a
            // convergence drain; it is re-encoded only when the seen set changed.
            seen_message_ids: self.seen_message_ids_hex_for_convergence(),
        };

        let max_rewind_commits = policy.convergence.max_rewind_commits;
        let run_id = convergence_run_id(group_id, previous_tip.0);
        let full_data = self.recorder.data_mode() == marmot_forensics::AuditDataMode::FullData;
        self.audit_group_with_context(
            group_id,
            convergence_run_context(&run_id, ConvergencePhase::Started),
            marmot_forensics::AuditEventKind::ConvergenceRunState {
                phase: ConvergencePhase::Started,
                current_tip_epoch: Some(previous_tip.0),
                retained_anchor_horizon: Some(retained_anchor_epoch),
                reason: None,
                error_kind: None,
            },
        );
        let result = canonicalize_stored_openmls_messages(
            &self.storage,
            group_id,
            state,
            vec![],
            policy,
            now_ms,
        )?;
        let error_kinds: Vec<String> = result
            .errors
            .iter()
            .map(|error| canonicalization_error_tag(*error).to_string())
            .collect();
        self.audit_group_with_context(
            group_id,
            convergence_run_context(&run_id, ConvergencePhase::Evaluating),
            crate::audit_helpers::convergence_decision_event(
                previous_tip.0,
                max_rewind_commits,
                result.selection_trace.as_ref(),
                error_kinds.clone(),
                full_data,
            ),
        );
        if matches!(
            result.convergence_status,
            ConvergenceStatus::Syncing | ConvergenceStatus::Resolving
        ) {
            self.audit_group_with_context(
                group_id,
                convergence_run_context(&run_id, ConvergencePhase::Waiting),
                marmot_forensics::AuditEventKind::ConvergenceRunState {
                    phase: ConvergencePhase::Waiting,
                    current_tip_epoch: Some(previous_tip.0),
                    retained_anchor_horizon: Some(retained_anchor_epoch),
                    reason: Some(
                        match result.convergence_status {
                            ConvergenceStatus::Resolving => "resolving",
                            _ => "syncing",
                        }
                        .to_string(),
                    ),
                    error_kind: None,
                },
            );
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
            let previous_state = self
                .epoch_manager
                .state(group_id)
                .map(|state| crate::audit_helpers::epoch_state_name_str(state.name()).to_string());
            self.epoch_manager.mark_unrecoverable(group_id);
            let epoch = self.epoch_manager.epoch(group_id).unwrap_or(previous_tip);
            self.audit_group(
                group_id,
                marmot_forensics::AuditEventKind::EpochStateChanged {
                    previous_state,
                    new_state: "unrecoverable".to_string(),
                    epoch: epoch.0,
                    reason: "missing_retained_anchor".to_string(),
                    pending_ref: None,
                    pending_kind: None,
                },
            );
            self.events_buf.push_back(GroupEvent::GroupUnrecoverable {
                group_id: group_id.clone(),
            });
            self.audit_group_with_context(
                group_id,
                convergence_run_context(&run_id, ConvergencePhase::Unrecoverable),
                marmot_forensics::AuditEventKind::ConvergenceRunState {
                    phase: ConvergencePhase::Unrecoverable,
                    current_tip_epoch: Some(previous_tip.0),
                    retained_anchor_horizon: Some(retained_anchor_epoch),
                    reason: None,
                    error_kind: Some("missing_retained_anchor".to_string()),
                },
            );
            return Ok(result);
        }
        if result.convergence_status == ConvergenceStatus::Blocked {
            self.audit_group_with_context(
                group_id,
                convergence_run_context(&run_id, ConvergencePhase::Blocked),
                marmot_forensics::AuditEventKind::ConvergenceRunState {
                    phase: ConvergencePhase::Blocked,
                    current_tip_epoch: Some(previous_tip.0),
                    retained_anchor_horizon: Some(retained_anchor_epoch),
                    reason: Some("blocked".to_string()),
                    error_kind: None,
                },
            );
            return Ok(result);
        }

        let observations = apply_openmls_canonicalization_result(
            &self.storage,
            group_id,
            &result,
            max_retained_anchor_rewind,
        )?;
        // #740 rotation: a routing-component update commit applied through
        // convergence may have changed this group's nostr_group_id; additively
        // refresh the transport-id index so it resolves on the inbound path
        // (prior id retained for the overlap window).
        self.reindex_transport_group_id(group_id);
        let origin_commit_id = single_accepted_commit_id(&result);
        let origin_commit_actor =
            single_accepted_commit_actor(&observations, origin_commit_id.as_ref());

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
                origin_commit_id,
                origin_commit_actor,
            )?;
        }
        self.emit_application_replay_events(group_id, &observations);
        self.emit_invalidated_app_events(group_id, &result)?;
        self.emit_rejected_proposal_convergence_audits(group_id, &result);
        self.emit_rolled_back_commits(group_id, &result)?;
        self.emit_superseded_processed_commits(group_id, &result)?;

        // A selected branch reached the canonical state (Settled): the run is
        // applied/stable. With no selected branch the pass simply settled with
        // nothing to apply.
        let applied_phase = if result.selected_tip.is_some() {
            ConvergencePhase::Applied
        } else {
            ConvergencePhase::Stable
        };
        self.audit_group_with_context(
            group_id,
            convergence_run_context(&run_id, applied_phase),
            marmot_forensics::AuditEventKind::ConvergenceRunState {
                phase: applied_phase,
                current_tip_epoch: result.selected_tip.or(Some(previous_tip.0)),
                retained_anchor_horizon: Some(retained_anchor_epoch),
                reason: None,
                error_kind: None,
            },
        );

        self.remember_canonicalization_result_messages(&result);
        Ok(result)
    }

    /// Best-effort load of the live MlsGroup's admin set, avatar component
    /// bytes, and message-retention seconds for before/after diffing around a
    /// convergence apply. `None` when the MLS state isn't materialized; the
    /// caller skips those diffs rather than failing convergence over missing
    /// presentation components.
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
        let message_retention =
            crate::app_components::message_retention_seconds_of_group(&mls_group)
                .ok()
                .flatten();
        Some((
            admins,
            crate::message_processor::avatar_component_snapshot(&mls_group),
            message_retention,
        ))
    }

    /// Whether the live OpenMLS group state records the local member as an
    /// active member: the group loads, is active, and its own leaf carries
    /// the engine's identity. Fail-closed (`false`) on any missing or
    /// unreadable state, so callers gating a safety-relevant transition on
    /// canonical membership never act on a copy MLS itself would refuse.
    fn self_leaf_is_active_in_mls(&self, group_id: &GroupId) -> bool {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let Ok(Some(mls_group)) = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                &provider,
            ),
            &mls_gid,
        ) else {
            return false;
        };
        if !mls_group.is_active() {
            return false;
        }
        let Some(leaf) = mls_group.own_leaf_node() else {
            return false;
        };
        let Ok(credential) = openmls::prelude::BasicCredential::try_from(leaf.credential().clone())
        else {
            return false;
        };
        credential.identity() == self.identity.self_id().as_slice()
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
        origin_commit_actor: Option<MemberId>,
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
        // `origin_commit_id` is populated only when this convergence pass applied
        // a single accepted commit, so the entire previous-tip → selected-tip
        // component diff can be tombstoned with that commit if it later loses a
        // fork (see `single_accepted_commit_id` + `emit_rolled_back_commits`).
        // Message-retention rows also use `origin_commit_actor` in that same
        // single-commit case so peers render the actor that changed the timer.
        // When several commits were applied in one pass the delta cannot be
        // split per-commit, so rows fall back to no origin commit and no actor.
        // The previous-tip → selected-tip diff is net of commits the direct seam
        // already applied (their effects are part of the "previous" snapshot),
        // so changes already emitted there do not re-emit here as duplicates.
        if let (
            Some((before_admins, before_avatar, before_message_retention)),
            Some((after_admins, after_avatar, after_message_retention)),
        ) = (previous_components, self.reorg_component_snapshot(group_id))
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
            for change in crate::group_state_changes::message_retention_changes(
                before_message_retention,
                after_message_retention,
            ) {
                self.push_group_state_change(
                    group_id,
                    selected_tip,
                    origin_commit_actor.clone(),
                    change,
                    origin_commit_id.clone(),
                );
            }
        }
        // Captured before `current_group.members` is consumed below: gates the
        // removed-marker reconciliation so the common (not-removed) path pays
        // no extra storage read.
        let group_record_was_removed = current_group.removed;
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
            if member_id == self.identity.self_id() {
                self.clear_leave_request_state(group_id)
                    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
                // The canonical branch removed our own leaf: mark the local
                // copy removed (member-departure.md, "Realizing removal") in
                // the same pass that emits the self-removed notification
                // below, so the marker and the notification stay coupled and
                // later `SelfEvicted` input does not re-emit it.
                let mut group = self
                    .storage
                    .get_group(group_id)
                    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
                if !group.removed {
                    group.removed = true;
                    self.storage
                        .put_group(&group)
                        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
                }
                // The copy just became removed: purge queued outbound intents
                // so later drains do not re-fail them forever against the
                // removed-copy send gate.
                self.discard_queued_outbound_intents_for_removed_group(group_id)
                    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
            }
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
        if current_ids.contains(self.identity.self_id()) {
            // The selected canonical branch records our membership, so a
            // surviving `removed` marker must clear (module docs, "Removed-
            // marker lifecycle"; marmot-protocol/marmot#220). Gated on the
            // record snapshot loaded above (no extra read on the common
            // not-removed path) AND on the live MLS state carrying our
            // active leaf, so the heal stays derivable from canonical MLS
            // state even if the record roster were ever stale.
            if group_record_was_removed && self.self_leaf_is_active_in_mls(group_id) {
                let mut group = self
                    .storage
                    .get_group(group_id)
                    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
                if group.removed {
                    group.removed = false;
                    self.storage
                        .put_group(&group)
                        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
                    // Privacy-safe breadcrumb: aggregate signal only, no
                    // group/member ids (observability.md).
                    tracing::info!(
                        target: "cgka_engine::distributed_convergence",
                        method = "emit_convergence_events",
                        "cleared removed marker: selected canonical branch records local membership"
                    );
                }
            }
            if self
                .load_leave_request_state(group_id)
                .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
                .is_some()
            {
                // The selected branch advanced without consuming our
                // SelfRemove. The proposal is epoch-bound, but the durable
                // leave request is not; keep the send gate so the async
                // convergence wrapper can publish a fresh proposal.
                self.leaving_groups.insert(group_id.clone());
            } else if self.leaving_groups.contains(group_id) {
                // Compatibility cleanup for a pre-durable in-memory gate.
                self.leaving_groups.remove(group_id);
            }
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
            if sender.is_empty() {
                // Backstop for the mirror-on-all-seams contract (#383): the
                // replay arm never produces an empty-sender observation, but
                // an unattributable application message must not surface as
                // MessageReceived from any seam.
                tracing::warn!(
                    target: "cgka_engine::distributed_convergence",
                    method = "emit_application_replay_events",
                    "skipping replayed application message with unattributable sender"
                );
                continue;
            }
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
            // A future-epoch decrypt miss is retryable and must not be
            // announced as permanently gone. The same reason at or below the
            // resulting tip is terminal, however, and must reach the app.
            if invalidated_app_is_retryable(result, invalidated) {
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

    fn emit_rejected_proposal_convergence_audits(
        &mut self,
        group_id: &GroupId,
        result: &CanonicalizationResult,
    ) {
        for dropped in &result.dropped_messages {
            let Some(category) = dropped.rejection_category else {
                continue;
            };
            let reason = crate::proposal_authorization::proposal_rejection_category_tag(category)
                .to_string();
            self.audit_group(
                group_id,
                marmot_forensics::AuditEventKind::Rejection {
                    msg_id: dropped.message_id.clone(),
                    reason,
                },
            );
        }
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
    ///
    /// Each rolled-back commit also gets a [`GroupEvent::GroupStateInvalidated`]:
    /// the spec-required explicit withdrawal of every state notification
    /// attributed to the superseded commit (convergence.md "Applying the
    /// selected branch"). This covers the client's own published-and-confirmed
    /// commit when it loses branch selection through the stored-convergence
    /// seam, mirroring the direct seam's `ForkRecovered` pairing.
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
            let invalidated_commit_id = message_id_from_hex(&dropped.message_id)?;
            // The stored record's epoch is the commit's source epoch (the fork
            // it lost). A missing record falls back to the selected branch's
            // fork epoch — the id-matched withdrawal is what conformance
            // requires; the epoch is presentation metadata. Any other storage
            // failure propagates: masking a locked/corrupt backend here would
            // emit a fabricated epoch and hide the failure from the caller.
            let epoch = match self.storage.get_message(&invalidated_commit_id) {
                Ok(record) => record.epoch,
                Err(StorageError::NotFound) => {
                    EpochId(result.selected_fork_epoch.unwrap_or(result.previous_tip))
                }
                Err(e) => return Err(OpenMlsProjectionError::Storage(format!("{e:?}"))),
            };
            self.events_buf.push_back(GroupEvent::CommitRolledBack {
                group_id: group_id.clone(),
                invalidated_commit_id: invalidated_commit_id.clone(),
            });
            self.events_buf
                .push_back(GroupEvent::GroupStateInvalidated {
                    group_id: group_id.clone(),
                    epoch,
                    invalidated_commit_id,
                    reason: GroupStateInvalidationReason::SupersededByBranchSelection,
                });
        }
        Ok(())
    }

    /// Withdraw every commit this device PREVIOUSLY APPLIED (stored state
    /// `Processed`) that a convergence apply left off the selected branch.
    ///
    /// The canonicalization drop set only covers commits the candidate BFS
    /// could materialize. A device's OWN published-and-confirmed commit is not
    /// replayable through `process_message` (MLS cannot process own messages),
    /// so when a reorg supersedes it — e.g. after a restart cleared the
    /// in-memory `committed_from` guard and routed a same-epoch sibling into
    /// stored convergence — the own commit gets no disposition at all: no
    /// `CommitRolledBack`, no withdrawal, and the confirm-time
    /// `GroupStateChanged` rows survive as the issue #363 lie.
    ///
    /// Spec (convergence.md "Applying the selected branch"): branch selection
    /// superseding "a commit the client previously applied — including the
    /// client's own published and confirmed commit" MUST withdraw the state
    /// notifications attributed to it. `Processed` is exactly "previously
    /// applied"; not on the accepted path at or above the selected fork epoch
    /// is exactly "superseded". Commits the drop set already covered are
    /// skipped so each supersession is reported once.
    fn emit_superseded_processed_commits(
        &mut self,
        group_id: &GroupId,
        result: &CanonicalizationResult,
    ) -> Result<(), OpenMlsProjectionError> {
        if result.selected_tip.is_none() {
            return Ok(());
        }
        let Some(fork_epoch) = result.selected_fork_epoch else {
            return Ok(());
        };
        let accepted: std::collections::BTreeSet<&str> =
            result.accepted_commits.iter().map(String::as_str).collect();
        // Scope the scan to `fork_epoch` onward (mdk#745): rows below the fork
        // epoch are skipped anyway, so listing from `EpochId(0)` re-decoded and
        // re-projected the group's entire retained history on every apply. The
        // storage query filters `at_or_after_epoch`, yielding an identical set.
        let records = self
            .storage
            .list_messages(group_id, EpochId(fork_epoch))
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        for record in records {
            if record.state != MessageState::Processed || record.epoch.0 < fork_epoch {
                continue;
            }
            let payload = StoredMessagePayload::decode(&record.payload)
                .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))?;
            let Some(message) = payload.as_openmls_wire() else {
                continue;
            };
            if project_mls_message(&message.payload)?.kind != OpenMlsContentKind::Commit {
                continue;
            }
            let record_id_hex = hex::encode(record.id.as_slice());
            // The same MLS bytes can be keyed by the wrap-time transport id
            // (own sent commits) or the content dedup id (inbound commits), so
            // acceptance is checked under both aliases before declaring the
            // record superseded.
            let content_id_hex = hex::encode(
                crate::message_processor::content_dedup_id(&message.payload).as_slice(),
            );
            if accepted.contains(record_id_hex.as_str())
                || accepted.contains(content_id_hex.as_str())
            {
                continue;
            }
            if result
                .dropped_messages
                .iter()
                .any(|dropped| dropped.message_id == record_id_hex)
            {
                continue;
            }
            self.storage
                .update_message_state(&record.id, MessageState::EpochInvalidated)
                .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
            self.audit_group(
                group_id,
                crate::audit_helpers::message_state_changed_event(
                    record_id_hex,
                    MessageState::EpochInvalidated,
                    "superseded_processed_commit",
                ),
            );
            self.events_buf.push_back(GroupEvent::CommitRolledBack {
                group_id: group_id.clone(),
                invalidated_commit_id: record.id.clone(),
            });
            self.events_buf
                .push_back(GroupEvent::GroupStateInvalidated {
                    group_id: group_id.clone(),
                    epoch: record.epoch,
                    invalidated_commit_id: record.id,
                    reason: GroupStateInvalidationReason::SupersededByBranchSelection,
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
            // A future-epoch app message must stay eligible for a later pass.
            // Terminal at-or-below-tip decrypt misses are remembered normally.
            if invalidated_app_is_retryable(result, invalidated) {
                continue;
            }
            if let Ok(bytes) = hex::decode(&invalidated.message_id) {
                self.seen_message_ids
                    .insert(cgka_traits::types::MessageId::new(bytes));
            }
        }
    }
}

fn invalidated_app_is_retryable(
    result: &CanonicalizationResult,
    invalidated: &crate::canonicalization::InvalidatedAppMessage,
) -> bool {
    invalidated.reason == InvalidatedAppMessageReason::UndecryptableInCanonicalState
        && invalidated.epoch > result.selected_tip.unwrap_or(result.previous_tip)
}

/// The single commit id this convergence pass applied, hex-decoded to a
/// [`MessageId`], or `None` when the pass applied zero or several commits.
///
/// Convergence-synthesized group-state-change rows can only be attributed to a
/// concrete origin commit when exactly one commit was accepted this pass — then
/// the entire previous-tip → selected-tip diff is that commit's effect. With
/// multiple accepted commits the per-commit attribution is ambiguous (the diff
/// is their combined effect), so the rows use no origin commit and no actor.
fn single_accepted_commit_id(result: &CanonicalizationResult) -> Option<MessageId> {
    let [only_commit] = result.accepted_commits.as_slice() else {
        return None;
    };
    hex::decode(only_commit).ok().map(MessageId::new)
}

fn single_accepted_commit_actor(
    observations: &[OpenMlsReplayObservation],
    origin_commit_id: Option<&MessageId>,
) -> Option<MemberId> {
    let origin_commit_hex = hex::encode(origin_commit_id?.as_slice());
    observations
        .iter()
        .find_map(|observation| match observation {
            OpenMlsReplayObservation::CommitStaged {
                message_id,
                committer,
                ..
            } if message_id == &origin_commit_hex => Some(MemberId::new(committer.clone())),
            _ => None,
        })
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
        selection_trace: None,
    }
}

/// Blocked no-op result for a hydration-quarantined group: convergence ran
/// against nothing, selected nothing, and reports no errors — the group is
/// deliberately frozen, not failing.
fn quarantined_result(current_tip: u64) -> CanonicalizationResult {
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
        errors: Vec::new(),
        selection_trace: None,
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

fn canonicalization_error_tag(error: CanonicalizationError) -> &'static str {
    match error {
        CanonicalizationError::UnsupportedPolicy => "unsupported_policy",
        CanonicalizationError::MissingRetainedAnchor => "missing_retained_anchor",
        CanonicalizationError::CandidateStateUnavailable => "candidate_state_unavailable",
        CanonicalizationError::MlsValidationFailed => "mls_validation_failed",
        CanonicalizationError::OutboundIntentStale => "outbound_intent_stale",
        CanonicalizationError::StorageUnavailable => "storage_unavailable",
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
