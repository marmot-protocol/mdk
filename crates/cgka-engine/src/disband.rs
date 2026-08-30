//! Durable terminal group-disband workflow.
//!
//! A user request is persisted and gates ordinary work immediately. Commit
//! preparation happens later, after any already-staged publish and the normal
//! bounded convergence gate have completed.

use crate::engine::Engine;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentData, GROUP_ADMIN_POLICY_COMPONENT_ID,
    GROUP_LIFECYCLE_COMPONENT_ID, GroupLifecycleV1, encode_components_list,
    encode_group_lifecycle_v1,
};
use cgka_traits::engine::SendResult;
use cgka_traits::engine_state::{EpochState, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::storage::{
    DisbandCandidate, DisbandFailureReason, DisbandRequest, DisbandRequestStatus, StorageError,
    StorageProvider,
};
use cgka_traits::transport::EncryptedPayload;
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateProposal, Proposal};
use openmls::prelude::BasicCredential;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tls_codec::Serialize as _;

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_enable_group_disbanding(
        &mut self,
        group_id: GroupId,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;

        let mut required = crate::app_components::required_app_components_of_group(&mls_group)?;
        let lifecycle = crate::app_components::lifecycle_of_group(&mls_group)?;
        if required.contains(GROUP_LIFECYCLE_COMPONENT_ID) {
            return match lifecycle {
                Some(GroupLifecycleV1::Active) => Ok(SendResult::NoChange { group_id }),
                Some(GroupLifecycleV1::Disbanded) => Err(EngineError::InvalidTransition(
                    cgka_traits::engine_state::InvalidTransition {
                        from: "Disbanded",
                        to: "EnableDisbanding",
                        reason: "Disbanded is terminal",
                    },
                )),
                None => Err(EngineError::Other(
                    "required lifecycle component has no state".into(),
                )),
            };
        }

        let blockers = crate::app_components::lifecycle_support_blockers(&mls_group)?;
        if !blockers.is_empty() {
            return Err(EngineError::DisbandingUnsupportedMembers {
                group_id,
                members: blockers,
            });
        }

        required.insert(GROUP_LIFECYCLE_COMPONENT_ID);
        let mut updates = vec![AppComponentData {
            component_id: APP_COMPONENTS_COMPONENT_ID,
            data: encode_components_list(&required.ids),
        }];
        if lifecycle.is_none() {
            updates.push(AppComponentData {
                component_id: GROUP_LIFECYCLE_COMPONENT_ID,
                data: encode_group_lifecycle_v1(GroupLifecycleV1::Active),
            });
        }
        self.do_send_update_app_components(group_id, updates).await
    }

    /// Persist the irreversible product intent and install its durable send
    /// gate. This deliberately does not stage a Commit.
    pub(crate) fn do_request_disband(
        &mut self,
        group_id: GroupId,
    ) -> Result<SendResult, EngineError> {
        if self.storage.disband_tombstone(&group_id)?.is_some() {
            return Ok(SendResult::NoChange { group_id });
        }
        if let Some(request) = self.storage.disband_request(&group_id)?
            && request.status == DisbandRequestStatus::Pending
        {
            self.schedule_pending_convergence_group(&group_id);
            return Ok(SendResult::DisbandRequested { request });
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let required = crate::app_components::required_app_components_of_group(&mls_group)?;
        if !required.contains(GROUP_LIFECYCLE_COMPONENT_ID)
            || crate::app_components::lifecycle_of_group(&mls_group)?
                != Some(GroupLifecycleV1::Active)
        {
            return Err(EngineError::DisbandingNotEnabled { group_id });
        }
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;

        let request = DisbandRequest {
            group_id: group_id.clone(),
            requested_at_ms: self.wall_clock.now_ms(),
            status: DisbandRequestStatus::Pending,
            last_prepared_epoch: None,
        };
        let preserve_staged_publish = matches!(
            self.epoch_manager.state(&group_id),
            Some(EpochState::PendingPublish(_) | EpochState::Merging(_))
        );
        self.storage.with_transaction(|storage| {
            storage.put_disband_request(&request)?;
            for queued in storage.list_queued_outbound_intents(&group_id)? {
                storage.delete_queued_outbound_intent(&queued.id)?;
            }
            for welcome in storage
                .list_welcomes()?
                .into_iter()
                .filter(|welcome| welcome.group_id == group_id)
            {
                let _ = storage.take_welcome(&welcome.message_id)?;
            }
            if !preserve_staged_publish {
                for fanout in storage.list_outbound_fanouts_for_group(&group_id)? {
                    storage.delete_outbound_fanout(fanout.message_id())?;
                }
                if let Some(maintenance) = storage.maintenance_storage() {
                    maintenance.delete_group_maintenance(&group_id)?;
                    for obligation in
                        maintenance.list_maintenance_obligations_for_group(&group_id)?
                    {
                        maintenance.delete_maintenance_obligation(&obligation.id)?;
                    }
                    for evolution in maintenance.list_group_evolutions_for_group(&group_id)? {
                        maintenance.delete_group_evolution(&evolution.id)?;
                    }
                    for fanout in maintenance.list_transport_fanouts()? {
                        if fanout.group_id.as_ref() == Some(&group_id) {
                            maintenance.delete_transport_fanout(&fanout.id)?;
                        }
                    }
                }
            }
            Ok::<(), StorageError>(())
        })?;
        self.queued_intent_by_message
            .retain(|_, (queued_group, _)| queued_group != &group_id);
        self.queued_intent_by_pending
            .retain(|_, (queued_group, _)| queued_group != &group_id);
        self.drop_self_remove_auto_commit_schedules_for_group(&group_id);
        self.schedule_pending_convergence_group(&group_id);
        Ok(SendResult::DisbandRequested { request })
    }

    pub(crate) fn record_inbound_disband_candidate(
        &mut self,
        group_id: &GroupId,
        source_epoch: EpochId,
        commit_id: cgka_traits::MessageId,
        commit_bytes: &[u8],
        actor: cgka_traits::MemberId,
        local_was_committer_leaf: bool,
    ) -> Result<(), EngineError> {
        let former_members = deduplicated_roster(&self.storage.get_group(group_id)?.members);
        let candidate = DisbandCandidate {
            group_id: group_id.clone(),
            source_epoch,
            commit_id,
            content_commit_id: crate::message_processor::content_dedup_id(commit_bytes),
            commit_digest: Sha256::digest(commit_bytes).into(),
            actor,
            local_was_committer_leaf,
            former_members,
        };
        self.storage.with_transaction(|storage| {
            storage.put_disband_candidate(&candidate)?;
            for queued in storage.list_queued_outbound_intents(group_id)? {
                storage.delete_queued_outbound_intent(&queued.id)?;
            }
            for welcome in storage
                .list_welcomes()?
                .into_iter()
                .filter(|welcome| &welcome.group_id == group_id)
            {
                let _ = storage.take_welcome(&welcome.message_id)?;
            }
            for fanout in storage.list_outbound_fanouts_for_group(group_id)? {
                storage.delete_outbound_fanout(fanout.message_id())?;
            }
            if let Some(maintenance) = storage.maintenance_storage() {
                maintenance.delete_group_maintenance(group_id)?;
                for obligation in maintenance.list_maintenance_obligations_for_group(group_id)? {
                    maintenance.delete_maintenance_obligation(&obligation.id)?;
                }
                for evolution in maintenance.list_group_evolutions_for_group(group_id)? {
                    maintenance.delete_group_evolution(&evolution.id)?;
                }
                for fanout in maintenance.list_transport_fanouts()? {
                    if fanout.group_id.as_ref() == Some(group_id) {
                        maintenance.delete_transport_fanout(&fanout.id)?;
                    }
                }
            }
            Ok::<(), StorageError>(())
        })?;
        self.queued_intent_by_message
            .retain(|_, (queued_group, _)| queued_group != group_id);
        self.queued_intent_by_pending
            .retain(|_, (queued_group, _)| queued_group != group_id);
        self.drop_self_remove_auto_commit_schedules_for_group(group_id);
        self.schedule_pending_convergence_group(group_id);
        Ok(())
    }

    pub(crate) fn disband_request_pending(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        Ok(self
            .storage
            .disband_request(group_id)?
            .is_some_and(|request| request.status == DisbandRequestStatus::Pending))
    }

    pub(crate) fn disband_candidate_pending(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        Ok(!self.storage.list_disband_candidates(group_id)?.is_empty())
    }

    pub fn disband_request(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<DisbandRequest>, EngineError> {
        Ok(self.storage.disband_request(group_id)?)
    }

    /// Whether outbound group work is gated while a terminal request or
    /// authenticated terminal candidate awaits convergence.
    ///
    /// This deliberately differs from [`Self::disband_request`]: an inbound
    /// disband Commit can make the group non-sendable before this account has a
    /// local request of its own.
    pub fn disbanding_in_progress(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        Ok(self.disband_request_pending(group_id)? || self.disband_candidate_pending(group_id)?)
    }

    /// Account identifiers for leaves that do not yet advertise lifecycle-v1.
    ///
    /// This is an advisory read. The enable commit repeats the same check under
    /// the engine mutation lock so a concurrent roster change remains safe.
    pub fn disbanding_support_blockers(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<cgka_traits::MemberId>, EngineError> {
        self.ensure_group_live(group_id)?;
        if self.storage.disband_tombstone(group_id)?.is_some() {
            return Ok(Vec::new());
        }
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        crate::app_components::lifecycle_support_blockers(&mls_group)
    }

    pub fn acknowledge_disband_failure(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        let Some(request) = self.storage.disband_request(group_id)? else {
            return Ok(false);
        };
        if !matches!(request.status, DisbandRequestStatus::Failed(_)) {
            return Ok(false);
        }
        self.storage.clear_disband_request(group_id)?;
        Ok(true)
    }

    fn fail_disband_request(
        &self,
        mut request: DisbandRequest,
        reason: DisbandFailureReason,
    ) -> Result<(), EngineError> {
        request.status = DisbandRequestStatus::Failed(reason);
        request.last_prepared_epoch = None;
        self.storage.put_disband_request(&request)?;
        Ok(())
    }

    /// Prepare the pending request against the currently selected active
    /// branch. Returns `None` while another mutation owns the group, while
    /// Unrecoverable is paused, or once a disband candidate is already in its
    /// convergence pass.
    pub(crate) async fn prepare_pending_disband(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<SendResult>, EngineError> {
        let Some(mut request) = self.storage.disband_request(group_id)? else {
            return Ok(None);
        };
        if request.status != DisbandRequestStatus::Pending
            || self.disband_candidate_pending(group_id)?
        {
            return Ok(None);
        }
        let Some(state) = self.epoch_manager.state(group_id) else {
            self.fail_disband_request(request, DisbandFailureReason::NoLongerMember)?;
            return Ok(None);
        };
        if matches!(state, EpochState::Unrecoverable(_)) {
            return Ok(None);
        }
        if !matches!(state, EpochState::Stable { .. }) {
            return Ok(None);
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let Some(mut mls_group) = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
        else {
            self.fail_disband_request(request, DisbandFailureReason::NoLongerMember)?;
            return Ok(None);
        };
        if crate::app_components::lifecycle_of_group(&mls_group)? != Some(GroupLifecycleV1::Active)
        {
            return Ok(None);
        }
        if crate::app_components::require_admin(&mls_group, group_id, self.identity.self_id())
            .is_err()
        {
            let member = mls_group.members().any(|member| {
                BasicCredential::try_from(member.credential).is_ok_and(|credential| {
                    credential.identity() == self.identity.self_id().as_slice()
                })
            });
            self.fail_disband_request(
                request,
                if member {
                    DisbandFailureReason::NoLongerAdmin
                } else {
                    DisbandFailureReason::NoLongerMember
                },
            )?;
            return Ok(None);
        }

        let source_epoch = EpochId(mls_group.epoch().as_u64());
        let own_leaf = mls_group.own_leaf_index();
        let removals = mls_group
            .members()
            .filter_map(|member| (member.index != own_leaf).then_some(member.index))
            .collect::<Vec<_>>();
        let committer_admin =
            crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let proposals = vec![
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                GROUP_LIFECYCLE_COMPONENT_ID,
                encode_group_lifecycle_v1(GroupLifecycleV1::Disbanded),
            ))),
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                GROUP_ADMIN_POLICY_COMPONENT_ID,
                crate::app_components::encode_admin_policy(&[committer_admin])?,
            ))),
        ];

        let guard = PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let context = crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let commit = self
            .stage_commit_with_app_data_updates(
                &mut mls_group,
                &provider,
                removals,
                Vec::new(),
                proposals,
                "disband",
            )?
            .0;
        let staged = mls_group
            .pending_commit()
            .ok_or_else(|| EngineError::Backend("disband produced no pending commit".into()))?;
        crate::app_components::require_admin_for_staged_commit(
            &mls_group,
            group_id,
            Some(self.identity.self_id()),
            staged,
        )?;
        crate::app_components::validate_admin_leaf_coupling_for_staged_commit(
            &mls_group, group_id, staged,
        )?;
        crate::app_components::validate_app_component_integrity_for_staged_commit(
            &mls_group, group_id, staged,
        )?;
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            &mls_group, staged, own_leaf,
        )?;
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
        let wrapped = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes.clone(),
                    aad: vec![],
                },
                &context,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let wrapped = crate::message_processor::route_wrapped_group_message(wrapped, &context);
        self.record_sent_openmls_message(&wrapped, &commit_bytes, group_id, source_epoch)?;

        let former_members = deduplicated_roster(&self.storage.get_group(group_id)?.members);
        let candidate = DisbandCandidate {
            group_id: group_id.clone(),
            source_epoch,
            commit_id: wrapped.id.clone(),
            content_commit_id: crate::message_processor::content_dedup_id(&commit_bytes),
            commit_digest: Sha256::digest(&commit_bytes).into(),
            actor: self.identity.self_id().clone(),
            local_was_committer_leaf: true,
            former_members,
        };
        request.last_prepared_epoch = Some(source_epoch);
        self.storage.with_transaction(|storage| {
            storage.put_disband_candidate(&candidate)?;
            storage.put_disband_request(&request)?;
            Ok::<(), StorageError>(())
        })?;

        let target_epoch = EpochId(source_epoch.0.saturating_add(1));
        let pending = self.epoch_manager.next_pending_ref();
        self.invalidate_deferred_peel_candidate_cache(group_id);
        self.epoch_manager.begin_pending(
            group_id.clone(),
            source_epoch,
            target_epoch,
            StagedCommitHandle::from_bytes(group_id.as_slice().to_vec()),
            pending,
            crate::epoch_manager::PendingKind::Disband,
            self.current_audit_context.clone(),
        )?;
        self.track_pending_origin_commit(pending, wrapped.id.clone());
        guard.disarm();
        Ok(Some(SendResult::GroupEvolution {
            msg: wrapped,
            welcomes: vec![],
            pending,
        }))
    }

    /// Complete or retry a terminal intent after a frozen convergence pass has
    /// selected and applied canonical state.
    pub(crate) fn settle_disband_after_convergence(
        &mut self,
        group_id: &GroupId,
        accepted_commit_ids: &[String],
        origin_commit_id: Option<&cgka_traits::MessageId>,
    ) -> Result<bool, EngineError> {
        let candidates = self.storage.list_disband_candidates(group_id)?;
        if candidates.is_empty() {
            return Ok(false);
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let Some(mut mls_group) = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
        else {
            if self.storage.disband_tombstone(group_id)?.is_some() {
                return Ok(true);
            }
            return Err(EngineError::UnknownGroup(group_id.clone()));
        };

        if crate::app_components::lifecycle_of_group(&mls_group)?
            != Some(GroupLifecycleV1::Disbanded)
        {
            // An active branch won. The irreversible local request survives,
            // but every epoch-bound terminal candidate is stale.
            self.storage.clear_disband_candidates(group_id)?;
            if let Some(mut request) = self.storage.disband_request(group_id)?
                && request.status == DisbandRequestStatus::Pending
            {
                request.last_prepared_epoch = None;
                self.storage.put_disband_request(&request)?;
                self.schedule_pending_convergence_group(group_id);
            }
            return Ok(false);
        }

        let selected = origin_commit_id
            .and_then(|commit_id| {
                candidates.iter().find(|candidate| {
                    &candidate.commit_id == commit_id || &candidate.content_commit_id == commit_id
                })
            })
            .or_else(|| {
                accepted_commit_ids.iter().rev().find_map(|commit_id_hex| {
                    candidates.iter().find(|candidate| {
                        hex::encode(candidate.commit_id.as_slice()) == *commit_id_hex
                            || hex::encode(candidate.content_commit_id.as_slice()) == *commit_id_hex
                    })
                })
            })
            .or_else(|| {
                let epoch = EpochId(mls_group.epoch().as_u64());
                let mut matching_epoch = candidates
                    .iter()
                    .filter(|candidate| candidate.source_epoch.0.saturating_add(1) == epoch.0);
                let only = matching_epoch.next()?;
                matching_epoch.next().is_none().then_some(only)
            })
            .cloned()
            .ok_or_else(|| {
                EngineError::Backend(
                    "selected Disbanded state has no authenticated candidate evidence".into(),
                )
            })?;
        let epoch = EpochId(mls_group.epoch().as_u64());
        let tombstone = cgka_traits::DisbandTombstone {
            epoch,
            actor: selected.actor.clone(),
            origin_commit_id: Some(selected.commit_id.clone()),
            commit_digest: selected.commit_digest,
            local_was_committer_leaf: selected.local_was_committer_leaf,
            former_members: selected.former_members.clone(),
            // The live `GroupDisbanded` this settle emits reaches the
            // application through a later, non-transactional drain that can
            // drop the whole batch (a failed publish gate, or a crash). Marking
            // here would suppress the one hydration replay that reconciles
            // exactly that loss, so the guard is born unannounced.
            announced: false,
        };

        self.storage
            .with_transaction(|storage| -> Result<(), EngineError> {
                storage.put_disband_tombstone(group_id, &tombstone)?;
                let mut group = storage.get_group(group_id)?;
                group.epoch = epoch;
                group.members = tombstone.former_members.clone();
                group.removed = false;
                group.unrecoverable = false;
                group.disbanded = Some(tombstone.clone());
                storage.put_group(&group)?;
                storage.clear_disband_request(group_id)?;
                storage.clear_disband_candidates(group_id)?;
                storage.clear_leave_request(group_id)?;
                for queued in storage.list_queued_outbound_intents(group_id)? {
                    storage.delete_queued_outbound_intent(&queued.id)?;
                }
                for fanout in storage.list_outbound_fanouts_for_group(group_id)? {
                    storage.delete_outbound_fanout(fanout.message_id())?;
                }
                for welcome in storage
                    .list_welcomes()?
                    .into_iter()
                    .filter(|welcome| &welcome.group_id == group_id)
                {
                    let _ = storage.take_welcome(&welcome.message_id)?;
                }
                storage.delete_convergence_pass(group_id)?;
                storage.delete_deferred_peel_generation(group_id)?;
                for snapshot in storage.list_group_snapshots(group_id)? {
                    storage.release_group_snapshot(group_id, &snapshot)?;
                }
                if let Some(maintenance) = storage.maintenance_storage() {
                    maintenance.delete_group_maintenance(group_id)?;
                    for obligation in
                        maintenance.list_maintenance_obligations_for_group(group_id)?
                    {
                        maintenance.delete_maintenance_obligation(&obligation.id)?;
                    }
                    for evolution in maintenance.list_group_evolutions_for_group(group_id)? {
                        maintenance.delete_group_evolution(&evolution.id)?;
                    }
                    for fanout in maintenance.list_transport_fanouts()? {
                        if fanout.group_id.as_ref() == Some(group_id) {
                            maintenance.delete_transport_fanout(&fanout.id)?;
                        }
                    }
                }
                let tx_provider =
                    EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                mls_group.delete(tx_provider.storage()).map_err(|error| {
                    EngineError::Backend(format!("delete MLS group: {error:?}"))
                })?;
                Ok(())
            })?;

        self.transport_group_id_index
            .retain(|_, mapped_group| mapped_group != group_id);
        // A disbanded group must be unroutable across restarts too; the
        // durable delete shares the in-memory retain's best-effort policy
        // (the tombstone keeps inbound handling terminal either way).
        let _ = self
            .storage
            .delete_transport_group_routes_for_group(group_id);
        self.route_backfill_pending.remove(group_id);
        self.pending_convergence_groups.remove(group_id);
        self.invalidate_deferred_peel_candidate_cache(group_id);
        self.engine_metrics.forget_group(group_id);
        self.leaving_groups.remove(group_id);
        self.drop_self_remove_auto_commit_schedules_for_group(group_id);
        self.epoch_manager.mark_disbanded(group_id, epoch)?;
        self.push_group_state_change(
            group_id,
            epoch,
            Some(tombstone.actor),
            cgka_traits::GroupStateChange::GroupDisbanded,
            tombstone.origin_commit_id,
        );
        Ok(true)
    }
}

pub(crate) fn deduplicated_roster(
    members: &[cgka_traits::group::Member],
) -> Vec<cgka_traits::group::Member> {
    let mut seen = HashSet::new();
    members
        .iter()
        .filter(|member| seen.insert(member.id.clone()))
        .cloned()
        .collect()
}
