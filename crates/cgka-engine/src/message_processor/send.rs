//! Outbound send path for [`Engine`]: dispatch `SendIntent` and stage commits.
//!
//! Outbound intents are checked against local epoch state and unresolved
//! convergence inputs before any OpenMLS mutation.

use super::route_wrapped_group_message;
use crate::engine::Engine;
use crate::group_lifecycle::{self};
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::{CommitOrderingKey, GroupStateChange, SendIntent, SendResult};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::EngineError;
use cgka_traits::peeler::GroupMessageMetadata;
use cgka_traits::storage::{LeaveRequest, StorageError, StorageProvider};
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId};
use openmls::group::MlsGroup;
use openmls::prelude::{BasicCredential, MlsMessageOut};
use std::collections::HashSet;
use tls_codec::Serialize as _;

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_send_ready(
        &mut self,
        intent: SendIntent,
    ) -> Result<SendResult, EngineError> {
        match intent {
            SendIntent::AppMessage { group_id, payload } => {
                self.do_send_app_message(group_id, payload).await
            }
            SendIntent::Invite {
                group_id,
                key_packages,
            } => self.do_send_invite(group_id, key_packages).await,
            SendIntent::RemoveMembers { group_id, members } => {
                self.do_send_remove_members(group_id, members).await
            }
            SendIntent::Leave { group_id } => self.do_send_leave(group_id).await,
            SendIntent::UpdateAppComponents { group_id, updates } => {
                self.do_send_update_app_components(group_id, updates).await
            }
            SendIntent::UpdateGroupData {
                group_id,
                name,
                description,
            } => {
                self.do_send_update_group_data(group_id, name, description)
                    .await
            }
        }
    }

    async fn do_send_invite(
        &mut self,
        group_id: GroupId,
        key_packages: Vec<cgka_traits::engine::KeyPackage>,
    ) -> Result<SendResult, EngineError> {
        // Load group + require Stable.
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "Invite",
                    reason: "invite requires Stable",
                },
            ));
        }
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;

        // Validate capabilities (same rule as create_group — see Risk #1
        // capability doc). The group's required capabilities cover required MLS
        // primitives and required app components; additionally fold in the
        // per-member role capabilities the agent-text-stream-QUIC component's
        // `required_member_roles` mask demands (#177,
        // agent-text-stream-quic-v1.md): a client MUST NOT invite a member whose
        // KeyPackage does not advertise every required role capability.
        let existing = self.storage.get_group(&group_id)?;
        let mut required = existing.required_capabilities.clone();
        merge_capabilities(
            &mut required,
            &crate::capability_manager::required_role_capabilities_from_group(&mls_group),
        );
        let mut parsed_kps = Vec::with_capacity(key_packages.len());
        for kp in &key_packages {
            let parsed = self.parse_key_package(kp)?;
            let had = crate::capabilities::capabilities_of_key_package(&parsed);
            let missing = required.missing_from(&had);
            if !missing.is_empty() {
                return Err(EngineError::MissingRequiredCapabilities {
                    required: Box::new(required),
                    had: Box::new(had),
                });
            }
            parsed_kps.push(parsed);
        }

        // Record the pre-commit epoch so a later same-epoch commit can be
        // compared against this locally produced branch.
        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        // Arm the cleanup guard before creating the snapshot so the snapshot is
        // released on early return / cancellation even before a pending commit
        // is staged.
        let mut pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, &group_id, pre_commit_epoch)?;
        pending_commit_guard.set_snapshot(recovery_snapshot.clone());
        self.audit_snapshot_created(
            &group_id,
            &recovery_snapshot,
            pre_commit_epoch,
            "pre_invite_commit",
        );
        self.epoch_manager
            .record_committed_from(&group_id, pre_commit_epoch);
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        // Stage the add-members commit. Publish-before-apply keeps
        // `mls_group` at the pre-commit epoch with the staged commit attached.
        // Wrap reads exporter from the still-current (pre-stage) epoch,
        // which is the right key for receivers to derive when peeling
        // (they're at the same pre-commit epoch when they decrypt the
        // wrap; only after they apply the inner commit do they advance).
        let (commit_out, welcome_out, _gi) = mls_group
            .add_members(&provider, &self.identity.signer, &parsed_kps)
            .map_err(|e| EngineError::Backend(format!("add_members: {e:?}")))?;

        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let welcome_bytes = welcome_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let commit_msg = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes.clone(),
                    aad: vec![],
                },
                &pre_commit_ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let commit_msg = route_wrapped_group_message(commit_msg, &pre_commit_ctx);
        self.record_sent_openmls_message(
            &commit_msg,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;

        let mut welcomes = Vec::with_capacity(parsed_kps.len());
        let welcome_relays = crate::group_lifecycle::welcome_relays_for_group(&mls_group)?;
        for (source_kp, parsed_kp) in key_packages.iter().zip(parsed_kps.iter()) {
            let recipient = {
                let bc = BasicCredential::try_from(parsed_kp.leaf_node().credential().clone())
                    .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
                MemberId::new(bc.identity().to_vec())
            };
            let payload = EncryptedPayload {
                ciphertext: welcome_bytes.clone(),
                aad: vec![],
            };
            let wrapped = if let Some(metadata) =
                crate::group_lifecycle::welcome_metadata_for_key_package(
                    source_kp,
                    welcome_relays.as_deref(),
                )? {
                self.peeler
                    .wrap_welcome_with_metadata(&payload, &recipient, &metadata)
                    .await
            } else {
                self.peeler.wrap_welcome(&payload, &recipient).await
            }
            .map_err(EngineError::Peeler)?;
            self.record_sent_message(&wrapped, &group_id, pre_commit_epoch)?;
            welcomes.push(wrapped);
        }

        // Cache invitees' capabilities NOW so `feature_status` reflects the
        // pending invite immediately. Update the Marmot record with the
        // projected post-merge member list — `members()` and
        // `feature_status` walk this list, and users expect the API to
        // reflect "what I just asked for" while the publish is pending.
        // Epoch stays at the pre-merge value; that updates on confirm.
        // On `publish_failed`, the engine re-derives from the (still-
        // unmerged) MLS state, which naturally drops the projection.
        crate::capability_manager::cache_from_key_packages(
            &self.storage,
            &group_id,
            &parsed_kps,
            self.ciphersuite,
        )?;
        let mut group_record = existing;
        group_record.members =
            crate::group_lifecycle::projected_members_with_pending(&mls_group, &parsed_kps)?;
        self.storage.put_group(&group_record)?;

        // State: begin pending at the projected new epoch via EpochManager.
        // The MLS group is still at the pre-commit epoch, so the projected
        // post-merge epoch is +1.
        let prior_epoch = EpochId(mls_group.epoch().as_u64());
        let new_epoch = EpochId(prior_epoch.0.saturating_add(1));
        let commit_priority = mls_group
            .pending_commit()
            .map(crate::app_components::commit_ordering_priority_for_staged)
            .ok_or_else(|| EngineError::Backend("invite produced no pending commit".into()))?;
        let pending_ref = self.epoch_manager.next_pending_ref();
        let staged =
            cgka_traits::engine_state::StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.epoch_manager.begin_pending(
            group_id.clone(),
            prior_epoch,
            new_epoch,
            staged,
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
        self.audit_group(
            &group_id,
            crate::audit_helpers::epoch_state_changed_event(
                Some("stable"),
                "pending_publish",
                new_epoch,
                "begin_pending",
                Some(pending_ref),
                Some(crate::audit_helpers::pending_kind_str(
                    crate::epoch_manager::PendingKind::GroupEvolution,
                )),
            ),
        );
        self.track_pending_commit_for_recovery(
            pending_ref,
            group_id.clone(),
            prior_epoch,
            commit_msg.id.clone(),
            CommitOrderingKey::from_commit_bytes(
                prior_epoch,
                commit_priority,
                self.identity.self_id().clone(),
                &commit_bytes,
            ),
            recovery_snapshot,
        );
        // Buffer the additions so confirm_published emits an attributed
        // GroupStateChanged (and the app a kind-1210 row) once the commit merges.
        let added_changes = parsed_kps
            .iter()
            .filter_map(|kp| crate::identity::validated_member_id_of_leaf(kp.leaf_node()).ok())
            .map(|member| crate::engine::PendingGroupStateChange {
                actor: Some(self.identity.self_id().clone()),
                change: GroupStateChange::MemberAdded { member },
            })
            .collect();
        self.pending_state_changes
            .insert(pending_ref, added_changes);
        pending_commit_guard.disarm();

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes,
            pending: pending_ref,
        })
    }

    async fn do_send_remove_members(
        &mut self,
        group_id: GroupId,
        members: Vec<MemberId>,
    ) -> Result<SendResult, EngineError> {
        let mut target_set = HashSet::new();
        let mut unique_targets = Vec::new();
        for member in members {
            if target_set.insert(member.clone()) {
                unique_targets.push(member);
            }
        }
        if unique_targets.is_empty() {
            return Err(EngineError::Other(
                "remove requires at least one member".into(),
            ));
        }
        if unique_targets
            .iter()
            .any(|member| member == self.identity.self_id())
        {
            return Err(EngineError::Other(
                "use SendIntent::Leave to remove the local member".into(),
            ));
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "RemoveMembers",
                    reason: "remove members requires Stable",
                },
            ));
        }

        let existing = self.storage.get_group(&group_id)?;
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;
        let admins = crate::app_components::admins_of_group(&mls_group)?;

        let mut leaf_indices = Vec::with_capacity(unique_targets.len());
        let mut found = HashSet::new();
        for member in mls_group.members() {
            let basic = BasicCredential::try_from(member.credential)
                .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
            let member_id = MemberId::new(basic.identity().to_vec());
            if target_set.contains(&member_id) {
                leaf_indices.push(member.index);
                found.insert(member_id);
            }
        }
        for member in &unique_targets {
            if !found.contains(member) {
                return Err(EngineError::UnknownMember {
                    group_id: group_id.clone(),
                    member: member.clone(),
                });
            }
        }

        let target_admins = unique_targets
            .iter()
            .map(crate::app_components::admin_pubkey_from_member_id)
            .collect::<Result<Vec<_>, _>>()?;
        if admins
            .iter()
            .all(|admin| target_admins.iter().any(|target| target == admin))
        {
            return Err(EngineError::AdminDepletion {
                group_id: group_id.clone(),
            });
        }

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        // Arm the cleanup guard before creating the snapshot so the snapshot is
        // released on early return / cancellation even before a pending commit
        // is staged.
        let mut pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, &group_id, pre_commit_epoch)?;
        pending_commit_guard.set_snapshot(recovery_snapshot.clone());
        self.audit_snapshot_created(
            &group_id,
            &recovery_snapshot,
            pre_commit_epoch,
            "pre_remove_members_commit",
        );
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        let (commit_out, _welcome_opt, _gi) = mls_group
            .remove_members(&provider, &self.identity.signer, &leaf_indices)
            .map_err(|e| EngineError::Backend(format!("remove_members: {e:?}")))?;

        let staged_commit = mls_group
            .pending_commit()
            .ok_or_else(|| EngineError::Backend("remove produced no pending commit".into()))?;
        crate::app_components::validate_admin_leaf_coupling_for_staged_commit(
            &mls_group,
            &group_id,
            staged_commit,
        )?;
        let commit_priority =
            crate::app_components::commit_ordering_priority_for_staged(staged_commit);
        self.epoch_manager
            .record_committed_from(&group_id, pre_commit_epoch);

        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let commit_msg = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes.clone(),
                    aad: vec![],
                },
                &pre_commit_ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let commit_msg = route_wrapped_group_message(commit_msg, &pre_commit_ctx);
        self.record_sent_openmls_message(
            &commit_msg,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;

        let mut group_record = existing;
        group_record
            .members
            .retain(|member| !target_set.contains(&member.id));
        self.storage.put_group(&group_record)?;

        let prior_epoch = EpochId(mls_group.epoch().as_u64());
        let new_epoch = EpochId(prior_epoch.0.saturating_add(1));
        let pending_ref = self.epoch_manager.next_pending_ref();
        let staged =
            cgka_traits::engine_state::StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.epoch_manager.begin_pending(
            group_id.clone(),
            prior_epoch,
            new_epoch,
            staged,
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
        self.audit_group(
            &group_id,
            crate::audit_helpers::epoch_state_changed_event(
                Some("stable"),
                "pending_publish",
                new_epoch,
                "begin_pending",
                Some(pending_ref),
                Some(crate::audit_helpers::pending_kind_str(
                    crate::epoch_manager::PendingKind::GroupEvolution,
                )),
            ),
        );
        self.track_pending_commit_for_recovery(
            pending_ref,
            group_id.clone(),
            prior_epoch,
            commit_msg.id.clone(),
            CommitOrderingKey::from_commit_bytes(
                prior_epoch,
                commit_priority,
                self.identity.self_id().clone(),
                &commit_bytes,
            ),
            recovery_snapshot,
        );
        let removed_changes = unique_targets
            .iter()
            .cloned()
            .map(|member| crate::engine::PendingGroupStateChange {
                actor: Some(self.identity.self_id().clone()),
                change: GroupStateChange::MemberRemoved { member },
            })
            .collect();
        self.pending_state_changes
            .insert(pending_ref, removed_changes);
        pending_commit_guard.disarm();

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes: vec![],
            pending: pending_ref,
        })
    }

    async fn do_send_leave(&mut self, group_id: GroupId) -> Result<SendResult, EngineError> {
        let mut existing = self.load_leave_request_state(&group_id)?;
        let requested_at_ms = existing.as_ref().map_or_else(
            || self.convergence_now_ms(),
            |request| request.requested_at_ms,
        );
        let current_epoch = self
            .storage
            .get_group(&group_id)
            .map_err(|e| match e {
                StorageError::NotFound => EngineError::UnknownGroup(group_id.clone()),
                other => EngineError::Storage(other),
            })?
            .epoch;
        if existing
            .as_ref()
            .and_then(|request| request.last_proposed_epoch)
            == Some(current_epoch)
        {
            self.leaving_groups.insert(group_id.clone());
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Leaving",
                    to: "Leave",
                    reason: "leave already requested for current epoch",
                },
            ));
        }

        let (msg, proposal_bytes, proposed_epoch) =
            self.prepare_self_remove_proposal(&group_id).await?;
        let request = existing.get_or_insert_with(|| LeaveRequest {
            group_id: group_id.clone(),
            requested_at_ms,
            last_proposed_epoch: None,
        });
        request.last_proposed_epoch = Some(proposed_epoch);
        self.record_sent_openmls_message_with_leave_request(
            &msg,
            proposal_bytes.as_slice(),
            &group_id,
            proposed_epoch,
            request,
        )?;

        Ok(SendResult::Proposal { msg })
    }

    pub(crate) async fn prepare_self_remove_proposal(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(TransportMessage, Vec<u8>, EpochId), EngineError> {
        // MIP-03 SelfRemove only. The legacy Remove-self flow is not exposed
        // by this engine.
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "Leave",
                    reason: "leave requires Stable",
                },
            ));
        }

        // member-departure.md:23-26 — an admin must leave the admin set before
        // using SelfRemove. This is stricter than merely preserving a non-empty
        // admin set: it prevents an admin identity from departing while still
        // present in the prior epoch's admin policy.
        let self_pubkey =
            crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let admins = crate::app_components::admins_of_group(&mls_group)?;
        let i_am_admin = admins.iter().any(|k| k == &self_pubkey);
        if i_am_admin {
            return Err(EngineError::AdminCannotSelfRemove {
                group_id: group_id.clone(),
            });
        }

        let proposal = mls_group
            .leave_group_via_self_remove(&provider, &self.identity.signer)
            .map_err(|e| EngineError::Backend(format!("self_remove: {e:?}")))?;

        let bytes = proposal
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let ctx = crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let wrapped = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: bytes.clone(),
                    aad: vec![],
                },
                &ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let wrapped = route_wrapped_group_message(wrapped, &ctx);

        Ok((wrapped, bytes, EpochId(mls_group.epoch().as_u64())))
    }

    pub(crate) async fn try_auto_repropose_leave_request(&mut self, group_id: &GroupId) {
        if let Err(err) = self.auto_repropose_leave_request(group_id).await {
            tracing::warn!(
                target: "cgka_engine::leave_request",
                method = "try_auto_repropose_leave_request",
                error_kind = crate::audit_helpers::engine_error_kind(&err),
                "failed to re-propose durable leave request"
            );
        }
    }

    async fn auto_repropose_leave_request(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        let Some(mut request) = self.load_leave_request_state(group_id)? else {
            self.leaving_groups.remove(group_id);
            return Ok(false);
        };
        let group = match self.storage.get_group(group_id) {
            Ok(group) => group,
            Err(StorageError::NotFound) => {
                self.clear_leave_request_state(group_id)?;
                return Ok(false);
            }
            Err(e) => return Err(EngineError::Storage(e)),
        };
        if !group
            .members
            .iter()
            .any(|member| &member.id == self.identity.self_id())
        {
            self.clear_leave_request_state(group_id)?;
            return Ok(false);
        }
        self.leaving_groups.insert(group_id.clone());

        if let Some(state) = self.epoch_manager.state(group_id)
            && !state.is_stable()
        {
            return Ok(false);
        }
        if request.last_proposed_epoch == Some(group.epoch) {
            return Ok(false);
        }

        let (msg, proposal_bytes, proposed_epoch) =
            self.prepare_self_remove_proposal(group_id).await?;
        request.last_proposed_epoch = Some(proposed_epoch);
        self.record_sent_openmls_message_with_leave_request(
            &msg,
            proposal_bytes.as_slice(),
            group_id,
            proposed_epoch,
            &request,
        )?;
        self.auto_proposal_buf.push_back(msg);
        Ok(true)
    }

    async fn do_send_app_message(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        // Direct sending still requires Stable after convergence gating.
        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "send",
                    reason: "send requires Stable",
                },
            ));
        }

        let app_event =
            crate::app_payload::validate_app_payload_for_sender(&payload, self.identity.self_id())?;
        let wrap_metadata = GroupMessageMetadata::application(
            app_event.created_at,
            crate::app_components::message_retention_seconds_of_group(&mls_group)?,
        );

        let out: MlsMessageOut = mls_group
            .create_message(&provider, &self.identity.signer, &payload)
            .map_err(|e| EngineError::Backend(format!("create_message: {e:?}")))?;
        let out_bytes = out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let ctx = group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let wrapped = self
            .peeler
            .wrap_group_message_with_metadata(
                &EncryptedPayload {
                    ciphertext: out_bytes.clone(),
                    aad: vec![],
                },
                &ctx,
                &wrap_metadata,
            )
            .await
            .map_err(EngineError::Peeler)?;

        let wrapped = route_wrapped_group_message(wrapped, &ctx);
        self.record_sent_openmls_message(
            &wrapped,
            out_bytes.as_slice(),
            &group_id,
            EpochId(mls_group.epoch().as_u64()),
        )?;

        Ok(SendResult::ApplicationMessage { msg: wrapped })
    }
}

/// Fold every capability in `extra` into `required` (set union). Used to add the
/// agent-stream `required_member_roles` role capabilities to a group's required
/// capability set before the per-KeyPackage invite check and the join-time
/// self-check (#177).
pub(crate) fn merge_capabilities(
    required: &mut cgka_traits::capabilities::GroupCapabilities,
    extra: &cgka_traits::capabilities::GroupCapabilities,
) {
    required.proposals.extend(extra.proposals.iter().copied());
    required.extensions.extend(extra.extensions.iter().copied());
    for id in &extra.app_components.ids {
        required.app_components.insert(*id);
    }
}
