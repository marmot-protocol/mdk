//! The link Commit, for `SendIntent::LinkDevice` (mdk#2628 item 3.3b, D21):
//! one admin Commit in the account's device group that adds a newly linked
//! device and writes its roster entry. That Commit is the link's approval
//! (ideas/multi-device.md, Scene 5 step 1).
//!
//! A first link needs none of this: the device group's founding create writes
//! both devices' entries. Every later link goes through here, so a device's
//! membership and its roster record are one decision.
//!
//! The checks before staging name the reason for a refusal: the group
//! requires the roster, the KeyPackage is this account's and advertises what
//! the group requires, and the update sets exactly one device entry. The
//! staged Commit then meets the sender rule for every own device-group Commit
//! that adds a leaf (`commit_class::authorize_own_staged_commit`: one Add, by
//! value, whose entry the same Commit sets for a new slot) and the
//! resulting-state rules: the roster's own invariants (at most 20 devices, no
//! slot both a device and rejected), one account per device group, and the
//! leaf limit.
//!
//! A link is never queued. While the device group has a Commit in flight or
//! convergence input to settle, it is refused with
//! [`EngineError::LinkDeviceUnsettled`] and the app retries while the new
//! device still waits for its Welcome. A queued link could drain after that
//! wait ended and add a device that never joins.
//!
//! The Commit carries an AppDataUpdate, so it is `privileged` and needs an
//! active admin: the device group's account. Like a same-account Add, the
//! intent keeps no `OwnCommitIntent`, so when branch selection supersedes it
//! nothing re-issues it; the app records whether the link settled.
//!
//! `SendIntent::UnlinkDevice` is its undo (D40): when the new device made no
//! Commit in the device group by the link's deadline, the device that
//! approved the link removes its leaf and its roster entry in one admin
//! Commit, under the same rules: never queued, built from those two
//! proposals only, and checked as every own device-group Commit is.

use crate::engine::Engine;
use crate::message_processor::route_wrapped_group_message;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceRosterOperationV1, decode_device_roster_update_v1,
    decode_device_roster_v1,
};
use cgka_traits::engine::{KeyPackage, SendResult};
use cgka_traits::engine_state::{
    EpochState, InvalidTransition, PendingStateRef, StagedCommitHandle,
};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::EncryptedPayload;
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateProposal, Proposal};
use openmls_traits::OpenMlsProvider as _;
use tls_codec::Serialize as _;

const INTENT: &str = "LinkDevice";
const UNLINK_INTENT: &str = "UnlinkDevice";

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_send_link_device(
        &mut self,
        group_id: GroupId,
        key_package: KeyPackage,
        roster_update: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mut mls_group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        // A Commit in flight: refused like unsettled convergence, never
        // queued. The terminal states were refused before this.
        if self
            .epoch_manager
            .state(&group_id)
            .is_some_and(|state| !matches!(state, EpochState::Stable { .. }))
        {
            return Err(EngineError::LinkDeviceUnsettled { group_id });
        }
        if !crate::app_components::group_requires_device_roster(&mls_group)? {
            return Err(EngineError::InvalidTransition(InvalidTransition {
                from: "DeviceRosterNotRequired",
                to: INTENT,
                reason: "the group does not require marmot.account.device-roster.v1",
            }));
        }
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;
        let existing = self.storage.get_group(&group_id)?;
        let parsed_kp = self.link_key_package(&mls_group, &existing, &key_package)?;
        validate_link_roster_update(&roster_update)?;

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let roster_proposal = Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
            DEVICE_ROSTER_COMPONENT_ID,
            roster_update,
        )));
        // Built from these two proposals only: nothing pending in the
        // proposal store rides along.
        let (commit_out, welcome_out) = self.stage_exact_commit_with_app_data_updates(
            &mut mls_group,
            &provider,
            Vec::new(),
            vec![parsed_kp.clone()],
            vec![roster_proposal],
            "link_device",
        )?;
        let welcome_out = welcome_out
            .ok_or_else(|| EngineError::Backend("link device produced no Welcome".into()))?;
        let own_leaf_index = mls_group.own_leaf_index();
        let staged_commit = mls_group
            .pending_commit()
            .ok_or_else(|| EngineError::Backend("link device produced no pending commit".into()))?;
        crate::commit_class::authorize_own_staged_commit(
            &mls_group,
            &group_id,
            self.identity.self_id(),
            staged_commit,
        )?;
        crate::app_components::validate_app_component_integrity_for_staged_commit(
            &mls_group,
            &group_id,
            staged_commit,
        )?;
        crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
            staged_commit,
            &mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            &mls_group,
            staged_commit,
            own_leaf_index,
        )?;
        let parsed_kps = vec![parsed_kp];
        crate::capability_manager::check_key_package_profiles(
            &self.storage,
            &group_id,
            &parsed_kps,
        )?;

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
        let key_packages = vec![key_package];
        let welcomes = self
            .wrap_staged_welcomes(
                &mls_group,
                &group_id,
                &commit_msg.id,
                pre_commit_epoch,
                &welcome_bytes,
                &key_packages,
                &parsed_kps,
            )
            .await?;

        // `members()` shows the linked device while the publish is pending;
        // `confirm_published` and `publish_failed` re-derive the record from
        // MLS state.
        let mut group_record = existing;
        group_record.members =
            crate::group_lifecycle::projected_members_with_pending(&mls_group, &parsed_kps)?;
        self.storage.put_group(&group_record)?;

        let pending_ref =
            self.begin_device_group_commit(&group_id, pre_commit_epoch, &commit_msg)?;
        pending_commit_guard.disarm();

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes,
            pending: pending_ref,
        })
    }

    pub(crate) async fn do_send_unlink_device(
        &mut self,
        group_id: GroupId,
        leaf_signature_key: Vec<u8>,
        roster_update: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mut mls_group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        if self
            .epoch_manager
            .state(&group_id)
            .is_some_and(|state| !matches!(state, EpochState::Stable { .. }))
        {
            return Err(EngineError::LinkDeviceUnsettled { group_id });
        }
        if !crate::app_components::group_requires_device_roster(&mls_group)? {
            return Err(EngineError::InvalidTransition(InvalidTransition {
                from: "DeviceRosterNotRequired",
                to: UNLINK_INTENT,
                reason: "the group does not require marmot.account.device-roster.v1",
            }));
        }
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;
        let existing = self.storage.get_group(&group_id)?;
        let account = crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let removed = crate::own_account_devices::own_account_leaves(
            &mls_group,
            std::slice::from_ref(&leaf_signature_key),
            &account,
        )?;
        validate_unlink_roster_update(&mls_group, &roster_update)?;

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let roster_proposal = Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
            DEVICE_ROSTER_COMPONENT_ID,
            roster_update,
        )));
        let (commit_out, welcome_out) = self.stage_exact_commit_with_app_data_updates(
            &mut mls_group,
            &provider,
            removed,
            Vec::new(),
            vec![roster_proposal],
            "unlink_device",
        )?;
        if welcome_out.is_some() {
            return Err(EngineError::Backend(
                "unlink device produced a Welcome".into(),
            ));
        }
        let own_leaf_index = mls_group.own_leaf_index();
        let staged_commit = mls_group.pending_commit().ok_or_else(|| {
            EngineError::Backend("unlink device produced no pending commit".into())
        })?;
        crate::commit_class::authorize_own_staged_commit(
            &mls_group,
            &group_id,
            self.identity.self_id(),
            staged_commit,
        )?;
        crate::app_components::validate_admin_leaf_coupling_for_staged_commit(
            &mls_group,
            &group_id,
            staged_commit,
        )?;
        crate::app_components::validate_app_component_integrity_for_staged_commit(
            &mls_group,
            &group_id,
            staged_commit,
        )?;
        crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
            staged_commit,
            &mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            &mls_group,
            staged_commit,
            own_leaf_index,
        )?;

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

        // `members()` drops the removed leaf while the publish is pending;
        // `confirm_published` and `publish_failed` re-derive the record from
        // MLS state.
        let mut group_record = existing;
        group_record.members = crate::group_lifecycle::marmot_members(&mls_group);
        group_record
            .members
            .retain(|member| member.credential != leaf_signature_key);
        self.storage.put_group(&group_record)?;

        let pending_ref =
            self.begin_device_group_commit(&group_id, pre_commit_epoch, &commit_msg)?;
        pending_commit_guard.disarm();

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes: Vec::new(),
            pending: pending_ref,
        })
    }

    /// Put the device group's staged link or unlink Commit pending publish.
    fn begin_device_group_commit(
        &mut self,
        group_id: &GroupId,
        pre_commit_epoch: EpochId,
        commit_msg: &cgka_traits::transport::TransportMessage,
    ) -> Result<PendingStateRef, EngineError> {
        let new_epoch = EpochId(pre_commit_epoch.0.saturating_add(1));
        let pending_ref = self.epoch_manager.next_pending_ref();
        self.invalidate_deferred_peel_candidate_cache(group_id);
        self.epoch_manager.begin_pending(
            group_id.clone(),
            pre_commit_epoch,
            new_epoch,
            StagedCommitHandle::from_bytes(group_id.as_slice().to_vec()),
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
        self.audit_group(
            group_id,
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
        self.track_pending_origin_commit(pending_ref, commit_msg.id.clone());
        Ok(pending_ref)
    }

    /// Parse the KeyPackage to link: this account's, on the group's profile,
    /// advertising everything the group requires, and not already a leaf.
    fn link_key_package(
        &self,
        mls_group: &MlsGroup,
        existing: &cgka_traits::group::Group,
        key_package: &KeyPackage,
    ) -> Result<openmls::prelude::KeyPackage, EngineError> {
        let account = crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let parsed = self.parse_key_package(key_package)?;
        if key_package.protocol_profile != existing.protocol_profile {
            return Err(EngineError::InvalidAccountIdentityProof(format!(
                "cannot link a {:?} KeyPackage into a {:?} group",
                key_package.protocol_profile, existing.protocol_profile
            )));
        }
        if crate::app_components::credential_account_pubkey(parsed.leaf_node().credential().clone())
            != Some(account)
        {
            return Err(EngineError::Other(
                "the KeyPackage to link belongs to another account".into(),
            ));
        }
        if mls_group
            .members()
            .any(|member| member.signature_key == parsed.leaf_node().signature_key().as_slice())
        {
            return Err(EngineError::Other(
                "the device to link is already in the device group".into(),
            ));
        }
        let mut required = existing.required_capabilities.clone();
        crate::capability_manager::merge_capabilities(
            &mut required,
            &crate::capability_manager::required_role_capabilities_from_group(mls_group),
        );
        let had = crate::capabilities::capabilities_of_key_package(&parsed);
        if !required.missing_from(&had).is_empty() {
            return Err(EngineError::MissingRequiredCapabilities {
                required: Box::new(required),
                had: Box::new(had),
            });
        }
        Ok(parsed)
    }
}

/// The link's roster update sets exactly one device entry. That the entry is
/// for a new slot and announces the linked KeyPackage is the sender rule
/// every own device-group Commit meets.
fn validate_link_roster_update(roster_update: &[u8]) -> Result<(), EngineError> {
    let update = decode_device_roster_update_v1(roster_update).map_err(|error| {
        EngineError::Serialize(format!("invalid device roster update: {error}"))
    })?;
    let [DeviceRosterOperationV1::SetDevice(..)] = update.operations() else {
        return Err(EngineError::Other(
            "invalid link roster update: it must set exactly one device entry".into(),
        ));
    };
    Ok(())
}

/// The unlink's roster update removes exactly one device entry, of a slot the
/// roster lists.
fn validate_unlink_roster_update(
    mls_group: &MlsGroup,
    roster_update: &[u8],
) -> Result<(), EngineError> {
    let update = decode_device_roster_update_v1(roster_update).map_err(|error| {
        EngineError::Serialize(format!("invalid device roster update: {error}"))
    })?;
    let [DeviceRosterOperationV1::RemoveDevice(slot)] = update.operations() else {
        return Err(EngineError::Other(
            "invalid unlink roster update: it must remove exactly one device entry".into(),
        ));
    };
    let roster =
        crate::app_components::app_component_data_of_group(mls_group, DEVICE_ROSTER_COMPONENT_ID)
            .ok_or_else(|| {
            EngineError::Other(
                "invalid device roster state: the required roster has no GroupContext state".into(),
            )
        })?;
    let roster = decode_device_roster_v1(&roster)
        .map_err(|error| EngineError::Serialize(format!("invalid device roster state: {error}")))?;
    if !roster.devices.contains_key(slot) {
        return Err(EngineError::Other(
            "invalid unlink roster update: the roster lists no such device".into(),
        ));
    }
    Ok(())
}
