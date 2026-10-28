//! Maintenance operations that need OpenMLS state.
//!
//! Scheduling and transport policy live above the engine, and so do the
//! account records it runs on: the session reads and writes them on its own
//! storage handle (mdk#2602). What stays here touches OpenMLS state too:
//! KeyPackage staging and promotion write OpenMLS material and the lifecycle
//! record in one transaction, and the own-leaf hash reads the MLS group.
//! Source-bound member recovery additionally owns an engine-side Preparing
//! descriptor before staging; only Prepared publications may escape to callers.

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::group_recovery::GroupRecoverySource;
use cgka_traits::maintenance::{
    KeyPackageLifecycleState, MaintenancePhase, PendingKeyPackageReplacement,
    RetainedKeyPackagePrivateMaterial, TransportFanoutTarget,
};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::Timestamp;
use cgka_traits::types::{EpochId, GroupId, MemberId};
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

impl<S: StorageProvider> Engine<S> {
    /// Record a fully validated, unexposed recovery before OpenMLS can stage it.
    pub(crate) fn prepare_member_recovery(
        &self,
        group_id: &GroupId,
        group: &openmls::group::MlsGroup,
        recoveries: &[cgka_traits::group_recovery::GroupMemberRecovery],
    ) -> Result<cgka_traits::maintenance::DurableGroupEvolution, EngineError> {
        use cgka_traits::maintenance::{
            DurableGroupEvolution, GroupEvolutionPhase, GroupEvolutionSemantic,
        };
        let source = recoveries
            .first()
            .ok_or_else(|| EngineError::Other("recovery requires member grants".into()))?;
        let mut grant_hashes = Vec::with_capacity(recoveries.len());
        let mut request_ids = Vec::with_capacity(recoveries.len());
        for recovery in recoveries {
            if recovery.source.epoch != source.source.epoch
                || recovery.source.epoch_authenticator_hash
                    != source.source.epoch_authenticator_hash
                || request_ids.contains(&recovery.request_id)
            {
                return Err(EngineError::GroupRecoverySourceMismatch {
                    group_id: group_id.clone(),
                });
            }
            let payload = cgka_traits::group_recovery::group_recovery_grant_bytes(
                group_id,
                self.identity.self_id(),
                &recovery.request_id,
                recovery.expires_at,
                &recovery.source,
                &recovery.key_package,
            )
            .map_err(EngineError::Peeler)?;
            let mut hash = Sha256::new();
            hash.update(b"mdk/group-recovery/evolution-grant/v1\0");
            hash.update((recovery.member.as_slice().len() as u64).to_be_bytes());
            hash.update(recovery.member.as_slice());
            hash.update((payload.len() as u64).to_be_bytes());
            hash.update(payload);
            hash.update((recovery.device_signature.len() as u64).to_be_bytes());
            hash.update(&recovery.device_signature);
            grant_hashes.push(<[u8; 32]>::from(hash.finalize()));
            request_ids.push(recovery.request_id);
        }
        grant_hashes.sort_unstable();
        request_ids.sort_unstable();
        let mut hash = Sha256::new();
        hash.update(b"mdk/group-recovery/evolution/v1\0");
        hash.update((group_id.as_slice().len() as u64).to_be_bytes());
        hash.update(group_id.as_slice());
        hash.update((grant_hashes.len() as u64).to_be_bytes());
        for grant in grant_hashes {
            hash.update(grant);
        }
        let own_leaf = group
            .own_leaf_node()
            .ok_or_else(|| EngineError::Backend("group has no local leaf".into()))?
            .tls_serialize_detached()
            .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
        let evolution = DurableGroupEvolution {
            id: cgka_traits::types::MessageId::new(hash.finalize().to_vec()),
            group_id: group_id.clone(),
            source_epoch: source.source.epoch,
            target_epoch: EpochId(source.source.epoch.0.saturating_add(1)),
            phase: GroupEvolutionPhase::Preparing,
            semantic: GroupEvolutionSemantic::RecoverMembers {
                request_ids,
                source_authenticator_hash: source.source.epoch_authenticator_hash,
            },
            own_leaf_before_hash: Some(Sha256::digest(own_leaf).to_vec()),
            removal_members: recoveries
                .iter()
                .map(|recovery| recovery.member.as_slice().to_vec())
                .collect(),
            signed_message_id: None,
            pending_ref: None,
        };
        self.storage.with_transaction(|storage| {
            let maintenance = storage
                .maintenance_storage()
                .ok_or_else(|| EngineError::Backend("maintenance storage is unavailable".into()))?;
            // Never replace an immutable or possibly exposed publication, even
            // when the caller supplies the exact same grant a second time.
            if maintenance.group_evolution(&evolution.id)?.is_some()
                || maintenance
                    .list_group_evolutions_for_group(group_id)?
                    .iter()
                    .any(|record| {
                        matches!(
                            record.phase,
                            GroupEvolutionPhase::Preparing
                                | GroupEvolutionPhase::Prepared
                                | GroupEvolutionPhase::Attempting
                        )
                    })
            {
                return Err(EngineError::GroupRecoveryUnsettled {
                    group_id: group_id.clone(),
                });
            }
            maintenance.put_group_evolution(&evolution)?;
            Ok::<_, EngineError>(())
        })?;
        Ok(evolution)
    }

    pub(crate) fn maintenance_storage(
        &self,
    ) -> Result<&dyn cgka_traits::storage::MaintenanceStorage, EngineError> {
        self.storage
            .maintenance_storage()
            .ok_or_else(|| EngineError::Backend("maintenance storage is unavailable".into()))
    }

    /// Atomically generate a private KeyPackage bundle and persist the
    /// replacement lifecycle intent that owns it.
    pub fn stage_key_package_replacement(
        &mut self,
        state: &mut KeyPackageLifecycleState,
        authored_created_at: Timestamp,
        refresh_lead_secs: u64,
        targets: Vec<TransportFanoutTarget>,
    ) -> Result<KeyPackage, EngineError> {
        let (staged, key_package) = self.storage.with_transaction(|storage| {
            let key_package = self.build_fresh_key_package(storage)?;
            let metadata = crate::key_package::key_package_metadata(&key_package)?;
            let mut staged = state.clone();
            // An older pending artifact may have reached a relay even without
            // a recorded ACK. Retain its private material when superseding it;
            // the replacement and this ownership transfer commit together.
            if let Some(previous) = staged.pending_replacement.take() {
                staged
                    .retained_private_material
                    .push(RetainedKeyPackagePrivateMaterial {
                        key_package: previous.key_package,
                        key_package_ref: previous.key_package_ref,
                        not_after: previous.not_after,
                        replaced_at: authored_created_at,
                        consumed: previous.consumed_at.is_some(),
                        authored_event_id: previous.signed_event.map(|event| event.id),
                    });
            }
            staged.pending_replacement = Some(PendingKeyPackageReplacement {
                generation_revision: cgka_traits::maintenance::KEY_PACKAGE_GENERATION_REVISION,
                key_package: key_package.clone(),
                key_package_ref: hex::decode(&metadata.key_package_ref_hex)
                    .map_err(|error| EngineError::Serialize(error.to_string()))?,
                authored_created_at,
                not_before: Timestamp(metadata.not_before),
                not_after: Timestamp(metadata.not_after),
                refresh_at: Timestamp(metadata.not_after.saturating_sub(refresh_lead_secs)),
                signed_event: None,
                targets,
                attempt_count: 0,
                last_failure_code: None,
                consumed_at: None,
            });
            staged.phase = MaintenancePhase::PendingPublication;
            storage
                .maintenance_storage()
                .ok_or_else(|| EngineError::Backend("maintenance storage is unavailable".into()))?
                .put_key_package_lifecycle(&staged)?;
            Ok::<_, EngineError>((staged, key_package))
        })?;
        *state = staged;
        Ok(key_package)
    }

    /// Atomically update lifecycle authority and retire a prior private init
    /// key. The network acknowledgement must happen before callers invoke this
    /// method.
    pub fn promote_key_package_lifecycle(
        &mut self,
        retired: &[KeyPackage],
        state: &KeyPackageLifecycleState,
    ) -> Result<(), EngineError> {
        self.storage.with_transaction(|storage| {
            for previous in retired {
                let msg =
                    MlsMessageIn::tls_deserialize_exact(previous.bytes()).map_err(|error| {
                        EngineError::Serialize(format!("key_package deserialize: {error:?}"))
                    })?;
                let key_package = match msg.extract() {
                    MlsMessageBodyIn::KeyPackage(key_package) => key_package,
                    _ => {
                        return Err(EngineError::Serialize(
                            "MLS message did not carry a KeyPackage".into(),
                        ));
                    }
                };
                let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                let key_package =
                    crate::key_package::validate_key_package(key_package, provider.crypto())?;
                let reference = key_package
                    .hash_ref(provider.crypto())
                    .map_err(|error| EngineError::Backend(format!("key_package ref: {error:?}")))?;
                use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;
                OpenMlsStorageProvider::delete_key_package(provider.storage(), &reference)
                    .map_err(|error| {
                        EngineError::Backend(format!("key_package delete: {error:?}"))
                    })?;
            }
            storage
                .maintenance_storage()
                .ok_or_else(|| EngineError::Backend("maintenance storage is unavailable".into()))?
                .put_key_package_lifecycle(state)?;
            Ok::<_, EngineError>(())
        })
    }

    pub(crate) fn recovery_source_for_group(
        &self,
        group_id: &GroupId,
        group: &openmls::group::MlsGroup,
        member: &MemberId,
        device_key_hash: &[u8; 32],
    ) -> Result<GroupRecoverySource, EngineError> {
        self.ensure_group_live(group_id)?;
        let record = self.storage.get_group(group_id)?;
        if record.is_terminal()
            || record.unrecoverable
            || self.leave_in_progress(group_id)?
            || self.disbanding_in_progress(group_id)?
            || !self
                .epoch_manager
                .state(group_id)
                .is_some_and(|state| state.is_stable())
            || group.pending_commit().is_some()
            || group.has_pending_proposals()
            || self.has_unresolved_convergence_inputs(group_id)?
        {
            return Err(EngineError::GroupRecoveryUnsettled {
                group_id: group_id.clone(),
            });
        }
        crate::app_components::require_admin(group, group_id, self.identity.self_id())?;
        let epoch = EpochId(group.epoch().as_u64());
        if record.epoch != epoch {
            return Err(EngineError::GroupRecoveryUnsettled {
                group_id: group_id.clone(),
            });
        }
        let nodes = crate::app_components::ratchet_tree_nodes(group.export_ratchet_tree())?;
        let (leaf_index, leaf) = nodes
            .iter()
            .step_by(2)
            .enumerate()
            .find_map(|(index, node)| match node {
                Some(openmls::treesync::Node::LeafNode(leaf))
                    if <[u8; 32]>::from(Sha256::digest(leaf.signature_key().as_slice()))
                        == *device_key_hash =>
                {
                    u32::try_from(index).ok().map(|index| (index, leaf))
                }
                _ => None,
            })
            .ok_or_else(|| EngineError::UnknownMember {
                group_id: group_id.clone(),
                member: member.clone(),
            })?;
        if crate::identity::validated_member_id_of_leaf(leaf)? != *member {
            return Err(EngineError::UnknownMember {
                group_id: group_id.clone(),
                member: member.clone(),
            });
        }
        if leaf_index == group.own_leaf_index().u32() {
            return Err(EngineError::UnknownMember {
                group_id: group_id.clone(),
                member: member.clone(),
            });
        }
        let bytes = leaf
            .tls_serialize_detached()
            .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
        Ok(GroupRecoverySource {
            epoch,
            epoch_authenticator_hash: Sha256::digest(group.epoch_authenticator().as_slice()).into(),
            leaf_index,
            leaf_hash: Sha256::digest(bytes).into(),
            device_key_hash: *device_key_hash,
        })
    }

    pub(crate) fn do_group_recovery_source(
        &self,
        group_id: &GroupId,
        member: &MemberId,
        device_key_hash: &[u8; 32],
    ) -> Result<GroupRecoverySource, EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let group = openmls::group::MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        self.recovery_source_for_group(group_id, &group, member, device_key_hash)
    }

    pub(crate) fn validate_recovery_for_group(
        &self,
        group_id: &GroupId,
        group: &openmls::group::MlsGroup,
        profile: cgka_traits::group::ProtocolProfile,
        required: &cgka_traits::capabilities::GroupCapabilities,
        recovery: &cgka_traits::group_recovery::GroupMemberRecovery,
    ) -> Result<openmls::prelude::KeyPackage, EngineError> {
        use openmls_traits::crypto::OpenMlsCrypto as _;
        let source = &recovery.source;
        let mismatch = || EngineError::GroupRecoverySourceMismatch {
            group_id: group_id.clone(),
        };
        if self.recovery_source_for_group(
            group_id,
            group,
            &recovery.member,
            &source.device_key_hash,
        )? != *source
            || recovery.expires_at <= self.wall_clock.now().0
            || recovery.device_signature.len() != 64
            || (self.new_protocol_profile == cgka_traits::group::ProtocolProfile::Current
                && profile == cgka_traits::group::ProtocolProfile::Legacy)
        {
            return Err(mismatch());
        }
        let parsed = self
            .parse_group_key_package(&recovery.key_package, profile, required)
            .map_err(|_| mismatch())?;
        let package_hash: [u8; 32] =
            Sha256::digest(parsed.leaf_node().signature_key().as_slice()).into();
        if crate::identity::validated_member_id_of_leaf(parsed.leaf_node())? != recovery.member
            || package_hash != source.device_key_hash
        {
            return Err(mismatch());
        }
        let payload = cgka_traits::group_recovery::group_recovery_grant_bytes(
            group_id,
            self.identity.self_id(),
            &recovery.request_id,
            recovery.expires_at,
            source,
            &recovery.key_package,
        )
        .map_err(|_| mismatch())?;
        let target = group
            .member_at(openmls::prelude::LeafNodeIndex::new(source.leaf_index))
            .ok_or_else(mismatch)?;
        self.crypto
            .verify_signature(
                self.ciphersuite.signature_algorithm(),
                &payload,
                &target.signature_key,
                &recovery.device_signature,
            )
            .map_err(|_| mismatch())?;
        Ok(parsed)
    }

    pub(crate) fn do_validate_member_recovery(
        &self,
        group_id: &GroupId,
        recovery: &cgka_traits::group_recovery::GroupMemberRecovery,
    ) -> Result<(), EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let group = openmls::group::MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let record = self.storage.get_group(group_id)?;
        let mut required = record.required_capabilities.clone();
        crate::capability_manager::merge_capabilities(
            &mut required,
            &crate::capability_manager::required_role_capabilities_from_group(&group),
        );
        self.validate_recovery_for_group(
            group_id,
            &group,
            record.protocol_profile,
            &required,
            recovery,
        )
        .map(|_| ())
    }

    pub(crate) fn do_sign_group_recovery(
        &self,
        group_id: &GroupId,
        coordinator: &MemberId,
        message: &cgka_traits::group_recovery::GroupRecoveryMessage,
    ) -> Result<Vec<u8>, EngineError> {
        use cgka_traits::group_recovery::{GroupRecoveryBody, group_recovery_grant_bytes};
        use openmls_traits::signatures::Signer as _;
        self.ensure_group_live(group_id)?;
        let record = self.storage.get_group(group_id)?;
        if !record.unrecoverable
            || !self.epoch_manager.is_unrecoverable(group_id)
            || record.is_terminal()
            || self.leave_in_progress(group_id)?
            || self.disbanding_in_progress(group_id)?
        {
            return Err(EngineError::GroupRecoveryUnsettled {
                group_id: group_id.clone(),
            });
        }
        if message.group_id != *group_id || message.expires_at <= self.wall_clock.now().0 {
            return Err(EngineError::GroupRecoverySourceMismatch {
                group_id: group_id.clone(),
            });
        }
        crate::identity::validate_credential_identity(coordinator.as_slice())?;
        let GroupRecoveryBody::Grant {
            source,
            key_package,
            ..
        } = &message.body
        else {
            return Err(EngineError::GroupRecoverySourceMismatch {
                group_id: group_id.clone(),
            });
        };
        let parsed = self.parse_key_package(key_package)?;
        let device_hash = self.own_recovery_key_hash(group_id)?;
        let package_hash: [u8; 32] =
            Sha256::digest(parsed.leaf_node().signature_key().as_slice()).into();
        if source.device_key_hash != device_hash
            || package_hash != device_hash
            || key_package.protocol_profile != record.protocol_profile
            || crate::identity::validated_member_id_of_leaf(parsed.leaf_node())?
                != *self.identity.self_id()
        {
            return Err(EngineError::GroupRecoverySourceMismatch {
                group_id: group_id.clone(),
            });
        }
        let signed = group_recovery_grant_bytes(
            group_id,
            coordinator,
            &message.request_id,
            message.expires_at,
            source,
            key_package,
        )
        .map_err(EngineError::Peeler)?;
        self.identity
            .signer
            .sign(&signed)
            .map_err(|error| EngineError::Backend(format!("recovery signature: {error:?}")))
    }

    pub fn own_leaf_hash(&self, group_id: &GroupId) -> Result<Vec<u8>, EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let leaf = mls_group
            .own_leaf_node()
            .ok_or_else(|| EngineError::Backend("group has no local leaf".into()))?
            .tls_serialize_detached()
            .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
        Ok(Sha256::digest(leaf).to_vec())
    }
}

/// Compensate an evolution whose exact bytes have never left the engine.
/// Hydration may call this only for Preparing; a live send guard also owns a
/// Prepared row until the pending handle is handed to its caller.
pub(crate) fn rollback_recovery_stage<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    evolution_id: &cgka_traits::types::MessageId,
) -> Result<(), EngineError> {
    storage.with_transaction(|storage| {
        let maintenance = storage
            .maintenance_storage()
            .ok_or_else(|| EngineError::Backend("maintenance storage is unavailable".into()))?;
        let evolution = maintenance
            .group_evolution(evolution_id)?
            .ok_or(cgka_traits::storage::StorageError::NotFound)?;
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut group = openmls::group::MlsGroup::load(storage.mls_storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let source_epoch = EpochId(group.epoch().as_u64());
        crate::message_processor::transition_staged_invite_welcomes(
            storage,
            group_id,
            source_epoch,
            None,
            cgka_traits::message::MessageState::Failed,
        )?;
        if group.pending_commit().is_some() {
            group
                .clear_pending_commit(storage.mls_storage())
                .map_err(|error| EngineError::Backend(format!("clear_pending: {error:?}")))?;
        }
        let mut record = storage.get_group(group_id)?;
        record.epoch = source_epoch;
        record.members = crate::group_lifecycle::marmot_members(&group);
        record.required_capabilities =
            crate::capability_manager::required_capabilities_from_group(&group);
        crate::group_lifecycle::mirror_app_components_into_record(&group, &mut record);
        storage.put_group(&record)?;
        if let Some(message_id) = &evolution.signed_message_id {
            match storage.get_message(message_id) {
                Ok(record) => {
                    let payload =
                        cgka_traits::message::StoredMessagePayload::decode(&record.payload)
                            .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
                    if let Some(wire) = payload.as_openmls_wire() {
                        let content_id = crate::message_processor::content_dedup_id(&wire.payload);
                        if content_id != *message_id {
                            storage.update_message_state(
                                &content_id,
                                cgka_traits::message::MessageState::Failed,
                            )?;
                        }
                    }
                    storage.update_message_state(
                        message_id,
                        cgka_traits::message::MessageState::Failed,
                    )?;
                }
                Err(cgka_traits::storage::StorageError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        maintenance.delete_group_evolution(evolution_id)?;
        Ok(())
    })
}
