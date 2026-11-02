//! Maintenance operations that need OpenMLS state.
//!
//! Scheduling and transport policy live above the engine, and so do the
//! account records it runs on: the session reads and writes them on its own
//! storage handle (mdk#2602). What stays here touches OpenMLS state too:
//! KeyPackage staging and promotion write OpenMLS material and the lifecycle
//! record in one transaction, and the own-leaf hash reads the MLS group.
//! Restored own checkpoints also retain a mandatory rotation obligation here:
//! their application sender ratchet may already have been used before rewind.

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::{KeyPackage, SendIntent, SendResult};
use cgka_traits::error::EngineError;
use cgka_traits::maintenance::{
    KeyPackageLifecycleState, MaintenanceObligation, MaintenancePhase, MaintenanceTrigger,
    PendingKeyPackageReplacement, RetainedKeyPackagePrivateMaterial, TransportFanoutTarget,
};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::Timestamp;
use cgka_traits::types::{GroupId, MessageId};
use openmls::prelude::{MlsGroup, MlsMessageBodyIn, MlsMessageIn};
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};
use web_time::{SystemTime, UNIX_EPOCH};

const REPLAY_ROTATION_PREFIX: &[u8] = b"marmot-replay-rotation-v1/";

fn replay_rotation_id(group_id: &GroupId, group: &MlsGroup) -> MessageId {
    let mut hash = Sha256::new();
    hash.update(REPLAY_ROTATION_PREFIX);
    hash.update((group_id.as_slice().len() as u64).to_be_bytes());
    hash.update(group_id.as_slice());
    let epoch = group.epoch().as_u64().to_be_bytes();
    hash.update(epoch);
    hash.update(group.epoch_authenticator().as_slice());
    // Maintenance ids are opaque byte strings, not transport event ids.
    // Retention can read this local epoch without loading old key material.
    let mut id = Vec::with_capacity(REPLAY_ROTATION_PREFIX.len() + 8 + 32);
    id.extend_from_slice(REPLAY_ROTATION_PREFIX);
    id.extend_from_slice(&epoch);
    id.extend_from_slice(&hash.finalize());
    MessageId::new(id)
}

/// The caller has already pruned exact checkpoints at this same boundary.
/// Never prune a marker whose epoch can still be installed by replay.
pub(crate) fn prune_replay_rotations<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    oldest_retained_epoch: u64,
) -> Result<(), StorageError> {
    let Some(maintenance) = storage.maintenance_storage() else {
        return Ok(());
    };
    for obligation in maintenance.list_maintenance_obligations_for_group(group_id)? {
        let Some(suffix) = obligation
            .id
            .as_slice()
            .strip_prefix(REPLAY_ROTATION_PREFIX)
        else {
            continue;
        };
        if suffix.len() != 8 + 32 {
            continue;
        }
        let mut epoch = [0; 8];
        epoch.copy_from_slice(&suffix[..8]);
        if u64::from_be_bytes(epoch) < oldest_retained_epoch {
            maintenance.delete_maintenance_obligation(&obligation.id)?;
        }
    }
    Ok(())
}

/// Called only by canonical apply, inside its rollback unit, never by probes.
/// Keep the obligation even after completion: revisiting this epoch must not
/// reuse its sender ratchet. Ordinary phase changes cannot release this gate.
pub(crate) fn require_replay_rotation<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &MlsGroup,
) -> Result<(), EngineError> {
    let maintenance = storage
        .maintenance_storage()
        .ok_or_else(|| EngineError::Backend("maintenance storage is unavailable".into()))?;
    let id = replay_rotation_id(group_id, group);
    if maintenance.maintenance_obligation(&id)?.is_some() {
        return Ok(());
    }
    let leaf = group
        .own_leaf_node()
        .ok_or_else(|| EngineError::Backend("group has no local leaf".into()))?
        .tls_serialize_detached()
        .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
    let now = Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    maintenance.put_maintenance_obligation(&MaintenanceObligation {
        id,
        group_id: group_id.clone(),
        trigger: MaintenanceTrigger::Manual,
        phase: MaintenancePhase::Retry,
        created_at: now,
        operational_target_at: None,
        overdue: false,
        eose_deadline_at: None,
        grace_until: None,
        quiet_since: None,
        own_leaf_baseline_hash: Some(Sha256::digest(leaf).to_vec()),
        sampled_jitter_ms: 0,
        not_before: None,
        attempt_count: 0,
        semantic_rearm_count: 0,
        last_failure_code: None,
    })?;
    Ok(())
}

pub(crate) fn replay_rotation_required<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &MlsGroup,
) -> Result<bool, EngineError> {
    // Such a backend cannot successfully install an own checkpoint above.
    let Some(maintenance) = storage.maintenance_storage() else {
        return Ok(false);
    };
    Ok(maintenance
        .maintenance_obligation(&replay_rotation_id(group_id, group))?
        .is_some())
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn needs_replay_rotation(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        let group = self
            .take_mls_group(group_id)?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let result = replay_rotation_required(&self.storage, group_id, &group);
        self.return_unmodified_mls_group(group_id, group);
        result
    }

    pub(crate) async fn stage_replay_rotation(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if self
            .epoch_manager
            .state(group_id)
            .is_some_and(|state| !state.is_stable())
            || self.leave_in_progress(group_id)?
            || self.disbanding_in_progress(group_id)?
            || !self.needs_replay_rotation(group_id)?
        {
            return Ok(false);
        }
        let SendResult::GroupEvolution { msg, pending, .. } = self
            .do_send_ready(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await?
        else {
            return Err(EngineError::Backend(
                "replay rotation produced no commit".into(),
            ));
        };
        self.auto_publish_buf
            .push_back(cgka_traits::AutoPublish { msg, pending });
        Ok(true)
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
    ///
    /// The replacement is due for its own refresh `refresh_after_secs` after
    /// `authored_created_at`, its publication time, or at its `not_after` if
    /// that is earlier.
    pub fn stage_key_package_replacement(
        &mut self,
        state: &mut KeyPackageLifecycleState,
        authored_created_at: Timestamp,
        refresh_after_secs: u64,
        targets: Vec<TransportFanoutTarget>,
    ) -> Result<KeyPackage, EngineError> {
        let (staged, key_package) = self.storage.with_transaction(|storage| {
            let key_package = self.build_fresh_key_package(storage)?;
            let metadata = crate::key_package::key_package_metadata(&key_package)?;
            let mut staged = state.clone();
            // An older pending artifact may have reached a relay even without
            // a recorded ACK. Retain its private material when superseding it;
            // the replacement and this ownership transfer commit together. Its
            // grace period starts once a replacement is confirmed, or now if a
            // Welcome already consumed it (mdk#2352).
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
                        awaiting_confirmed_replacement: previous.consumed_at.is_none(),
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
                refresh_at: Timestamp(
                    authored_created_at
                        .0
                        .saturating_add(refresh_after_secs)
                        .min(metadata.not_after),
                ),
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
