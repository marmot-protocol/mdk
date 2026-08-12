//! Public persistence helpers for account-device maintenance orchestration.
//!
//! Scheduling and transport policy live above the engine; these methods keep
//! their records in the same encrypted database as MLS state.

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::maintenance::{
    DurableGroupEvolution, DurableTransportFanout, GroupMaintenanceState, KeyPackageLifecycleState,
    MaintenanceObligation, MaintenancePhase, PendingKeyPackageReplacement,
    PeriodicMaintenancePolicy, TransportFanoutTarget,
};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::Timestamp;
use cgka_traits::types::{GroupId, MessageId};
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn maintenance_storage(
        &self,
    ) -> Result<&dyn cgka_traits::storage::MaintenanceStorage, EngineError> {
        self.storage
            .maintenance_storage()
            .ok_or_else(|| EngineError::Backend("maintenance storage is unavailable".into()))
    }

    pub fn key_package_lifecycle(&self) -> Result<Option<KeyPackageLifecycleState>, EngineError> {
        Ok(self.maintenance_storage()?.key_package_lifecycle()?)
    }

    pub fn put_key_package_lifecycle(
        &self,
        state: &KeyPackageLifecycleState,
    ) -> Result<(), EngineError> {
        Ok(self
            .maintenance_storage()?
            .put_key_package_lifecycle(state)?)
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
            staged.pending_replacement = Some(PendingKeyPackageReplacement {
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

    pub fn group_maintenance(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupMaintenanceState>, EngineError> {
        self.ensure_group_live(group_id)?;
        Ok(self.maintenance_storage()?.group_maintenance(group_id)?)
    }

    pub fn put_group_maintenance(&self, state: &GroupMaintenanceState) -> Result<(), EngineError> {
        self.ensure_group_live(&state.group_id)?;
        Ok(self.maintenance_storage()?.put_group_maintenance(state)?)
    }

    pub fn put_maintenance_obligation(
        &self,
        record: &MaintenanceObligation,
    ) -> Result<(), EngineError> {
        Ok(self
            .maintenance_storage()?
            .put_maintenance_obligation(record)?)
    }

    pub fn maintenance_obligation(
        &self,
        id: &MessageId,
    ) -> Result<Option<MaintenanceObligation>, EngineError> {
        Ok(self.maintenance_storage()?.maintenance_obligation(id)?)
    }

    pub fn list_maintenance_obligations(&self) -> Result<Vec<MaintenanceObligation>, EngineError> {
        Ok(self.maintenance_storage()?.list_maintenance_obligations()?)
    }

    pub fn list_maintenance_obligations_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<MaintenanceObligation>, EngineError> {
        self.ensure_group_live(group_id)?;
        Ok(self
            .maintenance_storage()?
            .list_maintenance_obligations_for_group(group_id)?)
    }

    pub fn delete_maintenance_obligation(&self, id: &MessageId) -> Result<(), EngineError> {
        Ok(self
            .maintenance_storage()?
            .delete_maintenance_obligation(id)?)
    }

    pub fn list_group_evolutions(&self) -> Result<Vec<DurableGroupEvolution>, EngineError> {
        Ok(self.maintenance_storage()?.list_group_evolutions()?)
    }

    pub fn list_group_evolutions_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<DurableGroupEvolution>, EngineError> {
        self.ensure_group_live(group_id)?;
        Ok(self
            .maintenance_storage()?
            .list_group_evolutions_for_group(group_id)?)
    }

    pub fn put_group_evolution(&self, record: &DurableGroupEvolution) -> Result<(), EngineError> {
        Ok(self.maintenance_storage()?.put_group_evolution(record)?)
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

    pub fn put_transport_fanout(&self, record: &DurableTransportFanout) -> Result<(), EngineError> {
        Ok(self.maintenance_storage()?.put_transport_fanout(record)?)
    }

    pub fn transport_fanout(
        &self,
        id: &MessageId,
    ) -> Result<Option<DurableTransportFanout>, EngineError> {
        Ok(self.maintenance_storage()?.transport_fanout(id)?)
    }

    pub fn list_transport_fanouts(&self) -> Result<Vec<DurableTransportFanout>, EngineError> {
        Ok(self.maintenance_storage()?.list_transport_fanouts()?)
    }

    pub fn delete_transport_fanout(&self, id: &MessageId) -> Result<(), EngineError> {
        Ok(self.maintenance_storage()?.delete_transport_fanout(id)?)
    }

    pub fn periodic_maintenance_policy(&self) -> Result<PeriodicMaintenancePolicy, EngineError> {
        Ok(self.maintenance_storage()?.periodic_maintenance_policy()?)
    }

    pub fn put_periodic_maintenance_policy(
        &self,
        policy: PeriodicMaintenancePolicy,
    ) -> Result<(), EngineError> {
        Ok(self
            .maintenance_storage()?
            .put_periodic_maintenance_policy(policy)?)
    }
}
