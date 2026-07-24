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
    MaintenanceObligation, PeriodicMaintenancePolicy,
};
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{GroupId, MessageId};
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

impl<S: StorageProvider> Engine<S> {
    fn maintenance_storage(
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
        Ok(self.maintenance_storage()?.group_maintenance(group_id)?)
    }

    pub fn put_group_maintenance(&self, state: &GroupMaintenanceState) -> Result<(), EngineError> {
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

    pub fn delete_maintenance_obligation(&self, id: &MessageId) -> Result<(), EngineError> {
        Ok(self
            .maintenance_storage()?
            .delete_maintenance_obligation(id)?)
    }

    pub fn list_group_evolutions(&self) -> Result<Vec<DurableGroupEvolution>, EngineError> {
        Ok(self.maintenance_storage()?.list_group_evolutions()?)
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
