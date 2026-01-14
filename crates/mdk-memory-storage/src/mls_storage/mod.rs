//! OpenMLS StorageProvider implementation for in-memory storage.
//!
//! This module implements the `StorageProvider<1>` trait from `openmls_traits`
//! directly on `MdkMemoryStorage`, enabling unified storage for both MLS
//! cryptographic state and MDK-specific data within a single storage structure.

// Allow complex types for MLS storage structures - these maps require compound keys
// for proper data organization and the complexity is inherent to the domain.
#![allow(clippy::type_complexity)]

use std::collections::HashMap;

use mdk_storage_traits::MdkStorageError;
pub use mdk_storage_traits::mls_codec::{GroupDataType, JsonCodec};
use parking_lot::RwLock;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The storage provider version matching OpenMLS's CURRENT_VERSION.
pub const STORAGE_PROVIDER_VERSION: u16 = 1;

// ============================================================================
// In-Memory Data Structures
// ============================================================================

/// In-memory storage for MLS group data.
/// Key: (group_id bytes, data type)
/// Value: serialized data bytes
#[derive(Debug, Default)]
pub struct MlsGroupData {
    data: RwLock<HashMap<(Vec<u8>, GroupDataType), Vec<u8>>>,
}

impl MlsGroupData {
    /// Creates a new empty MLS group data store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write group data.
    pub fn write<GroupId, GroupData>(
        &self,
        group_id: &GroupId,
        data_type: GroupDataType,
        data: &GroupData,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
        GroupData: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let data_bytes = serialize_entity(data)?;
        self.data
            .write()
            .insert((group_id_bytes, data_type), data_bytes);
        Ok(())
    }

    /// Read group data.
    pub fn read<GroupId, GroupData>(
        &self,
        group_id: &GroupId,
        data_type: GroupDataType,
    ) -> Result<Option<GroupData>, MdkStorageError>
    where
        GroupId: Serialize,
        GroupData: DeserializeOwned,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let guard = self.data.read();
        match guard.get(&(group_id_bytes, data_type)) {
            Some(bytes) => Ok(Some(deserialize_entity(bytes)?)),
            None => Ok(None),
        }
    }

    /// Delete group data.
    pub fn delete<GroupId>(
        &self,
        group_id: &GroupId,
        data_type: GroupDataType,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        self.data.write().remove(&(group_id_bytes, data_type));
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<(Vec<u8>, GroupDataType), Vec<u8>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<(Vec<u8>, GroupDataType), Vec<u8>>) {
        *self.data.write() = data;
    }
}

/// In-memory storage for MLS own leaf nodes.
/// Key: group_id bytes
/// Value: list of serialized leaf node bytes (in insertion order)
#[derive(Debug, Default)]
pub struct MlsOwnLeafNodes {
    data: RwLock<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
}

impl MlsOwnLeafNodes {
    /// Creates a new empty own leaf nodes store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a leaf node for a group.
    pub fn append<GroupId, LeafNode>(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
        LeafNode: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let leaf_node_bytes = serialize_entity(leaf_node)?;
        self.data
            .write()
            .entry(group_id_bytes)
            .or_default()
            .push(leaf_node_bytes);
        Ok(())
    }

    /// Read all leaf nodes for a group.
    pub fn read<GroupId, LeafNode>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, MdkStorageError>
    where
        GroupId: Serialize,
        LeafNode: DeserializeOwned,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let guard = self.data.read();
        match guard.get(&group_id_bytes) {
            Some(leaf_nodes) => {
                let mut result = Vec::with_capacity(leaf_nodes.len());
                for bytes in leaf_nodes {
                    result.push(deserialize_entity(bytes)?);
                }
                Ok(result)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Delete all leaf nodes for a group.
    pub fn delete<GroupId>(&self, group_id: &GroupId) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        self.data.write().remove(&group_id_bytes);
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<Vec<u8>, Vec<Vec<u8>>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<Vec<u8>, Vec<Vec<u8>>>) {
        *self.data.write() = data;
    }
}

/// In-memory storage for MLS proposals.
/// Key: (group_id bytes, proposal_ref bytes)
/// Value: serialized proposal bytes
#[derive(Debug, Default)]
pub struct MlsProposals {
    data: RwLock<HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>>,
}

impl MlsProposals {
    /// Creates a new empty proposals store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a proposal.
    pub fn queue<GroupId, ProposalRef, QueuedProposal>(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
        ProposalRef: Serialize,
        QueuedProposal: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let proposal_ref_bytes = serialize_key(proposal_ref)?;
        let proposal_bytes = serialize_entity(proposal)?;
        self.data
            .write()
            .insert((group_id_bytes, proposal_ref_bytes), proposal_bytes);
        Ok(())
    }

    /// Read all proposal refs for a group.
    pub fn read_refs<GroupId, ProposalRef>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, MdkStorageError>
    where
        GroupId: Serialize,
        ProposalRef: DeserializeOwned,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let guard = self.data.read();
        let mut refs = Vec::new();
        for (key, _) in guard.iter() {
            if key.0 == group_id_bytes {
                refs.push(deserialize_entity(&key.1)?);
            }
        }
        Ok(refs)
    }

    /// Read all proposals for a group.
    pub fn read_proposals<GroupId, ProposalRef, QueuedProposal>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, MdkStorageError>
    where
        GroupId: Serialize,
        ProposalRef: DeserializeOwned,
        QueuedProposal: DeserializeOwned,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let guard = self.data.read();
        let mut proposals = Vec::new();
        for ((gid, ref_bytes), proposal_bytes) in guard.iter() {
            if *gid == group_id_bytes {
                let proposal_ref: ProposalRef = deserialize_entity(ref_bytes)?;
                let proposal: QueuedProposal = deserialize_entity(proposal_bytes)?;
                proposals.push((proposal_ref, proposal));
            }
        }
        Ok(proposals)
    }

    /// Remove a single proposal.
    pub fn remove<GroupId, ProposalRef>(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
        ProposalRef: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let proposal_ref_bytes = serialize_key(proposal_ref)?;
        self.data
            .write()
            .remove(&(group_id_bytes, proposal_ref_bytes));
        Ok(())
    }

    /// Clear all proposals for a group.
    pub fn clear<GroupId>(&self, group_id: &GroupId) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        self.data
            .write()
            .retain(|(gid, _), _| *gid != group_id_bytes);
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<(Vec<u8>, Vec<u8>), Vec<u8>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>) {
        *self.data.write() = data;
    }
}

/// In-memory storage for MLS key packages.
/// Key: hash_ref bytes
/// Value: serialized key package bytes
#[derive(Debug, Default)]
pub struct MlsKeyPackages {
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MlsKeyPackages {
    /// Creates a new empty key packages store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a key package.
    pub fn write<HashReference, KeyPackage>(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), MdkStorageError>
    where
        HashReference: Serialize,
        KeyPackage: Serialize,
    {
        let hash_ref_bytes = serialize_key(hash_ref)?;
        let key_package_bytes = serialize_entity(key_package)?;
        self.data.write().insert(hash_ref_bytes, key_package_bytes);
        Ok(())
    }

    /// Read a key package.
    pub fn read<HashReference, KeyPackage>(
        &self,
        hash_ref: &HashReference,
    ) -> Result<Option<KeyPackage>, MdkStorageError>
    where
        HashReference: Serialize,
        KeyPackage: DeserializeOwned,
    {
        let hash_ref_bytes = serialize_key(hash_ref)?;
        let guard = self.data.read();
        match guard.get(&hash_ref_bytes) {
            Some(bytes) => Ok(Some(deserialize_entity(bytes)?)),
            None => Ok(None),
        }
    }

    /// Delete a key package.
    pub fn delete<HashReference>(&self, hash_ref: &HashReference) -> Result<(), MdkStorageError>
    where
        HashReference: Serialize,
    {
        let hash_ref_bytes = serialize_key(hash_ref)?;
        self.data.write().remove(&hash_ref_bytes);
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<Vec<u8>, Vec<u8>>) {
        *self.data.write() = data;
    }
}

/// In-memory storage for MLS PSKs.
/// Key: psk_id bytes
/// Value: serialized PSK bundle bytes
#[derive(Debug, Default)]
pub struct MlsPsks {
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MlsPsks {
    /// Creates a new empty PSKs store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a PSK.
    pub fn write<PskId, PskBundle>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), MdkStorageError>
    where
        PskId: Serialize,
        PskBundle: Serialize,
    {
        let psk_id_bytes = serialize_key(psk_id)?;
        let psk_bytes = serialize_entity(psk)?;
        self.data.write().insert(psk_id_bytes, psk_bytes);
        Ok(())
    }

    /// Read a PSK.
    pub fn read<PskId, PskBundle>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, MdkStorageError>
    where
        PskId: Serialize,
        PskBundle: DeserializeOwned,
    {
        let psk_id_bytes = serialize_key(psk_id)?;
        let guard = self.data.read();
        match guard.get(&psk_id_bytes) {
            Some(bytes) => Ok(Some(deserialize_entity(bytes)?)),
            None => Ok(None),
        }
    }

    /// Delete a PSK.
    pub fn delete<PskId>(&self, psk_id: &PskId) -> Result<(), MdkStorageError>
    where
        PskId: Serialize,
    {
        let psk_id_bytes = serialize_key(psk_id)?;
        self.data.write().remove(&psk_id_bytes);
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<Vec<u8>, Vec<u8>>) {
        *self.data.write() = data;
    }
}

/// In-memory storage for MLS signature keys.
/// Key: public_key bytes
/// Value: serialized signature key pair bytes
#[derive(Debug, Default)]
pub struct MlsSignatureKeys {
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MlsSignatureKeys {
    /// Creates a new empty signature keys store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a signature key pair.
    pub fn write<SignaturePublicKey, SignatureKeyPair>(
        &self,
        public_key: &SignaturePublicKey,
        key_pair: &SignatureKeyPair,
    ) -> Result<(), MdkStorageError>
    where
        SignaturePublicKey: Serialize,
        SignatureKeyPair: Serialize,
    {
        let public_key_bytes = serialize_key(public_key)?;
        let key_pair_bytes = serialize_entity(key_pair)?;
        self.data.write().insert(public_key_bytes, key_pair_bytes);
        Ok(())
    }

    /// Read a signature key pair.
    pub fn read<SignaturePublicKey, SignatureKeyPair>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, MdkStorageError>
    where
        SignaturePublicKey: Serialize,
        SignatureKeyPair: DeserializeOwned,
    {
        let public_key_bytes = serialize_key(public_key)?;
        let guard = self.data.read();
        match guard.get(&public_key_bytes) {
            Some(bytes) => Ok(Some(deserialize_entity(bytes)?)),
            None => Ok(None),
        }
    }

    /// Delete a signature key pair.
    pub fn delete<SignaturePublicKey>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), MdkStorageError>
    where
        SignaturePublicKey: Serialize,
    {
        let public_key_bytes = serialize_key(public_key)?;
        self.data.write().remove(&public_key_bytes);
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<Vec<u8>, Vec<u8>>) {
        *self.data.write() = data;
    }
}

/// In-memory storage for MLS encryption keys.
/// Key: public_key bytes
/// Value: serialized HPKE key pair bytes
#[derive(Debug, Default)]
pub struct MlsEncryptionKeys {
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MlsEncryptionKeys {
    /// Creates a new empty encryption keys store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write an encryption key pair.
    pub fn write<EncryptionKey, HpkeKeyPair>(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), MdkStorageError>
    where
        EncryptionKey: Serialize,
        HpkeKeyPair: Serialize,
    {
        let public_key_bytes = serialize_key(public_key)?;
        let key_pair_bytes = serialize_entity(key_pair)?;
        self.data.write().insert(public_key_bytes, key_pair_bytes);
        Ok(())
    }

    /// Read an encryption key pair.
    pub fn read<EncryptionKey, HpkeKeyPair>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, MdkStorageError>
    where
        EncryptionKey: Serialize,
        HpkeKeyPair: DeserializeOwned,
    {
        let public_key_bytes = serialize_key(public_key)?;
        let guard = self.data.read();
        match guard.get(&public_key_bytes) {
            Some(bytes) => Ok(Some(deserialize_entity(bytes)?)),
            None => Ok(None),
        }
    }

    /// Delete an encryption key pair.
    pub fn delete<EncryptionKey>(&self, public_key: &EncryptionKey) -> Result<(), MdkStorageError>
    where
        EncryptionKey: Serialize,
    {
        let public_key_bytes = serialize_key(public_key)?;
        self.data.write().remove(&public_key_bytes);
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<Vec<u8>, Vec<u8>>) {
        *self.data.write() = data;
    }
}

/// In-memory storage for MLS epoch key pairs.
/// Key: (group_id bytes, epoch bytes, leaf_index)
/// Value: serialized list of HPKE key pairs
#[derive(Debug, Default)]
pub struct MlsEpochKeyPairs {
    data: RwLock<HashMap<(Vec<u8>, Vec<u8>, u32), Vec<u8>>>,
}

impl MlsEpochKeyPairs {
    /// Creates a new empty epoch key pairs store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write epoch encryption key pairs.
    pub fn write<GroupId, EpochKey, HpkeKeyPair>(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
        EpochKey: Serialize,
        HpkeKeyPair: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let epoch_bytes = serialize_key(epoch)?;
        let key_pairs_bytes = serialize_entity(&key_pairs)?;
        self.data
            .write()
            .insert((group_id_bytes, epoch_bytes, leaf_index), key_pairs_bytes);
        Ok(())
    }

    /// Read epoch encryption key pairs.
    pub fn read<GroupId, EpochKey, HpkeKeyPair>(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, MdkStorageError>
    where
        GroupId: Serialize,
        EpochKey: Serialize,
        HpkeKeyPair: DeserializeOwned,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let epoch_bytes = serialize_key(epoch)?;
        let guard = self.data.read();
        match guard.get(&(group_id_bytes, epoch_bytes, leaf_index)) {
            Some(bytes) => deserialize_entity(bytes),
            None => Ok(Vec::new()),
        }
    }

    /// Delete epoch encryption key pairs.
    pub fn delete<GroupId, EpochKey>(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
        EpochKey: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let epoch_bytes = serialize_key(epoch)?;
        self.data
            .write()
            .remove(&(group_id_bytes, epoch_bytes, leaf_index));
        Ok(())
    }

    /// Clone all data for snapshotting.
    pub fn clone_data(&self) -> HashMap<(Vec<u8>, Vec<u8>, u32), Vec<u8>> {
        self.data.read().clone()
    }

    /// Restore data from a snapshot.
    pub fn restore_data(&self, data: HashMap<(Vec<u8>, Vec<u8>, u32), Vec<u8>>) {
        *self.data.write() = data;
    }
}

// ============================================================================
// Helper functions for serialization
// ============================================================================

/// Serialize a key to bytes for storage.
fn serialize_key<K>(key: &K) -> Result<Vec<u8>, MdkStorageError>
where
    K: Serialize,
{
    JsonCodec::serialize(key)
}

/// Serialize an entity to bytes for storage.
fn serialize_entity<E>(entity: &E) -> Result<Vec<u8>, MdkStorageError>
where
    E: Serialize,
{
    JsonCodec::serialize(entity)
}

/// Deserialize an entity from bytes.
fn deserialize_entity<E>(bytes: &[u8]) -> Result<E, MdkStorageError>
where
    E: DeserializeOwned,
{
    JsonCodec::deserialize(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_data_type_equality() {
        assert_eq!(
            GroupDataType::JoinGroupConfig,
            GroupDataType::JoinGroupConfig
        );
        assert_ne!(GroupDataType::JoinGroupConfig, GroupDataType::Tree);
    }

    #[test]
    fn test_mls_group_data_basic() {
        let store = MlsGroupData::new();
        let group_id = vec![1u8, 2, 3, 4];
        let data = "test data".to_string();

        // Write data
        store.write(&group_id, GroupDataType::Tree, &data).unwrap();

        // Read data
        let result: Option<String> = store.read(&group_id, GroupDataType::Tree).unwrap();
        assert_eq!(result, Some("test data".to_string()));

        // Read non-existent data type
        let result: Option<String> = store.read(&group_id, GroupDataType::Context).unwrap();
        assert!(result.is_none());

        // Delete data
        store
            .delete::<Vec<u8>>(&group_id, GroupDataType::Tree)
            .unwrap();
        let result: Option<String> = store.read(&group_id, GroupDataType::Tree).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_mls_key_packages_basic() {
        let store = MlsKeyPackages::new();
        let hash_ref = vec![1u8, 2, 3, 4];
        let key_package = "key package data".to_string();

        // Write key package
        store.write(&hash_ref, &key_package).unwrap();

        // Read key package
        let result: Option<String> = store.read(&hash_ref).unwrap();
        assert_eq!(result, Some("key package data".to_string()));

        // Delete key package
        store.delete(&hash_ref).unwrap();
        let result: Option<String> = store.read(&hash_ref).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_mls_own_leaf_nodes_basic() {
        let store = MlsOwnLeafNodes::new();
        let group_id = vec![1u8, 2, 3, 4];

        // Append leaf nodes
        store.append(&group_id, &"leaf1".to_string()).unwrap();
        store.append(&group_id, &"leaf2".to_string()).unwrap();

        // Read leaf nodes
        let result: Vec<String> = store.read(&group_id).unwrap();
        assert_eq!(result, vec!["leaf1".to_string(), "leaf2".to_string()]);

        // Delete leaf nodes
        store.delete(&group_id).unwrap();
        let result: Vec<String> = store.read(&group_id).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_snapshot_restore() {
        let store = MlsGroupData::new();
        let group_id = vec![1u8, 2, 3, 4];

        // Write initial data
        store
            .write(&group_id, GroupDataType::Tree, &"original".to_string())
            .unwrap();

        // Take snapshot
        let snapshot = store.clone_data();

        // Modify data
        store
            .write(&group_id, GroupDataType::Tree, &"modified".to_string())
            .unwrap();

        // Verify modification
        let result: Option<String> = store.read(&group_id, GroupDataType::Tree).unwrap();
        assert_eq!(result, Some("modified".to_string()));

        // Restore snapshot
        store.restore_data(snapshot);

        // Verify restoration
        let result: Option<String> = store.read(&group_id, GroupDataType::Tree).unwrap();
        assert_eq!(result, Some("original".to_string()));
    }
}
