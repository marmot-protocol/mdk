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
pub use mdk_storage_traits::mls_codec::{GroupDataType, MlsCodec};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The storage provider version matching OpenMLS's CURRENT_VERSION.
pub const STORAGE_PROVIDER_VERSION: u16 = 1;

// ============================================================================
// Macro helpers for MLS storage structs
// ============================================================================

/// Generates an MLS storage struct with redacted Debug, `new()`, `clone_data()`,
/// and `restore_data()` from a struct name and data type.
macro_rules! mls_store_base {
    ($(#[$meta:meta])* $name:ident, $data_ty:ty) => {
        $(#[$meta])*
        #[derive(Default)]
        pub struct $name {
            pub(crate) data: $data_ty,
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("data", &"[REDACTED]")
                    .finish()
            }
        }

        impl $name {
            /// Creates a new empty store.
            pub fn new() -> Self {
                Self::default()
            }

            /// Clone all data for snapshotting.
            pub fn clone_data(&self) -> $data_ty {
                self.data.clone()
            }

            /// Restore data from a snapshot.
            pub fn restore_data(&mut self, data: $data_ty) {
                self.data = data;
            }
        }
    };
}

/// Generates generic `write`, `read`, and `delete` methods for stores keyed by
/// a single serialized key (`HashMap<Vec<u8>, Vec<u8>>`).
macro_rules! mls_single_key_ops {
    ($name:ident) => {
        impl $name {
            /// Write a value by key.
            pub fn write<K, V>(&mut self, key: &K, value: &V) -> Result<(), MdkStorageError>
            where
                K: Serialize,
                V: Serialize,
            {
                let key_bytes = serialize_key(key)?;
                let value_bytes = serialize_entity(value)?;
                self.data.insert(key_bytes, value_bytes);
                Ok(())
            }

            /// Read a value by key.
            pub fn read<K, V>(&self, key: &K) -> Result<Option<V>, MdkStorageError>
            where
                K: Serialize,
                V: DeserializeOwned,
            {
                let key_bytes = serialize_key(key)?;
                match self.data.get(&key_bytes) {
                    Some(bytes) => Ok(Some(deserialize_entity(bytes)?)),
                    None => Ok(None),
                }
            }

            /// Delete a value by key.
            pub fn delete<K>(&mut self, key: &K) -> Result<(), MdkStorageError>
            where
                K: Serialize,
            {
                let key_bytes = serialize_key(key)?;
                self.data.remove(&key_bytes);
                Ok(())
            }
        }
    };
}

// ============================================================================
// MLS storage structs
// ============================================================================

// -- Composite-key stores (unique method signatures) --------------------------

mls_store_base!(
    /// In-memory storage for MLS group data.
    /// Key: (group_id bytes, data type), Value: serialized data bytes
    MlsGroupData, HashMap<(Vec<u8>, GroupDataType), Vec<u8>>
);

impl MlsGroupData {
    /// Write group data.
    pub fn write<GroupId, GroupData>(
        &mut self,
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
        self.data.insert((group_id_bytes, data_type), data_bytes);
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
        match self.data.get(&(group_id_bytes, data_type)) {
            Some(bytes) => Ok(Some(deserialize_entity(bytes)?)),
            None => Ok(None),
        }
    }

    /// Delete group data.
    pub fn delete<GroupId>(
        &mut self,
        group_id: &GroupId,
        data_type: GroupDataType,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        self.data.remove(&(group_id_bytes, data_type));
        Ok(())
    }
}

mls_store_base!(
    /// In-memory storage for MLS own leaf nodes.
    /// Key: group_id bytes, Value: list of serialized leaf node bytes (insertion order)
    MlsOwnLeafNodes, HashMap<Vec<u8>, Vec<Vec<u8>>>
);

impl MlsOwnLeafNodes {
    /// Append a leaf node for a group.
    pub fn append<GroupId, LeafNode>(
        &mut self,
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
        match self.data.get(&group_id_bytes) {
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
    pub fn delete<GroupId>(&mut self, group_id: &GroupId) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        self.data.remove(&group_id_bytes);
        Ok(())
    }
}

mls_store_base!(
    /// In-memory storage for MLS proposals.
    /// Key: (group_id bytes, proposal_ref bytes), Value: serialized proposal bytes
    MlsProposals, HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>
);

impl MlsProposals {
    /// Queue a proposal.
    pub fn queue<GroupId, ProposalRef, QueuedProposal>(
        &mut self,
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
        let mut refs = Vec::new();
        for (key, _) in self.data.iter() {
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
        let mut proposals = Vec::new();
        for ((gid, ref_bytes), proposal_bytes) in self.data.iter() {
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
        &mut self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
        ProposalRef: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        let proposal_ref_bytes = serialize_key(proposal_ref)?;
        self.data.remove(&(group_id_bytes, proposal_ref_bytes));
        Ok(())
    }

    /// Clear all proposals for a group.
    pub fn clear<GroupId>(&mut self, group_id: &GroupId) -> Result<(), MdkStorageError>
    where
        GroupId: Serialize,
    {
        let group_id_bytes = serialize_key(group_id)?;
        self.data.retain(|(gid, _), _| *gid != group_id_bytes);
        Ok(())
    }
}

mls_store_base!(
    /// In-memory storage for MLS epoch key pairs.
    /// Key: (group_id bytes, epoch bytes, leaf_index), Value: serialized HPKE key pairs
    MlsEpochKeyPairs, HashMap<(Vec<u8>, Vec<u8>, u32), Vec<u8>>
);

impl MlsEpochKeyPairs {
    /// Write epoch encryption key pairs.
    pub fn write<GroupId, EpochKey, HpkeKeyPair>(
        &mut self,
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
        match self.data.get(&(group_id_bytes, epoch_bytes, leaf_index)) {
            Some(bytes) => deserialize_entity(bytes),
            None => Ok(Vec::new()),
        }
    }

    /// Delete epoch encryption key pairs.
    pub fn delete<GroupId, EpochKey>(
        &mut self,
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
        self.data.remove(&(group_id_bytes, epoch_bytes, leaf_index));
        Ok(())
    }
}

// -- Single-key stores (identical write/read/delete via macro) ----------------

mls_store_base!(
    /// In-memory storage for MLS key packages.
    /// Key: hash_ref bytes, Value: serialized key package bytes
    MlsKeyPackages, HashMap<Vec<u8>, Vec<u8>>
);
mls_single_key_ops!(MlsKeyPackages);

mls_store_base!(
    /// In-memory storage for MLS PSKs.
    /// Key: psk_id bytes, Value: serialized PSK bundle bytes
    MlsPsks, HashMap<Vec<u8>, Vec<u8>>
);
mls_single_key_ops!(MlsPsks);

mls_store_base!(
    /// In-memory storage for MLS signature keys.
    /// Key: public_key bytes, Value: serialized signature key pair bytes
    MlsSignatureKeys, HashMap<Vec<u8>, Vec<u8>>
);
mls_single_key_ops!(MlsSignatureKeys);

mls_store_base!(
    /// In-memory storage for MLS encryption keys.
    /// Key: public_key bytes, Value: serialized HPKE key pair bytes
    MlsEncryptionKeys, HashMap<Vec<u8>, Vec<u8>>
);
mls_single_key_ops!(MlsEncryptionKeys);

// ============================================================================
// Helper functions for serialization
// ============================================================================

/// Serialize a key to bytes for storage.
fn serialize_key<K>(key: &K) -> Result<Vec<u8>, MdkStorageError>
where
    K: Serialize,
{
    MlsCodec::serialize(key)
}

/// Serialize an entity to bytes for storage.
fn serialize_entity<E>(entity: &E) -> Result<Vec<u8>, MdkStorageError>
where
    E: Serialize,
{
    MlsCodec::serialize(entity)
}

/// Deserialize an entity from bytes.
fn deserialize_entity<E>(bytes: &[u8]) -> Result<E, MdkStorageError>
where
    E: DeserializeOwned,
{
    MlsCodec::deserialize(bytes)
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
        let mut store = MlsGroupData::new();
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
        let mut store = MlsKeyPackages::new();
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
        let mut store = MlsOwnLeafNodes::new();
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
        let mut store = MlsGroupData::new();
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

    // ========================================
    // MlsProposals Tests
    // ========================================

    #[test]
    fn test_proposals_queue_and_read() {
        let mut store = MlsProposals::new();
        let group_id = vec![1u8, 2, 3, 4];
        let proposal_ref = vec![10u8, 20, 30];
        let proposal = "test proposal".to_string();

        // Queue proposal
        store.queue(&group_id, &proposal_ref, &proposal).unwrap();

        // Read proposal refs
        let refs: Vec<Vec<u8>> = store.read_refs(&group_id).unwrap();
        assert_eq!(refs, vec![proposal_ref.clone()]);

        // Read proposals
        let proposals: Vec<(Vec<u8>, String)> = store.read_proposals(&group_id).unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].0, proposal_ref);
        assert_eq!(proposals[0].1, proposal);
    }

    #[test]
    fn test_proposals_remove_single() {
        let mut store = MlsProposals::new();
        let group_id = vec![1u8, 2, 3, 4];
        let proposal_ref = vec![10u8, 20, 30];
        let proposal = "test proposal".to_string();

        // Queue and remove
        store.queue(&group_id, &proposal_ref, &proposal).unwrap();
        store.remove(&group_id, &proposal_ref).unwrap();

        // Verify removed
        let proposals: Vec<(Vec<u8>, String)> = store.read_proposals(&group_id).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn test_proposals_clear() {
        let mut store = MlsProposals::new();
        let group_id = vec![1u8, 2, 3, 4];

        // Queue multiple proposals
        for i in 0..3 {
            let proposal_ref = vec![i as u8; 4];
            store
                .queue(&group_id, &proposal_ref, &format!("proposal_{}", i))
                .unwrap();
        }

        // Clear all
        store.clear(&group_id).unwrap();

        // Verify empty
        let proposals: Vec<(Vec<u8>, String)> = store.read_proposals(&group_id).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn test_proposals_read_empty() {
        let store = MlsProposals::new();
        let group_id = vec![1u8, 2, 3, 4];

        let refs: Vec<Vec<u8>> = store.read_refs(&group_id).unwrap();
        assert!(refs.is_empty());

        let proposals: Vec<(Vec<u8>, String)> = store.read_proposals(&group_id).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn test_proposals_snapshot_restore() {
        let mut store = MlsProposals::new();
        let group_id = vec![1u8, 2, 3, 4];
        let proposal_ref = vec![10u8, 20, 30];

        // Queue proposal
        store
            .queue(&group_id, &proposal_ref, &"original".to_string())
            .unwrap();

        // Take snapshot
        let snapshot = store.clone_data();

        // Clear proposals
        store.clear(&group_id).unwrap();

        // Verify cleared
        let proposals: Vec<(Vec<u8>, String)> = store.read_proposals(&group_id).unwrap();
        assert!(proposals.is_empty());

        // Restore snapshot
        store.restore_data(snapshot);

        // Verify restored
        let proposals: Vec<(Vec<u8>, String)> = store.read_proposals(&group_id).unwrap();
        assert_eq!(proposals.len(), 1);
    }

    // ========================================
    // MlsPsks Tests
    // ========================================

    #[test]
    fn test_psks_write_and_read() {
        let mut store = MlsPsks::new();
        let psk_id = vec![1u8, 2, 3, 4];
        let psk_bundle = "psk bundle data".to_string();

        // Write PSK
        store.write(&psk_id, &psk_bundle).unwrap();

        // Read PSK
        let result: Option<String> = store.read(&psk_id).unwrap();
        assert_eq!(result, Some(psk_bundle));
    }

    #[test]
    fn test_psks_read_nonexistent() {
        let store = MlsPsks::new();
        let psk_id = vec![1u8, 2, 3, 4];

        let result: Option<String> = store.read(&psk_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_psks_delete() {
        let mut store = MlsPsks::new();
        let psk_id = vec![1u8, 2, 3, 4];
        let psk_bundle = "psk bundle".to_string();

        // Write and delete
        store.write(&psk_id, &psk_bundle).unwrap();
        store.delete(&psk_id).unwrap();

        // Verify deleted
        let result: Option<String> = store.read(&psk_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_psks_overwrite() {
        let mut store = MlsPsks::new();
        let psk_id = vec![1u8, 2, 3, 4];

        // Write first
        store.write(&psk_id, &"first".to_string()).unwrap();

        // Overwrite
        store.write(&psk_id, &"second".to_string()).unwrap();

        // Verify second
        let result: Option<String> = store.read(&psk_id).unwrap();
        assert_eq!(result, Some("second".to_string()));
    }

    #[test]
    fn test_psks_snapshot_restore() {
        let mut store = MlsPsks::new();
        let psk_id = vec![1u8, 2, 3, 4];

        // Write
        store.write(&psk_id, &"original".to_string()).unwrap();

        // Snapshot
        let snapshot = store.clone_data();

        // Modify
        store.write(&psk_id, &"modified".to_string()).unwrap();

        // Restore
        store.restore_data(snapshot);

        // Verify
        let result: Option<String> = store.read(&psk_id).unwrap();
        assert_eq!(result, Some("original".to_string()));
    }

    // ========================================
    // MlsSignatureKeys Tests
    // ========================================

    #[test]
    fn test_signature_keys_write_and_read() {
        let mut store = MlsSignatureKeys::new();
        let public_key = vec![1u8, 2, 3, 4];
        let key_pair = "signature key pair".to_string();

        // Write
        store.write(&public_key, &key_pair).unwrap();

        // Read
        let result: Option<String> = store.read(&public_key).unwrap();
        assert_eq!(result, Some(key_pair));
    }

    #[test]
    fn test_signature_keys_read_nonexistent() {
        let store = MlsSignatureKeys::new();
        let public_key = vec![1u8, 2, 3, 4];

        let result: Option<String> = store.read(&public_key).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_signature_keys_delete() {
        let mut store = MlsSignatureKeys::new();
        let public_key = vec![1u8, 2, 3, 4];
        let key_pair = "signature key pair".to_string();

        // Write and delete
        store.write(&public_key, &key_pair).unwrap();
        store.delete(&public_key).unwrap();

        // Verify deleted
        let result: Option<String> = store.read(&public_key).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_signature_keys_snapshot_restore() {
        let mut store = MlsSignatureKeys::new();
        let public_key = vec![1u8, 2, 3, 4];

        // Write
        store.write(&public_key, &"original".to_string()).unwrap();

        // Snapshot
        let snapshot = store.clone_data();

        // Modify
        store.write(&public_key, &"modified".to_string()).unwrap();

        // Restore
        store.restore_data(snapshot);

        // Verify
        let result: Option<String> = store.read(&public_key).unwrap();
        assert_eq!(result, Some("original".to_string()));
    }

    // ========================================
    // MlsEncryptionKeys Tests
    // ========================================

    #[test]
    fn test_encryption_keys_write_and_read() {
        let mut store = MlsEncryptionKeys::new();
        let public_key = vec![1u8, 2, 3, 4];
        let key_pair = "encryption key pair".to_string();

        // Write
        store.write(&public_key, &key_pair).unwrap();

        // Read
        let result: Option<String> = store.read(&public_key).unwrap();
        assert_eq!(result, Some(key_pair));
    }

    #[test]
    fn test_encryption_keys_read_nonexistent() {
        let store = MlsEncryptionKeys::new();
        let public_key = vec![1u8, 2, 3, 4];

        let result: Option<String> = store.read(&public_key).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encryption_keys_delete() {
        let mut store = MlsEncryptionKeys::new();
        let public_key = vec![1u8, 2, 3, 4];
        let key_pair = "encryption key pair".to_string();

        // Write and delete
        store.write(&public_key, &key_pair).unwrap();
        store.delete(&public_key).unwrap();

        // Verify deleted
        let result: Option<String> = store.read(&public_key).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encryption_keys_snapshot_restore() {
        let mut store = MlsEncryptionKeys::new();
        let public_key = vec![1u8, 2, 3, 4];

        // Write
        store.write(&public_key, &"original".to_string()).unwrap();

        // Snapshot
        let snapshot = store.clone_data();

        // Modify
        store.write(&public_key, &"modified".to_string()).unwrap();

        // Restore
        store.restore_data(snapshot);

        // Verify
        let result: Option<String> = store.read(&public_key).unwrap();
        assert_eq!(result, Some("original".to_string()));
    }

    // ========================================
    // MlsEpochKeyPairs Tests
    // ========================================

    #[test]
    fn test_epoch_key_pairs_write_and_read() {
        let mut store = MlsEpochKeyPairs::new();
        let group_id = vec![1u8, 2, 3, 4];
        let epoch = 5u64;
        let leaf_index = 0u32;
        let key_pairs = vec!["key1".to_string(), "key2".to_string()];

        // Write
        store
            .write(&group_id, &epoch, leaf_index, &key_pairs)
            .unwrap();

        // Read
        let result: Vec<String> = store.read(&group_id, &epoch, leaf_index).unwrap();
        assert_eq!(result, key_pairs);
    }

    #[test]
    fn test_epoch_key_pairs_read_nonexistent() {
        let store = MlsEpochKeyPairs::new();
        let group_id = vec![1u8, 2, 3, 4];
        let epoch = 5u64;
        let leaf_index = 0u32;

        let result: Vec<String> = store.read(&group_id, &epoch, leaf_index).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_epoch_key_pairs_delete() {
        let mut store = MlsEpochKeyPairs::new();
        let group_id = vec![1u8, 2, 3, 4];
        let epoch = 5u64;
        let leaf_index = 0u32;
        let key_pairs = vec!["key".to_string()];

        // Write and delete
        store
            .write(&group_id, &epoch, leaf_index, &key_pairs)
            .unwrap();
        store.delete(&group_id, &epoch, leaf_index).unwrap();

        // Verify deleted (returns empty vec)
        let result: Vec<String> = store.read(&group_id, &epoch, leaf_index).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_epoch_key_pairs_different_epochs() {
        let mut store = MlsEpochKeyPairs::new();
        let group_id = vec![1u8, 2, 3, 4];
        let leaf_index = 0u32;

        let keys_epoch_1 = ["epoch1".to_string()];
        let keys_epoch_2 = ["epoch2".to_string()];

        // Write for different epochs
        store
            .write(&group_id, &1u64, leaf_index, &keys_epoch_1)
            .unwrap();
        store
            .write(&group_id, &2u64, leaf_index, &keys_epoch_2)
            .unwrap();

        // Verify each epoch
        let result1: Vec<String> = store.read(&group_id, &1u64, leaf_index).unwrap();
        let result2: Vec<String> = store.read(&group_id, &2u64, leaf_index).unwrap();

        assert_eq!(result1, vec!["epoch1".to_string()]);
        assert_eq!(result2, vec!["epoch2".to_string()]);
    }

    #[test]
    fn test_epoch_key_pairs_different_leaf_indices() {
        let mut store = MlsEpochKeyPairs::new();
        let group_id = vec![1u8, 2, 3, 4];
        let epoch = 1u64;

        let keys_leaf_0 = ["leaf0".to_string()];
        let keys_leaf_1 = ["leaf1".to_string()];

        // Write for different leaf indices
        store.write(&group_id, &epoch, 0, &keys_leaf_0).unwrap();
        store.write(&group_id, &epoch, 1, &keys_leaf_1).unwrap();

        // Verify each leaf index
        let result0: Vec<String> = store.read(&group_id, &epoch, 0).unwrap();
        let result1: Vec<String> = store.read(&group_id, &epoch, 1).unwrap();

        assert_eq!(result0, vec!["leaf0".to_string()]);
        assert_eq!(result1, vec!["leaf1".to_string()]);
    }

    #[test]
    fn test_epoch_key_pairs_snapshot_restore() {
        let mut store = MlsEpochKeyPairs::new();
        let group_id = vec![1u8, 2, 3, 4];
        let epoch = 1u64;
        let leaf_index = 0u32;

        let original = ["original".to_string()];
        let modified = ["modified".to_string()];

        // Write
        store
            .write(&group_id, &epoch, leaf_index, &original)
            .unwrap();

        // Snapshot
        let snapshot = store.clone_data();

        // Modify
        store
            .write(&group_id, &epoch, leaf_index, &modified)
            .unwrap();

        // Restore
        store.restore_data(snapshot);

        // Verify
        let result: Vec<String> = store.read(&group_id, &epoch, leaf_index).unwrap();
        assert_eq!(result, vec!["original".to_string()]);
    }

    // ========================================
    // Serialization Tests
    // ========================================

    #[test]
    fn test_serialize_key_success() {
        let key = vec![1u8, 2, 3, 4];
        let result = serialize_key(&key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_entity_success() {
        let entity = "test entity".to_string();
        let result = serialize_entity(&entity);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_entity_success() {
        let original = "test entity".to_string();
        let serialized = serialize_entity(&original).unwrap();
        let result: String = deserialize_entity(&serialized).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_deserialize_entity_invalid_data() {
        let invalid = b"not valid data";
        let result: Result<String, _> = deserialize_entity(invalid);
        assert!(result.is_err());
    }
}
