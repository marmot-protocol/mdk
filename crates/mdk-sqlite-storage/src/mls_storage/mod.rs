//! OpenMLS StorageProvider implementation for SQLite.
//!
//! This module implements the `StorageProvider<1>` trait from `openmls_traits`
//! directly on `MdkSqliteStorage`, enabling unified storage for both MLS
//! cryptographic state and MDK-specific data within a single database connection.

pub mod codec;

use mdk_storage_traits::MdkStorageError;
use openmls_traits::storage::{Entity, Key};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use self::codec::JsonCodec;

/// The storage provider version matching OpenMLS's CURRENT_VERSION.
pub const STORAGE_PROVIDER_VERSION: u16 = 1;

/// Types of group data stored in the openmls_group_data table.
#[derive(Debug, Clone, Copy)]
pub enum GroupDataType {
    /// MLS group join configuration
    JoinGroupConfig,
    /// TreeSync tree structure
    Tree,
    /// Interim transcript hash
    InterimTranscriptHash,
    /// Group context
    Context,
    /// Confirmation tag
    ConfirmationTag,
    /// Group state (active, inactive, etc.)
    GroupState,
    /// Message secrets for decryption
    MessageSecrets,
    /// Resumption PSK store
    ResumptionPskStore,
    /// Own leaf index in the tree
    OwnLeafIndex,
    /// Group epoch secrets
    GroupEpochSecrets,
}

impl GroupDataType {
    /// Convert to string for database storage.
    fn as_str(&self) -> &'static str {
        match self {
            Self::JoinGroupConfig => "join_group_config",
            Self::Tree => "tree",
            Self::InterimTranscriptHash => "interim_transcript_hash",
            Self::Context => "context",
            Self::ConfirmationTag => "confirmation_tag",
            Self::GroupState => "group_state",
            Self::MessageSecrets => "message_secrets",
            Self::ResumptionPskStore => "resumption_psk_store",
            Self::OwnLeafIndex => "own_leaf_index",
            Self::GroupEpochSecrets => "group_epoch_secrets",
        }
    }
}

// ============================================================================
// Helper functions for serialization
// ============================================================================

/// Serialize a key to bytes for database storage.
fn serialize_key<K>(key: &K) -> Result<Vec<u8>, MdkStorageError>
where
    K: Serialize,
{
    JsonCodec::serialize(key)
}

/// Serialize an entity to bytes for database storage.
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

// ============================================================================
// Group Data Operations
// ============================================================================

/// Write group data to the database.
pub(crate) fn write_group_data<GroupId, GroupData>(
    conn: &Connection,
    group_id: &GroupId,
    data_type: GroupDataType,
    data: &GroupData,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    GroupData: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;
    let data_bytes = serialize_entity(data)?;

    conn.execute(
        "INSERT OR REPLACE INTO openmls_group_data (group_id, data_type, group_data, provider_version)
         VALUES (?, ?, ?, ?)",
        params![group_id_bytes, data_type.as_str(), data_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read group data from the database.
pub(crate) fn read_group_data<GroupId, GroupData>(
    conn: &Connection,
    group_id: &GroupId,
    data_type: GroupDataType,
) -> Result<Option<GroupData>, MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    GroupData: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT group_data FROM openmls_group_data
             WHERE group_id = ? AND data_type = ? AND provider_version = ?",
            params![group_id_bytes, data_type.as_str(), STORAGE_PROVIDER_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    match result {
        Some(bytes) => Ok(Some(deserialize_entity(&bytes)?)),
        None => Ok(None),
    }
}

/// Delete group data from the database.
pub(crate) fn delete_group_data<GroupId>(
    conn: &Connection,
    group_id: &GroupId,
    data_type: GroupDataType,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;

    conn.execute(
        "DELETE FROM openmls_group_data
         WHERE group_id = ? AND data_type = ? AND provider_version = ?",
        params![group_id_bytes, data_type.as_str(), STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

// ============================================================================
// Own Leaf Nodes Operations
// ============================================================================

/// Append an own leaf node for a group.
pub(crate) fn append_own_leaf_node<GroupId, LeafNode>(
    conn: &Connection,
    group_id: &GroupId,
    leaf_node: &LeafNode,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    LeafNode: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;
    let leaf_node_bytes = serialize_entity(leaf_node)?;

    conn.execute(
        "INSERT INTO openmls_own_leaf_nodes (group_id, leaf_node, provider_version)
         VALUES (?, ?, ?)",
        params![group_id_bytes, leaf_node_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read all own leaf nodes for a group.
pub(crate) fn read_own_leaf_nodes<GroupId, LeafNode>(
    conn: &Connection,
    group_id: &GroupId,
) -> Result<Vec<LeafNode>, MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    LeafNode: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;

    let mut stmt = conn
        .prepare(
            "SELECT leaf_node FROM openmls_own_leaf_nodes
             WHERE group_id = ? AND provider_version = ?
             ORDER BY id ASC",
        )
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    let rows = stmt
        .query_map(params![group_id_bytes, STORAGE_PROVIDER_VERSION], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    let mut leaf_nodes = Vec::new();
    for row in rows {
        let bytes = row.map_err(|e| MdkStorageError::Database(e.to_string()))?;
        leaf_nodes.push(deserialize_entity(&bytes)?);
    }

    Ok(leaf_nodes)
}

/// Delete all own leaf nodes for a group.
pub(crate) fn delete_own_leaf_nodes<GroupId>(
    conn: &Connection,
    group_id: &GroupId,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;

    conn.execute(
        "DELETE FROM openmls_own_leaf_nodes
         WHERE group_id = ? AND provider_version = ?",
        params![group_id_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

// ============================================================================
// Proposals Operations
// ============================================================================

/// Queue a proposal for a group.
pub(crate) fn queue_proposal<GroupId, ProposalRef, QueuedProposal>(
    conn: &Connection,
    group_id: &GroupId,
    proposal_ref: &ProposalRef,
    proposal: &QueuedProposal,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    ProposalRef: Key<STORAGE_PROVIDER_VERSION> + Entity<STORAGE_PROVIDER_VERSION>,
    QueuedProposal: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;
    let proposal_ref_bytes = serialize_key(proposal_ref)?;
    let proposal_bytes = serialize_entity(proposal)?;

    conn.execute(
        "INSERT OR REPLACE INTO openmls_proposals (group_id, proposal_ref, proposal, provider_version)
         VALUES (?, ?, ?, ?)",
        params![group_id_bytes, proposal_ref_bytes, proposal_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read all queued proposal refs for a group.
pub(crate) fn read_queued_proposal_refs<GroupId, ProposalRef>(
    conn: &Connection,
    group_id: &GroupId,
) -> Result<Vec<ProposalRef>, MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    ProposalRef: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;

    let mut stmt = conn
        .prepare(
            "SELECT proposal_ref FROM openmls_proposals
             WHERE group_id = ? AND provider_version = ?",
        )
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    let rows = stmt
        .query_map(params![group_id_bytes, STORAGE_PROVIDER_VERSION], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    let mut refs = Vec::new();
    for row in rows {
        let bytes = row.map_err(|e| MdkStorageError::Database(e.to_string()))?;
        refs.push(deserialize_entity(&bytes)?);
    }

    Ok(refs)
}

/// Read all queued proposals for a group.
pub(crate) fn read_queued_proposals<GroupId, ProposalRef, QueuedProposal>(
    conn: &Connection,
    group_id: &GroupId,
) -> Result<Vec<(ProposalRef, QueuedProposal)>, MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    ProposalRef: Entity<STORAGE_PROVIDER_VERSION>,
    QueuedProposal: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;

    let mut stmt = conn
        .prepare(
            "SELECT proposal_ref, proposal FROM openmls_proposals
             WHERE group_id = ? AND provider_version = ?",
        )
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    let rows = stmt
        .query_map(params![group_id_bytes, STORAGE_PROVIDER_VERSION], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    let mut proposals = Vec::new();
    for row in rows {
        let (ref_bytes, proposal_bytes) =
            row.map_err(|e| MdkStorageError::Database(e.to_string()))?;
        let proposal_ref: ProposalRef = deserialize_entity(&ref_bytes)?;
        let proposal: QueuedProposal = deserialize_entity(&proposal_bytes)?;
        proposals.push((proposal_ref, proposal));
    }

    Ok(proposals)
}

/// Remove a single proposal from a group's queue.
pub(crate) fn remove_proposal<GroupId, ProposalRef>(
    conn: &Connection,
    group_id: &GroupId,
    proposal_ref: &ProposalRef,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    ProposalRef: Key<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;
    let proposal_ref_bytes = serialize_key(proposal_ref)?;

    conn.execute(
        "DELETE FROM openmls_proposals
         WHERE group_id = ? AND proposal_ref = ? AND provider_version = ?",
        params![group_id_bytes, proposal_ref_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Clear all proposals for a group.
pub(crate) fn clear_proposal_queue<GroupId>(
    conn: &Connection,
    group_id: &GroupId,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;

    conn.execute(
        "DELETE FROM openmls_proposals
         WHERE group_id = ? AND provider_version = ?",
        params![group_id_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

// ============================================================================
// Key Packages Operations
// ============================================================================

/// Write a key package.
pub(crate) fn write_key_package<HashReference, KeyPackage>(
    conn: &Connection,
    hash_ref: &HashReference,
    key_package: &KeyPackage,
) -> Result<(), MdkStorageError>
where
    HashReference: Key<STORAGE_PROVIDER_VERSION>,
    KeyPackage: Entity<STORAGE_PROVIDER_VERSION>,
{
    let hash_ref_bytes = serialize_key(hash_ref)?;
    let key_package_bytes = serialize_entity(key_package)?;

    conn.execute(
        "INSERT OR REPLACE INTO openmls_key_packages (key_package_ref, key_package, provider_version)
         VALUES (?, ?, ?)",
        params![hash_ref_bytes, key_package_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read a key package.
pub(crate) fn read_key_package<HashReference, KeyPackage>(
    conn: &Connection,
    hash_ref: &HashReference,
) -> Result<Option<KeyPackage>, MdkStorageError>
where
    HashReference: Key<STORAGE_PROVIDER_VERSION>,
    KeyPackage: Entity<STORAGE_PROVIDER_VERSION>,
{
    let hash_ref_bytes = serialize_key(hash_ref)?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT key_package FROM openmls_key_packages
             WHERE key_package_ref = ? AND provider_version = ?",
            params![hash_ref_bytes, STORAGE_PROVIDER_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    match result {
        Some(bytes) => Ok(Some(deserialize_entity(&bytes)?)),
        None => Ok(None),
    }
}

/// Delete a key package.
pub(crate) fn delete_key_package<HashReference>(
    conn: &Connection,
    hash_ref: &HashReference,
) -> Result<(), MdkStorageError>
where
    HashReference: Key<STORAGE_PROVIDER_VERSION>,
{
    let hash_ref_bytes = serialize_key(hash_ref)?;

    conn.execute(
        "DELETE FROM openmls_key_packages
         WHERE key_package_ref = ? AND provider_version = ?",
        params![hash_ref_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

// ============================================================================
// Signature Keys Operations
// ============================================================================

/// Write a signature key pair.
pub(crate) fn write_signature_key_pair<SignaturePublicKey, SignatureKeyPair>(
    conn: &Connection,
    public_key: &SignaturePublicKey,
    signature_key_pair: &SignatureKeyPair,
) -> Result<(), MdkStorageError>
where
    SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>,
    SignatureKeyPair: Entity<STORAGE_PROVIDER_VERSION>,
{
    let public_key_bytes = serialize_key(public_key)?;
    let key_pair_bytes = serialize_entity(signature_key_pair)?;

    conn.execute(
        "INSERT OR REPLACE INTO openmls_signature_keys (public_key, signature_key, provider_version)
         VALUES (?, ?, ?)",
        params![public_key_bytes, key_pair_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read a signature key pair.
pub(crate) fn read_signature_key_pair<SignaturePublicKey, SignatureKeyPair>(
    conn: &Connection,
    public_key: &SignaturePublicKey,
) -> Result<Option<SignatureKeyPair>, MdkStorageError>
where
    SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>,
    SignatureKeyPair: Entity<STORAGE_PROVIDER_VERSION>,
{
    let public_key_bytes = serialize_key(public_key)?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT signature_key FROM openmls_signature_keys
             WHERE public_key = ? AND provider_version = ?",
            params![public_key_bytes, STORAGE_PROVIDER_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    match result {
        Some(bytes) => Ok(Some(deserialize_entity(&bytes)?)),
        None => Ok(None),
    }
}

/// Delete a signature key pair.
pub(crate) fn delete_signature_key_pair<SignaturePublicKey>(
    conn: &Connection,
    public_key: &SignaturePublicKey,
) -> Result<(), MdkStorageError>
where
    SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>,
{
    let public_key_bytes = serialize_key(public_key)?;

    conn.execute(
        "DELETE FROM openmls_signature_keys
         WHERE public_key = ? AND provider_version = ?",
        params![public_key_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

// ============================================================================
// Encryption Keys Operations
// ============================================================================

/// Write an encryption key pair.
pub(crate) fn write_encryption_key_pair<EncryptionKey, HpkeKeyPair>(
    conn: &Connection,
    public_key: &EncryptionKey,
    key_pair: &HpkeKeyPair,
) -> Result<(), MdkStorageError>
where
    EncryptionKey: Key<STORAGE_PROVIDER_VERSION>,
    HpkeKeyPair: Entity<STORAGE_PROVIDER_VERSION>,
{
    let public_key_bytes = serialize_key(public_key)?;
    let key_pair_bytes = serialize_entity(key_pair)?;

    conn.execute(
        "INSERT OR REPLACE INTO openmls_encryption_keys (public_key, key_pair, provider_version)
         VALUES (?, ?, ?)",
        params![public_key_bytes, key_pair_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read an encryption key pair.
pub(crate) fn read_encryption_key_pair<EncryptionKey, HpkeKeyPair>(
    conn: &Connection,
    public_key: &EncryptionKey,
) -> Result<Option<HpkeKeyPair>, MdkStorageError>
where
    EncryptionKey: Key<STORAGE_PROVIDER_VERSION>,
    HpkeKeyPair: Entity<STORAGE_PROVIDER_VERSION>,
{
    let public_key_bytes = serialize_key(public_key)?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT key_pair FROM openmls_encryption_keys
             WHERE public_key = ? AND provider_version = ?",
            params![public_key_bytes, STORAGE_PROVIDER_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    match result {
        Some(bytes) => Ok(Some(deserialize_entity(&bytes)?)),
        None => Ok(None),
    }
}

/// Delete an encryption key pair.
pub(crate) fn delete_encryption_key_pair<EncryptionKey>(
    conn: &Connection,
    public_key: &EncryptionKey,
) -> Result<(), MdkStorageError>
where
    EncryptionKey: Key<STORAGE_PROVIDER_VERSION>,
{
    let public_key_bytes = serialize_key(public_key)?;

    conn.execute(
        "DELETE FROM openmls_encryption_keys
         WHERE public_key = ? AND provider_version = ?",
        params![public_key_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

// ============================================================================
// Epoch Key Pairs Operations
// ============================================================================

/// Write epoch encryption key pairs.
pub(crate) fn write_encryption_epoch_key_pairs<GroupId, EpochKey, HpkeKeyPair>(
    conn: &Connection,
    group_id: &GroupId,
    epoch: &EpochKey,
    leaf_index: u32,
    key_pairs: &[HpkeKeyPair],
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    EpochKey: Key<STORAGE_PROVIDER_VERSION>,
    HpkeKeyPair: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;
    let epoch_bytes = serialize_key(epoch)?;
    let key_pairs_bytes = serialize_entity(&key_pairs)?;

    conn.execute(
        "INSERT OR REPLACE INTO openmls_epoch_key_pairs (group_id, epoch_id, leaf_index, key_pairs, provider_version)
         VALUES (?, ?, ?, ?, ?)",
        params![group_id_bytes, epoch_bytes, leaf_index, key_pairs_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read epoch encryption key pairs.
pub(crate) fn read_encryption_epoch_key_pairs<GroupId, EpochKey, HpkeKeyPair>(
    conn: &Connection,
    group_id: &GroupId,
    epoch: &EpochKey,
    leaf_index: u32,
) -> Result<Vec<HpkeKeyPair>, MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    EpochKey: Key<STORAGE_PROVIDER_VERSION>,
    HpkeKeyPair: Entity<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;
    let epoch_bytes = serialize_key(epoch)?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT key_pairs FROM openmls_epoch_key_pairs
             WHERE group_id = ? AND epoch_id = ? AND leaf_index = ? AND provider_version = ?",
            params![
                group_id_bytes,
                epoch_bytes,
                leaf_index,
                STORAGE_PROVIDER_VERSION
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    match result {
        Some(bytes) => deserialize_entity(&bytes),
        None => Ok(Vec::new()),
    }
}

/// Delete epoch encryption key pairs.
pub(crate) fn delete_encryption_epoch_key_pairs<GroupId, EpochKey>(
    conn: &Connection,
    group_id: &GroupId,
    epoch: &EpochKey,
    leaf_index: u32,
) -> Result<(), MdkStorageError>
where
    GroupId: Key<STORAGE_PROVIDER_VERSION>,
    EpochKey: Key<STORAGE_PROVIDER_VERSION>,
{
    let group_id_bytes = serialize_key(group_id)?;
    let epoch_bytes = serialize_key(epoch)?;

    conn.execute(
        "DELETE FROM openmls_epoch_key_pairs
         WHERE group_id = ? AND epoch_id = ? AND leaf_index = ? AND provider_version = ?",
        params![
            group_id_bytes,
            epoch_bytes,
            leaf_index,
            STORAGE_PROVIDER_VERSION
        ],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

// ============================================================================
// PSK Operations
// ============================================================================

/// Write a PSK bundle.
pub(crate) fn write_psk<PskId, PskBundle>(
    conn: &Connection,
    psk_id: &PskId,
    psk: &PskBundle,
) -> Result<(), MdkStorageError>
where
    PskId: Key<STORAGE_PROVIDER_VERSION>,
    PskBundle: Entity<STORAGE_PROVIDER_VERSION>,
{
    let psk_id_bytes = serialize_key(psk_id)?;
    let psk_bytes = serialize_entity(psk)?;

    conn.execute(
        "INSERT OR REPLACE INTO openmls_psks (psk_id, psk_bundle, provider_version)
         VALUES (?, ?, ?)",
        params![psk_id_bytes, psk_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}

/// Read a PSK bundle.
pub(crate) fn read_psk<PskId, PskBundle>(
    conn: &Connection,
    psk_id: &PskId,
) -> Result<Option<PskBundle>, MdkStorageError>
where
    PskId: Key<STORAGE_PROVIDER_VERSION>,
    PskBundle: Entity<STORAGE_PROVIDER_VERSION>,
{
    let psk_id_bytes = serialize_key(psk_id)?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT psk_bundle FROM openmls_psks
             WHERE psk_id = ? AND provider_version = ?",
            params![psk_id_bytes, STORAGE_PROVIDER_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    match result {
        Some(bytes) => Ok(Some(deserialize_entity(&bytes)?)),
        None => Ok(None),
    }
}

/// Delete a PSK bundle.
pub(crate) fn delete_psk<PskId>(conn: &Connection, psk_id: &PskId) -> Result<(), MdkStorageError>
where
    PskId: Key<STORAGE_PROVIDER_VERSION>,
{
    let psk_id_bytes = serialize_key(psk_id)?;

    conn.execute(
        "DELETE FROM openmls_psks
         WHERE psk_id = ? AND provider_version = ?",
        params![psk_id_bytes, STORAGE_PROVIDER_VERSION],
    )
    .map_err(|e| MdkStorageError::Database(e.to_string()))?;

    Ok(())
}
