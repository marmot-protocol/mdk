use super::SqliteOpenMlsStorageError;
use openmls_traits::storage::{CURRENT_VERSION, traits};

pub(crate) const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
pub(crate) const PSK_LABEL: &[u8] = b"Psk";
pub(crate) const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
pub(crate) const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
pub(crate) const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";
pub(crate) const TREE_LABEL: &[u8] = b"Tree";
pub(crate) const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
pub(crate) const APPLICATION_EXPORT_TREE_LABEL: &[u8] = b"ApplicationExportTree";
pub(crate) const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
pub(crate) const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";
pub(crate) const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
pub(crate) const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
pub(crate) const GROUP_STATE_LABEL: &[u8] = b"GroupState";
pub(crate) const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
pub(crate) const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
pub(crate) const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
pub(crate) const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
pub(crate) const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
pub(crate) const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";

pub(crate) fn build_key(label: &[u8], key: Vec<u8>) -> Vec<u8> {
    let mut out = label.to_vec();
    out.extend_from_slice(&key);
    out.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
    out
}

pub(crate) fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, SqliteOpenMlsStorageError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}
