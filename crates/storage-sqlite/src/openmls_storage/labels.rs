use super::SqliteOpenMlsStorageError;
use openmls_traits::storage::{CURRENT_VERSION, traits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::openmls_storage) enum ValueSensitivity {
    Public,
    Secret,
}

/// A stable OpenMLS storage label with an explicit serialized-value sensitivity.
///
/// Requiring this type at the value-store boundary prevents a newly added label
/// from silently inheriting ordinary `Vec<u8>` serialization buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::openmls_storage) struct OpenMlsValueLabel {
    bytes: &'static [u8],
    sensitivity: ValueSensitivity,
}

impl OpenMlsValueLabel {
    pub(in crate::openmls_storage) const fn public(bytes: &'static [u8]) -> Self {
        Self {
            bytes,
            sensitivity: ValueSensitivity::Public,
        }
    }

    pub(in crate::openmls_storage) const fn secret(bytes: &'static [u8]) -> Self {
        Self {
            bytes,
            sensitivity: ValueSensitivity::Secret,
        }
    }

    pub(in crate::openmls_storage) const fn as_bytes(self) -> &'static [u8] {
        self.bytes
    }

    pub(in crate::openmls_storage) const fn sensitivity(self) -> ValueSensitivity {
        self.sensitivity
    }
}

// OpenMLS's `KeyPackage` storage entity is a `KeyPackageBundle`, including its
// private init and leaf-encryption keys.
pub(crate) const KEY_PACKAGE_LABEL: OpenMlsValueLabel = OpenMlsValueLabel::secret(b"KeyPackage");
pub(crate) const PSK_LABEL: OpenMlsValueLabel = OpenMlsValueLabel::secret(b"Psk");
pub(crate) const ENCRYPTION_KEY_PAIR_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::secret(b"EncryptionKeyPair");
pub(crate) const SIGNATURE_KEY_PAIR_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::secret(b"SignatureKeyPair");
pub(crate) const EPOCH_KEY_PAIRS_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::secret(b"EpochKeyPairs");
pub(crate) const TREE_LABEL: OpenMlsValueLabel = OpenMlsValueLabel::public(b"Tree");
pub(crate) const GROUP_CONTEXT_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"GroupContext");
pub(crate) const APPLICATION_EXPORT_TREE_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::secret(b"ApplicationExportTree");
pub(crate) const INTERIM_TRANSCRIPT_HASH_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"InterimTranscriptHash");
pub(crate) const CONFIRMATION_TAG_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"ConfirmationTag");
pub(crate) const JOIN_CONFIG_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"MlsGroupJoinConfig");
pub(crate) const OWN_LEAF_NODES_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"OwnLeafNodes");
// Pending `MlsGroupState` embeds staged epoch/message secrets and HPKE keypairs.
pub(crate) const GROUP_STATE_LABEL: OpenMlsValueLabel = OpenMlsValueLabel::secret(b"GroupState");
pub(crate) const QUEUED_PROPOSAL_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"QueuedProposal");
pub(crate) const PROPOSAL_QUEUE_REFS_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"ProposalQueueRefs");
pub(crate) const OWN_LEAF_NODE_INDEX_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::public(b"OwnLeafNodeIndex");
pub(crate) const EPOCH_SECRETS_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::secret(b"EpochSecrets");
pub(crate) const RESUMPTION_PSK_STORE_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::secret(b"ResumptionPsk");
pub(crate) const MESSAGE_SECRETS_LABEL: OpenMlsValueLabel =
    OpenMlsValueLabel::secret(b"MessageSecrets");

const VALUE_STORAGE_KEY_V1: &[u8] = b"mdk.openmls.value-key.v1";

pub(crate) fn build_key(label: &[u8], key: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        VALUE_STORAGE_KEY_V1.len() + 8 + label.len() + 8 + key.len() + std::mem::size_of::<u16>(),
    );
    out.extend_from_slice(VALUE_STORAGE_KEY_V1);
    out.extend_from_slice(&(label.len() as u64).to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&(key.len() as u64).to_be_bytes());
    out.extend_from_slice(&key);
    out.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
    out
}

/// Reconstructs the pre-#349 generic value-store key: the bare concatenation
/// of label, key, and provider version.
///
/// This format is ambiguous because the label/key boundary is not encoded:
/// `(label = "A", key = "BC")` and `(label = "AB", key = "C")` collide. New
/// writes must use [`build_key`]. Legacy keys remain readable/deletable so
/// upgraded databases do not strand OpenMLS rows written by older builds.
pub(crate) fn build_key_legacy(label: &[u8], key: Vec<u8>) -> Vec<u8> {
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
    // Encode as a single JSON tuple so component boundaries are unambiguous.
    // Bare concatenation of the JSON encodings is unsafe here: GroupEpoch and
    // leaf_index both serialize to undelimited digit strings, so distinct
    // (epoch, leaf_index) pairs could collide (e.g. (3, 45) and (34, 5) both
    // yield "...345"). A colliding key under INSERT OR REPLACE would silently
    // clobber unrelated HPKE epoch key pairs. This mirrors the unambiguous
    // tuple pattern already used for queued-proposal keys in provider.rs.
    Ok(serde_json::to_vec(&(group_id, epoch, leaf_index))?)
}

/// Reconstructs the pre-#158 EpochKeyPairs storage key: the bare concatenation
/// of the JSON encodings of `group_id`, `epoch`, and `leaf_index`.
///
/// This format is ambiguous (see [`epoch_key_pairs_id`]) and must never be used
/// for new writes. It exists only so reads and deletes can still reach rows that
/// were written before the key format was disambiguated, keeping an upgraded
/// group's current-epoch HPKE private key material reachable until OpenMLS
/// re-stores it under the new tuple key. Once a tuple-key row exists for a given
/// (group, epoch, leaf) it takes precedence and the legacy key is never consulted.
pub(crate) fn epoch_key_pairs_id_legacy(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, SqliteOpenMlsStorageError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bearing_openmls_labels_require_zeroizing_buffers() {
        for label in [
            KEY_PACKAGE_LABEL,
            PSK_LABEL,
            ENCRYPTION_KEY_PAIR_LABEL,
            SIGNATURE_KEY_PAIR_LABEL,
            EPOCH_KEY_PAIRS_LABEL,
            APPLICATION_EXPORT_TREE_LABEL,
            GROUP_STATE_LABEL,
            EPOCH_SECRETS_LABEL,
            RESUMPTION_PSK_STORE_LABEL,
            MESSAGE_SECRETS_LABEL,
        ] {
            assert_eq!(label.sensitivity(), ValueSensitivity::Secret);
        }
    }

    #[test]
    fn public_only_openmls_labels_keep_ordinary_buffers() {
        for label in [
            TREE_LABEL,
            GROUP_CONTEXT_LABEL,
            INTERIM_TRANSCRIPT_HASH_LABEL,
            CONFIRMATION_TAG_LABEL,
            JOIN_CONFIG_LABEL,
            OWN_LEAF_NODES_LABEL,
            QUEUED_PROPOSAL_LABEL,
            PROPOSAL_QUEUE_REFS_LABEL,
            OWN_LEAF_NODE_INDEX_LABEL,
        ] {
            assert_eq!(label.sensitivity(), ValueSensitivity::Public);
        }
    }
}
