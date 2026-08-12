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
    const fn public(bytes: &'static [u8]) -> Self {
        Self {
            bytes,
            sensitivity: ValueSensitivity::Public,
        }
    }

    const fn secret(bytes: &'static [u8]) -> Self {
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

    #[cfg(test)]
    pub(in crate::openmls_storage) const fn test_public(bytes: &'static [u8]) -> Self {
        Self::public(bytes)
    }

    #[cfg(test)]
    pub(in crate::openmls_storage) const fn test_secret(bytes: &'static [u8]) -> Self {
        Self::secret(bytes)
    }
}

macro_rules! define_openmls_value_labels {
    ($($(#[$meta:meta])* $name:ident => $sensitivity:ident($bytes:literal);)+) => {
        $(
            $(#[$meta])*
            pub(crate) const $name: OpenMlsValueLabel =
                OpenMlsValueLabel::$sensitivity($bytes);
        )+

        #[cfg(test)]
        const ALL_LABELS: &[OpenMlsValueLabel] = &[$($name),+];
    };
}

define_openmls_value_labels! {
    /// OpenMLS's `KeyPackage` storage entity is a `KeyPackageBundle`, including
    /// its private init and leaf-encryption keys.
    KEY_PACKAGE_LABEL => secret(b"KeyPackage");
    PSK_LABEL => secret(b"Psk");
    ENCRYPTION_KEY_PAIR_LABEL => secret(b"EncryptionKeyPair");
    SIGNATURE_KEY_PAIR_LABEL => secret(b"SignatureKeyPair");
    EPOCH_KEY_PAIRS_LABEL => secret(b"EpochKeyPairs");
    TREE_LABEL => public(b"Tree");
    GROUP_CONTEXT_LABEL => public(b"GroupContext");
    APPLICATION_EXPORT_TREE_LABEL => secret(b"ApplicationExportTree");
    INTERIM_TRANSCRIPT_HASH_LABEL => public(b"InterimTranscriptHash");
    CONFIRMATION_TAG_LABEL => public(b"ConfirmationTag");
    JOIN_CONFIG_LABEL => public(b"MlsGroupJoinConfig");
    OWN_LEAF_NODES_LABEL => public(b"OwnLeafNodes");
    /// Pending `MlsGroupState` embeds staged epoch/message secrets and HPKE keypairs.
    GROUP_STATE_LABEL => secret(b"GroupState");
    QUEUED_PROPOSAL_LABEL => public(b"QueuedProposal");
    PROPOSAL_QUEUE_REFS_LABEL => public(b"ProposalQueueRefs");
    OWN_LEAF_NODE_INDEX_LABEL => public(b"OwnLeafNodeIndex");
    EPOCH_SECRETS_LABEL => secret(b"EpochSecrets");
    RESUMPTION_PSK_STORE_LABEL => secret(b"ResumptionPsk");
    MESSAGE_SECRETS_LABEL => secret(b"MessageSecrets");
}

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
        let secret_labels = [
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
        ];
        for label in secret_labels {
            assert_eq!(label.sensitivity(), ValueSensitivity::Secret);
        }

        assert_eq!(
            ALL_LABELS
                .iter()
                .filter(|label| label.sensitivity() == ValueSensitivity::Secret)
                .count(),
            secret_labels.len(),
            "the secret-label test list must exhaust the label registry"
        );
        for label in ALL_LABELS
            .iter()
            .filter(|label| label.sensitivity() == ValueSensitivity::Secret)
        {
            assert!(secret_labels.contains(label));
        }
    }

    #[test]
    fn public_only_openmls_labels_keep_ordinary_buffers() {
        let public_labels = [
            TREE_LABEL,
            GROUP_CONTEXT_LABEL,
            INTERIM_TRANSCRIPT_HASH_LABEL,
            CONFIRMATION_TAG_LABEL,
            JOIN_CONFIG_LABEL,
            OWN_LEAF_NODES_LABEL,
            QUEUED_PROPOSAL_LABEL,
            PROPOSAL_QUEUE_REFS_LABEL,
            OWN_LEAF_NODE_INDEX_LABEL,
        ];
        for label in public_labels {
            assert_eq!(label.sensitivity(), ValueSensitivity::Public);
        }

        assert_eq!(
            ALL_LABELS
                .iter()
                .filter(|label| label.sensitivity() == ValueSensitivity::Public)
                .count(),
            public_labels.len(),
            "the public-label test list must exhaust the label registry"
        );
        for label in ALL_LABELS
            .iter()
            .filter(|label| label.sensitivity() == ValueSensitivity::Public)
        {
            assert!(public_labels.contains(label));
        }
    }
}
