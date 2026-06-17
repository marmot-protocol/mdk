use super::labels::*;
use super::{SqliteOpenMlsStorage, SqliteOpenMlsStorageError};
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};

impl StorageProvider<CURRENT_VERSION> for SqliteOpenMlsStorage {
    type Error = SqliteOpenMlsStorageError;

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(JOIN_CONFIG_LABEL, group_id, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let group_key = Self::group_key(group_id)?;
        self.append_entity(
            OWN_LEAF_NODES_LABEL,
            group_key.clone(),
            Some(group_key),
            leaf_node,
        )
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let group_key = Self::group_key(group_id)?;
        let proposal_key = serde_json::to_vec(&(group_id, proposal_ref))?;
        self.write_entity(
            QUEUED_PROPOSAL_LABEL,
            proposal_key,
            Some(group_key.clone()),
            proposal,
        )?;
        self.append_entity(
            PROPOSAL_QUEUE_REFS_LABEL,
            group_key.clone(),
            Some(group_key),
            proposal_ref,
        )
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(TREE_LABEL, group_id, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            group_id,
            interim_transcript_hash,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(GROUP_CONTEXT_LABEL, group_id, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(CONFIRMATION_TAG_LABEL, group_id, confirmation_tag)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(GROUP_STATE_LABEL, group_id, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(MESSAGE_SECRETS_LABEL, group_id, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(RESUMPTION_PSK_STORE_LABEL, group_id, resumption_psk_store)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(OWN_LEAF_NODE_INDEX_LABEL, group_id, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(EPOCH_SECRETS_LABEL, group_id, group_epoch_secrets)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            SIGNATURE_KEY_PAIR_LABEL,
            serde_json::to_vec(public_key)?,
            None,
            signature_key_pair,
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            ENCRYPTION_KEY_PAIR_LABEL,
            serde_json::to_vec(public_key)?,
            None,
            key_pair,
        )
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        self.write_value(
            EPOCH_KEY_PAIRS_LABEL,
            epoch_key_pairs_id(group_id, epoch, leaf_index)?,
            Some(Self::group_key(group_id)?),
            serde_json::to_vec(key_pairs)?,
        )
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.write_entity(
            KEY_PACKAGE_LABEL,
            serde_json::to_vec(hash_ref)?,
            None,
            key_package,
        )
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write_entity(PSK_LABEL, serde_json::to_vec(psk_id)?, None, psk)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read_group_entity(JOIN_CONFIG_LABEL, group_id)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list(OWN_LEAF_NODES_LABEL, Self::group_key(group_id)?)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list(PROPOSAL_QUEUE_REFS_LABEL, Self::group_key(group_id)?)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> = match self
            .read_list(PROPOSAL_QUEUE_REFS_LABEL, Self::group_key(group_id)?)
        {
            Ok(refs) => refs,
            // The ref-list blob itself is present but undeserializable (truncated,
            // garbled, or a storage-format skew). This is the same cached-queue
            // corruption class as a dangling ref or a corrupt QueuedProposal entity:
            // recover by clearing the queue rather than bricking group load. Commits
            // after recovery start from the current MLS group state and require
            // proposals to be re-enqueued. Only deserialization failures are
            // recoverable here; operational SQLite/lock errors still propagate so a
            // transient backend fault is never mistaken for corruption.
            Err(SqliteOpenMlsStorageError::Serialization(_)) => {
                tracing::warn!(
                    target: "marmot.storage_sqlite.openmls",
                    method = "queued_proposals",
                    "clearing corrupted OpenMLS proposal queue after undeserializable proposal-queue ref list"
                );
                self.delete_group_labels(
                    group_id,
                    &[QUEUED_PROPOSAL_LABEL, PROPOSAL_QUEUE_REFS_LABEL],
                )?;
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        let mut proposals = Vec::with_capacity(refs.len());
        for proposal_ref in refs {
            let key = serde_json::to_vec(&(group_id, &proposal_ref))?;
            match self.read_entity(QUEUED_PROPOSAL_LABEL, key) {
                Ok(Some(proposal)) => proposals.push((proposal_ref, proposal)),
                Ok(None) => {
                    // A ref without its entity (dangling reference) means the persisted
                    // queue is no longer authoritative. Recover by clearing the entire
                    // queue instead of loading a partial subset: commits after recovery
                    // start from the current MLS group state and require proposals to be
                    // re-enqueued. This keeps corrupted historical queue state from
                    // silently influencing a future commit while still allowing group
                    // load (issue #315).
                    self.recover_corrupt_proposal_queue(
                        group_id,
                        "clearing corrupted OpenMLS proposal queue after dangling proposal reference",
                    )?;
                    return Ok(Vec::new());
                }
                Err(SqliteOpenMlsStorageError::Serialization(_)) => {
                    // The ref's entity row is present but its JSON blob fails to
                    // deserialize (out-of-band corruption, a partial write, or a
                    // storage-format skew). Treat undeserializable queue contents as the
                    // same recoverable corruption as a dangling ref: a partial/garbled
                    // queue must not silently influence a future commit, and permanently
                    // bricking group load is the worse failure mode (issue #350). Only the
                    // deserialize error is recovered here; Sqlite/Lock errors are
                    // operational rather than corruption, so they still propagate.
                    self.recover_corrupt_proposal_queue(
                        group_id,
                        "clearing corrupted OpenMLS proposal queue after undeserializable queued proposal",
                    )?;
                    return Ok(Vec::new());
                }
                Err(err) => return Err(err),
            }
        }
        Ok(proposals)
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read_group_entity(TREE_LABEL, group_id)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read_group_entity(GROUP_CONTEXT_LABEL, group_id)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read_group_entity(INTERIM_TRANSCRIPT_HASH_LABEL, group_id)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read_group_entity(CONFIRMATION_TAG_LABEL, group_id)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read_group_entity(GROUP_STATE_LABEL, group_id)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read_group_entity(MESSAGE_SECRETS_LABEL, group_id)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read_group_entity(RESUMPTION_PSK_STORE_LABEL, group_id)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read_group_entity(OWN_LEAF_NODE_INDEX_LABEL, group_id)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read_group_entity(EPOCH_SECRETS_LABEL, group_id)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.read_entity(SIGNATURE_KEY_PAIR_LABEL, serde_json::to_vec(public_key)?)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read_entity(ENCRYPTION_KEY_PAIR_LABEL, serde_json::to_vec(public_key)?)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        // Prefer the unambiguous tuple key (#158). Fall back to the legacy
        // concatenated key so rows written before the key format was
        // disambiguated stay reachable after upgrade: the current epoch's HPKE
        // private key material must remain readable until OpenMLS next re-stores
        // it under the new key, otherwise an in-flight commit could fail to find
        // the keys needed to process it.
        if let Some(value) = self.read_json(
            EPOCH_KEY_PAIRS_LABEL,
            epoch_key_pairs_id(group_id, epoch, leaf_index)?,
        )? {
            return Ok(value);
        }
        self.read_json(
            EPOCH_KEY_PAIRS_LABEL,
            epoch_key_pairs_id_legacy(group_id, epoch, leaf_index)?,
        )
        .map(|value| value.unwrap_or_default())
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.read_entity(KEY_PACKAGE_LABEL, serde_json::to_vec(hash_ref)?)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_entity(PSK_LABEL, serde_json::to_vec(psk_id)?)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let group_key = Self::group_key(group_id)?;
        self.remove_entity(
            PROPOSAL_QUEUE_REFS_LABEL,
            group_key.clone(),
            Some(group_key),
            proposal_ref,
        )?;
        self.delete_value(
            QUEUED_PROPOSAL_LABEL,
            serde_json::to_vec(&(group_id, proposal_ref))?,
        )
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(OWN_LEAF_NODES_LABEL, group_id)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(JOIN_CONFIG_LABEL, group_id)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(TREE_LABEL, group_id)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(CONFIRMATION_TAG_LABEL, group_id)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(GROUP_STATE_LABEL, group_id)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(GROUP_CONTEXT_LABEL, group_id)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(INTERIM_TRANSCRIPT_HASH_LABEL, group_id)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(MESSAGE_SECRETS_LABEL, group_id)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(RESUMPTION_PSK_STORE_LABEL, group_id)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(OWN_LEAF_NODE_INDEX_LABEL, group_id)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(EPOCH_SECRETS_LABEL, group_id)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_labels(
            group_id,
            &[QUEUED_PROPOSAL_LABEL, PROPOSAL_QUEUE_REFS_LABEL],
        )
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(SIGNATURE_KEY_PAIR_LABEL, serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(ENCRYPTION_KEY_PAIR_LABEL, serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        // Delete both encodings so a delete cannot leave a stale legacy-key row
        // behind that a later read would resurrect (see #158 read fallback).
        self.delete_value(
            EPOCH_KEY_PAIRS_LABEL,
            epoch_key_pairs_id(group_id, epoch, leaf_index)?,
        )?;
        self.delete_value(
            EPOCH_KEY_PAIRS_LABEL,
            epoch_key_pairs_id_legacy(group_id, epoch, leaf_index)?,
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete_value(KEY_PACKAGE_LABEL, serde_json::to_vec(hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(PSK_LABEL, serde_json::to_vec(psk_id)?)
    }

    fn write_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        self.write_group_entity(
            APPLICATION_EXPORT_TREE_LABEL,
            group_id,
            application_export_tree,
        )
    }

    fn application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        self.read_group_entity(APPLICATION_EXPORT_TREE_LABEL, group_id)
    }

    fn delete_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_group_value(APPLICATION_EXPORT_TREE_LABEL, group_id)
    }
}

impl SqliteOpenMlsStorage {
    /// Clear the entire OpenMLS proposal queue for `group_id` after detecting
    /// recoverable corruption (a dangling ref or an undeserializable queued
    /// proposal blob). Deletes `QUEUED_PROPOSAL_LABEL` and
    /// `PROPOSAL_QUEUE_REFS_LABEL` atomically via `delete_group_labels` so the
    /// queue cannot be left half-cleared, logs a privacy-safe warning, and lets
    /// the caller return an empty queue. Dropping a pending local proposal is
    /// safe; a later commit simply starts from the current MLS group state and
    /// requires proposals to be re-enqueued. Permitting a partial/garbled queue
    /// to load is not safe, so this trades unrecoverable group load failure for
    /// a clean, re-enqueueable empty queue.
    fn recover_corrupt_proposal_queue<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        warning: &'static str,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        tracing::warn!(
            target: "marmot.storage_sqlite.openmls",
            method = "queued_proposals",
            "{warning}"
        );
        self.delete_group_labels(
            group_id,
            &[QUEUED_PROPOSAL_LABEL, PROPOSAL_QUEUE_REFS_LABEL],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use openmls_traits::storage::{Entity, Key};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestGroupId(Vec<u8>);

    impl Key<CURRENT_VERSION> for TestGroupId {}
    impl traits::GroupId<CURRENT_VERSION> for TestGroupId {}

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestProposalRef(Vec<u8>);

    impl Entity<CURRENT_VERSION> for TestProposalRef {}
    impl Key<CURRENT_VERSION> for TestProposalRef {}
    impl traits::ProposalRef<CURRENT_VERSION> for TestProposalRef {}

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestQueuedProposal(Vec<u8>);

    impl Entity<CURRENT_VERSION> for TestQueuedProposal {}
    impl traits::QueuedProposal<CURRENT_VERSION> for TestQueuedProposal {}

    // Serializes transparently to a bare JSON number, matching how the real
    // GroupEpoch encodes. This is the property that made undelimited
    // concatenation in epoch_key_pairs_id unsafe.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct TestEpochKey(u64);

    impl Key<CURRENT_VERSION> for TestEpochKey {}
    impl traits::EpochKey<CURRENT_VERSION> for TestEpochKey {}

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestHpkeKeyPair(Vec<u8>);

    impl Entity<CURRENT_VERSION> for TestHpkeKeyPair {}
    impl traits::HpkeKeyPair<CURRENT_VERSION> for TestHpkeKeyPair {}

    // Regression test for #158: distinct (epoch, leaf_index) pairs whose
    // decimal digits realign — (epoch=3, leaf=45) and (epoch=34, leaf=5) —
    // must map to distinct storage keys. Under the old undelimited
    // concatenation ("3"+"45" == "34"+"5") the second write silently
    // clobbered the first via INSERT OR REPLACE, losing HPKE key material.
    #[test]
    fn epoch_key_pairs_no_collision_across_realigning_epoch_leaf_digits() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let group_id = TestGroupId(vec![1, 2, 3, 4]);

        let pairs_a = vec![TestHpkeKeyPair(vec![0xAA])];
        let pairs_b = vec![TestHpkeKeyPair(vec![0xBB])];

        // (epoch=3, leaf_index=45)
        mls.write_encryption_epoch_key_pairs(&group_id, &TestEpochKey(3), 45, &pairs_a)
            .unwrap();
        // (epoch=34, leaf_index=5) — would collide under undelimited concat.
        mls.write_encryption_epoch_key_pairs(&group_id, &TestEpochKey(34), 5, &pairs_b)
            .unwrap();

        // Both rows must survive independently.
        let read_a: Vec<TestHpkeKeyPair> = mls
            .encryption_epoch_key_pairs(&group_id, &TestEpochKey(3), 45)
            .unwrap();
        let read_b: Vec<TestHpkeKeyPair> = mls
            .encryption_epoch_key_pairs(&group_id, &TestEpochKey(34), 5)
            .unwrap();
        assert_eq!(read_a, pairs_a, "(epoch=3, leaf=45) was overwritten");
        assert_eq!(read_b, pairs_b, "(epoch=34, leaf=5) was not stored");

        // Deleting one must not affect the other.
        mls.delete_encryption_epoch_key_pairs(&group_id, &TestEpochKey(3), 45)
            .unwrap();
        let after_delete_a: Vec<TestHpkeKeyPair> = mls
            .encryption_epoch_key_pairs(&group_id, &TestEpochKey(3), 45)
            .unwrap();
        let after_delete_b: Vec<TestHpkeKeyPair> = mls
            .encryption_epoch_key_pairs(&group_id, &TestEpochKey(34), 5)
            .unwrap();
        assert_eq!(after_delete_a, Vec::new(), "delete missed its own row");
        assert_eq!(
            after_delete_b, pairs_b,
            "delete of (3, 45) wrongly removed (34, 5)"
        );
    }

    // Upgrade-compatibility for #158: rows written before the key format was
    // disambiguated live under the legacy concatenated key. After upgrade,
    // encryption_epoch_key_pairs must still find them (read fallback) and
    // delete_encryption_epoch_key_pairs must remove them (dual delete), so a
    // group's current-epoch HPKE private key material is not stranded.
    #[test]
    fn epoch_key_pairs_reads_and_deletes_legacy_concatenated_key() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let group_id = TestGroupId(vec![5, 6, 7, 8]);
        let epoch = TestEpochKey(7);
        let leaf_index = 2u32;
        let legacy_pairs = vec![TestHpkeKeyPair(vec![0xCC])];

        // Seed a row under the pre-#158 legacy key, mimicking on-disk state from
        // a build that predates the tuple-key fix.
        let legacy_key = epoch_key_pairs_id_legacy(&group_id, &epoch, leaf_index).unwrap();
        mls.write_value(
            EPOCH_KEY_PAIRS_LABEL,
            legacy_key,
            Some(SqliteOpenMlsStorage::group_key(&group_id).unwrap()),
            serde_json::to_vec(&legacy_pairs).unwrap(),
        )
        .unwrap();

        // Read falls back to the legacy key when no tuple-key row exists.
        let read_legacy: Vec<TestHpkeKeyPair> = mls
            .encryption_epoch_key_pairs(&group_id, &epoch, leaf_index)
            .unwrap();
        assert_eq!(read_legacy, legacy_pairs, "legacy row was not read back");

        // A new tuple-key write takes precedence over the shadowed legacy row.
        let new_pairs = vec![TestHpkeKeyPair(vec![0xDD])];
        mls.write_encryption_epoch_key_pairs(&group_id, &epoch, leaf_index, &new_pairs)
            .unwrap();
        let read_after_write: Vec<TestHpkeKeyPair> = mls
            .encryption_epoch_key_pairs(&group_id, &epoch, leaf_index)
            .unwrap();
        assert_eq!(
            read_after_write, new_pairs,
            "tuple-key row must shadow the legacy row"
        );

        // Delete removes both encodings, so the shadowed legacy row cannot be
        // resurrected after the tuple-key row is gone.
        mls.delete_encryption_epoch_key_pairs(&group_id, &epoch, leaf_index)
            .unwrap();
        let read_after_delete: Vec<TestHpkeKeyPair> = mls
            .encryption_epoch_key_pairs(&group_id, &epoch, leaf_index)
            .unwrap();
        assert_eq!(
            read_after_delete,
            Vec::new(),
            "legacy row resurfaced after delete"
        );
    }

    #[test]
    fn queued_proposals_recovers_from_dangling_refs_by_clearing_queue() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let group_id = TestGroupId(vec![1, 2, 3, 4]);
        let valid_ref = TestProposalRef(vec![0xAA]);
        let dangling_ref = TestProposalRef(vec![0xBB]);
        let valid_proposal = TestQueuedProposal(vec![0xCC]);

        mls.queue_proposal(&group_id, &valid_ref, &valid_proposal)
            .unwrap();
        let group_key = SqliteOpenMlsStorage::group_key(&group_id).unwrap();
        mls.append_entity(
            PROPOSAL_QUEUE_REFS_LABEL,
            group_key.clone(),
            Some(group_key),
            &dangling_ref,
        )
        .unwrap();

        let proposals: Vec<(TestProposalRef, TestQueuedProposal)> =
            mls.queued_proposals(&group_id).unwrap();
        assert_eq!(proposals, Vec::new());

        let refs: Vec<TestProposalRef> = mls.queued_proposal_refs(&group_id).unwrap();
        assert_eq!(refs, Vec::new());
    }

    #[test]
    fn queued_proposals_recovers_from_undeserializable_blob_by_clearing_queue() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let group_id = TestGroupId(vec![9, 8, 7, 6]);
        let corrupt_ref = TestProposalRef(vec![0xDD]);
        let proposal = TestQueuedProposal(vec![0xEE]);

        // Enqueue a normal proposal so both the ref list and the entity row exist.
        mls.queue_proposal(&group_id, &corrupt_ref, &proposal)
            .unwrap();

        // Corrupt the QueuedProposal entity in place: overwrite its JSON blob with
        // bytes that cannot deserialize into a TestQueuedProposal. The ref stays
        // intact, so this is the "row present but undeserializable" case (#350),
        // distinct from the dangling-ref ("row missing") case (#315).
        let group_key = SqliteOpenMlsStorage::group_key(&group_id).unwrap();
        let proposal_key = serde_json::to_vec(&(&group_id, &corrupt_ref)).unwrap();
        mls.write_value(
            QUEUED_PROPOSAL_LABEL,
            proposal_key,
            Some(group_key),
            b"not valid json for this entity".to_vec(),
        )
        .unwrap();

        // queued_proposals() must self-heal (clear the queue) instead of
        // propagating the deserialize error, which would otherwise brick group load.
        let proposals: Vec<(TestProposalRef, TestQueuedProposal)> =
            mls.queued_proposals(&group_id).unwrap();
        assert_eq!(proposals, Vec::new());

        // Both labels are cleared, so a subsequent load starts from a clean queue.
        let refs: Vec<TestProposalRef> = mls.queued_proposal_refs(&group_id).unwrap();
        assert_eq!(refs, Vec::new());
    }

    #[test]
    fn queued_proposals_recovers_from_corrupt_ref_list_blob_by_clearing_queue() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let group_id = TestGroupId(vec![9, 8, 7, 6]);
        let valid_ref = TestProposalRef(vec![0x11]);
        let valid_proposal = TestQueuedProposal(vec![0x22]);

        // Persist a real queued proposal so both the ref-list row and the
        // QueuedProposal entity row exist for this group.
        mls.queue_proposal(&group_id, &valid_ref, &valid_proposal)
            .unwrap();

        // Overwrite the ProposalQueueRefs row with bytes that are not valid JSON
        // for the persisted list shape (Vec<Vec<u8>>), simulating a truncated or
        // storage-format-skewed blob.
        let group_key = SqliteOpenMlsStorage::group_key(&group_id).unwrap();
        mls.write_value(
            PROPOSAL_QUEUE_REFS_LABEL,
            group_key.clone(),
            Some(group_key),
            b"not-json".to_vec(),
        )
        .unwrap();

        // The corrupt ref-list blob would otherwise surface as a serde error;
        // queued_proposals must recover by clearing the queue instead.
        let proposals: Vec<(TestProposalRef, TestQueuedProposal)> =
            mls.queued_proposals(&group_id).unwrap();
        assert_eq!(proposals, Vec::new());

        // Both the ref list and the queued-proposal entity must be gone.
        let refs: Vec<TestProposalRef> = mls.queued_proposal_refs(&group_id).unwrap();
        assert_eq!(refs, Vec::new());

        let proposal_key = serde_json::to_vec(&(&group_id, &valid_ref)).unwrap();
        let entity: Option<TestQueuedProposal> = mls
            .read_entity(QUEUED_PROPOSAL_LABEL, proposal_key)
            .unwrap();
        assert_eq!(entity, None);
    }
}
