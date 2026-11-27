//! RAII cleanup for locally staged OpenMLS pending commits.
//!
//! Commit-producing send paths stage an OpenMLS pending commit before they
//! cross transport wrapping and storage boundaries. Until the engine creates a
//! `PendingStateRef`, callers have no handle they can later pass to
//! `publish_failed`. This guard closes that orphan window: if the future is
//! dropped or returns early after staging but before the pending lifecycle is
//! handed off, `Drop` clears the OpenMLS pending commit best-effort.

use cgka_traits::error::EngineError;
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::types::{GroupId, MessageId};
use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::group::{MlsGroup, RemoveProposalError};
use std::sync::Arc;

const TRACE_TARGET: &str = "cgka_engine::pending_commit_guard";

/// Clears an OpenMLS pending commit on early return / cancellation unless the
/// caller disarms it after creating the engine-level pending state.
pub(crate) struct PendingCommitCleanupGuard<S: StorageProvider> {
    storage: Arc<S>,
    group_id: GroupId,
    // Proposals this staging attempt stored via `store_pending_proposal`, to
    // remove from the OpenMLS proposal store on Drop. Empty for send paths,
    // which commit proposals they did not store themselves.
    stored_proposal_refs: Vec<ProposalRef>,
    recovery_evolution: Option<MessageId>,
    armed: bool,
}

impl<S: StorageProvider> PendingCommitCleanupGuard<S> {
    pub(crate) fn arm(storage: Arc<S>, group_id: GroupId) -> Self {
        Self {
            storage,
            group_id,
            stored_proposal_refs: Vec::new(),
            recovery_evolution: None,
            armed: true,
        }
    }

    /// Attach the reference of a proposal the guarded path stored via
    /// `store_pending_proposal`, so `Drop` restores the proposal store to its
    /// pre-attempt state. A stale stored proposal is not benign residue:
    /// OpenMLS 0.8.1 panics when a later `remove_members` commit filters a
    /// leftover SelfRemove proposal against a Remove for the same leaf.
    pub(crate) fn set_stored_proposal_ref(&mut self, proposal_ref: ProposalRef) {
        self.stored_proposal_refs.push(proposal_ref);
    }

    /// Own the pre-staging descriptor until the exact Prepared publication is
    /// handed off. Cancellation must rewind the projection and Welcomes too.
    pub(crate) fn set_recovery_evolution(&mut self, id: MessageId) {
        self.recovery_evolution = Some(id);
    }

    /// Synchronous compensation when persisting Prepared fails. Keep the guard
    /// armed on failure so Drop can retry, and hydration retains Preparing.
    pub(crate) fn rollback_recovery(&mut self) -> Result<(), EngineError> {
        if let Some(id) = &self.recovery_evolution {
            crate::maintenance::rollback_recovery_stage(self.storage.as_ref(), &self.group_id, id)?;
            self.armed = false;
        }
        Ok(())
    }

    /// The staged commit is now tracked by `EpochManager` and can be cleaned
    /// up by the normal `publish_failed` path. Leave it attached to
    /// OpenMLS / storage.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl<S: StorageProvider> Drop for PendingCommitCleanupGuard<S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        if self.recovery_evolution.is_some() {
            if self.rollback_recovery().is_err() {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending recovery guard could not compensate unpublished evolution"
                );
            }
            return;
        }

        // Clear the staged OpenMLS pending commit and any proposals stored by
        // this attempt inside one storage transaction so a fault cannot tear
        // `ProposalQueueRefs` from `QueuedProposal` or leave a stored proposal
        // behind after clearing the pending commit. Best-effort: log on error
        // and never panic in Drop.
        let mls_gid = openmls::group::GroupId::from_slice(self.group_id.as_slice());
        let cleanup_result: Result<(), StorageError> = self.storage.with_transaction(|storage| {
            let mls_storage = storage.mls_storage();
            // Clears the commit this guard's own send staged on a live group;
            // the guard holds no engine to ask (see clippy.toml).
            #[allow(clippy::disallowed_methods)]
            let loaded = MlsGroup::load(mls_storage, &mls_gid)
                .map_err(|e| StorageError::Backend(format!("load group for cleanup: {e:?}")))?;
            let Some(mut mls_group) = loaded else {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending commit guard found no group for cleanup"
                );
                return Ok(());
            };
            if mls_group.pending_commit().is_some() {
                mls_group
                    .clear_pending_commit(mls_storage)
                    .map_err(|e| StorageError::Backend(format!("clear_pending: {e:?}")))?;
            }
            // Restore the proposal store to its pre-attempt state when this
            // path stored the proposal itself. A proposal that is already gone
            // is benign (`clear_pending_commit` does not remove stored
            // proposals, but a concurrent merge would have consumed it).
            for proposal_ref in &self.stored_proposal_refs {
                match mls_group.remove_pending_proposal(mls_storage, proposal_ref) {
                    Ok(()) | Err(RemoveProposalError::ProposalNotFound) => {}
                    Err(e) => {
                        return Err(StorageError::Backend(format!(
                            "remove_pending_proposal: {e:?}"
                        )));
                    }
                }
            }
            Ok(())
        });
        if cleanup_result.is_err() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drop",
                "pending commit guard could not clean up staged commit or stored proposals"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::provider::EngineOpenMlsProvider;
    use crate::wire_format::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
    use openmls::group::{MlsGroupCreateConfig, MlsGroupJoinConfig};
    use openmls::prelude::{BasicCredential, CredentialWithKey, KeyPackage};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::OpenMlsProvider as _;
    use openmls_traits::types::Ciphersuite;
    use rusqlite::{Connection, types::Value};
    use storage_sqlite::{
        SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, open_hardened_sqlcipher,
    };

    const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    fn openmls_rows_for_label(conn: &Connection, label: &[u8]) -> Vec<Vec<Value>> {
        let mut stmt = conn
            .prepare(
                "SELECT storage_key, value FROM openmls_values WHERE label = ?1 ORDER BY storage_key",
            )
            .unwrap();
        stmt.query_map([label], |row| Ok(vec![row.get(0)?, row.get(1)?]))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    #[test]
    fn drop_removes_stored_proposal_atomically_inside_a_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-guard-proposal.sqlite");
        let key = SqlCipherKey::raw([0x42; 32]);
        let alice_storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let bob_storage = SqliteAccountStorage::in_memory_for_test().unwrap();

        let alice_crypto = RustCrypto::default();
        let bob_crypto = RustCrypto::default();
        let alice_provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
            &alice_crypto,
            alice_storage.mls_storage(),
        );
        let bob_provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
            &bob_crypto,
            bob_storage.mls_storage(),
        );

        let alice_signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        let alice_cred = CredentialWithKey {
            credential: BasicCredential::new(vec![0x11; 32]).into(),
            signature_key: alice_signer.public().into(),
        };
        let bob_signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        let bob_cred = CredentialWithKey {
            credential: BasicCredential::new(vec![0x22; 32]).into(),
            signature_key: bob_signer.public().into(),
        };

        let caps = openmls::prelude::Capabilities::new(
            None,
            Some(&[SUITE]),
            None,
            Some(&[openmls::prelude::ProposalType::SelfRemove]),
            Some(&[openmls::prelude::CredentialType::Basic]),
        );
        let bob_kp = KeyPackage::builder()
            .leaf_node_capabilities(caps.clone())
            .build(SUITE, &bob_provider, &bob_signer, bob_cred.clone())
            .unwrap();

        let create_cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .capabilities(caps)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        let mut alice_group =
            MlsGroup::new(&alice_provider, &alice_signer, &create_cfg, alice_cred).unwrap();
        let (_commit, welcome, _gi) = alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                &[bob_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();

        let join_cfg = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let openmls::prelude::MlsMessageBodyOut::Welcome(welcome_body) = welcome.body() else {
            panic!("expected Welcome");
        };
        let staged_welcome = openmls::group::StagedWelcome::new_from_welcome(
            &bob_provider,
            &join_cfg,
            welcome_body.clone(),
            None,
        )
        .unwrap();
        let mut bob_group = staged_welcome.into_group(&bob_provider).unwrap();

        let proposal_msg = bob_group
            .leave_group_via_self_remove(&bob_provider, &bob_signer)
            .unwrap();
        let protocol_msg = openmls::prelude::MlsMessageIn::from(proposal_msg)
            .try_into_protocol_message()
            .unwrap();
        let processed = alice_group
            .process_message(&alice_provider, protocol_msg)
            .unwrap();
        let openmls::prelude::ProcessedMessageContent::ProposalMessage(queued) =
            processed.into_content()
        else {
            panic!("expected ProposalMessage");
        };
        let proposal_ref = queued.proposal_reference_ref().clone();

        alice_group
            .store_pending_proposal(alice_provider.storage(), *queued)
            .unwrap();
        let _commit_out = alice_group
            .commit_builder()
            .consume_proposal_store(true)
            .load_psks(alice_provider.storage())
            .unwrap()
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&alice_provider)
            .unwrap();
        assert!(alice_group.pending_commit().is_some());
        assert!(alice_group.has_pending_proposals());

        let observer = Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
        let refs_before = openmls_rows_for_label(&observer, b"ProposalQueueRefs");
        let queued_before = openmls_rows_for_label(&observer, b"QueuedProposal");
        assert!(!refs_before.is_empty());
        assert!(!queued_before.is_empty());

        // Inject a failure on the second write inside `remove_proposal`:
        // `remove_entity(ProposalQueueRefs)` runs first, then
        // `delete_value(QueuedProposal)` runs second. Without an enclosing
        // transaction, `ProposalQueueRefs` commits while `QueuedProposal` stays
        // orphaned (torn write), and `clear_pending_commit` already committed.
        observer
            .execute_batch(
                "CREATE TRIGGER fail_queued_proposal_delete \
                 BEFORE DELETE ON openmls_values \
                 WHEN OLD.label = CAST('QueuedProposal' AS BLOB) \
                 BEGIN SELECT RAISE(ABORT, 'injected-proposal-delete-fault'); END;",
            )
            .unwrap();

        let alice_storage_arc = Arc::new(alice_storage.clone());
        let group_id = GroupId::new(alice_group.group_id().as_slice().to_vec());
        {
            let mut guard =
                PendingCommitCleanupGuard::arm(Arc::clone(&alice_storage_arc), group_id.clone());
            guard.set_stored_proposal_ref(proposal_ref.clone());
        }

        assert_eq!(
            openmls_rows_for_label(&observer, b"ProposalQueueRefs"),
            refs_before,
            "failed proposal delete must roll back ProposalQueueRefs atomically (no torn write)"
        );
        assert_eq!(
            openmls_rows_for_label(&observer, b"QueuedProposal"),
            queued_before,
            "failed proposal delete must leave QueuedProposal consistent with ProposalQueueRefs"
        );
        let reloaded_after_fault =
            MlsGroup::load(alice_storage.mls_storage(), alice_group.group_id())
                .unwrap()
                .unwrap();
        assert!(
            reloaded_after_fault.pending_commit().is_some(),
            "clear_pending_commit and remove_pending_proposal must roll back together on fault"
        );
        assert!(reloaded_after_fault.has_pending_proposals());

        // Once the fault clears, a drop cleans up both pending commit and stored proposal.
        observer
            .execute_batch("DROP TRIGGER fail_queued_proposal_delete")
            .unwrap();
        {
            let mut guard =
                PendingCommitCleanupGuard::arm(Arc::clone(&alice_storage_arc), group_id);
            guard.set_stored_proposal_ref(proposal_ref);
        }

        let reloaded_after_heal =
            MlsGroup::load(alice_storage.mls_storage(), alice_group.group_id())
                .unwrap()
                .unwrap();
        assert!(reloaded_after_heal.pending_commit().is_none());
        assert!(!reloaded_after_heal.has_pending_proposals());
        assert!(openmls_rows_for_label(&observer, b"QueuedProposal").is_empty());

        drop(observer);
        alice_storage.close().unwrap();
    }
}
