//! Pure own-leaf rotation for `SendIntent::SelfUpdate`.
//!
//! The commit builder is configured with `force_self_update(true)` and
//! `consume_proposal_store(false)`: maintenance rotates only this device's
//! LeafNode and cannot accidentally absorb unrelated proposals.

use crate::engine::Engine;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::SendResult;
use cgka_traits::engine_state::{EpochState, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::maintenance::{
    DurableGroupEvolution, GroupEvolutionPhase, GroupEvolutionSemantic, MaintenanceTrigger,
};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::EncryptedPayload;
use cgka_traits::types::{EpochId, GroupId, MessageId};
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use tls_codec::Serialize as _;

struct PreparingEvolutionGuard<S: StorageProvider> {
    storage: *const S,
    id: MessageId,
    armed: bool,
}

// SAFETY: the pointer is only dereferenced from Drop while the guarded
// `&mut Engine` future, and therefore its storage, is still alive.
unsafe impl<S: StorageProvider> Send for PreparingEvolutionGuard<S> {}

impl<S: StorageProvider> PreparingEvolutionGuard<S> {
    fn arm(storage: &S, id: MessageId) -> Self {
        Self {
            storage,
            id,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl<S: StorageProvider> Drop for PreparingEvolutionGuard<S> {
    fn drop(&mut self) {
        if self.armed {
            // SAFETY: see the Send justification above.
            let storage = unsafe { &*self.storage };
            if let Some(maintenance) = storage.maintenance_storage() {
                let _ = maintenance.delete_group_evolution(&self.id);
            }
        }
    }
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_send_self_update(
        &mut self,
        group_id: GroupId,
    ) -> Result<SendResult, EngineError> {
        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "SelfUpdate",
                    reason: "self update requires Stable",
                },
            ));
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let source_epoch = EpochId(mls_group.epoch().as_u64());
        let own_leaf_before = mls_group
            .own_leaf_node()
            .ok_or_else(|| EngineError::Backend("group has no local leaf".into()))?
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let own_leaf_before_hash = Sha256::digest(&own_leaf_before).to_vec();

        // The semantic id is deterministic for this group/epoch/leaf, making a
        // crash before staging idempotent while still changing after a
        // canonical own-leaf rotation.
        let mut semantic_hasher = Sha256::new();
        semantic_hasher.update(b"marmot-self-update-evolution-v1");
        semantic_hasher.update((group_id.as_slice().len() as u64).to_be_bytes());
        semantic_hasher.update(group_id.as_slice());
        semantic_hasher.update(source_epoch.0.to_be_bytes());
        semantic_hasher.update(&own_leaf_before_hash);
        let evolution_id = MessageId::new(semantic_hasher.finalize().to_vec());
        let maintenance_storage = self.maintenance_storage()?;
        let active_obligation = maintenance_storage
            .list_maintenance_obligations_for_group(&group_id)?
            .into_iter()
            .filter(|obligation| {
                !matches!(
                    obligation.phase,
                    cgka_traits::maintenance::MaintenancePhase::Complete
                        | cgka_traits::maintenance::MaintenancePhase::Failed
                )
            })
            .min_by_key(|obligation| match obligation.trigger {
                MaintenanceTrigger::PostJoin => 0,
                MaintenanceTrigger::Manual => 1,
                MaintenanceTrigger::Periodic => 2,
            });
        let semantic = active_obligation
            .map(|obligation| GroupEvolutionSemantic::SelfUpdate {
                trigger: obligation.trigger,
                obligation_id: Some(obligation.id),
            })
            .unwrap_or_else(|| GroupEvolutionSemantic::SelfUpdate {
                trigger: MaintenanceTrigger::Manual,
                obligation_id: None,
            });
        let mut evolution = DurableGroupEvolution {
            id: evolution_id.clone(),
            group_id: group_id.clone(),
            source_epoch,
            target_epoch: EpochId(source_epoch.0.saturating_add(1)),
            phase: GroupEvolutionPhase::Preparing,
            semantic,
            own_leaf_before_hash: Some(own_leaf_before_hash),
            removal_members: Vec::new(),
            signed_message_id: None,
            pending_ref: None,
        };
        // Semantic intent precedes every MLS mutation.
        maintenance_storage.put_group_evolution(&evolution)?;
        let preparation_guard = PreparingEvolutionGuard::arm(&self.storage, evolution_id.clone());

        let pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        let commit_bundle = mls_group
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true)
            .load_psks(provider.storage())
            .map_err(|e| EngineError::Backend(format!("self_update load_psks: {e:?}")))?
            .build(
                provider.rand(),
                provider.crypto(),
                &self.identity.signer,
                |_| true,
            )
            .map_err(|e| EngineError::Backend(format!("self_update build: {e:?}")))?
            .stage_commit(&provider)
            .map_err(|e| EngineError::Backend(format!("self_update stage: {e:?}")))?;
        let commit_out = commit_bundle.into_commit();
        let staged_commit = mls_group
            .pending_commit()
            .ok_or_else(|| EngineError::Backend("self update produced no pending commit".into()))?;
        crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
            staged_commit,
            &mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            &mls_group,
            staged_commit,
            mls_group.own_leaf_index(),
        )?;
        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let wrapped = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes.clone(),
                    aad: Vec::new(),
                },
                &pre_commit_ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let wrapped =
            crate::message_processor::route_wrapped_group_message(wrapped, &pre_commit_ctx);

        // Exact signed transport bytes are durable before this result can
        // escape to a network caller.
        self.record_sent_openmls_message(&wrapped, &commit_bytes, &group_id, source_epoch)?;
        evolution.phase = GroupEvolutionPhase::Prepared;
        evolution.signed_message_id = Some(wrapped.id.clone());

        let pending_ref = self.epoch_manager.next_pending_ref();
        evolution.pending_ref = Some(pending_ref);
        self.maintenance_storage()?
            .put_group_evolution(&evolution)?;
        self.epoch_manager.begin_pending(
            group_id.clone(),
            source_epoch,
            evolution.target_epoch,
            StagedCommitHandle::from_bytes(group_id.as_slice().to_vec()),
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
        self.track_pending_origin_commit(pending_ref, wrapped.id.clone());
        pending_commit_guard.disarm();
        preparation_guard.disarm();

        Ok(SendResult::GroupEvolution {
            msg: wrapped,
            welcomes: Vec::new(),
            pending: pending_ref,
        })
    }
}
