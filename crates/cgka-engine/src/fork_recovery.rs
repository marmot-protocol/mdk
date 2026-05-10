//! Deterministic fork recovery for same-epoch competing commits.
//!
//! The engine snapshots the local group before it applies any commit that
//! advances epoch `N -> N + 1`. If a second commit later arrives for epoch
//! `N`, this manager compares content-derived ordering keys
//! (`SHA-256(mls_bytes)`). A better candidate rolls storage back to the
//! pre-commit snapshot so the caller can process the candidate against the
//! correct MLS epoch.
//!
//! ## Storage row identity
//!
//! Tie-break is content-derived; the storage row identity for marking an
//! invalidated commit is the transport-layer `MessageId`. The two are kept
//! separate inside `CommitRecoveryRecord` so the ordering key remains
//! transport-independent while the engine can still reach back to the
//! storage record that needs `MessageState::EpochInvalidated`.

use crate::engine::Engine;
use cgka_traits::engine::CommitOrderingKey;
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::message::MessageState;
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::types::{EpochId, GroupId, MessageId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Clone, Debug)]
struct CommitRecoveryRecord {
    group_id: GroupId,
    source_epoch: EpochId,
    ordering_key: CommitOrderingKey,
    /// Storage-layer identity of the commit. Used to update
    /// `MessageState::EpochInvalidated` when this commit loses a fork.
    storage_id: MessageId,
    snapshot_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForkResolution {
    CandidateWins {
        winner: CommitOrderingKey,
        invalidated: CommitOrderingKey,
        /// `MessageId` of the now-invalidated incumbent, for the storage
        /// `update_message_state` call site.
        invalidated_storage_id: MessageId,
    },
    IncumbentWins,
    MissingSnapshot,
}

#[derive(Default)]
pub(crate) struct ForkRecoveryManager {
    snapshot_counter: u64,
    pending: HashMap<PendingStateRef, CommitRecoveryRecord>,
    incumbents: HashMap<(GroupId, EpochId), CommitRecoveryRecord>,
}

impl ForkRecoveryManager {
    fn next_snapshot_name(&mut self, group_id: &GroupId, source_epoch: EpochId) -> String {
        self.snapshot_counter += 1;
        // Hash the group_id rather than embedding it as hex: snapshot
        // names appear in storage error messages and could leak through
        // tracing if storage tracing ever expands. Per the privacy rule
        // in `docs/marmot-architecture/overview/observability.md`,
        // group_ids must not appear in operational identifiers.
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-fork-recovery/v1");
        hasher.update(group_id.as_slice());
        hasher.update(source_epoch.0.to_be_bytes());
        hasher.update(self.snapshot_counter.to_be_bytes());
        let digest = hasher.finalize();
        format!(
            "fork-{}-{}-{}",
            source_epoch.0,
            self.snapshot_counter,
            hex::encode(&digest[..8])
        )
    }

    pub(crate) fn create_snapshot<S: StorageProvider>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> Result<String, EngineError> {
        let name = self.next_snapshot_name(group_id, source_epoch);
        storage.create_group_snapshot(group_id, &name)?;
        Ok(name)
    }

    fn record_pending(
        &mut self,
        pending: PendingStateRef,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        mls_bytes: &[u8],
        snapshot_name: String,
    ) {
        self.pending.insert(
            pending,
            CommitRecoveryRecord {
                group_id,
                source_epoch,
                ordering_key: CommitOrderingKey::from_commit_bytes(source_epoch, mls_bytes),
                storage_id,
                snapshot_name,
            },
        );
    }

    fn promote_pending(&mut self, pending: PendingStateRef) {
        if let Some(record) = self.pending.remove(&pending) {
            self.incumbents
                .insert((record.group_id.clone(), record.source_epoch), record);
        }
    }

    fn forget_pending(&mut self, pending: PendingStateRef) -> Option<CommitRecoveryRecord> {
        self.pending.remove(&pending)
    }

    fn record_applied(&mut self, record: CommitRecoveryRecord) {
        self.incumbents
            .insert((record.group_id.clone(), record.source_epoch), record);
    }

    fn resolve<S: StorageProvider>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        source_epoch: EpochId,
        candidate_mls_bytes: &[u8],
    ) -> Result<ForkResolution, EngineError> {
        let key = (group_id.clone(), source_epoch);
        let Some(incumbent) = self.incumbents.get(&key).cloned() else {
            return Ok(ForkResolution::MissingSnapshot);
        };

        let candidate_key = CommitOrderingKey::from_commit_bytes(source_epoch, candidate_mls_bytes);
        if candidate_key >= incumbent.ordering_key {
            return Ok(ForkResolution::IncumbentWins);
        }

        storage.rollback_group_to_snapshot(group_id, &incumbent.snapshot_name)?;
        match storage.release_group_snapshot(group_id, &incumbent.snapshot_name) {
            Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
            Err(e) => return Err(EngineError::Storage(e)),
        }
        self.incumbents.remove(&key);

        Ok(ForkResolution::CandidateWins {
            winner: candidate_key,
            invalidated: incumbent.ordering_key,
            invalidated_storage_id: incumbent.storage_id,
        })
    }

    fn retained_snapshots(&self, group_id: &GroupId) -> Vec<(EpochId, String)> {
        self.incumbents
            .values()
            .filter(|record| &record.group_id == group_id)
            .map(|record| (record.source_epoch, record.snapshot_name.clone()))
            .collect()
    }
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn track_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        mls_bytes: &[u8],
        snapshot_name: String,
    ) {
        self.fork_recovery.record_pending(
            pending,
            group_id,
            source_epoch,
            storage_id,
            mls_bytes,
            snapshot_name,
        );
    }

    pub(crate) fn promote_pending_commit_for_recovery(&mut self, pending: PendingStateRef) {
        self.fork_recovery.promote_pending(pending);
    }

    pub(crate) fn forget_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<(), EngineError> {
        if let Some(record) = self.fork_recovery.forget_pending(pending) {
            match self
                .storage
                .release_group_snapshot(&record.group_id, &record.snapshot_name)
            {
                Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
                Err(e) => return Err(EngineError::Storage(e)),
            }
        }
        Ok(())
    }

    pub(crate) fn record_applied_commit_for_recovery(
        &mut self,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        mls_bytes: &[u8],
        snapshot_name: String,
    ) {
        self.fork_recovery.record_applied(CommitRecoveryRecord {
            group_id,
            source_epoch,
            ordering_key: CommitOrderingKey::from_commit_bytes(source_epoch, mls_bytes),
            storage_id,
            snapshot_name,
        });
    }

    pub(crate) fn resolve_fork_candidate(
        &mut self,
        group_id: &GroupId,
        source_epoch: EpochId,
        candidate_mls_bytes: &[u8],
    ) -> Result<ForkResolution, EngineError> {
        let resolution = self.fork_recovery.resolve(
            &self.storage,
            group_id,
            source_epoch,
            candidate_mls_bytes,
        )?;
        if let ForkResolution::CandidateWins {
            invalidated_storage_id,
            ..
        } = &resolution
        {
            self.epoch_manager
                .set_stable(group_id.clone(), source_epoch);
            match self
                .storage
                .update_message_state(invalidated_storage_id, MessageState::EpochInvalidated)
            {
                Ok(()) | Err(StorageError::NotFound) => {}
                Err(e) => return Err(EngineError::Storage(e)),
            }
        }
        Ok(resolution)
    }

    pub(crate) fn retained_fork_snapshots(&self, group_id: &GroupId) -> Vec<(EpochId, String)> {
        self.fork_recovery.retained_snapshots(group_id)
    }
}
