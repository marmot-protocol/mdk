//! Deterministic fork recovery for same-epoch competing commits.
//!
//! The engine snapshots the local group before it applies any commit that
//! advances epoch `N -> N + 1`. If a second commit later arrives for epoch
//! `N`, this manager compares transport ordering keys. A better candidate
//! rolls storage back to the pre-commit snapshot so the caller can process
//! the candidate against the correct MLS epoch.

use crate::engine::Engine;
use cgka_traits::engine::CommitOrderingKey;
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::message::MessageState;
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId};
use std::collections::HashMap;

#[derive(Clone, Debug)]
struct CommitRecoveryRecord {
    group_id: GroupId,
    source_epoch: EpochId,
    ordering_key: CommitOrderingKey,
    snapshot_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForkResolution {
    CandidateWins {
        winner: CommitOrderingKey,
        invalidated: CommitOrderingKey,
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
        format!(
            "fork-{}-{}-{}",
            hex::encode(group_id.as_slice()),
            source_epoch.0,
            self.snapshot_counter
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
        _result_epoch: EpochId,
        msg: &TransportMessage,
        snapshot_name: String,
    ) {
        self.pending.insert(
            pending,
            CommitRecoveryRecord {
                group_id,
                source_epoch,
                ordering_key: CommitOrderingKey::from_transport_message(msg),
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
        candidate: &TransportMessage,
    ) -> Result<ForkResolution, EngineError> {
        let key = (group_id.clone(), source_epoch);
        let Some(incumbent) = self.incumbents.get(&key).cloned() else {
            return Ok(ForkResolution::MissingSnapshot);
        };

        let candidate_key = CommitOrderingKey::from_transport_message(candidate);
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
        })
    }
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn track_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
        group_id: GroupId,
        source_epoch: EpochId,
        _result_epoch: EpochId,
        msg: &TransportMessage,
        snapshot_name: String,
    ) {
        self.fork_recovery.record_pending(
            pending,
            group_id,
            source_epoch,
            _result_epoch,
            msg,
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
        _result_epoch: EpochId,
        msg: &TransportMessage,
        snapshot_name: String,
    ) {
        self.fork_recovery.record_applied(CommitRecoveryRecord {
            group_id,
            source_epoch,
            ordering_key: CommitOrderingKey::from_transport_message(msg),
            snapshot_name,
        });
    }

    pub(crate) fn resolve_fork_candidate(
        &mut self,
        group_id: &GroupId,
        source_epoch: EpochId,
        msg: &TransportMessage,
    ) -> Result<ForkResolution, EngineError> {
        let resolution = self
            .fork_recovery
            .resolve(&self.storage, group_id, source_epoch, msg)?;
        if let ForkResolution::CandidateWins { invalidated, .. } = &resolution {
            self.epoch_manager
                .set_stable(group_id.clone(), source_epoch);
            match self
                .storage
                .update_message_state(&invalidated.message_id, MessageState::EpochInvalidated)
            {
                Ok(()) | Err(StorageError::NotFound) => {}
                Err(e) => return Err(EngineError::Storage(e)),
            }
        }
        Ok(resolution)
    }
}
