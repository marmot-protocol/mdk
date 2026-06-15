//! Deterministic fork recovery for same-epoch competing commits.
//!
//! The engine snapshots the local group before it applies any commit that
//! advances epoch `N -> N + 1`. If a second commit later arrives for epoch
//! `N`, this manager compares ordering keys built from authenticated commit
//! metadata plus a same-committer digest fallback. A better candidate rolls
//! storage back to the pre-commit snapshot so the caller can process the
//! candidate against the correct MLS epoch.
//!
//! ## Storage row identity
//!
//! The ordering key is derived from MLS-authenticated commit metadata plus the
//! serialized MLS bytes; the storage row identity for marking an invalidated
//! commit is the transport-layer `MessageId`. The two are kept separate inside
//! `CommitRecoveryRecord` so the ordering key remains transport-independent
//! while the engine can still reach back to the storage record that needs
//! `MessageState::EpochInvalidated`.

use crate::engine::Engine;
use cgka_traits::engine::{CommitOrderingKey, CommitOrderingPriority};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::message::MessageState;
use cgka_traits::storage::{MessageStorage, StorageError, StorageProvider};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use marmot_forensics::{AuditEventKind, ForkWinner};
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

    pub(crate) fn create_snapshot<S: MessageStorage>(
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
        ordering_key: CommitOrderingKey,
        snapshot_name: String,
    ) {
        self.pending.insert(
            pending,
            CommitRecoveryRecord {
                group_id,
                source_epoch,
                ordering_key,
                storage_id,
                snapshot_name,
            },
        );
    }

    fn promote_pending(&mut self, pending: PendingStateRef) -> Option<MessageId> {
        if let Some(record) = self.pending.remove(&pending) {
            let storage_id = record.storage_id.clone();
            self.incumbents
                .insert((record.group_id.clone(), record.source_epoch), record);
            Some(storage_id)
        } else {
            None
        }
    }

    fn forget_pending(&mut self, pending: PendingStateRef) -> Option<CommitRecoveryRecord> {
        self.pending.remove(&pending)
    }

    fn record_applied(&mut self, record: CommitRecoveryRecord) {
        self.incumbents
            .insert((record.group_id.clone(), record.source_epoch), record);
    }

    fn resolve<S: MessageStorage>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        source_epoch: EpochId,
        candidate_priority: CommitOrderingPriority,
        candidate_committer: MemberId,
        candidate_mls_bytes: &[u8],
    ) -> Result<ForkResolution, EngineError> {
        let key = (group_id.clone(), source_epoch);
        let Some(incumbent) = self.incumbents.get(&key).cloned() else {
            return Ok(ForkResolution::MissingSnapshot);
        };

        let candidate_key = CommitOrderingKey::from_commit_bytes(
            source_epoch,
            candidate_priority,
            candidate_committer,
            candidate_mls_bytes,
        );
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

    fn recovery_snapshot_name(&self, group_id: &GroupId, source_epoch: EpochId) -> Option<String> {
        self.incumbents
            .get(&(group_id.clone(), source_epoch))
            .map(|record| record.snapshot_name.clone())
    }

    fn retained_snapshots(&self, group_id: &GroupId) -> Vec<(EpochId, String)> {
        self.incumbents
            .values()
            .filter(|record| &record.group_id == group_id)
            .map(|record| (record.source_epoch, record.snapshot_name.clone()))
            .collect()
    }

    fn prune_before<S: MessageStorage>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        oldest_retained_epoch: EpochId,
    ) {
        let stale: Vec<_> = self
            .incumbents
            .iter()
            .filter(|((record_group_id, source_epoch), _)| {
                record_group_id == group_id && source_epoch.0 < oldest_retained_epoch.0
            })
            .map(|(key, record)| (key.clone(), record.snapshot_name.clone()))
            .collect();

        for (key, snapshot_name) in stale {
            match storage.release_group_snapshot(group_id, &snapshot_name) {
                Ok(()) | Err(StorageError::SnapshotMissing(_)) => {
                    self.incumbents.remove(&key);
                }
                Err(_e) => {
                    tracing::warn!(
                        target: "cgka_engine::fork_recovery",
                        method = "prune_before",
                        source_epoch = key.1.0,
                        "failed to release pruned fork recovery snapshot; retaining incumbent for retry"
                    );
                }
            }
        }
    }
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn track_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        ordering_key: CommitOrderingKey,
        snapshot_name: String,
    ) {
        self.fork_recovery.record_pending(
            pending,
            group_id,
            source_epoch,
            storage_id,
            ordering_key,
            snapshot_name,
        );
    }

    pub(crate) fn promote_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
    ) -> Option<MessageId> {
        self.fork_recovery.promote_pending(pending)
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
        ordering_key: CommitOrderingKey,
        snapshot_name: String,
    ) {
        self.fork_recovery.record_applied(CommitRecoveryRecord {
            group_id,
            source_epoch,
            ordering_key,
            storage_id,
            snapshot_name,
        });
    }

    pub(crate) fn recovery_snapshot_name_for_fork(
        &self,
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> Option<String> {
        self.fork_recovery
            .recovery_snapshot_name(group_id, source_epoch)
    }

    pub(crate) fn resolve_fork_candidate(
        &mut self,
        group_id: &GroupId,
        source_epoch: EpochId,
        candidate_priority: CommitOrderingPriority,
        candidate_committer: MemberId,
        candidate_mls_bytes: &[u8],
    ) -> Result<ForkResolution, EngineError> {
        let candidate_digest_hex = hex::encode(Sha256::digest(candidate_mls_bytes));
        let resolution = self.fork_recovery.resolve(
            &self.storage,
            group_id,
            source_epoch,
            candidate_priority,
            candidate_committer,
            candidate_mls_bytes,
        )?;
        let (winner, incumbent_digest_hex, invalidated_msg_id) = match &resolution {
            ForkResolution::CandidateWins {
                invalidated,
                invalidated_storage_id,
                ..
            } => (
                ForkWinner::Candidate,
                Some(hex::encode(invalidated.commit_digest)),
                Some(hex::encode(invalidated_storage_id.as_slice())),
            ),
            ForkResolution::IncumbentWins => (ForkWinner::Incumbent, None, None),
            ForkResolution::MissingSnapshot => (ForkWinner::MissingSnapshot, None, None),
        };
        self.audit_group(
            group_id,
            AuditEventKind::ForkResolution {
                source_epoch: source_epoch.0,
                candidate_digest: candidate_digest_hex,
                incumbent_digest: incumbent_digest_hex,
                winner,
                invalidated_msg_id,
            },
        );
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
            self.audit_group(
                group_id,
                crate::audit_helpers::message_state_changed_event(
                    hex::encode(invalidated_storage_id.as_slice()),
                    MessageState::EpochInvalidated,
                    "fork_loser",
                ),
            );
        }
        Ok(resolution)
    }

    pub(crate) fn retained_fork_snapshots(&self, group_id: &GroupId) -> Vec<(EpochId, String)> {
        self.fork_recovery.retained_snapshots(group_id)
    }

    pub(crate) fn prune_fork_recovery_for_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        let current_epoch = self.storage.get_group(group_id)?.epoch;
        let policy = self
            .convergence_policy_for_group(group_id)
            .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
        let oldest_retained_epoch = EpochId(
            current_epoch
                .0
                .saturating_sub(policy.convergence.max_rewind_commits),
        );
        self.fork_recovery
            .prune_before(&self.storage, group_id, oldest_retained_epoch);
        self.epoch_manager
            .prune_committed_from_before(group_id, oldest_retained_epoch);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::message::{MessageRecord, MessageState};
    use cgka_traits::storage::StorageResult;
    use std::sync::Mutex;

    #[derive(Default)]
    struct HardFailingReleaseStorage {
        release_attempts: Mutex<Vec<String>>,
    }

    fn unused<T>() -> StorageResult<T> {
        unreachable!("unused in prune_before release-failure test")
    }

    impl MessageStorage for HardFailingReleaseStorage {
        fn put_message(&self, _record: &MessageRecord) -> StorageResult<()> {
            unused()
        }

        fn get_message(&self, _id: &MessageId) -> StorageResult<MessageRecord> {
            unused()
        }

        fn update_message_state(
            &self,
            _id: &MessageId,
            _new_state: MessageState,
        ) -> StorageResult<()> {
            unused()
        }

        fn list_messages(
            &self,
            _group_id: &GroupId,
            _at_or_after_epoch: EpochId,
        ) -> StorageResult<Vec<MessageRecord>> {
            unused()
        }

        fn create_group_snapshot(&self, _group_id: &GroupId, _name: &str) -> StorageResult<()> {
            unused()
        }

        fn list_group_snapshots(&self, _group_id: &GroupId) -> StorageResult<Vec<String>> {
            unused()
        }

        fn rollback_group_to_snapshot(
            &self,
            _group_id: &GroupId,
            _name: &str,
        ) -> StorageResult<()> {
            unused()
        }

        fn release_group_snapshot(&self, _group_id: &GroupId, name: &str) -> StorageResult<()> {
            self.release_attempts.lock().unwrap().push(name.to_string());
            Err(StorageError::Backend("release failed".into()))
        }
    }

    #[test]
    fn prune_before_keeps_incumbent_when_snapshot_release_hard_fails() {
        let mut manager = ForkRecoveryManager::default();
        let group_id = GroupId::new(b"group".to_vec());
        manager.record_applied(CommitRecoveryRecord {
            group_id: group_id.clone(),
            source_epoch: EpochId(1),
            ordering_key: CommitOrderingKey::from_commit_bytes(
                EpochId(1),
                CommitOrderingPriority::Ordinary,
                MemberId::new(b"alice".to_vec()),
                b"commit",
            ),
            storage_id: MessageId::new(b"message".to_vec()),
            snapshot_name: "fork-1".to_string(),
        });

        let storage = HardFailingReleaseStorage::default();
        manager.prune_before(&storage, &group_id, EpochId(2));

        assert_eq!(
            storage.release_attempts.lock().unwrap().as_slice(),
            &[String::from("fork-1")]
        );
        assert_eq!(
            manager.recovery_snapshot_name(&group_id, EpochId(1)),
            Some("fork-1".to_string())
        );
    }
}
