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
//! parking as `MessageState::ConvergenceDeferred` (reconsiderable by a later
//! distributed-convergence pass, not terminal).

use crate::engine::Engine;
use cgka_traits::engine::{CommitOrderingKey, CommitOrderingPriority};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::message::{MessageState, StoredMessagePayload};
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
    /// Storage-layer identity of the commit. Used to park the row
    /// `MessageState::ConvergenceDeferred` when this commit loses a fork
    /// (its branch stays reconsiderable for distributed convergence).
    storage_id: MessageId,
    snapshot_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForkResolution {
    CandidateWins {
        winner: CommitOrderingKey,
        invalidated: CommitOrderingKey,
        /// `MessageId` of the now-displaced incumbent, for the storage
        /// write that parks its row `ConvergenceDeferred`.
        invalidated_storage_id: MessageId,
        /// The displaced row actually parked by the atomic transition. A
        /// missing incumbent row must not produce a fictional state-change
        /// audit entry.
        parked: Option<MessageId>,
    },
    IncumbentWins {
        /// Ordering key of the commit this node kept. Carried so the
        /// `fork_resolution` audit row can record WHICH branch survived —
        /// without it, incumbent-wins rows are unverifiable against other
        /// nodes' logs (cross-node convergence cannot be proven from
        /// forensics alone).
        kept: CommitOrderingKey,
    },
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

    pub(crate) fn record_pending(
        &mut self,
        pending: PendingStateRef,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        ordering_key: CommitOrderingKey,
        snapshot_name: String,
    ) {
        if let Some(counter) = snapshot_name
            .strip_prefix("fork-")
            .and_then(|suffix| suffix.split('-').nth(1))
            .and_then(|counter| counter.parse::<u64>().ok())
        {
            self.snapshot_counter = self.snapshot_counter.max(counter);
        }
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

    fn peek_pending(&self, pending: PendingStateRef) -> Option<MessageId> {
        self.pending.get(&pending).map(|r| r.storage_id.clone())
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

    fn resolve<S: StorageProvider>(
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
            return Ok(ForkResolution::IncumbentWins {
                kept: incumbent.ordering_key,
            });
        }

        // Capture, rewind, restore and release are one durable transition.
        // SQLite snapshot operations join an outer `with_transaction`; if any
        // restore fails, the rollback itself is undone and the complete live
        // state plus retained recovery snapshot remain available for retry.
        // This is required because the pre-commit snapshot predates not only
        // the incumbent row but every later message and queued outbound intent.
        // Rebuilding selected rows outside a transaction can both tear the
        // input set and make the lost branch impossible to recover.
        //
        // Park the pairwise-losing incumbent `ConvergenceDeferred`, not
        // terminally `EpochInvalidated` — the mirror of the incumbent-wins
        // seam in `ingest_group_message`. The losing branch may still gain
        // follow-on commits from peers that applied it and never saw the
        // candidate; distributed convergence then selects the DEEPER branch,
        // and every convergence-only node reorgs onto it. A terminal (or
        // missing) row is excluded from convergence input, so this node could
        // never materialize that branch's root and would diverge from the
        // fleet forever. If the incumbent's branch also loses in convergence,
        // it is re-classified terminal there (`LosingBranch`).
        //
        // The row is re-keyed at the commit's SOURCE epoch (convergence
        // derives its rewind target from `record.epoch`) and its payload is
        // preserved verbatim — for an own commit it carries the convergence
        // ordering stamp (`stamp_processed_own_commit_record`) that replay
        // needs to rebuild the ordering key (MLS refuses to process own
        // commits).
        let snapshot_name = incumbent.snapshot_name.clone();
        let incumbent_storage_id = incumbent.storage_id.clone();
        let incumbent_source_epoch = incumbent.source_epoch;
        let parked =
            storage.with_transaction(|storage| -> Result<Option<MessageId>, EngineError> {
                let mut live_messages = storage.list_messages(group_id, EpochId(0))?;
                // The current ingest call owns the candidate row. Restoring
                // that just-persisted `Created` row across the rewind makes
                // the ingest retry hit durable dedup and return `Buffered`
                // before it can apply the pairwise winner. Exclude only rows
                // whose decoded MLS wire payload is this candidate; the
                // retry loop immediately persists it again before applying,
                // while every unrelated disposition remains part of this
                // atomic transition.
                live_messages.retain(|record| {
                    let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
                        return true;
                    };
                    payload
                        .as_openmls_wire()
                        .is_none_or(|message| message.payload.as_slice() != candidate_mls_bytes)
                });
                let live_queued_outbound = storage.list_queued_outbound_intents(group_id)?;
                let mut parked = None;

                for record in &mut live_messages {
                    if record.id == incumbent_storage_id {
                        record.epoch = incumbent_source_epoch;
                        record.state = MessageState::ConvergenceDeferred;
                        parked = Some(record.id.clone());
                        continue;
                    }

                    // `Processed` is the durable proof that this later commit was
                    // on the live incumbent lineage. Re-open only those canonical
                    // descendants after rewinding their parent. Other eligible,
                    // deferred, and terminal rows are restored with their existing
                    // dispositions; epoch ordering alone must never resurrect a
                    // rejected sibling branch.
                    if record.state != MessageState::Processed {
                        continue;
                    }
                    let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
                        continue;
                    };
                    let Some(message) = payload.as_openmls_wire() else {
                        continue;
                    };
                    let Ok(projection) =
                        crate::openmls_projection::project_mls_message(&message.payload)
                    else {
                        continue;
                    };
                    let Some(projected_source_epoch) = projection.source_epoch else {
                        continue;
                    };
                    if projection.kind == crate::openmls_projection::OpenMlsContentKind::Commit
                        && projected_source_epoch > source_epoch.0
                    {
                        record.epoch = EpochId(projected_source_epoch);
                        record.state = MessageState::Retryable;
                    }
                }

                storage.rollback_group_to_snapshot(group_id, &snapshot_name)?;
                for record in &live_messages {
                    storage.put_message(record)?;
                }
                for queued in &live_queued_outbound {
                    storage.put_queued_outbound_intent(queued)?;
                }
                match storage.release_group_snapshot(group_id, &snapshot_name) {
                    Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
                    Err(error) => return Err(EngineError::Storage(error)),
                }
                Ok(parked)
            })?;
        self.incumbents.remove(&key);

        Ok(ForkResolution::CandidateWins {
            winner: candidate_key,
            invalidated: incumbent.ordering_key,
            invalidated_storage_id: incumbent.storage_id,
            parked,
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

    /// Read the origin-commit storage id for a pending entry **without**
    /// consuming the recovery record. `do_confirm_published` needs this id to
    /// mark the commit `Processed` inside its durable transaction, but it must
    /// not promote the pending → incumbent until the transaction has committed
    /// (promotion is in-memory state that a rolled-back, retried confirm would
    /// otherwise have already mutated).
    pub(crate) fn peek_pending_commit_for_recovery(
        &self,
        pending: PendingStateRef,
    ) -> Option<MessageId> {
        self.fork_recovery.peek_pending(pending)
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
            ForkResolution::IncumbentWins { kept } => (
                ForkWinner::Incumbent,
                Some(hex::encode(kept.commit_digest)),
                None,
            ),
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
        if let ForkResolution::CandidateWins { parked, .. } = &resolution {
            self.epoch_manager
                .set_stable(group_id.clone(), source_epoch);
            // `ForkRecoveryManager::resolve` parked the displaced incumbent's
            // row `ConvergenceDeferred` at its source epoch (captured before
            // the rollback swept it); record the transition for forensics.
            if let Some(parked) = parked {
                self.audit_group(
                    group_id,
                    crate::audit_helpers::message_state_changed_event(
                        hex::encode(parked.as_slice()),
                        MessageState::ConvergenceDeferred,
                        "fork_loser",
                    ),
                );
            }
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
    use cgka_traits::engine::SendIntent;
    use cgka_traits::group::{Group, ProtocolProfile};
    use cgka_traits::message::{MessageRecord, MessageState};
    use cgka_traits::storage::{
        GroupStorage, OutboundIntentStorage, QueuedOutboundIntent, StorageResult,
    };
    use std::sync::Mutex;
    use storage_sqlite::SqliteAccountStorage;

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

        fn delete_message(&self, _id: &MessageId) -> StorageResult<()> {
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

        fn put_ingress_dedup_marker(&self, _id: &MessageId) -> StorageResult<()> {
            unused()
        }

        fn has_ingress_dedup_marker(&self, _id: &MessageId) -> StorageResult<bool> {
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

    #[test]
    fn candidate_win_restores_non_descendant_states_and_queued_work() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group_id = GroupId::new(b"group".to_vec());
        storage
            .put_group(&Group {
                id: group_id.clone(),
                name: "fork restore".into(),
                description: String::new(),
                epoch: EpochId(1),
                members: Vec::new(),
                required_capabilities: Default::default(),
                protocol_profile: ProtocolProfile::Legacy,
                removed: false,
                unrecoverable: false,
                disbanded: None,
                join_epoch: EpochId(0),
            })
            .unwrap();
        storage.create_group_snapshot(&group_id, "fork-1").unwrap();

        let record = |id: &[u8], epoch, state| MessageRecord {
            id: MessageId::new(id.to_vec()),
            group_id: group_id.clone(),
            epoch: EpochId(epoch),
            state,
            payload: vec![epoch as u8],
            deferred_peel: None,
        };
        let incumbent = record(b"incumbent", 1, MessageState::Processed);
        let terminal_sibling = record(b"terminal-sibling", 2, MessageState::Failed);
        let pending_sibling = record(b"pending-sibling", 2, MessageState::Retryable);
        storage.put_message(&incumbent).unwrap();
        storage.put_message(&terminal_sibling).unwrap();
        storage.put_message(&pending_sibling).unwrap();
        let queued = QueuedOutboundIntent {
            id: MessageId::new(b"queued".to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: b"queued".to_vec(),
            },
            created_at_ms: 1,
        };
        storage.put_queued_outbound_intent(&queued).unwrap();

        let mut manager = ForkRecoveryManager::default();
        let incumbent_key = CommitOrderingKey::from_commit_bytes(
            EpochId(1),
            CommitOrderingPriority::Ordinary,
            MemberId::new(vec![0xff; 32]),
            b"incumbent-commit",
        );
        manager.record_applied(CommitRecoveryRecord {
            group_id: group_id.clone(),
            source_epoch: EpochId(1),
            ordering_key: incumbent_key.clone(),
            storage_id: incumbent.id.clone(),
            snapshot_name: "fork-1".into(),
        });
        let candidate_committer = MemberId::new(vec![0; 32]);
        let candidate_key = CommitOrderingKey::from_commit_bytes(
            EpochId(1),
            CommitOrderingPriority::Ordinary,
            candidate_committer.clone(),
            b"candidate-commit",
        );
        assert!(candidate_key < incumbent_key);

        let resolution = manager
            .resolve(
                &storage,
                &group_id,
                EpochId(1),
                CommitOrderingPriority::Ordinary,
                candidate_committer,
                b"candidate-commit",
            )
            .unwrap();
        assert!(matches!(resolution, ForkResolution::CandidateWins { .. }));
        assert_eq!(
            storage.get_message(&incumbent.id).unwrap().state,
            MessageState::ConvergenceDeferred
        );
        assert_eq!(
            storage.get_message(&terminal_sibling.id).unwrap().state,
            MessageState::Failed,
            "terminal sibling must not be resurrected by epoch ordering"
        );
        assert_eq!(
            storage.get_message(&pending_sibling.id).unwrap().state,
            MessageState::Retryable
        );
        assert_eq!(
            storage.list_queued_outbound_intents(&group_id).unwrap(),
            vec![queued]
        );
    }
}
