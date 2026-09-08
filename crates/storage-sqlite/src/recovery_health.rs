//! Durable reports of unsuccessful automatic synchronization recovery.
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, StoredEpochStallEvidence};
use cgka_traits::GroupId;
use cgka_traits::storage::{StorageProvider, StorageResult};

impl SqliteAccountStorage {
    /// Whether completed automatic recovery has failed to restore synchronization.
    pub fn automatic_recovery_failed(&self, group_id: &GroupId) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM app_group_recovery_failures WHERE group_id = ?1)",
                [group_id.as_slice()],
                |row| row.get(0),
            )
            .storage()
    }

    /// Commit replay evidence and its warning together. Epoch movement may reset
    /// the evidence but never clears a warning already earned by failed replays.
    /// Returns the groups whose visible status changed.
    pub fn record_recovery_evidence(
        &self,
        evidence: &[StoredEpochStallEvidence],
        fruitless_threshold: u32,
    ) -> StorageResult<Vec<GroupId>> {
        if evidence.is_empty() {
            return Ok(Vec::new());
        }
        self.with_transaction(|storage| {
            storage.record_epoch_stall_evidence(evidence)?;
            let conn = storage.lock()?;
            let mut changed = Vec::new();
            for entry in evidence
                .iter()
                .filter(|entry| entry.fruitless_completions >= fruitless_threshold.max(1))
            {
                let group_id = hex::decode(&entry.group_id_hex).map_err(|error| {
                    cgka_traits::storage::StorageError::Serialization(error.to_string())
                })?;
                if conn
                    .execute_cached(
                        "INSERT OR IGNORE INTO app_group_recovery_failures(group_id) VALUES (?1)",
                        [group_id.as_slice()],
                    )
                    .storage()?
                    > 0
                {
                    changed.push(GroupId::new(group_id));
                }
            }
            Ok(changed)
        })
    }

    /// Authenticated recovery clears both the warning and persisted replay
    /// evidence, so reopening cannot resurrect an already-resolved failure.
    pub fn clear_recovery_failure(&self, group_id: &GroupId) -> StorageResult<bool> {
        let has_evidence: bool = self
            .lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM app_group_recovery_failures WHERE group_id = ?1)
             OR EXISTS(SELECT 1 FROM app_epoch_stall_evidence WHERE group_id = ?1)",
                [group_id.as_slice()],
                |row| row.get(0),
            )
            .storage()?;
        if !has_evidence {
            return Ok(false);
        }
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            conn.execute_cached(
                "DELETE FROM app_epoch_stall_evidence WHERE group_id = ?1",
                [group_id.as_slice()],
            )
            .storage()?;
            Ok(conn
                .execute_cached(
                    "DELETE FROM app_group_recovery_failures WHERE group_id = ?1",
                    [group_id.as_slice()],
                )
                .storage()?
                != 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    fn evidence(completions: u32) -> StoredEpochStallEvidence {
        StoredEpochStallEvidence {
            group_id_hex: hex::encode(gid(1).as_slice()),
            stalled_epoch: 1,
            fruitless_completions: completions,
            fruitless_reported: completions >= 3,
            last_arm_at_ms: 1,
        }
    }

    #[test]
    fn warning_requires_failed_replays_and_survives_epoch_movement() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        for n in 0..3 {
            assert!(
                storage
                    .record_recovery_evidence(&[evidence(n)], 3)
                    .unwrap()
                    .is_empty()
            );
            assert!(!storage.automatic_recovery_failed(&gid(1)).unwrap());
        }
        assert_eq!(
            storage.record_recovery_evidence(&[evidence(3)], 3).unwrap(),
            vec![gid(1)]
        );
        let mut moved = evidence(0);
        moved.stalled_epoch = 2;
        storage.record_recovery_evidence(&[moved], 3).unwrap();
        assert!(storage.automatic_recovery_failed(&gid(1)).unwrap());
        assert!(storage.clear_recovery_failure(&gid(1)).unwrap());
        assert!(storage.epoch_stall_evidence().unwrap().is_empty());
        assert!(!storage.automatic_recovery_failed(&gid(1)).unwrap());
        storage
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only = ON")
            .unwrap();
        assert!(!storage.clear_recovery_failure(&gid(1)).unwrap());
    }

    #[test]
    fn warning_and_replay_evidence_commit_atomically_and_cascade() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        storage.lock().unwrap().execute_batch("CREATE TRIGGER reject_warning BEFORE INSERT ON app_group_recovery_failures BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
        assert!(storage.record_recovery_evidence(&[evidence(3)], 3).is_err());
        assert!(storage.epoch_stall_evidence().unwrap().is_empty());
        storage
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_warning")
            .unwrap();
        storage.record_recovery_evidence(&[evidence(3)], 3).unwrap();
        storage.delete_group(&gid(1)).unwrap();
        assert!(!storage.automatic_recovery_failed(&gid(1)).unwrap());
    }
}
