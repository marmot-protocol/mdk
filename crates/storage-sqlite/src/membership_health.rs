//! Bounded, durable advisory membership evidence. Undecryptable traffic never
//! authorizes crypto-state replacement or changes authoritative membership.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{StorageProvider, StorageResult};
use cgka_traits::{EpochId, GroupId, MessageId};
use rusqlite::params;

impl SqliteAccountStorage {
    pub fn membership_unconfirmed(&self, group_id: &GroupId) -> StorageResult<bool> {
        self.lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM app_group_membership_uncertainty WHERE group_id = ?1)",
                [group_id.as_slice()],
                |row| row.get(0),
            )
            .storage()
    }

    /// Count distinct events, capped at the caller's bounded detector threshold.
    /// Epoch movement resets evidence, but only authenticated recovery clears
    /// the advisory warning. Returns whether the visible status changed.
    pub fn observe_membership_undecryptable(
        &self,
        group_id: &GroupId,
        message_id: &MessageId,
        epoch: EpochId,
        threshold: usize,
    ) -> StorageResult<bool> {
        self.with_transaction(|storage| {
            if storage.membership_unconfirmed(group_id)? {
                return Ok(false);
            }
            let conn = storage.lock()?;
            let epoch = crate::epoch_to_i64(epoch)?;
            conn.execute(
                "DELETE FROM app_group_membership_evidence
                 WHERE group_id = ?1 AND epoch != ?2",
                params![group_id.as_slice(), epoch],
            )
            .storage()?;
            conn.execute(
                "INSERT OR IGNORE INTO app_group_membership_evidence
                 (group_id, message_id, epoch) VALUES (?1, ?2, ?3)",
                params![group_id.as_slice(), message_id.as_slice(), epoch],
            )
            .storage()?;
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM app_group_membership_evidence
                 WHERE group_id = ?1",
                    [group_id.as_slice()],
                    |row| row.get(0),
                )
                .storage()?;
            if count >= threshold.clamp(1, 64) as i64 {
                conn.execute(
                    "INSERT OR IGNORE INTO app_group_membership_uncertainty
                     (group_id) VALUES (?1)",
                    [group_id.as_slice()],
                )
                .storage()?;
                return Ok(true);
            }
            Ok(false)
        })
    }

    pub fn clear_membership_uncertainty(&self, group_id: &GroupId) -> StorageResult<bool> {
        // Ordinary authenticated traffic usually has nothing to clear. Avoid
        // a writer transaction on that hot path, but include subthreshold
        // evidence so successful traffic also resets a partial failure streak.
        let has_evidence: bool = self
            .lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM app_group_membership_uncertainty WHERE group_id = ?1)
                 OR EXISTS(SELECT 1 FROM app_group_membership_evidence WHERE group_id = ?1)",
                [group_id.as_slice()],
                |row| row.get(0),
            )
            .storage()?;
        if !has_evidence {
            return Ok(false);
        }
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            conn.execute(
                "DELETE FROM app_group_membership_evidence WHERE group_id = ?1",
                [group_id.as_slice()],
            )
            .storage()?;
            Ok(conn
                .execute(
                    "DELETE FROM app_group_membership_uncertainty WHERE group_id = ?1",
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
    use crate::storage::test_support::{gid, mid, sample_group};
    use cgka_traits::storage::GroupStorage;

    #[test]
    fn empty_membership_clear_is_read_only_and_partial_evidence_still_resets() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        storage
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only = ON")
            .unwrap();
        assert!(
            !storage.clear_membership_uncertainty(&gid(1)).unwrap(),
            "an empty clear must succeed without opening a write transaction"
        );
        storage
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only = OFF")
            .unwrap();
        for n in 1..8 {
            assert!(
                !storage
                    .observe_membership_undecryptable(&gid(1), &mid(n), EpochId(1), 8)
                    .unwrap()
            );
        }
        assert!(!storage.clear_membership_uncertainty(&gid(1)).unwrap());
        assert!(
            !storage
                .observe_membership_undecryptable(&gid(1), &mid(8), EpochId(1), 8)
                .unwrap(),
            "successful traffic must reset the seven-event partial streak too"
        );
    }

    #[test]
    fn membership_evidence_is_distinct_bounded_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("membership-health.db");
        let key = crate::SqlCipherKey::new("membership-health-test").unwrap();
        let open = || {
            SqliteAccountStorage::open_encrypted_with_options(
                &path,
                &key,
                crate::SqliteStorageOptions::default(),
            )
            .unwrap()
        };
        let storage = open();
        storage.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        storage.put_group(&sample_group(gid(2), 1, 2)).unwrap();
        for _ in 0..20 {
            assert!(
                !storage
                    .observe_membership_undecryptable(&gid(1), &mid(1), EpochId(1), 8)
                    .unwrap()
            );
        }
        for n in 2..8 {
            assert!(
                !storage
                    .observe_membership_undecryptable(&gid(1), &mid(n), EpochId(1), 8)
                    .unwrap()
            );
        }
        drop(storage);
        let storage = open();
        assert!(
            storage
                .observe_membership_undecryptable(&gid(1), &mid(8), EpochId(1), 8)
                .unwrap()
        );
        for n in 9..100 {
            assert!(
                !storage
                    .observe_membership_undecryptable(&gid(1), &mid(n), EpochId(1), 8)
                    .unwrap()
            );
        }
        let count: i64 = storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM app_group_membership_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 8);
        assert!(!storage.membership_unconfirmed(&gid(2)).unwrap());
        drop(storage);
        let storage = open();
        assert!(storage.membership_unconfirmed(&gid(1)).unwrap());
        assert!(storage.clear_membership_uncertainty(&gid(1)).unwrap());
        assert!(!storage.membership_unconfirmed(&gid(1)).unwrap());
        for n in 1..8 {
            assert!(
                !storage
                    .observe_membership_undecryptable(&gid(1), &mid(n), EpochId(2), 8)
                    .unwrap()
            );
        }
        assert!(
            !storage
                .observe_membership_undecryptable(&gid(1), &mid(8), EpochId(3), 8)
                .unwrap()
        );
        storage.delete_group(&gid(1)).unwrap();
        let count: i64 = storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM app_group_membership_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
