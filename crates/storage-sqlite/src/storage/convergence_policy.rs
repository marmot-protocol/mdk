use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{ConvergencePolicyStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl ConvergencePolicyStorage for SqliteAccountStorage {
    fn put_convergence_policy(&self, group_id: &GroupId, policy: &[u8]) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_convergence_policies (group_id, policy)
                 VALUES (?1, ?2)",
                params![group_id.as_slice(), policy],
            )
            .storage()?;
        Ok(())
    }

    fn convergence_policy(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.lock()?
            .query_row(
                "SELECT policy FROM cgka_convergence_policies WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::{ConvergencePolicyStorage, GroupStorage, MessageStorage};

    #[test]
    fn convergence_policy_is_group_scoped_and_snapshot_restored() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let g1 = sample_group(gid(1), 0, 0);
        let g2 = sample_group(gid(2), 0, 0);
        store.put_group(&g1).unwrap();
        store.put_group(&g2).unwrap();

        store.put_convergence_policy(&g1.id, b"policy-v1").unwrap();
        store
            .put_convergence_policy(&g2.id, b"other-policy")
            .unwrap();
        store.create_group_snapshot(&g1.id, "policy").unwrap();
        store.put_convergence_policy(&g1.id, b"policy-v2").unwrap();

        store.rollback_group_to_snapshot(&g1.id, "policy").unwrap();

        assert_eq!(
            store.convergence_policy(&g1.id).unwrap(),
            Some(b"policy-v1".to_vec())
        );
        assert_eq!(
            store.convergence_policy(&g2.id).unwrap(),
            Some(b"other-policy".to_vec())
        );
    }
}
