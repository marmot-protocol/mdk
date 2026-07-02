use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{MemberValidationCacheStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl MemberValidationCacheStorage for SqliteAccountStorage {
    fn put_validated_tree_marker(&self, group_id: &GroupId, marker: &[u8]) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_member_validation_cache (group_id, marker)
                 VALUES (?1, ?2)",
                params![group_id.as_slice(), marker],
            )
            .storage()?;
        Ok(())
    }

    fn validated_tree_marker(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.lock()?
            .query_row(
                "SELECT marker FROM cgka_member_validation_cache WHERE group_id = ?1",
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
    use cgka_traits::storage::{GroupStorage, MemberValidationCacheStorage, MessageStorage};

    #[test]
    fn validated_tree_marker_is_group_scoped_and_snapshot_restored() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let g1 = sample_group(gid(1), 0, 0);
        let g2 = sample_group(gid(2), 0, 0);
        store.put_group(&g1).unwrap();
        store.put_group(&g2).unwrap();

        assert_eq!(store.validated_tree_marker(&g1.id).unwrap(), None);

        store
            .put_validated_tree_marker(&g1.id, b"marker-v1")
            .unwrap();
        store
            .put_validated_tree_marker(&g2.id, b"other-marker")
            .unwrap();
        store.create_group_snapshot(&g1.id, "anchor").unwrap();
        store
            .put_validated_tree_marker(&g1.id, b"marker-v2")
            .unwrap();

        store.rollback_group_to_snapshot(&g1.id, "anchor").unwrap();

        assert_eq!(
            store.validated_tree_marker(&g1.id).unwrap(),
            Some(b"marker-v1".to_vec())
        );
        assert_eq!(
            store.validated_tree_marker(&g2.id).unwrap(),
            Some(b"other-marker".to_vec())
        );
    }
}
