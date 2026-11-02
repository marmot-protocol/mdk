use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{MemberValidationCacheStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl MemberValidationCacheStorage for SqliteAccountStorage {
    fn put_validated_tree_marker(&self, group_id: &GroupId, marker: &[u8]) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO cgka_member_validation_cache (group_id, marker)
                 VALUES (?1, ?2)",
                params![group_id.as_slice(), marker],
            )
            .storage()?;
        Ok(())
    }

    fn validated_tree_marker(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.lock()?
            .query_row_cached(
                "SELECT marker FROM cgka_member_validation_cache WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }
}
