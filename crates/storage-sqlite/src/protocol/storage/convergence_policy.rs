use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{ConvergencePolicyStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl ConvergencePolicyStorage for SqliteAccountStorage {
    fn put_convergence_policy(&self, group_id: &GroupId, policy: &[u8]) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO cgka_convergence_policies (group_id, policy)
                 VALUES (?1, ?2)",
                params![group_id.as_slice(), policy],
            )
            .storage()?;
        Ok(())
    }

    fn convergence_policy(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.lock()?
            .query_row_cached(
                "SELECT policy FROM cgka_convergence_policies WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }
}
