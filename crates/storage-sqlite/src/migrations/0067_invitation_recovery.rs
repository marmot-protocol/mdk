use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Also gates the new durable reinvite/rejoin record fields against older writers.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_group_recovery_failures (
             group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE
         );",
    )
    .storage()
}
