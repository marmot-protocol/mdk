use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Retire the early-warning counter without upgrading weak evidence to failure.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "DROP TABLE app_group_membership_evidence;
         DROP TABLE app_group_membership_uncertainty;
         CREATE TABLE app_group_recovery_failures (
             group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE
         );",
    )
    .storage()
}
