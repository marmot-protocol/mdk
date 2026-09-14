use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // No group foreign key: this local decision must outlive all group state.
    tx.execute_batch(
        "CREATE TABLE locally_forgotten_groups (group_id BLOB PRIMARY KEY NOT NULL);
         CREATE TRIGGER reject_forgotten_group_insert BEFORE INSERT ON cgka_groups
         WHEN EXISTS(SELECT 1 FROM locally_forgotten_groups WHERE group_id = NEW.id)
         BEGIN SELECT RAISE(ABORT, 'group forgotten on this device'); END;",
    )
    .storage()
}
