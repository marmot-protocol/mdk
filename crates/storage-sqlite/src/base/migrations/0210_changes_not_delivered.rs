//! Migration 0210: the group changes this device rolled back after their
//! caller was given an unresolved result (mdk#2332).
//!
//! One row per rolled-back commit, written in the rollback's transaction and
//! kept until the host acknowledges it. Rows go with their group: forgetting
//! it, or deleting a terminal group, deletes the `cgka_groups` row, while an
//! active chat wipe keeps both. The table is outside every snapshot and
//! checkpoint, so rewinding a group neither drops nor restores a record.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_changes_not_delivered (
            commit_id BLOB PRIMARY KEY,
            group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
            record BLOB NOT NULL
        );
        CREATE INDEX idx_cgka_changes_not_delivered_group
            ON cgka_changes_not_delivered(group_id);",
    )
    .storage()
}
