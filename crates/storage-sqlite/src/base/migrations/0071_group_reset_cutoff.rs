use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Legacy markers have no creation time. Start their reset window at migration
    // rather than allowing every historical Welcome to resurrect the group.
    tx.execute_batch(
        "ALTER TABLE locally_forgotten_groups ADD COLUMN forgotten_at INTEGER NOT NULL DEFAULT 0 CHECK(forgotten_at >= 0);
         ALTER TABLE locally_forgotten_groups ADD COLUMN awaiting_welcome INTEGER NOT NULL DEFAULT 1 CHECK(awaiting_welcome IN (0, 1));
         UPDATE locally_forgotten_groups SET forgotten_at = CAST(strftime('%s', 'now') AS INTEGER);
         DROP TRIGGER reject_forgotten_group_insert;
         CREATE TRIGGER reject_forgotten_group_insert BEFORE INSERT ON cgka_groups
         WHEN EXISTS(SELECT 1 FROM locally_forgotten_groups
                     WHERE group_id = NEW.id AND awaiting_welcome = 1)
         BEGIN SELECT RAISE(ABORT, 'group awaiting fresh welcome'); END;",
    )
    .storage()
}
