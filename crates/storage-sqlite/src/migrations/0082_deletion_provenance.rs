use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Existing tombstones retain their IDs and masking without guessing from
    // historical sender roles. Deliberately avoid scanning history during upgrade;
    // no backfill is scheduled, so existing provenance may stay unknown indefinitely.
    tx.execute_batch(
        "ALTER TABLE message_timeline ADD COLUMN deletion_source TEXT NOT NULL DEFAULT 'unknown';
         ALTER TABLE chat_list_rows ADD COLUMN last_message_deletion_source TEXT NOT NULL DEFAULT 'unknown';",
    ).storage()
}
