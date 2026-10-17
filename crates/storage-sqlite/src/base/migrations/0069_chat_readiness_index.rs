use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(super) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Readiness probes need the latest receipt, regardless of preview eligibility.
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_message_timeline_group_received
             ON message_timeline(group_id_hex, received_at);",
    )
    .storage()
}
