use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Engine hydration replays every pending event in source-message order.
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_pending_application_events_order
         ON pending_application_events(message_insert_order, message_id);",
    )
    .storage()
}
