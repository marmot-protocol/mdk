use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // App messages invalidated by convergence are no longer dropped from the
    // timeline projection; they are kept as tombstones carrying the invalidation
    // reason so the sender's own message does not silently disappear (issue #111).
    // The raw `app_events.invalidation_reason` already exists; this column carries
    // the projected status onto the rebuilt timeline row.
    tx.execute_batch(
        r#"
ALTER TABLE message_timeline ADD COLUMN invalidation_status TEXT;
"#,
    )
    .storage()
}
