use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // SQLite appends rowid to this index, matching the recency tie-breaker.
    tx.execute_batch("CREATE INDEX IF NOT EXISTS idx_seen_events_recency ON seen_events(seen_at);")
        .storage()
}
