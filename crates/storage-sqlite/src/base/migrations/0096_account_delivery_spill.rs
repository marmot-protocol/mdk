//! Durable overflow tail of the bounded in-memory account delivery queue.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_delivery_spill (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id BLOB NOT NULL UNIQUE CHECK(typeof(event_id)='blob' AND length(event_id)>0),
            payload BLOB NOT NULL CHECK(typeof(payload)='blob'),
            metadata BLOB NOT NULL CHECK(typeof(metadata)='blob'),
            format INTEGER NOT NULL CHECK(format=1),
            bytes INTEGER NOT NULL CHECK(typeof(bytes)='integer' AND bytes>=0),
            spilled_at INTEGER NOT NULL CHECK(typeof(spilled_at)='integer' AND spilled_at>=0),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempts)='integer' AND attempts>=0),
            not_before INTEGER NOT NULL DEFAULT 0 CHECK(typeof(not_before)='integer' AND not_before>=0)
        );",
    )
    .storage()
}
