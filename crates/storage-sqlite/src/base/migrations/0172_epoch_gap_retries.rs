//! Runner-owned bounded return visits for an unresolved epoch-gap obligation.

use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_epoch_gap_retries (
            obligation_id BLOB PRIMARY KEY NOT NULL
                REFERENCES account_recovery_obligations(id) ON DELETE CASCADE,
            stalled_epoch INTEGER NOT NULL CHECK (stalled_epoch >= 0),
            visits INTEGER NOT NULL CHECK (visits > 0),
            in_progress INTEGER NOT NULL CHECK (in_progress IN (0, 1)),
            exhausted INTEGER NOT NULL CHECK (exhausted IN (0, 1)),
            next_retry_at_seconds INTEGER NOT NULL CHECK (next_retry_at_seconds >= 0)
        ) WITHOUT ROWID;",
    )
    .storage()
}
