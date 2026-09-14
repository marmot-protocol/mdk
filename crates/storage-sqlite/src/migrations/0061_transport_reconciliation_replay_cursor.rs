use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE transport_reconciliation_route_state ADD COLUMN replay_after BLOB
         CHECK (replay_after IS NULL OR (typeof(replay_after) = 'blob' AND length(replay_after) = 32));",
    ).storage()
}
