use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(super) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Both first-reference retention and retirement address an entire epoch.
    tx.execute_batch(
        "DROP INDEX IF EXISTS idx_media_secrets_retirement;
         CREATE INDEX IF NOT EXISTS idx_media_secrets_epoch
             ON encrypted_media_epoch_secrets(group_id_hex, source_epoch);",
    )
    .storage()
}
