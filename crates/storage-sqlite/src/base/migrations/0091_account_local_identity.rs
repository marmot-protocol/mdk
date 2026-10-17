use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Persist the account identity with the per-account projection root so every
/// timeline read can recognize sibling-device authors without depending on a
/// lazily-created notification-settings row.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("ALTER TABLE account_state ADD COLUMN local_account_id_hex TEXT;")
        .storage()?;
    Ok(())
}
