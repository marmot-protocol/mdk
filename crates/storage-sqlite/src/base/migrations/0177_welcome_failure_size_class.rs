//! Best-effort coarse diagnosis on the existing Welcome repair pointer.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("ALTER TABLE app_pending_welcome_delivery ADD COLUMN size_class TEXT")
        .storage()
}
