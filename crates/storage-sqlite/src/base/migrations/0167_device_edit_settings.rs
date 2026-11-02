//! Migration 0167: D37 user edits also retain device settings (mdk#2628 D86).
//! NULL keeps existing records label-only; no settings are invented on upgrade.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE device_renames ADD COLUMN settings INTEGER
         CHECK(settings IS NULL OR settings BETWEEN 0 AND 7);",
    )
    .storage()
}
