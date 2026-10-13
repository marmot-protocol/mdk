//! Migration 0108: account-private coalesced KeyPackage slot observation.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS key_package_slot_observation (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            record BLOB NOT NULL
        );",
    )
    .storage()
}
