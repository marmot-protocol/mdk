//! Migration 0165: retire the unused roster announcement history (mdk#2863,
//! mdk#2628 D81). The authoritative device roster remains unchanged.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "DROP INDEX IF EXISTS cgka_announced_key_packages_by_age;
         DROP TABLE IF EXISTS cgka_announced_key_packages;",
    )
    .storage()
}
