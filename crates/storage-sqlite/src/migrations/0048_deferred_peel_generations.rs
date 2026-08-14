//! Migration 0048: durable contested deferred-peel generation barrier.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_deferred_peel_generations (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);
"#,
    )
    .storage()
}
