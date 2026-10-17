//! Migration 0035: durable per-group frozen convergence-pass state.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_convergence_passes (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);
"#,
    )
    .storage()
}
