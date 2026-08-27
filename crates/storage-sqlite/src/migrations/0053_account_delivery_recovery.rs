//! Migration 0053: durable incomplete-recovery marker for app relay overflow.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE account_delivery_recovery (
    account_label TEXT PRIMARY KEY
        REFERENCES account_state(label) ON DELETE CASCADE,
    marker_token INTEGER NOT NULL CHECK (marker_token >= 0),
    pending_since INTEGER NOT NULL CHECK (pending_since >= 0),
    dropped_count INTEGER NOT NULL CHECK (dropped_count >= 0)
);
"#,
    )
    .storage()
}
