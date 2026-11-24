//! Migration 0225: what the sender keeps of each outbound Welcome's delivery
//! (mdk#1706).
//!
//! One row per Welcome, keyed by its id: the invite it belongs to and what its
//! publish attempts found. The row holds no delivery state; that is derived
//! from the engine's Welcome row whenever it is read. Rows go with their
//! group's `cgka_groups` row. The table is outside every snapshot and
//! checkpoint.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_welcome_delivery_ledger (
            welcome_id BLOB PRIMARY KEY,
            group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
            record BLOB NOT NULL
        );
        CREATE INDEX idx_cgka_welcome_delivery_ledger_group
            ON cgka_welcome_delivery_ledger(group_id);",
    )
    .storage()
}
