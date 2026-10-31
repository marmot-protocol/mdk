//! Migration 0163: the account's backup recovery key, as a device that trusts
//! no device group keeps it (mdk#2628 item 4.4a).
//!
//! `backup_recovery_key` holds at most one row: `public_key` is the public
//! half of the recovery key words confirmed while this device trusted no
//! device group derive. The roster this device founds carries it. Trusting
//! any device group deletes the row, since the roster's account entry is
//! then the account's. The words and the private half are never stored. No
//! rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE backup_recovery_key (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            public_key BLOB NOT NULL CHECK (length(public_key) BETWEEN 1 AND 255)
        );",
    )
    .storage()
}
