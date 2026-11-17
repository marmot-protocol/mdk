//! Migration 0211: the slots of the account's devices that the user linked
//! and then removed, as this device's sign-ins know them (mdk#2628 item 3.2).
//!
//! - `account_sign_in_removals`: one row per slot the trusted roster recorded
//!   as `removed` here. `removed_at` is that record's `rejected_at` plus the
//!   future skew the directory accepts from a publisher's clock. A
//!   publication in the slot no later than it is the removed device's, never
//!   a new sign-in, after the roster drops the record too.
//!
//! No rows are seeded: a `removed` record still in a roster is recorded at the
//! next check or device-group event.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_sign_in_removals (
            slot_id_hex TEXT PRIMARY KEY NOT NULL,
            removed_at INTEGER NOT NULL CHECK(removed_at >= 0)
        ) WITHOUT ROWID;",
    )
    .storage()
}
