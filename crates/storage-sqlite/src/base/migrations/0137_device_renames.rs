//! Migration 0137: renames this device made in its device group's roster
//! (mdk#2628 item 3.6, D37).
//!
//! `device_renames` holds one row per device this device renamed: the label
//! its latest rename of that device sets, the rename ids that rename wrote
//! (`written`, 16 bytes each, oldest first), and the rename ids the device's
//! entry held where this device's renames of it were built (`replaced`,
//! 17 bytes each, oldest first: a presence byte, then the id or 16 zero
//! bytes for an entry never renamed).
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_renames (
            slot_id_hex TEXT PRIMARY KEY NOT NULL,
            label TEXT NOT NULL,
            written BLOB NOT NULL CHECK(length(written) > 0 AND length(written) % 16 = 0),
            replaced BLOB NOT NULL CHECK(length(replaced) > 0 AND length(replaced) % 17 = 0)
        ) WITHOUT ROWID;",
    )
    .storage()
}
