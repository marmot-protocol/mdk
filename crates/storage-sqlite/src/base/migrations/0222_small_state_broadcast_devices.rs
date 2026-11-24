//! Migration 0222: the devices this device's last small-state broadcast was
//! made for (mdk#3556).
//!
//! - `small_state_broadcast_devices`: one row per device the trusted device
//!   group's roster listed when the last broadcast began, its 32-byte slot
//!   and the roster's `linked_at` for it, so a slot linked again counts as a
//!   new device. A new broadcast replaces every row. A device the roster
//!   lists with no row here has received no broadcast from this device.
//!
//! No rows are seeded: a device that upgrades broadcasts once more.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE small_state_broadcast_devices (
            slot BLOB PRIMARY KEY CHECK(length(slot) = 32),
            linked_at INTEGER NOT NULL CHECK(linked_at >= 0)
        ) WITHOUT ROWID;",
    )
    .storage()
}
