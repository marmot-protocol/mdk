//! Migration 0201: the inactivity clock for marking and removing inactive
//! siblings (mdk#2628 item 3.6b-2, D67, D94, D95).
//!
//! `device_activity` gains two columns for each sibling entry:
//! - `clock_from`: when this device last restarted that sibling's clock: when
//!   it read a heartbeat that moved the sibling's last activity later, or saw
//!   the sibling clear its own mark. Null until then, which reads as the row's
//!   `first_seen_at`.
//! - `marked_inactive`: whether the roster held the entry as `inactive` the
//!   last time this device looked, so it can tell when the mark was cleared.
//!
//! `device_inactivity_clock` holds at most one row: this device's last
//! maintenance pass that found it caught up with its device group
//! (`caught_up_at`), and when it last restarted every sibling's clock
//! (`restarted_at`).
//!
//! No rows are seeded: an existing row's clock starts at the next restart,
//! which the first caught-up pass makes.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE device_activity ADD COLUMN clock_from INTEGER;
        ALTER TABLE device_activity ADD COLUMN marked_inactive INTEGER NOT NULL DEFAULT 0
            CHECK(marked_inactive IN (0, 1));
        CREATE TABLE device_inactivity_clock (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
            caught_up_at INTEGER NOT NULL,
            restarted_at INTEGER NOT NULL
        );",
    )
    .storage()
}
