//! Migration 0143: heartbeats in the device group (mdk#2628 item 3.6, D35).
//!
//! `device_activity` holds one row per sibling this device has found in its
//! device group's roster: the `linked_at` of the roster entry it describes,
//! when this device first found that entry (`first_seen_at`) and the newest
//! time a heartbeat of that sibling counted for (`last_active_at`, null until
//! one does), all in Unix seconds. A slot linked again is a new entry with a
//! new `linked_at`, and its row starts afresh.
//!
//! `device_heartbeat_sent` holds at most one row: the device group this
//! device last sent its own heartbeat in and when.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_activity (
            slot_id_hex TEXT PRIMARY KEY NOT NULL,
            linked_at INTEGER NOT NULL,
            first_seen_at INTEGER NOT NULL,
            last_active_at INTEGER
        ) WITHOUT ROWID;
        CREATE TABLE device_heartbeat_sent (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
            group_id_hex TEXT NOT NULL,
            sent_at INTEGER NOT NULL
        );",
    )
    .storage()
}
