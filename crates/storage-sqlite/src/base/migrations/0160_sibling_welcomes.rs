//! Migration 0160: sibling Welcomes (mdk#2628 item 3.5b).
//!
//! `sibling_welcomes_received` holds each sibling Welcome (kind 461) this
//! device admitted from its trusted device group and has not joined from yet,
//! keyed by the device-group message that carried it. The app reads device-
//! group messages while it projects events and joins later, so an admitted
//! one waits here until the join settles it. `held_group_id_hex` names the
//! chat of one the engine held, because this device still held an active
//! copy of that chat; it joins once that copy lets go.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE sibling_welcomes_received (
            message_id_hex TEXT PRIMARY KEY NOT NULL,
            content BLOB NOT NULL,
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            received_at INTEGER NOT NULL CHECK(received_at >= 0),
            held_group_id_hex TEXT
        );",
    )
    .storage()
}
