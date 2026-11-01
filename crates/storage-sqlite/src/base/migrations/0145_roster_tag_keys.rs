//! Migration 0145: tag signature keys device-group rosters listed (mdk#2761).
//!
//! `cgka_roster_tag_keys` holds one row per `(group, slot, tag signature
//! key)` a roster this device held listed, in a device entry or a `removed`
//! record, with when this device last applied a roster state that listed it.
//! The engine writes them in the transaction that applies each roster state,
//! and never reads them: no snapshot or replay fingerprint covers them, so a
//! branch-selection rewind keeps them. A row is dropped 30 days after it was
//! last seen, each group slot keeps only its newest few, and deleting the
//! group deletes its rows.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_roster_tag_keys (
            group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
            slot BLOB NOT NULL CHECK(length(slot) = 32),
            tag_signature_key BLOB NOT NULL,
            last_seen_at INTEGER NOT NULL CHECK(last_seen_at >= 0),
            PRIMARY KEY (group_id, slot, tag_signature_key)
        );
        CREATE INDEX cgka_roster_tag_keys_by_age
            ON cgka_roster_tag_keys (last_seen_at);",
    )
    .storage()
}
