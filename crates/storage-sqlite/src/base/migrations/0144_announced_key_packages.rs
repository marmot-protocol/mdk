//! Migration 0144: KeyPackages device-group rosters announced (mdk#2628 D31
//! item 7).
//!
//! `cgka_announced_key_packages` holds one row per `(group, slot,
//! KeyPackageRef)` a roster this device held announced, with when this device
//! last applied a roster state that announced it. The engine writes them in
//! the transaction that applies each roster state, and never reads them: no
//! snapshot or replay fingerprint covers them, so a branch-selection rewind
//! keeps them. A row is dropped 30 days after it was last seen, each group
//! slot keeps only its newest few, and deleting the group deletes its rows.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_announced_key_packages (
            group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
            slot BLOB NOT NULL CHECK(length(slot) = 32),
            key_package_ref BLOB NOT NULL,
            last_seen_at INTEGER NOT NULL CHECK(last_seen_at >= 0),
            PRIMARY KEY (group_id, slot, key_package_ref)
        );
        CREATE INDEX cgka_announced_key_packages_by_age
            ON cgka_announced_key_packages (last_seen_at);",
    )
    .storage()
}
