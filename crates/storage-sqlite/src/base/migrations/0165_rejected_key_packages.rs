//! Migration 0165: rejected KeyPackages this device keeps itself (mdk#2628
//! item 3.7b).
//!
//! - `account_rejected_key_packages`: one row per KeyPackage this device
//!   rejected, keyed by its `KeyPackageRef`, with the slot it appeared in, its
//!   LeafNode's signature key and when this device recorded the rejection, by
//!   its own clock. A row stays after the roster takes it, until it lapses:
//!   the device commits it again whenever the roster lacks it.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_rejected_key_packages (
            key_package_ref_hex TEXT PRIMARY KEY NOT NULL,
            slot_id_hex TEXT NOT NULL,
            leaf_signature_key BLOB NOT NULL,
            rejected_at INTEGER NOT NULL CHECK(rejected_at >= 0)
        ) WITHOUT ROWID;",
    )
    .storage()
}
