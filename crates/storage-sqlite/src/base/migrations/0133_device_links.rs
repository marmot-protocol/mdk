//! Migration 0133: the links this device approved, and whether each
//! approving commit has settled (mdk#2628 item 3.3b).
//!
//! One row per device this device approved adding to the account's device
//! group, keyed by the group and the device's KeyPackage slot. The row is
//! written before the approving commit, so a crash cannot lose it.
//! `settlement` is one of:
//!
//! - `pending`: the approving commit has not settled under the convergence
//!   rules yet.
//! - `settled`: the group is past the commit with nothing left to converge,
//!   and the roster lists the device with the confirmed `KeyPackageRef`.
//!   Adding the device to chats waits for this.
//! - `reversed`: the group settled without the device: a competing commit
//!   won, or the approving commit never landed.
//!
//! `settled_at` is when the settlement was decided, NULL only while pending.
//! Linking a slot again replaces its row. No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_links (
            group_id_hex TEXT NOT NULL,
            slot_hex TEXT NOT NULL,
            key_package_ref_hex TEXT NOT NULL,
            linked_at INTEGER NOT NULL CHECK(linked_at >= 0),
            settlement TEXT NOT NULL CHECK(settlement IN ('pending', 'settled', 'reversed')),
            settled_at INTEGER CHECK(settled_at >= 0),
            CHECK((settlement = 'pending') = (settled_at IS NULL)),
            PRIMARY KEY (group_id_hex, slot_hex)
        );",
    )
    .storage()
}
