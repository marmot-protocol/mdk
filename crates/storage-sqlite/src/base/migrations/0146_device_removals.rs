//! Migration 0146: the removals of other devices this device decided
//! (mdk#2628 item 3.6b).
//!
//! `device_removals` holds one row per device this device's user removed
//! from the account's device group, keyed by the group and the removed
//! device's KeyPackage slot. The row is written before anything is
//! committed, so the decision survives a crash, a busy device group and a
//! lost fork. `requested_at` is when the user decided, and is the
//! `rejected_at` of the slot's `removed` record. While the roster lists the
//! slot as a device, this device owes the commit removing it; once the
//! roster no longer lists it, it owes the deletion of the slot's
//! KeyPackages, and `slot_withdrawn_at` records when a relay accepted that.
//! The row stays for as long as this device trusts the device group, so a
//! removal that branch selection drops later is committed again, and its
//! deletion sent again, even after the `removed` record has expired. Only
//! forgetting the group deletes its rows, with its `device_groups` row.
//! Removing a slot again keeps the first decision. No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_removals (
            group_id_hex TEXT NOT NULL,
            slot_hex TEXT NOT NULL,
            requested_at INTEGER NOT NULL CHECK(requested_at >= 0),
            slot_withdrawn_at INTEGER CHECK(slot_withdrawn_at IS NULL OR slot_withdrawn_at >= 0),
            PRIMARY KEY (group_id_hex, slot_hex)
        );",
    )
    .storage()
}
