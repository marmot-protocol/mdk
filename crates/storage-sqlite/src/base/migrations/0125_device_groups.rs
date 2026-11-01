//! Migration 0125: the device groups this device knows of (mdk#2628 item
//! 3.1).
//!
//! A device group is a hidden group holding only this account's devices. One
//! row per such group, with how this device came to know it. `trust` is one
//! of:
//!
//! - `creating`: this device recorded the id it chose before creating the
//!   group. A restart makes it `created` if the engine holds the group as
//!   this device created it, and drops the row otherwise.
//! - `created`: this device created the group.
//! - `awaiting_welcome`: a confirmed link named the group, and this device
//!   waits for its Welcome.
//! - `linked`: this device joined the group through the Welcome a confirmed
//!   link named.
//! - `untrusted`: this device holds a device group no confirmed link named.
//!   It stays hidden, and nothing acts on its roster.
//!
//! `key_package_ref_hex` is the confirmed `KeyPackageRef` (the added sibling's
//! for `creating` and `created`, this device's own otherwise), NULL only for
//! `untrusted`. No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_groups (
            group_id_hex TEXT PRIMARY KEY NOT NULL,
            trust TEXT NOT NULL CHECK(trust IN (
                'creating', 'created', 'awaiting_welcome', 'linked', 'untrusted'
            )),
            key_package_ref_hex TEXT,
            recorded_at INTEGER NOT NULL CHECK(recorded_at >= 0),
            CHECK((trust = 'untrusted') = (key_package_ref_hex IS NULL))
        );",
    )
    .storage()
}
