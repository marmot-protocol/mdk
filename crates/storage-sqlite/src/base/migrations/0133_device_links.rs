//! Migration 0133: the links this device approved and how each ended, and
//! the device groups it joined through a link whose first commit has not
//! landed yet (mdk#2628 item 3.3b, D40).
//!
//! `device_links` holds one row per device this device approved adding to
//! the account's device group, keyed by the group and the device's
//! KeyPackage slot. The row is written before the approving commit, so a
//! crash cannot lose it, with the leaf signature key of the KeyPackage the
//! link added. `welcome_id_hex` is the link's Welcome, recorded once the
//! commit made it; NULL until then. `outcome` is one of:
//!
//! - `pending`: the new device has not made its first commit in the device
//!   group yet, and the link's deadline has not passed.
//! - `linked`: that commit, which sets the device's tag signature key in its
//!   roster entry, is on the selected branch. Adding the device to chats
//!   waits for this. A linked link stays linked.
//! - `failed`: the approving commit never landed or lost, or the new device
//!   made no commit by the deadline. While the roster still lists the
//!   device as this device's link, this device owes the commit removing it.
//!
//! `decided_at` is when the outcome was decided, NULL only while pending.
//! Linking a slot again replaces its row.
//!
//! `device_group_joins` holds one row per device group this device joined
//! through a link while its first commit there has not been seen on the
//! selected branch. A device removed from that group while its row is here
//! tells its user that linking failed. No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_links (
            group_id_hex TEXT NOT NULL,
            slot_hex TEXT NOT NULL,
            key_package_ref_hex TEXT NOT NULL,
            leaf_signature_key_hex TEXT NOT NULL,
            welcome_id_hex TEXT,
            linked_at INTEGER NOT NULL CHECK(linked_at >= 0),
            outcome TEXT NOT NULL CHECK(outcome IN ('pending', 'linked', 'failed')),
            decided_at INTEGER CHECK(decided_at >= 0),
            CHECK((outcome = 'pending') = (decided_at IS NULL)),
            PRIMARY KEY (group_id_hex, slot_hex)
        );
        CREATE TABLE device_group_joins (
            group_id_hex TEXT PRIMARY KEY NOT NULL,
            joined_at INTEGER NOT NULL CHECK(joined_at >= 0)
        );",
    )
    .storage()
}
