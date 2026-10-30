//! Migration 0131: the account's sign-ins this device does not recognize
//! (mdk#2628 item 3.2).
//!
//! - `account_sign_ins`: one row per KeyPackage slot of this account that this
//!   device found fresh and valid, outside its own slot and outside the
//!   device group's roster.
//!   - `before_this_device` is 1 when this device's first check returned its
//!     slot, whether or not the slot counted then: a device that was there
//!     before this one. Every other slot is a new sign-in.
//!   - `appeared_at` is the earliest publication time this device saw in the
//!     slot, never later than when it first saw it; `last_published_at` is the
//!     newest. The KeyPackage columns name the newest publication.
//!   - `signed_in` is 0 once a complete read found no valid publication in
//!     the slot, fresh or not; only a complete read sets it again.
//!   - `answer` is this device's: `none`, `not_now`, `rejected` or
//!     `dismissed`. A rejection names the slot alone, and `roster_pending` is
//!     1 until the device group's roster records it.
//! - `account_sign_in_baseline`: at most one row, written by this device's
//!   first check.
//! - `account_sign_in_baseline_slots`: every slot that first check's read
//!   returned.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_sign_ins (
            slot_id_hex TEXT PRIMARY KEY NOT NULL,
            before_this_device INTEGER NOT NULL CHECK(before_this_device IN (0, 1)),
            client TEXT NOT NULL,
            appeared_at INTEGER NOT NULL CHECK(appeared_at >= 0),
            last_published_at INTEGER NOT NULL CHECK(last_published_at >= 0),
            key_package_event_id_hex TEXT NOT NULL,
            key_package_ref_hex TEXT NOT NULL,
            signed_in INTEGER NOT NULL CHECK(signed_in IN (0, 1)),
            answer TEXT NOT NULL CHECK(answer IN ('none', 'not_now', 'rejected', 'dismissed')),
            answered_at INTEGER CHECK(answered_at IS NULL OR answered_at >= 0),
            roster_pending INTEGER NOT NULL CHECK(roster_pending IN (0, 1)),
            CHECK((answer = 'none') = (answered_at IS NULL)),
            CHECK(roster_pending = 0 OR answer = 'rejected')
        );
        CREATE TABLE account_sign_in_baseline (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
            taken_at INTEGER NOT NULL CHECK(taken_at >= 0)
        );
        CREATE TABLE account_sign_in_baseline_slots (
            slot_id_hex TEXT PRIMARY KEY NOT NULL
        ) WITHOUT ROWID;",
    )
    .storage()
}
