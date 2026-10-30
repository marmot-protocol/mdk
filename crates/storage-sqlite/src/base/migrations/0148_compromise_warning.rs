//! Migration 0148: the compromise warning and starting fresh (mdk#2628 item
//! 3.7a, D53 and D54).
//!
//! - `account_compromise_warning_items`: one row per thing the warning
//!   gathers, keyed by its reason and subject: a rejected sign-in by its
//!   slot, a rejected KeyPackage by its `KeyPackageRef`. `reason` is text
//!   with no CHECK, so a later reason needs no migration. `occurred_at` is
//!   when the rejection was made, as its maker wrote it; `recorded_at` is
//!   when this device first gathered it, by its own clock. `seen_at` is NULL
//!   until the user dismisses the warning holding it. A seen row stays (a
//!   rejected KeyPackage until it could no longer be valid), so a rejection
//!   that branch selection drops and restores does not warn again.
//! - `account_compromise_warning_baseline`: at most one row, naming the
//!   device group this device first trusted. It is written in the same
//!   transaction that makes the group trusted, and the rejections in the
//!   roster trusted then count as seen. A group trusted before this
//!   migration has no row, so its first gather is taken instead.
//! - `account_sign_in_baseline.started_fresh_at`: set when the user started
//!   this device without the devices its first check found.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_compromise_warning_items (
            reason TEXT NOT NULL,
            subject TEXT NOT NULL,
            slot_id_hex TEXT NOT NULL,
            occurred_at INTEGER NOT NULL CHECK(occurred_at >= 0),
            recorded_at INTEGER NOT NULL CHECK(recorded_at >= 0),
            seen_at INTEGER CHECK(seen_at IS NULL OR seen_at >= 0),
            PRIMARY KEY (reason, subject)
        ) WITHOUT ROWID;
        CREATE TABLE account_compromise_warning_baseline (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
            device_group_id_hex TEXT NOT NULL,
            taken_at INTEGER NOT NULL CHECK(taken_at >= 0)
        );
        ALTER TABLE account_sign_in_baseline
            ADD COLUMN started_fresh_at INTEGER CHECK(started_fresh_at IS NULL OR started_fresh_at >= 0);",
    )
    .storage()
}
