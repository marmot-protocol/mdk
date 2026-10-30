//! Migration 0135: private KeyPackages (mdk#2628 item 3.4b).
//!
//! A private KeyPackage is single-use, issued by one device to one sibling in
//! its device group, handed over inside the device group and never published.
//!
//! - `cgka_private_key_packages` is the issuer's side: one row per issued
//!   KeyPackage, a serialized `IssuedPrivateKeyPackage`. The engine writes and
//!   deletes each row in the same transaction as its OpenMLS private bundle.
//! - `private_key_packages_received` is the receiver's side: the KeyPackages a
//!   sibling handed over, keyed by the issuer's slot, until they expire. One
//!   this device used keeps its row with `taken_at` set and its bytes
//!   dropped, so the same KeyPackage handed over again is not kept twice
//!   (mdk#2628 D42).
//! - `private_key_package_requests` holds this device's unmet need from one
//!   sibling and when it last asked, so a request repeats at most once an
//!   hour while the need lasts.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_private_key_packages (
            key_package_ref BLOB PRIMARY KEY NOT NULL,
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            record BLOB NOT NULL
        );
        CREATE TABLE private_key_packages_received (
            key_package_ref_hex TEXT PRIMARY KEY NOT NULL,
            issuer_slot_hex TEXT NOT NULL,
            not_before INTEGER NOT NULL CHECK(not_before >= 0),
            not_after INTEGER NOT NULL CHECK(not_after >= not_before),
            key_package BLOB NOT NULL,
            received_at INTEGER NOT NULL CHECK(received_at >= 0),
            taken_at INTEGER CHECK(taken_at >= 0)
        );
        CREATE INDEX private_key_packages_received_by_issuer
            ON private_key_packages_received (issuer_slot_hex, not_after);
        CREATE TABLE private_key_package_requests (
            issuer_slot_hex TEXT PRIMARY KEY NOT NULL,
            need INTEGER NOT NULL CHECK(need BETWEEN 1 AND 100),
            requested_at INTEGER CHECK(requested_at >= 0)
        );",
    )
    .storage()
}
