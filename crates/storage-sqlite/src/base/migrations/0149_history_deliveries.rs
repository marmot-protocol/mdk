//! Migration 0149: sealed history deliveries between this account's devices
//! (mdk#2628 item 4.2b, D76).
//!
//! - `cgka_sibling_adds`: on the sending device, one row per group and sibling
//!   slot that one of this device's own confirmed Commits added. The engine
//!   writes it in the transaction that confirms the Commit and never reads
//!   it; no snapshot or replay fingerprint covers it, so a branch-selection
//!   rewind keeps it. `added_at` is in seconds. The app turns each row into
//!   an owed history and deletes it; a row left a week goes, and deleting the
//!   group deletes its rows.
//! - `history_deliveries_owed`: on the sending device, one row per chat and
//!   receiving sibling whose history this device owes it. A chat is its MLS
//!   group id as hex, a sibling its slot as hex. `owed_at` is when it became
//!   owed, in seconds, and the row goes a week later. `sent_at` is NULL while
//!   the history is still to be sent, and set once every delivery reached a
//!   relay.
//! - `history_deliveries_parked`: on the receiving device, each delivery read
//!   before this device holds its chat, kept until it does. One row per
//!   delivery's app event id, with the chat, the sending sibling's slot, the
//!   sealed key and hash as received (opened again at import), and the bundle
//!   ciphertext. `received_at` is in seconds; a row goes a week later, and
//!   all but the newest 1,024 go.
//! - `history_delivery_sends`: on the sending device, the chat and receiving
//!   sibling of each delivery it sent, by the delivery's app event id, so a
//!   delivery branch selection withdraws makes its history owed again.
//!   `recorded_at` is in seconds; a row goes a week later.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_sibling_adds (
            group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
            slot BLOB NOT NULL CHECK(length(slot) = 32),
            added_at INTEGER NOT NULL CHECK(added_at >= 0),
            PRIMARY KEY (group_id, slot)
        ) WITHOUT ROWID;
        CREATE TABLE history_deliveries_owed (
            group_id_hex TEXT NOT NULL,
            receiver_slot_hex TEXT NOT NULL,
            owed_at INTEGER NOT NULL CHECK(owed_at >= 0),
            sent_at INTEGER CHECK(sent_at IS NULL OR sent_at >= 0),
            PRIMARY KEY (group_id_hex, receiver_slot_hex)
        ) WITHOUT ROWID;
        CREATE TABLE history_deliveries_parked (
            app_event_id TEXT PRIMARY KEY NOT NULL,
            group_id_hex TEXT NOT NULL,
            sender_slot_hex TEXT NOT NULL,
            sealed BLOB NOT NULL,
            bundle BLOB NOT NULL,
            received_at INTEGER NOT NULL CHECK(received_at >= 0)
        );
        CREATE INDEX history_deliveries_parked_group
            ON history_deliveries_parked(group_id_hex);
        CREATE TABLE history_delivery_sends (
            app_event_id TEXT PRIMARY KEY NOT NULL,
            group_id_hex TEXT NOT NULL,
            receiver_slot_hex TEXT NOT NULL,
            recorded_at INTEGER NOT NULL CHECK(recorded_at >= 0)
        );",
    )
    .storage()
}
