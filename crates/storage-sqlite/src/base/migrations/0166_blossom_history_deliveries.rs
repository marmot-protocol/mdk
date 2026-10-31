//! Migration 0166: history deliveries through Blossom (mdk#2628 item 4.2c,
//! D77).
//!
//! - `history_deliveries_owed` gains `blossom_due_at` and `blossom_attempts`.
//!   `blossom_due_at` is NULL while a history goes inline; once it is too
//!   long for inline deliveries, it is when the sender next uploads it, in
//!   seconds. `blossom_attempts` counts failed uploads, for backoff. Owing a
//!   history afresh clears both.
//! - `history_deliveries_parked` is rebuilt so a delivery parks either its
//!   inline `bundle` or the `blossom` servers that hold it, newline-separated,
//!   never both. A Blossom delivery is fetched from `fetch_due_at`, in
//!   seconds, and `fetch_attempts` counts failed fetches, for backoff. Parked
//!   rows keep their order.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE history_deliveries_owed ADD COLUMN blossom_due_at INTEGER
            CHECK(blossom_due_at IS NULL OR blossom_due_at >= 0);
        ALTER TABLE history_deliveries_owed ADD COLUMN blossom_attempts INTEGER NOT NULL
            DEFAULT 0 CHECK(blossom_attempts >= 0);
        CREATE TABLE history_deliveries_parked_0166 (
            app_event_id TEXT PRIMARY KEY NOT NULL,
            group_id_hex TEXT NOT NULL,
            sender_slot_hex TEXT NOT NULL,
            sealed BLOB NOT NULL,
            bundle BLOB,
            blossom TEXT,
            received_at INTEGER NOT NULL CHECK(received_at >= 0),
            fetch_due_at INTEGER CHECK(fetch_due_at IS NULL OR fetch_due_at >= 0),
            fetch_attempts INTEGER NOT NULL DEFAULT 0 CHECK(fetch_attempts >= 0),
            CHECK((bundle IS NULL) <> (blossom IS NULL)),
            CHECK((blossom IS NULL) = (fetch_due_at IS NULL))
        );
        INSERT INTO history_deliveries_parked_0166
            (app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at)
        SELECT app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at
        FROM history_deliveries_parked ORDER BY rowid;
        DROP TABLE history_deliveries_parked;
        ALTER TABLE history_deliveries_parked_0166 RENAME TO history_deliveries_parked;
        CREATE INDEX history_deliveries_parked_group
            ON history_deliveries_parked(group_id_hex);",
    )
    .storage()
}
