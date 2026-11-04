//! The finite Made-time device-group move owner (mdk#2628 D102).
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE device_group_moves (
        move_id INTEGER PRIMARY KEY AUTOINCREMENT,
        destination_id BLOB NOT NULL,
        original_id BLOB NOT NULL CHECK(original_id != destination_id),
        original_trust TEXT NOT NULL CHECK(original_trust IN ('created','linked')),
        original_key_package_ref_hex TEXT NOT NULL,
        original_recorded_at INTEGER NOT NULL CHECK(original_recorded_at >= 0),
        sender_signature_key BLOB NOT NULL,
        key_package_ref BLOB NOT NULL,
        expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
        own_slot BLOB NOT NULL CHECK(length(own_slot) = 32),
        siblings BLOB NOT NULL,
        phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 3),
        rejected_slots BLOB
    );
    CREATE UNIQUE INDEX idx_device_group_move_pending ON device_group_moves((1)) WHERE phase IN (0,1);
    CREATE INDEX idx_device_group_move_destination ON device_group_moves(destination_id, move_id);")
    .storage()
}
