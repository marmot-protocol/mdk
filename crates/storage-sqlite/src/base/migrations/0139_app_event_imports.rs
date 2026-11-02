//! Migration 0139: app events imported from a sibling's history (mdk#2628 4.2a).
//!
//! One row per imported app event, naming the roster slot of the device that
//! sent it. Imported rows never count as unread, and the rows leave with their
//! app event on retention prune.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_event_imports (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    source_slot BLOB NOT NULL CHECK (length(source_slot) = 32),
    imported_at INTEGER NOT NULL CHECK (imported_at >= 0),
    PRIMARY KEY (group_id_hex, message_id_hex),
    FOREIGN KEY (group_id_hex, message_id_hex)
        REFERENCES app_events (group_id_hex, message_id_hex) ON DELETE CASCADE
) WITHOUT ROWID;
"#,
    )
    .storage()
}
