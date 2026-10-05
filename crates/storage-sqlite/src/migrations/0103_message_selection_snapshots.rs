use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Selection ids live in the encrypted account database, not SQLite's in-memory temp store.
/// They are transient application state and are removed when the selection is released.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE message_selection_snapshots (
            token TEXT PRIMARY KEY,
            group_id_hex TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            selected_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE message_selection_snapshot_items (
            token TEXT NOT NULL REFERENCES message_selection_snapshots(token) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            message_id_hex TEXT NOT NULL,
            PRIMARY KEY (token, ordinal),
            UNIQUE (token, message_id_hex)
        );",
    )
    .storage()
}
