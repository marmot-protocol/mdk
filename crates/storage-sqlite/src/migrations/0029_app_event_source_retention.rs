use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // No backfill: legacy rows keep NULL retention fields and are safe-preserved
    // by sweeps rather than reinterpreted from the current group component.
    tx.execute_batch(
        r#"
ALTER TABLE app_events ADD COLUMN source_retention_secs BLOB;
ALTER TABLE app_events ADD COLUMN expiry_timestamp BLOB;
CREATE INDEX IF NOT EXISTS idx_app_events_group_expiry
    ON app_events(group_id_hex, expiry_timestamp)
    WHERE expiry_timestamp IS NOT NULL;
"#,
    )
    .storage()
}
