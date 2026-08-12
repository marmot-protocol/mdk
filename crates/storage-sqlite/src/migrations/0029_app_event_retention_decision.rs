use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE app_events ADD COLUMN retention_seconds INTEGER;
ALTER TABLE app_events ADD COLUMN retention_expires_at INTEGER;

CREATE INDEX idx_app_events_group_retention_expiry
ON app_events(group_id_hex, retention_expires_at)
WHERE retention_expires_at IS NOT NULL;
"#,
    )
    .storage()
}
