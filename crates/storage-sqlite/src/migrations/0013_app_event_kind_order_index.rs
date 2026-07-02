use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE INDEX idx_app_events_group_kind_order
    ON app_events (group_id_hex, kind, recorded_at, message_id_hex);
"#,
    )
    .storage()
}
