use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_pending_welcome_delivery (
    message_id_hex TEXT PRIMARY KEY,
    group_id_hex   TEXT NOT NULL,
    recipient_hex  TEXT NOT NULL,
    recorded_at    INTEGER NOT NULL
);
CREATE INDEX app_pending_welcome_delivery_group_idx
    ON app_pending_welcome_delivery (group_id_hex);
"#,
    )
    .storage()
}
