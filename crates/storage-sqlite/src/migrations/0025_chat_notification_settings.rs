use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE chat_notification_settings (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    muted_until_ms INTEGER,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
"#,
    )
    .storage()
}
