use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS encrypted_media_epoch_secrets (
    group_id_hex TEXT NOT NULL,
    component_id INTEGER NOT NULL,
    source_epoch INTEGER NOT NULL,
    secret BLOB NOT NULL,
    created_at_unix_seconds INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, component_id, source_epoch)
);
"#,
    )
    .storage()
}
