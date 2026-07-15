use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE app_events ADD COLUMN moderation_grant INTEGER NOT NULL DEFAULT 0;
"#,
    )
    .storage()
}
