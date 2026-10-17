use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE app_events ADD COLUMN source_epoch INTEGER;
ALTER TABLE message_timeline ADD COLUMN source_epoch INTEGER;
"#,
    )
    .storage()
}
