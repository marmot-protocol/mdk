use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE chat_list_rows ADD COLUMN unread_mention_count INTEGER NOT NULL DEFAULT 0;
"#,
    )
    .storage()
}
