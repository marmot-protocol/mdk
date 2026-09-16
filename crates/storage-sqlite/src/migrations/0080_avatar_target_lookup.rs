use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE INDEX IF NOT EXISTS chat_avatar_target_lookup ON chat_list_rows(presentation_row_epoch);").storage()
}
