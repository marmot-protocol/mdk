use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE app_events ADD COLUMN sender_device TEXT;
                      ALTER TABLE message_timeline ADD COLUMN sender_device TEXT;",
    )
    .storage()
}
