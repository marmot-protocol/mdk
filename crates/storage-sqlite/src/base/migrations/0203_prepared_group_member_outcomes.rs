use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE app_prepared_group_image_upload ADD COLUMN member_outcomes_json TEXT;",
    )
    .storage()
}
