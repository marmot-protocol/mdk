use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_epoch_backfill_intents (
    group_id       BLOB PRIMARY KEY
                   REFERENCES cgka_groups(id) ON DELETE CASCADE,
    stalled_epoch  INTEGER NOT NULL CHECK (stalled_epoch >= 0),
    updated_at     INTEGER NOT NULL
);
"#,
    )
    .storage()
}
