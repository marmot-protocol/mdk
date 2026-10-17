use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_epoch_stall_evidence (
    group_id              BLOB PRIMARY KEY
                          REFERENCES cgka_groups(id) ON DELETE CASCADE,
    stalled_epoch         INTEGER NOT NULL CHECK (stalled_epoch >= 0),
    fruitless_completions INTEGER NOT NULL CHECK (fruitless_completions >= 0),
    fruitless_reported    INTEGER NOT NULL CHECK (fruitless_reported IN (0, 1)),
    last_arm_at_ms        INTEGER NOT NULL CHECK (last_arm_at_ms >= 0),
    updated_at            INTEGER NOT NULL
);
"#,
    )
    .storage()
}
