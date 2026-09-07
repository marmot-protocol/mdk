use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// The intent behind each own commit this device stages, retained until the
/// commit is confirmed or rolled back so a supersession by convergence can
/// re-issue it against the canonical state (mdk#1734).
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_own_commit_intents (
    commit_id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE INDEX cgka_own_commit_intents_group_idx
    ON cgka_own_commit_intents (group_id, insert_order);
"#,
    )
    .storage()
}
