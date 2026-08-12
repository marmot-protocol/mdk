use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_group_state_checkpoints (
    group_id BLOB NOT NULL,
    checkpoint_id TEXT NOT NULL,
    resulting_epoch INTEGER NOT NULL,
    checkpoint BLOB NOT NULL,
    PRIMARY KEY (group_id, checkpoint_id),
    FOREIGN KEY (group_id) REFERENCES cgka_groups(id) ON DELETE CASCADE
);

CREATE INDEX idx_cgka_group_state_checkpoints_epoch
    ON cgka_group_state_checkpoints(group_id, resulting_epoch);
"#,
    )
    .storage()
}
