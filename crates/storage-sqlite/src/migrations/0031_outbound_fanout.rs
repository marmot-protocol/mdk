use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_outbound_fanout (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id BLOB NOT NULL UNIQUE,
    group_id BLOB,
    record BLOB NOT NULL,
    FOREIGN KEY(group_id) REFERENCES cgka_groups(id) ON DELETE CASCADE
);

CREATE INDEX idx_cgka_outbound_fanout_group
    ON cgka_outbound_fanout(group_id, insert_order);
"#,
    )
    .storage()
}
