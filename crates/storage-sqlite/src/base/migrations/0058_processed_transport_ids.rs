use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Keep successfully peeled outer transport ids for the lifetime of their
/// owning protocol group. Unlike `cgka_ingress_dedup`, this table is not a
/// hostile-input cache: callers admit a row only after durable group-content
/// admission, so correctness must not depend on an account-wide FIFO cap.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_processed_transport_ids (
    id       BLOB PRIMARY KEY,
    group_id BLOB NOT NULL
             REFERENCES cgka_groups(id) ON DELETE CASCADE
);
CREATE INDEX idx_cgka_processed_transport_ids_group
    ON cgka_processed_transport_ids (group_id);
"#,
    )
    .storage()
}
