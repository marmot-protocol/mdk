use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_ingress_dedup (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE
);
"#,
    )
    .storage()
}
