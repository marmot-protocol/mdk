use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE secure_delete_checkpoint_intents (
    operation_kind TEXT NOT NULL,
    scope TEXT NOT NULL,
    intent_nonce BLOB NOT NULL,
    result_json TEXT NOT NULL,
    created_at_unix_seconds INTEGER NOT NULL,
    PRIMARY KEY (operation_kind, scope)
);
"#,
    )
    .storage()
}
