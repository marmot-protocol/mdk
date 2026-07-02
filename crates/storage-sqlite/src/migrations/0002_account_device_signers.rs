use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS cgka_account_device_signers (
    marmot_identity BLOB PRIMARY KEY,
    record BLOB NOT NULL
);
"#,
    )
    .storage()
}
