//! The Welcome a new device waits for after a confirmed device link
//! (mdk#2628 D28, D30). One row per device group id; the join that matches it
//! deletes it.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS cgka_device_group_welcome_expectations (
    group_id BLOB PRIMARY KEY,
    record BLOB NOT NULL
);
"#,
    )
    .storage()
}
