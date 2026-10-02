//! Migration 0102: per-group hold on epoch advancement while known history is
//! still being acquired (mdk#2086).

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_history_acquisition_holds (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    transport_group_id BLOB NOT NULL
        CHECK(typeof(transport_group_id) = 'blob' AND length(transport_group_id) = 32),
    PRIMARY KEY(group_id, transport_group_id)
);
"#,
    )
    .storage()
}
