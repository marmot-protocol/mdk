use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_released_transport_receipts (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL CHECK (epoch >= 0)
);
CREATE INDEX idx_released_transport_receipts_group
    ON cgka_released_transport_receipts(group_id);
CREATE INDEX idx_transport_reconciliation_event
    ON transport_reconciliation_items(event_id);
"#,
    )
    .storage()
}
