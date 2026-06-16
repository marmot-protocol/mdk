use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE INDEX idx_message_timeline_reply_lookup
    ON message_timeline (group_id_hex, reply_to_message_id_hex, message_id_hex)
    WHERE reply_to_message_id_hex IS NOT NULL;
"#,
    )
    .storage()
}
