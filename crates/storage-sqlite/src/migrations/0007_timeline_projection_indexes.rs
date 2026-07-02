use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE INDEX idx_message_timeline_group_kind_order
    ON message_timeline (group_id_hex, kind, timeline_at DESC, message_id_hex DESC);

CREATE INDEX idx_message_timeline_group_kind_unread
    ON message_timeline (group_id_hex, kind, deleted, timeline_at, message_id_hex);

CREATE INDEX idx_message_timeline_account_order
    ON message_timeline (timeline_at DESC, message_id_hex DESC);

CREATE INDEX idx_chat_list_rows_order
    ON chat_list_rows (last_message_timeline_at DESC, group_id_hex);
"#,
    )
    .storage()
}
