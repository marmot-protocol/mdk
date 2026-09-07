use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE INDEX IF NOT EXISTS idx_message_timeline_chat_preview
    ON message_timeline (
        group_id_hex,
        CASE
            WHEN direction = 'sent'
             AND invalidation_status = 'local_publish_failed' THEN 0
            WHEN direction = 'sent'
             AND source_message_id_hex IS NULL
             AND invalidation_status IS NULL THEN 2
            ELSE 1
        END DESC,
        timeline_order_class DESC,
        timeline_order_primary DESC,
        timeline_order_phase DESC,
        timeline_order_at DESC,
        message_id_hex DESC
    );

CREATE INDEX IF NOT EXISTS idx_app_events_group_insert_order
    ON app_events (group_id_hex, insert_order DESC);
"#,
    )
    .storage()
}
