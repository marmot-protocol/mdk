use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
-- SQLite appends rowid, preserving the seen-event recency tie-breaker.
CREATE INDEX idx_seen_events_recency ON seen_events(seen_at);

-- Engine hydration replays pending events across groups in source order.
CREATE INDEX idx_pending_application_events_order
    ON pending_application_events(message_insert_order, message_id);

-- Promotion must skip already-normalized history on every bounded batch.
CREATE INDEX idx_cgka_messages_legacy_order
    ON cgka_messages(insert_order) WHERE storage_format = 1;

-- Retire an epoch across components without scanning every cached epoch.
CREATE INDEX idx_media_secrets_retirement
    ON encrypted_media_epoch_secrets(group_id_hex, source_epoch)
    WHERE retention_managed = 1;

-- Chat projections use text ids; protocol tombstones retain opaque binary ids.
CREATE INDEX idx_disband_tombstones_hex
    ON cgka_disband_tombstones(lower(hex(group_id)));

-- A terminal sweep usually has no unpublished sends among retained history.
CREATE INDEX idx_app_events_pending_sent
    ON app_events(group_id_hex)
    WHERE direction = 'sent' AND source_message_id_hex IS NULL AND invalidated = 0;
"#,
    )
    .storage()
}
