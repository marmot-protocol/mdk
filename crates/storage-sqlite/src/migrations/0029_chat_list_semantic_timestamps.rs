//! Add durable semantic timestamps for chat-list ordering (#1086).
//!
//! `conversation_created_at` is anchored once on the durable account-group row.
//! Existing rows use the earliest retained app-event time when available, capped
//! by the group's persisted first/last projection timestamp; never-messaged rows
//! use that persisted group timestamp. `activity_sort_at` starts at the latest
//! visible chat timeline time, then falls back to the durable read cursor and
//! finally conversation creation. No migration wall clock participates.

use crate::{SqliteResultExt, u64_to_i64};
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE account_groups
    ADD COLUMN conversation_created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_list_rows
    ADD COLUMN conversation_created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_list_rows
    ADD COLUMN activity_sort_at INTEGER NOT NULL DEFAULT 0;
"#,
    )
    .storage()?;

    tx.execute(
        "UPDATE account_groups AS ag
         SET conversation_created_at = CASE
             WHEN (
                 SELECT MIN(events.recorded_at)
                 FROM app_events AS events
                 WHERE events.group_id_hex = ag.group_id_hex
             ) IS NULL THEN ag.updated_at
             WHEN ag.updated_at = 0 THEN (
                 SELECT MIN(events.recorded_at)
                 FROM app_events AS events
                 WHERE events.group_id_hex = ag.group_id_hex
             )
             ELSE MIN(
                 ag.updated_at,
                 (
                     SELECT MIN(events.recorded_at)
                     FROM app_events AS events
                     WHERE events.group_id_hex = ag.group_id_hex
                 )
             )
         END",
        [],
    )
    .storage()?;

    tx.execute(
        "UPDATE chat_list_rows AS row
         SET conversation_created_at = COALESCE(
                 (
                     SELECT ag.conversation_created_at
                     FROM account_groups AS ag
                     WHERE ag.group_id_hex = row.group_id_hex
                 ),
                 0
             ),
             activity_sort_at = MAX(
                 COALESCE(
                     (
                         SELECT timeline.timeline_at
                         FROM message_timeline AS timeline
                         WHERE timeline.group_id_hex = row.group_id_hex
                           AND timeline.kind = ?1
                           AND timeline.invalidation_status IS NULL
                         ORDER BY timeline.timeline_at DESC, timeline.message_id_hex DESC
                         LIMIT 1
                     ),
                     0
                 ),
                 COALESCE(
                     (
                         SELECT read_state.last_read_timeline_at
                         FROM conversation_read_state AS read_state
                         WHERE read_state.group_id_hex = row.group_id_hex
                     ),
                     0
                 ),
                 COALESCE(
                     (
                         SELECT ag.conversation_created_at
                         FROM account_groups AS ag
                         WHERE ag.group_id_hex = row.group_id_hex
                     ),
                     0
                 )
             )",
        params![u64_to_i64(MARMOT_APP_EVENT_KIND_CHAT)?],
    )
    .storage()?;

    tx.execute_batch(
        r#"
DROP INDEX IF EXISTS idx_chat_list_rows_archived_order;
CREATE INDEX idx_chat_list_rows_archived_activity_order
    ON chat_list_rows (archived, activity_sort_at DESC, group_id_hex);
"#,
    )
    .storage()?;

    Ok(())
}
