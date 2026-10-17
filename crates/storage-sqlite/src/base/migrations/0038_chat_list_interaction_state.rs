//! Add durable local interaction state needed by the app chat list.
//!
//! Manual unread is independent of the monotonic message read marker.
//! `member_count` is a restart-safe local projection used to classify current
//! direct versus group conversations without hydrating every group on read.
//! Latest-message media JSON and delivery state remain projections of the
//! durable timeline row, never independent sources of truth.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE conversation_read_state
    ADD COLUMN manually_marked_unread INTEGER NOT NULL DEFAULT 0;
ALTER TABLE account_groups
    ADD COLUMN member_count INTEGER;
ALTER TABLE chat_list_rows
    ADD COLUMN manually_marked_unread INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_list_rows
    ADD COLUMN last_message_media_json TEXT;
ALTER TABLE chat_list_rows
    ADD COLUMN last_message_delivery_state TEXT NOT NULL DEFAULT 'not_applicable';
"#,
    )
    .storage()?;

    // Force the normal warm-up reconciliation to rebuild every materialized
    // row from the timeline and read-state sources. Existing rows otherwise
    // have valid old `updated_at` values but migration-default media/delivery
    // fields.
    tx.execute(
        "UPDATE chat_list_projection_meta
         SET mention_counts_version = 0
         WHERE id = 1",
        [],
    )
    .storage()?;
    Ok(())
}
