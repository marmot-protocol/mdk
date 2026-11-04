//! Migration 0173: a peer's reaction settles a locally-sent row (mdk#1291).
//!
//! - `message_timeline` gains `recipient_confirmed`. It is 1 for a failed sent
//!   row with no relay acceptance on record that another account has reacted
//!   to. The reaction proves that peer received the row, so the row is
//!   delivered: its `local_publish_failed` projection is cleared, while
//!   `app_events.invalidation_reason` keeps the raw fact.
//! - `kept_recipient_receipts` holds the sends whose confirming reaction
//!   retention pruned, so they stay delivered. It starts empty and is deleted
//!   with its send.
//! - `idx_message_timeline_chat_preview` is rebuilt so a confirmed row keeps
//!   the rank it had as a failed send instead of ranking as a pending send at
//!   the head of the chat list. `chat_list::preview_rank_sql` spells the same
//!   expression.
//! - Existing failed rows are settled from the reaction senders their projection
//!   already stores in `reactions_json`. Those are the reactions the projector
//!   kept: valid, not invalidated, not retracted, and none on a deleted row.
//!   The chat list notices the changed delivery state and rebuilds on open.
//!
//! Frozen schema-173 transformation: never call the evolving live projector.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE message_timeline
    ADD COLUMN recipient_confirmed INTEGER NOT NULL DEFAULT 0;

CREATE TABLE kept_recipient_receipts (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex),
    FOREIGN KEY (group_id_hex, message_id_hex)
        REFERENCES app_events (group_id_hex, message_id_hex) ON DELETE CASCADE
) WITHOUT ROWID;

DROP INDEX IF EXISTS idx_message_timeline_chat_preview;
CREATE INDEX idx_message_timeline_chat_preview
    ON message_timeline (
        group_id_hex,
        CASE
            WHEN direction = 'sent'
             AND (invalidation_status = 'local_publish_failed'
                  OR recipient_confirmed = 1) THEN 0
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
"#,
    )
    .storage()?;
    settle_recipient_confirmed_sends(tx)
}

/// Settle every stored send a peer has reacted to. Split out so a test can
/// check it against the live projector on the same events.
pub(super) fn settle_recipient_confirmed_sends(tx: &rusqlite::Connection) -> StorageResult<()> {
    tx.execute_batch(
        "UPDATE message_timeline AS t
         SET invalidation_status = NULL,
             recipient_confirmed = 1
         WHERE t.direction = 'sent'
           AND t.deleted = 0
           AND t.source_message_id_hex IS NULL
           AND t.invalidation_status = 'local_publish_failed'
           AND json_valid(t.reactions_json)
           AND EXISTS (
               SELECT 1
               FROM json_each(t.reactions_json, '$.user_reactions') AS reaction
               WHERE json_extract(reaction.value, '$.sender') != t.sender
           );",
    )
    .storage()
}
