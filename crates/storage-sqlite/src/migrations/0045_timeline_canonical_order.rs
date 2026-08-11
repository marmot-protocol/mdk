use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Index the accepted-history timeline order introduced by mdk#1172. Virtual
/// columns keep the SQL definition in one place while deriving it from existing
/// projection columns, so upgrades need no row rewrite or reprojection.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE message_timeline
ADD COLUMN timeline_order_class INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN source_epoch IS NOT NULL THEN 1
        WHEN source_message_id_hex IS NULL
         AND invalidation_status IS NULL THEN 2
        ELSE 0
    END
) VIRTUAL;

ALTER TABLE message_timeline
ADD COLUMN timeline_order_primary INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN source_epoch IS NOT NULL THEN source_epoch
        ELSE timeline_at
    END
) VIRTUAL;

ALTER TABLE message_timeline
ADD COLUMN timeline_order_phase INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN kind = 1210
         AND source_message_id_hex IS NULL
         AND source_epoch IS NOT NULL THEN 0
        ELSE 1
    END
) VIRTUAL;

ALTER TABLE message_timeline
ADD COLUMN timeline_order_at INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN kind = 1210
         AND source_message_id_hex IS NULL
         AND source_epoch IS NOT NULL THEN 0
        ELSE timeline_at
    END
) VIRTUAL;

CREATE INDEX idx_message_timeline_group_canonical_order
    ON message_timeline (
        group_id_hex,
        timeline_order_class,
        timeline_order_primary,
        timeline_order_phase,
        timeline_order_at,
        message_id_hex
    );

ALTER TABLE conversation_read_state
ADD COLUMN last_read_order_class INTEGER;

ALTER TABLE conversation_read_state
ADD COLUMN last_read_order_primary INTEGER;

UPDATE conversation_read_state
SET last_read_order_class = (
        SELECT timeline.timeline_order_class
        FROM message_timeline AS timeline
        WHERE timeline.group_id_hex = conversation_read_state.group_id_hex
          AND timeline.message_id_hex = conversation_read_state.last_read_message_id_hex
    ),
    last_read_order_primary = (
        SELECT timeline.timeline_order_primary
        FROM message_timeline AS timeline
        WHERE timeline.group_id_hex = conversation_read_state.group_id_hex
          AND timeline.message_id_hex = conversation_read_state.last_read_message_id_hex
    )
WHERE last_read_message_id_hex IS NOT NULL;

-- Timeline rows themselves need no rewrite: the canonical key is computed from
-- columns already populated by migration 0009. Chat-list rows do cache latest
-- and unread projections, so force one normal projection rebuild on next open.
UPDATE chat_list_rows
SET updated_at = 0
WHERE EXISTS (
    SELECT 1
    FROM message_timeline AS timeline
    WHERE timeline.group_id_hex = chat_list_rows.group_id_hex
);
"#,
    )
    .storage()
}
