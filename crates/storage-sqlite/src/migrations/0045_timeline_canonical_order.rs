use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Index the accepted-history timeline order introduced by mdk#1172. The key is
/// computed from existing projection columns, so upgraded databases immediately
/// gain canonical ordering without rewriting or re-projecting rows.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE INDEX idx_message_timeline_group_canonical_order
    ON message_timeline (
        group_id_hex,
        (CASE
            WHEN source_epoch IS NOT NULL THEN 1
            WHEN source_message_id_hex IS NULL THEN 2
            ELSE 0
         END),
        (CASE
            WHEN source_epoch IS NOT NULL THEN source_epoch
            ELSE timeline_at
         END),
        (CASE
            WHEN kind = 1210
             AND source_message_id_hex IS NULL
             AND source_epoch IS NOT NULL THEN 0
            ELSE 1
         END),
        (CASE
            WHEN kind = 1210
             AND source_message_id_hex IS NULL
             AND source_epoch IS NOT NULL THEN 0
            ELSE timeline_at
         END),
        message_id_hex
    );

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
