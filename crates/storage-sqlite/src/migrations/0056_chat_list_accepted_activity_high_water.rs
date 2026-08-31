//! Persist the accepted-activity insertion boundary used to demote stale
//! optimistic chat previews.
//!
//! Secure plaintext pruning can remove every accepted timeline row newer than
//! an unresolved local send. The insertion-order high-water mark preserves the
//! fact that accepted activity already displaced that pending row, without
//! retaining message content or identifiers.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE chat_list_rows
    ADD COLUMN accepted_activity_insert_order INTEGER NOT NULL DEFAULT 0;
"#,
    )
    .storage()?;

    // Keep the historical v56 activity predicate self-contained. Calling the
    // live chat-list SQL helper here would let a future projection change
    // alter migration results on fresh installs while already-migrated
    // databases retain the old backfill.
    tx.execute_batch(
        r#"
UPDATE chat_list_rows AS row
SET accepted_activity_insert_order = COALESCE((
    SELECT MAX(accepted_source.insert_order)
    FROM message_timeline AS accepted
    JOIN app_events AS accepted_source
      ON accepted_source.group_id_hex = accepted.group_id_hex
     AND accepted_source.message_id_hex = accepted.message_id_hex
    WHERE accepted.group_id_hex = row.group_id_hex
      AND (
          accepted.kind = 9
          OR (
              accepted.kind = 1210
              AND accepted.tags_json IN (
                  '[["system","member_added"]]',
                  '[["system","member_removed"]]',
                  '[["system","member_left"]]',
                  '[["system","admin_added"]]',
                  '[["system","admin_removed"]]'
              )
              AND EXISTS (
                  SELECT 1
                  FROM account_groups AS activity_group
                  WHERE activity_group.group_id_hex = accepted.group_id_hex
                    AND (
                        trim(activity_group.profile_name) != ''
                        OR (
                            activity_group.member_count IS NOT NULL
                            AND activity_group.member_count != 2
                        )
                    )
              )
          )
      )
      AND accepted.invalidation_status IS NULL
      AND NOT (
          accepted.direction = 'sent'
          AND accepted.source_message_id_hex IS NULL
      )
), 0);
"#,
    )
    .storage()?;

    Ok(())
}
