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

    let activity_filter = crate::chat_list::chat_list_activity_filter_sql("accepted.");
    tx.execute(
        &format!(
            "UPDATE chat_list_rows AS row
             SET accepted_activity_insert_order = COALESCE((
                 SELECT MAX(accepted_source.insert_order)
                 FROM message_timeline AS accepted
                 JOIN app_events AS accepted_source
                   ON accepted_source.group_id_hex = accepted.group_id_hex
                  AND accepted_source.message_id_hex = accepted.message_id_hex
                 WHERE accepted.group_id_hex = row.group_id_hex
                   AND {activity_filter}
                   AND accepted.invalidation_status IS NULL
                   AND NOT (
                       accepted.direction = 'sent'
                       AND accepted.source_message_id_hex IS NULL
                   )
             ), 0)"
        ),
        [],
    )
    .storage()?;

    Ok(())
}
