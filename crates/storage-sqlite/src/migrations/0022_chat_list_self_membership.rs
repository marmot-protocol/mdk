use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Denormalize the local account's per-group membership into the chat-list
    // projection so a single-table row read can surface whether the account is
    // an active member, left voluntarily, or was removed — without a join.
    //
    // The source of truth stays `account_groups.self_membership`; this column
    // is a materialized copy refreshed by `rebuild_chat_list_row_for_group_tx`.
    // Existing rows default to 'member' here, which is correct for still-joined
    // groups and harmless otherwise: the open-path freshness check treats a row
    // whose membership drifts from `account_groups` as stale and rebuilds it
    // (see `chat_list_projection_complete_tx`), so any group the account had
    // already left / been removed from before upgrading is corrected on the
    // next open.
    tx.execute_batch(
        r#"
ALTER TABLE chat_list_rows ADD COLUMN self_membership TEXT NOT NULL DEFAULT 'member';
"#,
    )
    .storage()
}
