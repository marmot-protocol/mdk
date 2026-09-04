use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Versioned, display-only direct-peer presentation carried by chat-list rows.
///
/// The peer id binds every cached name/avatar reference to the exact current
/// two-member roster. Projection rebuilds preserve values only while that id
/// remains the remote member; a peer change or Direct-to-Group transition
/// clears the values and records an invalidated state.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE chat_list_rows
    ADD COLUMN direct_peer_presentation_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE chat_list_rows
    ADD COLUMN direct_peer_account_id_hex TEXT;
ALTER TABLE chat_list_rows
    ADD COLUMN direct_peer_display_name TEXT;
ALTER TABLE chat_list_rows
    ADD COLUMN direct_peer_avatar_url TEXT;
ALTER TABLE chat_list_rows
    ADD COLUMN direct_peer_profile_created_at INTEGER;
ALTER TABLE chat_list_rows
    ADD COLUMN direct_peer_presentation_state TEXT NOT NULL DEFAULT 'absent';
"#,
    )
    .storage()
}
