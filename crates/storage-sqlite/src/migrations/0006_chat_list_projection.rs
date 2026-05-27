use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE conversation_read_state (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    last_read_message_id_hex TEXT,
    last_read_timeline_at INTEGER,
    initialized_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);

CREATE TABLE chat_list_rows (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0,
    pending_confirmation INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    group_name TEXT NOT NULL DEFAULT '',
    avatar_image_hash_hex TEXT NOT NULL DEFAULT '',
    avatar_image_key_hex TEXT NOT NULL DEFAULT '',
    avatar_image_nonce_hex TEXT NOT NULL DEFAULT '',
    avatar_image_upload_key_hex TEXT NOT NULL DEFAULT '',
    avatar_media_type TEXT,
    last_message_id_hex TEXT,
    last_message_sender TEXT,
    last_message_preview TEXT,
    last_message_kind INTEGER,
    last_message_timeline_at INTEGER,
    last_message_deleted INTEGER NOT NULL DEFAULT 0,
    unread_count INTEGER NOT NULL DEFAULT 0,
    first_unread_message_id_hex TEXT,
    last_read_message_id_hex TEXT,
    last_read_timeline_at INTEGER,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);

CREATE INDEX idx_chat_list_rows_archived_order
    ON chat_list_rows (archived, last_message_timeline_at DESC, group_id_hex);
"#,
    )
    .storage()
}
