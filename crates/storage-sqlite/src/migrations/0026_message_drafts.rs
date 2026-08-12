use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE message_drafts (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    reply_to_message_id_hex TEXT
        CHECK (
            reply_to_message_id_hex IS NULL OR (
                length(reply_to_message_id_hex) = 64
                AND reply_to_message_id_hex NOT GLOB '*[^0-9a-f]*'
            )
        ),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);

CREATE TABLE message_draft_attachments (
    group_id_hex TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    attachment_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    plaintext BLOB NOT NULL,
    dim TEXT,
    thumbhash TEXT,
    duration_seconds REAL,
    waveform_samples_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (group_id_hex, position),
    UNIQUE (group_id_hex, attachment_id),
    FOREIGN KEY (group_id_hex) REFERENCES message_drafts(group_id_hex) ON DELETE CASCADE
);
"#,
    )
    .storage()
}
