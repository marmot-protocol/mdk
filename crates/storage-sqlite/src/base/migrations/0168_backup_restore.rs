//! Migration 0168: private backup catalog and honest history provenance.
//! Existing sibling imports retain their slot; backup imports have no device
//! attribution. Both use the same import mark for retention/unread/media rules.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
-- Keep the table and its dependent views/triggers in place. Replacing only
-- the slot column removes its old NOT NULL constraint without a table rename
-- through an invalid attachment-history schema. All changes share the runner's
-- transaction; existing sibling slots retain their exact bytes.
ALTER TABLE app_event_imports ADD COLUMN sibling_source_slot BLOB
    CHECK (sibling_source_slot IS NULL OR length(sibling_source_slot) = 32);
UPDATE app_event_imports SET sibling_source_slot = source_slot;
ALTER TABLE app_event_imports DROP COLUMN source_slot;
ALTER TABLE app_event_imports RENAME COLUMN sibling_source_slot TO source_slot;
ALTER TABLE app_event_imports ADD COLUMN backup_recovery_key BLOB
    CHECK (backup_recovery_key IS NULL OR length(backup_recovery_key) = 32);
ALTER TABLE app_event_imports ADD COLUMN backup_id BLOB
    CHECK (backup_id IS NULL OR length(backup_id) = 16);
ALTER TABLE app_event_imports ADD COLUMN backup_head_sha256 BLOB
    CHECK (backup_head_sha256 IS NULL OR length(backup_head_sha256) = 32);
ALTER TABLE app_event_imports ADD COLUMN backup_written_at INTEGER
    CHECK (backup_written_at IS NULL OR backup_written_at >= 0)
    CONSTRAINT history_import_source CHECK (
        (source_slot IS NOT NULL AND backup_recovery_key IS NULL AND backup_id IS NULL
            AND backup_head_sha256 IS NULL AND backup_written_at IS NULL)
        OR
        (source_slot IS NULL AND backup_recovery_key IS NOT NULL AND backup_id IS NOT NULL
            AND backup_head_sha256 IS NOT NULL AND backup_written_at IS NOT NULL)
    );

CREATE TABLE backup_restore_catalog (
    recovery_key BLOB NOT NULL CHECK (length(recovery_key) = 32),
    backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
    head_sha256 BLOB NOT NULL CHECK (length(head_sha256) = 32),
    head_server TEXT NOT NULL,
    head_size INTEGER NOT NULL CHECK (head_size > 0 AND head_size <= 8388608),
    written_at INTEGER NOT NULL CHECK (written_at >= 0),
    PRIMARY KEY (recovery_key, backup_id)
) WITHOUT ROWID;
CREATE TABLE backup_restore_catalog_chats (
    recovery_key BLOB NOT NULL,
    backup_id BLOB NOT NULL,
    chat_id BLOB NOT NULL CHECK (length(chat_id) BETWEEN 1 AND 256),
    PRIMARY KEY (recovery_key, backup_id, chat_id),
    FOREIGN KEY (recovery_key, backup_id) REFERENCES backup_restore_catalog
        (recovery_key, backup_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX backup_restore_catalog_by_chat
    ON backup_restore_catalog_chats(chat_id,recovery_key,backup_id);
"#,
    )
    .storage()
}
