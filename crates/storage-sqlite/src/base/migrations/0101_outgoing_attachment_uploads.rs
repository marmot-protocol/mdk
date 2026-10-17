//! Protect upload plaintext until a confirmed outgoing source owns it.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Staging and retained bytes share quota accounting and account encryption.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE outgoing_attachment_uploads (
        token BLOB PRIMARY KEY NOT NULL CHECK(length(token)=16),
        group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
        source_epoch INTEGER NOT NULL CHECK(source_epoch>=0),
        plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32),
        bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes)<=536870912),
        slot_json TEXT CHECK(length(slot_json)<=16384),
        quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1)),
        recovery_message_id_hex TEXT NOT NULL DEFAULT '',
        recovery_attachment_index INTEGER NOT NULL DEFAULT -1,
        expires_at INTEGER NOT NULL
    );
    CREATE INDEX idx_attachment_history_outgoing_slot ON attachment_history(group_id_hex,source_epoch,slot_json,message_id_hex,attachment_index);
    CREATE TABLE outgoing_attachment_recovery_cursor (
        id INTEGER PRIMARY KEY CHECK(id=1),
        group_id_hex TEXT NOT NULL DEFAULT '',
        message_id_hex TEXT NOT NULL DEFAULT '',
        upload_token BLOB NOT NULL DEFAULT x''
    );
    INSERT INTO outgoing_attachment_recovery_cursor(id) VALUES(1);
    CREATE INDEX outgoing_attachment_upload_slot ON outgoing_attachment_uploads(group_id_hex,source_epoch,slot_json);
    CREATE INDEX outgoing_attachment_upload_expiry ON outgoing_attachment_uploads(expires_at,token);
    CREATE TABLE outgoing_attachment_upload_owners (
        token BLOB NOT NULL REFERENCES outgoing_attachment_uploads(token) ON DELETE CASCADE,
        group_id_hex TEXT NOT NULL,
        message_id_hex TEXT NOT NULL,
        PRIMARY KEY(token,group_id_hex,message_id_hex),
        FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
    );
    CREATE TRIGGER outgoing_upload_bytes_added AFTER INSERT ON outgoing_attachment_uploads BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count+length(NEW.bytes) WHERE id=1;
    END;
    CREATE TRIGGER outgoing_upload_bytes_changed AFTER UPDATE OF bytes ON outgoing_attachment_uploads BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count-length(OLD.bytes)+length(NEW.bytes) WHERE id=1;
    END;
    CREATE TRIGGER outgoing_upload_bytes_removed AFTER DELETE ON outgoing_attachment_uploads BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count-length(OLD.bytes) WHERE id=1;
    END;") .storage()
}
