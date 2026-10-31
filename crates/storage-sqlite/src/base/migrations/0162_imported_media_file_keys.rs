//! Migration 0162: attachment keys imported from a sibling's history
//! (mdk#2628 4.2a).
//!
//! - `imported_media_file_keys`: one per-file attachment key per imported chat
//!   message and media reference, named by the reference's
//!   `ciphertext_sha256`. This device was never in the epoch the message was
//!   sent in, so it cannot derive the key; the sibling sent it. Rows leave with
//!   their app event, and a trigger zeroes each key before its app event goes.
//! - `attachment_history_source` now also takes a chat message without a
//!   transport id when `app_event_imports` marks it as imported, so imported
//!   messages get attachment slots. Such a row uses its app event id in the
//!   attachment tables' `source_message_id_hex`, which is `NOT NULL` there;
//!   nothing reads that column back as a transport id. The insert trigger
//!   takes the same rows, so a timeline rebuild keeps their slots. On the
//!   first insert the import has not written its mark yet, so the import adds
//!   those slots itself; slots for messages already imported are added here.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE imported_media_file_keys (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL CHECK (length(ciphertext_sha256) = 64),
    file_key BLOB NOT NULL CHECK (length(file_key) = 32),
    PRIMARY KEY (group_id_hex, message_id_hex, ciphertext_sha256),
    FOREIGN KEY (group_id_hex, message_id_hex)
        REFERENCES app_events (group_id_hex, message_id_hex) ON DELETE CASCADE
);
-- Download looks a key up by the media reference alone.
CREATE INDEX idx_imported_media_file_keys_ciphertext
    ON imported_media_file_keys (group_id_hex, ciphertext_sha256);
-- The cascade deletes key rows; zero their bytes first, as epoch secrets are.
CREATE TRIGGER imported_media_file_keys_scrub BEFORE DELETE ON app_events BEGIN
    UPDATE imported_media_file_keys SET file_key = zeroblob(32)
    WHERE group_id_hex = OLD.group_id_hex AND message_id_hex = OLD.message_id_hex;
END;

DROP TRIGGER attachment_source_insert;
DROP VIEW attachment_history_source;
CREATE VIEW attachment_history_source AS
SELECT t.group_id_hex,t.message_id_hex,CAST(j.key AS INTEGER) AS attachment_index,
       COALESCE(t.source_message_id_hex,t.message_id_hex) AS source_message_id_hex,
       t.source_epoch,t.sender,t.timeline_at,t.received_at,
       t.timeline_order_class AS order_class,t.timeline_order_primary AS order_primary,
       t.timeline_order_phase AS order_phase,t.timeline_order_at AS order_at,
       CASE WHEN j.type IN ('array','object') THEN j.value
            WHEN j.type IN ('true','false') THEN j.type
            ELSE json_quote(j.value) END AS slot_json,
       (t.sender NOT IN (SELECT public_key FROM user_blocks)
        AND t.group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)) AS visible
FROM message_timeline t, json_each(
    CASE WHEN t.media_json IS NULL THEN '[]'
         WHEN NOT json_valid(t.media_json) THEN '[null]'
         WHEN json_type(t.media_json) != 'object' THEN '[null]'
         WHEN json_type(t.media_json,'$.imeta') IS NULL THEN '[]'
         WHEN json_type(t.media_json,'$.imeta') != 'array' THEN '[null]'
         ELSE json_extract(t.media_json,'$.imeta') END
) j
WHERE t.kind=9
  AND (t.source_message_id_hex IS NOT NULL OR EXISTS(
      SELECT 1 FROM app_event_imports i
      WHERE i.group_id_hex=t.group_id_hex AND i.message_id_hex=t.message_id_hex))
  AND t.deleted=0 AND t.invalidation_status IS NULL;

CREATE TRIGGER attachment_source_insert AFTER INSERT ON message_timeline
WHEN NEW.kind=9 AND NEW.media_json IS NOT NULL AND NEW.deleted=0 AND NEW.invalidation_status IS NULL
 AND (NEW.source_message_id_hex IS NOT NULL OR EXISTS(
     SELECT 1 FROM app_event_imports i
     WHERE i.group_id_hex=NEW.group_id_hex AND i.message_id_hex=NEW.message_id_hex)) BEGIN
    INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
        source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
    SELECT * FROM attachment_history_source WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
END;

INSERT OR IGNORE INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
    source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
SELECT s.* FROM attachment_history_source s
JOIN app_event_imports i ON i.group_id_hex=s.group_id_hex AND i.message_id_hex=s.message_id_hex;
"#,
    )
    .storage()
}
