use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
CREATE TABLE attachment_history_versions (
    group_id_hex TEXT PRIMARY KEY,
    generation BLOB NOT NULL DEFAULT (randomblob(16)),
    revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE attachment_history (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL,
    attachment_order INTEGER GENERATED ALWAYS AS (-attachment_index) VIRTUAL,
    source_message_id_hex TEXT NOT NULL,
    source_epoch INTEGER,
    sender TEXT NOT NULL,
    timeline_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    order_class INTEGER NOT NULL,
    order_primary INTEGER NOT NULL,
    order_phase INTEGER NOT NULL,
    order_at INTEGER NOT NULL,
    slot_json TEXT NOT NULL,
    visible INTEGER NOT NULL,
    PRIMARY KEY(group_id_hex,message_id_hex,attachment_index)
);
CREATE INDEX idx_attachment_history_page ON attachment_history(
    group_id_hex,order_class,order_primary,order_phase,order_at,message_id_hex,attachment_order
) WHERE visible=1;
CREATE INDEX idx_attachment_history_sender ON attachment_history(sender);

-- Only the derived slot is copied, never the whole album or message body. CASE
-- is deliberately lazy: retention wipes may replace media_json with zero bytes.
-- Corrupt containers become one null slot, retaining the parser's diagnostic.
CREATE VIEW attachment_history_source AS
SELECT t.group_id_hex,t.message_id_hex,CAST(j.key AS INTEGER) AS attachment_index,
       t.source_message_id_hex,t.source_epoch,t.sender,t.timeline_at,t.received_at,
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
WHERE t.kind=9 AND t.source_message_id_hex IS NOT NULL
  AND t.deleted=0 AND t.invalidation_status IS NULL;

CREATE TRIGGER attachment_history_added AFTER INSERT ON attachment_history BEGIN
    -- Even wholly hidden groups need a version row for a later unblock.
    INSERT INTO attachment_history_versions(group_id_hex,revision) VALUES(NEW.group_id_hex,NEW.visible)
    ON CONFLICT(group_id_hex) DO UPDATE SET revision=revision+NEW.visible;
END;
CREATE TRIGGER attachment_history_removed AFTER DELETE ON attachment_history
WHEN OLD.visible=1 BEGIN
    UPDATE attachment_history_versions SET revision=revision+1 WHERE group_id_hex=OLD.group_id_hex;
END;
CREATE TRIGGER attachment_history_visibility AFTER UPDATE OF visible ON attachment_history
WHEN OLD.visible IS NOT NEW.visible BEGIN
    UPDATE attachment_history_versions SET revision=revision+1 WHERE group_id_hex=NEW.group_id_hex;
END;

INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
    source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
SELECT * FROM attachment_history_source;

CREATE TRIGGER attachment_source_insert AFTER INSERT ON message_timeline
WHEN NEW.kind=9 AND NEW.source_message_id_hex IS NOT NULL AND NEW.media_json IS NOT NULL
 AND NEW.deleted=0 AND NEW.invalidation_status IS NULL BEGIN
    INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
        source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
    SELECT * FROM attachment_history_source WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
END;
CREATE TRIGGER attachment_source_delete AFTER DELETE ON message_timeline
WHEN OLD.media_json IS NOT NULL BEGIN
    DELETE FROM attachment_history WHERE group_id_hex=OLD.group_id_hex AND message_id_hex=OLD.message_id_hex;
END;
CREATE TRIGGER attachment_source_update AFTER UPDATE ON message_timeline
WHEN (OLD.media_json IS NOT NULL OR NEW.media_json IS NOT NULL) AND (
     OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.message_id_hex IS NOT NEW.message_id_hex
  OR OLD.source_message_id_hex IS NOT NEW.source_message_id_hex OR OLD.source_epoch IS NOT NEW.source_epoch
  OR OLD.kind IS NOT NEW.kind OR OLD.deleted IS NOT NEW.deleted
  OR OLD.invalidation_status IS NOT NEW.invalidation_status OR OLD.media_json IS NOT NEW.media_json
  OR OLD.sender IS NOT NEW.sender OR OLD.timeline_at IS NOT NEW.timeline_at OR OLD.received_at IS NOT NEW.received_at)
BEGIN
    DELETE FROM attachment_history WHERE group_id_hex=OLD.group_id_hex AND message_id_hex=OLD.message_id_hex;
    INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
        source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
    SELECT * FROM attachment_history_source WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
END;
CREATE TRIGGER attachment_block_added AFTER INSERT ON user_blocks BEGIN
    UPDATE attachment_history SET visible=0 WHERE sender=NEW.public_key;
END;
CREATE TRIGGER attachment_block_removed AFTER DELETE ON user_blocks BEGIN
    UPDATE attachment_history SET visible=(group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites))
    WHERE sender=OLD.public_key;
END;
CREATE TRIGGER attachment_block_changed AFTER UPDATE OF public_key ON user_blocks BEGIN
    UPDATE attachment_history SET visible=(sender NOT IN (SELECT public_key FROM user_blocks)
        AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites))
    WHERE sender IN (OLD.public_key,NEW.public_key);
END;
CREATE TRIGGER attachment_invite_blocked AFTER INSERT ON blocked_pending_invites BEGIN
    UPDATE attachment_history SET visible=0 WHERE group_id_hex=NEW.group_id_hex;
END;
CREATE TRIGGER attachment_invite_unblocked AFTER DELETE ON blocked_pending_invites BEGIN
    UPDATE attachment_history SET visible=(sender NOT IN (SELECT public_key FROM user_blocks)) WHERE group_id_hex=OLD.group_id_hex;
END;
CREATE TRIGGER attachment_group_deleted AFTER DELETE ON account_groups BEGIN
    -- Snapshot reconciliation may drop account_groups while retaining the
    -- timeline. Preserve that source's index, but fence handles across the group
    -- lifecycle boundary. Ordinary local deletion removes the timeline first.
    UPDATE attachment_history_versions SET generation=randomblob(16),revision=revision+1
    WHERE group_id_hex=OLD.group_id_hex;
    DELETE FROM attachment_history_versions WHERE group_id_hex=OLD.group_id_hex
        AND NOT EXISTS(SELECT 1 FROM attachment_history WHERE group_id_hex=OLD.group_id_hex);
END;
"#).storage()
}
