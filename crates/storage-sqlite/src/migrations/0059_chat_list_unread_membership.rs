use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Materialize unread membership so projecting one new message does not scan
/// and reclassify the entire unread window.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE chat_list_unread_messages (
    group_id_hex           TEXT NOT NULL
                           REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    message_id_hex         TEXT NOT NULL,
    mentions_local         INTEGER NOT NULL CHECK (mentions_local IN (0, 1)),
    timeline_order_class   INTEGER NOT NULL,
    timeline_order_primary INTEGER NOT NULL,
    timeline_order_phase   INTEGER NOT NULL,
    timeline_order_at      INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE INDEX idx_chat_list_unread_messages_first
    ON chat_list_unread_messages (
        group_id_hex,
        timeline_order_class,
        timeline_order_primary,
        timeline_order_phase,
        timeline_order_at,
        message_id_hex
    );

CREATE TABLE chat_list_unread_dirty_groups (
    group_id_hex TEXT PRIMARY KEY
                 REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
INSERT INTO chat_list_unread_dirty_groups (group_id_hex)
SELECT group_id_hex FROM account_groups;

CREATE TRIGGER chat_list_unread_dirty_after_timeline_insert
AFTER INSERT ON message_timeline
BEGIN
    INSERT INTO chat_list_unread_dirty_groups (group_id_hex)
    SELECT NEW.group_id_hex
    WHERE EXISTS (
        SELECT 1 FROM account_groups WHERE group_id_hex = NEW.group_id_hex
    )
    ON CONFLICT(group_id_hex) DO NOTHING;
END;
CREATE TRIGGER chat_list_unread_dirty_after_timeline_update
AFTER UPDATE ON message_timeline
BEGIN
    INSERT INTO chat_list_unread_dirty_groups (group_id_hex)
    SELECT NEW.group_id_hex
    WHERE EXISTS (
        SELECT 1 FROM account_groups WHERE group_id_hex = NEW.group_id_hex
    )
    ON CONFLICT(group_id_hex) DO NOTHING;
END;
CREATE TRIGGER chat_list_unread_dirty_after_timeline_delete
AFTER DELETE ON message_timeline
BEGIN
    INSERT INTO chat_list_unread_dirty_groups (group_id_hex)
    SELECT OLD.group_id_hex
    WHERE EXISTS (
        SELECT 1 FROM account_groups WHERE group_id_hex = OLD.group_id_hex
    )
    ON CONFLICT(group_id_hex) DO NOTHING;
END;

-- Force one authoritative rebuild to seed the new derived projection.
UPDATE chat_list_projection_meta
SET mention_counts_version = 0
WHERE id = 1;
"#,
    )
    .storage()
}
