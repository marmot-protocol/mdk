use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE user_blocks (
            public_key TEXT PRIMARY KEY,
            is_private INTEGER NOT NULL CHECK(is_private IN (0, 1)),
            created_at_ms INTEGER NOT NULL
        );
        CREATE TABLE user_block_list (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            revision INTEGER NOT NULL DEFAULT 0,
            event_id TEXT NOT NULL DEFAULT '',
            event_created_at INTEGER NOT NULL DEFAULT 0,
            public_tags TEXT NOT NULL DEFAULT '[]',
            private_tags TEXT NOT NULL DEFAULT '[]',
            unreadable_event_id TEXT NOT NULL DEFAULT '',
            unreadable_event_created_at INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO user_block_list(id) VALUES (1);
        CREATE TABLE user_block_publication (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            target TEXT NOT NULL,
            blocked INTEGER NOT NULL,
            event_json TEXT NOT NULL
        );
        CREATE TABLE blocked_notification_suppressions (group_id TEXT NOT NULL, message_id TEXT NOT NULL, PRIMARY KEY(group_id,message_id));
        CREATE TRIGGER suppress_blocked_notifications AFTER INSERT ON app_events
        WHEN NEW.sender IN (SELECT public_key FROM user_blocks) BEGIN
            INSERT OR IGNORE INTO blocked_notification_suppressions VALUES (NEW.group_id_hex,NEW.message_id_hex);
        END;
        -- Notification identities have no replay target after physical event or
        -- group deletion. Welcome dismissals have no admitted group/event row:
        -- retain their ids for the account lifetime to reject relay replay.
        CREATE TRIGGER prune_blocked_notification AFTER DELETE ON app_events BEGIN
            DELETE FROM blocked_notification_suppressions
            WHERE group_id=OLD.group_id_hex AND message_id=OLD.message_id_hex;
        END;
        CREATE TRIGGER prune_group_blocked_notifications AFTER DELETE ON account_groups BEGIN
            DELETE FROM blocked_notification_suppressions WHERE group_id=OLD.group_id_hex;
        END;
        CREATE TABLE blocked_welcome_dismissals (message_id TEXT PRIMARY KEY);
        CREATE INDEX idx_account_groups_pending_inviter ON account_groups(welcomer_account_id_hex,group_id_hex) WHERE pending_confirmation != 0;
        -- Keep the exclusion set indexed. Navigation and badges must never scan
        -- unrelated account groups to discover that no inviter is blocked.
        CREATE TABLE blocked_pending_invites (group_id_hex TEXT PRIMARY KEY);
        CREATE TRIGGER block_inviter_added AFTER INSERT ON user_blocks BEGIN
            INSERT OR IGNORE INTO blocked_pending_invites
            SELECT group_id_hex FROM account_groups WHERE pending_confirmation != 0 AND welcomer_account_id_hex=NEW.public_key;
        END;
        CREATE TRIGGER block_inviter_removed AFTER DELETE ON user_blocks BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex IN (
                SELECT group_id_hex FROM account_groups WHERE pending_confirmation != 0 AND welcomer_account_id_hex=OLD.public_key);
        END;
        CREATE TRIGGER block_invite_inserted AFTER INSERT ON account_groups BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex=NEW.group_id_hex;
            INSERT OR IGNORE INTO blocked_pending_invites SELECT NEW.group_id_hex
            WHERE NEW.pending_confirmation != 0 AND NEW.welcomer_account_id_hex IN (SELECT public_key FROM user_blocks);
        END;
        CREATE TRIGGER block_invite_updated AFTER UPDATE OF pending_confirmation,welcomer_account_id_hex ON account_groups BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex=OLD.group_id_hex;
            INSERT OR IGNORE INTO blocked_pending_invites SELECT NEW.group_id_hex
            WHERE NEW.pending_confirmation != 0 AND NEW.welcomer_account_id_hex IN (SELECT public_key FROM user_blocks);
        END;
        CREATE TRIGGER block_invite_deleted AFTER DELETE ON account_groups BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex=OLD.group_id_hex;
        END;
        CREATE VIEW visible_message_timeline AS SELECT * FROM message_timeline
            WHERE sender NOT IN (SELECT public_key FROM user_blocks)
            AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites);
        CREATE VIEW visible_chat_list_rows AS SELECT * FROM chat_list_rows
            WHERE group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites);",
    ).storage()
}
