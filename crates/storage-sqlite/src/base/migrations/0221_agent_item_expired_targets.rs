//! Migration 0221: remember the agent items retention removed.
//!
//! A device without an item's first event shows the item from its edits
//! (marmot-agents D-124). Once retention has removed an item, an edit of it
//! that reaches the device later must not show it again, so the sweep records
//! the ids of the item rows it removed.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE agent_item_expired_targets (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE TRIGGER agent_item_expired_targets_group_deleted AFTER DELETE ON account_groups BEGIN
    DELETE FROM agent_item_expired_targets WHERE group_id_hex = OLD.group_id_hex;
END;
"#,
    )
    .storage()
}
