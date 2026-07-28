//! Add durable, device-local manual ordering for pinned chats.
//!
//! Pin rows deliberately live outside the rebuildable `chat_list_rows`
//! projection. The account database is scoped to one account-device identity,
//! so this state remains local without entering MLS or transport state.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE chat_pin_positions (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    ordinal INTEGER NOT NULL UNIQUE CHECK (ordinal >= 0),
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);

CREATE INDEX idx_chat_pin_positions_order
    ON chat_pin_positions (ordinal, group_id_hex);

CREATE TRIGGER unpin_chat_when_archived
AFTER UPDATE OF archived ON account_groups
WHEN NEW.archived = 1
BEGIN
    DELETE FROM chat_pin_positions WHERE group_id_hex = NEW.group_id_hex;
END;
"#,
    )
    .storage()
}
