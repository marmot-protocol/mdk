use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE chat_presentation_checkpoint (
        id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL DEFAULT 0
            CHECK(typeof(generation)='integer' AND generation>=0), state BLOB);
        INSERT INTO chat_presentation_checkpoint(id) VALUES(1);
        CREATE TABLE chat_presentation_row_work (
            group_id_hex TEXT PRIMARY KEY REFERENCES account_groups(group_id_hex) ON DELETE CASCADE);
        INSERT INTO chat_presentation_row_work SELECT a.group_id_hex FROM account_groups a
            WHERE NOT EXISTS(SELECT 1 FROM chat_list_rows r WHERE r.group_id_hex=a.group_id_hex);
        CREATE TRIGGER chat_presentation_group_created AFTER INSERT ON account_groups BEGIN
            INSERT OR IGNORE INTO chat_presentation_row_work VALUES(NEW.group_id_hex);
        END;
        CREATE TRIGGER chat_presentation_row_prepared AFTER INSERT ON chat_list_rows BEGIN
            DELETE FROM chat_presentation_row_work WHERE group_id_hex=NEW.group_id_hex;
        END;")
        .storage()
}
