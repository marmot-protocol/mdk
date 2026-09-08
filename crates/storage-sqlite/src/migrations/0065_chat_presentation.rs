use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Internal P1 storage only. Profile fanout and native reads land separately.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE chat_list_rows ADD COLUMN presentation_json BLOB;
ALTER TABLE chat_list_rows ADD COLUMN presentation_row_epoch BLOB NOT NULL DEFAULT X'';
UPDATE chat_list_rows SET presentation_row_epoch = randomblob(16);
CREATE TRIGGER chat_presentation_row_created AFTER INSERT ON chat_list_rows BEGIN
    UPDATE chat_list_rows SET presentation_row_epoch = randomblob(16)
        WHERE group_id_hex = NEW.group_id_hex;
END;
ALTER TABLE chat_list_rows ADD COLUMN presentation_source_revision INTEGER NOT NULL DEFAULT 0
    CHECK(typeof(presentation_source_revision) = 'integer' AND presentation_source_revision >= 0);
CREATE INDEX chat_presentation_pending ON chat_list_rows(group_id_hex)
    WHERE presentation_json IS NULL;
CREATE TABLE chat_presentation_meta (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    store_epoch BLOB NOT NULL CHECK(length(store_epoch) = 16),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision) = 'integer' AND revision >= 0)
);
INSERT INTO chat_presentation_meta(id, store_epoch) VALUES(1, randomblob(16));
CREATE TABLE chat_presentation_members (
    group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    member_id_hex TEXT NOT NULL,
    PRIMARY KEY(group_id_hex, member_id_hex)
);
INSERT INTO chat_presentation_members SELECT group_id_hex, member_id_hex FROM direct_conversation_members;
CREATE TABLE chat_presentation_dependencies (
    group_id_hex TEXT NOT NULL REFERENCES chat_list_rows(group_id_hex) ON DELETE CASCADE,
    member_id_hex TEXT NOT NULL,
    roles INTEGER NOT NULL CHECK(roles BETWEEN 1 AND 3),
    PRIMARY KEY(group_id_hex, member_id_hex)
);
CREATE INDEX chat_presentation_by_member
    ON chat_presentation_dependencies(member_id_hex, group_id_hex);
CREATE TRIGGER chat_presentation_value_changed AFTER UPDATE OF presentation_json ON chat_list_rows
WHEN OLD.presentation_json IS NOT NULL AND NEW.presentation_json IS NULL BEGIN
    UPDATE chat_presentation_meta SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER chat_presentation_value_removed AFTER DELETE ON chat_list_rows
WHEN OLD.presentation_json IS NOT NULL BEGIN
    UPDATE chat_presentation_meta SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER chat_presentation_group_changed AFTER UPDATE ON account_groups
WHEN OLD.profile_name IS NOT NEW.profile_name
  OR OLD.member_count IS NOT NEW.member_count
  OR OLD.self_membership IS NOT NEW.self_membership
  OR OLD.image_hash_hex IS NOT NEW.image_hash_hex
  OR OLD.image_key_hex IS NOT NEW.image_key_hex
  OR OLD.image_nonce_hex IS NOT NEW.image_nonce_hex
  OR OLD.image_upload_key_hex IS NOT NEW.image_upload_key_hex
  OR OLD.image_media_type IS NOT NEW.image_media_type
BEGIN
    UPDATE chat_list_rows SET presentation_json = NULL,
        presentation_source_revision = presentation_source_revision + 1
        WHERE group_id_hex = NEW.group_id_hex;
    DELETE FROM chat_presentation_dependencies WHERE group_id_hex = NEW.group_id_hex;
    DELETE FROM chat_presentation_members WHERE group_id_hex = NEW.group_id_hex
        AND (OLD.member_count IS NOT NEW.member_count OR OLD.self_membership IS NOT NEW.self_membership);
END;
"#,
    ).storage()?;
    // Component bytes can carry the group avatar URL independently of the name/image columns.
    for (operation, reference, condition) in [
        ("INSERT", "NEW", "NEW.component_id = 32775"),
        (
            "UPDATE",
            "NEW",
            "NEW.component_id = 32775 AND OLD.component_data_hex IS NOT NEW.component_data_hex",
        ),
        ("DELETE", "OLD", "OLD.component_id = 32775"),
    ] {
        tx.execute_batch(&format!(
            "CREATE TRIGGER chat_presentation_avatar_{operation} AFTER {operation} ON account_group_app_components
             WHEN {condition} BEGIN
                UPDATE chat_list_rows SET presentation_json = NULL,
                    presentation_source_revision = presentation_source_revision + 1
                    WHERE group_id_hex = {reference}.group_id_hex;
                DELETE FROM chat_presentation_dependencies WHERE group_id_hex = {reference}.group_id_hex;
             END;"
        )).storage()?;
    }
    Ok(())
}
