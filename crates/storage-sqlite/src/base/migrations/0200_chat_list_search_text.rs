//! Migration 0200: chat-list text search (mdk#2983 slice 4).
//!
//! - `chat_list_rows.search_text` holds the normalized searchable text a
//!   `Text` filter leaf matches: the literal title, group name, description
//!   and a direct chat's peer profile names, written with each presentation
//!   (`store_chat_presentation`).
//! - `chat_presentation_dependencies.roles` gains the search role (4): every
//!   eligible peer is a dependency, so its profile names stay current even
//!   when a group name is the title. The table is rebuilt to widen its CHECK;
//!   the two triggers whose bodies name it are recreated around the rebuild.
//! - A description change now invalidates the row's presentation, as a name
//!   change does, so its search text is rewritten.
//! - Every stored presentation is invalidated once. Rows keep rendering their
//!   last value while the account's presentation worker rewrites them, and a
//!   text query is not ready until it has.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE chat_list_rows ADD COLUMN search_text TEXT NOT NULL DEFAULT '';
DROP TRIGGER chat_presentation_value_changed;
DROP TRIGGER chat_presentation_group_changed;
CREATE TABLE chat_presentation_dependencies_search (
    group_id_hex TEXT NOT NULL REFERENCES chat_list_rows(group_id_hex) ON DELETE CASCADE,
    member_id_hex TEXT NOT NULL,
    roles INTEGER NOT NULL CHECK(roles BETWEEN 1 AND 7),
    PRIMARY KEY(group_id_hex, member_id_hex)
);
INSERT INTO chat_presentation_dependencies_search(group_id_hex, member_id_hex, roles)
    SELECT group_id_hex, member_id_hex, roles FROM chat_presentation_dependencies;
DROP TABLE chat_presentation_dependencies;
ALTER TABLE chat_presentation_dependencies_search RENAME TO chat_presentation_dependencies;
CREATE INDEX chat_presentation_by_member
    ON chat_presentation_dependencies(member_id_hex, group_id_hex);
CREATE TRIGGER chat_presentation_value_changed AFTER UPDATE OF presentation_json ON chat_list_rows
WHEN OLD.presentation_json IS NOT NULL AND NEW.presentation_json IS NULL BEGIN
    UPDATE chat_presentation_meta SET revision = revision + 1 WHERE id = 1;
    DELETE FROM chat_presentation_dependencies WHERE group_id_hex = NEW.group_id_hex;
END;
CREATE TRIGGER chat_presentation_group_changed AFTER UPDATE ON account_groups
WHEN OLD.profile_name IS NOT NEW.profile_name
  OR OLD.profile_description IS NOT NEW.profile_description
  OR OLD.member_count IS NOT NEW.member_count
  OR OLD.self_membership IS NOT NEW.self_membership
  OR OLD.image_hash_hex IS NOT NEW.image_hash_hex
  OR OLD.image_key_hex IS NOT NEW.image_key_hex
  OR OLD.image_nonce_hex IS NOT NEW.image_nonce_hex
  OR OLD.image_upload_key_hex IS NOT NEW.image_upload_key_hex
  OR OLD.image_media_type IS NOT NEW.image_media_type
BEGIN
    UPDATE chat_list_rows SET presentation_json = CASE
            WHEN OLD.member_count IS NOT NEW.member_count OR OLD.self_membership IS NOT NEW.self_membership
              OR (trim(OLD.profile_name) != '' AND trim(NEW.profile_name) = '')
              OR (OLD.image_hash_hex != '' AND coalesce(NEW.image_hash_hex, '') = '')
              OR (OLD.image_key_hex != '' AND coalesce(NEW.image_key_hex, '') = '')
              OR (OLD.image_nonce_hex != '' AND coalesce(NEW.image_nonce_hex, '') = '')
              OR (OLD.image_upload_key_hex != '' AND coalesce(NEW.image_upload_key_hex, '') = '')
            THEN NULL ELSE presentation_json END,
        presentation_source_revision = presentation_source_revision + 1
        WHERE group_id_hex = NEW.group_id_hex;
    DELETE FROM chat_presentation_dependencies WHERE group_id_hex = NEW.group_id_hex
        AND (OLD.member_count IS NOT NEW.member_count OR OLD.self_membership IS NOT NEW.self_membership);
    DELETE FROM chat_presentation_members WHERE group_id_hex = NEW.group_id_hex
        AND (OLD.member_count IS NOT NEW.member_count OR OLD.self_membership IS NOT NEW.self_membership);
END;
UPDATE chat_list_rows SET presentation_source_revision = presentation_source_revision + 1
    WHERE presentation_json IS NOT NULL;
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::{Connection, params};

    fn pending(conn: &Connection, group: &str) -> bool {
        conn.query_row(
            "SELECT presentation_applied_source_revision != presentation_source_revision
             FROM chat_list_rows WHERE group_id_hex = ?1",
            [group],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn stored_presentations_are_redone_and_descriptions_invalidate() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 199).unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('01', '', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows(group_id_hex, updated_at, presentation_json,
                 presentation_applied_source_revision)
             VALUES ('01', 0, X'7b7d', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_presentation_dependencies(group_id_hex, member_id_hex, roles)
             VALUES ('01', ?1, 3)",
            ["aa".repeat(32)],
        )
        .unwrap();
        assert!(!pending(&conn, "01"));
        run_through(&mut conn, 200).unwrap();
        // The search column is filled when the worker re-prepares the row.
        assert!(pending(&conn, "01"));
        let roles: i64 = conn
            .query_row(
                "SELECT roles FROM chat_presentation_dependencies WHERE group_id_hex = '01'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(roles, 3, "dependencies survive the rebuild");
        conn.execute(
            "UPDATE chat_presentation_dependencies SET roles = 7 WHERE group_id_hex = '01'",
            [],
        )
        .unwrap();

        conn.execute(
            "UPDATE chat_list_rows SET presentation_applied_source_revision = presentation_source_revision",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE account_groups SET profile_description = ?1 WHERE group_id_hex = '01'",
            params!["About us"],
        )
        .unwrap();
        assert!(pending(&conn, "01"));
        // Only a membership change drops the selected value or its dependencies.
        let kept: (bool, i64) = conn
            .query_row(
                "SELECT presentation_json IS NOT NULL,
                        (SELECT count(*) FROM chat_presentation_dependencies)
                 FROM chat_list_rows WHERE group_id_hex = '01'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(kept, (true, 1));
    }
}
