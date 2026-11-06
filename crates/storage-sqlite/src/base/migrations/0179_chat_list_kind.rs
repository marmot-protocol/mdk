//! Migration 0179: conversation kind as a chat-list query key (mdk#2983 slice 3).
//!
//! `chat_list_rows.list_kind` holds the conversation kind the chat-list
//! classifier (`app::chat_list::conversation_kind`) derives from the row's
//! `group_name` and its `account_groups.member_count`: 0 Unknown, 1 Direct,
//! 2 Group. Triggers on both inputs keep it current for every writer, as
//! migration 0072's navigation keys are, and existing rows are backfilled here.
//! The classifier stays the owner of the presented row's kind.
//!
//! Migration 0072's navigation-revision triggers are dropped: nothing reads
//! `chat_list_navigation_meta.revision` since cross-read cursors went (#3008).
//! The table stays for `pin_rewrite_in_progress`.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Unicode White_Space, the set Rust `str::trim` removes. Frozen here: a
/// migration never follows a later change to the runtime's constant.
const WHITE_SPACE: &str = "\u{0009}\u{000a}\u{000b}\u{000c}\u{000d}\u{0020}\u{0085}\u{00a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}";

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // A named chat is a group; otherwise two member accounts is direct, any
    // other known count is a group, and an unknown (or invalid) count is
    // Unknown, matching the classifier's `u64::try_from` of the stored value.
    let kind = format!(
        "CASE WHEN trim(chat_list_rows.group_name, '{WHITE_SPACE}') != '' THEN 2
         ELSE COALESCE((SELECT CASE
                 WHEN kind_group.member_count IS NULL OR kind_group.member_count < 0 THEN 0
                 WHEN kind_group.member_count = 2 THEN 1
                 ELSE 2 END
             FROM account_groups AS kind_group
             WHERE kind_group.group_id_hex = chat_list_rows.group_id_hex), 0) END"
    );
    let refresh = format!("UPDATE chat_list_rows SET list_kind = {kind}");
    tx.execute_batch(&format!(
        "DROP TRIGGER chat_list_navigation_changed;
         DROP TRIGGER chat_list_navigation_inserted;
         DROP TRIGGER chat_list_navigation_deleted;
         ALTER TABLE chat_list_rows ADD COLUMN list_kind INTEGER NOT NULL DEFAULT 0
             CHECK(list_kind IN (0, 1, 2));
         {refresh};
         CREATE TRIGGER chat_list_kind_row_inserted AFTER INSERT ON chat_list_rows BEGIN
             {refresh} WHERE group_id_hex = NEW.group_id_hex;
         END;
         CREATE TRIGGER chat_list_kind_row_updated AFTER UPDATE OF group_id_hex, group_name ON chat_list_rows
         WHEN OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.group_name IS NOT NEW.group_name BEGIN
             {refresh} WHERE group_id_hex = NEW.group_id_hex;
         END;
         CREATE TRIGGER chat_list_kind_group_inserted AFTER INSERT ON account_groups BEGIN
             {refresh} WHERE group_id_hex = NEW.group_id_hex;
         END;
         CREATE TRIGGER chat_list_kind_group_updated AFTER UPDATE OF group_id_hex, member_count ON account_groups
         WHEN OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.member_count IS NOT NEW.member_count BEGIN
             {refresh} WHERE group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex);
         END;
         CREATE TRIGGER chat_list_kind_group_deleted AFTER DELETE ON account_groups BEGIN
             {refresh} WHERE group_id_hex = OLD.group_id_hex;
         END;"
    ))
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::params;

    #[test]
    fn existing_rows_get_the_classifier_kind_and_revision_triggers_go() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run_through(&mut conn, 177).unwrap();
        // (id, group name, member count, kind): 0 Unknown, 1 Direct, 2 Group.
        let rows: [(&str, &str, Option<i64>, i64); 7] = [
            ("01", "", None, 0),
            ("02", "", Some(2), 1),
            ("03", "", Some(3), 2),
            ("04", "", Some(1), 2),
            ("05", "\u{3000} \n", Some(2), 1),
            ("06", "Team", Some(2), 2),
            ("07", "Team", None, 2),
        ];
        for (id, name, members, _) in rows {
            conn.execute(
                "INSERT INTO account_groups(group_id_hex, endpoint, updated_at, member_count)
                 VALUES (?1, '', 0, ?2)",
                params![id, members],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chat_list_rows(group_id_hex, updated_at, group_name) VALUES (?1, 0, ?2)",
                params![id, name],
            )
            .unwrap();
        }
        run_through(&mut conn, 179).unwrap();
        for (id, _, _, kind) in rows {
            let stored: i64 = conn
                .query_row(
                    "SELECT list_kind FROM chat_list_rows WHERE group_id_hex = ?1",
                    [id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(stored, kind, "{id}");
        }
        let revision_triggers: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'trigger'
                 AND name LIKE 'chat_list_navigation_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(revision_triggers, 0);
        // The pin-rewrite flag the pin triggers read is still there.
        let rewriting: i64 = conn
            .query_row(
                "SELECT pin_rewrite_in_progress FROM chat_list_navigation_meta",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rewriting, 0);
    }
}
