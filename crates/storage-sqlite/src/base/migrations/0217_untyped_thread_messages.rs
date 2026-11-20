//! Project stored kind-1111 thread messages that carry a lowercase `e` but no
//! numeric `k` as comments. White Noise Linux sent its thread messages that
//! way until 2026-11-17, and schema 208 left them as custom events.
use super::migration_0208_nip22_comments::repair_comments;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Rows with a numeric k were projected by schema 208 and since then by
    // the live projector; only the e-only form is new here.
    repair_comments(tx, |tags| {
        let named = |name: &str| {
            tags.iter()
                .any(|tag| tag.first().is_some_and(|n| n == name))
        };
        let numeric_k = tags.iter().any(|tag| {
            tag.first().is_some_and(|name| name == "k")
                && tag.get(1).is_some_and(|kind| kind.parse::<u64>().is_ok())
        });
        named("e") && !numeric_k
    })
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;
    use serde_json::{Value, json};

    #[test]
    fn e_only_thread_messages_become_comments() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 216).unwrap();
        conn.execute_batch(r#"
            INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('11', 'fixture', 0);
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,source_epoch,recorded_at,received_at)
            VALUES ('11','linux-text','received','alice','original',1111,'[["e","root"]]',NULL,1,1),
                   ('11','linux-media','received','alice','',1111,'[["e","root"],["imeta","v encrypted-media-v1","url a"]]',7,1,1),
                   ('11','scope-only','received','alice','custom',1111,'[["E","root"],["q","quote"]]',NULL,1,1),
                   ('11','typed','received','alice','typed',1111,'[["e","root"],["k","9"]]',NULL,1,1),
                   ('11','edit','received','alice','edited',1009,'[["e","linux-text"]]',NULL,2,2);
            UPDATE app_events SET source_message_id_hex='source-'||message_id_hex;
            INSERT INTO message_modifier_edges(group_id_hex,modifier_message_id_hex,target_message_id_hex,kind,sender,recorded_at)
            VALUES ('11','edit','linux-text',1009,'alice',2);
            INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json)
            SELECT group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,
                   recorded_at,received_at,'{"by_emoji":{},"user_reactions":[]}'
            FROM app_events WHERE kind = 1111;
            UPDATE message_timeline SET reply_to_message_id_hex='kept' WHERE message_id_hex='typed';
            CREATE TEMP TABLE untouched AS SELECT * FROM message_timeline
                WHERE message_id_hex IN ('scope-only','typed');
        "#).unwrap();

        run_through(&mut conn, 217).unwrap();

        let row = |id: &str| -> (String, Option<String>, Option<String>, Option<String>) {
            conn.query_row(
                "SELECT plaintext,reply_to_message_id_hex,media_json,edit_json
                 FROM message_timeline WHERE message_id_hex=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
        };
        let text = row("linux-text");
        assert_eq!(
            (text.0.as_str(), text.1.as_deref()),
            ("edited", Some("root"))
        );
        assert_eq!(
            serde_json::from_str::<Value>(&text.3.unwrap()).unwrap(),
            json!({"edit_count":1,"latest_edit_message_id_hex":"edit","edited_at":2})
        );
        let media = row("linux-media");
        assert_eq!(media.1.as_deref(), Some("root"));
        assert_eq!(
            serde_json::from_str::<Value>(&media.2.unwrap()).unwrap(),
            json!({"imeta":[["imeta","v encrypted-media-v1","url a"]]})
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM encrypted_media_epoch_secret_references
                 WHERE message_id_hex='linux-media' AND source_epoch=7",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM attachment_history WHERE message_id_hex='linux-media'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM (SELECT * FROM untouched EXCEPT SELECT * FROM message_timeline)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "comments without e, and comments schema 208 already owned, stay as they were"
        );
    }
}
