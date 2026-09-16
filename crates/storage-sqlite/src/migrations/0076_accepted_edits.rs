use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Frozen schema-76 transformation: never call the evolving live projector.
    tx.execute_batch(r#"
        ALTER TABLE message_timeline ADD COLUMN edit_json TEXT;
        INSERT OR IGNORE INTO message_modifier_edges
            (group_id_hex,modifier_message_id_hex,target_message_id_hex,kind,sender,recorded_at)
        SELECT e.group_id_hex,e.message_id_hex,json_extract(tag.value,'$[1]'),1009,e.sender,e.recorded_at
        FROM app_events e, json_each(e.tags_json) tag
        WHERE e.kind=1009 AND json_extract(tag.value,'$[0]')='e'
          AND json_type(tag.value,'$[1]')='text';

        CREATE TEMP TABLE accepted_edits_0076 AS
        SELECT e.group_id_hex,x.target_message_id_hex,e.message_id_hex,e.plaintext,e.recorded_at,
               count(*) OVER (PARTITION BY e.group_id_hex,x.target_message_id_hex) AS edit_count,
               row_number() OVER (PARTITION BY e.group_id_hex,x.target_message_id_hex
                                  ORDER BY e.recorded_at DESC,e.message_id_hex DESC) AS winner
        FROM app_events e
        JOIN message_modifier_edges x ON x.group_id_hex=e.group_id_hex
             AND x.modifier_message_id_hex=e.message_id_hex AND x.kind=1009
        JOIN message_timeline t ON t.group_id_hex=x.group_id_hex
             AND t.message_id_hex=x.target_message_id_hex
        JOIN app_events original ON original.group_id_hex=t.group_id_hex
             AND original.message_id_hex=t.message_id_hex
        WHERE e.kind=1009 AND e.invalidated=0 AND e.sender=t.sender
          AND t.kind=9 AND t.deleted=0 AND t.invalidation_status IS NULL
          AND original.kind=9 AND original.invalidated=0
          AND (SELECT count(*) FROM json_each(e.tags_json) tag
               WHERE json_extract(tag.value,'$[0]')='e')=1
          AND NOT EXISTS (
              SELECT 1 FROM message_modifier_edges dx
              JOIN app_events d ON d.group_id_hex=dx.group_id_hex
                   AND d.message_id_hex=dx.modifier_message_id_hex
              WHERE dx.group_id_hex=e.group_id_hex AND dx.target_message_id_hex=e.message_id_hex
                AND dx.kind=5 AND d.invalidated=0 AND d.sender=e.sender);
        CREATE INDEX accepted_edits_0076_target
            ON accepted_edits_0076(group_id_hex,target_message_id_hex,winner);
        UPDATE message_timeline AS t
        SET (plaintext,edit_json)=(
            SELECT plaintext,json_object('edit_count',edit_count,
                   'latest_edit_message_id_hex',message_id_hex,'edited_at',recorded_at)
            FROM accepted_edits_0076 a WHERE a.group_id_hex=t.group_id_hex
              AND a.target_message_id_hex=t.message_id_hex AND a.winner=1)
        WHERE EXISTS (SELECT 1 FROM accepted_edits_0076 a WHERE a.group_id_hex=t.group_id_hex
                      AND a.target_message_id_hex=t.message_id_hex AND a.winner=1);
        DELETE FROM message_timeline WHERE kind=1009;
        UPDATE chat_list_rows AS c SET last_message_preview=(
            SELECT plaintext FROM accepted_edits_0076 a WHERE a.group_id_hex=c.group_id_hex
              AND a.target_message_id_hex=c.last_message_id_hex AND a.winner=1)
        WHERE EXISTS (SELECT 1 FROM accepted_edits_0076 a WHERE a.group_id_hex=c.group_id_hex
                      AND a.target_message_id_hex=c.last_message_id_hex AND a.winner=1);
        DROP TABLE accepted_edits_0076;
    "#).storage()
}

#[cfg(test)]
mod tests {
    #[test]
    fn populated_upgrade_resolves_edits_and_keeps_raw_history() {
        use crate::migrations::{MIGRATIONS, run};
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..75]).unwrap();
        conn.execute_batch(r#"
            INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES ('11','fixture',0);
            INSERT INTO chat_list_rows(group_id_hex,updated_at,last_message_id_hex,last_message_preview,last_message_timeline_at,unread_count)
            VALUES ('11',1,'target','old',1,2);
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
            VALUES ('11','target','received','alice','old',9,'[]',1,1),
                   ('11','edit','received','alice','new',1009,'[["e","target"]]',2,2);
            INSERT INTO message_timeline(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json)
            SELECT group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at,'{"by_emoji":{},"user_reactions":[]}' FROM app_events;
        "#).unwrap();
        conn.execute_batch(r#"
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
            VALUES ('11','edit-z','received','alice','winner',1009,'[["e","target"]]',2,2),
                   ('11','wrong','received','mallory','wrong author',1009,'[["e","target"]]',3,3),
                   ('11','invalid','received','alice','invalid',1009,'[["e","target"]]',4,4),
                   ('11','malformed','received','alice','malformed',1009,'[["e","target"],["e","target"]]',5,5),
                   ('11','retracted','received','alice','retracted',1009,'[["e","target"]]',6,6),
                   ('11','delete','received','alice','',5,'[["e","retracted"]]',7,7);
            UPDATE app_events SET invalidated=1 WHERE message_id_hex='invalid';
            INSERT INTO message_modifier_edges(group_id_hex,modifier_message_id_hex,target_message_id_hex,kind,sender,recorded_at)
            VALUES ('11','delete','retracted',5,'alice',7);
        "#).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let (text, edit): (String, String) = conn
            .query_row(
                "SELECT plaintext,edit_json FROM message_timeline WHERE message_id_hex='target'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(text, "winner");
        let preview: (String,i64,i64) = conn.query_row(
            "SELECT last_message_preview,last_message_timeline_at,unread_count FROM chat_list_rows WHERE group_id_hex='11'",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).unwrap();
        assert_eq!(preview, ("winner".into(), 1, 2));
        assert_eq!(
            serde_json::from_str::<super::super::super::timeline::TimelineEditSummary>(&edit)
                .unwrap()
                .edit_count,
            2
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM message_timeline", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM app_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            8
        );
        run(&mut conn, MIGRATIONS).unwrap();
    }
}
