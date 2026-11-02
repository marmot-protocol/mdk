//! Reactions own attachment sources even though they never own timeline rows.
use crate::SqliteResultExt;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Preserve the chat projection, including imported history's source-id rule.
    // Existing triggers continue to address the union under its original name.
    let prior: String = tx
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='view' AND name='attachment_history_source'",
            [],
            |r| r.get(0),
        )
        .storage()?;
    let (_, select) = prior
        .split_once(" AS")
        .ok_or_else(|| StorageError::Backend("attachment source view has no SELECT body".into()))?;
    tx.execute_batch(&format!("CREATE VIEW chat_attachment_history_source AS {select}; DROP VIEW attachment_history_source;"))
        .storage()?;
    tx.execute_batch(r#"
CREATE VIEW reaction_attachment_history_source AS
SELECT a.group_id_hex,a.message_id_hex,CAST(j.key AS INTEGER) AS attachment_index,
       COALESCE(a.source_message_id_hex,a.message_id_hex) AS source_message_id_hex,
       a.source_epoch,a.sender,a.recorded_at AS timeline_at,a.received_at,
       CASE WHEN a.source_epoch IS NOT NULL THEN 1 ELSE 0 END AS order_class,
       COALESCE(a.source_epoch,a.recorded_at) AS order_primary,1 AS order_phase,a.recorded_at AS order_at,
       j.value AS slot_json,
       (a.sender NOT IN (SELECT public_key FROM user_blocks)
        AND a.group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)) AS visible
FROM app_events a, json_each(
    (SELECT json_group_array(json(tag.value) ORDER BY CAST(tag.key AS INTEGER))
     FROM json_each(CASE WHEN json_valid(a.tags_json) THEN
         CASE WHEN json_type(a.tags_json)='array' THEN a.tags_json ELSE '[]' END ELSE '[]' END) tag
     WHERE CASE WHEN tag.type='array' THEN json_extract(tag.value,'$[0]')='imeta' ELSE 0 END)
) j
WHERE a.kind=7 AND a.invalidated=0
  AND (a.source_message_id_hex IS NOT NULL OR EXISTS(SELECT 1 FROM app_event_imports i
      WHERE i.group_id_hex=a.group_id_hex AND i.message_id_hex=a.message_id_hex))
  AND EXISTS (SELECT 1 FROM message_modifier_edges e JOIN message_timeline t
      ON t.group_id_hex=e.group_id_hex AND t.message_id_hex=e.target_message_id_hex
      WHERE e.group_id_hex=a.group_id_hex AND e.modifier_message_id_hex=a.message_id_hex
        AND e.kind=7 AND t.deleted=0 AND t.invalidation_status IS NULL)
  AND NOT EXISTS (SELECT 1 FROM message_modifier_edges e JOIN app_events d
      ON d.group_id_hex=e.group_id_hex AND d.message_id_hex=e.modifier_message_id_hex
      WHERE e.group_id_hex=a.group_id_hex AND e.target_message_id_hex=a.message_id_hex
        AND e.kind=5 AND d.invalidated=0 AND d.sender=a.sender);

CREATE VIEW attachment_history_source AS
SELECT * FROM chat_attachment_history_source UNION ALL SELECT * FROM reaction_attachment_history_source;

-- Raw-event removal can bypass timeline rows for modifier events. Acquisition
-- jobs are already tied to their app event by an ON DELETE CASCADE foreign key.
CREATE TRIGGER reaction_attachment_event_removed AFTER DELETE ON app_events WHEN OLD.kind=7 BEGIN
    DELETE FROM attachment_history WHERE group_id_hex=OLD.group_id_hex AND message_id_hex=OLD.message_id_hex;
END;
CREATE TRIGGER reaction_attachment_kind_changed AFTER UPDATE OF kind ON app_events
WHEN OLD.kind=7 AND NEW.kind<>7 BEGIN
    DELETE FROM attachment_history WHERE group_id_hex=OLD.group_id_hex AND message_id_hex=OLD.message_id_hex;
END;

-- The index keeps identical slots through projection rebuilds. Artwork naming
-- metadata still fences every previously presented reaction slot.
CREATE TRIGGER reaction_attachment_emoji_changed AFTER UPDATE OF tags_json ON app_events
WHEN NEW.kind=7 AND OLD.tags_json IS NOT NEW.tags_json AND EXISTS (
    SELECT 1 FROM attachment_history WHERE group_id_hex=NEW.group_id_hex
        AND message_id_hex=NEW.message_id_hex AND visible=1
) BEGIN
    UPDATE attachment_history_versions SET revision=revision+1 WHERE group_id_hex=NEW.group_id_hex;
END;

INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
    source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
SELECT * FROM reaction_attachment_history_source;
"#).storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};

    #[test]
    fn reaction_artwork_upgrade_backfills_active_event_sources_without_timeline_rows() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(
            &mut conn,
            &MIGRATIONS[..MIGRATIONS.partition_point(|migration| migration.version < 167)],
        )
        .unwrap();
        conn.execute_batch(r#"
INSERT INTO account_groups(group_id_hex,endpoint,updated_at,pending_confirmation) VALUES('aa','',0,0);
INSERT INTO app_events(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
VALUES('aa','root','source-root',1,'received','alice','hello',9,'[]',1,1),
 ('aa','active','source-active',1,'received','alice',':party:',7,'[["e","root"],["imeta","v future"],["emoji","party","https://example.com/a"]]',2,2),
 ('aa','retracted','source-retracted',1,'received','alice',':party:',7,'[["e","root"],["imeta","v future"]]',3,3),
 ('aa','delete','source-delete',1,'received','alice','',5,'[["e","retracted"]]',4,4);
INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json)
VALUES('aa','root','source-root',1,'received','alice','hello',9,'[]',1,1,'[]');
INSERT INTO message_modifier_edges VALUES('aa','active','root',7,'alice',2),('aa','retracted','root',7,'alice',3),('aa','delete','retracted',5,'alice',4);
"#).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_history", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        run(
            &mut conn,
            &MIGRATIONS[..MIGRATIONS.partition_point(|migration| migration.version <= 167)],
        )
        .unwrap();
        let actual: (String,String,i64) = conn.query_row("SELECT message_id_hex,source_message_id_hex,attachment_index FROM attachment_history",[], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(actual, ("active".into(), "source-active".into(), 0));
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM attachment_worker_demand WHERE message_id_hex='active'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM message_timeline WHERE kind=7",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}
