use crate::{SqliteResultExt, tags_from_json};
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("ALTER TABLE message_timeline ADD COLUMN edit_json TEXT;")
        .storage()?;
    let mut stmt = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, sender, recorded_at, tags_json
         FROM app_events WHERE kind=1009",
        )
        .storage()?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut targets = std::collections::BTreeSet::new();
    for (group, id, sender, at, tags) in rows {
        for tag in tags_from_json(tags)
            .map_err(|e| cgka_traits::StorageError::Serialization(e.to_string()))?
        {
            if tag.first().is_some_and(|t| t == "e")
                && let Some(target) = tag.get(1)
            {
                tx.execute(
                    "INSERT OR IGNORE INTO message_modifier_edges
                     (group_id_hex,modifier_message_id_hex,target_message_id_hex,kind,sender,recorded_at)
                     VALUES (?1,?2,?3,1009,?4,?5)",
                    params![group,id,target,sender,at],
                ).storage()?;
                targets.insert((group.clone(), target.clone()));
            }
        }
    }
    // Edits remain in raw app_events/history, never as transcript rows.
    tx.execute("DELETE FROM message_timeline WHERE kind=1009", [])
        .storage()?;
    for (group, target) in targets {
        crate::timeline::upsert_message_timeline_projection_for_message_tx(tx, &group, &target)?;
        // Keep existing read/activity/delivery state intact, updating only the selected body.
        tx.execute(
            "UPDATE chat_list_rows SET last_message_preview = (
                 SELECT plaintext FROM message_timeline WHERE group_id_hex=?1 AND message_id_hex=?2)
             WHERE group_id_hex=?1 AND last_message_id_hex=?2
               AND EXISTS (SELECT 1 FROM message_timeline WHERE group_id_hex=?1 AND message_id_hex=?2)",
            params![group,target],
        ).storage()?;
    }
    Ok(())
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
        run(&mut conn, MIGRATIONS).unwrap();
        let (text, edit): (String, String) = conn
            .query_row(
                "SELECT plaintext,edit_json FROM message_timeline WHERE message_id_hex='target'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(text, "new");
        let preview: (String,i64,i64) = conn.query_row(
            "SELECT last_message_preview,last_message_timeline_at,unread_count FROM chat_list_rows WHERE group_id_hex='11'",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).unwrap();
        assert_eq!(preview, ("new".into(), 1, 2));
        assert_eq!(
            serde_json::from_str::<super::super::super::timeline::TimelineEditSummary>(&edit)
                .unwrap()
                .edit_count,
            1
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
            2
        );
        run(&mut conn, MIGRATIONS).unwrap();
    }
}
