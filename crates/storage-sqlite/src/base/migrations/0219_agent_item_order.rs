//! Migration 0219: agent items take the shape of marmot-agents D-076.
//!
//! A turn's agent items (kind 1201) are ordered by their `seq` within one
//! second, so the timeline gets `timeline_order_seq` between the order's
//! second and its event id, and the canonical order index takes it in the same
//! place. Each item's first event gives it, read with the projector's parser;
//! an item of the old shape, which carries no `seq`, keeps 0. An answer or a
//! control (kind 1202) no longer has a timeline row; its source `app_events`
//! row stays, like every other retained event.
use crate::{SqliteResultExt, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE message_timeline
ADD COLUMN timeline_order_seq INTEGER NOT NULL DEFAULT 0;

DROP INDEX IF EXISTS idx_message_timeline_group_canonical_order;
CREATE INDEX idx_message_timeline_group_canonical_order
    ON message_timeline (
        group_id_hex,
        timeline_order_class,
        timeline_order_primary,
        timeline_order_phase,
        timeline_order_at,
        timeline_order_seq,
        message_id_hex
    );

DELETE FROM message_timeline WHERE kind = 1202;
"#,
    )
    .storage()?;
    let items = {
        let mut stmt = tx
            .prepare(
                "SELECT timeline.group_id_hex, timeline.message_id_hex, source.tags_json
                 FROM message_timeline AS timeline
                 JOIN app_events AS source
                   ON source.group_id_hex = timeline.group_id_hex
                  AND source.message_id_hex = timeline.message_id_hex
                 WHERE timeline.kind = 1201",
            )
            .storage()?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?
    };
    for (group, message, tags_json) in items {
        let Ok(tags) = serde_json::from_str::<Vec<Vec<String>>>(&tags_json) else {
            continue;
        };
        let seq = cgka_traits::agent_events::agent_item_order_seq(1201, &tags);
        if seq == 0 {
            continue;
        }
        tx.execute(
            "UPDATE message_timeline SET timeline_order_seq = ?3
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group, message, u64_to_i64(seq)?],
        )
        .storage()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn items_take_their_seq_and_requests_leave_the_timeline() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 218).unwrap();
        let item_tags = r#"[["v","1"],["state","running"],["title","Running"],["harness","codex"],["item_id","i"],["seq","42"],["fields","{\"type\":\"tool\",\"body\":{}}"]]"#;
        conn.execute_batch(&format!(
            r#"
            INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('11', 'fixture', 0);
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
            VALUES ('11','item','received','agent','Running',1201,'{item_tags}',1,1),
                   ('11','old','received','agent','{{"v":1}}',1201,'[["status","error"]]',1,1),
                   ('11','request','received','alice','Stop',1202,'[["p","agent"]]',1,1),
                   ('11','chat','received','alice','hi',9,'[]',1,1);
            INSERT INTO message_timeline(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json)
            SELECT group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at,
                   '{{"by_emoji":{{}},"user_reactions":[]}}'
            FROM app_events;
            "#
        ))
        .unwrap();

        run_through(&mut conn, 219).unwrap();

        let rows = conn
            .prepare(
                "SELECT message_id_hex, timeline_order_seq FROM visible_message_timeline
                 ORDER BY message_id_hex",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                ("chat".to_owned(), 0),
                ("item".to_owned(), 42),
                ("old".to_owned(), 0)
            ]
        );
        let request_source: i64 = conn
            .query_row(
                "SELECT count(*) FROM app_events WHERE message_id_hex = 'request'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(request_source, 1);
        let index: String = conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE name = 'idx_message_timeline_group_canonical_order'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            index.contains(
                "timeline_order_at,\n        timeline_order_seq,\n        message_id_hex"
            )
        );
    }
}
