//! Migration 0218: drop the storage of the retired agent text stream feature.
//! Stream starts (kind 1200) no longer project a timeline row, and a
//! stream-final chat message carries no stream metadata, so the stream-start
//! index, the publisher sequences and the timeline's stream column go. The
//! source `app_events` rows stay, like every other retained event.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
DROP TABLE IF EXISTS agent_stream_starts;
DROP TABLE IF EXISTS agent_stream_publisher_sequences;
DELETE FROM message_timeline WHERE kind = 1200;
ALTER TABLE message_timeline DROP COLUMN agent_stream_json;
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn stream_storage_goes_and_stream_starts_leave_the_timeline() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 217).unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('11', 'fixture', 0);
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
            VALUES ('11','start','received','agent','',1200,'[["stream","aa"]]',1,1),
                   ('11','final','received','agent','done',9,'[["stream","aa"],["stream-start","start"]]',2,2);
            INSERT INTO message_timeline(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,agent_stream_json,reactions_json)
            VALUES ('11','start','received','agent','',1200,'[["stream","aa"]]',1,1,'{"status":"started"}','{"by_emoji":{},"user_reactions":[]}'),
                   ('11','final','received','agent','done',9,'[["stream","aa"],["stream-start","start"]]',2,2,'{"status":"finalized"}','{"by_emoji":{},"user_reactions":[]}');
            INSERT INTO agent_stream_starts(group_id_hex,message_id_hex,sender,stream_id_hex,tags_json,started_at,received_at)
            VALUES ('11','start','agent','aa','[]',1,1);
            INSERT INTO agent_stream_publisher_sequences(context_id,next_seq,transcript_hash,chunk_count,updated_at_ms)
            VALUES (zeroblob(32),1,zeroblob(32),0,0);
            "#,
        )
        .unwrap();

        run_through(&mut conn, 218).unwrap();

        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE name IN ('agent_stream_starts', 'agent_stream_publisher_sequences',
                                'idx_agent_stream_starts_group_stream')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
        let stream_column: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('message_timeline')
                 WHERE name = 'agent_stream_json'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stream_column, 0);
        // The stream-final chat message stays an ordinary row, read through the
        // visibility view as every timeline reader does.
        let rows = conn
            .prepare("SELECT message_id_hex, kind, plaintext FROM visible_message_timeline")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows, vec![("final".to_owned(), 9, "done".to_owned())]);
        let sources: i64 = conn
            .query_row("SELECT count(*) FROM app_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sources, 2);
    }
}
