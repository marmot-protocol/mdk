use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Metadata after the large plaintext column otherwise requires walking its
    // overflow pages. Keep selected composer reads on a blob-free covering index.
    // Trade-off: this duplicates descriptor strings and waveform JSON on disk
    // and adds index writes. Splitting plaintext into a separately keyed table
    // is the structural follow-up; this index keeps the existing draft layout
    // and revision triggers intact while removing blob-sized metadata reads.
    // Structural follow-up: https://github.com/marmot-protocol/mdk/issues/1941.
    tx.execute_batch(
        "CREATE INDEX message_draft_attachment_descriptors ON message_draft_attachments (
            group_id_hex, position, attachment_id, file_name, media_type,
            length(plaintext), dim, thumbhash, duration_seconds, waveform_samples_json
        );",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_drafts::{ATTACHMENT_SUMMARIES_SQL, revisioned::SELECTED_ATTACHMENTS_SQL};
    use crate::migrations::{MIGRATIONS, Migration, run};
    use cgka_traits::storage::StorageError;
    use rusqlite::{Connection, params};

    fn interrupted(tx: &Transaction<'_>) -> StorageResult<()> {
        apply(tx)?;
        Err(StorageError::Backend("injected migration failure".into()))
    }

    #[test]
    fn draft_descriptor_upgrade_preserves_data_and_uses_covering_index() {
        // Pin both the tiny-draft and populated-table planner choices, using
        // production's current no-ANALYZE policy and the actual read statements.
        for count in [1, 32] {
            let mut conn = Connection::open_in_memory().unwrap();
            conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
            run(&mut conn, &MIGRATIONS[..87]).unwrap();
            conn.execute_batch(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES ('group','',0);
                 INSERT INTO message_drafts VALUES ('group','saved text',NULL,1,2);",
            ).unwrap();
            let bytes = vec![42_u8; 64 * 1024];
            for position in 0..count {
                conn.execute(
                    "INSERT INTO message_draft_attachments VALUES
                     ('group',?1,?2,'voice.mp4','audio/mp4',?3,'1x1','thumb',2.5,'[0.5,1.0]')",
                    params![position, format!("attachment-{position}"), bytes],
                )
                .unwrap();
            }
            let revision = |conn: &Connection| -> i64 {
                conn.query_row(
                    "SELECT revision FROM message_draft_revisions WHERE group_id_hex='group'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
            };
            let before = revision(&conn);
            assert!(
                run(
                    &mut conn,
                    &[Migration {
                        version: 88,
                        name: "0088_draft_attachment_descriptors",
                        apply: interrupted,
                    }]
                )
                .is_err()
            );
            let index_count: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='message_draft_attachment_descriptors'",
                [], |r| r.get(0),
            ).unwrap();
            assert_eq!(index_count, 0, "failed migration must roll back its index");
            run(&mut conn, MIGRATIONS).unwrap();
            run(&mut conn, MIGRATIONS).unwrap();
            assert_eq!(
                revision(&conn),
                before,
                "migration must not change draft revisions"
            );
            let draft: (String, i64, i64) = conn
                .query_row(
                    "SELECT content,created_at_ms,updated_at_ms FROM message_drafts",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(draft, ("saved text".into(), 1, 2));
            let preserved: i64 = conn.query_row(
                "SELECT count(*) FROM message_draft_attachments WHERE plaintext=?1
                 AND file_name='voice.mp4' AND media_type='audio/mp4' AND dim='1x1'
                 AND thumbhash='thumb' AND duration_seconds=2.5 AND waveform_samples_json='[0.5,1.0]'",
                [&bytes], |r| r.get(0),
            ).unwrap();
            assert_eq!(preserved, count);
            for sql in [SELECTED_ATTACHMENTS_SQL, ATTACHMENT_SUMMARIES_SQL] {
                let plan: Vec<String> = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .unwrap()
                    .query_map(["group"], |r| r.get(3))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                assert!(
                    plan.iter().any(|step| step
                        .contains("USING COVERING INDEX message_draft_attachment_descriptors")),
                    "descriptor query must avoid blob pages: {plan:?}"
                );
                let descriptors: Vec<(String, i64)> = conn
                    .prepare(sql)
                    .unwrap()
                    .query_map(["group"], |r| Ok((r.get(0)?, r.get(3)?)))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                assert_eq!(
                    descriptors,
                    (0..count)
                        .map(|position| (format!("attachment-{position}"), bytes.len() as i64))
                        .collect::<Vec<_>>()
                );
            }
            conn.execute(
                "UPDATE message_draft_attachments SET plaintext=x'0102' WHERE position=0",
                [],
            )
            .unwrap();
            assert!(
                revision(&conn) > before,
                "revision triggers must remain live"
            );
            let size: i64 = conn
                .query_row(SELECTED_ATTACHMENTS_SQL, ["group"], |r| r.get(3))
                .unwrap();
            assert_eq!(size, 2, "covering index must track attachment updates");
        }
    }
}
