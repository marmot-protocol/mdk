use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE message_draft_revision_clock (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            revision INTEGER NOT NULL CHECK(typeof(revision) = 'integer' AND revision >= 0)
        );
        INSERT INTO message_draft_revision_clock VALUES (1, 0);
        CREATE TABLE message_draft_revisions (
            group_id_hex TEXT PRIMARY KEY REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            revision INTEGER NOT NULL CHECK(revision > 0)
        );
        INSERT INTO message_draft_revisions
            SELECT group_id_hex, row_number() OVER (ORDER BY group_id_hex) FROM account_groups;
        UPDATE message_draft_revision_clock SET revision = (SELECT count(*) FROM account_groups);
        CREATE TRIGGER message_draft_group_insert AFTER INSERT ON account_groups BEGIN
            UPDATE message_draft_revision_clock SET revision = revision + 1;
            INSERT INTO message_draft_revisions
                SELECT NEW.group_id_hex, revision FROM message_draft_revision_clock;
        END;
        CREATE TABLE message_draft_submissions (
            group_id_hex TEXT PRIMARY KEY REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            app_event_id TEXT NOT NULL,
            payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32)
        );",
    )
    .storage()?;
    // Include legacy writes and attachment-only edits. Group deletion removes
    // the revision row; the global clock prevents reuse after group recreation.
    for table in ["message_drafts", "message_draft_attachments"] {
        for (action, row) in [("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")] {
            tx.execute_batch(&format!(
                "CREATE TRIGGER {table}_revision_{action} AFTER {action} ON {table} BEGIN
                    UPDATE message_draft_revision_clock SET revision = revision + 1;
                    UPDATE message_draft_revisions SET revision =
                        (SELECT revision FROM message_draft_revision_clock)
                        WHERE group_id_hex = {row}.group_id_hex;
                END;"
            ))
            .storage()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, Migration, run};
    use cgka_traits::storage::StorageError;
    fn aborted(tx: &Transaction<'_>) -> StorageResult<()> {
        apply(tx)?;
        Err(StorageError::Backend("injected migration failure".into()))
    }
    #[test]
    fn draft_revision_upgrade_preserves_populated_drafts_and_rolls_back_completely() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        run(&mut conn, &MIGRATIONS[..72]).unwrap();
        conn.execute_batch("INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES ('group','',0);
            INSERT INTO message_drafts VALUES ('group','saved text',NULL,1,1);
            INSERT INTO message_draft_attachments VALUES ('group',0,'attachment','file','audio/mp4',x'010203',NULL,NULL,2.5,'[0.5]');").unwrap();
        let interrupted = [Migration {
            version: 73,
            name: "0073_message_draft_revisions",
            apply: aborted,
        }];
        assert!(run(&mut conn, &interrupted).is_err());
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='message_draft_revisions'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
        run(&mut conn, MIGRATIONS).unwrap();
        let bytes: Vec<u8> = conn
            .query_row("SELECT plaintext FROM message_draft_attachments", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(bytes, [1, 2, 3]);
        let text: String = conn
            .query_row("SELECT content FROM message_drafts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(text, "saved text");
        let revision: i64 = conn
            .query_row("SELECT revision FROM message_draft_revisions", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(revision > 0);
        conn.execute_batch("UPDATE message_drafts SET updated_at_ms=1")
            .unwrap();
        let next: i64 = conn
            .query_row("SELECT revision FROM message_draft_revisions", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(next > revision);
    }
}
