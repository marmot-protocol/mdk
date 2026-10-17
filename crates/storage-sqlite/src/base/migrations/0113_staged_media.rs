//! Migration 0113: staged media files for outgoing attachments (mdk#2314
//! step 3). A `staged` file (state 3) is complete and synced, owned by an
//! outgoing upload row, and not yet referenced by any slot. It becomes
//! `ready` when the message carrying it is published.
//!
//! `media_files` is rebuilt to widen its state check; the triggers that
//! name it are dropped and recreated around the rebuild.
//! `outgoing_attachment_uploads.file_id` records an upload's staged (or
//! promoted) file. A file lives while a slot references it or an upload
//! owns it: an upload shared by several messages keeps its promoted file
//! while one of them still waits for it. Deleting the upload row, or pointing
//! it at another file, deletes a still-staged row (its key), and a promoted
//! one that no slot references any more. A store reset deletes every media
//! row and clears the column.
use crate::SqliteResultExt;
use cgka_traits::StorageError;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// The registry suspends enforcement for this parent rebuild and checks the
/// tables that reference it.
pub(crate) const SUSPEND_FOREIGN_KEYS: &[&str] =
    &["media_file_refs", "outgoing_attachment_uploads"];

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    if tx
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
        .storage()?
    {
        return Err(StorageError::Backend(
            "media file rebuild requires migration-runner foreign-key scope".into(),
        ));
    }
    tx.execute_batch(
        "DROP TRIGGER media_file_refs_ready;
        DROP TRIGGER media_file_refs_last;
        DROP TRIGGER media_files_store_reset;
        CREATE TABLE media_files_next (
            id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),
            file_key BLOB NOT NULL CHECK(length(file_key)=32),
            state INTEGER NOT NULL CHECK(state IN (0,1,2,3)),
            category INTEGER NOT NULL CHECK(category IN (1,2)),
            byte_len INTEGER NOT NULL CHECK(byte_len>=0),
            plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32),
            created_at INTEGER NOT NULL CHECK(created_at>=0),
            last_used_at INTEGER NOT NULL CHECK(last_used_at>=0)
        );
        INSERT INTO media_files_next SELECT * FROM media_files;
        DROP TABLE media_files;
        ALTER TABLE media_files_next RENAME TO media_files;
        CREATE UNIQUE INDEX media_files_ready_digest
            ON media_files(category,plaintext_digest) WHERE state=1;
        CREATE TRIGGER media_file_refs_ready BEFORE INSERT ON media_file_refs
        WHEN (SELECT state FROM media_files WHERE id=NEW.file_id) IS NOT 1 BEGIN
            SELECT RAISE(ABORT,'media file reference requires a ready file');
        END;
        CREATE TRIGGER media_files_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM media_file_refs;
            DELETE FROM media_files;
        END;
        ALTER TABLE outgoing_attachment_uploads ADD COLUMN file_id BLOB
            REFERENCES media_files(id) ON DELETE SET NULL;
        CREATE INDEX outgoing_attachment_upload_file
            ON outgoing_attachment_uploads(file_id) WHERE file_id IS NOT NULL;
        CREATE TRIGGER outgoing_upload_staged_released AFTER DELETE ON outgoing_attachment_uploads
        WHEN OLD.file_id IS NOT NULL BEGIN
            DELETE FROM media_files WHERE id=OLD.file_id AND (state=3 OR (state IN (1,2)
                AND NOT EXISTS(SELECT 1 FROM media_file_refs WHERE file_id=OLD.file_id)
                AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_uploads WHERE file_id=OLD.file_id)));
        END;
        CREATE TRIGGER outgoing_upload_staged_replaced AFTER UPDATE OF file_id ON outgoing_attachment_uploads
        WHEN OLD.file_id IS NOT NULL AND OLD.file_id IS NOT NEW.file_id BEGIN
            DELETE FROM media_files WHERE id=OLD.file_id AND (state=3 OR (state IN (1,2)
                AND NOT EXISTS(SELECT 1 FROM media_file_refs WHERE file_id=OLD.file_id)
                AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_uploads WHERE file_id=OLD.file_id)));
        END;
        CREATE TRIGGER media_file_refs_last AFTER DELETE ON media_file_refs
        WHEN NOT EXISTS(SELECT 1 FROM media_file_refs WHERE file_id=OLD.file_id)
            AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_uploads WHERE file_id=OLD.file_id) BEGIN
            DELETE FROM media_files WHERE id=OLD.file_id AND state IN (1,2);
        END;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};

    fn count(conn: &rusqlite::Connection, query: &str) -> i64 {
        conn.query_row(query, [], |row| row.get(0)).unwrap()
    }

    /// Existing pending, ready and lost rows and their references survive the
    /// rebuild; the recreated triggers still guard references and delete a
    /// file with its last one; staged rows are allowed and owned by uploads.
    #[test]
    fn staged_media_upgrade_keeps_rows_and_triggers() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..112]).unwrap();
        assert_eq!(MIGRATIONS[112].version, 113);
        conn.execute_batch(
            "PRAGMA foreign_keys=OFF;
            INSERT INTO media_files VALUES(x'00000000000000000000000000000001',zeroblob(32),0,1,3,zeroblob(32),1,1);
            INSERT INTO media_files VALUES(x'00000000000000000000000000000002',zeroblob(32),1,1,3,randomblob(32),1,1);
            INSERT INTO media_files VALUES(x'00000000000000000000000000000003',zeroblob(32),2,1,3,randomblob(32),1,1);
            PRAGMA foreign_keys=ON;",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(count(&conn, "SELECT count(*) FROM media_files"), 3);
        let states: String = conn
            .query_row(
                "SELECT group_concat(state) FROM (SELECT state FROM media_files ORDER BY id)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            states, "0,1,2",
            "pending, ready and lost rows keep their state"
        );
        // References need acquisition rows; the triggers are what is checked.
        conn.execute_batch(
            "PRAGMA foreign_keys=OFF;
            INSERT INTO media_file_refs VALUES(x'aa',x'00000000000000000000000000000002');",
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO media_file_refs VALUES(x'bb',x'00000000000000000000000000000001')",
                []
            )
            .is_err(),
            "a reference still requires a ready file"
        );
        conn.execute(
            "INSERT INTO media_files VALUES(x'00000000000000000000000000000004',zeroblob(32),3,1,3,randomblob(32),1,1)",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM media_file_refs WHERE token=x'aa'", [])
            .unwrap();
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM media_files WHERE id=x'00000000000000000000000000000002'"
            ),
            0,
            "the last reference still deletes its file's key"
        );
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM media_files WHERE id=x'00000000000000000000000000000004'"
            ),
            1,
            "a staged row has no references to lose"
        );
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM pragma_table_info('outgoing_attachment_uploads') WHERE name='file_id'"
            ),
            1
        );
    }
}
