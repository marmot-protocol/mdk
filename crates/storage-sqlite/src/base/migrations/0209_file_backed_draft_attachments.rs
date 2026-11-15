//! Migration 0209: file-backed composer draft attachments (mdk#3431).
//!
//! A draft attachment either keeps its bytes inline (`plaintext`, as before)
//! or owns a staged media-store file (`file_id`) and keeps an empty
//! `plaintext`. The draft row is the staged file's owner: deleting the row,
//! or pointing it away from the file, deletes a still-staged (or lost) file
//! row, which is the key erase; the store unlinks the file afterwards, or its
//! sweep does. A file row that goes first (a store reset) takes its draft
//! attachment with it.
//!
//! Each group's revision row gains `composition`, taken from the global
//! revision clock when the row is created and whenever a draft ends:
//! deleting its row (clear, delete or send) by trigger, and the clear or
//! delete of a composer that has no row yet in code. The clock outlives the
//! group, so a recreated group never reuses a value, and a file staged into
//! one composition never joins the next, while text saves during the copy
//! keep it. The group-insert trigger now names its columns.
//!
//! The descriptor index gains `file_id` so selected-draft reads stay off the
//! blob pages, and `file_id` gets its own index for the foreign key and the
//! sweep's owner check.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE message_draft_attachments ADD COLUMN file_id BLOB
            REFERENCES media_files(id) ON DELETE CASCADE
            CHECK(file_id IS NULL OR (length(file_id)=16 AND length(plaintext)=0));
        DROP INDEX message_draft_attachment_descriptors;
        CREATE INDEX message_draft_attachment_descriptors ON message_draft_attachments (
            group_id_hex, position, attachment_id, file_name, media_type,
            length(plaintext), dim, thumbhash, duration_seconds, waveform_samples_json, file_id
        );
        CREATE INDEX message_draft_attachment_files
            ON message_draft_attachments(file_id) WHERE file_id IS NOT NULL;
        CREATE TRIGGER message_draft_attachment_file_released
        AFTER DELETE ON message_draft_attachments WHEN OLD.file_id IS NOT NULL BEGIN
            DELETE FROM media_files WHERE id=OLD.file_id AND state IN (2,3);
        END;
        CREATE TRIGGER message_draft_attachment_file_replaced
        AFTER UPDATE OF file_id ON message_draft_attachments
        WHEN OLD.file_id IS NOT NULL AND OLD.file_id IS NOT NEW.file_id BEGIN
            DELETE FROM media_files WHERE id=OLD.file_id AND state IN (2,3);
        END;
        ALTER TABLE message_draft_revisions ADD COLUMN composition INTEGER NOT NULL DEFAULT 0;
        DROP TRIGGER message_draft_group_insert;
        CREATE TRIGGER message_draft_group_insert AFTER INSERT ON account_groups BEGIN
            UPDATE message_draft_revision_clock SET revision = revision + 1;
            INSERT INTO message_draft_revisions (group_id_hex, revision, composition)
                SELECT NEW.group_id_hex, revision, revision FROM message_draft_revision_clock;
        END;
        CREATE TRIGGER message_draft_composition_ended AFTER DELETE ON message_drafts BEGIN
            UPDATE message_draft_revision_clock SET revision = revision + 1;
            UPDATE message_draft_revisions
               SET composition = (SELECT revision FROM message_draft_revision_clock)
             WHERE group_id_hex = OLD.group_id_hex;
        END;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    fn count(conn: &Connection, query: &str) -> i64 {
        conn.query_row(query, [], |row| row.get(0)).unwrap()
    }

    /// Inline drafts survive the upgrade unchanged; a file-backed row must
    /// keep no inline bytes, and deleting it or replacing its file deletes
    /// the staged file row while leaving other media rows alone.
    #[test]
    fn file_backed_draft_attachments_own_their_staged_file() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        run_through(&mut conn, 208).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES ('group','',0);
             INSERT INTO message_drafts VALUES ('group','saved text',NULL,1,1);
             INSERT INTO message_draft_attachments
                 VALUES ('group',0,'inline','file','image/png',x'010203',NULL,NULL,NULL,'[]');",
        )
        .unwrap();
        run_through(&mut conn, 209).unwrap();
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM message_draft_attachments
                 WHERE plaintext=x'010203' AND file_id IS NULL"
            ),
            1
        );
        let staged = |id: u8| {
            conn.execute(
                "INSERT INTO media_files VALUES(?1,zeroblob(32),3,1,3,randomblob(32),1,1)",
                [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, id]],
            )
            .unwrap();
        };
        let file = |id: u8| [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, id].to_vec();
        staged(1);
        assert!(
            conn.execute(
                "INSERT INTO message_draft_attachments(group_id_hex,position,attachment_id,
                 file_name,media_type,plaintext,waveform_samples_json,file_id)
                 VALUES ('group',1,'both','f','video/mp4',x'01','[]',?1)",
                [file(1)],
            )
            .is_err(),
            "a file-backed row keeps no inline bytes"
        );
        conn.execute(
            "INSERT INTO message_draft_attachments(group_id_hex,position,attachment_id,
             file_name,media_type,plaintext,waveform_samples_json,file_id)
             VALUES ('group',1,'video','f','video/mp4',x'','[]',?1)",
            [file(1)],
        )
        .unwrap();
        staged(2);
        staged(3);
        conn.execute(
            "UPDATE message_draft_attachments SET file_id=?1 WHERE attachment_id='video'",
            [file(2)],
        )
        .unwrap();
        assert_eq!(
            count(&conn, "SELECT count(*) FROM media_files"),
            2,
            "replacing the file releases the old one"
        );
        conn.execute("DELETE FROM message_drafts", []).unwrap();
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM media_files WHERE id=x'00000000000000000000000000000003'"
            ),
            1,
            "deleting the draft keeps unrelated rows"
        );
        assert_eq!(
            count(&conn, "SELECT count(*) FROM media_files"),
            1,
            "deleting the draft releases its file"
        );
        conn.execute("DELETE FROM media_files", []).unwrap();
        conn.execute_batch(
            "INSERT INTO message_drafts VALUES ('group','',NULL,1,1);
             INSERT INTO media_files VALUES(x'00000000000000000000000000000004',zeroblob(32),3,1,3,randomblob(32),1,1);
             INSERT INTO message_draft_attachments(group_id_hex,position,attachment_id,
                 file_name,media_type,plaintext,waveform_samples_json,file_id)
                 VALUES ('group',0,'video','f','video/mp4',x'','[]',x'00000000000000000000000000000004');
             DELETE FROM media_files;",
        )
        .unwrap();
        assert_eq!(
            count(&conn, "SELECT count(*) FROM message_draft_attachments"),
            0,
            "a file row that goes first takes its draft attachment with it"
        );
    }
}
