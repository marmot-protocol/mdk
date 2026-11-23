//! Give a group's drafts stable keys and keep attachment ownership with each
//! draft when its state changes. Copy the old rows before installing triggers
//! so the upgrade preserves live revisions and already-bound submissions.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE message_drafts_next (
    draft_id BLOB PRIMARY KEY NOT NULL DEFAULT (randomblob(16))
        CHECK (typeof(draft_id) = 'blob' AND length(draft_id) = 16),
    group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    content_revision INTEGER NOT NULL DEFAULT 0,
    content_bytes INTEGER GENERATED ALWAYS AS (length(CAST(content AS BLOB))) STORED,
    reply_to_message_id_hex TEXT
        CHECK (reply_to_message_id_hex IS NULL OR (
            length(reply_to_message_id_hex) = 64
            AND reply_to_message_id_hex NOT GLOB '*[^0-9a-f]*'
        )),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    content TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX message_draft_active_group ON message_drafts_next(group_id_hex) WHERE active = 1;
INSERT INTO message_drafts_next (
    group_id_hex, content, reply_to_message_id_hex, created_at_ms, updated_at_ms
)
SELECT group_id_hex, content, reply_to_message_id_hex, created_at_ms, updated_at_ms
FROM message_drafts;

CREATE TABLE message_draft_attachments_next (
    draft_id BLOB NOT NULL REFERENCES message_drafts_next(draft_id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 0),
    attachment_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    plaintext BLOB NOT NULL,
    dim TEXT,
    thumbhash TEXT,
    duration_seconds REAL,
    waveform_samples_json TEXT NOT NULL DEFAULT '[]',
    file_id BLOB REFERENCES media_files(id) ON DELETE CASCADE
        CHECK (file_id IS NULL OR (length(file_id) = 16 AND length(plaintext) = 0)),
    PRIMARY KEY (draft_id, position),
    UNIQUE (draft_id, attachment_id)
);
INSERT INTO message_draft_attachments_next
SELECT d.draft_id, a.position, a.attachment_id, a.file_name, a.media_type, a.plaintext,
       a.dim, a.thumbhash, a.duration_seconds, a.waveform_samples_json, a.file_id
FROM message_draft_attachments a
JOIN message_drafts_next d ON d.group_id_hex = a.group_id_hex AND d.active = 1;

DROP TABLE message_draft_attachments;
DROP TABLE message_drafts;
ALTER TABLE message_drafts_next RENAME TO message_drafts;
ALTER TABLE message_draft_attachments_next RENAME TO message_draft_attachments;

-- Keep the preview out of the full-text row so a legacy draft close to
-- SQLite's row-size limit does not grow by another 4 KiB.
CREATE TABLE message_draft_previews (
    draft_id BLOB PRIMARY KEY NOT NULL REFERENCES message_drafts(draft_id) ON DELETE CASCADE,
    content_preview BLOB NOT NULL
);
INSERT INTO message_draft_previews
SELECT draft_id, coalesce(substr(CAST(content AS BLOB), 1, 4096), x'') FROM message_drafts;

CREATE TRIGGER message_draft_preview_insert AFTER INSERT ON message_drafts BEGIN
    INSERT INTO message_draft_previews
        VALUES (NEW.draft_id, coalesce(substr(CAST(NEW.content AS BLOB), 1, 4096), x''));
END;
CREATE TRIGGER message_draft_preview_update AFTER UPDATE OF content ON message_drafts
WHEN OLD.content IS NOT NEW.content BEGIN
    UPDATE message_draft_previews
        SET content_preview = coalesce(substr(CAST(NEW.content AS BLOB), 1, 4096), x'')
        WHERE draft_id = NEW.draft_id;
END;

-- Group revisions check the selected composer; a draft's own version only
-- changes when its content changes, including attachment writes.
CREATE TRIGGER message_draft_content_revision_update
AFTER UPDATE OF content, reply_to_message_id_hex ON message_drafts
WHEN OLD.content IS NOT NEW.content OR OLD.reply_to_message_id_hex IS NOT NEW.reply_to_message_id_hex BEGIN
    UPDATE message_drafts SET content_revision = content_revision + 1 WHERE draft_id = NEW.draft_id;
END;

CREATE TABLE message_draft_submissions_next (
    group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    app_event_id TEXT NOT NULL,
    payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
    draft_id BLOB NOT NULL REFERENCES message_drafts(draft_id) ON DELETE CASCADE,
    content_revision INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, revision)
);
-- Previously only a binding to the current group revision could clear a draft.
INSERT INTO message_draft_submissions_next
SELECT s.group_id_hex, s.revision, s.app_event_id, s.payload_hash, d.draft_id, d.content_revision
FROM message_draft_submissions s
JOIN message_draft_revisions r USING (group_id_hex, revision)
JOIN message_drafts d ON d.group_id_hex = s.group_id_hex AND d.active = 1;
DROP TABLE message_draft_submissions;
ALTER TABLE message_draft_submissions_next RENAME TO message_draft_submissions;
CREATE INDEX message_draft_submission_draft ON message_draft_submissions(draft_id);


CREATE INDEX message_draft_group_order ON message_drafts(group_id_hex, updated_at_ms DESC, draft_id);
CREATE INDEX message_draft_attachment_descriptors ON message_draft_attachments (
    draft_id, position, attachment_id, file_name, media_type, length(plaintext),
    dim, thumbhash, duration_seconds, waveform_samples_json, file_id
);
CREATE INDEX message_draft_attachment_files
    ON message_draft_attachments(file_id) WHERE file_id IS NOT NULL;

CREATE TRIGGER message_draft_attachment_file_released
AFTER DELETE ON message_draft_attachments WHEN OLD.file_id IS NOT NULL BEGIN
    DELETE FROM media_files WHERE id = OLD.file_id AND state IN (2, 3);
END;
CREATE TRIGGER message_draft_attachment_file_replaced
AFTER UPDATE OF file_id ON message_draft_attachments
WHEN OLD.file_id IS NOT NULL AND OLD.file_id IS NOT NEW.file_id BEGIN
    DELETE FROM media_files WHERE id = OLD.file_id AND state IN (2, 3);
END;
"#,
    )
    .storage()?;

    // The compatibility projection keeps its group revision. Only active
    // changes advance it; changing selection also invalidates in-flight file
    // staging, which intentionally tolerates ordinary text edits.
    for (action, event, row, condition, move_composition) in [
        ("insert", "INSERT", "NEW", "NEW.active = 1", "0"),
        (
            "update",
            "UPDATE OF active, content, reply_to_message_id_hex, updated_at_ms",
            "NEW",
            "OLD.active = 1 OR NEW.active = 1",
            "OLD.active <> NEW.active",
        ),
        ("delete", "DELETE", "OLD", "OLD.active = 1", "1"),
    ] {
        tx.execute_batch(&format!(
            "CREATE TRIGGER message_drafts_revision_{action} AFTER {event} ON message_drafts
             WHEN {condition} BEGIN
                UPDATE message_draft_revision_clock SET revision = revision + 1;
                UPDATE message_draft_revisions
                   SET revision = (SELECT revision FROM message_draft_revision_clock),
                       composition = CASE WHEN {move_composition}
                                          THEN (SELECT revision FROM message_draft_revision_clock)
                                          ELSE composition END
                 WHERE group_id_hex = {row}.group_id_hex;
             END;"
        ))
        .storage()?;
    }
    for (action, row) in [("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")] {
        tx.execute_batch(&format!(
            "CREATE TRIGGER message_draft_attachments_revision_{action}
             AFTER {action} ON message_draft_attachments
             BEGIN
                UPDATE message_drafts SET content_revision = content_revision + 1
                 WHERE draft_id = {row}.draft_id;
                UPDATE message_draft_revision_clock SET revision = revision + 1
                 WHERE EXISTS (SELECT 1 FROM message_drafts WHERE draft_id = {row}.draft_id AND active = 1);
                UPDATE message_draft_revisions
                   SET revision = (SELECT revision FROM message_draft_revision_clock)
                 WHERE group_id_hex = (SELECT group_id_hex FROM message_drafts
                                       WHERE draft_id = {row}.draft_id AND active = 1);
             END;"
        ))
        .storage()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn saved_message_drafts_upgrade_an_original_schema_26_draft() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
            .unwrap();
        run_through(&mut conn, 26).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('chat','',0);
             INSERT INTO message_drafts(group_id_hex, content, created_at_ms, updated_at_ms)
                VALUES ('chat','old draft',11,22);
             INSERT INTO message_draft_attachments(group_id_hex, position, attachment_id,
                 file_name, media_type, plaintext)
                VALUES ('chat',0,'original','old.txt','text/plain',x'010203');",
        )
        .unwrap();
        run_through(&mut conn, 228).unwrap();
        assert!(
            conn.query_row(
                "SELECT active = 1 AND length(d.draft_id) = 16 AND content = 'old draft'
                      AND content_preview = CAST(content AS BLOB) AND content_bytes = 9
                      AND created_at_ms = 11 AND updated_at_ms = 22
                      AND position = 0 AND attachment_id = 'original' AND plaintext = x'010203'
             FROM message_drafts d JOIN message_draft_attachments a USING(draft_id)
             JOIN message_draft_previews p USING(draft_id)
             WHERE group_id_hex = 'chat'",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
        );
    }

    #[test]
    fn saved_message_drafts_upgrade_a_large_legacy_draft() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
            .unwrap();
        run_through(&mut conn, 227).unwrap();
        conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 8_000)
            .unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('chat','',0);
             INSERT INTO message_drafts(group_id_hex, content, created_at_ms, updated_at_ms)
                VALUES ('chat',replace(hex(zeroblob(3000)), '0', 'a'),11,22);",
        )
        .unwrap();

        run_through(&mut conn, 228).unwrap();
        let length: i64 = conn
            .query_row(
                "SELECT length(content) FROM message_drafts WHERE group_id_hex = 'chat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(length, 6000);
    }

    #[test]
    fn saved_message_drafts_upgrade_preserves_pending_send_and_media_key() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
            .unwrap();
        run_through(&mut conn, 227).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('chat','',0);
             INSERT INTO media_files VALUES (zeroblob(16),zeroblob(32),3,1,3,randomblob(32),1,1);
             INSERT INTO message_drafts(group_id_hex, content, reply_to_message_id_hex,
                                        created_at_ms, updated_at_ms)
                VALUES ('chat','saved text',lower(hex(zeroblob(32))),1,2);
             INSERT INTO message_draft_attachments(group_id_hex, position, attachment_id,
                 file_name, media_type, plaintext, file_id)
                VALUES ('chat',0,'inline','photo','image/png',x'010203',NULL),
                       ('chat',1,'staged','video','video/mp4',x'',zeroblob(16));
             INSERT INTO message_draft_submissions
                SELECT group_id_hex, revision, 'pending', zeroblob(32) FROM message_draft_revisions;",
        )
        .unwrap();

        run_through(&mut conn, 228).unwrap();

        assert!(
            conn.query_row(
                "SELECT active = 1 AND length(draft_id) = 16 AND content = 'saved text'
                        AND reply_to_message_id_hex = lower(hex(zeroblob(32)))
                        AND created_at_ms = 1 AND updated_at_ms = 2
                 FROM message_drafts WHERE group_id_hex = 'chat'",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
        );
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM message_draft_attachments a
                 JOIN message_drafts d ON d.draft_id = a.draft_id
                 WHERE d.group_id_hex = 'chat'
                   AND ((position = 0 AND plaintext = x'010203' AND file_id IS NULL)
                     OR (position = 1 AND plaintext = x'' AND file_id IN (SELECT id FROM media_files)))",
                [], |row| row.get(0),
            ).unwrap();
        assert_eq!(count, 2);
        let send_still_current: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM message_draft_revisions r JOIN message_draft_submissions s
                USING(group_id_hex, revision) WHERE s.app_event_id = 'pending')",
            [], |row| row.get(0),
        ).unwrap();
        assert!(send_still_current);

        conn.execute("DELETE FROM account_groups WHERE group_id_hex = 'chat'", [])
            .unwrap();
        for table in [
            "message_drafts",
            "message_draft_attachments",
            "message_draft_previews",
            "message_draft_submissions",
            "media_files",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
    }
}
