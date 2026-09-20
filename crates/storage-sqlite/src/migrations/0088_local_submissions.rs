use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE local_message_submissions (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            client_token TEXT NOT NULL CHECK(length(client_token) BETWEEN 1 AND 128),
            message_id_hex TEXT NOT NULL,
            request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
            payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
            payload BLOB,
            request_json TEXT,
            expected_epoch INTEGER,
            state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 2)),
            outcome_json TEXT,
            UNIQUE(group_id_hex, client_token),
            UNIQUE(group_id_hex, message_id_hex)
        );
        CREATE INDEX local_message_submissions_pending ON local_message_submissions(sequence) WHERE state = 0;
        CREATE TRIGGER local_submission_source_deleted AFTER DELETE ON app_events BEGIN
            DELETE FROM local_message_submissions
            WHERE group_id_hex = OLD.group_id_hex AND message_id_hex = OLD.message_id_hex;
        END;",
    ).storage()
}
