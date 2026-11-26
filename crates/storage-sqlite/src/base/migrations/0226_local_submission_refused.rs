//! Migration 0226: a token send can end refused, state 4, because the group
//! gained a member account the send's member list leaves out.
//!
//! A send limited to member accounts carries its list in its retained request
//! and in the engine's queued intent, both JSON an older binary still reads
//! and would send without the list. This migration fences such binaries out,
//! and the rebuild widens the state check. A partial index finds the refused
//! sends whose row an account open still retracts.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "DROP TRIGGER local_submission_source_deleted;
        CREATE TABLE local_message_submissions_next (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            client_token TEXT NOT NULL CHECK(length(client_token) BETWEEN 1 AND 128),
            message_id_hex TEXT NOT NULL,
            request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
            payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
            payload BLOB,
            request_json TEXT,
            state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 3, 4)),
            outcome_json TEXT,
            UNIQUE(group_id_hex, client_token),
            UNIQUE(group_id_hex, message_id_hex)
        );
        INSERT INTO local_message_submissions_next (sequence, group_id_hex, client_token, message_id_hex,
            request_hash, payload_hash, payload, request_json, state, outcome_json)
        SELECT sequence, group_id_hex, client_token, message_id_hex, request_hash, payload_hash, payload,
            request_json, state, outcome_json
        FROM local_message_submissions;
        DROP TABLE local_message_submissions;
        ALTER TABLE local_message_submissions_next RENAME TO local_message_submissions;
        CREATE INDEX local_message_submissions_pending ON local_message_submissions(sequence) WHERE state = 0;
        CREATE INDEX local_message_submissions_refused ON local_message_submissions(group_id_hex) WHERE state = 4;
        CREATE TRIGGER local_submission_source_deleted AFTER DELETE ON app_events BEGIN
            DELETE FROM local_message_submissions
            WHERE group_id_hex = OLD.group_id_hex AND message_id_hex = OLD.message_id_hex;
        END;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;

    const ROW: &str = "INSERT INTO local_message_submissions
        (group_id_hex, client_token, message_id_hex, request_hash, payload_hash, state, outcome_json)
        VALUES ('aa', ?1, ?2, zeroblob(32), zeroblob(32), ?3, ?4)";

    /// Existing sends keep every field and their order, a queued send keeps
    /// the payload and request it is published from, and state 4 is accepted
    /// only from this version.
    #[test]
    fn rebuild_keeps_sends_and_admits_the_refused_state() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run_through(&mut conn, 225).unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('aa', '', 0)",
            [],
        )
        .unwrap();
        conn.execute(ROW, rusqlite::params!["sent", "m1", 1, "outcome"])
            .unwrap();
        conn.execute(
            "INSERT INTO local_message_submissions
                (group_id_hex, client_token, message_id_hex, request_hash, payload_hash, payload, request_json)
                VALUES ('aa', 'queued', 'm3', zeroblob(32), zeroblob(32), x'0102', '{\"version\":1}')",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(ROW, rusqlite::params!["early", "m2", 4, None::<String>])
                .is_err()
        );

        run_through(&mut conn, 226).unwrap();
        let kept: (i64, String, i64, String) = conn
            .query_row(
                "SELECT sequence, message_id_hex, state, outcome_json FROM local_message_submissions WHERE client_token = 'sent'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(kept, (1, "m1".into(), 1, "outcome".into()));
        let queued: (i64, Vec<u8>, String) = conn
            .query_row(
                "SELECT sequence, payload, request_json FROM local_message_submissions WHERE state = 0 ORDER BY sequence LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(queued, (2, vec![1, 2], "{\"version\":1}".into()));
        conn.execute(ROW, rusqlite::params!["refused", "m2", 4, None::<String>])
            .unwrap();
        let sequence: i64 = conn
            .query_row(
                "SELECT sequence FROM local_message_submissions WHERE client_token = 'refused'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(sequence > 2, "the sequence keeps counting");
    }
}
