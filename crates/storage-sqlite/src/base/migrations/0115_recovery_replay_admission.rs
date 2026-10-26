//! Widen the existing owner ledger for limited native replay admission.
use crate::SqliteResultExt;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::Transaction;

/// Rebuilding the parent must not cascade-delete its frozen scope windows.
pub(crate) const SUSPEND_FOREIGN_KEYS: &[&str] = &["account_recovery_scopes"];

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    if tx
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
        .storage()?
    {
        return Err(StorageError::Backend(
            "recovery ledger rebuild requires migration-runner foreign-key scope".into(),
        ));
    }
    tx.execute_batch(
        r#"
CREATE TABLE account_recovery_obligations_next (
    id BLOB PRIMARY KEY NOT NULL DEFAULT(randomblob(16)) CHECK(typeof(id) = 'blob' AND length(id) = 16),
    demand_key TEXT NOT NULL UNIQUE,
    cause INTEGER NOT NULL CHECK(cause BETWEEN 0 AND 7),
    group_id BLOB REFERENCES cgka_groups(id) ON DELETE CASCADE,
    account_label TEXT REFERENCES account_state(label) ON DELETE CASCADE,
    stalled_epoch INTEGER CHECK(stalled_epoch IS NULL OR (typeof(stalled_epoch) = 'integer' AND stalled_epoch >= 0)),
    marker_token INTEGER CHECK(marker_token IS NULL OR (typeof(marker_token) = 'integer' AND marker_token >= 0)),
    pending_since INTEGER CHECK(pending_since IS NULL OR (typeof(pending_since) = 'integer' AND pending_since >= 0)),
    dropped_count INTEGER CHECK(dropped_count IS NULL OR (typeof(dropped_count) = 'integer' AND dropped_count >= 0)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(revision) = 'integer' AND revision > 0),
    predicate INTEGER NOT NULL DEFAULT 0 CHECK(predicate BETWEEN 0 AND 3),
    urgency INTEGER NOT NULL DEFAULT 0 CHECK(urgency BETWEEN 0 AND 2),
    created_at_ms INTEGER NOT NULL CHECK(typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(typeof(updated_at_ms) = 'integer' AND updated_at_ms >= 0),
    state INTEGER NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 2),
    eligibility INTEGER NOT NULL DEFAULT 0 CHECK(eligibility BETWEEN 0 AND 4),
    incomplete_reason INTEGER CHECK(incomplete_reason BETWEEN 0 AND 7),
    caller_origin INTEGER NOT NULL DEFAULT 0 CHECK(caller_origin IN (0, 1)),
    parked_at_ms INTEGER CHECK(parked_at_ms IS NULL OR (typeof(parked_at_ms)='integer' AND parked_at_ms>=0)),
    dismissed_scopes BLOB CHECK(dismissed_scopes IS NULL OR typeof(dismissed_scopes)='blob'),
    CHECK((cause NOT IN (0, 6)) OR (account_label IS NOT NULL AND marker_token IS NOT NULL
          AND pending_since IS NOT NULL AND dropped_count IS NOT NULL)),
    CHECK((cause != 1) OR (group_id IS NOT NULL AND stalled_epoch IS NOT NULL))
);
INSERT INTO account_recovery_obligations_next SELECT * FROM account_recovery_obligations;
DROP TABLE account_recovery_obligations;
ALTER TABLE account_recovery_obligations_next RENAME TO account_recovery_obligations;
CREATE INDEX account_recovery_pending ON account_recovery_obligations(state, eligibility);
CREATE INDEX account_recovery_group ON account_recovery_obligations(cause, group_id, stalled_epoch);
CREATE INDEX account_recovery_account ON account_recovery_obligations(cause, account_label, marker_token);
CREATE INDEX account_recovery_epoch_order ON account_recovery_obligations(updated_at_ms, group_id) WHERE cause = 1 AND state = 0;
CREATE UNIQUE INDEX account_recovery_single_explicit ON account_recovery_obligations(cause) WHERE cause=3;
CREATE UNIQUE INDEX account_recovery_single_replay ON account_recovery_obligations(cause) WHERE cause=7;
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};

    #[test]
    fn native_replay_upgrade_preserves_existing_debt_scopes_and_retry_cost() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..114]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_recovery_obligations
                (id,demand_key,cause,created_at_ms,updated_at_ms,revision,eligibility,parked_at_ms,dismissed_scopes)
             VALUES(zeroblob(16),'incremental',5,1,2,9,4,3,x'00');
             INSERT INTO account_recovery_scopes
                (obligation_id,scope_id,since_seconds,until_seconds,snapshot_state,scope_payload)
             VALUES(zeroblob(16),0,7,99,1,x'010203');
             UPDATE account_recovery_state SET next_attempt=8,retry_ordinal=5,retry_not_before_ms=12345;",
        ).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let retained: (i64, i64, i64, Vec<u8>, i64, i64, Vec<u8>) = conn.query_row(
            "SELECT revision,eligibility,parked_at_ms,dismissed_scopes,since_seconds,until_seconds,scope_payload
             FROM account_recovery_obligations JOIN account_recovery_scopes ON id=obligation_id",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        ).unwrap();
        assert_eq!(retained, (9, 4, 3, vec![0], 7, 99, vec![1, 2, 3]));
        let retry: (i64, i64, i64) = conn
            .query_row(
                "SELECT next_attempt,retry_ordinal,retry_not_before_ms FROM account_recovery_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(retry, (8, 5, 12345));
        conn.execute_batch(
            "INSERT INTO account_recovery_obligations(demand_key,cause,predicate,created_at_ms,updated_at_ms)
             VALUES('replay:first',7,3,1,1);",
        ).unwrap();
        assert!(conn.execute(
            "INSERT INTO account_recovery_obligations(demand_key,cause,predicate,created_at_ms,updated_at_ms)
             VALUES('replay:second',7,3,1,1)", [],
        ).is_err());
        conn.execute("DELETE FROM account_recovery_obligations WHERE cause=5", [])
            .unwrap();
        let scopes: i64 = conn
            .query_row("SELECT count(*) FROM account_recovery_scopes", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(scopes, 0, "foreign-key cascade is restored after rebuild");
    }
}
