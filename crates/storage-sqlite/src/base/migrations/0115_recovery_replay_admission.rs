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
    use crate::base::migrations::run_through;
    use rusqlite::{Connection, types::Value};

    fn columns(conn: &Connection, table: &str) -> String {
        let statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        statement.column_names().join(",")
    }

    fn rows(conn: &Connection, table: &str, columns: &str) -> Vec<Vec<Value>> {
        let mut statement = conn
            .prepare(&format!("SELECT {columns} FROM {table} ORDER BY 1"))
            .unwrap();
        let width = statement.column_count();
        statement
            .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Every debt shape at 114 keeps each column through the rebuild: queue
    /// loss, an epoch gap, an explicit demand with its caller origin and
    /// urgency, and incremental history with its scope window.
    #[test]
    fn native_replay_upgrade_preserves_existing_debt_scopes_and_retry_cost() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run_through(&mut conn, 114).unwrap();
        conn.execute_batch(
            "INSERT INTO account_state(label,updated_at) VALUES ('alice',100);
             INSERT INTO cgka_groups(id,epoch,record) VALUES (x'aa',7,x'00');
             INSERT INTO account_recovery_obligations
                (id,demand_key,cause,group_id,account_label,stalled_epoch,marker_token,pending_since,
                 dropped_count,revision,predicate,urgency,created_at_ms,updated_at_ms,state,
                 eligibility,incomplete_reason,caller_origin,parked_at_ms,dismissed_scopes)
             VALUES
                (x'11111111111111111111111111111111','overflow:alice',0,x'aa','alice',3,42,124,9,
                 2,1,2,10,11,1,2,3,1,12,x'0a'),
                (x'22222222222222222222222222222222','epoch:aa',1,x'aa','alice',7,43,125,8,
                 3,2,1,20,21,2,3,4,1,22,x'0b'),
                (x'33333333333333333333333333333333','explicit',3,x'aa','alice',5,44,126,7,
                 4,1,1,30,31,1,1,5,1,32,x'0c'),
                (zeroblob(16),'incremental',5,NULL,NULL,NULL,NULL,NULL,NULL,
                 9,0,0,1,2,0,4,NULL,0,3,x'00');
             INSERT INTO account_recovery_scopes
                (obligation_id,scope_id,since_seconds,until_seconds,snapshot_state,scope_payload)
             VALUES(zeroblob(16),0,7,99,1,x'010203');
             UPDATE account_recovery_state SET next_attempt=8,retry_ordinal=5,retry_not_before_ms=12345;",
        )
        .unwrap();
        let tables = ["account_recovery_obligations", "account_recovery_scopes"];
        let before: Vec<_> = tables
            .iter()
            .map(|table| {
                let columns = columns(&conn, table);
                let rows = rows(&conn, table, &columns);
                (columns, rows)
            })
            .collect();
        assert_eq!(before[0].1.len(), 4);
        run_through(&mut conn, 115).unwrap();
        for (table, (columns, expected)) in tables.iter().zip(&before) {
            assert_eq!(&rows(&conn, table, columns), expected, "{table}");
        }
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
        // The rebuild keeps 0093's single explicit demand.
        let duplicate = conn
            .execute(
                "INSERT INTO account_recovery_obligations(demand_key,cause,created_at_ms,updated_at_ms)
                 VALUES('explicit:second',3,1,1)",
                [],
            )
            .unwrap_err();
        assert!(
            duplicate.to_string().contains("UNIQUE constraint failed"),
            "{duplicate}"
        );
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
