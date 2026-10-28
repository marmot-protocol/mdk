//! Migration 0126: the coverage ledger's un-cover log (mdk#2660 phase 4).
//!
//! Every write that takes coverage away (a loss import, a released receipt)
//! appends the ranges it un-covered to `account_recovery_coverage_uncovers`
//! under the account's next un-cover generation. A fetch remembers the
//! generation it started at; its coverage write subtracts every range
//! un-covered after it, so a loss or release that lands during the fetch
//! keeps its debt. `route_kind` and `route_id` are `NULL` for an un-cover of
//! every route, and `until_seconds` is `NULL` for one open to now.
//!
//! `account_recovery_coverage_uncover_state` holds the current generation and
//! the highest generation pruning removed rows of. A write whose fetch started
//! below that cannot see everything un-covered since, so it records nothing.
//!
//! `account_recovery_coverage_released` holds each route's seconds released
//! for replay. A live boundary leaves them out, since its REQ will not deliver
//! a released event again; only a fetch proof covers them, on its own relay.
//! A row ends at retention pruning.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_coverage_uncovers (
            generation INTEGER NOT NULL CHECK (generation > 0),
            route_kind INTEGER CHECK (route_kind IN (0, 1)),
            route_id BLOB,
            since_seconds INTEGER NOT NULL CHECK (since_seconds >= 0),
            until_seconds INTEGER CHECK (until_seconds >= since_seconds),
            recorded_at_seconds INTEGER NOT NULL,
            CHECK ((route_kind IS NULL) = (route_id IS NULL))
        );
        CREATE INDEX account_recovery_coverage_uncovers_generation
            ON account_recovery_coverage_uncovers(generation);
        CREATE TABLE account_recovery_coverage_uncover_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            generation INTEGER NOT NULL CHECK (generation >= 0),
            pruned_through INTEGER NOT NULL CHECK (pruned_through BETWEEN 0 AND generation)
        );
        INSERT INTO account_recovery_coverage_uncover_state (singleton, generation, pruned_through)
            VALUES (1, 0, 0);
        CREATE TABLE account_recovery_coverage_released (
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            second INTEGER NOT NULL CHECK (second >= 0),
            PRIMARY KEY (route_kind, route_id, second)
        ) WITHOUT ROWID;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// The log starts empty at generation zero and keeps every-route rows'
    /// route columns together.
    #[test]
    fn log_starts_empty_and_keeps_route_columns_together() {
        let mut conn = Connection::open_in_memory().unwrap();
        let end = MIGRATIONS.iter().position(|m| m.version == 126).unwrap() + 1;
        run(&mut conn, &MIGRATIONS[..end]).unwrap();
        let state: (i64, i64) = conn
            .query_row(
                "SELECT generation, pruned_through FROM account_recovery_coverage_uncover_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, (0, 0));
        conn.execute(
            "INSERT INTO account_recovery_coverage_uncovers VALUES (1, NULL, NULL, 10, NULL, 0)",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO account_recovery_coverage_uncovers VALUES (1, 1, NULL, 10, 20, 0)",
                [],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO account_recovery_coverage_uncovers VALUES (1, 0, x'', 10, 9, 0)",
                [],
            )
            .is_err()
        );
    }
}
