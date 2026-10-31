//! Migration 0130: each route's parked remainder (mdk#2660 phase 4).
//!
//! `account_recovery_coverage_remainders` holds, per route, the earliest and
//! latest `created_at` second the retention floor overtook while some relay
//! still owed it, so that debt is parked rather than dropped. The row keeps a
//! park revision from `account_recovery_park_revision` and the time it was
//! first parked. Only a dismissal deletes it. It is never coverage.
//!
//! `account_recovery_coverage_goals` gains `settled_below_seconds`: every
//! second of the route below it was settled by a retention prune, parked if a
//! certifying relay still owed it and dropped otherwise. A later prune parks
//! only from it up, so a goal widened back below it parks nothing twice. Loss
//! lowers it to the loss floor. An existing goal starts settled at its own
//! floor: the earlier prune raised every goal to its floor and dropped the
//! coverage below, so a goal at rest sits there, or at the floor of a loss
//! imported since.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_coverage_remainders (
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            since_seconds INTEGER NOT NULL CHECK (since_seconds >= 0),
            until_seconds INTEGER NOT NULL CHECK (until_seconds >= since_seconds),
            park_revision INTEGER NOT NULL CHECK (park_revision > 0),
            parked_at_seconds INTEGER NOT NULL CHECK (parked_at_seconds >= 0),
            PRIMARY KEY (route_kind, route_id)
        ) WITHOUT ROWID;
        ALTER TABLE account_recovery_coverage_goals ADD COLUMN settled_below_seconds
            INTEGER NOT NULL DEFAULT 0 CHECK (settled_below_seconds >= 0);
        UPDATE account_recovery_coverage_goals SET settled_below_seconds = since_seconds;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// A remainder is one range per route with a real park revision, and each
    /// existing goal starts settled at its own floor: the earlier prune left
    /// nothing below it to park again.
    #[test]
    fn a_remainder_is_one_range_per_route() {
        let mut conn = Connection::open_in_memory().unwrap();
        let end = MIGRATIONS.iter().position(|m| m.version == 130).unwrap();
        run(&mut conn, &MIGRATIONS[..end]).unwrap();
        conn.execute(
            "INSERT INTO account_recovery_coverage_goals VALUES (0, x'', 40), (1, x'02', 700)",
            [],
        )
        .unwrap();
        run(&mut conn, &MIGRATIONS[..end + 1]).unwrap();
        let settled: Vec<(i64, i64)> = conn
            .prepare(
                "SELECT since_seconds, settled_below_seconds
                 FROM account_recovery_coverage_goals ORDER BY route_kind",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(settled, [(40, 40), (700, 700)]);
        assert!(
            conn.execute(
                "UPDATE account_recovery_coverage_goals SET settled_below_seconds = -1",
                [],
            )
            .is_err()
        );
        conn.execute(
            "INSERT INTO account_recovery_coverage_remainders VALUES (0, x'', 10, 20, 1, 30)",
            [],
        )
        .unwrap();
        for row in [
            "(0, x'', 5, 8, 2, 30)",
            "(1, x'01', 20, 10, 1, 30)",
            "(1, x'01', 10, 20, 0, 30)",
        ] {
            assert!(
                conn.execute(
                    &format!("INSERT INTO account_recovery_coverage_remainders VALUES {row}"),
                    [],
                )
                .is_err(),
                "{row}"
            );
        }
    }
}
