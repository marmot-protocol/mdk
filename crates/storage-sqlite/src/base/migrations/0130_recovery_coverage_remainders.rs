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

    /// A remainder is one range per route with a real park revision, and an
    /// existing goal starts settled at its own floor.
    #[test]
    fn a_remainder_is_one_range_per_route() {
        let mut conn = Connection::open_in_memory().unwrap();
        let end = MIGRATIONS.iter().position(|m| m.version == 130).unwrap();
        run(&mut conn, &MIGRATIONS[..end]).unwrap();
        conn.execute(
            "INSERT INTO account_recovery_coverage_goals VALUES (0, x'', 40)",
            [],
        )
        .unwrap();
        run(&mut conn, &MIGRATIONS[..end + 1]).unwrap();
        let settled: i64 = conn
            .query_row(
                "SELECT settled_below_seconds FROM account_recovery_coverage_goals",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(settled, 40);
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

    /// An account the earlier prune left at its floor: coverage below it is
    /// gone, and one route's loss was imported since. Upgraded through the
    /// production open path, widening the first route's goal back below the
    /// floor (as each report does for pending loss) parks none of the dropped
    /// history, while the loss still parks what it owes.
    #[test]
    fn an_upgraded_goal_starts_settled_at_its_floor() {
        use crate::{
            RecoveryCoverageRange, SqlCipherHardening, SqlCipherKey, SqliteAccountStorage,
            TransportReconciliationRoute, open_hardened_sqlcipher,
        };
        const KEY: &str = "mdk storage 0130 upgrade key";
        const OLD_FLOOR: u64 = 1_000_000;
        let (covered, lost) = (
            TransportReconciliationRoute::Group([1; 32]),
            TransportReconciliationRoute::Group([2; 32]),
        );
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("schema-129.sqlite3");
        {
            let key = SqlCipherKey::new(KEY).unwrap();
            let mut conn = Connection::open(&database).unwrap();
            open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
            let end = MIGRATIONS.iter().position(|m| m.version == 130).unwrap();
            run(&mut conn, &MIGRATIONS[..end]).unwrap();
            conn.execute_batch(&format!(
                "INSERT INTO account_recovery_coverage_goals VALUES
                     (1, x'{covered}', {OLD_FLOOR}), (1, x'{lost}', {loss});
                 INSERT INTO account_recovery_coverage VALUES
                     (1, x'{covered}', 'wss://relay.example', 1, {OLD_FLOOR}, {top}, 0);",
                covered = "01".repeat(32),
                lost = "02".repeat(32),
                loss = OLD_FLOOR - 300,
                top = OLD_FLOOR + 1_000,
            ))
            .unwrap();
        }
        let key = SqlCipherKey::new(KEY).unwrap();
        let store = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let app = store.app_storage();
        app.widen_recovery_coverage_goals(std::slice::from_ref(&covered), OLD_FLOOR - 500)
            .unwrap();
        let relays = vec!["wss://relay.example".to_owned()];
        app.prune_recovery_coverage(
            OLD_FLOOR + 100,
            &[(covered.clone(), relays.clone()), (lost.clone(), relays)],
        )
        .unwrap();
        let remainders = app.recovery_coverage_remainders().unwrap();
        assert!(
            remainders
                .iter()
                .all(|remainder| remainder.route != covered)
        );
        let lost_remainder = remainders
            .iter()
            .find(|remainder| remainder.route == lost)
            .expect("the loss still parks");
        assert!(
            lost_remainder.range
                == RecoveryCoverageRange {
                    since_seconds: OLD_FLOOR - 300,
                    until_seconds: OLD_FLOOR + 99,
                }
        );
    }
}
