//! Migration 0135: a fencing unit keeps the ranges it fences (mdk#2660 phase 4).
//!
//! Only capture debt holds a group's live frames: the part of a live REQ's
//! range, `[since, oldest event seen]`, that its relay's non-empty count left
//! unproven. A restart forgets the counts, so `account_recovery_unit_fences`
//! keeps every capture range a unit still owes, one row each; ranges of one
//! unit never overlap. The bare `fencing` mark goes: without its ranges it
//! would fence all of the unit's debt, the cold-start gap a restart leaves
//! included. Nothing set the mark before this migration.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_units DROP COLUMN fencing;
        CREATE TABLE account_recovery_unit_fences (
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            relay TEXT NOT NULL CHECK (length(relay) > 0),
            since_seconds INTEGER NOT NULL CHECK (since_seconds >= 0),
            until_seconds INTEGER NOT NULL CHECK (until_seconds >= since_seconds),
            PRIMARY KEY (route_kind, route_id, relay, since_seconds)
        ) WITHOUT ROWID;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// A unit row from the schema before keeps its state and fences nothing;
    /// a fence is an ordered range.
    #[test]
    fn a_fence_is_an_ordered_range() {
        let mut conn = Connection::open_in_memory().unwrap();
        let end = MIGRATIONS.iter().position(|m| m.version == 135).unwrap();
        run(&mut conn, &MIGRATIONS[..end]).unwrap();
        conn.execute(
            "INSERT INTO account_recovery_units (route_kind, route_id, relay, no_progress, fencing)
             VALUES (0, x'', 'wss://a', 2, 1)",
            [],
        )
        .unwrap();
        run(&mut conn, &MIGRATIONS[..end + 1]).unwrap();
        let no_progress: i64 = conn
            .query_row(
                "SELECT no_progress FROM account_recovery_units",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(no_progress, 2);
        let fences: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM account_recovery_unit_fences",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fences, 0);
        let fence = |since: i64, until: i64| {
            conn.execute(
                "INSERT INTO account_recovery_unit_fences
                 (route_kind, route_id, relay, since_seconds, until_seconds)
                 VALUES (0, x'', 'wss://a', ?1, ?2)",
                rusqlite::params![since, until],
            )
        };
        assert!(fence(10, 9).is_err());
        assert!(fence(-1, 9).is_err());
        fence(10, 10).unwrap();
        fence(20, 30).unwrap();
    }
}
