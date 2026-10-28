//! Migration 0123: the account recovery coverage ledger (mdk#2660 phase 2).
//!
//! `account_recovery_coverage` holds, per route and relay, the `created_at`
//! ranges (inclusive seconds) proved complete and how each was proved. Ranges
//! with the same route, relay and proof never overlap or touch: a write merges
//! them. `recorded_at_seconds` is the oldest proof time among merged ranges,
//! so a later re-check finds the stalest part first.
//!
//! `account_recovery_coverage_goals` holds each route's goal floor: the route
//! needs everything from that floor up to now. Debt is the goal minus what is
//! covered. A route without a goal row owes nothing.
//!
//! The ledger runs in shadow mode: nothing schedules recovery from it yet. No
//! rows are seeded; a fresh ledger owes and covers nothing.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_coverage (
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            relay TEXT NOT NULL,
            proof INTEGER NOT NULL CHECK (proof BETWEEN 1 AND 4),
            since_seconds INTEGER NOT NULL CHECK (since_seconds >= 0),
            until_seconds INTEGER NOT NULL CHECK (until_seconds >= since_seconds),
            recorded_at_seconds INTEGER NOT NULL,
            PRIMARY KEY (route_kind, route_id, relay, proof, since_seconds)
        ) WITHOUT ROWID;
        CREATE INDEX account_recovery_coverage_until
            ON account_recovery_coverage(until_seconds);
        CREATE TABLE account_recovery_coverage_goals (
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            since_seconds INTEGER NOT NULL CHECK (since_seconds >= 0),
            PRIMARY KEY (route_kind, route_id)
        ) WITHOUT ROWID;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// The ledger starts empty and rejects inverted ranges.
    #[test]
    fn ledger_starts_empty_and_rejects_inverted_ranges() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..123]).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM account_recovery_coverage", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
        assert!(
            conn.execute(
                "INSERT INTO account_recovery_coverage
                 VALUES (0, x'', 'wss://relay.example', 1, 10, 9, 0)",
                [],
            )
            .is_err()
        );
    }
}
