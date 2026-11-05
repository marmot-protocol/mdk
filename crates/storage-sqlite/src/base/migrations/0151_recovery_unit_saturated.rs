//! Migration 0151: a recovery unit remembers whether its last answered quantum
//! stopped on a second its relay cannot prove (mdk#2660 phase 4).
//!
//! A relay with no published cap and no negentropy can prove a slice only by
//! a reply smaller than one it sent before, so a busy second may stay
//! unprovable however often it is asked. A sweep that stops there is not cut
//! short: its next attempt stops at the same second. Admission lets such a
//! unit's group go rather than hold its live input for history the relay
//! cannot give, and keeps holding for a unit whose answer was only cut short.
//! The flag outlives the process, since a restart would otherwise hold again
//! until the unit's next attempt. Existing units start unsaturated.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_units ADD COLUMN saturated INTEGER NOT NULL
            DEFAULT 0 CHECK (saturated IN (0, 1));",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    /// A unit row from the schema before starts unsaturated.
    #[test]
    fn an_existing_unit_starts_unsaturated() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 150).unwrap();
        conn.execute(
            "INSERT INTO account_recovery_units (route_kind, route_id, relay, no_progress)
             VALUES (0, x'', 'wss://a', 2)",
            [],
        )
        .unwrap();
        run_through(&mut conn, 151).unwrap();
        let (no_progress, saturated): (i64, i64) = conn
            .query_row(
                "SELECT no_progress, saturated FROM account_recovery_units",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((no_progress, saturated), (2, 0));
        assert!(
            conn.execute("UPDATE account_recovery_units SET saturated = 2", [])
                .is_err()
        );
    }
}
