//! Migration 0151: a recovery unit remembers the second its last answered
//! quantum stopped on because its relay cannot prove it (mdk#2660 phase 4).
//!
//! A relay with no published cap and no negentropy can prove a slice only by
//! a reply smaller than one it sent before, so a busy second may stay
//! unprovable however often it is asked. A sweep that stops there is not cut
//! short: while that second is still the first one the unit owes and the
//! relay's caps are unchanged, its next attempt stops at the same second.
//! Admission lets such a unit's group go rather than hold its live input for
//! history the relay cannot give, and keeps holding for a unit whose answer
//! was only cut short. The second outlives the process, since a restart would
//! otherwise hold again until the unit's next attempt. Existing units have
//! none.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_units ADD COLUMN saturated_second INTEGER
            CHECK (saturated_second IS NULL OR saturated_second >= 0);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    /// A unit row from the schema before has no saturated second.
    #[test]
    fn an_existing_unit_has_no_saturated_second() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 150).unwrap();
        conn.execute(
            "INSERT INTO account_recovery_units (route_kind, route_id, relay, no_progress)
             VALUES (0, x'', 'wss://a', 2)",
            [],
        )
        .unwrap();
        run_through(&mut conn, 151).unwrap();
        let (no_progress, saturated): (i64, Option<i64>) = conn
            .query_row(
                "SELECT no_progress, saturated_second FROM account_recovery_units",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((no_progress, saturated), (2, None));
        assert!(
            conn.execute(
                "UPDATE account_recovery_units SET saturated_second = -1",
                []
            )
            .is_err()
        );
    }
}
