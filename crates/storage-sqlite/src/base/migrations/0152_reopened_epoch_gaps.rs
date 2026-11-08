//! Migration 0152: the recovery conversion's marker counts the epoch gaps it
//! reopened (mdk#3059).
//!
//! The old owner satisfied an epoch gap once its relays answered for the gap's
//! window, never once the engine left the stalled epoch, so the conversion's
//! last step reopens every satisfied epoch gap as pending. The report counts
//! them on the marker, beside the other counts that are not one converted
//! cause's disposition: the per-cause counts admit only the causes the
//! conversion takes from the old owner. A database that converted before this
//! migration reopened none.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_conversion ADD COLUMN epoch_gaps_reopened INTEGER NOT NULL
            DEFAULT 0 CHECK (epoch_gaps_reopened >= 0);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    /// The marker from the schema before has reopened no epoch gap, and never
    /// counts a negative number.
    #[test]
    fn an_existing_marker_has_reopened_no_epoch_gap() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 151).unwrap();
        conn.execute(
            "UPDATE account_recovery_conversion SET step = 6, units_broken = 2",
            [],
        )
        .unwrap();
        run_through(&mut conn, 152).unwrap();
        let (step, reopened): (i64, i64) = conn
            .query_row(
                "SELECT step, epoch_gaps_reopened FROM account_recovery_conversion",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((step, reopened), (6, 0));
        assert!(
            conn.execute(
                "UPDATE account_recovery_conversion SET epoch_gaps_reopened = -1",
                []
            )
            .is_err()
        );
    }
}
