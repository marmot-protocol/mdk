//! Migration 0136: the one-time conversion of the old recovery owner's rows
//! into the coverage ledger (mdk#2660 phase 4, PR 5d).
//!
//! `account_recovery_conversion` holds the conversion's marker: `step` is the
//! next step to run, and the conversion is done once it reaches the last.
//! Every database starts at step 0, a new one included, because the account
//! worker runs the conversion on whatever the old owner has written by the
//! time the runner first takes over, not when this migration runs. Storage has
//! none of the conversion's inputs (routing, the retention floor, the clock),
//! so nothing here converts a row.
//!
//! The conversion changes which "history may be incomplete" notices exist, and
//! the notice reader announces nothing on its first read, so
//! `notices_changed` asks the worker to announce the change once.
//! `report_pending` keeps what the conversion converted until the worker has
//! written its audit summary and finished the relay plane's overflow recovery
//! for the converted loss: the counts by cause and disposition in
//! `account_recovery_conversion_counts`, the loss watermarks of every account
//! and cause whose live loss it turned into ledger debt in
//! `account_recovery_conversion_loss`, and the rest on the marker. All of it survives a restart, since the steps that produced it may
//! have committed in an earlier process.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_conversion (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            step INTEGER NOT NULL CHECK (step >= 0),
            notices_changed INTEGER NOT NULL DEFAULT 0 CHECK (notices_changed IN (0, 1)),
            report_pending INTEGER NOT NULL DEFAULT 0 CHECK (report_pending IN (0, 1)),
            shadow_ranges INTEGER NOT NULL DEFAULT 0 CHECK (shadow_ranges >= 0),
            shadow_remainders INTEGER NOT NULL DEFAULT 0 CHECK (shadow_remainders >= 0),
            units_broken INTEGER NOT NULL DEFAULT 0 CHECK (units_broken >= 0)
        );
        INSERT INTO account_recovery_conversion (singleton, step) VALUES (1, 0);
        CREATE TABLE account_recovery_conversion_counts (
            cause INTEGER NOT NULL CHECK (cause IN (0, 3, 5, 6, 7)),
            disposition INTEGER NOT NULL CHECK (disposition BETWEEN 0 AND 3),
            obligations INTEGER NOT NULL CHECK (obligations > 0),
            PRIMARY KEY (cause, disposition)
        ) WITHOUT ROWID;
        CREATE TABLE account_recovery_conversion_loss (
            account_label TEXT NOT NULL,
            cause INTEGER NOT NULL CHECK (cause IN (0, 1)),
            marker_token INTEGER NOT NULL CHECK (marker_token >= 0),
            observed_count INTEGER NOT NULL CHECK (observed_count >= 0),
            PRIMARY KEY (account_label, cause, marker_token)
        ) WITHOUT ROWID;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    fn marker(conn: &Connection) -> (i64, i64, i64) {
        conn.query_row(
            "SELECT step, notices_changed, report_pending FROM account_recovery_conversion",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    }

    /// A database from before the migration and a new one both start with the
    /// conversion pending, nothing to announce and no report.
    #[test]
    fn every_database_starts_with_the_conversion_pending() {
        let mut upgraded = Connection::open_in_memory().unwrap();
        let before = MIGRATIONS
            .iter()
            .position(|migration| migration.version == 136)
            .unwrap();
        run(&mut upgraded, &MIGRATIONS[..before]).unwrap();
        run(&mut upgraded, MIGRATIONS).unwrap();
        assert_eq!(marker(&upgraded), (0, 0, 0));

        let mut fresh = Connection::open_in_memory().unwrap();
        run(&mut fresh, MIGRATIONS).unwrap();
        assert_eq!(marker(&fresh), (0, 0, 0));
        for table in [
            "account_recovery_conversion_counts",
            "account_recovery_conversion_loss",
        ] {
            let rows: i64 = fresh
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
    }
}
