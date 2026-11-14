//! Migration 0205: remember which attachment jobs storage readmission released.
//!
//! `attachment_acquisition.storage_readmitted` is set when readmission releases
//! a storage-parked job and cleared when the user retries, cancels or resets
//! it. Readmission counts the need of every queued or retrying job it released
//! (alongside every job in flight) against free space, so a later pass cannot
//! fund another job into space those still have to write (mdk#3414). The park
//! streak cannot carry this: recorded checkpoint progress clears it long before
//! the job finishes. Existing rows start unset: nothing readmitted before this
//! version is known, and the worker's admission check still parks a job that
//! would not fit.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE attachment_acquisition ADD COLUMN storage_readmitted INTEGER NOT NULL DEFAULT 0
             CHECK(storage_readmitted IN (0,1));",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    /// The column arrives unset on a schema-204 database and admits only 0 or 1.
    #[test]
    fn adds_an_unset_readmission_flag() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 205).unwrap();
        let columns: Vec<(String, String, i64, Option<String>)> = conn
            .prepare("PRAGMA table_info(attachment_acquisition)")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(columns.contains(&(
            "storage_readmitted".into(),
            "INTEGER".into(),
            1,
            Some("0".into())
        )));
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name='attachment_acquisition'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(sql.contains("CHECK(storage_readmitted IN (0,1))"));
    }
}
