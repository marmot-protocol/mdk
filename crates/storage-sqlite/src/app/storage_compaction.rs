//! Returning the account database's free pages to the filesystem (mdk#2314
//! step 6).
//!
//! Deleting rows (a moved legacy attachment body, a removal) only frees pages
//! inside the file. Account databases were created without `auto_vacuum`,
//! and that cannot be switched on without one full `VACUUM`, so compaction is
//! a one-time switch: checkpoint the WAL, set `auto_vacuum=INCREMENTAL`,
//! `VACUUM` (SQLCipher re-encrypts the copy; an interrupted `VACUUM` rolls
//! back and leaves the database as it was), and checkpoint again so the WAL
//! that held the copy shrinks. From then on [`SqliteAppStorage::reclaim_free_pages`]
//! returns freed pages in bounded steps.
//!
//! The `VACUUM` holds the account connection for its whole run, and with
//! `temp_store=MEMORY` it builds the copy in memory: callers decide when the
//! live database is small enough and the volume has room (the app runtime's
//! gates), and run it on the blocking pool.
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::Connection;

use crate::{SqliteAppStorage, SqliteResultExt};

/// `PRAGMA auto_vacuum` value for incremental mode.
const AUTO_VACUUM_INCREMENTAL: i64 = 2;

/// The account database's pages: its size, the part that is free, and
/// whether freed pages can be returned without a full `VACUUM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseSpace {
    pub page_size: u64,
    pub page_count: u64,
    pub free_pages: u64,
    /// `auto_vacuum=INCREMENTAL`: compaction already happened.
    pub incremental: bool,
}

impl DatabaseSpace {
    /// The database file's size.
    pub fn file_bytes(&self) -> u64 {
        self.page_count.saturating_mul(self.page_size)
    }

    /// Bytes of free pages inside the file.
    pub fn free_bytes(&self) -> u64 {
        self.free_pages.saturating_mul(self.page_size)
    }

    /// Bytes of pages in use: what a `VACUUM` copies.
    pub fn live_bytes(&self) -> u64 {
        self.file_bytes().saturating_sub(self.free_bytes())
    }
}

pub(crate) fn database_space_in(conn: &Connection) -> StorageResult<DatabaseSpace> {
    // Table-valued pragmas: SQLCipher answers the `PRAGMA page_size`
    // statement with its own cipher setting.
    let (page_count, page_size, free_pages, auto_vacuum): (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT (SELECT page_count FROM pragma_page_count()),
                    CAST((SELECT page_size FROM pragma_page_size()) AS INTEGER),
                    (SELECT freelist_count FROM pragma_freelist_count()),
                    (SELECT auto_vacuum FROM pragma_auto_vacuum())",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .storage()?;
    let unsigned = |value: i64| u64::try_from(value).unwrap_or(0);
    Ok(DatabaseSpace {
        page_size: unsigned(page_size),
        page_count: unsigned(page_count),
        free_pages: unsigned(free_pages),
        incremental: auto_vacuum == AUTO_VACUUM_INCREMENTAL,
    })
}

impl SqliteAppStorage {
    /// The account database's page figures. Reads no rows.
    pub fn database_space(&self) -> StorageResult<DatabaseSpace> {
        let conn = self.lock()?;
        database_space_in(&conn)
    }

    /// The one-time compaction: switch to `auto_vacuum=INCREMENTAL` and
    /// `VACUUM`, between two WAL checkpoints. Blocking, and it holds the
    /// account connection until it finishes. A failure, including an
    /// interrupted `VACUUM`, leaves the database as it was. Refused inside
    /// a transaction.
    pub fn compact_database(&self) -> StorageResult<()> {
        let conn = self.lock()?;
        if !conn.is_autocommit() {
            return Err(StorageError::Backend(
                "database compaction cannot run inside a transaction".into(),
            ));
        }
        checkpoint(&conn);
        // A close (a host about to suspend) must not wait out the copy: it
        // interrupts it, and the interrupted VACUUM rolls back.
        let _interruptible = self
            .connection
            .interrupt_on_close(conn.get_interrupt_handle());
        if self.connection.is_closing() {
            return Err(StorageError::Closed(
                "database compaction cancelled by close".into(),
            ));
        }
        let vacuumed = conn
            .execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;")
            .storage();
        if vacuumed.is_err() {
            // Drop the pending mode change with the failed copy.
            let _ = conn.execute_batch("PRAGMA auto_vacuum=NONE;");
        }
        vacuumed?;
        // The WAL now holds the whole copy; fold it back and truncate it.
        checkpoint(&conn);
        Ok(())
    }

    /// Returns up to `max_pages` free pages to the filesystem once the
    /// database is incremental; a no-op before compaction. The pages leave
    /// the file at the next checkpoint. Returns how many were freed.
    pub fn reclaim_free_pages(&self, max_pages: u64) -> StorageResult<u64> {
        let conn = self.lock()?;
        let before = database_space_in(&conn)?;
        if !before.incremental || before.free_pages == 0 || max_pages == 0 {
            return Ok(0);
        }
        let pages = i64::try_from(max_pages.min(before.free_pages)).unwrap_or(i64::MAX);
        // The pragma frees one page per step: run it to completion.
        let mut statement = conn
            .prepare(&format!("PRAGMA incremental_vacuum({pages})"))
            .storage()?;
        let mut rows = statement.query([]).storage()?;
        while rows.next().storage()?.is_some() {}
        drop(rows);
        drop(statement);
        let after = database_space_in(&conn)?;
        Ok(before.free_pages.saturating_sub(after.free_pages))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SqliteAppStorage {
    /// Holds the account connection, as a running `VACUUM` does: signals
    /// `held`, then waits for `release`. Test support only.
    pub fn hold_connection_for_test(
        &self,
        held: &std::sync::mpsc::Sender<()>,
        release: &std::sync::mpsc::Receiver<()>,
    ) {
        let _conn = self.lock().expect("account connection");
        let _ = held.send(());
        let _ = release.recv();
    }
}

/// `wal_checkpoint(TRUNCATE)`, best effort: a reader holding an old snapshot
/// can block it, and the next checkpoint finishes the job.
fn checkpoint(conn: &Connection) {
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
}

#[cfg(test)]
#[path = "storage_compaction_tests.rs"]
mod tests;
