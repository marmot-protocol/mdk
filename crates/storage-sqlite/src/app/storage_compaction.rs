//! Returning the account database's free pages to the filesystem (mdk#2314
//! step 6).
//!
//! Deleting rows (a moved legacy attachment body, a removal) only frees pages
//! inside the file. New account databases are created incremental (see
//! `finish_account_open`), but older ones were created without `auto_vacuum`,
//! which cannot be switched on without one full `VACUUM`, so for them
//! compaction is a one-time switch: checkpoint the WAL, set `auto_vacuum=INCREMENTAL`,
//! `VACUUM` (SQLCipher re-encrypts the copy; an interrupted `VACUUM` rolls
//! back and leaves the database as it was), and checkpoint again so the WAL
//! that held the copy shrinks. From then on [`SqliteAppStorage::reclaim_free_pages`]
//! returns freed pages in bounded steps.
//!
//! The `VACUUM` holds the account connection for its whole run, and with
//! `temp_store=MEMORY` it builds the copy in memory. A close stops the build
//! (the statement polls the close latch), but not the final write-back of the
//! copy into the file, which SQLite runs as one uninterruptible page copy:
//! callers decide when the live database is small enough to bound both and
//! the volume has room (the app runtime's gates), and run it on the blocking
//! pool.
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::Connection;

use crate::{SqliteAppStorage, SqliteResultExt};

/// `PRAGMA auto_vacuum` value for incremental mode.
const AUTO_VACUUM_INCREMENTAL: i64 = 2;
/// Virtual machine steps between the `VACUUM`'s checks of the close latch.
const CLOSE_POLL_OPS: std::ffi::c_int = 1_000;

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
    ///
    /// `Ok(true)` when the WAL that held the copy was truncated too. With
    /// `Ok(false)` a reader on another connection blocked the truncate: the
    /// compaction committed, and [`Self::truncate_wal`] finishes the job
    /// later.
    pub fn compact_database(&self) -> StorageResult<bool> {
        self.compact_database_pausing(&|| {})
    }

    /// [`Self::compact_database`], calling `pause` with the connection held
    /// between the closing check and the `VACUUM`. Test support only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn compact_database_pausing_for_test(&self, pause: &dyn Fn()) -> StorageResult<bool> {
        self.compact_database_pausing(pause)
    }

    /// Rewrites the database in the layout accounts created before mdk#2314
    /// step 6 have: no auto-vacuum. Test support only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn make_non_incremental_for_test(&self) -> StorageResult<()> {
        self.lock()?
            .execute_batch("PRAGMA auto_vacuum=NONE; VACUUM;")
            .storage()
    }

    /// Whether a close of the account database has begun. Test support only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn is_closing_for_test(&self) -> bool {
        self.connection.is_closing()
    }

    fn compact_database_pausing(&self, pause: &dyn Fn()) -> StorageResult<bool> {
        let conn = self.lock()?;
        if !conn.is_autocommit() {
            return Err(StorageError::Backend(
                "database compaction cannot run inside a transaction".into(),
            ));
        }
        // Best effort: the VACUUM writes into the WAL either way.
        let _ = self.truncate_wal_locked(&conn);
        if self.connection.is_closing() {
            return Err(StorageError::Closed(
                "database compaction cancelled by close".into(),
            ));
        }
        pause();
        // A close (a host about to suspend) must not wait out the copy, and
        // may begin at any moment, even before the copy starts: the VACUUM
        // polls the close latch as it runs, stops once a close has begun,
        // and rolls back.
        let closing = self.connection.closing_probe();
        conn.progress_handler(CLOSE_POLL_OPS, Some(closing))
            .storage()?;
        let vacuumed = conn
            .execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;")
            .storage();
        conn.progress_handler(CLOSE_POLL_OPS, None::<fn() -> bool>)
            .storage()?;
        if vacuumed.is_err() {
            // Drop the pending mode change with the failed copy.
            let _ = conn.execute_batch("PRAGMA auto_vacuum=NONE;");
        }
        vacuumed?;
        // The WAL now holds the whole copy; fold it back and truncate it.
        self.truncate_wal_locked(&conn)
    }

    /// Returns up to `max_pages` free pages once the database is
    /// incremental, then truncates the WAL so they leave the file; a no-op
    /// before compaction.
    pub fn reclaim_free_pages(&self, max_pages: u64) -> StorageResult<PageReclaim> {
        let conn = self.lock()?;
        let before = database_space_in(&conn)?;
        if !before.incremental || before.free_pages == 0 || max_pages == 0 {
            return Ok(PageReclaim::default());
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
        Ok(PageReclaim {
            pages: before.free_pages.saturating_sub(after.free_pages),
            truncated: self.truncate_wal_locked(&conn)?,
        })
    }

    /// Checkpoints the WAL into the database and truncates it, without
    /// waiting for readers on other connections. `false` when one held an
    /// older snapshot: nothing is lost, and a later call finishes the job.
    pub fn truncate_wal(&self) -> StorageResult<bool> {
        let conn = self.lock()?;
        self.truncate_wal_locked(&conn)
    }

    /// Whether a compaction's or reclaim's WAL truncate was blocked by a
    /// reader and is still owed; [`Self::truncate_wal`] settles it.
    pub fn wal_truncate_pending(&self) -> bool {
        self.connection.wal_truncate_pending()
    }

    /// [`truncate_wal_in`] on the locked connection, recording the result
    /// before the lock is released.
    /// A failed attempt leaves the truncate owed, as a blocked one does.
    fn truncate_wal_locked(&self, conn: &Connection) -> StorageResult<bool> {
        let truncated = truncate_wal_in(conn);
        self.connection
            .record_wal_truncate(matches!(truncated, Ok(true)));
        truncated
    }
}

/// What [`SqliteAppStorage::reclaim_free_pages`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageReclaim {
    /// Free pages returned.
    pub pages: u64,
    /// The WAL was truncated, so the pages left the file. `false` while a
    /// reader blocked it; [`SqliteAppStorage::truncate_wal`] retries.
    pub truncated: bool,
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

/// `wal_checkpoint(TRUNCATE)` without waiting on the busy handler: a reader
/// holding an older snapshot on another connection makes it report busy
/// (its first column), not fail. `true` when it truncated.
fn truncate_wal_in(conn: &Connection) -> StorageResult<bool> {
    let wait: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .storage()?;
    conn.busy_timeout(std::time::Duration::ZERO).storage()?;
    let checkpoint = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        })
        .storage();
    let restored = conn
        .busy_timeout(std::time::Duration::from_millis(
            u64::try_from(wait).unwrap_or(0),
        ))
        .storage();
    let busy = checkpoint?;
    restored?;
    Ok(busy == 0)
}

#[cfg(test)]
#[path = "storage_compaction_tests.rs"]
mod tests;
