use super::*;
use crate::{SqlCipherKey, SqliteAccountStorage};

const FILLER_ROWS: i64 = 2_000;
const FILLER_BYTES: i64 = 4_000;

struct Fixture {
    dir: tempfile::TempDir,
    store: SqliteAccountStorage,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new(hex::encode([0x5c; 32])).unwrap();
        let store =
            SqliteAccountStorage::open_encrypted(dir.path().join("session.sqlite"), &key).unwrap();
        // The layout accounts created before incremental mode have.
        store.app_storage().make_non_incremental_for_test().unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TABLE compaction_filler(id INTEGER PRIMARY KEY, body BLOB NOT NULL);
                 CREATE TABLE compaction_marker(value TEXT NOT NULL);
                 INSERT INTO compaction_marker VALUES('kept');",
            )
            .unwrap();
        Self { dir, store }
    }

    /// About 8 MB of rows, then deleted: free pages inside the file.
    fn fill_and_delete(&self) {
        let conn = self.store.lock().unwrap();
        conn.execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?1)
             INSERT INTO compaction_filler(body) SELECT randomblob(?2) FROM n",
            rusqlite::params![FILLER_ROWS, FILLER_BYTES],
        )
        .unwrap();
        conn.execute("DELETE FROM compaction_filler", []).unwrap();
        let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    }

    fn space(&self) -> DatabaseSpace {
        self.store.app_storage().database_space().unwrap()
    }

    fn file_len(&self) -> u64 {
        std::fs::metadata(self.dir.path().join("session.sqlite"))
            .unwrap()
            .len()
    }

    fn marker(&self) -> String {
        self.store
            .lock()
            .unwrap()
            .query_row("SELECT value FROM compaction_marker", [], |r| r.get(0))
            .unwrap()
    }
}

/// A populated database with free pages shrinks on disk, keeps its rows, and
/// switches to incremental mode, after which freed pages return in bounded
/// steps without another full copy.
#[test]
fn compaction_shrinks_the_file_and_then_reclaims_incrementally() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    fixture.fill_and_delete();
    let before = fixture.space();
    assert!(!before.incremental);
    assert!(before.free_bytes() > 6_000_000, "{before:?}");
    assert_eq!(
        app.reclaim_free_pages(u64::MAX).unwrap(),
        PageReclaim::default(),
        "not before compaction"
    );
    let file_before = fixture.file_len();

    assert!(app.compact_database().unwrap(), "the WAL was truncated");
    let after = fixture.space();
    assert!(after.incremental);
    assert_eq!(after.free_pages, 0);
    assert!(
        fixture.file_len() + 6_000_000 < file_before,
        "the file shrank on disk"
    );
    assert_eq!(fixture.marker(), "kept");

    fixture.fill_and_delete();
    let freed = fixture.space().free_pages;
    assert!(freed > 1_000);
    let file_bloated = fixture.file_len();
    assert_eq!(app.reclaim_free_pages(100).unwrap().pages, 100, "bounded");
    let rest = app.reclaim_free_pages(u64::MAX).unwrap();
    assert_eq!(
        rest,
        PageReclaim {
            pages: freed - 100,
            truncated: true
        }
    );
    assert_eq!(fixture.space().free_pages, 0);
    // The reclaim's own truncate shrank the file: no extra checkpoint here.
    assert!(fixture.file_len() + 6_000_000 < file_bloated);
    assert_eq!(fixture.marker(), "kept");
}

/// Compaction never runs inside a caller's transaction.
#[test]
fn compaction_is_refused_inside_a_transaction() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let result: StorageResult<bool> = app.connection.with_transaction(|| app.compact_database());
    assert!(result.is_err());
    assert!(!fixture.space().incremental);
}

/// A close (a host about to suspend) does not wait out a compaction, even one
/// that begins after the compaction checked for a close and before its
/// `VACUUM` starts: the copy polls the close latch, stops, and rolls back.
/// The reopened database is as it was, and compacts later.
#[test]
fn a_close_stops_a_compaction_that_has_not_started_copying() {
    let fixture = Fixture::new();
    fixture.fill_and_delete();
    let before = fixture.space();
    let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
    let app = fixture.store.app_storage();
    let compacting = std::thread::spawn(move || {
        let probe = app.clone();
        app.compact_database_pausing_for_test(&|| {
            let _ = paused_tx.send(());
            while !probe.is_closing_for_test() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })
    });
    paused_rx.recv().unwrap();
    fixture.store.closer().begin_close();
    let closing = std::time::Instant::now();
    assert!(compacting.join().unwrap().is_err(), "the copy stopped");
    fixture.store.close().unwrap();
    assert!(closing.elapsed() < std::time::Duration::from_secs(5));

    let key = SqlCipherKey::new(hex::encode([0x5c; 32])).unwrap();
    let reopened =
        SqliteAccountStorage::open_encrypted(fixture.dir.path().join("session.sqlite"), &key)
            .unwrap();
    let app = reopened.app_storage();
    let space = app.database_space().unwrap();
    assert!(!space.incremental);
    assert_eq!(space.free_pages, before.free_pages);
    let marker = || -> String {
        reopened
            .lock()
            .unwrap()
            .query_row("SELECT value FROM compaction_marker", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(marker(), "kept");
    assert!(app.compact_database().unwrap());
    assert!(app.database_space().unwrap().incremental);
    assert_eq!(marker(), "kept");
}

/// A reader on another connection (the account engine's) that holds an older
/// snapshot blocks the truncate after the VACUUM without failing it: the
/// compaction commits, reports the WAL untruncated, and a later truncate
/// finishes the job once the reader is gone.
#[test]
fn a_reader_blocks_the_truncate_and_a_later_one_finishes_it() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    fixture.fill_and_delete();
    let file_before = fixture.file_len();
    let path = fixture.dir.path().join("session.sqlite");
    let reader = rusqlite::Connection::open(&path).unwrap();
    crate::open_hardened_sqlcipher(
        &reader,
        &SqlCipherKey::new(hex::encode([0x5c; 32])).unwrap(),
        crate::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM compaction_marker", [], |r| r.get(0))
        .unwrap();

    assert!(
        !app.compact_database().unwrap(),
        "the reader blocked the truncate"
    );
    assert!(app.wal_truncate_pending());
    assert!(
        fixture.space().incremental,
        "the compaction itself committed"
    );
    let wal = || {
        std::fs::metadata(fixture.dir.path().join("session.sqlite-wal"))
            .map(|m| m.len())
            .unwrap_or(0)
    };
    assert!(wal() > 0);
    assert!(!app.truncate_wal().unwrap(), "still held");

    assert!(app.wal_truncate_pending());
    reader.execute_batch("COMMIT").unwrap();
    assert!(app.truncate_wal().unwrap());
    assert!(!app.wal_truncate_pending());
    assert_eq!(wal(), 0);
    assert!(fixture.file_len() + 6_000_000 < file_before);
    assert_eq!(fixture.marker(), "kept");
}

/// A new account database starts incremental: it never needs the one-time
/// compaction, and freed pages return without it.
#[test]
fn a_new_database_starts_incremental() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new(hex::encode([0x5c; 32])).unwrap();
    let path = dir.path().join("session.sqlite");
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(store.app_storage().database_space().unwrap().incremental);
    store.close().unwrap();
    // Reopening an existing database keeps its mode and never rewrites it.
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    reopened
        .app_storage()
        .make_non_incremental_for_test()
        .unwrap();
    reopened.close().unwrap();
    let again = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(!again.app_storage().database_space().unwrap().incremental);
}
