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
        0,
        "not before compaction"
    );
    let file_before = fixture.file_len();

    app.compact_database().unwrap();
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
    assert_eq!(app.reclaim_free_pages(100).unwrap(), 100, "bounded");
    assert_eq!(app.reclaim_free_pages(u64::MAX).unwrap(), freed - 100);
    assert_eq!(fixture.space().free_pages, 0);
    let _ = fixture
        .store
        .lock()
        .unwrap()
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    assert!(fixture.file_len() + 6_000_000 < file_bloated);
    assert_eq!(fixture.marker(), "kept");
}

/// An interrupted compaction leaves the database as it was: same rows, same
/// free pages, not incremental. A later attempt succeeds.
#[test]
fn an_interrupted_compaction_changes_nothing() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    fixture.fill_and_delete();
    let before = fixture.space();

    fixture
        .store
        .lock()
        .unwrap()
        .progress_handler(1_000, Some(|| true))
        .unwrap();
    assert!(app.compact_database().is_err());
    fixture
        .store
        .lock()
        .unwrap()
        .progress_handler(1_000, None::<fn() -> bool>)
        .unwrap();
    assert_eq!(fixture.space(), before);
    assert_eq!(fixture.marker(), "kept");

    app.compact_database().unwrap();
    assert!(fixture.space().incremental);
    assert_eq!(fixture.marker(), "kept");
}

/// Compaction never runs inside a caller's transaction.
#[test]
fn compaction_is_refused_inside_a_transaction() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let result: StorageResult<()> = app.connection.with_transaction(|| app.compact_database());
    assert!(result.is_err());
    assert!(!fixture.space().incremental);
}
