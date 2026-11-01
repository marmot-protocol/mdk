//! Crossing contracts the protocol and app owners cannot prove alone.

use crate::SqliteAccountStorage;
use crate::app::account_projection::DeleteLocalGroupDataResult;
use rusqlite::params;

fn count(store: &SqliteAccountStorage, sql: &str) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

/// The logical wipe has committed when the checkpoint finish runs, so a
/// failed finish reports that wipe instead of an error that would invite the
/// caller to restore erased state, and keeps the intent so a retry erases the
/// WAL.
#[test]
fn a_failed_checkpoint_finish_reports_the_committed_wipe_and_keeps_its_intent() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('aa', '', 0);
             CREATE TRIGGER fail_finish BEFORE DELETE ON secure_delete_checkpoint_intents
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();

    assert_eq!(
        store.delete_local_group_data("aa").unwrap(),
        DeleteLocalGroupDataResult {
            deleted_rows: 1,
            completed_pending_checkpoint: false,
            erasure_pending: true,
        }
    );
    assert_eq!(count(&store, "SELECT count(*) FROM account_groups"), 0);
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        1
    );

    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_finish")
        .unwrap();
    assert_eq!(
        store.delete_local_group_data("aa").unwrap(),
        DeleteLocalGroupDataResult {
            deleted_rows: 1,
            completed_pending_checkpoint: true,
            erasure_pending: false,
        }
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM secure_delete_checkpoint_intents"
        ),
        0
    );
}

/// The app queues an engine authority request only for a message the engine
/// still holds in that group, once.
#[test]
fn an_authority_backfill_is_queued_once_and_only_for_a_message_the_engine_holds() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let conn = store.lock().unwrap();
    conn.execute_batch(
        "INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 7, x'00'), (x'02', 7, x'00');
         INSERT INTO cgka_messages(id, group_id, epoch, state, record)
         VALUES (x'aa', x'01', 7, 0, x'00');",
    )
    .unwrap();
    for (message, group) in [(b"\xaa", b"\x02"), (b"\xbb", b"\x01")] {
        super::authority::request_authority_backfill(&conn, message, group, b"stray").unwrap();
    }
    super::authority::request_authority_backfill(&conn, b"\xaa", b"\x01", b"first").unwrap();
    super::authority::request_authority_backfill(&conn, b"\xaa", b"\x01", b"again").unwrap();

    let queued = conn
        .prepare("SELECT message_id, group_id, record FROM pending_application_authority")
        .unwrap()
        .query_map(params![], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(queued, [(vec![0xaa], vec![0x01], b"first".to_vec())]);
}
