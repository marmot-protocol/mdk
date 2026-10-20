//! The maintenance tick's legacy body migration (mdk#2314 step 6): one batch
//! on the blocking pool, with the account's policy and free space, waking
//! attachment observers when it finishes.
use super::*;
use crate::media::attachment_resume::test_free_space;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_maintenance_batch_moves_a_legacy_body_and_wakes_observers() {
    let (dir, client, storage, _reference) = offline_fixture().await;
    test_free_space::set(dir.path(), 1 << 40);
    let plaintext = b"retained worker bytes";
    let now = crate::unix_now_seconds();
    admit_demands(&storage.app_storage(), now, false).unwrap();
    let asset = storage
        .app_storage()
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    let job = storage
        .app_storage()
        .claim_attachment_acquisition(&asset, now, now + 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        storage
            .app_storage()
            .complete_attachment_acquisition(&job, plaintext, now, u64::MAX / 2)
            .unwrap(),
        storage_sqlite::AttachmentPublishResult::Published
    );
    let shared = RuntimeSharedServices::default();
    let observer = shared.attachment_updates.subscribe();
    let mut admission = Admission::default();

    spawn_legacy_migration(&client, &shared, &mut admission);
    admission.legacy_migration.take().unwrap().await.unwrap();

    assert!(
        observer.has_changed().unwrap(),
        "completion wakes observers"
    );
    assert_eq!(storage.app_storage().legacy_attachment_bytes().unwrap(), 0);
    let read = read_retained(&storage, &client.app, "alice", &asset, now, 0, 1024)
        .unwrap()
        .unwrap();
    assert_eq!(read.as_slice(), plaintext);
    assert!(matches!(
        storage
            .app_storage()
            .retained_attachment_read(&asset, now, 0, 16)
            .unwrap(),
        Some(storage_sqlite::RetainedAttachmentRead::MediaFile(_))
    ));
    test_free_space::clear(dir.path());
}

/// The maintenance tick's compaction runs once per worker ownership, awaited
/// off the worker's async thread, and wakes observers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_maintenance_tick_compacts_the_database_once() {
    let (dir, client, storage, _reference) = offline_fixture().await;
    test_free_space::set(dir.path(), 1 << 40);
    storage
        .app_storage()
        .make_non_incremental_for_test()
        .unwrap();
    {
        // Free pages inside the database, as moved or removed bodies leave.
        let conn = super::retention_fault_connection(&client.app);
        conn.execute_batch(
            "CREATE TABLE compaction_filler(body BLOB NOT NULL);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000)
             INSERT INTO compaction_filler SELECT randomblob(4000) FROM n;
             DROP TABLE compaction_filler;",
        )
        .unwrap();
    }
    let before = storage.app_storage().database_space().unwrap();
    assert!(!before.incremental);
    assert!(before.free_bytes() >= 3_000_000);
    let shared = RuntimeSharedServices::default();
    let observer = shared.attachment_updates.subscribe();
    let mut admission = Admission::default();

    compact_if_due(&client, &shared, &mut admission).await;
    assert!(admission.compaction_attempted);
    assert!(observer.has_changed().unwrap(), "observers hear of it");
    let after = storage.app_storage().database_space().unwrap();
    assert!(after.incremental);
    assert!(after.file_bytes() < before.file_bytes());
    test_free_space::clear(dir.path());
}

/// A compaction that rolls back (here: another connection holds the write
/// lock) leaves the database as it was and is tried again on a later tick,
/// where it completes. It does not use up the worker's one attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rolled_back_compaction_is_tried_again_later() {
    let (dir, client, storage, _reference) = offline_fixture().await;
    test_free_space::set(dir.path(), 1 << 40);
    storage
        .app_storage()
        .make_non_incremental_for_test()
        .unwrap();
    let writer = super::retention_fault_connection(&client.app);
    writer
        .execute_batch(
            "CREATE TABLE compaction_filler(body BLOB NOT NULL);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000)
             INSERT INTO compaction_filler SELECT randomblob(4000) FROM n;
             DROP TABLE compaction_filler;",
        )
        .unwrap();
    let shared = RuntimeSharedServices::default();
    let mut admission = Admission::default();

    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    compact_if_due(&client, &shared, &mut admission).await;
    assert!(!admission.compaction_attempted);
    assert_eq!(admission.compaction_rollbacks, 1);
    assert!(!storage.app_storage().database_space().unwrap().incremental);

    writer.execute_batch("COMMIT").unwrap();
    compact_if_due(&client, &shared, &mut admission).await;
    assert!(admission.compaction_attempted);
    assert!(storage.app_storage().database_space().unwrap().incremental);
    test_free_space::clear(dir.path());
}

/// Repeated rollbacks stop after the cap, so a failure that keeps happening
/// cannot rebuild the in-memory copy on every tick.
#[test]
fn compaction_rollbacks_are_capped_per_worker() {
    use crate::media::storage_compaction::CompactionAttempt;
    let mut admission = Admission::default();
    admission.record_compaction(CompactionAttempt::NotDue);
    for _ in 0..MAX_COMPACTION_ROLLBACKS {
        assert!(!admission.compaction_attempted);
        admission.record_compaction(CompactionAttempt::RolledBack);
    }
    assert!(admission.compaction_attempted);
    let mut fresh = Admission::default();
    fresh.record_compaction(CompactionAttempt::Done);
    assert!(
        fresh.compaction_attempted,
        "a completed one is not repeated"
    );
}
