//! The maintenance tick's legacy body migration (mdk#2314 step 6): one batch
//! on the blocking pool, with the account's policy and free space, waking
//! attachment observers with a state change when it finishes.
use super::*;
use crate::media::attachment_resume::test_free_space;

/// One maintenance batch moves a legacy body into the media store, still
/// readable, and wakes observers with a state change.
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
    assert!(*observer.borrow() > 0, "as a state change");
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
/// off the worker's async thread, and wakes observers with a state change.
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

    maintenance_tick(&client, &shared, &mut admission).await;
    assert!(admission.compaction_attempted);
    assert!(observer.has_changed().unwrap(), "observers hear of it");
    assert!(*observer.borrow() > 0, "as a state change");
    let after = storage.app_storage().database_space().unwrap();
    assert!(after.incremental);
    assert!(after.file_bytes() < before.file_bytes());
    test_free_space::clear(dir.path());
}

/// A compaction that rolls back (here: another connection holds the write
/// lock) leaves the database as it was and is not tried again on the next
/// tick, only once its spacing has passed, where it completes. It does not
/// use up the worker's one attempt.
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
    maintenance_tick(&client, &shared, &mut admission).await;
    assert!(!admission.compaction_attempted);
    assert_eq!(admission.compaction_rollbacks, 1);
    assert!(!storage.app_storage().database_space().unwrap().incremental);

    writer.execute_batch("COMMIT").unwrap();
    maintenance_tick(&client, &shared, &mut admission).await;
    assert!(
        !storage.app_storage().database_space().unwrap().incremental,
        "not before its spacing has passed"
    );
    let past = std::time::Instant::now() - Duration::from_secs(1);
    admission.compaction_retry_at = Some(past);
    admission.latches.recheck_due = Some(past);
    maintenance_tick(&client, &shared, &mut admission).await;
    assert!(admission.compaction_attempted);
    assert!(storage.app_storage().database_space().unwrap().incremental);
    test_free_space::clear(dir.path());
}

/// The compaction check runs on every batch while a migration is owed, not
/// only on the hourly recheck: the batch that moves a legacy body frees its
/// pages, then sees them, so the compaction follows on that tick instead of
/// up to an hour later (mdk#2923).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tick_that_finishes_the_migration_flags_the_compaction() {
    use std::sync::atomic::Ordering;
    let body = vec![7u8; 4 << 20];
    let (dir, client, storage, _reference) = offline_fixture_with(&body).await;
    let app_storage = storage.app_storage();
    app_storage.make_non_incremental_for_test().unwrap();
    // A legacy body large enough that moving it leaves the database
    // mostly free pages.
    let now = crate::unix_now_seconds();
    admit_demands(&app_storage, now, false).unwrap();
    let asset = app_storage
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    let job = app_storage
        .claim_attachment_acquisition(&asset, now, now + 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        app_storage
            .complete_attachment_acquisition(&job, &body, now, u64::MAX / 2)
            .unwrap(),
        storage_sqlite::AttachmentPublishResult::Published
    );
    let shared = RuntimeSharedServices::default();
    let mut admission = Admission::default();

    // No free space: the migration pauses, so the first check is not due.
    test_free_space::set(dir.path(), 0);
    maintenance_tick(&client, &shared, &mut admission).await;
    assert!(app_storage.legacy_attachment_bytes().unwrap() > 0);
    assert!(!admission.compaction_due.load(Ordering::Acquire));
    assert!(!app_storage.database_space().unwrap().incremental);
    assert!(
        admission
            .latches
            .recheck_due
            .is_some_and(|due| due > std::time::Instant::now()),
        "the hourly recheck is not due on the next tick"
    );

    test_free_space::set(dir.path(), 1 << 40);
    maintenance_tick(&client, &shared, &mut admission).await;
    assert_eq!(app_storage.legacy_attachment_bytes().unwrap(), 0);
    assert!(admission.latches.legacy_bodies_done.load(Ordering::Acquire));
    assert!(admission.compaction_attempted, "flagged and compacted");
    assert!(app_storage.database_space().unwrap().incremental);
    test_free_space::clear(dir.path());
}

/// A rolled-back compaction waits 1 minute before its next attempt, then 10
/// minutes; the third rollback ends the attempts for this worker (mdk#2923).
#[test]
fn compaction_rollbacks_are_spaced_1_min_then_10_min() {
    use crate::media::storage_compaction::CompactionAttempt;
    let mut admission = Admission::default();
    let waits = |admission: &Admission| {
        admission
            .compaction_retry_at
            .unwrap()
            .duration_since(std::time::Instant::now())
    };
    admission.record_compaction(CompactionAttempt::RolledBack);
    assert!((Duration::from_secs(59)..=Duration::from_secs(60)).contains(&waits(&admission)));
    assert_eq!(admission.latches.recheck_due, admission.compaction_retry_at);
    admission.record_compaction(CompactionAttempt::RolledBack);
    assert!((Duration::from_secs(599)..=Duration::from_secs(600)).contains(&waits(&admission)));
    let last = admission.compaction_retry_at;
    admission.record_compaction(CompactionAttempt::RolledBack);
    assert!(
        admission.compaction_attempted,
        "the third ends the attempts"
    );
    assert_eq!(admission.compaction_retry_at, last);
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

/// One maintenance tick's storage work, as the worker runs it: the
/// maintenance task (migration batch, reclaim, compaction check), then the
/// compaction the worker waits for only when the task found it due.
async fn maintenance_tick(
    client: &AppClient,
    shared: &RuntimeSharedServices,
    admission: &mut Admission,
) {
    spawn_legacy_migration(client, shared, admission);
    if let Some(task) = admission.legacy_migration.take() {
        task.await.unwrap();
    }
    compact_if_due(client, shared, admission).await;
}

/// A new account database is incremental: the maintenance task never finds
/// a compaction due, so the worker never waits for one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tick_with_nothing_to_compact_does_not_make_the_worker_wait() {
    let (dir, client, storage, _reference) = offline_fixture().await;
    test_free_space::set(dir.path(), 1 << 40);
    assert!(storage.app_storage().database_space().unwrap().incremental);
    let shared = RuntimeSharedServices::default();
    let mut admission = Admission::default();
    maintenance_tick(&client, &shared, &mut admission).await;
    assert!(
        !admission
            .compaction_due
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(!admission.compaction_attempted);
    assert_eq!(admission.compaction_rollbacks, 0);
    test_free_space::clear(dir.path());
}

/// The worker never compacts on its own: without the maintenance task's due
/// flag it does not wait on the blocking pool, even for a database that
/// would qualify. The next full tick raises the flag and compacts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_compacts_only_when_the_maintenance_task_flags_it() {
    let (dir, client, storage, _reference) = offline_fixture().await;
    test_free_space::set(dir.path(), 1 << 40);
    storage
        .app_storage()
        .make_non_incremental_for_test()
        .unwrap();
    {
        let conn = super::retention_fault_connection(&client.app);
        conn.execute_batch(
            "CREATE TABLE compaction_filler(body BLOB NOT NULL);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000)
             INSERT INTO compaction_filler SELECT randomblob(4000) FROM n;
             DROP TABLE compaction_filler;",
        )
        .unwrap();
    }
    let shared = RuntimeSharedServices::default();
    let mut admission = Admission::default();

    compact_if_due(&client, &shared, &mut admission).await;
    assert!(
        !storage.app_storage().database_space().unwrap().incremental,
        "no flag, no compaction"
    );
    assert!(!admission.compaction_attempted);

    maintenance_tick(&client, &shared, &mut admission).await;
    assert!(storage.app_storage().database_space().unwrap().incremental);
    assert!(admission.compaction_attempted);
    test_free_space::clear(dir.path());
}
