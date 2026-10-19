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
