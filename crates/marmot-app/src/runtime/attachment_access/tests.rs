use super::*;
use crate::{AttachmentMigrationState, MarmotApp};
use marmot_account::AccountHome;
use sha2::{Digest, Sha256};
use storage_sqlite::{SqliteAccountStorage, SqliteAppStorage};
use storage_sqlite::{StoredAccountGroup, StoredAccountState, StoredAppEvent};
const GROUP: &str = "abababababababababababababababab";
fn group(pending: bool) -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: GROUP.into(),
        endpoint: String::new(),
        profile_name: String::new(),
        profile_description: String::new(),
        image_hash_hex: String::new(),
        image_key_hex: String::new(),
        image_nonce_hex: String::new(),
        image_upload_key_hex: String::new(),
        image_media_type: None,
        admin_keys_hex: String::new(),
        archived: false,
        pending_confirmation: pending,
        member_count: None,
        direct_member_ids_hex: None,
        presentation_member_ids_hex: None,
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
        nostr_routing_last_epoch: 0,
        prior_nostr_routes: vec![],
        self_membership: Default::default(),
        components: vec![storage_sqlite::StoredAccountGroupComponent {
            component_id: crate::NOSTR_ROUTING_COMPONENT_ID,
            component_name: "marmot.group.nostr.routing.v1".into(),
            component_data_hex: hex::encode(
                cgka_traits::app_components::encode_nostr_routing_v1(
                    &cgka_traits::app_components::NostrRoutingV1::new(
                        [0xaa; 32],
                        vec!["wss://relay.example".into()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
        }],
    }
}

fn target() -> AttachmentLocalTarget {
    AttachmentLocalTarget {
        message_id_hex: "aa".repeat(32),
        source_message_id_hex: "bb".repeat(32),
        attachment_index: 0,
    }
}
fn seed(store: &SqliteAppStorage, bytes: &[u8]) {
    seed_at(store, target(), bytes);
}

/// A legacy database body for slot `key`, received at 10.
fn seed_at(store: &SqliteAppStorage, key: AttachmentLocalTarget, bytes: &[u8]) {
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".into(),
                groups: vec![group(false)],
                ..Default::default()
            },
            100,
            300,
        )
        .unwrap();
    store
        .record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(),
            message_id_hex: key.message_id_hex.clone(),
            source_message_id_hex: Some(key.source_message_id_hex),
            source_epoch: Some(3),
            direction: "received".into(),
            sender: "cc".repeat(32),
            plaintext: String::new(),
            kind: 9,
            tags: vec![vec![
                "imeta".into(),
                "m application/octet-stream".into(),
                format!("x {}", hex::encode(Sha256::digest(bytes))),
            ]],
            recorded_at: 10,
            received_at: 10,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    let entry = store
        .attachment_history_page(GROUP, 64, None)
        .unwrap()
        .entries
        .into_iter()
        .find(|entry| entry.message_id_hex == key.message_id_hex)
        .unwrap();
    let now = crate::unix_now_seconds();
    let storage_sqlite::AttachmentDemand::Requested(reference) = store
        .request_attachment_acquisition(GROUP, &entry, Sha256::digest(bytes).into(), now)
        .unwrap()
    else {
        panic!("demand")
    };
    let job = store
        .claim_attachment_acquisition(&reference, now, now + 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, bytes, now, 10_000_000)
            .unwrap(),
        storage_sqlite::AttachmentPublishResult::Published
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_local_access_is_bounded_offline_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![42; MAX_ATTACHMENT_LOCAL_READ_BYTES + 17];
    seed(&store.app_storage(), &body);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let mut stale = target();
    stale.source_message_id_hex = "dd".repeat(32);
    let mut capital = target();
    capital.message_id_hex.make_ascii_uppercase();
    capital.source_message_id_hex.make_ascii_uppercase();
    let assets = runtime
        .attachment_local_assets("alice", &group, vec![capital, stale, target()])
        .await
        .unwrap();
    let asset = assets[0].as_ref().unwrap();
    assert_eq!(asset.byte_count, body.len() as u64);
    assert_eq!(assets[0], assets[2]);
    assert!(assets[1].is_none());
    let reference = asset.reference.clone();
    assert!(
        runtime
            .read_attachment_asset("bob", reference.clone(), 0, 1)
            .await
            .unwrap()
            .is_none()
    );
    for (offset, count) in [
        (0, MAX_ATTACHMENT_LOCAL_READ_BYTES),
        (MAX_ATTACHMENT_LOCAL_READ_BYTES as u64, 17),
        (body.len() as u64, 0),
        (u32::MAX as u64, 0),
    ] {
        let bytes = runtime
            .read_attachment_asset(
                "alice",
                reference.clone(),
                offset,
                MAX_ATTACHMENT_LOCAL_READ_BYTES,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes.len(), count);
        assert!(bytes.iter().all(|b| *b == 42));
    }
    assert!(runtime.accounts.workers.lock().await.is_empty());
    runtime.shutdown_and_close().await.unwrap();
    assert!(
        runtime
            .read_attachment_asset("alice", reference.clone(), 0, 1)
            .await
            .is_err()
    );
    drop(runtime);
    drop(app);
    drop(store);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let runtime = app.runtime();
    let reopened = runtime
        .attachment_local_assets("alice", &group, vec![target()])
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(reopened.reference, reference);
    assert_eq!(
        runtime
            .read_attachment_asset(
                "alice",
                reference.clone(),
                MAX_ATTACHMENT_LOCAL_READ_BYTES as u64,
                100
            )
            .await
            .unwrap()
            .unwrap()
            .len(),
        17
    );
    let store = app.account_storage("alice").unwrap().app_storage();
    store
        .set_group_self_membership(GROUP, storage_sqlite::SelfMembership::Left)
        .unwrap();
    assert!(
        runtime
            .read_attachment_asset("alice", reference.clone(), 0, 1)
            .await
            .unwrap()
            .is_some()
    );
    store
        .remove_local_attachment(GROUP, &target().message_id_hex, 0)
        .unwrap();
    assert!(
        runtime
            .attachment_local_assets("alice", &group, vec![target()])
            .await
            .unwrap()[0]
            .is_none()
    );
    assert!(
        runtime
            .read_attachment_asset("alice", reference, 0, 1)
            .await
            .unwrap()
            .is_none()
    );
    assert!(runtime.accounts.workers.lock().await.is_empty());
    runtime.shutdown_and_close().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_local_access_rejects_unbounded_inputs_without_starting_workers() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed(&store.app_storage(), b"");
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let asset = runtime
        .attachment_local_assets("alice", &group, vec![target()])
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(asset.byte_count, 0);
    assert!(
        runtime
            .read_attachment_asset("alice", asset.reference.clone(), 0, 1)
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert!(
        runtime
            .attachment_local_assets(
                "alice",
                &group,
                vec![target(); MAX_ATTACHMENT_ASSET_LOOKUPS + 1]
            )
            .await
            .is_err()
    );
    let mut invalid = target();
    invalid.message_id_hex = "bad".into();
    assert!(
        runtime
            .attachment_local_assets("alice", &group, vec![invalid])
            .await
            .is_err()
    );
    for (offset, limit) in [
        (0, 0),
        (0, MAX_ATTACHMENT_LOCAL_READ_BYTES + 1),
        (u64::MAX, 1),
    ] {
        assert!(
            runtime
                .read_attachment_asset("alice", asset.reference.clone(), offset, limit)
                .await
                .is_err()
        );
    }
    assert!(
        runtime
            .attachment_local_assets("missing", &group, vec![target()])
            .await
            .is_err()
    );
    store
        .app_storage()
        .invalidate_app_event_by_message_id(
            GROUP,
            &target().message_id_hex,
            "branch_selection_withdrawn",
        )
        .unwrap();
    assert!(
        runtime
            .read_attachment_asset("alice", asset.reference, 0, 1)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .attachment_local_assets("alice", &group, vec![target()])
            .await
            .unwrap()[0]
            .is_none()
    );
    assert!(runtime.accounts.workers.lock().await.is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_progress_stream_observes_removal_without_network_or_erasing_ready_on_cancel() {
    use crate::{AttachmentControl, AttachmentTransferState};
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed(&store.app_storage(), b"retained");
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let stream = runtime
        .subscribe_attachment_transfers("alice", &group, vec![target()])
        .await
        .unwrap();
    let first = stream.next().await.unwrap().unwrap().remove(0).unwrap();
    assert_eq!(first.state, AttachmentTransferState::Ready);
    let reference = first.reference.unwrap();
    assert!(
        !runtime
            .control_attachment("alice", reference.clone(), AttachmentControl::Cancel)
            .await
            .unwrap()
    );
    assert!(
        runtime
            .control_attachment("alice", reference.clone(), AttachmentControl::Remove)
            .await
            .unwrap()
    );
    let update = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(update.state, AttachmentTransferState::Removed);
    assert!(
        runtime
            .read_attachment_asset("alice", reference, 0, 100)
            .await
            .unwrap()
            .is_none()
    );
    stream.close();
    assert!(stream.next().await.unwrap().is_none());
    runtime.shutdown_and_close().await.unwrap();
}

/// Claims the fixture slot's acquisition and publishes `bytes` into the
/// account's media store, as a download does.
fn seed_file_backed(app: &MarmotApp, account: &SqliteAccountStorage, bytes: &[u8]) {
    let store = &account.app_storage();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".into(),
                groups: vec![group(false)],
                ..Default::default()
            },
            100,
            300,
        )
        .unwrap();
    let key = target();
    store
        .record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(),
            message_id_hex: key.message_id_hex.clone(),
            source_message_id_hex: Some(key.source_message_id_hex),
            source_epoch: Some(3),
            direction: "received".into(),
            sender: "cc".repeat(32),
            plaintext: String::new(),
            kind: 9,
            tags: vec![vec![
                "imeta".into(),
                "m application/octet-stream".into(),
                format!("x {}", hex::encode(Sha256::digest(bytes))),
            ]],
            recorded_at: 10,
            received_at: 10,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    let entry = store
        .attachment_history_page(GROUP, 1, None)
        .unwrap()
        .entries
        .remove(0);
    let now = crate::unix_now_seconds();
    let storage_sqlite::AttachmentDemand::Requested(reference) = store
        .request_attachment_acquisition(GROUP, &entry, Sha256::digest(bytes).into(), now)
        .unwrap()
    else {
        panic!("demand")
    };
    let job = store
        .claim_attachment_acquisition(&reference, now, now + 60)
        .unwrap()
        .unwrap();
    let media = app.account_media_store("alice", account).unwrap();
    let clock = crate::unix_now_seconds;
    assert!(matches!(
        media
            .publish(
                &store.attachment_publication(&job, &clock),
                media_store::Category::Retained,
                &mut std::io::Cursor::new(bytes),
                bytes.len() as u64,
                job.plaintext_digest().unwrap(),
                now,
                &|| false,
            )
            .unwrap(),
        media_store::PublishOutcome::Published(_)
    ));
}

fn handoff_entries(app: &MarmotApp) -> usize {
    std::fs::read_dir(crate::media::handoff::handoff_directory(app, "alice"))
        .map(|entries| entries.count())
        .unwrap_or(0)
}

/// A handoff copies a retained body (database or media store layout) into a
/// private file named for the attachment, and only release deletes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handoff_copies_either_layout_into_a_private_file_until_release() {
    for file_backed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let store = app.account_storage("alice").unwrap();
        let body = (0..MAX_ATTACHMENT_LOCAL_READ_BYTES + 4097)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        if file_backed {
            seed_file_backed(&app, &store, &body);
        } else {
            seed(&store.app_storage(), &body);
        }
        let runtime = app.runtime();
        let group = GroupId::new(vec![0xab; 16]);
        let control = std::sync::Arc::new(crate::MediaFileTransferControl::default());
        let handoff = runtime
            .open_attachment_handoff("alice", &group, target(), control.clone())
            .await
            .unwrap()
            .expect("the attachment is held locally");
        assert_eq!(handoff.byte_count, body.len() as u64);
        assert_eq!(handoff.file_name, "attachment.bin");
        assert_eq!(handoff.media_type, "application/octet-stream");
        assert_eq!(control.processed_bytes(), body.len() as u64);
        assert_eq!(
            std::fs::read(&handoff.path).unwrap(),
            body,
            "file_backed={file_backed}"
        );
        assert!(
            handoff
                .path
                .starts_with(app.account_dir("alice").join("handoff"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &std::path::Path| {
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777
            };
            assert_eq!(mode(&handoff.path), 0o600);
            assert_eq!(mode(handoff.path.parent().unwrap()), 0o700);
        }
        // A second lease is a separate copy.
        let second = runtime
            .open_attachment_handoff("alice", &group, target(), Default::default())
            .await
            .unwrap()
            .unwrap();
        assert_ne!(second.lease, handoff.lease);
        assert_eq!(handoff_entries(&app), 2);
        runtime
            .release_attachment_handoff(&handoff.lease)
            .await
            .unwrap();
        assert!(!handoff.path.exists());
        assert!(second.path.exists());
        runtime
            .release_attachment_handoff(&handoff.lease)
            .await
            .unwrap();
        assert!(
            matches!(
                runtime.release_attachment_handoff("not-a-lease").await,
                Err(AppError::InvalidEncryptedMedia(_))
            ),
            "a malformed lease is bad input, not retryable I/O"
        );
        runtime
            .release_attachment_handoff(&second.lease)
            .await
            .unwrap();
        assert_eq!(handoff_entries(&app), 0);
        runtime.shutdown_and_close().await.unwrap();
    }
}

/// A missing attachment yields no lease, a cancelled copy and a full disk
/// leave nothing behind, and a closed runtime refuses new handoffs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handoff_refusals_leave_nothing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed(&store.app_storage(), &[7; 4096]);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let mut absent = target();
    absent.source_message_id_hex = "dd".repeat(32);
    assert!(
        runtime
            .open_attachment_handoff("alice", &group, absent, Default::default())
            .await
            .unwrap()
            .is_none()
    );
    let cancelled = std::sync::Arc::new(crate::MediaFileTransferControl::default());
    cancelled.cancel();
    assert!(
        runtime
            .open_attachment_handoff("alice", &group, target(), cancelled)
            .await
            .is_err()
    );
    crate::media::attachment_resume::test_free_space::set(&app.account_dir("alice"), 1024);
    let full = runtime
        .open_attachment_handoff("alice", &group, target(), Default::default())
        .await
        .unwrap_err();
    assert!(matches!(
        full,
        AppError::Storage(cgka_traits::StorageError::Capacity(_))
    ));
    assert_eq!(handoff_entries(&app), 0);
    // With room again, only the closed runtime refuses.
    crate::media::attachment_resume::test_free_space::set(&app.account_dir("alice"), u64::MAX / 2);
    runtime.shutdown_and_close().await.unwrap();
    let closed = runtime
        .open_attachment_handoff("alice", &group, target(), Default::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            closed,
            AppError::RuntimeStopping | AppError::Storage(cgka_traits::StorageError::Closed(_))
        ),
        "{closed:?}"
    );
    assert_eq!(handoff_entries(&app), 0);
}

/// Abandoning an opening call mid-copy, without cancelling its control (a
/// host coroutine cancelled), leaves neither a copy nor a live lease once
/// the copy task finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abandoned_handoff_leaves_no_copy() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![9u8; 64 * 1024 * 1024];
    seed_file_backed(&app, &store, &body);
    let runtime = app.runtime();
    let control = std::sync::Arc::new(crate::MediaFileTransferControl::default());
    let opening = {
        let (runtime, control) = (runtime.clone(), control.clone());
        tokio::spawn(async move {
            runtime
                .open_attachment_handoff("alice", &GroupId::new(vec![0xab; 16]), target(), control)
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while control.processed_bytes() == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    opening.abort();
    assert!(opening.await.unwrap_err().is_cancelled());
    assert!(
        control.processed_bytes() < body.len() as u64,
        "abandoned while copying"
    );
    let handoffs = crate::media::handoff::handoff_directory(&app, "alice");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while handoff_entries(&app) != 0 || crate::media::handoff::live_leases_under(&handoffs) != 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the abandoned copy and its lease are discarded");
    runtime.shutdown_and_close().await.unwrap();
}

/// A copy that finished while its opening call was not being polled (the
/// result is stored, not yet collected) is discarded when that call is
/// dropped, with its lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finished_but_uncollected_handoff_is_discarded() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![5u8; 4096];
    seed(&store.app_storage(), &body);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let control = std::sync::Arc::new(crate::MediaFileTransferControl::default());
    let mut opening =
        Box::pin(runtime.open_attachment_handoff("alice", &group, target(), control.clone()));
    assert!(futures::poll!(&mut opening).is_pending());
    let handoffs = crate::media::handoff::handoff_directory(&app, "alice");
    // The copy completes on the blocking pool while nobody polls the call.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while control.processed_bytes() < body.len() as u64 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        handoff_entries(&app),
        1,
        "the finished copy waits to be collected"
    );
    drop(opening);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while handoff_entries(&app) != 0 || crate::media::handoff::live_leases_under(&handoffs) != 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the uncollected copy and its lease are discarded");
    runtime.shutdown_and_close().await.unwrap();
}

/// A symlinked handoff directory is refused, never followed: no plaintext
/// lands outside the account directory.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_symlinked_handoff_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed(&store.app_storage(), &[3; 2048]);
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(
        &elsewhere,
        crate::media::handoff::handoff_directory(&app, "alice"),
    )
    .unwrap();
    let runtime = app.runtime();
    assert!(
        runtime
            .open_attachment_handoff(
                "alice",
                &GroupId::new(vec![0xab; 16]),
                target(),
                Default::default()
            )
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nothing written through the link"
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// A copy admitted just before its account was removed (the account
/// directory already renamed away) fails instead of recreating the account
/// directory, and leaves no lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handoff_never_recreates_a_removed_account_directory() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed(&store.app_storage(), &[4; 2048]);
    let source = crate::media::handoff::HandoffSource::find(&store, GROUP, &target(), false)
        .unwrap()
        .expect("admitted");
    let account_dir = app.account_dir("alice");
    let tombstone = dir.path().join("removed-alice");
    // What account removal does after admission: the directory moves away.
    std::fs::rename(&account_dir, &tombstone).unwrap();
    let control = crate::MediaFileTransferControl::default();
    assert!(crate::media::handoff::open(&app, "alice", &store, source, &control).is_err());
    assert!(
        !account_dir.exists(),
        "the removed account directory is not recreated"
    );
    assert_eq!(
        crate::media::handoff::live_leases_under(&account_dir),
        0,
        "no lease survives"
    );
    std::fs::rename(&tombstone, &account_dir).unwrap();
}

/// A handoff admitted on a storage handle that account removal then evicted
/// (with the account reopened at the same path, as a re-import does) never
/// writes into the new account's directory or hands out a lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handoff_on_an_evicted_handle_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let old = app.account_storage("alice").unwrap();
    seed(&old.app_storage(), &[6; 2048]);
    let source = crate::media::handoff::HandoffSource::find(&old, GROUP, &target(), false)
        .unwrap()
        .expect("admitted");
    // Removal evicts the handle; the account then reopens at the same path.
    app.drop_account_caches("alice");
    let reopened = app.account_storage("alice").unwrap();
    assert!(!reopened.shares_connection_with(&old));
    let control = crate::MediaFileTransferControl::default();
    let refused = crate::media::handoff::open(&app, "alice", &old, source, &control).unwrap_err();
    assert!(matches!(
        refused,
        AppError::Storage(cgka_traits::StorageError::Closed(_))
    ));
    assert_eq!(
        handoff_entries(&app),
        0,
        "nothing written into the reopened account"
    );
    assert_eq!(
        crate::media::handoff::live_leases_under(&app.account_dir("alice")),
        0
    );
}

/// Files under the account's media store directory.
fn media_files_on_disk(app: &MarmotApp) -> usize {
    fn walk(path: &std::path::Path) -> usize {
        std::fs::read_dir(path)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| {
                        if entry.file_type().unwrap().is_dir() {
                            walk(&entry.path())
                        } else {
                            1
                        }
                    })
                    .sum()
            })
            .unwrap_or(0)
    }
    walk(&app.account_dir("alice").join(media_store::MEDIA_DIRECTORY))
}

/// Manage storage reports a file-backed attachment, and removing its chat
/// frees the file at once, without waiting for the sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manage_storage_reports_and_frees_a_chat_at_once() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![8u8; 96 * 1024];
    seed_file_backed(&app, &store, &body);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);

    let usage = runtime.attachment_storage_usage("alice").await.unwrap();
    assert_eq!(usage.media_bytes, body.len() as u64);
    assert_eq!(usage.attachment_count, 1);
    let chats = runtime
        .attachment_storage_by_chat("alice", None, 8)
        .await
        .unwrap();
    assert_eq!(
        chats
            .iter()
            .map(|chat| (chat.group_id_hex.as_str(), chat.bytes))
            .collect::<Vec<_>>(),
        vec![(GROUP, body.len() as u64)]
    );
    let largest = runtime
        .largest_retained_attachments("alice", Some(&group), None, 8)
        .await
        .unwrap();
    assert_eq!(largest.len(), 1);
    assert_eq!(largest[0].byte_count, body.len() as u64);
    assert_eq!(largest[0].target.message_id_hex, target().message_id_hex);
    assert_eq!(largest[0].group_id_hex, GROUP);

    assert_eq!(media_files_on_disk(&app), 1);
    assert_eq!(
        runtime
            .remove_chat_attachments("alice", &group)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        media_files_on_disk(&app),
        0,
        "freed before the call returns"
    );
    assert_eq!(
        runtime
            .attachment_storage_usage("alice")
            .await
            .unwrap()
            .attachment_count,
        0
    );
    assert!(
        runtime
            .attachment_local_assets("alice", &group, vec![target()])
            .await
            .unwrap()[0]
            .is_none()
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// The single explicit Remove also unlinks a released file at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_remove_unlinks_a_released_file_at_once() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed_file_backed(&app, &store, &[9u8; 4096]);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let asset = runtime
        .attachment_local_assets("alice", &group, vec![target()])
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(media_files_on_disk(&app), 1);
    assert!(
        runtime
            .control_attachment("alice", asset.reference, crate::AttachmentControl::Remove)
            .await
            .unwrap()
    );
    assert_eq!(media_files_on_disk(&app), 0);
    runtime.shutdown_and_close().await.unwrap();
}

/// A Remove whose media store cannot open (its storage handle was evicted)
/// fails before anything is removed: the attachment and its file stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remove_that_cannot_open_the_store_removes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let old = app.account_storage("alice").unwrap();
    seed_file_backed(&app, &old, &[9u8; 4096]);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let asset = runtime
        .attachment_local_assets("alice", &group, vec![target()])
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    app.drop_account_caches("alice");
    let refused =
        crate::runtime::attachment_controls::remove_now(&app, "alice", &old, &asset.reference)
            .unwrap_err();
    assert!(matches!(
        refused,
        AppError::Storage(cgka_traits::StorageError::Closed(_))
    ));
    assert_eq!(media_files_on_disk(&app), 1, "the file stays");
    assert!(
        runtime
            .attachment_local_assets("alice", &group, vec![target()])
            .await
            .unwrap()[0]
            .is_some(),
        "the attachment is still retained"
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// Removal by age uses the message's received time and works on legacy
/// database bodies too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removal_by_age_covers_legacy_bodies() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![5u8; 3000];
    // The fixture message was received at 10.
    seed(&store.app_storage(), &body);
    let runtime = app.runtime();
    let usage = runtime.attachment_storage_usage("alice").await.unwrap();
    assert_eq!(
        (usage.legacy_bytes, usage.attachment_count),
        (body.len() as u64, 1)
    );
    assert_eq!(
        runtime
            .remove_attachments_older_than("alice", 10, None)
            .await
            .unwrap(),
        0,
        "received at 10 is not before 10"
    );
    assert_eq!(
        runtime
            .remove_attachments_older_than("alice", 11, None)
            .await
            .unwrap(),
        1
    );
    let usage = runtime.attachment_storage_usage("alice").await.unwrap();
    assert_eq!((usage.legacy_bytes, usage.attachment_count), (0, 0));
    runtime.shutdown_and_close().await.unwrap();
}

/// Choosing a "Keep media" window removes what is already past it before the
/// call returns, freeing the file at once, and the attachment shows as
/// cleaned by the setting. Forever removes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_media_cleans_past_the_window_at_once() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    // The fixture message was received at 10, long before any window.
    seed_file_backed(&app, &store, &[6u8; 8192]);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    assert_eq!(
        runtime.attachment_keep_media("alice").await.unwrap(),
        crate::AttachmentKeepMedia::Forever
    );
    assert_eq!(
        runtime
            .set_attachment_keep_media("alice", crate::AttachmentKeepMedia::Forever)
            .await
            .unwrap(),
        0
    );
    assert_eq!(media_files_on_disk(&app), 1);

    assert_eq!(
        runtime
            .set_attachment_keep_media("alice", crate::AttachmentKeepMedia::SixMonths)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        runtime.attachment_keep_media("alice").await.unwrap(),
        crate::AttachmentKeepMedia::SixMonths
    );
    assert_eq!(
        media_files_on_disk(&app),
        0,
        "freed before the call returns"
    );
    let status = runtime
        .attachment_transfer_snapshot("alice", &group, vec![target()])
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(
        status.state,
        crate::AttachmentTransferState::CleanedBySetting
    );
    runtime.shutdown_and_close().await.unwrap();
}

// Moving legacy bodies into the media store (mdk#2314 step 6).

/// A second connection to alice's database, for damaging rows directly.
fn raw_connection(app: &MarmotApp) -> rusqlite::Connection {
    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

fn legacy_slot(n: u8) -> AttachmentLocalTarget {
    AttachmentLocalTarget {
        message_id_hex: format!("{n:02x}").repeat(32),
        source_message_id_hex: format!("{n:02x}").repeat(32),
        attachment_index: 0,
    }
}

/// One migration batch with `free` bytes free on the volume and a 1 KiB
/// reserve, recorded where the usage summary reads it. Whether attachment
/// observers would wake.
fn migrate_legacy(app: &MarmotApp, store: &SqliteAccountStorage, free: u64) -> bool {
    let media = app.account_media_store("alice", store).unwrap();
    crate::media::legacy_migration::run_batch(
        &store.app_storage(),
        &media,
        1024,
        &|| Ok(free),
        &app.legacy_media_migration("alice"),
    )
}

/// The whole retained body at `target`, read the way a host does.
async fn read_whole(runtime: &MarmotAppRuntime, target: AttachmentLocalTarget) -> Option<Vec<u8>> {
    let group = GroupId::new(vec![0xab; 16]);
    let asset = runtime
        .attachment_local_assets("alice", &group, vec![target])
        .await
        .unwrap()
        .remove(0)?;
    let mut body = Vec::new();
    loop {
        let window = runtime
            .read_attachment_asset(
                "alice",
                asset.reference.clone(),
                body.len() as u64,
                MAX_ATTACHMENT_LOCAL_READ_BYTES,
            )
            .await
            .unwrap()?;
        if window.is_empty() {
            return Some(body);
        }
        body.extend_from_slice(&window);
    }
}

/// Legacy bodies move into store files, stay readable, and the usage summary
/// follows the move from running to complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_bodies_move_into_the_media_store_and_usage_reports_completion() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let small = vec![1u8; 3000];
    let large = vec![2u8; 200_000];
    seed_at(&store.app_storage(), legacy_slot(0x11), &small);
    seed_at(&store.app_storage(), legacy_slot(0x12), &large);
    let runtime = app.runtime();
    assert_eq!(
        runtime
            .attachment_storage_usage("alice")
            .await
            .unwrap()
            .migration,
        AttachmentMigrationState::Running {
            remaining_bytes: 203_000
        }
    );

    assert!(
        migrate_legacy(&app, &store, u64::MAX / 2),
        "completion is news"
    );
    let usage = runtime.attachment_storage_usage("alice").await.unwrap();
    assert_eq!(usage.migration, AttachmentMigrationState::Complete);
    assert_eq!((usage.legacy_bytes, usage.media_bytes), (0, 203_000));
    assert_eq!(media_files_on_disk(&app), 2);
    assert_eq!(
        read_whole(&runtime, legacy_slot(0x11)).await.unwrap(),
        small
    );
    assert_eq!(
        read_whole(&runtime, legacy_slot(0x12)).await.unwrap(),
        large
    );
    assert!(
        !migrate_legacy(&app, &store, u64::MAX / 2),
        "already announced"
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// An account that never had legacy bodies has nothing to move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_account_without_legacy_bodies_needs_no_migration() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed_file_backed(&app, &store, &[3u8; 4096]);
    assert!(!migrate_legacy(&app, &store, u64::MAX / 2));
    let runtime = app.runtime();
    assert_eq!(
        runtime
            .attachment_storage_usage("alice")
            .await
            .unwrap()
            .migration,
        AttachmentMigrationState::NotNeeded
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// On a tight disk the move takes what fits (smallest first), pauses with
/// the space it still needs, and keeps the rest in the database. Pruning the
/// body that does not fit lets it finish; nothing is dropped to make room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tight_disk_pauses_the_move_until_the_user_prunes() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let small = vec![4u8; 2000];
    let large = vec![5u8; 100_000];
    seed_at(&store.app_storage(), legacy_slot(0x21), &small);
    seed_at(&store.app_storage(), legacy_slot(0x22), &large);
    let runtime = app.runtime();

    // Room for the reserve and the small body's store file, 10 bytes short
    // of the large one's.
    let free = 1024 + media_store::DiskPolicy::migration_need(100_000) - 10;
    assert!(migrate_legacy(&app, &store, free), "the pause is news");
    assert_eq!(
        runtime
            .attachment_storage_usage("alice")
            .await
            .unwrap()
            .migration,
        AttachmentMigrationState::Paused { needed_bytes: 10 }
    );
    assert!(!migrate_legacy(&app, &store, free), "still paused");
    assert_eq!(media_files_on_disk(&app), 1);
    assert_eq!(
        read_whole(&runtime, legacy_slot(0x21)).await.unwrap(),
        small
    );
    assert_eq!(
        read_whole(&runtime, legacy_slot(0x22)).await.unwrap(),
        large,
        "the body that did not fit stays readable from the database"
    );

    let group = GroupId::new(vec![0xab; 16]);
    let asset = runtime
        .attachment_local_assets("alice", &group, vec![legacy_slot(0x22)])
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert!(
        runtime
            .control_attachment("alice", asset.reference, crate::AttachmentControl::Remove)
            .await
            .unwrap()
    );
    assert!(migrate_legacy(&app, &store, free), "resumed and finished");
    let usage = runtime.attachment_storage_usage("alice").await.unwrap();
    assert_eq!(usage.migration, AttachmentMigrationState::Complete);
    assert_eq!(usage.legacy_bytes, 0);
    runtime.shutdown_and_close().await.unwrap();
}

/// A legacy body that fails its digest is dropped, its slot becomes
/// unavailable with download-again allowed, and the move continues.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_corrupt_legacy_body_is_dropped_and_the_move_continues() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let damaged = vec![6u8; 150_000];
    let intact = vec![7u8; 160_000];
    seed_at(&store.app_storage(), legacy_slot(0x31), &damaged);
    seed_at(&store.app_storage(), legacy_slot(0x32), &intact);
    {
        let conn = raw_connection(&app);
        conn.execute_batch("DROP TRIGGER attachment_file_chunk_update_immutable;")
            .unwrap();
        conn.execute(
            "UPDATE retained_attachment_chunks SET bytes=zeroblob(length(bytes))
             WHERE offset=0 AND token=(SELECT nonce FROM retained_attachment_files
                 WHERE byte_len=150000)",
            [],
        )
        .unwrap();
    }
    let runtime = app.runtime();
    let media = app.account_media_store("alice", &store).unwrap();
    assert_eq!(
        crate::media::legacy_migration::migrate_batch(
            &store.app_storage(),
            &media,
            0,
            &|| Ok(u64::MAX / 2),
            crate::unix_now_seconds(),
        ),
        crate::media::legacy_migration::LegacyMigrationBatch::Progress {
            moved: 1,
            moved_bytes: 160_000,
            dropped_corrupt: 1,
            more: false,
        }
    );
    assert_eq!(media_files_on_disk(&app), 1);
    assert_eq!(
        read_whole(&runtime, legacy_slot(0x32)).await.unwrap(),
        intact
    );
    assert_eq!(read_whole(&runtime, legacy_slot(0x31)).await, None);
    let group = GroupId::new(vec![0xab; 16]);
    let status = runtime
        .attachment_transfer_snapshot("alice", &group, vec![legacy_slot(0x31)])
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(
        status.state,
        storage_sqlite::AttachmentTransferState::PreviouslyAcquiredUnavailable
    );
    assert_eq!(
        runtime
            .attachment_storage_usage("alice")
            .await
            .unwrap()
            .legacy_bytes,
        0
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// A move interrupted after its publish, before the rows were dropped, is
/// finished by the next batch without writing a second file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_move_is_finished_without_a_second_copy() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![8u8; 70_000];
    seed_at(&store.app_storage(), legacy_slot(0x41), &body);
    let media = app.account_media_store("alice", &store).unwrap();
    let app_storage = store.app_storage();
    let legacy = app_storage.legacy_attachment_bodies(8).unwrap().remove(0);
    assert!(matches!(
        media
            .publish(
                &app_storage.legacy_attachment_publication(&legacy),
                media_store::Category::Retained,
                &mut app_storage.legacy_attachment_reader(&legacy),
                legacy.byte_len(),
                legacy.digest().unwrap(),
                crate::unix_now_seconds(),
                &|| false,
            )
            .unwrap(),
        media_store::PublishOutcome::Published(_)
    ));

    assert!(migrate_legacy(&app, &store, u64::MAX / 2));
    assert_eq!(media_files_on_disk(&app), 1);
    assert_eq!(app_storage.legacy_attachment_bytes().unwrap(), 0);
    let runtime = app.runtime();
    assert_eq!(read_whole(&runtime, legacy_slot(0x41)).await.unwrap(), body);
    runtime.shutdown_and_close().await.unwrap();
}

/// Flips the last byte of every media file: the length, header and
/// therefore an open still succeed, but the last segment no longer
/// authenticates.
fn damage_media_files(app: &MarmotApp) {
    let root = app.account_dir("alice").join(media_store::MEDIA_DIRECTORY);
    for shard in std::fs::read_dir(root).unwrap() {
        for file in std::fs::read_dir(shard.unwrap().path()).unwrap() {
            let path = file.unwrap().path();
            let mut bytes = std::fs::read(&path).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            std::fs::write(&path, bytes).unwrap();
        }
    }
}

/// An interrupted move whose file was damaged afterwards keeps the database
/// copy: the file is read in full before the rows go, and a fresh file is
/// written from them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_move_with_a_damaged_file_moves_again_from_the_rows() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![9u8; 150_000];
    seed_at(&store.app_storage(), legacy_slot(0x51), &body);
    let media = app.account_media_store("alice", &store).unwrap();
    let app_storage = store.app_storage();
    let legacy = app_storage.legacy_attachment_bodies(8).unwrap().remove(0);
    media
        .publish(
            &app_storage.legacy_attachment_publication(&legacy),
            media_store::Category::Retained,
            &mut app_storage.legacy_attachment_reader(&legacy),
            legacy.byte_len(),
            legacy.digest().unwrap(),
            crate::unix_now_seconds(),
            &|| false,
        )
        .unwrap();
    damage_media_files(&app);

    assert!(migrate_legacy(&app, &store, u64::MAX / 2));
    assert_eq!(app_storage.legacy_attachment_bytes().unwrap(), 0);
    let runtime = app.runtime();
    assert_eq!(read_whole(&runtime, legacy_slot(0x51)).await.unwrap(), body);
    runtime.shutdown_and_close().await.unwrap();
}

/// A stored twin that does not read back is never trusted in place of the
/// database copy: the batch keeps the rows, and the next one writes a fresh
/// file from them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_damaged_stored_twin_does_not_replace_the_database_copy() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![10u8; 150_000];
    seed_file_backed(&app, &store, &body);
    seed_at(&store.app_storage(), legacy_slot(0x52), &body);
    damage_media_files(&app);
    let runtime = app.runtime();

    migrate_legacy(&app, &store, u64::MAX / 2);
    assert_eq!(
        store.app_storage().legacy_attachment_bytes().unwrap(),
        body.len() as u64,
        "the rows stay while the twin fails"
    );
    assert_eq!(read_whole(&runtime, legacy_slot(0x52)).await.unwrap(), body);

    assert!(migrate_legacy(&app, &store, u64::MAX / 2));
    assert_eq!(store.app_storage().legacy_attachment_bytes().unwrap(), 0);
    assert_eq!(read_whole(&runtime, legacy_slot(0x52)).await.unwrap(), body);
    runtime.shutdown_and_close().await.unwrap();
}

// Returning freed database pages to the filesystem (mdk#2314 step 6).

/// Runs the maintenance pass the worker runs after a migration batch, with
/// plenty of free disk. Whether it woke observers.
/// The worker's compaction step with plenty of free disk: whether it was
/// attempted, and whether it woke observers.
fn compact_if_due(app: &MarmotApp, store: &SqliteAccountStorage) -> (bool, bool) {
    let woke = std::sync::atomic::AtomicBool::new(false);
    let attempted = crate::media::storage_compaction::compact_if_due(
        &store.app_storage(),
        1024,
        &|| Ok(u64::MAX / 2),
        &app.legacy_media_migration("alice"),
        &|| woke.store(true, std::sync::atomic::Ordering::Release),
    );
    (
        attempted == crate::media::storage_compaction::CompactionAttempt::Done,
        woke.load(std::sync::atomic::Ordering::Acquire),
    )
}

/// Once moved legacy bodies leave enough free pages, the database is
/// compacted once: it shrinks on disk, switches to incremental mode, and
/// keeps every attachment readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moved_legacy_bodies_are_compacted_out_of_the_database() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    // An account created before new databases started incremental.
    store.app_storage().make_non_incremental_for_test().unwrap();
    let body = vec![11u8; 6_000_000];
    seed_at(&store.app_storage(), legacy_slot(0x61), &body);
    assert!(migrate_legacy(&app, &store, u64::MAX / 2));
    let before = store.app_storage().database_space().unwrap();
    assert!(!before.incremental);
    assert!(before.free_bytes() >= 6_000_000);

    assert_eq!(
        compact_if_due(&app, &store),
        (true, true),
        "start and end wake observers"
    );
    let after = store.app_storage().database_space().unwrap();
    assert!(after.incremental);
    assert!(after.file_bytes() + 6_000_000 <= before.file_bytes());
    assert_eq!(compact_if_due(&app, &store), (false, false), "only once");
    let runtime = app.runtime();
    let usage = runtime.attachment_storage_usage("alice").await.unwrap();
    assert_eq!(usage.migration, AttachmentMigrationState::Complete);
    assert_eq!(usage.database_free_bytes, 0);
    assert_eq!(read_whole(&runtime, legacy_slot(0x61)).await.unwrap(), body);
    runtime.shutdown_and_close().await.unwrap();
}

/// While the database compacts, usage answers from the snapshot taken just
/// before, as `Compacting`, without waiting for the connection the `VACUUM`
/// holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usage_reports_compacting_from_its_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed_at(&store.app_storage(), legacy_slot(0x62), &[1u8; 2000]);
    let snapshot = store
        .app_storage()
        .attachment_storage_usage(crate::unix_now_seconds())
        .unwrap();
    app.legacy_media_migration("alice")
        .lock()
        .unwrap()
        .compacting = Some(snapshot.clone());
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = store.app_storage();
    let holding =
        std::thread::spawn(move || holder.hold_connection_for_test(&held_tx, &release_rx));
    held_rx.recv().unwrap();
    let runtime = app.runtime();
    let usage = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        runtime.attachment_storage_usage("alice"),
    )
    .await
    .expect("usage does not wait for the held connection")
    .unwrap();
    assert_eq!(usage.migration, AttachmentMigrationState::Compacting);
    assert_eq!(usage.legacy_bytes, snapshot.legacy_bytes);
    release_tx.send(()).unwrap();
    holding.join().unwrap();
    app.legacy_media_migration("alice")
        .lock()
        .unwrap()
        .compacting = None;
    assert!(matches!(
        runtime
            .attachment_storage_usage("alice")
            .await
            .unwrap()
            .migration,
        AttachmentMigrationState::Running { .. }
    ));
    runtime.shutdown_and_close().await.unwrap();
}

/// After compaction, a bulk removal of legacy bodies returns their pages
/// before the call returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_removal_reclaims_pages_once_the_database_is_incremental() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    store.app_storage().compact_database().unwrap();
    seed_at(
        &store.app_storage(),
        legacy_slot(0x63),
        &vec![12u8; 3_000_000],
    );
    let runtime = app.runtime();
    assert_eq!(
        runtime
            .remove_attachments_older_than("alice", 11, None)
            .await
            .unwrap(),
        1
    );
    assert_eq!(store.app_storage().database_space().unwrap().free_pages, 0);
    runtime.shutdown_and_close().await.unwrap();
}

/// Closing storage (a host about to suspend) does not wait out a compaction,
/// even when a media sweep is blocked behind it holding its store's sweep
/// lock, which the media store's close takes before the databases close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_storage_cuts_short_a_compaction_with_a_sweep_behind_it() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed_file_backed(&app, &store, &[4u8; 4096]);
    let media = app.account_media_store("alice", &store).unwrap();

    let (paused_tx, paused_rx) = std::sync::mpsc::channel();
    let compacting = store.app_storage();
    // A real compaction, paused after its closing check and before its copy:
    // the close below begins in exactly that window.
    let compaction = std::thread::spawn(move || {
        let probe = compacting.clone();
        compacting.compact_database_pausing_for_test(&|| {
            let _ = paused_tx.send(());
            while !probe.is_closing_for_test() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })
    });
    paused_rx.recv().unwrap();
    let sweep = std::thread::spawn(move || media.sweep(256));
    // Let the sweep take its lock and block on the held connection.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let closing_app = app.clone();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = closed_tx.send(closing_app.close_storage());
    });
    let closed = closed_rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("close_storage finished without waiting out the compaction");
    assert!(closed.is_ok());
    assert!(compaction.join().unwrap().is_err(), "the copy stopped");
    assert!(sweep.join().unwrap().is_err(), "the sweep failed as closed");
}

/// A WAL truncate owed when an earlier process ended is recorded nowhere: the
/// first maintenance pass of a worker truncates once on an incremental
/// database, while later passes leave a WAL with nothing owed alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_maintenance_pass_settles_a_leftover_wal() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    assert!(store.app_storage().compact_database().unwrap());
    // Leave frames in the WAL, as a crash after a blocked truncate would.
    seed_at(&store.app_storage(), legacy_slot(0x71), &[5u8; 20_000]);
    let wal = || {
        let mut path = app.account_storage_path("alice").into_os_string();
        path.push("-wal");
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    };
    assert!(wal() > 0);
    assert!(!store.app_storage().wal_truncate_pending());

    assert!(crate::media::storage_compaction::reclaim(
        &store.app_storage(),
        false
    ));
    assert!(wal() > 0, "nothing owed, nothing truncated");
    assert!(
        crate::media::storage_compaction::reclaim(&store.app_storage(), true),
        "settled"
    );
    assert_eq!(wal(), 0, "the first pass truncated");
    let runtime = app.runtime();
    runtime.shutdown_and_close().await.unwrap();
}
