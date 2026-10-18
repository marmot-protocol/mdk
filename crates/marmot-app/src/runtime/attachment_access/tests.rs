use super::*;
use crate::MarmotApp;
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
            message_id_hex: key.message_id_hex,
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
            message_id_hex: key.message_id_hex,
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
