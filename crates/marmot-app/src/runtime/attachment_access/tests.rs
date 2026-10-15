use super::*;
use crate::MarmotApp;
use marmot_account::AccountHome;
use sha2::{Digest, Sha256};
use storage_sqlite::{
    SqliteAccountStorage, StoredAccountGroup, StoredAccountState, StoredAppEvent,
};
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
/// Seed one explicit transfer for `bytes` and complete it, so its row is Ready.
fn seed(store: &SqliteAccountStorage, bytes: &[u8]) {
    let job = seed_downloading(store, bytes);
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, bytes, crate::unix_now_seconds(), 10_000_000)
            .unwrap(),
        storage_sqlite::AttachmentPublishResult::Published
    );
}

/// Seed one explicit transfer for `bytes` and claim it, so its row is Downloading.
fn seed_downloading(
    store: &SqliteAccountStorage,
    bytes: &[u8],
) -> storage_sqlite::AttachmentAcquisition {
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
    store
        .claim_attachment_acquisition(&reference, now, now + 60)
        .unwrap()
        .unwrap()
}
#[tokio::test]
async fn attachment_local_access_is_bounded_offline_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let body = vec![42; MAX_ATTACHMENT_LOCAL_READ_BYTES + 17];
    seed(&store, &body);
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
    let store = app.account_storage("alice").unwrap();
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
#[tokio::test]
async fn attachment_local_access_rejects_unbounded_inputs_without_starting_workers() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed(&store, b"");
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

#[tokio::test]
async fn attachment_progress_stream_observes_removal_without_network_or_erasing_ready_on_cancel() {
    use crate::{AttachmentControl, AttachmentTransferState};
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    seed(&store, b"retained");
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

/// Opens a runtime over one claimed transfer and returns its subscription after the
/// initial Downloading frame.
async fn downloading_subscription(
    dir: &tempfile::TempDir,
    bytes: &[u8],
) -> (
    crate::MarmotAppRuntime,
    SqliteAccountStorage,
    storage_sqlite::AttachmentAcquisition,
    std::sync::Arc<crate::RuntimeAttachmentTransferSubscription>,
) {
    use crate::AttachmentTransferState;
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = app.account_storage("alice").unwrap();
    let job = seed_downloading(&store, bytes);
    let runtime = app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let stream = runtime
        .subscribe_attachment_transfers("alice", &group, vec![target()])
        .await
        .unwrap();
    let first = stream.next().await.unwrap().unwrap().remove(0).unwrap();
    assert_eq!(first.state, AttachmentTransferState::Downloading);
    (runtime, store, job, stream)
}

/// Writes byte progress for `job` and wakes subscribers, as the worker does.
fn report_progress(
    runtime: &crate::MarmotAppRuntime,
    store: &SqliteAccountStorage,
    job: &storage_sqlite::AttachmentAcquisition,
    received: u64,
) {
    assert!(
        store
            .update_attachment_progress(
                job,
                crate::unix_now_seconds(),
                1,
                received,
                Some(1 << 20),
                false
            )
            .unwrap()
    );
    runtime.shared.attachment_updates.send_modify(|_| {});
}

/// Publishes `job` and wakes subscribers, as the worker does after a download.
fn report_ready(
    runtime: &crate::MarmotAppRuntime,
    store: &SqliteAccountStorage,
    job: &storage_sqlite::AttachmentAcquisition,
    bytes: &[u8],
) {
    assert_eq!(
        store
            .complete_attachment_acquisition(job, bytes, crate::unix_now_seconds(), 10_000_000)
            .unwrap(),
        storage_sqlite::AttachmentPublishResult::Published
    );
    runtime.shared.attachment_updates.send_modify(|_| {});
}

/// Asserts a frame reported at `reported` arrived without waiting out the
/// progress window that opened at `opened`. When the report itself ran most of
/// the window, a held frame and a prompt one cannot be told apart, so only a
/// prompt report is timed.
fn assert_not_held(
    opened: std::time::Instant,
    reported: std::time::Instant,
    arrived: std::time::Instant,
) {
    if reported - opened < std::time::Duration::from_millis(120) {
        assert!(
            arrived - reported < std::time::Duration::from_millis(110),
            "frame arrived {:?} after its report, {:?} into the window",
            arrived - reported,
            arrived - opened
        );
    }
}

/// Waits for the next frame of `stream` and returns its only row.
async fn next_row(
    stream: &crate::RuntimeAttachmentTransferSubscription,
) -> crate::AttachmentTransferStatus {
    tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .remove(0)
        .unwrap()
}

/// mdk#2157: a transfer that becomes Ready right after the previous frame is
/// delivered at once, not up to 250 ms later.
#[tokio::test]
async fn attachment_transfer_state_change_skips_the_progress_window() {
    use crate::AttachmentTransferState;
    let dir = tempfile::tempdir().unwrap();
    let (runtime, store, job, stream) = downloading_subscription(&dir, b"prompt").await;
    let opened = std::time::Instant::now();
    report_ready(&runtime, &store, &job, b"prompt");
    let reported = std::time::Instant::now();
    let ready = next_row(&stream).await;
    assert_eq!(ready.state, AttachmentTransferState::Ready);
    assert_not_held(opened, reported, std::time::Instant::now());
    stream.close();
    runtime.shutdown_and_close().await.unwrap();
}

/// Byte progress alone is still coalesced: with a write every 20 ms, frames
/// that only advance progress stay close to the window apart.
#[tokio::test]
async fn attachment_progress_only_frames_stay_coalesced() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, store, job, stream) = downloading_subscription(&dir, b"progress").await;
    let writer = {
        let (runtime, store, job) = (runtime.clone(), store.clone(), job.clone());
        tokio::spawn(async move {
            for step in 1..=60u64 {
                report_progress(&runtime, &store, &job, step * 1024);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
    };
    let started = std::time::Instant::now();
    let mut arrivals = vec![started];
    while let Ok(frame) = tokio::time::timeout(
        std::time::Duration::from_millis(1_300).saturating_sub(started.elapsed()),
        stream.next(),
    )
    .await
    {
        let row = frame.unwrap().unwrap().remove(0).unwrap();
        assert_eq!(row.state, crate::AttachmentTransferState::Downloading);
        arrivals.push(std::time::Instant::now());
    }
    writer.await.unwrap();
    assert!(
        arrivals.len() >= 3,
        "expected some progress frames: {arrivals:?}"
    );
    // Uncoalesced frames would follow the 20 ms writes; the slack below the
    // 250 ms window absorbs a loaded runner timing a frame late.
    for pair in arrivals.windows(2) {
        assert!(
            pair[1] - pair[0] >= std::time::Duration::from_millis(175),
            "progress frames {:?} apart",
            pair[1] - pair[0]
        );
    }
    stream.close();
    runtime.shutdown_and_close().await.unwrap();
}

/// A state change that lands while a read progress frame waits out the window
/// is delivered at once, and no stale progress frame follows it.
#[tokio::test]
async fn attachment_terminal_frame_is_not_held_behind_progress() {
    use crate::AttachmentTransferState;
    let dir = tempfile::tempdir().unwrap();
    let (runtime, store, job, stream) = downloading_subscription(&dir, b"terminal").await;
    let opened = std::time::Instant::now();
    let pending = tokio::spawn({
        let stream = stream.clone();
        async move { next_row(&stream).await }
    });
    report_progress(&runtime, &store, &job, 1024);
    // The pending call reads this progress and holds it for the window.
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    report_ready(&runtime, &store, &job, b"terminal");
    let reported = std::time::Instant::now();
    let next = pending.await.unwrap();
    assert_eq!(next.state, AttachmentTransferState::Ready);
    assert_not_held(opened, reported, std::time::Instant::now());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(400), stream.next())
            .await
            .is_err(),
        "a frame followed the terminal one"
    );
    stream.close();
    runtime.shutdown_and_close().await.unwrap();
}

/// A state change that lands while a presentation wake waits out its spacing
/// is read at once rather than at the end of that spacing.
#[tokio::test]
async fn attachment_state_change_is_not_held_behind_presentation_churn() {
    use crate::AttachmentTransferState;
    let dir = tempfile::tempdir().unwrap();
    let (runtime, store, job, stream) = downloading_subscription(&dir, b"churn").await;
    let opened = std::time::Instant::now();
    let pending = tokio::spawn({
        let stream = stream.clone();
        async move { next_row(&stream).await }
    });
    let _ = runtime.accounts.app.presentation_signals.updates.send(
        crate::chat_presentation::signals::PresentationInvalidation {
            account_label: "alice".into(),
            version: storage_sqlite::ChatPresentationVersion {
                store_epoch: Vec::new(),
                revision: 1,
            },
        },
    );
    // The pending call takes the presentation wake and waits out its spacing.
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    report_ready(&runtime, &store, &job, b"churn");
    let reported = std::time::Instant::now();
    let next = pending.await.unwrap();
    assert_eq!(next.state, AttachmentTransferState::Ready);
    assert_not_held(opened, reported, std::time::Instant::now());
    stream.close();
    runtime.shutdown_and_close().await.unwrap();
}

/// Caller timeouts that cancel `next()` while its database read runs leave
/// that read in flight, and the next call awaits it rather than starting
/// another, so short timeouts under contention never stack reads.
#[tokio::test]
async fn attachment_reads_survive_cancelled_next_without_stacking() {
    use crate::AttachmentTransferState;
    let dir = tempfile::tempdir().unwrap();
    let (runtime, store, job, stream) = downloading_subscription(&dir, b"stacked").await;
    let gate = stream.gate_reads_for_test();
    report_ready(&runtime, &store, &job, b"stacked");
    for _ in 0..6 {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), stream.next())
                .await
                .is_err(),
            "a held read delivered a frame"
        );
    }
    let started = || gate.started.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(started(), 1, "each cancelled call started another read");
    gate.open.send_replace(true);
    let ready = next_row(&stream).await;
    assert_eq!(ready.state, AttachmentTransferState::Ready);
    assert_eq!(started(), 1);
    stream.close();
    runtime.shutdown_and_close().await.unwrap();
}

/// A caller timeout that cancels `next()` while progress waits out the window
/// keeps the owed read, so the next call delivers that progress when the
/// window ends rather than after the idle fallback.
#[tokio::test]
async fn attachment_progress_survives_a_cancelled_next() {
    let dir = tempfile::tempdir().unwrap();
    let (runtime, store, job, stream) = downloading_subscription(&dir, b"cancel").await;
    let opened = std::time::Instant::now();
    report_progress(&runtime, &store, &job, 1024);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err(),
        "progress skipped the window"
    );
    let row = next_row(&stream).await;
    assert_eq!(row.received, 1024);
    // The idle fallback for an active transfer is a second away.
    assert!(
        opened.elapsed() < std::time::Duration::from_millis(700),
        "progress arrived {:?} after its report",
        opened.elapsed()
    );
    stream.close();
    runtime.shutdown_and_close().await.unwrap();
}
