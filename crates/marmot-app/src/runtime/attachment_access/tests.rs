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
fn seed(store: &SqliteAccountStorage, bytes: &[u8]) {
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
