use super::*;

#[test]
fn attachment_capacity_reserves_disk_overhead_and_never_evicts() {
    let p = crate::AttachmentAcquisitionPolicy::default();
    assert_eq!(p.retained_bytes_per_account, 2 * 1024 * 1024 * 1024);
    assert_eq!(p.minimum_free_disk_bytes, 256 * 1024 * 1024);
    assert_eq!(p.maximum_transfer_bytes, 64 * 1024 * 1024);
    let free = p.minimum_free_disk_bytes + 4 * p.maximum_transfer_bytes;
    assert!(capacity(&p, free));
    assert!(!capacity(&p, free - 1));
    assert!(!capacity(
        &crate::AttachmentAcquisitionPolicy {
            maximum_transfer_bytes: u64::MAX,
            ..p
        },
        u64::MAX
    ));
}

use crate::tests::ScriptedPushRelayClient;
use crate::{MarmotApp, MarmotAppConfig};
use marmot_account::AccountHome;
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
fn seed(
    storage: &SqliteAccountStorage,
    reference: &crate::MediaAttachmentReference,
    pending: bool,
) {
    storage
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".into(),
                groups: vec![group(pending)],
                ..Default::default()
            },
            100,
            300,
        )
        .unwrap();
    let tag = vec![
        "imeta".into(),
        format!("v {}", reference.version),
        format!("locator blossom-v1 {}", reference.locators[0].value),
        format!("ciphertext_sha256 {}", reference.ciphertext_sha256),
        format!("plaintext_sha256 {}", reference.plaintext_sha256),
        format!("nonce {}", reference.nonce_hex),
        format!("m {}", reference.media_type),
        format!("filename {}", reference.file_name),
    ];
    storage
        .record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(),
            message_id_hex: "11".repeat(32),
            source_message_id_hex: Some("22".repeat(32)),
            source_epoch: Some(3),
            direction: "received".into(),
            sender: "33".repeat(32),
            plaintext: String::new(),
            kind: 9,
            tags: vec![tag, vec!["imeta".into(), "v future".into()]],
            recorded_at: 10,
            received_at: 10,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
}
fn projection(reference: &crate::MediaAttachmentReference) -> crate::AppGroupRecord {
    let mut projection = crate::conversions::app_group_from_stored_group(group(false)).unwrap();
    projection.encrypted_media = crate::AppGroupEncryptedMediaComponent {
        component_id: crate::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
        component: "marmot.encrypted-media.v2".into(),
        required: true,
        media_format: "encrypted-media-v2".into(),
        allowed_locator_kinds: vec!["blossom-v1".into()],
        default_blob_endpoints: vec![crate::AppBlobEndpoint {
            locator_kind: "blossom-v1".into(),
            base_url: reference.locators[0]
                .value
                .rsplit_once('/')
                .unwrap()
                .0
                .into(),
        }],
        data_hex: String::new(),
    };
    projection
}

async fn offline_fixture() -> (
    tempfile::TempDir,
    AppClient,
    SqliteAccountStorage,
    crate::MediaAttachmentReference,
) {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig {
            attachment_acquisition: Some(crate::AttachmentAcquisitionPolicy::default()),
            ..Default::default()
        },
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let storage = app.account_storage("alice").unwrap();
    let (mut reference, _) =
        crate::media::tests::attachment_worker_fixture(b"retained worker bytes");
    reference.locators = vec![crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!("https://media.example/{}", reference.ciphertext_sha256),
    }];
    seed(&storage, &reference, false);
    client.state.groups.push(projection(&reference));
    (dir, client, storage, reference)
}

fn context() -> (MediaHttpContext, mpsc::UnboundedReceiver<MediaHttpDone>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        MediaHttpContext {
            product: Default::default(),
            tx,
            permits: Arc::new(Semaphore::new(4)),
            prepared_group_image_uploads: Arc::new(Mutex::new(HashSet::new())),
            worker_lifetime: watch::channel(()).0,
        },
        rx,
    )
}

#[tokio::test]
async fn attachment_worker_downloads_without_engine_group_or_screen_and_retains_through_restart() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut reference, ciphertext) =
        crate::media::tests::attachment_worker_fixture(b"retained worker bytes");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    reference.locators = vec![crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!(
            "http://{}/{}",
            listener.local_addr().unwrap(),
            reference.ciphertext_sha256
        ),
    }];
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    ciphertext.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(&ciphertext).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig {
            attachment_acquisition: Some(crate::AttachmentAcquisitionPolicy::default()),
            allow_loopback_blob_endpoints: true,
            ..Default::default()
        },
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let storage = app.account_storage("alice").unwrap();
    seed(&storage, &reference, true);
    let projection = projection(&reference);
    client.state.groups.push(projection);
    storage
        .remember_encrypted_media_epoch_secret(
            GROUP,
            crate::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
            3,
            &[7; 32],
        )
        .unwrap();
    let shared = RuntimeSharedServices::default();
    let (http, mut completions) = context();
    let mut admission = Admission::default();
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert!(
        storage
            .due_attachment_acquisitions(crate::unix_now_seconds(), 32)
            .unwrap()
            .is_empty()
    );
    // Accept the invitation, without creating or hydrating an MLS group.
    seed(&storage, &reference, false);
    assert!(
        client
            .prepare_background_attachment_download(
                &GroupId::new(vec![0xab; 16]),
                reference.clone(),
                64 * 1024 * 1024
            )
            .unwrap()
            .is_some(),
        "retained source secret"
    );
    assert!(
        !storage.attachment_worker_demands(32).unwrap().is_empty(),
        "accepted source demand"
    );
    let policy = client.app.config.attachment_acquisition.take();
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert!(!admission.is_waiting(), "disabled automatic work");
    client.app.config.attachment_acquisition = policy;
    client.app.config.cursor_persistence = crate::CursorPersistence::Frozen;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert!(
        !admission.is_waiting(),
        "short-lived frozen runtimes skip acquisition"
    );
    client.app.config.cursor_persistence = crate::CursorPersistence::Advance;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert!(
        admission.is_waiting(),
        "eligible job must queue for global capacity"
    );
    admission.ready().await;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert_eq!(shared.attachment_transfer.available_permits(), 0);
    assert_eq!(http.permits.available_permits(), 3);
    let done = tokio::time::timeout(Duration::from_secs(5), completions.recv())
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    assert_eq!(
        shared.attachment_transfer.available_permits(),
        0,
        "queued plaintext still owns global capacity"
    );
    let asset = match &done.completion {
        MediaHttpCompletion::Attachment { job, .. } => job.reference.clone(),
        _ => panic!("attachment"),
    };
    complete_media_http(&mut client, done, &shared, &http).await;
    assert_eq!(shared.attachment_transfer.available_permits(), 1);
    assert_eq!(
        &*storage
            .read_retained_attachment(&asset, crate::unix_now_seconds(), 0, 100)
            .unwrap()
            .unwrap(),
        b"retained worker bytes"
    );
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert!(
        completions.try_recv().is_err(),
        "ready source must not download twice"
    );
    assert!(
        storage.attachment_worker_demands(32).unwrap().is_empty(),
        "invalid sibling was acknowledged"
    );
    drop(client);
    drop(storage);
    drop(app);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    assert_eq!(
        &*storage
            .read_retained_attachment(&asset, crate::unix_now_seconds(), 0, 100)
            .unwrap()
            .unwrap(),
        b"retained worker bytes"
    );
}

#[tokio::test]
async fn attachment_worker_exit_cancels_transfer_and_releases_global_capacity() {
    let shared = RuntimeSharedServices::default();
    let (http, mut completions) = context();
    let global = shared
        .attachment_transfer
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let permit = http.permits.clone().acquire_owned().await.unwrap();
    let permits = http.permits.clone();
    let (started, ready) = oneshot::channel();
    spawn_media_http(
        &http,
        permit,
        async move {
            let _global = global;
            let _ = started.send(());
            std::future::pending::<MediaHttpCompletion>().await
        },
        |completion| completion,
    );
    ready.await.unwrap();
    assert_eq!(shared.attachment_transfer.available_permits(), 0);
    drop(http);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), completions.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(shared.attachment_transfer.available_permits(), 1);
    assert_eq!(permits.available_permits(), 4);
}

#[tokio::test]
async fn attachment_missing_secret_does_not_claim_or_back_off_a_page_of_siblings() {
    let (_dir, client, storage, reference) = offline_fixture().await;
    let entry = storage
        .attachment_history_page(GROUP, 100, None)
        .unwrap()
        .entries
        .remove(0);
    for n in 1..20 {
        storage
            .record_app_event(&StoredAppEvent {
                group_id_hex: GROUP.into(),
                message_id_hex: format!("{n:064x}"),
                source_message_id_hex: Some(format!("{:064x}", n + 1000)),
                source_epoch: Some(3),
                direction: "received".into(),
                sender: "33".repeat(32),
                plaintext: String::new(),
                kind: 9,
                tags: vec![serde_json::from_value(entry.slot.clone()).unwrap()],
                recorded_at: 10,
                received_at: 10,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .unwrap();
    }
    assert!(
        client
            .prepare_background_attachment_download(&GroupId::new(vec![0xab; 16]), reference, 1024)
            .unwrap()
            .is_none()
    );
    let now = crate::unix_now_seconds();
    while admit_demands(&storage, now, false).unwrap() {}
    let jobs = storage.due_attachment_acquisitions(now, 32).unwrap();
    assert_eq!(jobs.len(), 20);
    let shared = RuntimeSharedServices::default();
    let (http, mut completions) = context();
    let mut admission = Admission::default();
    schedule(&client, &shared, &http, &mut admission).unwrap();
    admission.ready().await;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert_eq!(
        storage.due_attachment_acquisitions(now, 32).unwrap().len(),
        19
    );
    for job in jobs {
        assert_eq!(
            storage
                .attachment_acquisition_status(&job)
                .unwrap()
                .unwrap()
                .attempts,
            0
        );
    }
    assert!(completions.try_recv().is_err());
    assert_eq!(shared.attachment_transfer.available_permits(), 1);
}

#[tokio::test]
async fn attachment_restart_reclaims_inflight_and_late_publication_cannot_win() {
    let (_dir, client, storage, _) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    admit_demands(&storage, now, false).unwrap();
    let asset = storage
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    let old = storage
        .claim_attachment_acquisition(&asset, now, now + LEASE_SECONDS)
        .unwrap()
        .unwrap();
    assert!(
        storage
            .due_attachment_acquisitions(now, 1)
            .unwrap()
            .is_empty()
    );
    let (http, _completions) = context();
    let shared = RuntimeSharedServices::default();
    let mut restarted = Admission::default();
    schedule(&client, &shared, &http, &mut restarted).unwrap();
    let now = crate::unix_now_seconds();
    assert_eq!(
        storage.due_attachment_acquisitions(now, 1).unwrap(),
        vec![asset.clone()]
    );
    complete(
        &client,
        &old,
        Ok(MediaDownloadResult {
            plaintext: b"retained worker bytes".to_vec(),
            size_bytes: 21,
            file_name: "fixture.bin".into(),
            media_type: "application/octet-stream".into(),
        }),
        10000,
    )
    .unwrap();
    assert!(
        storage
            .read_retained_attachment(&asset, now, 0, 100)
            .unwrap()
            .is_none()
    );
    let next = storage
        .claim_attachment_acquisition(&asset, now, now + LEASE_SECONDS)
        .unwrap()
        .unwrap();
    storage
        .remove_local_attachment(GROUP, &"11".repeat(32), 0)
        .unwrap();
    complete(
        &client,
        &next,
        Ok(MediaDownloadResult {
            plaintext: b"retained worker bytes".to_vec(),
            size_bytes: 21,
            file_name: "fixture.bin".into(),
            media_type: "application/octet-stream".into(),
        }),
        10000,
    )
    .unwrap();
    assert!(
        storage
            .read_retained_attachment(&asset, now, 0, 100)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn attachment_publication_digest_bug_is_terminal_and_native_default_is_off() {
    assert!(MarmotAppConfig::default().attachment_acquisition.is_none());
    let (_dir, client, storage, _) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    let entry = storage
        .attachment_history_page(GROUP, 100, None)
        .unwrap()
        .entries
        .remove(0);
    let storage_sqlite::AttachmentDemand::Requested(asset) = storage
        .request_attachment_acquisition(GROUP, &entry, [0; 32], now)
        .unwrap()
    else {
        panic!("demand");
    };
    let job = storage
        .claim_attachment_acquisition(&asset, now, now + LEASE_SECONDS)
        .unwrap()
        .unwrap();
    complete(
        &client,
        &job,
        Ok(MediaDownloadResult {
            plaintext: b"retained worker bytes".to_vec(),
            size_bytes: 21,
            file_name: "fixture.bin".into(),
            media_type: "application/octet-stream".into(),
        }),
        10000,
    )
    .unwrap();
    let status = storage
        .attachment_acquisition_status(&asset)
        .unwrap()
        .unwrap();
    assert_eq!(
        status.state,
        storage_sqlite::AttachmentAcquisitionState::Blocked
    );
    assert!(status.due.is_none());
}

mod resume;

#[tokio::test]
async fn attachment_worker_budget_pause_does_not_consume_attempts() {
    let (_dir, mut client, store, _reference) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    admit_demands(&store, now, false).unwrap();
    let asset = store.due_attachment_acquisitions(now, 1).unwrap().remove(0);
    client
        .app
        .config
        .attachment_acquisition
        .as_mut()
        .unwrap()
        .retained_bytes_per_account = 0;
    let (http, _rx) = context();
    let shared = RuntimeSharedServices::default();
    let mut admission = Admission::default();
    schedule(&client, &shared, &http, &mut admission).unwrap();
    admission.ready().await;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    let status = store
        .attachment_acquisition_status(&asset)
        .unwrap()
        .unwrap();
    assert_eq!(status.attempts, 0);
    assert!(status.due.unwrap() > now);
    assert_eq!(shared.attachment_transfer.available_permits(), 1);
}
