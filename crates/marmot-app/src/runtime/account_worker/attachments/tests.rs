use super::*;

#[test]
fn attachment_capacity_reserves_disk_overhead_and_never_evicts() {
    let p = super::super::super::attachment_controls::default_policy(&MarmotAppConfig::default());
    assert_eq!(p.retained_bytes, 2 * 1024 * 1024 * 1024);
    assert_eq!(p.disk_reserve, 256 * 1024 * 1024);
    assert_eq!(p.transfer_limit, 64 * 1024 * 1024);
    let free = p.disk_reserve + 4 * p.transfer_limit;
    assert!(capacity(&p, p.transfer_limit, free));
    assert!(!capacity(&p, p.transfer_limit, free - 1));
    assert!(!capacity(&p, u64::MAX, u64::MAX));
}

use crate::tests::ScriptedPushRelayClient;
use crate::{MarmotApp, MarmotAppConfig};
use marmot_account::AccountHome;
use storage_sqlite::{StoredAccountGroup, StoredAccountState, StoredAppEvent};

const GROUP: &str = "abababababababababababababababab";
/// Build a stored group whose invitation state can be varied without an MLS engine.
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
/// Seed the default received-source projection used by adjacent worker tests.
fn seed(
    storage: &SqliteAccountStorage,
    reference: &crate::MediaAttachmentReference,
    pending: bool,
) {
    seed_direction(storage, reference, pending, "received");
}

/// Seed an accepted source row with an explicit direction under the same attachment identity.
fn seed_direction(
    storage: &SqliteAccountStorage,
    reference: &crate::MediaAttachmentReference,
    pending: bool,
    direction: &str,
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
            direction: direction.into(),
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
/// Give worker tests a group policy that points to the attachment fixture's Blossom endpoint.
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

/// Create a local account and accepted attachment source without a live media endpoint.
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

/// Supply a bounded media HTTP lane and its completion receiver to worker tests.
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

/// Count loopback response bytes once, then prove the retained asset survives a client restart.
#[tokio::test]
async fn attachment_worker_downloads_without_engine_group_or_screen_and_retains_through_restart() {
    download_without_engine_and_retain(false, "received", false).await;
    download_without_engine_and_retain(true, "received", false).await;
    download_without_engine_and_retain(false, "sent", false).await;
}

/// Exercise received or sent-source rows without a second HTTP body on local re-open.
async fn download_without_engine_and_retain(
    explicit: bool,
    direction: &str,
    outgoing_faults: bool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut reference, ciphertext) =
        crate::media::tests::attachment_worker_fixture(b"retained worker bytes");
    let expected_body_bytes = ciphertext.len();
    let served_body_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server_body_bytes = Arc::clone(&served_body_bytes);
    let (stop_observing, observation_complete) = oneshot::channel::<()>();
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
        server_body_bytes.fetch_add(ciphertext.len(), std::sync::atomic::Ordering::SeqCst);
        drop(socket);
        tokio::select! {
            biased;
            connection = listener.accept() => panic!("retained return requested another ciphertext body: {connection:?}"),
            _ = observation_complete => {}
        }
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
    seed_direction(&storage, &reference, true, direction);
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
    seed_direction(&storage, &reference, false, direction);
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
    if explicit && direction == "sent" {
        let connection = retention_fault_connection(&app);
        // A pending sibling keeps the shared quarantine marker alive through Retry.
        storage
            .record_app_event(&StoredAppEvent {
                group_id_hex: GROUP.into(),
                message_id_hex: "55".repeat(32),
                source_message_id_hex: None,
                source_epoch: None,
                direction: "sent".into(),
                sender: "33".repeat(32),
                plaintext: String::new(),
                kind: 9,
                tags: vec![reference.imeta_tag()],
                recorded_at: 10,
                received_at: 10,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .unwrap();
        let tokens = storage
            .stage_attachment_uploads(GROUP, 3, &[b"retained worker bytes"], 10, 1_000_000)
            .unwrap();
        storage
            .bind_attachment_uploads(
                &tokens,
                &[(
                    serde_json::to_value(reference.imeta_tag()).unwrap(),
                    crate::media::media_hash_from_reference(&reference).unwrap(),
                )],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE outgoing_attachment_uploads SET bytes=x'00' WHERE token=?1",
                [&tokens[0]],
            )
            .unwrap();
        assert_eq!(
            storage
                .promote_attachment_uploads(
                    GROUP,
                    &"11".repeat(32),
                    crate::unix_now_seconds(),
                    1_000_000
                )
                .unwrap(),
            0
        );
    }
    let _fault_connection = outgoing_faults.then(|| {
        let connection = retention_fault_connection(&app);
        let tag = reference.imeta_tag();
        storage.record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(), message_id_hex: "55".repeat(32),
            source_message_id_hex: Some("66".repeat(32)), source_epoch: Some(3),
            direction: "sent".into(), sender: "33".repeat(32), plaintext: String::new(),
            kind: 9, tags: vec![tag.clone()], recorded_at: 10, received_at: 10,
            origin_commit_id: None, moderation_grant: false,
        }).unwrap();
        let tokens = storage.stage_attachment_uploads(GROUP,3,&[b"retained worker bytes"],10,1_000_000).unwrap();
        storage.bind_attachment_uploads(&tokens,&[(serde_json::to_value(tag).unwrap(),crate::media::media_hash_from_reference(&reference).unwrap())]).unwrap();
        storage.protect_attachment_uploads(GROUP,&"55".repeat(32),&[reference.imeta_tag()]).unwrap();
        storage.stage_attachment_uploads(GROUP,3,&[b"orphan"],0,1_000_000).unwrap();
        connection.execute_batch(&format!("CREATE TRIGGER fail_outgoing_prune BEFORE DELETE ON outgoing_attachment_uploads WHEN OLD.slot_json IS NULL BEGIN SELECT RAISE(ABORT,'generated prune fault'); END;
        CREATE TRIGGER fail_outgoing_promotion BEFORE INSERT ON retained_attachment_bytes WHEN EXISTS(SELECT 1 FROM attachment_acquisition q WHERE q.token=NEW.token AND q.message_id_hex='{}') BEGIN SELECT RAISE(ABORT,'generated promotion fault'); END;", "55".repeat(32))).unwrap();
        connection
    });
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
    assert_eq!(
        admission.is_waiting(),
        !(explicit && direction == "sent"),
        "automatic work must not fetch a quarantined outgoing body"
    );
    if explicit {
        // Pure explicit work must retain native retry behavior in HostManaged,
        // even though it passes through the same worker as automatic demand.
        client.app.config.attachment_acquisition_mode =
            crate::AttachmentAcquisitionMode::HostManaged;
        let now = crate::unix_now_seconds();
        let asset = if direction == "sent" {
            storage
                .attachment_transfer_status(GROUP, &"11".repeat(32), &"22".repeat(32), 0, now, true)
                .unwrap()
                .unwrap()
                .reference
                .unwrap()
        } else {
            storage
                .attachment_transfer_candidates(now, 1, true)
                .unwrap()
                .remove(0)
        };
        storage.explicitly_retry_attachment(&asset, now).unwrap();
        let mut policy =
            super::super::super::attachment_controls::default_policy(&client.app.config);
        policy.automatic = false;
        // Enough quota for the default admission reservation, but not the
        // explicit 512 MiB ceiling. A tiny explicit file must still finish.
        policy.retained_bytes = policy.transfer_limit;
        storage
            .set_attachment_download_policy(&policy, now)
            .unwrap();
    }
    if explicit && direction == "sent" {
        schedule(&client, &shared, &http, &mut admission).unwrap();
        assert!(
            admission.is_waiting(),
            "deliberate Retry survives quarantine recovery and enters HTTP admission"
        );
    }
    admission.ready().await;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert_eq!(shared.attachment_transfer.available_permits(), 0);
    assert_eq!(http.permits.available_permits(), 3);
    let done = tokio::time::timeout(Duration::from_secs(5), completions.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        shared.attachment_transfer.available_permits(),
        0,
        "queued plaintext still owns global capacity"
    );
    let asset = match &done.completion {
        MediaHttpCompletion::Attachment { job, .. } => job.reference.clone(),
        _ => panic!("attachment"),
    };
    if explicit {
        let MediaHttpCompletion::Attachment { job, .. } = &done.completion else {
            panic!("attachment");
        };
        // A receipt on an opted-in job forbids any further automatic attempt.
        // This pure explicit job must not have acquired that contract.
        assert_eq!(
            storage
                .begin_attachment_network_attempt(job, crate::unix_now_seconds())
                .unwrap(),
            direction != "sent",
            "a deliberately retried outgoing receipt remains single-body; pure explicit received work keeps its existing contract"
        );
    }
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
    stop_observing.send(()).unwrap();
    server.await.unwrap();
    assert_eq!(
        served_body_bytes.load(std::sync::atomic::Ordering::SeqCst),
        expected_body_bytes,
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
async fn attachment_missing_secret_deferral_is_bounded_and_explicit_retry_readmits() {
    let (_dir, client, storage, reference) = offline_fixture().await;
    assert!(
        client
            .prepare_background_attachment_download(&GroupId::new(vec![0xab; 16]), reference, 1024)
            .unwrap()
            .is_none()
    );
    let now = crate::unix_now_seconds();
    // Earlier worker ticks already found the source-epoch material missing.
    let mut at = now - 10_000;
    admit_demands(&storage, at, false).unwrap();
    let asset = storage
        .due_attachment_acquisitions(at, 1)
        .unwrap()
        .remove(0);
    for _ in 0..5 {
        assert!(!storage.defer_attachment_preparation(&asset, at).unwrap());
        at = storage
            .attachment_acquisition_status(&asset)
            .unwrap()
            .unwrap()
            .due
            .unwrap();
    }
    assert!(at <= now);
    let shared = RuntimeSharedServices::default();
    let (http, mut completions) = context();
    let mut admission = Admission::default();
    schedule(&client, &shared, &http, &mut admission).unwrap();
    admission.ready().await;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    let status = storage
        .attachment_acquisition_status(&asset)
        .unwrap()
        .unwrap();
    assert_eq!(
        status.state,
        storage_sqlite::AttachmentAcquisitionState::Blocked
    );
    assert_eq!(status.attempts, 0);
    assert!(status.due.is_none());
    let transfer = || {
        storage
            .attachment_transfer_status(GROUP, &"11".repeat(32), &"22".repeat(32), 0, now, true)
            .unwrap()
            .unwrap()
            .state
    };
    assert_eq!(transfer(), storage_sqlite::AttachmentTransferState::Failed);
    assert!(completions.try_recv().is_err());
    assert!(storage.explicitly_retry_attachment(&asset, now).unwrap());
    assert_eq!(transfer(), storage_sqlite::AttachmentTransferState::Queued);
}

/// Rows projected before projection cached the source epoch's key stay
/// uncached. Retry must derive it from the epoch's retained anchor rather than
/// repeat the same six misses and fail again.
#[test]
fn attachment_explicit_retry_derives_an_uncached_source_epoch_key() {
    crate::tests::run_composed_app_runtime_test("attachment-retry-anchor", || async {
        use cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY;
        use cgka_traits::engine::SendIntent;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        let group_id = client.create_group("retry media", &[]).await.unwrap();
        let group_hex = hex::encode(group_id.as_slice());
        // Group creation caches its founding epoch; the source epoch is the
        // next one, and the group has left it by the time the row exists.
        let self_update = SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        };
        client.runtime.send(self_update.clone()).await.unwrap();
        let (source_epoch, secret) = client
            .runtime
            .exporter_secret_with_epoch(&group_id, GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY, 32)
            .unwrap();
        client.runtime.send(self_update).await.unwrap();

        let (mut reference, ciphertext) =
            crate::media::tests::attachment_worker_fixture_with_secret(
                b"anchored bytes",
                secret.as_ref(),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        reference.source_epoch = source_epoch.0;
        reference.locators = vec![crate::MediaLocator {
            kind: "blossom-v1".into(),
            value: format!("{base_url}/{}", reference.ciphertext_sha256),
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
        // No fallback dial may leave the loopback server.
        client
            .state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == group_hex)
            .unwrap()
            .encrypted_media
            .default_blob_endpoints = vec![crate::AppBlobEndpoint {
            locator_kind: "blossom-v1".into(),
            base_url,
        }];
        storage
            .record_app_event(&StoredAppEvent {
                group_id_hex: group_hex.clone(),
                message_id_hex: "11".repeat(32),
                source_message_id_hex: Some("22".repeat(32)),
                source_epoch: Some(source_epoch.0),
                direction: "received".into(),
                sender: "33".repeat(32),
                plaintext: String::new(),
                kind: 9,
                tags: vec![vec![
                    "imeta".into(),
                    format!("v {}", reference.version),
                    format!("locator blossom-v1 {}", reference.locators[0].value),
                    format!("ciphertext_sha256 {}", reference.ciphertext_sha256),
                    format!("plaintext_sha256 {}", reference.plaintext_sha256),
                    format!("nonce {}", reference.nonce_hex),
                    format!("m {}", reference.media_type),
                    format!("filename {}", reference.file_name),
                ]],
                recorded_at: 10,
                received_at: 10,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .unwrap();

        // Automatic work only reads the cache: five earlier misses, then the
        // sixth in this pass fails the job.
        let now = crate::unix_now_seconds();
        let mut at = now - 10_000;
        admit_demands(&storage, at, true).unwrap();
        let asset = storage
            .due_attachment_acquisitions(at, 1)
            .unwrap()
            .remove(0);
        for _ in 0..5 {
            assert!(!storage.defer_attachment_preparation(&asset, at).unwrap());
            at = storage
                .attachment_acquisition_status(&asset)
                .unwrap()
                .unwrap()
                .due
                .unwrap();
        }
        let shared = RuntimeSharedServices::default();
        let (http, mut completions) = context();
        let mut admission = Admission::default();
        schedule(&client, &shared, &http, &mut admission).unwrap();
        admission.ready().await;
        schedule(&client, &shared, &http, &mut admission).unwrap();
        let transfer = || {
            storage
                .attachment_transfer_status(
                    &group_hex,
                    &"11".repeat(32),
                    &"22".repeat(32),
                    0,
                    crate::unix_now_seconds(),
                    true,
                )
                .unwrap()
                .unwrap()
                .state
        };
        assert_eq!(transfer(), storage_sqlite::AttachmentTransferState::Failed);
        assert!(completions.try_recv().is_err());

        assert!(storage.explicitly_retry_attachment(&asset, now).unwrap());
        schedule(&client, &shared, &http, &mut admission).unwrap();
        admission.ready().await;
        schedule(&client, &shared, &http, &mut admission).unwrap();
        let done = tokio::time::timeout(Duration::from_secs(10), completions.recv())
            .await
            .expect("Retry must start the transfer")
            .unwrap();
        server.await.unwrap();
        complete_media_http(&mut client, done, &shared, &http).await;
        assert_eq!(transfer(), storage_sqlite::AttachmentTransferState::Ready);
        assert_eq!(
            &*storage
                .read_retained_attachment(&asset, crate::unix_now_seconds(), 0, 100)
                .unwrap()
                .unwrap(),
            b"anchored bytes"
        );
    });
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
async fn attachment_publication_digest_bug_is_terminal_and_native_default_is_on() {
    assert!(MarmotAppConfig::default().attachment_acquisition.is_some());
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
async fn attachment_worker_disk_pause_does_not_consume_attempts() {
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
        .minimum_free_disk_bytes =
        i64::MAX as u64 - 4 * crate::media::MAX_ENCRYPTED_MEDIA_BLOB_BYTES;
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
    let progress = store
        .attachment_transfer_status(GROUP, &"11".repeat(32), &"22".repeat(32), 0, now, true)
        .unwrap()
        .unwrap();
    assert_eq!(
        progress.state,
        storage_sqlite::AttachmentTransferState::RetryScheduled
    );
    assert_eq!(progress.retry_at, status.due);
    assert_eq!(shared.attachment_transfer.available_permits(), 1);
}

#[tokio::test]
async fn attachment_cancellation_observation_error_is_not_cancellation() {
    let (_dir, _client, store, _reference) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    admit_demands(&store, now, false).unwrap();
    let asset = store.due_attachment_acquisitions(now, 1).unwrap().remove(0);
    let job = store
        .claim_attachment_acquisition(&asset, now, now + LEASE_SECONDS)
        .unwrap()
        .unwrap();
    let (_updates, watch) = watch::channel(());
    store.close().unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            cancelled(store, job, watch, None)
        )
        .await
        .is_err(),
        "an unobservable store must not masquerade as a durable cancel"
    );
}

fn automatic_target() -> crate::AttachmentLocalTarget {
    crate::AttachmentLocalTarget {
        message_id_hex: "11".repeat(32),
        source_message_id_hex: "22".repeat(32),
        attachment_index: 0,
    }
}
fn all_attachment_permission() -> crate::AttachmentAutomaticPermission {
    crate::AttachmentAutomaticPermission {
        images: true,
        videos: true,
        audio: true,
        files: true,
    }
}

#[tokio::test]
async fn attachment_host_managed_requires_demand_and_fences_permission_generations() {
    let (_dir, mut client, storage, reference) = offline_fixture().await;
    assert!(matches!(
        client
            .app
            .runtime()
            .begin_attachment_permission_update("alice")
            .await,
        Err(AppError::AttachmentModeRequired)
    ));
    client.app.config.attachment_acquisition_mode = crate::AttachmentAcquisitionMode::HostManaged;
    let runtime = client.app.runtime();
    let group = GroupId::new(vec![0xab; 16]);
    let (http, _completions) = context();
    let mut admission = Admission::default();
    // Startup cannot turn projection demand into network acquisition.
    schedule(&client, &runtime.shared, &http, &mut admission).unwrap();
    assert!(
        storage
            .due_attachment_acquisitions(crate::unix_now_seconds(), 64)
            .unwrap()
            .is_empty()
    );
    let denied = runtime
        .request_automatic_attachment("alice", &group, automatic_target())
        .await
        .unwrap();
    assert!(!denied.newly_queued);
    assert_eq!(
        denied.status.unwrap().state,
        storage_sqlite::AttachmentTransferState::PolicyBlocked
    );
    let stale = runtime
        .begin_attachment_permission_update("alice")
        .await
        .unwrap();
    let current = runtime
        .begin_attachment_permission_update("alice")
        .await
        .unwrap();
    assert!(
        !runtime
            .set_attachment_automatic_permission("alice", stale, all_attachment_permission())
            .await
            .unwrap()
    );
    assert!(
        runtime
            .set_attachment_automatic_permission(
                "alice",
                current.clone(),
                all_attachment_permission()
            )
            .await
            .unwrap()
    );
    assert!(
        !runtime
            .set_attachment_automatic_permission("alice", current, all_attachment_permission())
            .await
            .unwrap()
    );
    schedule(&client, &runtime.shared, &http, &mut admission).unwrap();
    assert!(
        storage
            .due_attachment_acquisitions(crate::unix_now_seconds(), 64)
            .unwrap()
            .is_empty(),
        "permission alone is not demand"
    );
    let result = runtime
        .request_automatic_attachment("alice", &group, automatic_target())
        .await
        .unwrap();
    assert!(result.newly_queued);
    let updates = runtime.shared.attachment_updates.subscribe();
    let repeated = runtime
        .request_automatic_attachment("alice", &group, automatic_target())
        .await
        .unwrap();
    assert!(!repeated.newly_queued);
    assert!(
        !updates.has_changed().unwrap(),
        "unchanged demand must not create a presentation wake loop"
    );
    let asset = result.status.unwrap().reference.unwrap();
    let now = crate::unix_now_seconds();
    let job = storage
        .claim_attachment_acquisition(&asset, now, now + 100)
        .unwrap()
        .unwrap();
    let lease = runtime
        .shared
        .attachment_permissions
        .lease(
            &storage.attachment_store_identity().unwrap(),
            &reference.media_type,
        )
        .unwrap();
    assert!(lease.allowed());
    let next = runtime
        .begin_attachment_permission_update("alice")
        .await
        .unwrap();
    assert!(!lease.allowed());
    assert!(!storage.begin_attachment_network_attempt(&job, now).unwrap());
    assert!(!storage.attachment_transfer_is_active(&job, now).unwrap());
    assert!(
        runtime
            .set_attachment_automatic_permission("alice", next.clone(), all_attachment_permission())
            .await
            .unwrap()
    );
    assert!(
        !lease.allowed(),
        "reapproval must not revive an old transfer"
    );
    let replacement = client.app.runtime();
    assert!(
        !replacement
            .set_attachment_automatic_permission("alice", next, all_attachment_permission())
            .await
            .unwrap()
    );
    assert_eq!(
        replacement
            .request_automatic_attachment("alice", &group, automatic_target())
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        storage_sqlite::AttachmentTransferState::Paused
    );
    let pending_callback = runtime
        .begin_attachment_permission_update("alice")
        .await
        .unwrap();
    runtime.accounts.deactivate_account("alice").await.unwrap();
    assert!(matches!(
        runtime.begin_attachment_permission_update("alice").await,
        Err(AppError::AttachmentAccountSignedOut)
    ));
    assert!(
        !runtime
            .set_attachment_automatic_permission(
                "alice",
                pending_callback.clone(),
                all_attachment_permission()
            )
            .await
            .unwrap()
    );
    // Reopening the same retained account store must not revive its old approval.
    AccountHome::open(_dir.path())
        .set_account_signed_out("alice", false)
        .unwrap();
    assert!(
        !runtime
            .set_attachment_automatic_permission(
                "alice",
                pending_callback,
                all_attachment_permission()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        runtime
            .request_automatic_attachment("alice", &group, automatic_target())
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        storage_sqlite::AttachmentTransferState::Paused
    );
    AccountHome::open(_dir.path())
        .create_account("bob")
        .unwrap();
    let bob = client.app.account_storage("bob").unwrap();
    seed(&bob, &reference, false);
    assert_eq!(
        runtime
            .request_automatic_attachment("bob", &group, automatic_target())
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        storage_sqlite::AttachmentTransferState::PolicyBlocked
    );
}

/// Explicit promotion detaches automatic permission while retaining the same
/// transport lease; later deliberate cancellation still stops that attempt.
#[tokio::test]
async fn promoted_attempt_survives_automatic_revocation_without_extending_lease() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig {
            attachment_acquisition_mode: crate::AttachmentAcquisitionMode::HostManaged,
            ..Default::default()
        },
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let generation = runtime
        .begin_attachment_permission_update("alice")
        .await
        .unwrap();
    assert!(
        runtime
            .set_attachment_automatic_permission(
                "alice",
                generation,
                crate::AttachmentAutomaticPermission {
                    images: true,
                    ..Default::default()
                }
            )
            .await
            .unwrap()
    );
    let storage = app.account_storage("alice").unwrap();
    let (mut reference, _) = crate::media::tests::attachment_worker_fixture(b"promotion bytes");
    reference.locators = vec![crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!("https://blob.example/{}", reference.ciphertext_sha256),
    }];
    seed(&storage, &reference, false);
    let now = crate::unix_now_seconds();
    let selected = storage
        .attachment_history_page(GROUP, 1, None)
        .unwrap()
        .entries
        .remove(0);
    let storage_sqlite::AttachmentDemand::Requested(asset) = storage
        .request_attachment_acquisition(
            GROUP,
            &selected,
            crate::media::media_hash_from_reference(&reference).unwrap(),
            now,
        )
        .unwrap()
    else {
        panic!("request")
    };
    let job = storage
        .claim_attachment_acquisition(&asset, now, now + 180)
        .unwrap()
        .unwrap();
    let deadline = storage
        .attachment_acquisition_status(&asset)
        .unwrap()
        .unwrap()
        .due;
    let identity = storage.attachment_store_identity().unwrap();
    let permission = runtime
        .shared
        .attachment_permissions
        .lease(&identity, "image/png")
        .unwrap();
    assert!(storage.promote_attachment_demand(&asset, now).unwrap());
    runtime
        .begin_attachment_permission_update("alice")
        .await
        .unwrap();
    assert!(!permission.allowed());
    let (_, updates) = watch::channel(());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            cancelled(storage.clone(), job.clone(), updates, Some(permission))
        )
        .await
        .is_err()
    );
    assert_eq!(
        storage
            .attachment_acquisition_status(&asset)
            .unwrap()
            .unwrap()
            .due,
        deadline
    );
    storage.cancel_attachment_acquisition(&asset).unwrap();
    let (_, updates) = watch::channel(());
    tokio::time::timeout(
        Duration::from_secs(1),
        cancelled(storage, job, updates, None),
    )
    .await
    .unwrap();
}

/// Keep the real incoming GET and verified local read independent of outgoing SQL failures.
#[tokio::test]
async fn attachment_worker_downloads_despite_outgoing_maintenance_failures() {
    download_without_engine_and_retain(false, "received", true).await;
}

/// Open a second encrypted connection only to inject deterministic test faults.
fn retention_fault_connection(app: &MarmotApp) -> rusqlite::Connection {
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

/// Every core source entry point must commit despite a deterministic optional byte-write failure.
#[tokio::test]
async fn outgoing_retention_failure_preserves_all_source_projection_paths() {
    let (_dir, client, storage, reference) = offline_fixture().await;
    let connection = retention_fault_connection(&client.app);
    let token = storage
        .stage_attachment_uploads(GROUP, 3, &[b"retained worker bytes"], 10, 1_000_000)
        .unwrap();
    storage
        .bind_attachment_uploads(
            &token,
            &[(
                serde_json::to_value(reference.imeta_tag()).unwrap(),
                crate::media::media_hash_from_reference(&reference).unwrap(),
            )],
        )
        .unwrap();
    connection.execute_batch("CREATE TRIGGER fail_optional_bytes BEFORE INSERT ON retained_attachment_bytes BEGIN SELECT RAISE(ABORT,'generated optional retention fault'); END;").unwrap();
    let mut message = crate::AppMessageProjection {
        authority: None,
        message_id_hex: "55".repeat(32),
        source_message_id_hex: Some("66".repeat(32)),
        direction: "sent".into(),
        group_id_hex: GROUP.into(),
        sender: "33".repeat(32),
        plaintext: "accepted".into(),
        kind: 9,
        tags: vec![reference.imeta_tag()],
        source_epoch: Some(3),
        retention: None,
        recorded_at: Some(10),
        origin_commit_id: None,
        moderation_grant: false,
    };
    client
        .app
        .record_account_app_event_at("alice", &message, 10)
        .unwrap();
    message.message_id_hex = "77".repeat(32);
    message.source_message_id_hex = None;
    message.source_epoch = None;
    client
        .app
        .record_account_app_event_refreshing_moderation_grant("alice", &message)
        .unwrap();
    client
        .app
        .finalize_account_app_event_source_retention(
            "alice",
            GROUP,
            &message.message_id_hex,
            Some(&"88".repeat(32)),
            3,
            crate::AppMessageRetentionDecision::new(10, 0),
            None,
        )
        .unwrap();
    let rows: i64 = connection.query_row("SELECT count(*) FROM app_events WHERE direction='sent' AND source_message_id_hex IS NOT NULL",[],|row|row.get(0)).unwrap();
    assert_eq!(
        rows, 2,
        "both confirmed sources survive the retention fault"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM retained_attachment_bytes",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert!(
        connection
            .query_row(
                "SELECT count(*) FROM chat_list_rows WHERE group_id_hex=?1",
                [GROUP],
                |row| row.get::<_, i64>(0)
            )
            .unwrap()
            > 0
    );
    connection
        .execute_batch("DROP TRIGGER fail_optional_bytes")
        .unwrap();
    assert!(
        storage
            .recover_attachment_uploads(11, 64, 1_000_000)
            .unwrap()
            > 0
    );
}

/// Deliberate Retry may fetch a replacement even when a pending sibling holds a quarantine marker.
#[tokio::test]
async fn attachment_worker_quarantined_outgoing_retry_downloads_once_and_retains() {
    download_without_engine_and_retain(true, "sent", false).await;
}
