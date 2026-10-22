use super::*;
use storage_sqlite::SqliteAppStorage;

#[test]
fn attachment_capacity_reserves_disk_overhead_and_never_evicts() {
    let p =
        super::super::super::attachment_controls::default_policy(&MarmotAppConfig::white_noise());
    assert_eq!(p.retained_bytes, 2 * 1024 * 1024 * 1024);
    assert_eq!(p.disk_reserve, 256 * 1024 * 1024);
    assert_eq!(p.transfer_limit, 64 * 1024 * 1024);
    // The reserve plus a wire checkpoint and a store file (mdk#2314).
    let free = p.disk_reserve + 2 * p.transfer_limit;
    assert!(capacity(&p, p.transfer_limit, None, free));
    assert!(!capacity(&p, p.transfer_limit, None, free - 1));
    assert!(!capacity(&p, u64::MAX, None, u64::MAX));
    // A checkpoint is already on disk, and so may be one unrecorded append
    // a crash left: a resumed download is credited both, and needs at least
    // its store file.
    let saved = p.transfer_limit / 2;
    let credit = saved + media_store::CHECKPOINT_APPEND_MAX as u64;
    assert!(capacity(&p, p.transfer_limit, Some(saved), free - credit));
    assert!(!capacity(
        &p,
        p.transfer_limit,
        Some(saved),
        free - credit - 1
    ));
    let floor = p.disk_reserve + p.transfer_limit;
    assert!(capacity(
        &p,
        p.transfer_limit,
        Some(2 * p.transfer_limit),
        floor
    ));
    assert!(!capacity(
        &p,
        p.transfer_limit,
        Some(2 * p.transfer_limit),
        floor - 1
    ));
}

/// Readmission's checkpoint threshold admits exactly the parked jobs worker
/// admission would let start, whatever their recorded checkpoint.
#[test]
fn readmission_threshold_agrees_with_worker_admission() {
    let mib = 1024 * 1024;
    let slack = media_store::CHECKPOINT_APPEND_MAX as u64;
    for limit in [mib, 3 * mib, 64 * mib] {
        let mut policy = super::super::super::attachment_controls::default_policy(
            &MarmotAppConfig::white_noise(),
        );
        policy.transfer_limit = limit;
        policy.disk_reserve = 7 * mib;
        for available in [
            0,
            slack - 1,
            limit - 1,
            limit,
            limit + slack,
            2 * limit - 1,
            2 * limit,
            3 * limit,
        ] {
            let free = policy.disk_reserve + available;
            let threshold = readmit_admission(&policy, free);
            for recorded in [
                None,
                Some(0),
                Some(1),
                Some(limit / 2),
                Some(limit - slack),
                Some(limit),
                Some(2 * limit),
            ] {
                assert_eq!(
                    threshold.admits(recorded),
                    capacity(&policy, limit, recorded, free),
                    "limit {limit} available {available} recorded {recorded:?}"
                );
            }
        }
        assert_eq!(
            readmit_admission(&policy, policy.disk_reserve - 1),
            storage_sqlite::ReadmitAdmission::NONE
        );
    }
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
    seed_direction(&storage.app_storage(), reference, pending, "received");
}

/// Seed an accepted source row with an explicit direction under the same attachment identity.
fn seed_direction(
    storage: &SqliteAppStorage,
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
            ..MarmotAppConfig::white_noise()
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            ..MarmotAppConfig::white_noise()
        },
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let storage = app.account_storage("alice").unwrap();
    seed_direction(&storage.app_storage(), &reference, true, direction);
    let projection = projection(&reference);
    client.state.groups.push(projection);
    storage
        .app_storage()
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
            .app_storage()
            .due_attachment_acquisitions(crate::unix_now_seconds(), 32)
            .unwrap()
            .is_empty()
    );
    // Accept the invitation, without creating or hydrating an MLS group.
    seed_direction(&storage.app_storage(), &reference, false, direction);
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
        !storage
            .app_storage()
            .attachment_worker_demands(32)
            .unwrap()
            .is_empty(),
        "accepted source demand"
    );
    if explicit && direction == "sent" {
        let connection = retention_fault_connection(&app);
        // A pending sibling keeps the shared quarantine marker alive through Retry.
        storage
            .app_storage()
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
            .app_storage()
            .stage_attachment_uploads(GROUP, 3, &[b"retained worker bytes"], 10, 1_000_000)
            .unwrap();
        storage
            .app_storage()
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
                .app_storage()
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
        storage.app_storage().record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(), message_id_hex: "55".repeat(32),
            source_message_id_hex: Some("66".repeat(32)), source_epoch: Some(3),
            direction: "sent".into(), sender: "33".repeat(32), plaintext: String::new(),
            kind: 9, tags: vec![tag.clone()], recorded_at: 10, received_at: 10,
            origin_commit_id: None, moderation_grant: false,
        }).unwrap();
        let tokens = storage.app_storage().stage_attachment_uploads(GROUP,3,&[b"retained worker bytes"],10,1_000_000).unwrap();
        storage.app_storage().bind_attachment_uploads(&tokens,&[(serde_json::to_value(tag).unwrap(),crate::media::media_hash_from_reference(&reference).unwrap())]).unwrap();
        storage.app_storage().protect_attachment_uploads(GROUP,&"55".repeat(32),&[reference.imeta_tag()]).unwrap();
        storage.app_storage().stage_attachment_uploads(GROUP,3,&[b"orphan"],0,1_000_000).unwrap();
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
                .app_storage()
                .attachment_transfer_status(GROUP, &"11".repeat(32), &"22".repeat(32), 0, now, true)
                .unwrap()
                .unwrap()
                .reference
                .unwrap()
        } else {
            storage
                .app_storage()
                .attachment_transfer_candidates(now, 1, true)
                .unwrap()
                .remove(0)
        };
        storage
            .app_storage()
            .explicitly_retry_attachment(&asset, now)
            .unwrap();
        let mut policy =
            super::super::super::attachment_controls::default_policy(&client.app.config);
        policy.automatic = false;
        // Enough quota for the default admission reservation, but not the
        // explicit 512 MiB ceiling. A tiny explicit file must still finish.
        policy.retained_bytes = policy.transfer_limit;
        storage
            .app_storage()
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
                .app_storage()
                .begin_attachment_network_attempt(job, crate::unix_now_seconds())
                .unwrap(),
            direction != "sent",
            "a deliberately retried outgoing receipt remains single-body; pure explicit received work keeps its existing contract"
        );
    }
    complete_and_settle(&mut client, done, &shared, &http, &mut completions).await;
    assert_eq!(shared.attachment_transfer.available_permits(), 1);
    assert_eq!(
        &*read_retained(
            &storage,
            &client.app,
            &client.state.label,
            &asset,
            crate::unix_now_seconds(),
            0,
            100
        )
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
        storage
            .app_storage()
            .attachment_worker_demands(32)
            .unwrap()
            .is_empty(),
        "invalid sibling was acknowledged"
    );
    drop(client);
    drop(storage);
    drop(app);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let storage = app.account_storage("alice").unwrap();
    assert_eq!(
        &*read_retained(
            &storage,
            &app,
            "alice",
            &asset,
            crate::unix_now_seconds(),
            0,
            100
        )
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_missing_secret_does_not_claim_or_back_off_a_page_of_siblings() {
    let (_dir, client, storage, reference) = offline_fixture().await;
    let entry = storage
        .app_storage()
        .attachment_history_page(GROUP, 100, None)
        .unwrap()
        .entries
        .remove(0);
    for n in 1..20 {
        storage
            .app_storage()
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
    while admit_demands(&storage.app_storage(), now, false).unwrap() {}
    let jobs = storage
        .app_storage()
        .due_attachment_acquisitions(now, 32)
        .unwrap();
    assert_eq!(jobs.len(), 20);
    let shared = RuntimeSharedServices::default();
    let (http, mut completions) = context();
    let mut admission = Admission::default();
    schedule(&client, &shared, &http, &mut admission).unwrap();
    admission.ready().await;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    assert_eq!(
        storage
            .app_storage()
            .due_attachment_acquisitions(now, 32)
            .unwrap()
            .len(),
        19
    );
    for job in jobs {
        assert_eq!(
            storage
                .app_storage()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    admit_demands(&storage.app_storage(), at, false).unwrap();
    let asset = storage
        .app_storage()
        .due_attachment_acquisitions(at, 1)
        .unwrap()
        .remove(0);
    for _ in 0..5 {
        assert!(
            !storage
                .app_storage()
                .defer_attachment_preparation(&asset, at)
                .unwrap()
        );
        at = storage
            .app_storage()
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
        .app_storage()
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
            .app_storage()
            .attachment_transfer_status(GROUP, &"11".repeat(32), &"22".repeat(32), 0, now, true)
            .unwrap()
            .unwrap()
            .state
    };
    assert_eq!(transfer(), storage_sqlite::AttachmentTransferState::Failed);
    assert!(completions.try_recv().is_err());
    assert!(
        storage
            .app_storage()
            .explicitly_retry_attachment(&asset, now)
            .unwrap()
    );
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
                ..MarmotAppConfig::white_noise()
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
            .app_storage()
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
        admit_demands(&storage.app_storage(), at, true).unwrap();
        let asset = storage
            .app_storage()
            .due_attachment_acquisitions(at, 1)
            .unwrap()
            .remove(0);
        for _ in 0..5 {
            assert!(
                !storage
                    .app_storage()
                    .defer_attachment_preparation(&asset, at)
                    .unwrap()
            );
            at = storage
                .app_storage()
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
                .app_storage()
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

        assert!(
            storage
                .app_storage()
                .explicitly_retry_attachment(&asset, now)
                .unwrap()
        );
        schedule(&client, &shared, &http, &mut admission).unwrap();
        admission.ready().await;
        schedule(&client, &shared, &http, &mut admission).unwrap();
        let done = tokio::time::timeout(Duration::from_secs(10), completions.recv())
            .await
            .expect("Retry must start the transfer")
            .unwrap();
        server.await.unwrap();
        complete_and_settle(&mut client, done, &shared, &http, &mut completions).await;
        assert_eq!(transfer(), storage_sqlite::AttachmentTransferState::Ready);
        assert_eq!(
            &*read_retained(
                &storage,
                &client.app,
                &client.state.label,
                &asset,
                crate::unix_now_seconds(),
                0,
                100
            )
            .unwrap()
            .unwrap(),
            b"anchored bytes"
        );
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_restart_reclaims_inflight_and_late_publication_cannot_win() {
    let (_dir, client, storage, _) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    admit_demands(&storage.app_storage(), now, false).unwrap();
    let asset = storage
        .app_storage()
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    let old = storage
        .app_storage()
        .claim_attachment_acquisition(&asset, now, now + LEASE_SECONDS)
        .unwrap()
        .unwrap();
    assert!(
        storage
            .app_storage()
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
        storage
            .app_storage()
            .due_attachment_acquisitions(now, 1)
            .unwrap(),
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
    )
    .unwrap();
    assert!(
        read_retained(
            &storage,
            &client.app,
            &client.state.label,
            &asset,
            now,
            0,
            100
        )
        .unwrap()
        .is_none()
    );
    let next = storage
        .app_storage()
        .claim_attachment_acquisition(&asset, now, now + LEASE_SECONDS)
        .unwrap()
        .unwrap();
    storage
        .app_storage()
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
    )
    .unwrap();
    assert!(
        read_retained(
            &storage,
            &client.app,
            &client.state.label,
            &asset,
            now,
            0,
            100
        )
        .unwrap()
        .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_publication_digest_bug_is_terminal_and_native_default_is_on() {
    assert!(
        MarmotAppConfig::white_noise()
            .attachment_acquisition
            .is_some()
    );
    let (_dir, client, storage, _) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    let entry = storage
        .app_storage()
        .attachment_history_page(GROUP, 100, None)
        .unwrap()
        .entries
        .remove(0);
    let storage_sqlite::AttachmentDemand::Requested(asset) = storage
        .app_storage()
        .request_attachment_acquisition(GROUP, &entry, [0; 32], now)
        .unwrap()
    else {
        panic!("demand");
    };
    let job = storage
        .app_storage()
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
    )
    .unwrap();
    let status = storage
        .app_storage()
        .attachment_acquisition_status(&asset)
        .unwrap()
        .unwrap();
    assert_eq!(
        status.state,
        storage_sqlite::AttachmentAcquisitionState::Blocked
    );
    assert!(status.due.is_none());
}

mod legacy_migration;
mod resume;
mod storage_block;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_worker_disk_pause_does_not_consume_attempts() {
    let (_dir, mut client, store, _reference) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    admit_demands(&store.app_storage(), now, false).unwrap();
    let asset = store
        .app_storage()
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
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
        .app_storage()
        .attachment_acquisition_status(&asset)
        .unwrap()
        .unwrap();
    assert_eq!(status.attempts, 0);
    assert!(status.due.unwrap() > now);
    let progress = store
        .app_storage()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_cancellation_observation_error_is_not_cancellation() {
    let (_dir, _client, store, _reference) = offline_fixture().await;
    let now = crate::unix_now_seconds();
    admit_demands(&store.app_storage(), now, false).unwrap();
    let asset = store
        .app_storage()
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    let job = store
        .app_storage()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            .app_storage()
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
            .app_storage()
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
        .app_storage()
        .claim_attachment_acquisition(&asset, now, now + 100)
        .unwrap()
        .unwrap();
    let lease = runtime
        .shared
        .attachment_permissions
        .lease(
            &storage.app_storage().attachment_store_identity().unwrap(),
            &reference.media_type,
        )
        .unwrap();
    assert!(lease.allowed());
    let next = runtime
        .begin_attachment_permission_update("alice")
        .await
        .unwrap();
    assert!(!lease.allowed());
    assert!(
        !storage
            .app_storage()
            .begin_attachment_network_attempt(&job, now)
            .unwrap()
    );
    assert!(
        !storage
            .app_storage()
            .attachment_transfer_is_active(&job, now)
            .unwrap()
    );
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            ..MarmotAppConfig::white_noise()
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
    let app = storage.app_storage();
    let (mut reference, _) = crate::media::tests::attachment_worker_fixture(b"promotion bytes");
    reference.locators = vec![crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!("https://blob.example/{}", reference.ciphertext_sha256),
    }];
    seed(&storage, &reference, false);
    let now = crate::unix_now_seconds();
    let selected = app
        .attachment_history_page(GROUP, 1, None)
        .unwrap()
        .entries
        .remove(0);
    let storage_sqlite::AttachmentDemand::Requested(asset) = app
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
    let job = app
        .claim_attachment_acquisition(&asset, now, now + 180)
        .unwrap()
        .unwrap();
    let deadline = app
        .attachment_acquisition_status(&asset)
        .unwrap()
        .unwrap()
        .due;
    let identity = app.attachment_store_identity().unwrap();
    let permission = runtime
        .shared
        .attachment_permissions
        .lease(&identity, "image/png")
        .unwrap();
    assert!(app.promote_attachment_demand(&asset, now).unwrap());
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
        app.attachment_acquisition_status(&asset)
            .unwrap()
            .unwrap()
            .due,
        deadline
    );
    app.cancel_attachment_acquisition(&asset).unwrap();
    let (_, updates) = watch::channel(());
    tokio::time::timeout(
        Duration::from_secs(1),
        cancelled(storage, job, updates, None),
    )
    .await
    .unwrap();
}

/// Keep the real incoming GET and verified local read independent of outgoing SQL failures.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outgoing_retention_failure_preserves_all_source_projection_paths() {
    let (_dir, client, storage, reference) = offline_fixture().await;
    let connection = retention_fault_connection(&client.app);
    let token = storage
        .app_storage()
        .stage_attachment_uploads(GROUP, 3, &[b"retained worker bytes"], 10, 1_000_000)
        .unwrap();
    storage
        .app_storage()
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
            .app_storage()
            .recover_attachment_uploads(11, 64, 1_000_000)
            .unwrap()
            > 0
    );
}

/// Deliberate Retry may fetch a replacement even when a pending sibling holds a quarantine marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_worker_quarantined_outgoing_retry_downloads_once_and_retains() {
    download_without_engine_and_retain(true, "sent", false).await;
}

/// Reads a retained body the way the runtime does: the database authorizes
/// and locates it, and a media-file body is read through the account's store.
pub(super) fn read_retained(
    storage: &SqliteAccountStorage,
    app: &crate::MarmotApp,
    label: &str,
    reference: &storage_sqlite::AttachmentAssetRef,
    now: u64,
    offset: u64,
    limit: usize,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, AppError> {
    match storage
        .app_storage()
        .retained_attachment_read(reference, now, offset, limit)?
    {
        None => Ok(None),
        Some(storage_sqlite::RetainedAttachmentRead::Bytes(bytes)) => Ok(Some(bytes)),
        Some(storage_sqlite::RetainedAttachmentRead::MediaFile(id)) => {
            let media = app.account_media_store(label, storage)?;
            let mut bytes = zeroize::Zeroizing::new(vec![0; limit]);
            let Some(read) = media
                .read_at(&id, offset, &mut bytes)
                .map_err(storage_sqlite::media_storage_error)?
            else {
                return Ok(None);
            };
            bytes.truncate(read);
            Ok(Some(bytes))
        }
    }
}

/// Processes a media completion the way the worker loop does, including the
/// follow-up that a body's publication on the blocking pool sends back.
pub(super) async fn complete_and_settle(
    client: &mut AppClient,
    done: MediaHttpDone,
    shared: &RuntimeSharedServices,
    http: &MediaHttpContext,
    completions: &mut mpsc::UnboundedReceiver<MediaHttpDone>,
) {
    let publishes = matches!(
        &done.completion,
        MediaHttpCompletion::Attachment { result: Ok(_), .. }
    );
    complete_media_http(client, done, shared, http).await;
    if publishes {
        let retained = tokio::time::timeout(Duration::from_secs(60), completions.recv())
            .await
            .expect("publication finishes on the blocking pool")
            .expect("publication completion");
        assert!(matches!(
            retained.completion,
            MediaHttpCompletion::AttachmentRetained { .. }
        ));
        complete_media_http(client, retained, shared, http).await;
    }
}

/// Records a second message carrying the same attachment as `seed`, then
/// downloads it "elsewhere": its body is retained in the media store directly.
fn retain_twin(
    client: &AppClient,
    storage: &SqliteAccountStorage,
    reference: &crate::MediaAttachmentReference,
) {
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
    let (message, source) = ("44".repeat(32), "55".repeat(32));
    storage
        .app_storage()
        .record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(),
            message_id_hex: message.clone(),
            source_message_id_hex: Some(source.clone()),
            source_epoch: Some(3),
            direction: "received".into(),
            sender: "33".repeat(32),
            plaintext: String::new(),
            kind: 9,
            tags: vec![tag],
            recorded_at: 11,
            received_at: 11,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    let now = crate::unix_now_seconds();
    admit_demands(&storage.app_storage(), now, false).unwrap();
    let twin = storage
        .app_storage()
        .attachment_transfer_status(GROUP, &message, &source, 0, now, true)
        .unwrap()
        .unwrap()
        .reference
        .unwrap();
    let job = storage
        .app_storage()
        .claim_attachment_acquisition(&twin, now, now + 600)
        .unwrap()
        .unwrap();
    let body = b"retained worker bytes";
    let media = client
        .app
        .account_media_store(&client.state.label, storage)
        .unwrap();
    let clock = crate::unix_now_seconds;
    assert!(matches!(
        media
            .publish(
                &storage.app_storage().attachment_publication(&job, &clock),
                media_store::Category::Retained,
                &mut std::io::Cursor::new(&body[..]),
                body.len() as u64,
                job.plaintext_digest().unwrap(),
                now,
                &|| false,
            )
            .unwrap(),
        media_store::PublishOutcome::Published(_)
    ));
}

/// Content another slot already retains is attached before the download-only
/// gates, so neither low disk (no room for a new body) nor missing
/// source-epoch material (no way to decrypt one) can defer or fail the slot.
async fn reuse_skips_download_gates(low_disk: bool) {
    let (dir, mut client, storage, reference) = offline_fixture().await;
    // The source epoch's key is missing: a download could not be prepared.
    assert!(
        client
            .prepare_background_attachment_download(
                &GroupId::new(vec![0xab; 16]),
                reference.clone(),
                1024
            )
            .unwrap()
            .is_none()
    );
    retain_twin(&client, &storage, &reference);
    if low_disk {
        crate::media::attachment_resume::test_free_space::set(dir.path(), 0);
    }
    let now = crate::unix_now_seconds();
    admit_demands(&storage.app_storage(), now, false).unwrap();
    let shared = RuntimeSharedServices::default();
    let (http, mut completions) = context();
    let mut admission = Admission::default();
    schedule(&client, &shared, &http, &mut admission).unwrap();
    admission.ready().await;
    schedule(&client, &shared, &http, &mut admission).unwrap();
    let done = tokio::time::timeout(Duration::from_secs(10), completions.recv())
        .await
        .expect("the retained twin is attached without waiting on a download")
        .unwrap();
    assert!(matches!(
        &done.completion,
        MediaHttpCompletion::Attachment {
            result: Ok(crate::client::AcquiredMediaBody::Retained),
            ..
        }
    ));
    complete_and_settle(&mut client, done, &shared, &http, &mut completions).await;
    let (message, source) = ("11".repeat(32), "22".repeat(32));
    let status = storage
        .app_storage()
        .attachment_transfer_status(GROUP, &message, &source, 0, now, true)
        .unwrap()
        .unwrap();
    assert_eq!(status.state, storage_sqlite::AttachmentTransferState::Ready);
    assert_eq!(
        &*read_retained(
            &storage,
            &client.app,
            &client.state.label,
            &status.reference.unwrap(),
            crate::unix_now_seconds(),
            0,
            100
        )
        .unwrap()
        .unwrap(),
        b"retained worker bytes"
    );
    if low_disk {
        crate::media::attachment_resume::test_free_space::clear(dir.path());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_reuse_attaches_a_retained_twin_despite_low_disk() {
    reuse_skips_download_gates(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_reuse_attaches_a_retained_twin_without_source_epoch_material() {
    reuse_skips_download_gates(false).await;
}

/// A media store is created like a database open: refused once storage
/// closes, even by a caller still holding a database handle, and every store
/// created before the close is closed with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn media_stores_close_with_storage_and_are_refused_afterwards() {
    let (_dir, client, storage, _) = offline_fixture().await;
    let media = client.app.account_media_store("alice", &storage).unwrap();
    assert!(!media.is_closed());
    client.app.close_storage().unwrap();
    assert!(media.is_closed());
    assert!(client.app.account_media_store("alice", &storage).is_err());
}

/// A caller still holding a database handle that removal evicted can neither
/// recreate the account's media store afterwards nor, once the account is
/// opened again, replace and close the new store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evicted_database_handles_cannot_create_or_replace_media_stores() {
    let (_dir, client, stale, _) = offline_fixture().await;
    let app = &client.app;
    let evicted = app.account_media_store("alice", &stale).unwrap();
    app.drop_account_caches("alice");
    assert!(evicted.is_closed());
    assert!(app.account_media_store("alice", &stale).is_err());

    let reopened = app.account_storage("alice").unwrap();
    assert!(!reopened.shares_connection_with(&stale));
    let current = app.account_media_store("alice", &reopened).unwrap();
    assert!(app.account_media_store("alice", &stale).is_err());
    assert!(
        !current.is_closed(),
        "a stale handle must not close the current store"
    );
    assert!(
        !app.account_media_store("alice", &reopened)
            .unwrap()
            .is_closed()
    );
}

/// Automatic demand does not fetch an attachment already past the "Keep
/// media" window (mdk#2314 step 10): it shows as cleaned by the setting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_media_skips_automatic_demand_past_the_window() {
    let (_dir, _client, store, _reference) = offline_fixture().await;
    let app_storage = store.app_storage();
    app_storage
        .set_attachment_keep_media(storage_sqlite::AttachmentKeepMedia::ThirtyDays)
        .unwrap();
    let now = crate::unix_now_seconds();
    admit_demands(&app_storage, now, false).unwrap();
    assert!(
        app_storage
            .due_attachment_acquisitions(now, 1)
            .unwrap()
            .is_empty(),
        "nothing to fetch"
    );
    let status = app_storage
        .attachment_transfer_status(GROUP, &"11".repeat(32), &"22".repeat(32), 0, now, true)
        .unwrap()
        .unwrap();
    assert_eq!(
        status.state,
        storage_sqlite::AttachmentTransferState::CleanedBySetting
    );
}

/// The maintenance batch at worker start applies "Keep media" to retained
/// attachments, then waits an hour before sweeping again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_maintenance_batch_cleans_past_the_keep_media_window() {
    let (_dir, client, store, _reference) = offline_fixture().await;
    let app_storage = store.app_storage();
    let now = crate::unix_now_seconds();
    admit_demands(&app_storage, now, false).unwrap();
    let asset = app_storage
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    let job = app_storage
        .claim_attachment_acquisition(&asset, now, now + LEASE_SECONDS)
        .unwrap()
        .unwrap();
    assert_eq!(
        app_storage
            .complete_attachment_acquisition(&job, b"retained worker bytes", now, 10_000_000)
            .unwrap(),
        storage_sqlite::AttachmentPublishResult::Published
    );
    app_storage
        .set_attachment_keep_media(storage_sqlite::AttachmentKeepMedia::OneYear)
        .unwrap();

    let shared = RuntimeSharedServices::default();
    let updates = shared.attachment_updates.subscribe();
    let mut admission = Admission::default();
    spawn_legacy_migration(&client, &shared, &mut admission);
    admission.legacy_migration.take().unwrap().await.unwrap();
    let status = app_storage
        .attachment_transfer_status(GROUP, &"11".repeat(32), &"22".repeat(32), 0, now, true)
        .unwrap()
        .unwrap();
    assert_eq!(
        status.state,
        storage_sqlite::AttachmentTransferState::CleanedBySetting
    );
    assert!(updates.has_changed().unwrap(), "observers are woken");
    assert!(
        admission.keep_media_due.unwrap()
            > std::time::Instant::now() + KEEP_MEDIA_SWEEP_INTERVAL - Duration::from_secs(60)
    );
    assert!(
        !admission
            .keep_media_more
            .load(std::sync::atomic::Ordering::Acquire)
    );
}
