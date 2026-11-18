use super::*;
use crate::media::crypto::{
    ClaimedViewOnceConsumption, decrypt_claimed_view_once, derive_media_file_key, media_aad,
};
use crate::{EncryptedMediaVersion, MediaAttachmentReference, MediaLocator};
use cgka_traits::MarmotAppEvent as InnerEvent;
use sha2::{Digest, Sha256};
use storage_sqlite::{
    SqlCipherKey, SqliteAccountStorage, StoredAccountGroup, StoredAccountState, StoredAppEvent,
    ViewOnceClaim,
};

const GROUP: &str = "abababababababababababababababab";
const RECIPIENT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SECRET: [u8; 32] = [0x31; 32];

fn group_row() -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: GROUP.into(),
        endpoint: "wss://relay.example".into(),
        profile_name: String::new(),
        profile_description: String::new(),
        image_hash_hex: String::new(),
        image_key_hex: String::new(),
        image_nonce_hex: String::new(),
        image_upload_key_hex: String::new(),
        image_media_type: None,
        admin_keys_hex: String::new(),
        archived: false,
        pending_confirmation: false,
        member_count: Some(2),
        direct_member_ids_hex: None,
        presentation_member_ids_hex: None,
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
        nostr_routing_last_epoch: 1,
        prior_nostr_routes: Vec::new(),
        self_membership: crate::SelfMembership::Member,
        components: Vec::new(),
    }
}

fn fixture(
    now: u64,
    nonce_byte: u8,
) -> (StoredAppEvent, MediaAttachmentReference, Vec<u8>, Vec<u8>) {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let mut output = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([3, 7, 11, 255]),
    ))
    .write_to(&mut output, image::ImageFormat::Png)
    .unwrap();
    let plaintext = output.into_inner();
    let hash: [u8; 32] = Sha256::digest(&plaintext).into();
    let version = EncryptedMediaVersion::ViewOnceV1;
    let key = derive_media_file_key(&SECRET, version, &hash, "image/png", "view-once.png").unwrap();
    let aad = media_aad(version, &hash, "image/png", "view-once.png");
    let nonce = [nonce_byte; 12];
    let mut encrypted = plaintext.clone();
    ChaCha20Poly1305::new_from_slice(&key)
        .unwrap()
        .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut encrypted)
        .unwrap();
    let reference = MediaAttachmentReference {
        locators: vec![MediaLocator {
            kind: "blossom-v1".into(),
            value: "https://media.example/file".into(),
        }],
        ciphertext_sha256: hex::encode(Sha256::digest(&encrypted)),
        plaintext_sha256: hex::encode(hash),
        nonce_hex: hex::encode(nonce),
        file_name: "view-once.png".into(),
        media_type: "image/png".into(),
        version: version.as_str().into(),
        source_epoch: 1,
        source_epoch_identity: None,
        dim: None,
        thumbhash: None,
    };
    let inner = InnerEvent::new(
        "11".repeat(32),
        now,
        9,
        vec![
            reference.imeta_tag(),
            vec![
                "view-once".into(),
                "view-once-v1".into(),
                (now + 3600).to_string(),
            ],
        ],
        String::new(),
    );
    let event = StoredAppEvent {
        group_id_hex: GROUP.into(),
        message_id_hex: inner.id,
        source_message_id_hex: Some(hex::encode([nonce_byte; 32])),
        source_epoch: Some(1),
        direction: "received".into(),
        sender: inner.pubkey,
        plaintext: inner.content,
        kind: inner.kind,
        tags: inner.tags,
        recorded_at: now,
        received_at: now,
        origin_commit_id: None,
        moderation_grant: false,
    };
    (event, reference, encrypted, plaintext)
}

fn seed(store: &SqliteAccountStorage, event: &StoredAppEvent) {
    let storage = store.app_storage();
    storage
        .ensure_account_projection_with_identity("viewer", RECIPIENT)
        .unwrap();
    storage
        .save_account_projection_state(
            &StoredAccountState {
                label: "viewer".into(),
                groups: vec![group_row()],
                ..Default::default()
            },
            64,
            300,
        )
        .unwrap();
    let policy = InnerEvent::new(
        event.sender.clone(),
        event.recorded_at,
        event.kind,
        event.tags.clone(),
        event.plaintext.clone(),
    )
    .view_once_policy()
    .unwrap()
    .unwrap();
    storage
        .record_app_event_with_retention(
            event,
            Some(cgka_traits::app_event::AppMessageRetentionDecision {
                retention_seconds: 0,
                expires_at: None,
                view_once: Some(policy),
            }),
        )
        .unwrap();
}

fn claim(store: &SqliteAccountStorage, event: &StoredAppEvent) {
    assert!(matches!(
        store
            .app_storage()
            .claim_view_once(
                crate::media::view_once_content::VIEW_ONCE_MIME,
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                crate::unix_now_seconds()
            )
            .unwrap(),
        ViewOnceClaim::Claimed {
            source_epoch: 1,
            ..
        }
    ));
}

fn opening(
    app: &MarmotApp,
    store: &SqliteAccountStorage,
    event: &StoredAppEvent,
    claimed_at: tokio::time::Instant,
) -> Arc<ViewOnceViewer> {
    ViewOnceViewer::opening(
        app,
        "viewer",
        ViewOnceAccess {
            storage: store.app_storage(),
            group: GROUP.into(),
            message: event.message_id_hex.clone(),
            attachment_index: 0,
            expires_at: event.recorded_at + 3600,
            claimed_at,
        },
        app.view_once_sessions.reserve("viewer").unwrap(),
        "image/png".into(),
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn viewer_timeout_releases_slot() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    let (event, reference, encrypted, plaintext) = fixture(crate::unix_now_seconds(), 1);
    seed(&store, &event);
    let claimed_at = tokio::time::Instant::now();
    claim(&store, &event);
    tokio::time::advance(Duration::from_secs(VIEW_ONCE_VIEWER_SECONDS / 2)).await;
    let viewer = opening(&app, &store, &event, claimed_at);
    let bytes = decrypt_claimed_view_once(
        &reference,
        &SECRET,
        encrypted,
        ClaimedViewOnceConsumption::DurablyClaimed,
    )
    .unwrap();
    assert!(viewer.finish(bytes).await.unwrap());
    assert_eq!(
        &**viewer.read(0, 1024).await.unwrap().as_ref().unwrap(),
        &plaintext
    );
    tokio::time::advance(Duration::from_secs(VIEW_ONCE_VIEWER_SECONDS / 2)).await;
    assert!(viewer.read(0, 1024).await.unwrap().is_none());
    assert!(viewer.inner.body.lock().unwrap().bytes.is_none());
    let permit = app
        .view_once_sessions
        .reserve("viewer")
        .expect("timeout releases per-account admission");
    drop(permit);
    assert_eq!(
        store
            .app_storage()
            .claim_view_once(
                crate::media::view_once_content::VIEW_ONCE_MIME,
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                crate::unix_now_seconds()
            )
            .unwrap(),
        ViewOnceClaim::Consumed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_sibling_source_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account = app.account_home().create_account("viewer").unwrap();
    let mut state = app.load_state("viewer").unwrap();
    state.groups.push(crate::AppGroupRecord::new(
        GROUP.into(),
        crate::AppGroupNostrRoutingComponent::new(
            cgka_traits::NostrRoutingV1::new([0xAB; 32], vec!["wss://relay.example".into()])
                .unwrap(),
        )
        .unwrap(),
        String::new(),
        String::new(),
        crate::AppGroupImageInput::default(),
        crate::AppGroupAdminPolicyComponent::new(Vec::new()),
        crate::AppGroupMessageRetentionComponent::disabled(),
    ));
    app.save_state(&state).unwrap();
    let now = crate::unix_now_seconds();
    let (mut event, _, _, _) = fixture(now, 45);
    let inner = InnerEvent::new(
        &account.account_id_hex,
        now,
        event.kind,
        event.tags.clone(),
        "",
    );
    let policy = inner.view_once_policy().unwrap();
    event.message_id_hex = inner.id.clone();
    event.sender = inner.pubkey;
    let projection = crate::AppMessageProjection {
        authority: None,
        message_id_hex: event.message_id_hex.clone(),
        source_message_id_hex: event.source_message_id_hex.clone(),
        direction: "received".into(),
        group_id_hex: GROUP.into(),
        sender: event.sender.clone(),
        plaintext: String::new(),
        kind: event.kind,
        tags: event.tags.clone(),
        source_epoch: event.source_epoch,
        retention: Some(cgka_traits::app_event::AppMessageRetentionDecision {
            retention_seconds: 0,
            expires_at: None,
            view_once: policy,
        }),
        recorded_at: Some(now),
        origin_commit_id: None,
        moderation_grant: false,
    };
    let update = app.record_account_app_event("viewer", &projection).unwrap();
    assert_eq!(
        update.timeline_messages[0]
            .view_once
            .as_ref()
            .unwrap()
            .state,
        crate::ViewOnceState::Sent
    );
    let row = app
        .timeline_message("viewer", GROUP, &event.message_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(row.direction, "sent");
    assert_eq!(row.source_message_id_hex, event.source_message_id_hex);
    assert_eq!(row.source_epoch, Some(1));
    assert_eq!(
        row.view_once.as_ref().unwrap().state,
        crate::ViewOnceState::Sent
    );
    let storage = app.account_storage("viewer").unwrap().app_storage();
    let prepared = storage
        .conversation_presentation_page(crate::TimelinePage {
            messages: vec![row],
            has_more_before: false,
            has_more_after: false,
        })
        .unwrap();
    assert_eq!(
        prepared.page().messages[0]
            .view_once
            .as_ref()
            .unwrap()
            .state,
        crate::ViewOnceState::Sent
    );
    assert_eq!(
        app.runtime()
            .view_once_state(
                "viewer",
                &cgka_traits::GroupId::new(hex::decode(GROUP).unwrap()),
                &event.message_id_hex,
                0
            )
            .await
            .unwrap(),
        crate::ViewOnceState::Sent
    );
    assert_eq!(
        storage
            .claim_view_once(
                crate::media::view_once_content::VIEW_ONCE_MIME,
                GROUP,
                &event.message_id_hex,
                0,
                &account.account_id_hex,
                now
            )
            .unwrap(),
        ViewOnceClaim::Unavailable
    );
    assert!(
        storage
            .invalidate_pending_sent_app_events_for_group(GROUP, "local_publish_failed")
            .unwrap()
            .is_none()
    );
    let reply = InnerEvent::new(
        "11".repeat(32),
        now,
        9,
        vec![vec!["e".into(), event.message_id_hex.clone()]],
        "reply",
    );
    let mut ordinary = projection.clone();
    ordinary.source_message_id_hex = Some(reply.id.clone());
    ordinary.message_id_hex = reply.id;
    ordinary.sender = reply.pubkey;
    ordinary.plaintext = reply.content;
    ordinary.tags = reply.tags;
    ordinary.retention = None;
    let update = app.record_account_app_event("viewer", &ordinary).unwrap();
    let reply = update
        .timeline_messages
        .iter()
        .find(|row| row.message_id_hex == ordinary.message_id_hex)
        .unwrap();
    assert_eq!(reply.direction, "received");
    assert_eq!(
        reply
            .reply_preview
            .as_ref()
            .unwrap()
            .view_once
            .as_ref()
            .unwrap()
            .state,
        crate::ViewOnceState::Sent
    );
    let own_ordinary = InnerEvent::new(
        account.account_id_hex,
        now,
        9,
        Vec::new(),
        "ordinary sibling message",
    );
    ordinary.source_message_id_hex = Some(own_ordinary.id.clone());
    ordinary.message_id_hex = own_ordinary.id;
    ordinary.sender = own_ordinary.pubkey;
    ordinary.plaintext = own_ordinary.content;
    ordinary.tags.clear();
    app.record_account_app_event("viewer", &ordinary).unwrap();
    assert_eq!(
        app.message_by_id("viewer", GROUP, &ordinary.message_id_hex)
            .unwrap()
            .unwrap()
            .direction,
        "received"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_secret_refusal_unspent() {
    let dir = tempfile::tempdir().unwrap();
    let mut deployment = crate::MarmotDeployment::neutral();
    deployment.new_group_media_endpoints = vec!["https://media.example".into()];
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::default().with_deployment(deployment),
    )
    .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
    let account = app.account_home().create_account("viewer").unwrap();
    let mut client = app.client("viewer").await.unwrap();
    let group = client
        .create_group("preclaim", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    client.enable_view_once(&group).await.unwrap();
    let source_epoch = client.runtime.epoch_pin(&group).unwrap().epoch.0;
    let group_hex = hex::encode(group.as_slice());
    let storage = app.account_storage("viewer").unwrap().app_storage();
    for (nonce, retired) in [(46, true), (47, false)] {
        let now = crate::unix_now_seconds();
        let (mut event, _, _, _) = fixture(now, nonce);
        event.group_id_hex = group_hex.clone();
        event.source_epoch = Some(source_epoch);
        let policy = InnerEvent::new(&event.sender, now, event.kind, event.tags.clone(), "")
            .view_once_policy()
            .unwrap();
        storage
            .record_app_event_with_retention(
                &event,
                Some(cgka_traits::app_event::AppMessageRetentionDecision {
                    retention_seconds: 0,
                    expires_at: None,
                    view_once: policy,
                }),
            )
            .unwrap();
        if retired {
            storage.execute_batch_for_test(&format!(
                "DELETE FROM encrypted_media_epoch_secret_references WHERE group_id_hex='{group_hex}' AND source_epoch={source_epoch}; INSERT INTO encrypted_media_epoch_secret_retirement_watermarks(group_id_hex,retired_through_epoch,retired_at_unix_seconds) VALUES('{group_hex}',{source_epoch},{now});"
            )).unwrap();
        } else {
            storage.execute_batch_for_test(&format!(
                "DELETE FROM encrypted_media_epoch_secret_retirement_watermarks WHERE group_id_hex='{group_hex}';"
            )).unwrap();
            for step in 0..7 {
                client
                    .update_group_profile(&group, Some(&format!("advanced {step}")), None)
                    .await
                    .unwrap();
            }
            storage.execute_batch_for_test(&format!(
                "DELETE FROM encrypted_media_epoch_secrets WHERE group_id_hex='{group_hex}' AND source_epoch={source_epoch};"
            )).unwrap();
        }
        assert!(
            storage
                .view_once_metadata(
                    &group_hex,
                    &event.message_id_hex,
                    0,
                    &account.account_id_hex,
                    now
                )
                .unwrap()
                .is_some()
        );
        let result = client
            .prepare_view_once_consume(
                &group,
                &event.message_id_hex,
                0,
                app.view_once_sessions.reserve("viewer").unwrap(),
            )
            .unwrap();
        assert!(matches!(
            result,
            crate::client::view_once::ViewOncePreparation::Terminal(
                crate::ViewOnceConsumeOutcome::Unavailable
            )
        ));
        assert_eq!(
            storage
                .view_once_state(&group_hex, &event.message_id_hex, 0, now)
                .unwrap(),
            crate::ViewOnceState::Unopened
        );
        drop(
            app.view_once_sessions
                .reserve("viewer")
                .expect("preclaim refusal releases the slot"),
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locator_refusal_is_unspent() {
    let dir = tempfile::tempdir().unwrap();
    let mut deployment = crate::MarmotDeployment::neutral();
    deployment.new_group_media_endpoints = vec!["https://media.example".into()];
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::default().with_deployment(deployment),
    )
    .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
    app.account_home().create_account("viewer").unwrap();
    let mut client = app.client("viewer").await.unwrap();
    let group = client
        .create_group("preclaim", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    client.enable_view_once(&group).await.unwrap();
    let source_epoch = client.runtime.epoch_pin(&group).unwrap().epoch.0;
    let group_hex = hex::encode(group.as_slice());
    let storage = app.account_storage("viewer").unwrap().app_storage();
    let now = crate::unix_now_seconds();
    let (mut event, _, _, _) = fixture(now, 49);
    event.group_id_hex = group_hex.clone();
    event.source_epoch = Some(source_epoch);
    let policy = InnerEvent::new(&event.sender, now, event.kind, event.tags.clone(), "")
        .view_once_policy()
        .unwrap();
    storage
        .record_app_event_with_retention(
            &event,
            Some(cgka_traits::app_event::AppMessageRetentionDecision {
                retention_seconds: 0,
                expires_at: None,
                view_once: policy,
            }),
        )
        .unwrap();
    client
        .replace_encrypted_media_blob_endpoints(
            &group,
            vec![crate::AppBlobEndpoint {
                locator_kind: "future-v1".into(),
                base_url: "https://media.example".into(),
            }],
        )
        .await
        .unwrap();
    let result = client
        .prepare_view_once_consume(
            &group,
            &event.message_id_hex,
            0,
            app.view_once_sessions.reserve("viewer").unwrap(),
        )
        .unwrap();
    assert!(matches!(
        result,
        crate::client::view_once::ViewOncePreparation::Terminal(
            crate::ViewOnceConsumeOutcome::Unavailable
        )
    ));
    assert_eq!(
        storage
            .view_once_state(&group_hex, &event.message_id_hex, 0, now)
            .unwrap(),
        crate::ViewOnceState::Unopened
    );
    drop(
        app.view_once_sessions
            .reserve("viewer")
            .expect("refusal releases the slot"),
    );
    client
        .replace_encrypted_media_blob_endpoints(
            &group,
            vec![crate::AppBlobEndpoint {
                locator_kind: "blossom-v1".into(),
                base_url: "https://192.168.1.1".into(),
            }],
        )
        .await
        .unwrap();
    let result = client
        .prepare_view_once_consume(
            &group,
            &event.message_id_hex,
            0,
            app.view_once_sessions.reserve("viewer").unwrap(),
        )
        .unwrap();
    assert!(matches!(
        result,
        crate::client::view_once::ViewOncePreparation::Terminal(
            crate::ViewOnceConsumeOutcome::Unavailable
        )
    ));
    assert_eq!(
        storage
            .view_once_state(&group_hex, &event.message_id_hex, 0, now)
            .unwrap(),
        crate::ViewOnceState::Unopened
    );
    drop(
        app.view_once_sessions
            .reserve("viewer")
            .expect("unusable URLs release the slot"),
    );
    client
        .replace_encrypted_media_blob_endpoints(
            &group,
            vec![crate::AppBlobEndpoint {
                locator_kind: "blossom-v1".into(),
                base_url: "https://media.example".into(),
            }],
        )
        .await
        .unwrap();
    let ready = client
        .prepare_view_once_consume(
            &group,
            &event.message_id_hex,
            0,
            app.view_once_sessions.reserve("viewer").unwrap(),
        )
        .unwrap();
    assert!(matches!(
        &ready,
        crate::client::view_once::ViewOncePreparation::Ready(_)
    ));
    assert_eq!(
        storage
            .view_once_state(&group_hex, &event.message_id_hex, 0, now)
            .unwrap(),
        crate::ViewOnceState::Consumed
    );
    drop(ready);
}

#[test]
fn mime_refusal_releases_slot() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    let now = crate::unix_now_seconds();
    let (mut event, _, _, _) = fixture(now, 3);
    event.tags[0]
        .iter_mut()
        .find(|field| field.starts_with("m "))
        .map(|field| *field = "m image/svg+xml".into())
        .unwrap();
    event.message_id_hex = cgka_traits::MarmotAppEvent::new(
        event.sender.clone(),
        event.recorded_at,
        event.kind,
        event.tags.clone(),
        event.plaintext.clone(),
    )
    .id;
    seed(&store, &event);
    let permit = app.view_once_sessions.reserve("viewer").unwrap();
    assert!(matches!(
        app.view_once_sessions.reserve("viewer"),
        Err(crate::AppError::AccountWorkerBusy)
    ));
    assert_eq!(
        store
            .app_storage()
            .claim_view_once(
                crate::media::view_once_content::VIEW_ONCE_MIME,
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                now
            )
            .unwrap(),
        ViewOnceClaim::Unavailable,
    );
    assert_eq!(
        store
            .app_storage()
            .view_once_state(GROUP, &event.message_id_hex, 0, now)
            .unwrap(),
        crate::ViewOnceState::Unopened,
    );
    drop(permit);
    drop(app.view_once_sessions.reserve("viewer").unwrap());
}

#[test]
fn unknown_profiles_stay_private() {
    let group = cgka_traits::GroupId::new(hex::decode(GROUP).unwrap());
    for version in [
        "encrypted-media-view-once-v999",
        "encrypted-media-view-once",
        "encrypted-media-v1",
    ] {
        let (event, _, _, _) = fixture(crate::unix_now_seconds(), 48);
        let mut tags = event.tags;
        tags[0][1] = format!("v {version}");
        if version != "encrypted-media-v1" {
            tags.truncate(1);
        } else {
            tags[0].push("ciphertext_sha256 malformed".into());
        }
        let inner = InnerEvent::new(&event.sender, event.recorded_at, 9, tags, "private caption");
        let payload = inner.encode().unwrap();
        let mut decoded = crate::groups::decode_received_event(
            &payload,
            &event.sender,
            None,
            &group,
            1,
            None,
            "source",
            event.recorded_at,
            None,
            false,
        )
        .expect("view-once grammar never invalidates the carrying app message");
        let host =
            crate::groups::host_group_event(&cgka_traits::engine::GroupEvent::MessageReceived {
                group_id: group.clone(),
                message_id: cgka_traits::MessageId::new(vec![48; 32]),
                sender: cgka_traits::MemberId::new(hex::decode(&event.sender).unwrap()),
                sender_leaf_index: None,
                epoch: cgka_traits::EpochId(1),
                payload,
                retention: None,
                authority: None,
                encrypted_media_secret: None,
            });
        let cgka_traits::engine::GroupEvent::MessageReceived { payload, .. } = host else {
            unreachable!()
        };
        assert!(payload.is_empty());
        redact_fields(&mut decoded.plaintext, &mut decoded.tags);
        assert_eq!(decoded.plaintext, "");
        assert!(is_view_once(&decoded.tags));
        assert!(
            decoded
                .tags
                .iter()
                .all(|tag| tag.first().is_some_and(|name| name == "view-once"))
        );
    }
}

#[test]
fn bad_marker_fields_are_private() {
    let mut plaintext = "private caption".to_owned();
    let mut tags = vec![
        vec![
            "view-once".into(),
            "unknown".into(),
            "100".into(),
            "private-caption".into(),
        ],
        vec!["view-once".into(), "private-locator".into()],
        vec!["imeta".into(), "locator private-ciphertext".into()],
    ];
    redact_fields(&mut plaintext, &mut tags);
    assert_eq!(plaintext, "");
    assert_eq!(tags, vec![vec!["view-once".to_owned()]]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_viewer_refuses_decode() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let store = SqliteAccountStorage::in_memory_for_test().unwrap();
    let (event, reference, encrypted, _) = fixture(crate::unix_now_seconds(), 2);
    seed(&store, &event);
    let claimed_at = tokio::time::Instant::now();
    claim(&store, &event);
    let viewer = opening(&app, &store, &event, claimed_at);
    app.close_storage().unwrap();
    let bytes = decrypt_claimed_view_once(
        &reference,
        &SECRET,
        encrypted,
        ClaimedViewOnceConsumption::DurablyClaimed,
    )
    .unwrap();
    assert!(!viewer.finish(bytes).await.unwrap());
    assert!(viewer.inner.body.lock().unwrap().bytes.is_none());
    assert!(viewer.read(0, 1024).await.unwrap().is_none());
    assert_eq!(
        store
            .app_storage()
            .claim_view_once(
                crate::media::view_once_content::VIEW_ONCE_MIME,
                GROUP,
                &event.message_id_hex,
                0,
                RECIPIENT,
                crate::unix_now_seconds()
            )
            .unwrap(),
        ViewOnceClaim::Consumed
    );
}

#[test]
fn view_once_crash_child() {
    let Ok(directory) = std::env::var("MDK_ONCE_CRASH_DIRECTORY") else {
        return;
    };
    let stage = std::env::var("MDK_ONCE_CRASH_STAGE").unwrap();
    let nonce = std::env::var("MDK_ONCE_CRASH_NONCE")
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let now = std::env::var("MDK_ONCE_CRASH_TIME")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let store = SqliteAccountStorage::open_encrypted(
        std::path::Path::new(&directory).join("session.sqlite"),
        &SqlCipherKey::raw([0x63; 32]),
    )
    .unwrap();
    let (event, reference, encrypted, plaintext) = fixture(now, nonce);
    let boundary = |name: &str| {
        if stage == name {
            use std::io::Write;
            println!("ONCE_CRASH_READY");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        boundary("before-claim");
        let claimed_at = tokio::time::Instant::now();
        claim(&store, &event);
        boundary("after-claim");
        let bytes = decrypt_claimed_view_once(
            &reference,
            &SECRET,
            encrypted,
            ClaimedViewOnceConsumption::DurablyClaimed,
        )
        .unwrap();
        boundary("after-decrypt");
        let app = MarmotApp::with_relay(
            std::path::Path::new(&directory).join("viewer-root"),
            "wss://relay.example",
        );
        let viewer = opening(&app, &store, &event, claimed_at);
        assert!(viewer.finish(bytes).await.unwrap());
        boundary("before-display");
        assert_eq!(
            &**viewer.read(0, 1024).await.unwrap().as_ref().unwrap(),
            &plaintext
        );
        boundary("after-display");
        viewer.close();
        assert!(viewer.read(0, 1024).await.unwrap().is_none());
        boundary("after-close");
        panic!("unknown crash boundary");
    });
}

#[test]
fn crashes_never_reopen_a_viewer() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.sqlite");
    let key = SqlCipherKey::raw([0x63; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let now = crate::unix_now_seconds();
    for (nonce, stage) in [
        "before-claim",
        "after-claim",
        "after-decrypt",
        "before-display",
        "after-display",
        "after-close",
    ]
    .into_iter()
    .enumerate()
    {
        let nonce = nonce as u8 + 10;
        let (event, _, _, _) = fixture(now, nonce);
        seed(&store, &event);
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "view_once::tests::view_once_crash_child",
                "--nocapture",
            ])
            .env("MDK_ONCE_CRASH_DIRECTORY", dir.path())
            .env("MDK_ONCE_CRASH_STAGE", stage)
            .env("MDK_ONCE_CRASH_NONCE", nonce.to_string())
            .env("MDK_ONCE_CRASH_TIME", now.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = KillOnDrop(child);
        let stdout = child.0.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let ready = std::io::BufReader::new(stdout)
                .lines()
                .any(|line| line.is_ok_and(|line| line == "ONCE_CRASH_READY"));
            let _ = send.send(ready);
        });
        assert!(
            receive.recv_timeout(Duration::from_secs(10)).unwrap(),
            "child reaches {stage}"
        );
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        reader.join().unwrap();
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let expected = if stage == "before-claim" {
            crate::ViewOnceState::Unopened
        } else {
            crate::ViewOnceState::Consumed
        };
        assert_eq!(
            reopened
                .app_storage()
                .view_once_state(GROUP, &event.message_id_hex, 0, now)
                .unwrap(),
            expected,
            "{stage}"
        );
        if expected == crate::ViewOnceState::Consumed {
            assert_eq!(
                reopened
                    .app_storage()
                    .claim_view_once(
                        crate::media::view_once_content::VIEW_ONCE_MIME,
                        GROUP,
                        &event.message_id_hex,
                        0,
                        RECIPIENT,
                        now
                    )
                    .unwrap(),
                ViewOnceClaim::Consumed
            );
            assert!(
                reopened
                    .app_storage()
                    .timeline_message(GROUP, &event.message_id_hex)
                    .unwrap()
                    .unwrap()
                    .media
                    .is_none()
            );
        }
    }
    assert!(!dir.path().join("viewer-root/handoff").exists());
    assert!(!dir.path().join("viewer-root/media-staging").exists());
}
