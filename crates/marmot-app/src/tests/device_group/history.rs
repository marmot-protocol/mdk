//! A chat's history moved between devices as history bundles (mdk#2628 4.2a),
//! before their transport exists. The sender leaves out what a bundle must not
//! carry; the receiver only adds rows, marks each with the sending device's
//! slot, never counts them as unread, and never moves its read position. No
//! device group gives or takes history.

use super::*;
use crate::history_bundle::{
    BundledEvent, ChatPosition, HISTORY_BUNDLE_MAX_PLAINTEXT, HistoryBundle, seal_history_bundle,
};
use crate::messages::AppMessageIntent;
use cgka_traits::MarmotAppEvent;
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION,
};

const PHONE_SLOT: [u8; 32] = [0x11; 32];

fn sealed(bundle: &HistoryBundle) -> crate::client::DevSealedHistoryBundle {
    let sealed = seal_history_bundle(bundle).unwrap();
    crate::client::DevSealedHistoryBundle {
        key: *sealed.key,
        ciphertext_sha256: sealed.ciphertext_sha256,
        ciphertext: sealed.ciphertext,
    }
}

fn refusal<T: std::fmt::Debug>(result: Result<T, AppError>) -> &'static str {
    match result {
        Err(AppError::DeviceGroupRefused(reason)) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn send(client: &mut AppClient, chat: &GroupId, intent: AppMessageIntent) -> String {
    client.send_app_event(chat, intent).await.unwrap().0.id
}

fn text(content: &str) -> AppMessageIntent {
    AppMessageIntent::Chat {
        content: content.to_owned(),
    }
}

/// Bob joins Alice's chat after it has history. Alice's bundle gives him what
/// he missed, except the message she deleted and the reaction to it, and
/// leaves the message he received live as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_who_joined_later_imports_the_history_it_missed() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_group_app_at(&dir, relay.clone());
    remember_test_member_inbox(&app, &bob_account.account_id_hex, "wss://relay.example");
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let chat = alice
        .create_group("book club", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let chat_hex = hex::encode(chat.as_slice());

    let first = send(&mut alice, &chat, text("first")).await;
    let gone = send(&mut alice, &chat, text("deleted later")).await;
    let reaction = alice
        .react_to_message(&chat, &gone, "+")
        .await
        .unwrap()
        .message_ids;
    assert_eq!(reaction.len(), 1);
    let deletion = send(
        &mut alice,
        &chat,
        AppMessageIntent::Delete {
            target_message_id: gone.clone(),
        },
    )
    .await;
    alice
        .invite_members(&chat, &[&bob_account.account_id_hex])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let mut cursor = 0;
    deliver_new(&mut bob, &relay, &mut cursor).await;
    bob.sync().await.unwrap();
    bob.accept_group_invite(&chat).unwrap();
    let live = send(&mut alice, &chat, text("after bob joined")).await;
    deliver_new(&mut bob, &relay, &mut cursor).await;
    bob.sync().await.unwrap();
    let storage = app.account_storage("bob").unwrap();
    let storage = storage.app_storage();
    assert!(
        storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );
    let unread = |storage: &storage_sqlite::SqliteAppStorage| {
        storage
            .refresh_chat_list_row(&bob_account.account_id_hex, &chat_hex, &|_, _| false)
            .unwrap()
            .unwrap()
            .unread_count
    };
    let live_unread = unread(&storage);

    let bundles = alice.dev_export_chat_history(&chat).unwrap();
    assert_eq!(bundles.len(), 1);
    let update = bob
        .dev_import_history_bundle(&chat, &PHONE_SLOT, &bundles[0])
        .unwrap()
        .expect("the history is new");
    assert_eq!(update.chat_list_row.unwrap().unread_count, live_unread);
    let imported = storage
        .timeline_message(&chat_hex, &first)
        .unwrap()
        .expect("imported");
    assert_eq!(imported.plaintext, "first");
    assert_eq!(imported.source_message_id_hex, None);
    assert_eq!(
        storage.app_event_import_source(&chat_hex, &first).unwrap(),
        Some(PHONE_SLOT)
    );
    // The deletion travels; the message it deleted and the reaction do not.
    assert!(
        storage
            .timeline_message(&chat_hex, &gone)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        storage
            .app_event_import_source(&chat_hex, &deletion)
            .unwrap(),
        Some(PHONE_SLOT)
    );
    let rows = storage
        .history_export_page(&chat_hex, None, unix_now_seconds(), 100)
        .unwrap();
    assert!(rows.iter().all(|row| row.message_id_hex != gone));
    assert_eq!(
        rows.iter()
            .filter(|row| row
                .event
                .as_ref()
                .is_some_and(|event| event.event.kind == 7))
            .count(),
        0,
        "no reaction reached bob"
    );
    let live_row = storage.timeline_message(&chat_hex, &live).unwrap().unwrap();
    assert!(live_row.source_message_id_hex.is_some());
    assert_eq!(
        storage.app_event_import_source(&chat_hex, &live).unwrap(),
        None
    );
    // Imported rows are never unread, and importing reads nothing.
    assert_eq!(unread(&storage), live_unread);
    assert_eq!(
        app.chat_list_row("bob", &chat_hex)
            .unwrap()
            .unwrap()
            .last_read_message_id_hex,
        None
    );

    // The same bundle again changes nothing.
    assert!(
        bob.dev_import_history_bundle(&chat, &PHONE_SLOT, &bundles[0])
            .unwrap()
            .is_none()
    );

    // A reaction to a message Bob lacks, from another device, changes no
    // timeline row, yet names a new latest import, so hosts are told
    // (mdk#2628 4.2d).
    bob.take_chat_history_imports_changed();
    const TABLET_SLOT: [u8; 32] = [0x22; 32];
    let orphan = MarmotAppEvent::new(
        bob_account.account_id_hex.clone(),
        3,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![vec![EVENT_REF_TAG.to_owned(), "99".repeat(32)]],
        "+",
    );
    let mut reaction_only = HistoryBundle::new(
        chat.as_slice(),
        ChatPosition::of(&orphan, 0),
        ChatPosition::of(&orphan, 0),
    );
    reaction_only.events = vec![BundledEvent {
        event: orphan.clone(),
        epoch: 0,
        retention: None,
        grant: None,
        keys: None,
    }];
    assert!(
        bob.dev_import_history_bundle(&chat, &TABLET_SLOT, &sealed(&reaction_only))
            .unwrap()
            .is_none(),
        "no timeline row changed"
    );
    assert_eq!(
        storage
            .app_event_import_source(&chat_hex, &orphan.id)
            .unwrap(),
        Some(TABLET_SLOT)
    );
    assert!(bob.take_chat_history_imports_changed());
    assert!(matches!(
        &bob.chat_history_imports().unwrap()[..],
        [crate::ChatHistoryImport {
            state: crate::ChatHistoryImportState::Imported { from, .. },
            ..
        }] if from.device_slot_id_hex == hex::encode(TABLET_SLOT)
    ));
    bob.dev_import_history_bundle(&chat, &TABLET_SLOT, &sealed(&reaction_only))
        .unwrap();
    assert!(!bob.take_chat_history_imports_changed(), "nothing new");

    // A bundle for another chat, or whose hash its message did not vouch for,
    // is refused whole. An event whose id does not match its content is
    // dropped alone.
    let honest = MarmotAppEvent::new(
        bob_account.account_id_hex.clone(),
        1,
        MARMOT_APP_EVENT_KIND_CHAT,
        Vec::new(),
        "honest",
    );
    let mut forged = MarmotAppEvent::new(
        bob_account.account_id_hex.clone(),
        2,
        MARMOT_APP_EVENT_KIND_CHAT,
        Vec::new(),
        "said",
    );
    forged.content = "rewritten".to_owned();
    let device_group_control = MarmotAppEvent::new(
        bob_account.account_id_hex.clone(),
        3,
        crate::small_state::KIND_SMALL_STATE_UPDATE,
        Vec::new(),
        r#"{"v":1,"items":[]}"#,
    );
    let malformed_media = vec![
        "imeta".to_owned(),
        format!("v {}", crate::media::EncryptedMediaVersion::V1.as_str()),
    ];
    let rejected_comment = MarmotAppEvent::new(
        bob_account.account_id_hex.clone(),
        2,
        1111,
        vec![vec!["k".into(), "1".into()], malformed_media.clone()],
        "malformed legacy comment attachment",
    );
    let custom_events = [
        (1111, vec!["k".into(), "not-a-kind".into()]),
        (1111, vec!["K".into(), "1".into()]),
        (42, vec!["k".into(), "1".into()]),
    ]
    .map(|(kind, marker)| {
        MarmotAppEvent::new(
            bob_account.account_id_hex.clone(),
            2,
            kind,
            vec![marker, malformed_media.clone()],
            "app-defined metadata stays unchanged",
        )
    });
    let mut bundle = HistoryBundle::new(
        chat.as_slice(),
        ChatPosition::of(&honest, 0),
        ChatPosition::of(&device_group_control, 0),
    );
    bundle.events = [&honest, &forged, &device_group_control, &rejected_comment]
        .into_iter()
        .chain(custom_events.iter())
        .map(|event| BundledEvent {
            event: event.clone(),
            epoch: 0,
            retention: None,
            grant: None,
            keys: None,
        })
        .collect();
    let mut elsewhere = bundle.clone();
    elsewhere.chat = "77".repeat(16);
    assert_eq!(
        refusal(bob.dev_import_history_bundle(&chat, &PHONE_SLOT, &sealed(&elsewhere))),
        "history_bundle_chat"
    );
    let mut unvouched = sealed(&bundle);
    unvouched.ciphertext_sha256[0] ^= 1;
    assert_eq!(
        refusal(bob.dev_import_history_bundle(&chat, &PHONE_SLOT, &unvouched)),
        "history_bundle_hash"
    );
    bob.dev_import_history_bundle(&chat, &PHONE_SLOT, &sealed(&bundle))
        .unwrap()
        .expect("the honest event is new");
    assert!(
        storage
            .timeline_message(&chat_hex, &honest.id)
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .timeline_message(&chat_hex, &forged.id)
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .timeline_message(&chat_hex, &device_group_control.id)
            .unwrap()
            .is_none(),
        "history never projects a device-group control as a chat event"
    );
    assert_eq!(
        storage
            .app_event_import_provenance(&chat_hex, &device_group_control.id)
            .unwrap(),
        None
    );
    assert!(
        storage
            .timeline_message(&chat_hex, &rejected_comment.id)
            .unwrap()
            .is_none(),
        "comments obey the live path's message-fatal legacy media validation"
    );
    for event in custom_events {
        let imported = storage
            .timeline_message(&chat_hex, &event.id)
            .unwrap()
            .expect("custom imeta metadata is not interpreted as an attachment");
        assert_eq!(imported.plaintext, event.content);
        assert_eq!(imported.tags, event.tags);
    }
}

/// Bob joins after Alice sent a photo, reaction artwork and a comment image.
/// Their bundle supplies attachment slots and per-file keys so he can decrypt
/// without the source epoch. Unnamed keys and custom-event metadata acquire
/// no attachment semantics, and later exports preserve the imported keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_imported_photo_comes_with_its_attachment_key() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_group_app_at(&dir, relay.clone());
    remember_test_member_inbox(&app, &bob_account.account_id_hex, "wss://relay.example");
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let chat = alice
        .create_group("photos", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let chat_hex = hex::encode(chat.as_slice());

    let blossom = super::history_delivery::local_blossom();
    let plaintext = b"history comment image";
    let uploaded = alice
        .upload_media(
            &chat,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "photo.jpg".into(),
                    media_type: "image/jpeg".into(),
                    plaintext: plaintext.to_vec(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                send: false,
                blossom_server: Some(blossom.url.clone()),
                message_tags: Vec::new(),
            },
        )
        .await
        .unwrap();
    let reference = uploaded.attachments[0].reference.clone();
    let ciphertext_sha256 = reference.ciphertext_sha256.clone();
    let photo = send(
        &mut alice,
        &chat,
        AppMessageIntent::Media {
            message_tags: Vec::new(),
            caption: None,
            attachments: vec![reference.clone()],
        },
    )
    .await;
    let reaction = send(
        &mut alice,
        &chat,
        AppMessageIntent::Reaction {
            target_message_id: photo.clone(),
            emoji: ":photo:".into(),
            tags: vec![vec![
                "emoji".into(),
                "photo".into(),
                reference.locators[0].value.clone(),
            ]],
            attachments: vec![reference.clone()],
        },
    )
    .await;
    let alice_storage = app.account_storage("alice").unwrap();
    let alice_storage = alice_storage.app_storage();
    let epoch = alice_storage
        .timeline_message(&chat_hex, &photo)
        .unwrap()
        .unwrap()
        .source_epoch
        .unwrap();
    let secret = alice_storage
        .encrypted_media_epoch_secret(
            &chat_hex,
            crate::media::EncryptedMediaVersion::V2.component_id(),
            epoch,
        )
        .unwrap()
        .expect("upload cached its source epoch secret");
    let file_key =
        hex::encode(crate::media::media_file_key_for_reference(&secret, &reference).unwrap());
    let comment = send(
        &mut alice,
        &chat,
        AppMessageIntent::Custom {
            kind: 1111,
            tags: vec![
                vec!["k".into(), "not-a-kind".into()],
                vec!["k".into(), "01".into()],
                reference.imeta_tag(),
            ],
            content: "comment image".into(),
        },
    )
    .await;
    let custom = send(
        &mut alice,
        &chat,
        AppMessageIntent::Custom {
            kind: 1111,
            tags: vec![vec!["K".into(), "1".into()], reference.imeta_tag()],
            content: "app-defined image metadata".into(),
        },
    )
    .await;

    alice
        .invite_members(&chat, &[&bob_account.account_id_hex])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let mut cursor = 0;
    deliver_new(&mut bob, &relay, &mut cursor).await;
    bob.sync().await.unwrap();
    bob.accept_group_invite(&chat).unwrap();
    let source = crate::media::MediaAttachmentReference {
        source_epoch: epoch,
        source_epoch_identity: None,
        ..reference.clone()
    };
    assert!(
        bob.cache_attachment_source_epoch_secret(&chat, &photo, &source)
            .is_err()
    );

    let mut once_imeta = reference.imeta_tag();
    *once_imeta
        .iter_mut()
        .find(|field| field.starts_with("v "))
        .unwrap() = "v encrypted-media-view-once-v1".into();
    let created_at = unix_now_seconds();
    let marker = vec![
        "view-once".into(),
        "view-once-v1".into(),
        (created_at + 3600).to_string(),
    ];
    let mut unknown_marker = marker.clone();
    unknown_marker[1] = "unknown-version".into();
    let alice_id = app.account_home().account("alice").unwrap().account_id_hex;
    let once_events = [
        (vec![marker.clone(), once_imeta.clone()], ""),
        (vec![unknown_marker, once_imeta.clone()], ""),
        (vec![once_imeta.clone()], ""),
        (vec![marker.clone(), reference.imeta_tag()], ""),
        (vec![marker, once_imeta], "forbidden caption"),
    ]
    .map(|(tags, content)| {
        MarmotAppEvent::new(
            &alice_id,
            created_at,
            MARMOT_APP_EVENT_KIND_CHAT,
            tags,
            content,
        )
    });
    assert_eq!(
        once_events[0]
            .view_once_policy()
            .unwrap()
            .unwrap()
            .unopened_expires_at,
        created_at + 3600
    );
    for event in &once_events {
        app.record_account_app_event(
            "alice",
            &crate::AppMessageProjection {
                authority: None,
                message_id_hex: event.id.clone(),
                source_message_id_hex: Some(event.id.clone()),
                direction: "received".into(),
                group_id_hex: chat_hex.clone(),
                sender: event.pubkey.clone(),
                plaintext: event.content.clone(),
                kind: event.kind,
                tags: event.tags.clone(),
                source_epoch: Some(epoch),
                retention: None,
                recorded_at: Some(created_at),
                origin_commit_id: None,
                moderation_grant: false,
            },
        )
        .unwrap();
    }

    let mut bundle = alice
        .export_chat_history(&chat, None, HISTORY_BUNDLE_MAX_PLAINTEXT)
        .unwrap()
        .unwrap()
        .bundle;
    assert!(
        bundle
            .events
            .iter()
            .all(|event| once_events.iter().all(|once| event.event.id != once.id)),
        "the shared sibling/backup exporter omits once events, including malformed policies"
    );
    for id in [&reaction, &comment] {
        assert_eq!(
            bundle
                .events
                .iter()
                .find(|event| &event.event.id == id)
                .unwrap()
                .keys,
            Some(vec![crate::history_bundle::FileKey {
                ciphertext_sha256: ciphertext_sha256.clone(),
                key: file_key.clone(),
            }]),
            "reaction artwork and comment images carry their per-file keys"
        );
    }
    let custom_event = bundle
        .events
        .iter_mut()
        .find(|event| event.event.id == custom)
        .unwrap();
    assert_eq!(custom_event.keys, None);
    custom_event.keys = Some(vec![crate::history_bundle::FileKey {
        ciphertext_sha256: ciphertext_sha256.clone(),
        key: file_key.clone(),
    }]);
    let event = bundle
        .events
        .iter_mut()
        .find(|event| event.event.id == photo)
        .unwrap();
    assert_eq!(
        event.keys,
        Some(vec![crate::history_bundle::FileKey {
            ciphertext_sha256: ciphertext_sha256.clone(),
            key: file_key.clone(),
        }])
    );
    event
        .keys
        .as_mut()
        .unwrap()
        .push(crate::history_bundle::FileKey {
            ciphertext_sha256: "44".repeat(32),
            key: "55".repeat(32),
        });
    for event in &once_events {
        let position = ChatPosition::of(event, epoch);
        bundle.from = bundle.from.clone().min(position.clone());
        bundle.to = bundle.to.clone().max(position);
        bundle.events.push(BundledEvent {
            event: event.clone(),
            epoch,
            retention: None,
            grant: None,
            keys: Some(vec![crate::history_bundle::FileKey {
                ciphertext_sha256: ciphertext_sha256.clone(),
                key: file_key.clone(),
            }]),
        });
    }
    bob.dev_import_history_bundle(&chat, &PHONE_SLOT, &sealed(&bundle))
        .unwrap()
        .expect("the photo is new");

    let storage = app.account_storage("bob").unwrap();
    let storage = storage.app_storage();
    for event in &once_events {
        assert_eq!(
            storage.timeline_message(&chat_hex, &event.id).unwrap(),
            None,
            "portable history cannot create a once message"
        );
        assert!(
            storage
                .imported_media_file_keys(&chat_hex, &event.id)
                .unwrap()
                .is_empty(),
            "portable history cannot import a once attachment key"
        );
        assert_eq!(
            storage
                .app_event_import_provenance(&chat_hex, &event.id)
                .unwrap(),
            None
        );
    }
    assert_eq!(
        storage
            .imported_media_file_keys(&chat_hex, &photo)
            .unwrap()
            .iter()
            .map(|key| (key.ciphertext_sha256.clone(), hex::encode(*key.key)))
            .collect::<Vec<_>>(),
        vec![(ciphertext_sha256.clone(), file_key.clone())]
    );
    let slots = storage
        .attachment_history_page(&chat_hex, 10, None)
        .unwrap()
        .entries;
    assert_eq!(slots.len(), 3);
    for id in [&photo, &reaction, &comment] {
        let slot = slots
            .iter()
            .find(|slot| &slot.message_id_hex == id)
            .unwrap();
        assert_eq!(&slot.source_message_id_hex, id);
        assert_eq!(slot.source_epoch, Some(epoch));
        assert!(
            storage
                .imported_media_file_keys(&chat_hex, id)
                .unwrap()
                .iter()
                .map(|key| hex::encode(*key.key))
                .collect::<Vec<_>>()
                == vec![file_key.clone()],
            "the imported source retains exactly its named file key"
        );
    }
    bob.cache_attachment_source_epoch_secret(&chat, &reaction, &source)
        .expect("the imported key opens reaction artwork");
    bob.cache_attachment_source_epoch_secret(&chat, &photo, &source)
        .expect("the imported key opens the photo");
    bob.cache_attachment_source_epoch_secret(&chat, &comment, &source)
        .expect("the imported key opens the comment image");
    assert!(
        storage
            .imported_media_file_keys(&chat_hex, &custom)
            .unwrap()
            .is_empty(),
        "unmarked kind 1111 does not acquire attachment semantics"
    );
    let prepared_comment = bob
        .prepare_background_attachment_download_for_message(
            &chat,
            Some(&comment),
            source.clone(),
            1024,
        )
        .unwrap()
        .expect("the imported comment key permits acquisition");
    assert!(prepared_comment.opens_with_imported_key());
    assert_eq!(
        storage
            .encrypted_media_epoch_secret(
                &chat_hex,
                crate::media::EncryptedMediaVersion::V2.component_id(),
                epoch,
            )
            .unwrap(),
        None,
        "the importing sibling has no source epoch secret"
    );
    assert_eq!(
        prepared_comment.run(None).await.unwrap().plaintext,
        plaintext.as_slice(),
        "the sibling decrypts comment image bytes without the source epoch"
    );
    let prepared = bob
        .prepare_background_attachment_download_for_message(
            &chat,
            Some(&photo),
            source.clone(),
            1024,
        )
        .unwrap()
        .expect("the imported key opens the photo");
    assert!(prepared.opens_with_imported_key());

    // The key belongs to the imported photo. A message Bob received himself
    // that names the same file waits for its epoch's secret instead.
    let received = "ee".repeat(32);
    assert!(
        bob.prepare_background_attachment_download_for_message(
            &chat,
            Some(&received),
            source.clone(),
            1024,
        )
        .unwrap()
        .is_none()
    );
    assert!(
        bob.cache_attachment_source_epoch_secret(&chat, &received, &source)
            .is_err()
    );
    // Once the epoch's secret is here, it opens even the imported photo.
    storage
        .remember_encrypted_media_epoch_secret(
            &chat_hex,
            crate::media::EncryptedMediaVersion::V2.component_id(),
            epoch,
            &secret,
        )
        .unwrap();
    let prepared = bob
        .prepare_background_attachment_download_for_message(
            &chat,
            Some(&photo),
            source.clone(),
            1024,
        )
        .unwrap()
        .unwrap();
    assert!(!prepared.opens_with_imported_key());

    let passed_on = bob
        .export_chat_history(&chat, None, HISTORY_BUNDLE_MAX_PLAINTEXT)
        .unwrap()
        .unwrap()
        .bundle;
    for id in [&reaction, &comment] {
        assert_eq!(
            passed_on
                .events
                .iter()
                .find(|event| &event.event.id == id)
                .unwrap()
                .keys,
            Some(vec![crate::history_bundle::FileKey {
                ciphertext_sha256: ciphertext_sha256.clone(),
                key: file_key.clone(),
            }]),
            "a later export preserves reaction and comment keys"
        );
    }
    let event = passed_on
        .events
        .iter()
        .find(|event| event.event.id == photo)
        .unwrap();
    assert_eq!(
        event.keys,
        Some(vec![crate::history_bundle::FileKey {
            ciphertext_sha256,
            key: file_key,
        }])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_group_never_gives_or_takes_history() {
    let Devices {
        _dirs,
        relay,
        phone_app: _phone_app,
        laptop_app: _laptop_app,
        mut phone,
        mut laptop,
        link,
    } = phone_and_laptop().await;
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let device_group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let event = MarmotAppEvent::new(
        "bb".repeat(32),
        1,
        MARMOT_APP_EVENT_KIND_CHAT,
        Vec::new(),
        "hi",
    );
    let position = ChatPosition::of(&event, 0);
    let bundle = sealed(&HistoryBundle::new(
        device_group.as_slice(),
        position.clone(),
        position,
    ));

    for client in [&mut phone, &mut laptop] {
        assert_eq!(
            refusal(client.dev_export_chat_history(&device_group)),
            "history_of_device_group"
        );
        assert_eq!(
            refusal(client.dev_import_history_bundle(&device_group, &PHONE_SLOT, &bundle)),
            "history_of_device_group"
        );
    }
    let unknown = GroupId::new(vec![0x77; 16]);
    match laptop.dev_export_chat_history(&unknown) {
        Err(AppError::UnknownGroup(_)) => {}
        other => panic!("expected an unknown group, got {other:?}"),
    }
}
