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
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;

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
    let chat = alice.create_group("book club", &[]).await.unwrap();
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
        .unwrap();
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
    let mut bundle = HistoryBundle::new(
        chat.as_slice(),
        ChatPosition::of(&honest, 0),
        ChatPosition::of(&forged, 0),
    );
    bundle.events = [&honest, &forged]
        .map(|event| BundledEvent {
            event: event.clone(),
            epoch: 0,
            retention: None,
            grant: None,
            keys: None,
        })
        .to_vec();
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
}

/// Bob joins after Alice sent a photo. He was never in that epoch, so he can
/// open the photo only with the key Alice's bundle carries for it: the
/// photo's message gets an attachment slot and the key, a key naming no
/// attachment is dropped, and Bob passes the key on when he exports.
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
    let chat = alice.create_group("photos", &[]).await.unwrap();
    let chat_hex = hex::encode(chat.as_slice());

    let ciphertext_sha256 = "11".repeat(32);
    let reference = crate::media::MediaAttachmentReference {
        locators: vec![crate::media::MediaLocator {
            kind: "blossom-v1".into(),
            value: format!("https://blossom.example/{ciphertext_sha256}"),
        }],
        ciphertext_sha256: ciphertext_sha256.clone(),
        plaintext_sha256: "22".repeat(32),
        nonce_hex: "33".repeat(12),
        file_name: "photo.jpg".into(),
        media_type: "image/jpeg".into(),
        version: crate::media::EncryptedMediaVersion::V2.as_str().into(),
        source_epoch: 0,
        dim: None,
        thumbhash: None,
    };
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
    let alice_storage = app.account_storage("alice").unwrap();
    let alice_storage = alice_storage.app_storage();
    let epoch = alice_storage
        .timeline_message(&chat_hex, &photo)
        .unwrap()
        .unwrap()
        .source_epoch
        .unwrap();
    let secret = [0x5a; 32];
    alice_storage
        .remember_encrypted_media_epoch_secret(
            &chat_hex,
            crate::media::EncryptedMediaVersion::V2.component_id(),
            epoch,
            &secret,
        )
        .unwrap();
    let file_key =
        hex::encode(crate::media::media_file_key_for_reference(&secret, &reference).unwrap());

    alice
        .invite_members(&chat, &[&bob_account.account_id_hex])
        .await
        .unwrap();
    let mut cursor = 0;
    deliver_new(&mut bob, &relay, &mut cursor).await;
    bob.sync().await.unwrap();
    bob.accept_group_invite(&chat).unwrap();
    let source = crate::media::MediaAttachmentReference {
        source_epoch: epoch,
        ..reference.clone()
    };
    assert!(
        bob.cache_attachment_source_epoch_secret(&chat, &photo, &source)
            .is_err()
    );

    let mut bundle = alice
        .export_chat_history(&chat, None, HISTORY_BUNDLE_MAX_PLAINTEXT)
        .unwrap()
        .unwrap();
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
    bob.dev_import_history_bundle(&chat, &PHONE_SLOT, &sealed(&bundle))
        .unwrap()
        .expect("the photo is new");

    let storage = app.account_storage("bob").unwrap();
    let storage = storage.app_storage();
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
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].message_id_hex, photo);
    assert_eq!(slots[0].source_message_id_hex, photo);
    assert_eq!(slots[0].source_epoch, Some(epoch));
    bob.cache_attachment_source_epoch_secret(&chat, &photo, &source)
        .expect("the imported key opens the photo");
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
        .unwrap();
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
