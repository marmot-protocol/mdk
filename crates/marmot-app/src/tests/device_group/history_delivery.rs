//! Sealed history deliveries (mdk#2628 4.2b and 4.2c, D76, D77): a chat's
//! history sent through the device group to one sibling, by the device whose
//! own Commit added it. The sender owes the history before it sends
//! anything, and keeps owing it until every delivery reached a relay; a
//! delivery withdrawn, or whose publish fails for good, makes it owed again.
//! The receiver imports a delivery it can open once it holds the chat, and
//! parks it until then. A history too long for inline deliveries goes
//! through the chat's Blossom server.

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::history_delivery::{
    INLINE_BUNDLE_MAX_PLAINTEXT, KIND_HISTORY_DELIVERY, MAX_INLINE_BUNDLES,
};
use crate::messages::AppMessageIntent;
use cgka_traits::app_components::BLOSSOM_LOCATOR_KIND_V1;
use cgka_traits::storage::SiblingAddStorage as _;
use sha2::{Digest as _, Sha256};
use storage_sqlite::{ParkedBundle, SqliteAppStorage};

/// A Blossom server on loopback: an upload keeps the blob by its SHA-256 and
/// a fetch serves it. Uploads fail while `refuse_uploads` is set.
struct LocalBlossom {
    url: String,
    blobs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    refuse_uploads: Arc<AtomicBool>,
}

fn local_blossom() -> LocalBlossom {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let blobs = Arc::<Mutex<HashMap<String, Vec<u8>>>>::default();
    let refuse_uploads = Arc::<AtomicBool>::default();
    let (served, refused) = (blobs.clone(), refuse_uploads.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (served, refused) = (served.clone(), refused.clone());
            std::thread::spawn(move || serve_blossom(stream, &served, &refused));
        }
    });
    LocalBlossom {
        url,
        blobs,
        refuse_uploads,
    }
}

fn serve_blossom(
    stream: std::net::TcpStream,
    blobs: &Mutex<HashMap<String, Vec<u8>>>,
    refuse_uploads: &AtomicBool,
) {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    let mut len = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        if request.is_empty() {
            request = line;
        } else if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            len = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; len];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let respond = |status: &str, body: &[u8]| {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    };
    let mut parts = request.split_whitespace();
    let response = match (parts.next(), parts.next()) {
        (Some("PUT"), Some("/upload")) if refuse_uploads.load(Ordering::SeqCst) => {
            respond("500 Internal Server Error", b"")
        }
        (Some("PUT"), Some("/upload")) => {
            let hash = hex::encode(Sha256::digest(&body));
            blobs.lock().unwrap().insert(hash.clone(), body);
            respond("200 OK", format!(r#"{{"sha256":"{hash}"}}"#).as_bytes())
        }
        (Some("GET"), Some(path)) => match blobs.lock().unwrap().get(&path[1..]) {
            Some(blob) => respond("200 OK", blob),
            None => respond("404 Not Found", b""),
        },
        _ => respond("405 Method Not Allowed", b""),
    };
    let _ = reader.get_mut().write_all(&response);
}

/// Point `chat`'s encrypted-media endpoints at `server` alone.
async fn use_blossom(client: &mut AppClient, chat: &GroupId, locator_kind: &str, server: &str) {
    client
        .replace_encrypted_media_blob_endpoints(
            chat,
            vec![crate::AppBlobEndpoint {
                locator_kind: locator_kind.to_owned(),
                base_url: server.to_owned(),
            }],
        )
        .await
        .unwrap();
}

fn storage(app: &MarmotApp) -> SqliteAppStorage {
    app.account_storage("alice").unwrap().app_storage()
}

fn published_count(relay: &ScriptedPushRelayClient) -> usize {
    relay.published_events.lock().unwrap().len()
}

async fn send_text(client: &mut AppClient, chat: &GroupId, content: &str) -> String {
    client
        .send_app_event(
            chat,
            AppMessageIntent::Chat {
                content: content.to_owned(),
            },
        )
        .await
        .unwrap()
        .0
        .id
}

/// The phone edits the laptop's roster entry and the laptop takes the
/// commit.
async fn edit_laptop_entry(
    devices: &mut Devices,
    group: &GroupId,
    edit: impl FnOnce(&mut DeviceEntryV1),
) {
    let laptop_slot = slot_of(&devices.laptop);
    let mut cursor = published_count(&devices.relay);
    let edited = devices
        .phone
        .runtime
        .edit_device_roster_entry(group, &laptop_slot, &[], edit)
        .await
        .unwrap();
    assert!(matches!(edited, DeviceRosterEdit::Committed(_)));
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    devices.laptop.sync().await.unwrap();
}

/// The phone adds the laptop's tagged KeyPackage to `chat`; the laptop joins.
async fn add_laptop(devices: &mut Devices, chat: &GroupId) {
    let mut cursor = published_count(&devices.relay);
    let key_package = published_key_package(&mut devices.laptop, &devices.relay).await;
    let effects = devices
        .phone
        .runtime
        .send(SendIntent::Invite {
            group_id: chat.clone(),
            key_packages: vec![key_package],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    devices
        .phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    devices.laptop.sync().await.unwrap();
    devices.laptop.accept_group_invite(chat).unwrap();
}

/// Tagging devices whose laptop asks for history, and a chat the phone has
/// one message in.
async fn history_devices() -> (Devices, GroupId, GroupId, String) {
    let (mut devices, group) = tagging_devices().await;
    assert!(
        roster(&devices.phone, &group).devices[&slot_of(&devices.laptop)]
            .history_key
            .is_some(),
        "the laptop's history key rides on its tag-key commit"
    );
    edit_laptop_entry(&mut devices, &group, |entry| {
        entry.settings.bring_history = true;
    })
    .await;
    let chat = devices.phone.create_group("team", &[]).await.unwrap();
    let first = send_text(&mut devices.phone, &chat, "before the laptop").await;
    (devices, group, chat, first)
}

/// The phone's confirmed Commit that adds the laptop to a chat owes the
/// laptop that chat's history, once its entry asks for history. One delivery
/// carries it; the laptop imports it, marked with the phone's slot, even
/// though it holds a later device-group epoch than the delivery's. An add
/// while the entry asks for none sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_device_that_adds_a_sibling_to_a_chat_sends_it_the_history() {
    let (mut devices, group) = tagging_devices().await;
    let phone_storage = storage(&devices.phone_app);
    let quiet = devices.phone.create_group("quiet", &[]).await.unwrap();
    send_text(&mut devices.phone, &quiet, "never sent").await;
    add_laptop(&mut devices, &quiet).await;
    let adds = devices
        .phone_app
        .account_storage("alice")
        .unwrap()
        .sibling_adds()
        .unwrap();
    assert_eq!(adds.len(), 1, "the add commit records the laptop");
    assert_eq!(adds[0].slot, slot_of(&devices.laptop));
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(
        published_count(&devices.relay),
        before,
        "the laptop's entry asks for no history"
    );
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    edit_laptop_entry(&mut devices, &group, |entry| {
        entry.settings.bring_history = true;
    })
    .await;
    let chat = devices.phone.create_group("team", &[]).await.unwrap();
    let chat_hex = hex::encode(chat.as_slice());
    let first = send_text(&mut devices.phone, &chat, "before the laptop").await;
    add_laptop(&mut devices, &chat).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );
    // The laptop's second KeyPackage moved the device group on, and the phone
    // sends before it takes that commit: the laptop reads who sent the
    // delivery at the delivery's epoch, not its own later one.
    assert!(
        devices.laptop.runtime.group_record(&group).unwrap().epoch
            > devices.phone.runtime.group_record(&group).unwrap().epoch
    );
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before + 1, "one delivery");
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
    assert!(
        devices
            .phone_app
            .account_storage("alice")
            .unwrap()
            .sibling_adds()
            .unwrap()
            .is_empty()
    );
    devices.laptop.take_pending_projection_updates();
    deliver_all(&mut devices.laptop, &devices.relay).await;

    let imported = laptop_storage
        .timeline_message(&chat_hex, &first)
        .unwrap()
        .expect("imported");
    assert_eq!(imported.plaintext, "before the laptop");
    assert_eq!(
        laptop_storage
            .app_event_import_source(&chat_hex, &first)
            .unwrap(),
        Some(slot_of(&devices.phone))
    );
    assert!(
        devices
            .laptop
            .take_pending_projection_updates()
            .iter()
            .any(|update| update.group_id_hex == chat_hex)
    );
    assert!(
        laptop_storage
            .device_group_messages()
            .unwrap()
            .iter()
            .any(|(.., kind)| *kind == KIND_HISTORY_DELIVERY),
        "the reader records the delivery, so its withdrawal owes no small state"
    );
    assert!(
        devices
            .laptop_app
            .account_storage("alice")
            .unwrap()
            .sibling_adds()
            .unwrap()
            .is_empty(),
        "only the adder owes the history"
    );
}

/// A delivery the laptop reads before it holds the chat waits for it, and the
/// laptop's next maintenance pass after joining imports it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_read_before_the_chat_waits_until_the_sibling_joins() {
    let (mut devices, _group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    // The delivery overtakes the Welcome.
    devices
        .phone
        .dev_record_sibling_add(&chat, &slot_of(&devices.laptop))
        .unwrap();
    devices.phone.drive_history_deliveries().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert_eq!(
        laptop_storage.parked_history_delivery_chats().unwrap(),
        std::slice::from_ref(&chat_hex)
    );

    add_laptop(&mut devices, &chat).await;
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );
    devices.laptop.drive_history_deliveries().await;
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_some()
    );
    assert!(
        laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
    );
}

/// A delivery sealed to a key other than the laptop's is refused: nothing is
/// imported or parked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_the_receiver_cannot_open_is_refused() {
    let (mut devices, group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    add_laptop(&mut devices, &chat).await;
    let phone_key = devices.phone.runtime.history_public_key().unwrap();
    edit_laptop_entry(&mut devices, &group, |entry| {
        entry.history_key = Some(phone_key);
    })
    .await;
    devices.phone.drive_history_deliveries().await;
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );
    assert!(
        laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
    );
}

/// A history whose delivery reached no relay stays owed and goes at the
/// next pass. Withdrawing a sent delivery, or a later drain reporting that
/// its publish failed for good, makes it owed again; the receiver imports
/// the copies without adding a row twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_history_stays_owed_until_it_reaches_a_relay_and_again_once_withdrawn_or_failed() {
    let (mut devices, group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    add_laptop(&mut devices, &chat).await;
    let phone_storage = storage(&devices.phone_app);

    devices.relay.reject_next_publish();
    devices.phone.drive_history_deliveries().await;
    assert_eq!(phone_storage.unsent_history_deliveries().unwrap().len(), 1);
    devices.phone.drive_history_deliveries().await;
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    let (_, _, message_id, _) = phone_storage
        .device_group_messages()
        .unwrap()
        .into_iter()
        .rfind(|(.., kind)| *kind == KIND_HISTORY_DELIVERY)
        .expect("the delivery is recorded");
    let message_id = MessageId::new(hex::decode(message_id.unwrap()).unwrap());
    devices
        .phone
        .observe_device_group_event(&GroupEvent::AppMessageInvalidated {
            group_id: group.clone(),
            message_id,
            epoch: cgka_traits::EpochId(0),
            reason: cgka_traits::engine::AppMessageInvalidationReason::LosingBranch,
            decrypted_payload_ref: None,
        })
        .unwrap();
    assert_eq!(phone_storage.unsent_history_deliveries().unwrap().len(), 1);
    devices.phone.drive_history_deliveries().await;
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    let (_, app_event_id, message_id, _) = phone_storage
        .device_group_messages()
        .unwrap()
        .into_iter()
        .rfind(|(.., kind)| *kind == KIND_HISTORY_DELIVERY)
        .expect("the second delivery is recorded");
    let failed = marmot_session::AccountDeviceEffects {
        failed_app_messages: vec![marmot_session::FailedApplicationMessage {
            group_id: group.clone(),
            app_event_id,
            message_id: MessageId::new(hex::decode(message_id.unwrap()).unwrap()),
            reason: "every relay refused it".to_owned(),
        }],
        ..Default::default()
    };
    let _ = devices.phone.observe_drained_session_events(&failed).await;
    assert_eq!(phone_storage.unsent_history_deliveries().unwrap().len(), 1);
    devices.phone.drive_history_deliveries().await;
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        laptop_storage
            .history_export_page(&chat_hex, None, crate::unix_now_seconds(), 64)
            .unwrap()
            .iter()
            .filter(|row| row.message_id_hex == first)
            .count(),
        1,
        "imported once"
    );
}

/// A history that fills the inline bundles a link may send goes out, one
/// delivery per bundle. One that needs more goes through the chat's Blossom
/// server: the phone uploads its one bundle, then sends one delivery naming
/// the server; the laptop parks it, fetches the blob and imports every
/// message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_history_too_long_to_send_inline_goes_through_blossom() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    let phone_storage = storage(&devices.phone_app);
    let blossom = local_blossom();
    // Two of these overflow one inline bundle, so each takes its own; the
    // first shares its bundle with the short message before it. Each differs,
    // so none shares another's id.
    let long = "x".repeat(15_000);
    for index in 0..MAX_INLINE_BUNDLES {
        send_text(&mut devices.phone, &chat, &format!("{index}{long}")).await;
    }
    add_laptop(&mut devices, &chat).await;
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before + MAX_INLINE_BUNDLES);
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    let longer = devices.phone.create_group("longer", &[]).await.unwrap();
    let longer_hex = hex::encode(longer.as_slice());
    use_blossom(
        &mut devices.phone,
        &longer,
        BLOSSOM_LOCATOR_KIND_V1,
        &blossom.url,
    )
    .await;
    let mut sent = Vec::new();
    for index in 0..=MAX_INLINE_BUNDLES {
        sent.push(send_text(&mut devices.phone, &longer, &format!("{index}{long}")).await);
    }
    add_laptop(&mut devices, &longer).await;
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before, "none goes inline");
    assert!(blossom.blobs.lock().unwrap().is_empty());
    devices.phone.drive_history_blobs().await;
    assert_eq!(blossom.blobs.lock().unwrap().len(), 1, "one 8 MiB bundle");
    assert_eq!(published_count(&devices.relay), before + 1);
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );

    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert_eq!(
        laptop_storage.parked_history_delivery_chats().unwrap(),
        std::slice::from_ref(&longer_hex),
        "a Blossom delivery parks until its blob is fetched"
    );
    devices.laptop.drive_history_blobs().await;
    for id in &sent {
        assert!(
            laptop_storage
                .timeline_message(&longer_hex, id)
                .unwrap()
                .is_some()
        );
    }
    assert!(
        laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
    );
}

/// Through the runtime, the account worker's maintenance pass fetches a
/// parked Blossom delivery off the worker, and its messages reach
/// subscribers as the fetch completes, not at the next pass 15 s later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_fetches_a_blossom_history_and_shows_it_at_once() {
    let (mut devices, _group, _chat, _first) = history_devices().await;
    let blossom = local_blossom();
    let long = "x".repeat(15_000);
    let longer = devices.phone.create_group("longer", &[]).await.unwrap();
    let longer_hex = hex::encode(longer.as_slice());
    use_blossom(
        &mut devices.phone,
        &longer,
        BLOSSOM_LOCATOR_KIND_V1,
        &blossom.url,
    )
    .await;
    for index in 0..=MAX_INLINE_BUNDLES {
        send_text(&mut devices.phone, &longer, &format!("{index}{long}")).await;
    }
    add_laptop(&mut devices, &longer).await;
    devices.phone.drive_history_deliveries().await;
    devices.phone.drive_history_blobs().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    assert_eq!(
        laptop_storage.parked_history_delivery_chats().unwrap(),
        std::slice::from_ref(&longer_hex)
    );

    let Devices {
        _dirs,
        relay,
        laptop_app,
        laptop,
        ..
    } = devices;
    drop(laptop);
    let account_id_hex = laptop_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let _eose = scripted_eose_pump(laptop_app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the worker fetches and imports the blob");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::ProjectionUpdated(published))
                    if published.account_id_hex == account_id_hex
                        && published.update.group_id_hex == longer_hex
                        && !published.update.timeline_messages.is_empty() =>
                {
                    break;
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => panic!("events closed"),
            }
        }
    })
    .await
    .expect("the imported history is published as the fetch completes");
    runtime.shutdown().await;
}

/// An upload the server refuses leaves the history owed until its wait ends,
/// then it goes. A blob the server no longer holds, or serves altered, keeps
/// the delivery parked until its wait ends; the laptop imports it once the
/// server serves the blob as uploaded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_blossom_upload_or_fetch_tries_again_later() {
    let (mut devices, _group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    let phone_storage = storage(&devices.phone_app);
    let blossom = local_blossom();
    use_blossom(
        &mut devices.phone,
        &chat,
        BLOSSOM_LOCATOR_KIND_V1,
        &blossom.url,
    )
    .await;
    // An event too large for an inline bundle sends the history through
    // Blossom.
    send_text(
        &mut devices.phone,
        &chat,
        &"y".repeat(INLINE_BUNDLE_MAX_PLAINTEXT),
    )
    .await;
    add_laptop(&mut devices, &chat).await;
    devices.phone.drive_history_deliveries().await;

    blossom.refuse_uploads.store(true, Ordering::SeqCst);
    let before = published_count(&devices.relay);
    devices.phone.drive_history_blobs().await;
    assert_eq!(published_count(&devices.relay), before);
    let owed = phone_storage.unsent_history_deliveries().unwrap().remove(0);
    assert_eq!(owed.blossom_attempts, 1);
    assert!(owed.blossom_due_at.unwrap() > crate::unix_now_seconds());
    blossom.refuse_uploads.store(false, Ordering::SeqCst);
    devices.phone.drive_history_blobs().await;
    assert_eq!(published_count(&devices.relay), before, "it waits");
    phone_storage
        .defer_blossom_history_delivery(&owed, 0)
        .unwrap();
    devices.phone.drive_history_blobs().await;
    assert_eq!(published_count(&devices.relay), before + 1);

    let (hash, blob) = blossom.blobs.lock().unwrap().drain().next().unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    let fetch_attempts =
        || match &laptop_storage.parked_history_deliveries(&chat_hex).unwrap()[0].bundle {
            ParkedBundle::Blossom { fetch_attempts, .. } => *fetch_attempts,
            ParkedBundle::Inline(_) => panic!("a Blossom delivery"),
        };
    devices.laptop.drive_history_blobs().await;
    assert_eq!(fetch_attempts(), 1, "the blob is gone");
    let parked = laptop_storage.parked_history_deliveries(&chat_hex).unwrap()[0].clone();
    let mut altered = blob.clone();
    altered[0] ^= 1;
    blossom.blobs.lock().unwrap().insert(hash.clone(), altered);
    laptop_storage
        .defer_parked_history_fetch(&parked.app_event_id, 0)
        .unwrap();
    devices.laptop.drive_history_blobs().await;
    assert_eq!(fetch_attempts(), 3, "other bytes than its hash names");
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_none()
    );

    blossom.blobs.lock().unwrap().insert(hash, blob);
    laptop_storage
        .defer_parked_history_fetch(&parked.app_event_id, 0)
        .unwrap();
    devices.laptop.drive_history_blobs().await;
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_some()
    );
    assert!(
        laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
    );
}

/// A Blossom delivery the laptop reads before it holds the chat waits for
/// it: nothing is fetched until the laptop joins, then the blob is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blossom_delivery_read_before_the_chat_is_fetched_once_the_sibling_joins() {
    let (mut devices, _group, chat, first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    let blossom = local_blossom();
    use_blossom(
        &mut devices.phone,
        &chat,
        BLOSSOM_LOCATOR_KIND_V1,
        &blossom.url,
    )
    .await;
    send_text(
        &mut devices.phone,
        &chat,
        &"y".repeat(INLINE_BUNDLE_MAX_PLAINTEXT),
    )
    .await;
    // The delivery overtakes the Welcome.
    devices
        .phone
        .dev_record_sibling_add(&chat, &slot_of(&devices.laptop))
        .unwrap();
    devices.phone.drive_history_deliveries().await;
    devices.phone.drive_history_blobs().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let laptop_storage = storage(&devices.laptop_app);
    let fetch_attempts =
        || match &laptop_storage.parked_history_deliveries(&chat_hex).unwrap()[0].bundle {
            ParkedBundle::Blossom { fetch_attempts, .. } => *fetch_attempts,
            ParkedBundle::Inline(_) => panic!("a Blossom delivery"),
        };
    devices.laptop.drive_history_blobs().await;
    assert_eq!(fetch_attempts(), 0, "no fetch before the chat is held");

    add_laptop(&mut devices, &chat).await;
    devices.laptop.drive_history_blobs().await;
    assert!(
        laptop_storage
            .timeline_message(&chat_hex, &first)
            .unwrap()
            .is_some()
    );
    assert!(
        laptop_storage
            .parked_history_delivery_chats()
            .unwrap()
            .is_empty()
    );
}

/// Uploaded blobs whose deliveries reach no relay leave the history owed,
/// backing off even when the refusal owes it again; the next attempt uploads
/// afresh, under new keys, and sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blossom_history_whose_delivery_reaches_no_relay_is_sent_again() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    let phone_storage = storage(&devices.phone_app);
    let blossom = local_blossom();
    use_blossom(
        &mut devices.phone,
        &chat,
        BLOSSOM_LOCATOR_KIND_V1,
        &blossom.url,
    )
    .await;
    send_text(
        &mut devices.phone,
        &chat,
        &"y".repeat(INLINE_BUNDLE_MAX_PLAINTEXT),
    )
    .await;
    add_laptop(&mut devices, &chat).await;
    devices.phone.drive_history_deliveries().await;

    devices.relay.reject_next_publish();
    let before = published_count(&devices.relay);
    devices.phone.drive_history_blobs().await;
    assert_eq!(blossom.blobs.lock().unwrap().len(), 1);
    assert_eq!(published_count(&devices.relay), before);
    let owed = phone_storage.unsent_history_deliveries().unwrap().remove(0);
    assert_eq!(owed.blossom_attempts, 1);
    assert!(owed.blossom_due_at.unwrap() > crate::unix_now_seconds());

    phone_storage
        .defer_blossom_history_delivery(&owed, 0)
        .unwrap();
    devices.phone.drive_history_blobs().await;
    assert_eq!(blossom.blobs.lock().unwrap().len(), 2, "a fresh upload");
    assert_eq!(published_count(&devices.relay), before + 1);
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// A chat made where no media server is configured carries no media policy,
/// so it has no Blossom endpoint: its long history is forgotten unsent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_history_of_a_text_only_chat_is_forgotten() {
    let (devices, _group, _chat, _first) = history_devices().await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        phone,
        laptop,
        link,
    } = devices;
    drop(phone);
    drop(phone_app);
    let phone_app = MarmotApp::with_relay_and_config(
        _dirs[0].path(),
        "wss://relay.example",
        MarmotAppConfig::default()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0)
            .with_dev_device_groups(true)
            .with_allow_loopback_blob_endpoints(true),
    )
    .with_test_relay_client(relay.clone());
    let phone = phone_app.client("alice").await.unwrap();
    let mut devices = Devices {
        _dirs,
        relay,
        phone_app,
        laptop_app,
        phone,
        laptop,
        link,
    };
    let text_only = devices.phone.create_group("text only", &[]).await.unwrap();
    send_text(
        &mut devices.phone,
        &text_only,
        &"y".repeat(INLINE_BUNDLE_MAX_PLAINTEXT),
    )
    .await;
    add_laptop(&mut devices, &text_only).await;
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .len(),
        1,
        "owed through Blossom"
    );
    devices.phone.drive_history_blobs().await;
    assert_eq!(published_count(&devices.relay), before);
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// A history too long for inline deliveries, of a chat with no Blossom
/// endpoint, is forgotten without sending any of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_history_of_a_chat_with_no_blossom_endpoint_is_forgotten() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    use_blossom(
        &mut devices.phone,
        &chat,
        "other-v1",
        "https://store.example/",
    )
    .await;
    send_text(
        &mut devices.phone,
        &chat,
        &"y".repeat(INLINE_BUNDLE_MAX_PLAINTEXT),
    )
    .await;
    add_laptop(&mut devices, &chat).await;
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    devices.phone.drive_history_blobs().await;
    assert_eq!(published_count(&devices.relay), before);
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// A history longer than the cap sends its newest bundles: the walk starts
/// after the bundle before them, or at the start when the cap holds it all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_history_longer_than_the_cap_sends_its_newest_bundles() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    let chat_hex = hex::encode(chat.as_slice());
    let long = "x".repeat(15_000);
    for index in 0..4 {
        send_text(&mut devices.phone, &chat, &format!("{index}{long}")).await;
    }
    let mut ends = Vec::new();
    while let Some(exported) = devices
        .phone
        .export_chat_history(&chat, ends.last(), INLINE_BUNDLE_MAX_PLAINTEXT)
        .unwrap()
    {
        ends.push(exported.bundle.to);
    }
    assert_eq!(ends.len(), 4);
    let account = devices.phone_app.account_storage("alice").unwrap();
    let start = |cap| {
        crate::client::newest_bundles_start(
            &account,
            &chat,
            &chat_hex,
            INLINE_BUNDLE_MAX_PLAINTEXT,
            cap,
            true,
        )
        .unwrap()
    };
    assert_eq!(start(2), Some(ends[1].clone()));
    assert_eq!(start(3), Some(ends[0].clone()));
    assert_eq!(start(4), None);
    assert_eq!(start(16), None);
}

/// A storage failure while the history is exported is no refusal: the
/// history stays owed and goes once storage works again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_storage_failure_while_sending_leaves_the_history_owed() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    add_laptop(&mut devices, &chat).await;
    let phone_storage = storage(&devices.phone_app);
    phone_storage
        .execute_batch_for_test("ALTER TABLE message_timeline RENAME TO message_timeline_hidden")
        .unwrap();
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before);
    assert_eq!(phone_storage.unsent_history_deliveries().unwrap().len(), 1);
    phone_storage
        .execute_batch_for_test("ALTER TABLE message_timeline_hidden RENAME TO message_timeline")
        .unwrap();
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before + 1);
    assert!(
        phone_storage
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// An add this device recorded a week ago, before it stopped for longer than
/// that, is forgotten without owing or sending anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_add_a_week_old_is_forgotten_unsent() {
    let (mut devices, _group, chat, _first) = history_devices().await;
    let account = devices.phone_app.account_storage("alice").unwrap();
    let week_old = crate::unix_now_seconds() - storage_sqlite::HISTORY_DELIVERY_RETENTION_SECS - 1;
    account
        .record_sibling_adds(&chat, &[slot_of(&devices.laptop)], week_old)
        .unwrap();
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before);
    assert!(account.sibling_adds().unwrap().is_empty());
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// An add recorded for the device group itself, which the engine skips, owes
/// nothing: the device group is no chat whose history goes anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_add_to_the_device_group_owes_no_history() {
    let (mut devices, group, _chat, _first) = history_devices().await;
    devices
        .phone
        .dev_record_sibling_add(&group, &slot_of(&devices.laptop))
        .unwrap();
    let before = published_count(&devices.relay);
    devices.phone.drive_history_deliveries().await;
    assert_eq!(published_count(&devices.relay), before);
    assert!(
        storage(&devices.phone_app)
            .unsent_history_deliveries()
            .unwrap()
            .is_empty()
    );
}
