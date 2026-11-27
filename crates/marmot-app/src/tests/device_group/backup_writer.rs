//! Writing backups (mdk#2628 item 4.4b, D71, D79). The writer's pass
//! uploads the account's backup to the deployment's Blossom server and
//! lists it in the backup pointer; the backup counts only once a relay
//! accepts that pointer. Retention drops older backups, and a later pass
//! deletes the blobs of a backup or run that never counted or no longer
//! does, unless the pointer it fetched lists that backup. Only the writer
//! writes, at most daily, and new words mid-pass abandon the run. A sibling
//! takes over a writer that is leaving or quiet for a week. The tests move
//! due time by dating the pointer and ledger earlier. The startup admission
//! regression advances Tokio time only while the real startup future is held.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use super::backups::{answers, entropy_of, key_pair_of};
use super::devices::exchange;
use super::history_delivery::{LocalBlossom, local_blossom, send_text, storage};
use super::*;
use crate::backup_archive::{
    ArchiveKey, BackupHead, BackupIndex, BackupPointer, ListedBackup, PointerEntry, backup_address,
    open_backup_bundle, open_backup_small_state,
};
use crate::client::backup_writer::KIND_BACKUP_POINTER;
use crate::history_bundle::HISTORY_BUNDLE_MAX_PLAINTEXT;
use cgka_engine::recovery_key::{RECOVERY_ENTROPY_LEN, open_with_recovery_key};
use cgka_traits::app_components::AccountEntryV1;
use openmls_rust_crypto::RustCrypto;
use sha2::{Digest as _, Sha256};
use storage_sqlite::{BackupRunHead, BackupSchedule};

const DAY: u64 = 24 * 60 * 60;
/// Later than any delete or pass the ledger schedules.
const ANY_TIME: u64 = i64::MAX as u64;

/// Confirmed recovery words: their public half, entropy, private half and
/// phrase.
struct Words {
    public: Vec<u8>,
    entropy: [u8; RECOVERY_ENTROPY_LEN],
    private: Vec<u8>,
    phrase: String,
}

async fn confirm_words(device: &mut AppClient) -> Words {
    let shown = device.begin_recovery_words().unwrap();
    device
        .confirm_recovery_words(&answers(&shown))
        .await
        .unwrap();
    let (public, private) = key_pair_of(&shown);
    Words {
        public,
        entropy: entropy_of(&shown),
        private,
        phrase: shown.words.join(" "),
    }
}

/// Alice's phone and laptop on a deployment whose one Blossom server is
/// `blossom`. The phone, with no device group, confirmed words and holds a
/// chat with one message.
async fn lone_writer(blossom: &LocalBlossom) -> (Devices, GroupId, Words) {
    let mut devices = phone_and_laptop_on(MarmotDeployment {
        new_group_media_endpoints: vec![blossom.url.clone()],
        ..MarmotDeployment::white_noise()
    })
    .await;
    let words = confirm_words(&mut devices.phone).await;
    let chat = devices
        .phone
        .create_group("team", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    send_text(&mut devices.phone, &chat, "before the backup").await;
    (devices, chat, words)
}

/// [`lone_writer`] once the phone founds its device group with its key and
/// itself as writer, and the laptop joins.
async fn linked_writer(blossom: &LocalBlossom) -> (Devices, GroupId, GroupId, Words) {
    let (mut devices, chat, words) = lone_writer(blossom).await;
    devices
        .laptop
        .dev_record_confirmed_device_link(devices.link.clone())
        .unwrap();
    let group = devices
        .phone
        .dev_create_device_group(devices.link.clone())
        .await
        .unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert_eq!(
        roster(&devices.laptop, &group).account.backup_writer,
        Some(slot_of(&devices.phone))
    );
    (devices, group, chat, words)
}

/// The newest backup pointer the relay holds under `key`.
fn pointer_event(relay: &ScriptedPushRelayClient, key: &[u8]) -> Option<NostrTransportEvent> {
    let address = backup_address(key);
    relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| {
            event.kind == KIND_BACKUP_POINTER && event.tag_values("d").contains(&address.as_str())
        })
        .max_by_key(|event| event.created_at)
        .cloned()
}

fn pointer(relay: &ScriptedPushRelayClient, key: &[u8]) -> Vec<PointerEntry> {
    let event = pointer_event(relay, key).expect("a pointer is published");
    BackupPointer::open(&event.content, key).unwrap().backups
}

fn pointers_published(relay: &ScriptedPushRelayClient) -> usize {
    relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == KIND_BACKUP_POINTER)
        .count()
}

fn ids(backups: &[PointerEntry]) -> Vec<String> {
    backups.iter().map(|entry| entry.id.clone()).collect()
}

/// Publish a pointer listing `backups` under `key`, signed by the account
/// and newer than any before it, as another writer would.
async fn publish_pointer(
    device: &AppClient,
    relay: &ScriptedPushRelayClient,
    key: &[u8],
    backups: Vec<PointerEntry>,
) {
    publish_pointer_at(device, relay, key, backups, unix_now_seconds()).await;
}

/// [`publish_pointer`], made no earlier than `at`.
async fn publish_pointer_at(
    device: &AppClient,
    relay: &ScriptedPushRelayClient,
    key: &[u8],
    backups: Vec<PointerEntry>,
    at: u64,
) {
    let summary = device
        .app
        .account_home()
        .account(&device.state.label)
        .unwrap();
    let signer = device
        .app
        .account_signer_for_summary(&summary)
        .unwrap()
        .as_nostr_signer();
    let unsigned = NostrTransportEvent::new_unsigned_at(
        summary.account_id_hex,
        KIND_BACKUP_POINTER,
        vec![vec!["d".to_owned(), backup_address(key)]],
        BackupPointer::new(backups).seal(key).unwrap(),
        at,
    );
    let event = device
        .app
        .sign_replaceable_identity_event(&device.state.label, signer, &unsigned)
        .await
        .unwrap();
    relay.published_events.lock().unwrap().push(event);
}

/// Date every backup the pointer lists `by` seconds earlier.
async fn age_backups(device: &AppClient, relay: &ScriptedPushRelayClient, key: &[u8], by: u64) {
    let mut backups = pointer(relay, key);
    for entry in &mut backups {
        entry.written_at -= by;
    }
    publish_pointer(device, relay, key, backups).await;
}

/// Make `device`'s next backup pass due now.
fn due_now(device: &AppClient) {
    let ledger = storage(&device.app);
    let schedule = ledger.backup_schedule().unwrap();
    ledger
        .schedule_backup_pass(BackupSchedule {
            next_pass_at: 0,
            ..schedule
        })
        .unwrap();
}

/// Make every delete `device` owes under `key` due now.
fn deletes_due_now(device: &AppClient, key: &[u8]) {
    let ledger = storage(&device.app);
    for blob in ledger.due_condemned_backup_blobs(key, ANY_TIME).unwrap() {
        ledger
            .defer_condemned_backup_blob(&blob.sha256, &blob.server, 0)
            .unwrap();
    }
}

fn condemned(device: &AppClient, key: &[u8]) -> BTreeSet<String> {
    storage(&device.app)
        .due_condemned_backup_blobs(key, ANY_TIME)
        .unwrap()
        .into_iter()
        .map(|blob| blob.sha256)
        .collect()
}

/// The hashes of the blobs `blossom` holds.
fn held(blossom: &LocalBlossom) -> BTreeSet<String> {
    blossom.blobs.lock().unwrap().keys().cloned().collect()
}

/// The head and index of the backup `entry` lists, read from `blossom` with
/// the public half.
fn read_backup(
    blossom: &LocalBlossom,
    entry: &PointerEntry,
    key: &[u8],
) -> (BackupHead, BackupIndex) {
    let head = BackupHead::decode(&blossom.blobs.lock().unwrap()[&entry.head.sha256]).unwrap();
    let index = head.open_index(key).unwrap();
    (head, index)
}

/// The hashes of every blob of the backup `entry` lists.
fn blobs_of(blossom: &LocalBlossom, entry: &PointerEntry, key: &[u8]) -> BTreeSet<String> {
    let (_, index) = read_backup(blossom, entry, key);
    ListedBackup {
        entry: entry.clone(),
        index: Some(index),
    }
    .locators()
    .into_iter()
    .map(|locator| locator.sha256)
    .collect()
}

fn opened_archive_key(head: &BackupHead, words: &Words) -> Vec<u8> {
    let (context, sealed) = head.sealed_archive_key();
    open_with_recovery_key(&RustCrypto::default(), &words.entropy, &context, sealed)
        .unwrap()
        .expect("the words open the archive key")
        .to_vec()
}

/// The writer's pass uploads the account's backup to the deployment's
/// Blossom server and lists it in the backup pointer: kind 30078, signed by
/// the account, at the address the recovery key derives. The server then
/// holds exactly that backup's blobs, which open with the words to the
/// chat's export and this device's small state. The run leaves the ledger
/// once a relay accepts the pointer, and the next pass is due a day after
/// the backup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_writer_lists_its_backup_once_a_relay_accepts_the_pointer() {
    let blossom = local_blossom();
    let (mut devices, _group, chat, words) = linked_writer(&blossom).await;
    let chat_hex = hex::encode(chat.as_slice());
    devices
        .phone_app
        .set_chat_pinned("alice", &chat_hex, true)
        .unwrap();
    devices.phone.sync_small_state(&[]).unwrap();
    let ledger = storage(&devices.phone_app);
    let items = ledger.small_state_items().unwrap();
    assert!(!items.is_empty());

    devices.phone.drive_backup_pass().await;
    let event = pointer_event(&devices.relay, &words.public).expect("a pointer is published");
    assert_eq!(
        event.pubkey,
        devices
            .phone_app
            .account_home()
            .account("alice")
            .unwrap()
            .account_id_hex
    );
    let listed = pointer(&devices.relay, &words.public);
    assert_eq!(listed.len(), 1);
    let (head, index) = read_backup(&blossom, &listed[0], &words.public);
    assert_eq!(hex::encode(head.id), listed[0].id);
    assert_eq!(
        held(&blossom),
        blobs_of(&blossom, &listed[0], &words.public)
    );

    let archive_key = ArchiveKey::from_opened(&opened_archive_key(&head, &words)).unwrap();
    let blobs = blossom.blobs.lock().unwrap().clone();
    let bundles = index
        .blobs()
        .map(|(number, chat, blob)| {
            open_backup_bundle(&archive_key, number, chat, blob, &blobs[&blob.sha256]).unwrap()
        })
        .collect::<Vec<_>>();
    let export = devices
        .phone
        .export_chat_history(&chat, None, HISTORY_BUNDLE_MAX_PLAINTEXT)
        .unwrap()
        .unwrap()
        .bundle;
    assert_eq!(bundles, vec![export]);
    let small_state = index.small_state.as_ref().unwrap();
    assert_eq!(
        open_backup_small_state(&archive_key, small_state, &blobs[&small_state.sha256]).unwrap(),
        items
    );

    assert!(ledger.backup_runs().unwrap().is_empty());
    assert_eq!(
        ledger.backup_schedule().unwrap(),
        BackupSchedule {
            next_pass_at: listed[0].written_at + DAY,
            failed_passes: 0,
        }
    );
}

/// Only the writer writes, and no more than daily: a pass the day of a
/// backup writes nothing, nor does a sibling's pass, nor any pass once
/// backups are off, though a backup is due. A sibling takes nothing over
/// from a writer that just wrote, or while backups are off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_writer_writes_and_at_most_daily() {
    let blossom = local_blossom();
    let (mut devices, group, _chat, words) = linked_writer(&blossom).await;
    devices.phone.drive_backup_pass().await;
    let written = (pointers_published(&devices.relay), held(&blossom));
    assert_eq!(written.0, 1);

    for device in [&mut devices.phone, &mut devices.laptop] {
        due_now(device);
        device.drive_backup_pass().await;
    }
    assert_eq!(
        (pointers_published(&devices.relay), held(&blossom)),
        written
    );
    assert_eq!(
        roster(&devices.laptop, &group).account.backup_writer,
        Some(slot_of(&devices.phone))
    );

    age_backups(&devices.phone, &devices.relay, &words.public, 2 * DAY).await;
    devices.phone.turn_off_backups().await.unwrap();
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let written = (pointers_published(&devices.relay), held(&blossom));
    for device in [&mut devices.phone, &mut devices.laptop] {
        due_now(device);
        device.drive_backup_pass().await;
        device.drive_backup_takeover().await;
    }
    assert_eq!(
        (pointers_published(&devices.relay), held(&blossom)),
        written
    );
    for device in [&devices.phone, &devices.laptop] {
        assert_eq!(roster(device, &group).account, AccountEntryV1::default());
    }
}

/// A backup counts only once a relay accepts its pointer. Until then its
/// run stays in the ledger, nothing is condemned, and the pass counts as
/// failed; the next pass publishes the same backup again, uploading
/// nothing. A pointer every relay refuses for size is retried the same way,
/// and the pass logs it as a size refusal (mdk#2334).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_whose_pointer_no_relay_accepts_goes_out_again() {
    for too_large in [false, true] {
        a_refused_pointer_goes_out_again(too_large).await;
    }
}

async fn a_refused_pointer_goes_out_again(too_large: bool) {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let mut phone = devices.phone;
    if too_large {
        devices
            .relay
            .reject_publishes_of_kind_as_too_large(KIND_BACKUP_POINTER);
    } else {
        devices.relay.fail_publishes_of_kind(KIND_BACKUP_POINTER);
    }
    let logged = if too_large {
        "event_too_large"
    } else {
        "device_group_refused"
    };
    assert_eq!(phone.drive_backup_pass().await, Some(logged));
    let ledger = storage(&devices.phone_app);
    let runs = ledger.backup_runs().unwrap();
    assert_eq!(runs.len(), 1);
    assert!(runs[0].head.is_some());
    assert!(pointer_event(&devices.relay, &words.public).is_none());
    assert!(condemned(&phone, &words.public).is_empty());
    assert_eq!(ledger.backup_schedule().unwrap().failed_passes, 1);
    let uploaded = held(&blossom);
    assert!(!uploaded.is_empty());

    devices.relay.allow_all_publish_kinds();
    due_now(&phone);
    assert_eq!(phone.drive_backup_pass().await, None);
    assert_eq!(
        ids(&pointer(&devices.relay, &words.public)),
        vec![hex::encode(runs[0].backup_id)]
    );
    assert_eq!(held(&blossom), uploaded);
    assert!(ledger.backup_runs().unwrap().is_empty());
    assert_eq!(ledger.backup_schedule().unwrap().failed_passes, 0);
}

/// A run that never counts is abandoned and its blobs deleted, while the
/// listed backup stays whole: a run whose pointer no relay accepted for a
/// day, and a run a crash cut short before its head. A later pass deletes
/// their blobs, no sooner than an hour after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_that_never_counts_is_deleted_later() {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let (mut phone, relay, key) = (devices.phone, devices.relay, words.public);
    phone.drive_backup_pass().await;
    let first = pointer(&relay, &key).remove(0);
    let first_blobs = held(&blossom);

    age_backups(&phone, &relay, &key, 2 * DAY).await;
    relay.fail_publishes_of_kind(KIND_BACKUP_POINTER);
    due_now(&phone);
    phone.drive_backup_pass().await;
    relay.allow_all_publish_kinds();
    let ledger = storage(&devices.phone_app);
    let [unlisted] = <[_; 1]>::try_from(ledger.backup_runs().unwrap()).unwrap();
    let unlisted_blobs = &held(&blossom) - &first_blobs;
    ledger
        .record_backup_run_head(
            &unlisted.backup_id,
            &BackupRunHead {
                publish_until: 0,
                ..unlisted.head.unwrap()
            },
        )
        .unwrap();
    let cut_short = [0xc5; 16];
    let stray = b"one blob of a run cut short".to_vec();
    let stray_hash = hex::encode(Sha256::digest(&stray));
    ledger.begin_backup_run(&cut_short, &key, 1).unwrap();
    ledger
        .record_backup_run_blob(&cut_short, &stray_hash, &blossom.url)
        .unwrap();
    blossom
        .blobs
        .lock()
        .unwrap()
        .insert(stray_hash.clone(), stray);

    due_now(&phone);
    phone.drive_backup_pass().await;
    assert!(ledger.backup_runs().unwrap().is_empty());
    let listed = pointer(&relay, &key);
    assert_eq!(ids(&listed[1..]), vec![first.id.clone()]);
    let mut never_counted = unlisted_blobs;
    never_counted.insert(stray_hash);
    assert_eq!(condemned(&phone, &key), never_counted);
    assert!(held(&blossom).is_superset(&never_counted));

    deletes_due_now(&phone, &key);
    phone.drive_backup_pass().await;
    assert_eq!(
        held(&blossom),
        &first_blobs | &blobs_of(&blossom, &listed[0], &key)
    );
    assert!(condemned(&phone, &key).is_empty());
}

/// Retention drops a backup newer ones cover and condemns its blobs before
/// the pointer that drops it goes out. A later pass deletes them, unless
/// the pointer it fetched lists that backup again, as another writer's may:
/// then they are forgotten, never deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_backup_is_deleted_later_unless_the_pointer_lists_it_again() {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let (mut phone, relay, key) = (devices.phone, devices.relay, words.public);
    // Daily backups of one unchanged chat: the oldest of three holds
    // nothing the newer two do not.
    let mut written = Vec::new();
    for day in 0..3 {
        if day > 0 {
            age_backups(&phone, &relay, &key, 2 * DAY).await;
            due_now(&phone);
        }
        phone.drive_backup_pass().await;
        let newest = pointer(&relay, &key).remove(0);
        let blobs = blobs_of(&blossom, &newest, &key);
        written.push((newest, blobs));
    }
    let listed = pointer(&relay, &key);
    assert_eq!(
        ids(&listed),
        vec![written[2].0.id.clone(), written[1].0.id.clone()]
    );
    assert_eq!(condemned(&phone, &key), written[0].1);
    assert!(held(&blossom).is_superset(&written[0].1));

    let mut relisted = listed.clone();
    relisted.push(PointerEntry {
        written_at: listed[1].written_at - 2 * DAY,
        ..written[0].0.clone()
    });
    publish_pointer(&phone, &relay, &key, relisted).await;
    deletes_due_now(&phone, &key);
    phone.drive_backup_pass().await;
    assert!(condemned(&phone, &key).is_empty());
    assert!(held(&blossom).is_superset(&written[0].1));

    age_backups(&phone, &relay, &key, 2 * DAY).await;
    due_now(&phone);
    phone.drive_backup_pass().await;
    let listed = pointer(&relay, &key);
    assert_eq!(ids(&listed[1..]), vec![written[2].0.id.clone()]);
    let dropped = &written[0].1 | &written[1].1;
    assert_eq!(condemned(&phone, &key), dropped);

    // No relay answers in full: nothing is deleted.
    relay
        .unfinished_directory_reads
        .store(true, Ordering::SeqCst);
    deletes_due_now(&phone, &key);
    phone.drive_backup_pass().await;
    assert_eq!(condemned(&phone, &key), dropped);
    assert!(held(&blossom).is_superset(&dropped));
    assert!(blossom.deleters.lock().unwrap().is_empty());

    relay
        .unfinished_directory_reads
        .store(false, Ordering::SeqCst);
    due_now(&phone);
    deletes_due_now(&phone, &key);
    phone.drive_backup_pass().await;
    assert_eq!(
        held(&blossom),
        &written[2].1 | &blobs_of(&blossom, &listed[0], &key)
    );
    let account = phone
        .app
        .account_home()
        .account(&phone.state.label)
        .unwrap()
        .account_id_hex;
    let deleters = blossom.deleters.lock().unwrap().clone();
    assert_eq!(deleters, vec![account; dropped.len()]);
}

/// A listed backup whose head is longer or shorter than its locator says
/// has no index to read, so retention keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_head_that_does_not_match_its_locator_keeps_its_backup() {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let (mut phone, relay, key) = (devices.phone, devices.relay, words.public);
    phone.drive_backup_pass().await;
    age_backups(&phone, &relay, &key, 2 * DAY).await;
    due_now(&phone);
    phone.drive_backup_pass().await;
    let mut listed = pointer(&relay, &key);
    assert_eq!(listed.len(), 2);
    for entry in &mut listed {
        entry.written_at -= 2 * DAY;
    }
    listed[0].head.size -= 1;
    listed[1].head.size += 1;
    publish_pointer(&phone, &relay, &key, listed.clone()).await;
    due_now(&phone);
    phone.drive_backup_pass().await;
    assert_eq!(ids(&pointer(&relay, &key)[1..]), ids(&listed));
    assert!(condemned(&phone, &key).is_empty());
}

/// A new pointer replaces the one its pass fetched when the fetched pointer's
/// clock skew is within the allowed future skew window, and refuses excessive
/// future skew without signing or advancing the replaceable floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_pointer_postdates_the_one_it_replaces() {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let (mut phone, relay, key) = (devices.phone, devices.relay, words.public);
    phone.drive_backup_pass().await;
    let mut first = pointer(&relay, &key);
    first[0].written_at -= 2 * DAY;
    let ahead = unix_now_seconds() + 60;
    publish_pointer_at(&devices.laptop, &relay, &key, first.clone(), ahead).await;

    due_now(&phone);
    assert_eq!(phone.drive_backup_pass().await, None);
    let event = pointer_event(&relay, &key).unwrap();
    assert!(event.created_at > ahead);
    let listed = BackupPointer::open(&event.content, &key).unwrap().backups;
    assert_eq!(ids(&listed[1..]), ids(&first));

    // A pointer dated far into the future must not be propagated.
    let mut skewed = listed;
    for entry in &mut skewed {
        entry.written_at -= 2 * DAY;
    }
    let far_ahead = unix_now_seconds() + DAY;
    publish_pointer_at(&devices.laptop, &relay, &key, skewed, far_ahead).await;
    let published_before = pointers_published(&relay);
    let blobs_before = held(&blossom);
    let floor_before = devices
        .phone_app
        .account_home()
        .replaceable_record_floors("alice")
        .unwrap()
        .get(&KIND_BACKUP_POINTER)
        .copied()
        .unwrap_or(0);

    due_now(&phone);
    assert_eq!(
        phone.drive_backup_pass().await,
        Some("device_group_refused")
    );
    assert_eq!(
        pointers_published(&relay),
        published_before,
        "excessive future skew must not publish a replacement pointer"
    );
    assert_eq!(
        held(&blossom),
        blobs_before,
        "excessive future skew must not upload blobs for an unpublishable pass"
    );
    assert!(condemned(&phone, &key).is_empty());
    let floor_after = devices
        .phone_app
        .account_home()
        .replaceable_record_floors("alice")
        .unwrap()
        .get(&KIND_BACKUP_POINTER)
        .copied()
        .unwrap_or(0);
    assert_eq!(
        floor_after, floor_before,
        "excessive future skew must not poison replaceable_record_floors"
    );
}

/// A far-future cached or persisted replaceable-record floor must refuse a
/// backup pass under rotated recovery words (where discovery returns no
/// pointer) without uploading blobs, invoking the signer, publishing, or
/// advancing the floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn far_future_floor_blocks_rotated_recovery_key_without_upload_sign_or_advance() {
    use crate::backup_archive::backup_address;
    use nostr_sdk::prelude::{Event, PublicKey, UnsignedEvent};
    use transport_nostr_peeler::{
        MarmotNostrSigner, MarmotSignerError, NostrTransportEvent, SignerFuture,
    };

    #[derive(Debug)]
    struct PanicSigner;
    impl MarmotNostrSigner for PanicSigner {
        fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, MarmotSignerError>> {
            panic!("signer must not be invoked when floor exceeds future skew bound");
        }
        fn sign_event(
            &self,
            _unsigned: UnsignedEvent,
        ) -> SignerFuture<'_, Result<Event, MarmotSignerError>> {
            panic!("signer must not be invoked when floor exceeds future skew bound");
        }
        fn nip04_encrypt<'a>(
            &'a self,
            _public_key: &'a PublicKey,
            _content: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            panic!("unexpected nip04_encrypt");
        }
        fn nip04_decrypt<'a>(
            &'a self,
            _public_key: &'a PublicKey,
            _payload: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            panic!("unexpected nip04_decrypt");
        }
        fn nip44_encrypt<'a>(
            &'a self,
            _public_key: &'a PublicKey,
            _content: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            panic!("unexpected nip44_encrypt");
        }
        fn nip44_decrypt<'a>(
            &'a self,
            _public_key: &'a PublicKey,
            _payload: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            panic!("unexpected nip44_decrypt");
        }
    }

    let blossom = local_blossom();
    let (devices, _chat, old_words) = lone_writer(&blossom).await;
    let (mut phone, relay) = (devices.phone, devices.relay);
    let far_ahead = unix_now_seconds() + DAY;
    // Simulate a previously authored far-future pointer, populating both the
    // in-memory cache and persisted `replaceable_record_floors`.
    publish_pointer_at(&phone, &relay, &old_words.public, Vec::new(), far_ahead).await;

    // Rotate recovery words so relay discovery at the new address is empty.
    let rotated = confirm_words(&mut phone).await;
    assert!(pointer_event(&relay, &rotated.public).is_none());

    let published_before = pointers_published(&relay);
    let blobs_before = held(&blossom);
    let floor_before = devices
        .phone_app
        .account_home()
        .replaceable_record_floors("alice")
        .unwrap()
        .get(&KIND_BACKUP_POINTER)
        .copied()
        .unwrap_or(0);
    assert!(floor_before >= far_ahead);

    due_now(&phone);
    assert_eq!(
        phone.drive_backup_pass().await,
        Some("device_group_refused")
    );
    assert_eq!(
        held(&blossom),
        blobs_before,
        "far-future floor must block uploads before write_backup"
    );
    assert!(
        storage(&phone.app).backup_runs().unwrap().is_empty(),
        "far-future floor must not record a backup run"
    );
    assert_eq!(
        pointers_published(&relay),
        published_before,
        "far-future floor must not publish a replacement pointer"
    );
    let floor_after_pass = devices
        .phone_app
        .account_home()
        .replaceable_record_floors("alice")
        .unwrap()
        .get(&KIND_BACKUP_POINTER)
        .copied()
        .unwrap_or(0);
    assert_eq!(
        floor_after_pass, floor_before,
        "far-future floor must not advance during a refused pass"
    );

    // Also verify the atomic sign-time guard refuses without invoking the
    // signer or advancing the persisted floor.
    let summary = devices.phone_app.account_home().account("alice").unwrap();
    let now = unix_now_seconds();
    let unsigned = NostrTransportEvent::new_unsigned_at(
        summary.account_id_hex.clone(),
        KIND_BACKUP_POINTER,
        vec![vec!["d".to_owned(), backup_address(&rotated.public)]],
        "ciphertext".to_owned(),
        now,
    );
    let err = devices
        .phone_app
        .sign_replaceable_identity_event_bounded(
            "alice",
            Arc::new(PanicSigner),
            &unsigned,
            now + 5 * 60,
            |_| AppError::DeviceGroupRefused("backup_pointer_clock_skew"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            AppError::DeviceGroupRefused("backup_pointer_clock_skew")
        ),
        "expected backup_pointer_clock_skew, got {err:?}"
    );
    let floor_after_sign = devices
        .phone_app
        .account_home()
        .replaceable_record_floors("alice")
        .unwrap()
        .get(&KIND_BACKUP_POINTER)
        .copied()
        .unwrap_or(0);
    assert_eq!(
        floor_after_sign, floor_before,
        "bounded signer refusal must not advance replaceable_record_floors"
    );
}

/// An unauthenticated BackupIndex (encrypted under another recovery key or
/// tampered) is rejected by `read_index` and never condemns or triggers
/// BUD-01 DELETE signing for its listed blobs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_backup_index_never_condemns_or_deletes_blobs() {
    use crate::backup_archive::{BlobLocator, MAX_POINTER_BACKUPS};

    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let (mut phone, relay, key) = (devices.phone, devices.relay, words.public);

    let victim_bytes = b"victim blob on configured server".to_vec();
    let victim_hash = hex::encode(Sha256::digest(&victim_bytes));
    blossom
        .blobs
        .lock()
        .unwrap()
        .insert(victim_hash.clone(), victim_bytes.clone());
    let wrong_public = cgka_engine::recovery_key::derive_recovery_key_pair(
        &RustCrypto::default(),
        &[0x99; RECOVERY_ENTROPY_LEN],
    )
    .unwrap()
    .public;
    let mut unauth_index = BackupIndex::new(100, &slot_of(&phone));
    unauth_index.small_state = Some(BlobLocator {
        sha256: victim_hash.clone(),
        size: victim_bytes.len() as u64,
        server: blossom.url.clone(),
    });
    let unauth_id = [0xee; 16];
    let unauth_head = BackupHead::seal(
        unauth_id,
        &ArchiveKey::generate(),
        &wrong_public,
        &unauth_index,
    )
    .unwrap()
    .encode();
    let unauth_head_hash = hex::encode(Sha256::digest(&unauth_head));
    let unauth_head_len = unauth_head.len() as u64;
    blossom
        .blobs
        .lock()
        .unwrap()
        .insert(unauth_head_hash.clone(), unauth_head);
    let mut full_listing = Vec::new();
    for index in 1..=MAX_POINTER_BACKUPS as u8 {
        let id = [index; 16];
        let head = BackupHead::seal(
            id,
            &ArchiveKey::generate(),
            &key,
            &BackupIndex::new(1_000 + u64::from(index), &slot_of(&phone)),
        )
        .unwrap()
        .encode();
        let head_hash = hex::encode(Sha256::digest(&head));
        let head_len = head.len() as u64;
        blossom
            .blobs
            .lock()
            .unwrap()
            .insert(head_hash.clone(), head);
        full_listing.push(PointerEntry::new(
            &id,
            1_000 + u64::from(index),
            BlobLocator {
                sha256: head_hash,
                size: head_len,
                server: blossom.url.clone(),
            },
        ));
    }
    // Replace the oldest slot with the unauthenticated head so adding one new
    // backup forces it past MAX_POINTER_BACKUPS and into `dropped`.
    full_listing[0] = PointerEntry::new(
        &unauth_id,
        100,
        BlobLocator {
            sha256: unauth_head_hash,
            size: unauth_head_len,
            server: blossom.url.clone(),
        },
    );
    publish_pointer(&phone, &relay, &key, full_listing).await;

    due_now(&phone);
    phone.drive_backup_pass().await;
    assert!(
        !condemned(&phone, &key).contains(&victim_hash),
        "blobs from an unauthenticated BackupIndex must never be condemned"
    );
    deletes_due_now(&phone, &key);
    phone.drive_backup_pass().await;
    assert!(
        blossom.blobs.lock().unwrap().contains_key(&victim_hash),
        "victim blob named only in an unauthenticated BackupIndex must never be deleted"
    );
}

/// Partial relay discovery (`any_complete` only, where one relay completes empty
/// while another holding the active pointer does not complete) must fail the pass
/// without deleting live blobs, condemning blobs, or publishing a truncated pointer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_relay_discovery_never_condemns_deletes_or_truncates_pointer() {
    let blossom = local_blossom();
    let (mut devices, _chat, words) = lone_writer(&blossom).await;
    devices.phone.drive_backup_pass().await;
    let first = pointer(&devices.relay, &words.public).remove(0);
    let live_blobs = held(&blossom);
    // Condemn one of the live backup's blobs as if an older pass queued it:
    // on an authoritative pointer listing `first`, it would be spared, whereas
    // an empty partial view would have deleted it!
    let live_blob_hash = first.head.sha256.clone();
    let live_backup_id: [u8; 16] = hex::decode(&first.id).unwrap().try_into().unwrap();
    storage(&devices.phone_app)
        .condemn_backup_blobs(
            &words.public,
            &live_backup_id,
            &[(live_blob_hash.clone(), blossom.url.clone())],
            1,
            0,
        )
        .unwrap();
    // Age the live pointer so a pass would also try to write and publish a new
    // pointer if it accepted the empty partial view.
    age_backups(&devices.phone, &devices.relay, &words.public, 2 * DAY).await;

    let account = devices.phone_app.account_home().account("alice").unwrap();
    let directory = devices.phone_app.directory();
    let mut entry = directory
        .directory_entry_for_account_id(&account.account_id_hex)
        .unwrap()
        .unwrap_or_else(|| directory.empty_directory_record_for_test(&account.account_id_hex));
    entry.relay_lists.nip65.created_at = unix_now_seconds();
    entry.relay_lists.nip65.relays = vec![
        "wss://completed-empty.example".into(),
        "wss://unfinished-pointer.example".into(),
    ];
    entry.relay_lists.refresh();
    directory.save_directory_entry_for_test(&entry).unwrap();

    devices.phone.app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        None,
        devices.relay.clone(),
        Arc::new(restore::PartialPointerView {
            relay: devices.relay.clone(),
            visible: false,
            any_completed: true,
        }),
        false,
    );

    let published_before = pointers_published(&devices.relay);
    due_now(&devices.phone);
    deletes_due_now(&devices.phone, &words.public);
    assert_eq!(
        devices.phone.drive_backup_pass().await,
        Some("device_group_refused"),
        "partial discovery (any_complete without complete) must refuse the pass"
    );
    assert!(
        blossom.deleters.lock().unwrap().is_empty(),
        "partial discovery must never sign BUD-01 DELETE for live blobs"
    );
    assert_eq!(
        held(&blossom),
        live_blobs,
        "partial discovery must not delete live blobs or upload a truncated backup"
    );
    assert_eq!(
        pointers_published(&devices.relay),
        published_before,
        "partial discovery must not publish a truncated pointer"
    );
}

/// When backup discovery fails while a condemned blob is due, both pass
/// admission and worker wake scheduling must honor the failed pass's retry
/// backoff instead of looping immediately, while normal succeeded schedules
/// keep waking for due deletes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_backup_discovery_honors_retry_backoff_with_due_condemned_blobs() {
    use crate::BackgroundBackupOutcome::{FinishedAttempt, NotStarted};
    use std::sync::atomic::AtomicUsize;

    struct CountingPartialView {
        inner: restore::PartialPointerView,
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl transport_nostr::DirectoryRelayFetcher for CountingPartialView {
        async fn fetch_directory_events(
            &self,
            request: transport_nostr::DirectoryFetchRequest,
        ) -> Result<Vec<transport_nostr::DirectoryRelayEventRecord>, String> {
            self.inner.fetch_directory_events(request).await
        }

        async fn fetch_directory_events_with_completion(
            &self,
            request: transport_nostr::DirectoryFetchRequest,
        ) -> Result<transport_nostr::DirectoryFetchOutcome, String> {
            if request
                .queries
                .iter()
                .any(|query| query.kind == KIND_BACKUP_POINTER)
            {
                self.fetches.fetch_add(1, Ordering::SeqCst);
            }
            self.inner
                .fetch_directory_events_with_completion(request)
                .await
        }
    }

    let blossom = local_blossom();
    let (mut devices, _chat, words) = lone_writer(&blossom).await;
    devices.phone.drive_backup_pass().await;
    let first = pointer(&devices.relay, &words.public).remove(0);
    let live_backup_id: [u8; 16] = hex::decode(&first.id).unwrap().try_into().unwrap();
    storage(&devices.phone_app)
        .condemn_backup_blobs(
            &words.public,
            &live_backup_id,
            &[(first.head.sha256.clone(), blossom.url.clone())],
            1,
            0,
        )
        .unwrap();

    // First verify normal succeeded schedule (failed_passes == 0) keeps due-delete
    // wakeups and admission working while next_pass_at is far in the future.
    storage(&devices.phone_app)
        .schedule_backup_pass(BackupSchedule {
            next_pass_at: unix_now_seconds() + DAY,
            failed_passes: 0,
        })
        .unwrap();
    assert_eq!(
        devices.phone.history_dispatch_next_at(),
        Some(0),
        "normal succeeded schedule must still wake immediately for due deletes"
    );
    assert!(
        devices.phone.prepare_backup_pass().unwrap().is_some(),
        "normal succeeded schedule must still admit due-delete passes"
    );

    let account = devices.phone_app.account_home().account("alice").unwrap();
    let directory = devices.phone_app.directory();
    let mut entry = directory
        .directory_entry_for_account_id(&account.account_id_hex)
        .unwrap()
        .unwrap_or_else(|| directory.empty_directory_record_for_test(&account.account_id_hex));
    entry.relay_lists.nip65.created_at = unix_now_seconds();
    entry.relay_lists.nip65.relays = vec![
        "wss://completed-empty.example".into(),
        "wss://unfinished-pointer.example".into(),
    ];
    entry.relay_lists.refresh();
    directory.save_directory_entry_for_test(&entry).unwrap();

    let fetches = Arc::new(AtomicUsize::new(0));
    let failing_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        None,
        devices.relay.clone(),
        Arc::new(CountingPartialView {
            inner: restore::PartialPointerView {
                relay: devices.relay.clone(),
                visible: false,
                any_completed: true,
            },
            fetches: fetches.clone(),
        }),
        false,
    );
    devices.phone.app.relay_plane = failing_plane.clone();
    devices.phone_app.relay_plane = failing_plane;

    // Direct client check: after a failed discovery pass, the due condemned row
    // must not bypass retry backoff in prepare_backup_pass or history_dispatch_next_at.
    due_now(&devices.phone);
    deletes_due_now(&devices.phone, &words.public);
    assert_eq!(
        devices.phone.drive_backup_pass().await,
        Some("device_group_refused")
    );
    let schedule = storage(&devices.phone_app).backup_schedule().unwrap();
    assert_eq!(schedule.failed_passes, 1);
    assert!(schedule.next_pass_at > unix_now_seconds());
    assert!(
        devices.phone.prepare_backup_pass().unwrap().is_none(),
        "failed discovery backoff must block immediate re-admission despite due deletes"
    );
    assert_eq!(
        devices.phone.history_dispatch_next_at(),
        Some(schedule.next_pass_at),
        "worker wake calculation must honor failed pass backoff despite due deletes"
    );

    // Runtime worker check: completion of the failed discovery pass must NOT
    // immediately launch a second pass in a tight loop.
    let phone_app = devices.phone_app.clone();
    drop(devices.phone);
    fetches.store(0, Ordering::SeqCst);
    storage(&phone_app)
        .schedule_backup_pass(BackupSchedule::default())
        .unwrap();
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    runtime
        .set_runtime_backup_background_conditions(true, true)
        .unwrap();
    runtime.reconcile_accounts().await.unwrap();
    assert_eq!(
        runtime.run_due_backup_pass("alice").await.unwrap(),
        FinishedAttempt
    );
    // Barrier commands give the worker loop a chance to re-dispatch if buggy.
    runtime.backup_settings("alice").await.unwrap();
    runtime.run_due_maintenance("alice").await.unwrap();
    assert_eq!(
        runtime.run_due_backup_pass("alice").await.unwrap(),
        NotStarted,
        "worker must honor backoff instead of re-admitting a failed discovery pass"
    );
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "failed discovery with due condemned blobs must not repeat relay reads on completion"
    );
    assert_eq!(
        storage(&phone_app).backup_schedule().unwrap().failed_passes,
        1
    );
    runtime.shutdown().await;
}

/// A healthy configured discovery fallback relay written with an uppercase
/// hostname or explicit default port must match the canonical endpoint reported
/// by transport completion so backup passes still run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_pass_accepts_completed_noncanonical_fallback_relay_url() {
    let blossom = local_blossom();
    let (mut devices, _chat, words) = lone_writer(&blossom).await;
    // Clear cached NIP-65 relays so backup_pointer_endpoints falls back to the
    // configured directory_relay_urls containing an uppercase host and explicit
    // default port.
    let account = devices.phone_app.account_home().account("alice").unwrap();
    let directory = devices.phone_app.directory();
    let mut entry = directory
        .directory_entry_for_account_id(&account.account_id_hex)
        .unwrap()
        .unwrap_or_else(|| directory.empty_directory_record_for_test(&account.account_id_hex));
    entry.relay_lists.nip65.relays.clear();
    entry.relay_lists.refresh();
    directory.save_directory_entry_for_test(&entry).unwrap();

    devices.phone.app.config.directory_relay_urls =
        vec!["wss://BACKUP-FALLBACK.EXAMPLE:443".into()];
    assert_eq!(
        devices.phone.app.directory().directory_source_relays(&[]),
        vec![TransportEndpoint(
            "wss://BACKUP-FALLBACK.EXAMPLE:443".into()
        )]
    );

    assert_eq!(
        devices.phone.drive_backup_pass().await,
        None,
        "completed canonical fallback relay must be recognized as complete"
    );
    assert_eq!(pointer(&devices.relay, &words.public).len(), 1);
}

/// Under a key nothing can be sealed to, the writer uploads nothing and
/// lists nothing, and tries again a day later, not at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_that_seals_nothing_gets_no_backup() {
    let blossom = local_blossom();
    let (devices, _chat, _words) = lone_writer(&blossom).await;
    let mut phone = devices.phone;
    storage(&devices.phone_app)
        .keep_recovery_key(&[0x04; 33])
        .unwrap();
    due_now(&phone);
    let before = unix_now_seconds();
    phone.drive_backup_pass().await;
    let after = unix_now_seconds();
    assert!(held(&blossom).is_empty());
    assert_eq!(pointers_published(&devices.relay), 0);
    let schedule = storage(&phone.app).backup_schedule().unwrap();
    assert!((before + DAY..=after + DAY).contains(&schedule.next_pass_at));
    assert_eq!(schedule.failed_passes, 0);
}

/// A device with no device group writes under the key it keeps. New words
/// while a pass runs abandon its run before the pointer: none goes out,
/// and the run's blobs, under the old words, are never deleted. The next
/// pass writes under the new words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_words_mid_pass_abandon_the_run_before_its_pointer() {
    let blossom = local_blossom();
    let (devices, _chat, old) = lone_writer(&blossom).await;
    let (mut phone, relay) = (devices.phone, devices.relay);
    phone.drive_backup_pass().await;
    assert_eq!(pointer(&relay, &old.public).len(), 1);

    age_backups(&phone, &relay, &old.public, 2 * DAY).await;
    let (published, before) = (pointers_published(&relay), held(&blossom));
    due_now(&phone);
    let pass = phone.prepare_backup_pass().unwrap().expect("a pass is due");
    let outcome = pass.run().await;
    let uploaded = held(&blossom);
    assert!(uploaded.is_superset(&before) && uploaded != before);
    let new = confirm_words(&mut phone).await;
    phone.finish_backup_pass(outcome).await;
    assert_eq!(pointers_published(&relay), published);
    assert!(storage(&phone.app).backup_runs().unwrap().is_empty());

    deletes_due_now(&phone, &old.public);
    due_now(&phone);
    phone.drive_backup_pass().await;
    assert_eq!(pointer(&relay, &new.public).len(), 1);
    assert!(held(&blossom).is_superset(&uploaded));
    assert!(condemned(&phone, &old.public).is_empty());
}

/// A sibling takes over writing from a writer that listed nothing for a
/// week since the sibling first saw it named, and at once from a writer
/// that is leaving. A writer just named is not taken over.
/// Quiet, leaving and moved writers release the role to a staying sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_takes_over_a_quiet_or_leaving_writer() {
    for status in [DeviceStatusV1::Leaving, DeviceStatusV1::Moved] {
        let blossom = local_blossom();
        let (mut devices, group, _chat, words) = linked_writer(&blossom).await;
        let (phone_slot, laptop_slot) = (slot_of(&devices.phone), slot_of(&devices.laptop));
        let writer = |device: &AppClient| roster(device, &group).account.backup_writer;
        let start = devices.relay.published_events.lock().unwrap().len();
        let mut cursors = (start, start);

        devices.laptop.drive_backup_pass().await;
        assert_eq!(writer(&devices.laptop), Some(phone_slot));

        let ledger = storage(&devices.laptop_app);
        ledger
            .note_backup_writer(&words.public, &laptop_slot, 0)
            .unwrap();
        ledger
            .note_backup_writer(&words.public, &phone_slot, unix_now_seconds() - 8 * DAY)
            .unwrap();
        due_now(&devices.laptop);
        devices.laptop.drive_backup_pass().await;
        assert_eq!(writer(&devices.laptop), Some(laptop_slot));
        exchange(
            &mut devices.phone,
            &mut devices.laptop,
            &devices.relay,
            &group,
            &mut cursors,
        )
        .await;
        assert_eq!(writer(&devices.phone), Some(laptop_slot));

        let edit = devices
            .laptop
            .runtime
            .edit_device_roster_entry(&group, &laptop_slot, &[], |entry| {
                entry.status = status;
            })
            .await
            .unwrap();
        assert!(matches!(edit, DeviceRosterEdit::Committed(_)));
        exchange(
            &mut devices.phone,
            &mut devices.laptop,
            &devices.relay,
            &group,
            &mut cursors,
        )
        .await;
        devices.phone.drive_backup_takeover().await;
        assert_eq!(writer(&devices.phone), Some(phone_slot));
    }
}

/// A writer named again after this device wrote gets a fresh week: the
/// time this device first saw it named starts again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_named_again_gets_a_fresh_week() {
    let blossom = local_blossom();
    let (mut devices, group, _chat, words) = linked_writer(&blossom).await;
    let (phone_slot, laptop_slot) = (slot_of(&devices.phone), slot_of(&devices.laptop));
    let writer = |device: &AppClient| roster(device, &group).account.backup_writer;
    let start = devices.relay.published_events.lock().unwrap().len();
    let mut cursors = (start, start);

    let ledger = storage(&devices.laptop_app);
    ledger
        .note_backup_writer(&words.public, &laptop_slot, 0)
        .unwrap();
    ledger
        .note_backup_writer(&words.public, &phone_slot, unix_now_seconds() - 8 * DAY)
        .unwrap();
    due_now(&devices.laptop);
    devices.laptop.drive_backup_pass().await;
    assert_eq!(writer(&devices.laptop), Some(laptop_slot));
    devices.laptop.drive_backup_takeover().await;
    exchange(
        &mut devices.phone,
        &mut devices.laptop,
        &devices.relay,
        &group,
        &mut cursors,
    )
    .await;

    let edit = devices
        .phone
        .runtime
        .edit_roster_account_entry(&group, &[], |entry| {
            entry.backup_writer = Some(phone_slot);
        })
        .await
        .unwrap();
    assert!(matches!(edit, DeviceRosterEdit::Committed(_)));
    exchange(
        &mut devices.phone,
        &mut devices.laptop,
        &devices.relay,
        &group,
        &mut cursors,
    )
    .await;
    assert_eq!(writer(&devices.laptop), Some(phone_slot));
    devices.laptop.drive_backup_takeover().await;
    due_now(&devices.laptop);
    devices.laptop.drive_backup_pass().await;
    assert_eq!(writer(&devices.laptop), Some(phone_slot));
}

/// A device that stops writing abandons the run whose pointer no relay
/// accepted, so a later pass deletes its blobs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_former_writer_abandons_its_unlisted_run() {
    let blossom = local_blossom();
    let (mut devices, group, _chat, words) = linked_writer(&blossom).await;
    let (phone_slot, laptop_slot) = (slot_of(&devices.phone), slot_of(&devices.laptop));
    let start = devices.relay.published_events.lock().unwrap().len();
    let mut cursors = (start, start);
    devices.relay.fail_publishes_of_kind(KIND_BACKUP_POINTER);
    devices.phone.drive_backup_pass().await;
    let uploaded = held(&blossom);
    assert!(!uploaded.is_empty());

    let ledger = storage(&devices.laptop_app);
    ledger
        .note_backup_writer(&words.public, &laptop_slot, 0)
        .unwrap();
    ledger
        .note_backup_writer(&words.public, &phone_slot, unix_now_seconds() - 8 * DAY)
        .unwrap();
    due_now(&devices.laptop);
    devices.laptop.drive_backup_pass().await;
    exchange(
        &mut devices.phone,
        &mut devices.laptop,
        &devices.relay,
        &group,
        &mut cursors,
    )
    .await;
    assert_eq!(
        roster(&devices.phone, &group).account.backup_writer,
        Some(laptop_slot)
    );

    due_now(&devices.phone);
    devices.phone.drive_backup_pass().await;
    assert!(
        storage(&devices.phone_app)
            .backup_runs()
            .unwrap()
            .is_empty()
    );
    assert_eq!(condemned(&devices.phone, &words.public), uploaded);
}

static STATEMENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_statement(event: rusqlite::trace::TraceEvent<'_>) {
    if let rusqlite::trace::TraceEvent::Stmt(statement, _) = event {
        STATEMENTS
            .lock()
            .unwrap()
            .push(statement.expanded_sql().unwrap_or_default());
    }
}

/// The archive key lives only in the pass: neither it, the words nor the
/// private half reaches the account database while a backup is written
/// and listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_archive_key_never_reaches_storage() {
    let blossom = local_blossom();
    let (mut devices, _chat, words) = lone_writer(&blossom).await;
    devices
        .phone_app
        .account_storage("alice")
        .unwrap()
        .trace_queries_for_test(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(record_statement),
        )
        .unwrap();
    devices.phone.drive_backup_pass().await;

    let statements = std::mem::take(&mut *STATEMENTS.lock().unwrap());
    let entry = pointer(&devices.relay, &words.public).remove(0);
    assert!(
        statements
            .iter()
            .any(|sql| sql.to_lowercase().contains(&entry.head.sha256)),
        "the trace sees the head recorded"
    );
    let (head, _) = read_backup(&blossom, &entry, &words.public);
    let secrets = [
        hex::encode(opened_archive_key(&head, &words)),
        hex::encode(words.entropy),
        hex::encode(&words.private),
        words.phrase.clone(),
    ];
    for sql in &statements {
        let sql = sql.to_lowercase();
        for secret in &secrets {
            assert!(!sql.contains(secret.as_str()), "a secret reached storage");
        }
    }
}

// One thread permits clock control only while the real startup future is held.
#[tokio::test(flavor = "current_thread")]
async fn a_due_backup_request_waits_through_startup() {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let Devices {
        _dirs,
        phone_app,
        phone,
        relay,
        ..
    } = devices;
    drop(phone);
    let runtime = MarmotAppRuntime::new(phone_app);
    runtime
        .set_runtime_backup_background_conditions(true, true)
        .unwrap();
    let startup = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_startup_sync_barrier(startup.clone());
    let mut upload = blossom.hold_upload();
    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), startup.wait())
        .await
        .expect("the real worker reaches initial sync");
    let mut completion = Box::pin(runtime.run_due_backup_pass("alice"));
    assert!(futures::poll!(&mut completion).is_pending());
    // The backup command is deferred while the startup rendezvous stays held.
    crate::worker_fences::startup_sync_took_queued_commands(&runtime, "alice")
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(crate::APP_RUNTIME_LOCAL_WORKER_RESPONSE_WAIT + Duration::from_millis(1))
        .await;
    let after_admission_bound = futures::poll!(&mut completion);
    tokio::time::resume();
    startup.wait().await;
    if after_admission_bound.is_ready() {
        upload.release();
        runtime.shutdown().await;
        panic!("backup request must keep waiting through held startup: {after_admission_bound:?}");
    }
    tokio::time::timeout(Duration::from_secs(10), upload.entered())
        .await
        .expect("startup release admits a real backup upload");
    assert!(futures::poll!(&mut completion).is_pending());
    upload.release();
    let finished = tokio::time::timeout(Duration::from_secs(10), completion)
        .await
        .expect("the waiting host observes serialized backup settlement");
    runtime.shutdown().await;
    assert_eq!(
        finished.unwrap(),
        crate::BackgroundBackupOutcome::FinishedAttempt
    );
    assert_eq!(pointer(&relay, &words.public).len(), 1);
}

/// Through the runtime, the account worker's maintenance pass runs a due
/// backup pass off the worker and publishes its pointer as it completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_writes_a_due_backup() {
    use crate::BackgroundBackupOutcome::{FinishedAttempt, NotStarted};

    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let Devices {
        _dirs,
        relay,
        phone_app,
        phone,
        ..
    } = devices;
    drop(phone);
    let account_id = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let deployment = MarmotDeployment {
        new_group_media_endpoints: vec![blossom.url.clone()],
        ..MarmotDeployment::white_noise()
    };
    // Each runtime shutdown terminates its `MarmotApp`'s relay plane, so each
    // subsequent runtime reopens a fresh `MarmotApp` on the same directory.
    let reopen_phone_app = || {
        let app = device_group_app_on(&_dirs[0], relay.clone(), deployment.clone());
        remember_test_member_inbox(&app, &account_id, "wss://relay.example");
        app
    };
    let ledger = storage(&phone_app);
    let old_run = [0xe1; 16];
    ledger.begin_backup_run(&old_run, &[0xf2; 32], 1).unwrap();
    let before = ledger.backup_runs().unwrap();
    let closed = MarmotAppRuntime::new(phone_app);
    closed.reconcile_accounts().await.unwrap();
    // Durable cleanup happens synchronously during preparation, so this
    // proves closed admission even before any HTTP future could be polled.
    closed.run_due_maintenance("alice").await.unwrap();
    assert_eq!(ledger.backup_runs().unwrap(), before);
    for (wifi, charging) in [(true, false), (false, true)] {
        closed
            .set_backup_background_conditions("alice", wifi, charging)
            .await
            .unwrap();
        assert_eq!(
            closed.run_due_backup_pass("alice").await.unwrap(),
            NotStarted
        );
        assert_eq!(
            ledger.backup_runs().unwrap(),
            before,
            "both platform facts are required"
        );
    }
    assert_eq!(pointers_published(&relay), 0);
    closed.shutdown().await;

    let runtime = MarmotAppRuntime::new(reopen_phone_app());
    // With no workers or watch receivers, the report must still be retained.
    runtime
        .set_runtime_backup_background_conditions(true, true)
        .unwrap();
    let invalid = runtime
        .set_backup_background_conditions("missing-account", false, false)
        .await
        .unwrap_err();
    assert!(matches!(
        invalid,
        AppError::AccountHome(AccountHomeError::UnknownAccount(_))
    ));
    let mut upload = blossom.hold_upload();
    runtime.reconcile_accounts().await.unwrap();
    runtime.run_due_maintenance("alice").await.unwrap();
    assert!(
        !ledger
            .backup_runs()
            .unwrap()
            .iter()
            .any(|run| run.backup_id == old_run),
        "eligible facts reported before workers must reach preparation"
    );
    tokio::time::timeout(Duration::from_secs(10), upload.entered())
        .await
        .unwrap();
    // The pass is already admitted and held at real I/O. Both callers join
    // it; the following command is a FIFO barrier proving their admission.
    let mut completion = Box::pin(runtime.run_due_backup_pass("alice"));
    assert!(futures::poll!(&mut completion).is_pending());
    let mut cancelled_waiter = Box::pin(runtime.run_due_backup_pass("alice"));
    assert!(futures::poll!(&mut cancelled_waiter).is_pending());
    runtime.backup_settings("alice").await.unwrap();
    let pending = futures::poll!(&mut completion);
    assert!(
        pending.is_pending(),
        "held pass completed before serialized settlement: {pending:?}"
    );
    drop(cancelled_waiter);
    runtime
        .set_runtime_backup_background_conditions(false, false)
        .unwrap();
    // A caller arriving after admission closes still joins this held pass.
    let mut after_false = Box::pin(runtime.run_due_backup_pass("alice"));
    assert!(futures::poll!(&mut after_false).is_pending());
    runtime.backup_settings("alice").await.unwrap();
    assert!(futures::poll!(&mut after_false).is_pending());
    relay.fail_publishes_of_kind(KIND_BACKUP_POINTER);
    upload.release();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), completion)
            .await
            .expect("the admitted pass settles after conditions close")
            .unwrap(),
        FinishedAttempt
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), after_false)
            .await
            .expect("the later caller joins the failed attempt")
            .unwrap(),
        FinishedAttempt
    );
    assert_eq!(ledger.backup_schedule().unwrap().failed_passes, 1);
    assert!(pointer_event(&relay, &words.public).is_none());
    // Retry the retained backup through ordinary due admission. Consume the
    // eligible report while not due, so the explicit call owns admission.
    relay.allow_all_publish_kinds();
    ledger
        .schedule_backup_pass(BackupSchedule {
            next_pass_at: ANY_TIME,
            failed_passes: 0,
        })
        .unwrap();
    runtime
        .set_runtime_backup_background_conditions(true, true)
        .unwrap();
    assert_eq!(
        runtime.run_due_backup_pass("alice").await.unwrap(),
        NotStarted
    );
    ledger
        .schedule_backup_pass(BackupSchedule::default())
        .unwrap();
    assert_eq!(
        runtime.run_due_backup_pass("alice").await.unwrap(),
        FinishedAttempt
    );
    runtime
        .set_runtime_backup_background_conditions(false, false)
        .unwrap();
    let listed = pointer(&relay, &words.public);
    assert_eq!(listed.len(), 1);
    assert_eq!(
        ledger.backup_schedule().unwrap().next_pass_at,
        listed[0].written_at + DAY
    );
    let next_run = [0xe3; 16];
    ledger.begin_backup_run(&next_run, &[0xf4; 32], 2).unwrap();
    ledger
        .schedule_backup_pass(BackupSchedule::default())
        .unwrap();
    assert_eq!(
        runtime.run_due_backup_pass("alice").await.unwrap(),
        NotStarted
    );
    assert_eq!(
        ledger.backup_runs().unwrap()[0].backup_id,
        next_run,
        "false blocks later passes, including cleanup"
    );
    // Eligible facts survive an actual account-worker replacement in THIS
    // runtime. A recent pointer needs no upload, but its real cleanup pass
    // must retire the foreign-key run before reporting completion.
    ledger
        .schedule_backup_pass(BackupSchedule {
            next_pass_at: ANY_TIME,
            failed_passes: 0,
        })
        .unwrap();
    runtime
        .set_runtime_backup_background_conditions(true, true)
        .unwrap();
    assert_eq!(
        runtime.run_due_backup_pass("alice").await.unwrap(),
        NotStarted
    );
    runtime.restart_account(&account_id).await.unwrap();
    ledger
        .schedule_backup_pass(BackupSchedule::default())
        .unwrap();
    assert_eq!(
        runtime.run_due_backup_pass("alice").await.unwrap(),
        FinishedAttempt
    );
    assert!(
        !ledger
            .backup_runs()
            .unwrap()
            .iter()
            .any(|run| run.backup_id == next_run),
        "replacement workers inherit the runtime's eligible facts"
    );
    assert_eq!(pointers_published(&relay), 1);

    // A new confirmed recovery key has no pointer yet, so it gives another
    // genuine due upload without faking clocks, receipts or pass outcomes.
    runtime
        .set_runtime_backup_background_conditions(false, false)
        .unwrap();
    let shown = runtime.begin_recovery_words("alice").await.unwrap();
    let answers = shown
        .confirm_positions
        .iter()
        .map(|position| shown.words[*position as usize - 1].clone())
        .collect();
    runtime
        .confirm_recovery_words("alice", answers)
        .await
        .unwrap();
    ledger
        .schedule_backup_pass(BackupSchedule::default())
        .unwrap();
    let mut stopped_upload = blossom.hold_upload();
    runtime
        .set_backup_background_conditions("alice", true, true)
        .await
        .unwrap();
    // Only the platform report precedes this real upload: the due-pass call
    // below must join, rather than supplying an alternate admission path.
    tokio::time::timeout(Duration::from_secs(10), stopped_upload.entered())
        .await
        .expect("eligible compatibility reports wake the existing worker");
    let mut stopped_waiter = Box::pin(runtime.run_due_backup_pass("alice"));
    assert!(futures::poll!(&mut stopped_waiter).is_pending());
    runtime.backup_settings("alice").await.unwrap();
    assert!(futures::poll!(&mut stopped_waiter).is_pending());
    runtime.shutdown().await;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), stopped_waiter)
            .await
            .expect("worker stop must close its completion sender"),
        Err(AppError::TransportClosed)
    ));
    stopped_upload.release();

    // A NEW runtime starts closed even though the previous one reported true.
    let replacement = MarmotAppRuntime::new(reopen_phone_app());
    let new_run = [0xe5; 16];
    ledger.begin_backup_run(&new_run, &[0xf6; 32], 3).unwrap();
    let after_stop = ledger.backup_runs().unwrap();
    ledger
        .schedule_backup_pass(BackupSchedule::default())
        .unwrap();
    replacement.reconcile_accounts().await.unwrap();
    assert_eq!(
        replacement.run_due_backup_pass("alice").await.unwrap(),
        NotStarted
    );
    replacement.run_due_maintenance("alice").await.unwrap();
    assert_eq!(ledger.backup_runs().unwrap(), after_stop);
    assert_eq!(pointers_published(&relay), 1);
    replacement.shutdown().await;
}

#[path = "backup_restore.rs"]
mod restore;
