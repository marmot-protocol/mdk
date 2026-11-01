//! Writing backups (mdk#2628 item 4.4b, D71, D79). The writer's pass
//! uploads the account's backup to the deployment's Blossom server and
//! lists it in the backup pointer; the backup counts only once a relay
//! accepts that pointer. Retention drops older backups, and a later pass
//! deletes the blobs of a backup or run that never counted or no longer
//! does, unless the pointer it fetched lists that backup. Only the writer
//! writes, at most daily, and new words mid-pass abandon the run. A sibling
//! takes over a writer that is leaving or quiet for a week. The tests move
//! time by dating the pointer and the ledger earlier, never the clock.

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
    let chat = devices.phone.create_group("team", &[]).await.unwrap();
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
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_whose_pointer_no_relay_accepts_goes_out_again() {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let mut phone = devices.phone;
    devices.relay.fail_publishes_of_kind(KIND_BACKUP_POINTER);
    phone.drive_backup_pass().await;
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
    phone.drive_backup_pass().await;
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

/// A new pointer replaces the one its pass fetched, though another device
/// whose clock runs a day ahead made that one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_pointer_postdates_the_one_it_replaces() {
    let blossom = local_blossom();
    let (devices, _chat, words) = lone_writer(&blossom).await;
    let (mut phone, relay, key) = (devices.phone, devices.relay, words.public);
    phone.drive_backup_pass().await;
    let mut first = pointer(&relay, &key);
    first[0].written_at -= 2 * DAY;
    let ahead = unix_now_seconds() + DAY;
    publish_pointer_at(&devices.laptop, &relay, &key, first.clone(), ahead).await;

    due_now(&phone);
    phone.drive_backup_pass().await;
    let event = pointer_event(&relay, &key).unwrap();
    assert!(event.created_at > ahead);
    let listed = BackupPointer::open(&event.content, &key).unwrap().backups;
    assert_eq!(ids(&listed[1..]), ids(&first));
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_takes_over_a_quiet_or_leaving_writer() {
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
            entry.status = DeviceStatusV1::Leaving;
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

/// Through the runtime, the account worker's maintenance pass runs a due
/// backup pass off the worker and publishes its pointer as it completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_writes_a_due_backup() {
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
    let _eose = scripted_eose_pump(
        phone_app.relay_plane.clone(),
        relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let ledger = storage(&phone_app);
    tokio::time::timeout(Duration::from_secs(30), async {
        while ledger.backup_schedule().unwrap().next_pass_at == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the worker settles a backup pass");
    let listed = pointer(&relay, &words.public);
    assert_eq!(listed.len(), 1);
    assert_eq!(
        ledger.backup_schedule().unwrap().next_pass_at,
        listed[0].written_at + DAY
    );
    runtime.shutdown().await;
}
