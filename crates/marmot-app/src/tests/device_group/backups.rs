//! Backups' recovery words (mdk#2628 item 4.4a, D71). Confirming 12 words
//! makes their key the account's recovery key: kept by a device with no
//! device group, carried into the roster it founds, and otherwise committed
//! to the roster's account entry as a compare-and-set. Turning backups off
//! clears the entry the same way. Maintenance carries a change the roster
//! lost again while it still holds the key the change replaced and the
//! engine keeps one of this device's account-entry commits, never words that
//! turned backups on. Words the roster does not hold read as pending until
//! nothing could make them its key, past the rewind horizon, and only then
//! as not in use. The words and the private half never reach storage.

use super::devices::{edit_own_entry, exchange, published_count, refusal};
use super::*;
use crate::{BackupSettings, RecoveryWords};
use bip39::{Language, Mnemonic};
use cgka_engine::convergence::V1_MAX_REWIND_COMMITS;
use cgka_engine::recovery_key::derive_recovery_key_pair;
use cgka_traits::app_components::AccountEntryV1;
use openmls_rust_crypto::RustCrypto;
use std::sync::Mutex;
use storage_sqlite::BackupRecoveryKeyRecord;

/// The words at `shown`'s confirm positions, in order.
fn answers(shown: &RecoveryWords) -> Vec<String> {
    shown
        .confirm_positions
        .iter()
        .map(|&at| shown.words[at as usize - 1].clone())
        .collect()
}

/// The entropy `shown`'s words carry, read back through their checksum.
fn entropy_of(shown: &RecoveryWords) -> [u8; 16] {
    Mnemonic::parse_in(Language::English, shown.words.join(" "))
        .unwrap()
        .to_entropy()
        .try_into()
        .unwrap()
}

/// The recovery key pair `shown`'s words derive: (public, private).
fn key_pair_of(shown: &RecoveryWords) -> (Vec<u8>, Vec<u8>) {
    let pair = derive_recovery_key_pair(&RustCrypto::default(), &entropy_of(shown)).unwrap();
    (pair.public, pair.private.as_ref().to_vec())
}

/// Make and confirm new words on `device`; the public key they derive.
async fn confirm_new_words(device: &mut AppClient) -> Vec<u8> {
    let shown = device.begin_recovery_words().unwrap();
    device
        .confirm_recovery_words(&answers(&shown))
        .await
        .unwrap();
    key_pair_of(&shown).0
}

fn kept(device: &AppClient) -> BackupRecoveryKeyRecord {
    device
        .app
        .account_storage(&device.state.label)
        .unwrap()
        .app_storage()
        .backup_recovery_key()
        .unwrap()
}

fn lone(public_key: &[u8]) -> BackupRecoveryKeyRecord {
    BackupRecoveryKeyRecord::Kept {
        public_key: public_key.to_vec(),
    }
}

fn confirmed(public_key: &[u8], replaces: Option<&[u8]>) -> BackupRecoveryKeyRecord {
    BackupRecoveryKeyRecord::Confirmed {
        public_key: public_key.to_vec(),
        replaces: replaces.map(<[u8]>::to_vec),
    }
}

fn keep(device: &AppClient, record: &BackupRecoveryKeyRecord) {
    device
        .app
        .account_storage(&device.state.label)
        .unwrap()
        .app_storage()
        .put_backup_recovery_key(record)
        .unwrap();
}

fn account_entry(device: &AppClient, group: &GroupId) -> AccountEntryV1 {
    roster(device, group).account
}

/// Backups on, written here, words pending, off pending, words unused.
type Settings = (bool, bool, bool, bool, bool);

fn settings(expected: Settings, device: &mut AppClient) {
    let read = device.backup_settings().unwrap();
    assert_eq!(
        (
            read.enabled,
            read.this_device_writes,
            read.words_pending,
            read.off_pending,
            read.words_unused,
        ),
        expected,
        "{read:?}"
    );
}

const OFF: Settings = (false, false, false, false, false);
const ON_WRITING: Settings = (true, true, false, false, false);
const ON: Settings = (true, false, false, false, false);

/// Take the device group past the rewind horizon: one more commit of the
/// laptop's than the horizon spans, which both devices apply, then each
/// device's maintenance re-derivation, which collects the own-commit records
/// the horizon left behind.
async fn pass_the_rewind_horizon(
    phone: &mut AppClient,
    laptop: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
    cursors: &mut (usize, usize),
) {
    let platforms: Vec<String> = (0..=V1_MAX_REWIND_COMMITS)
        .map(|commit| format!("past the horizon {commit}"))
        .collect();
    let platforms: Vec<&str> = platforms.iter().map(String::as_str).collect();
    edit_own_entry(laptop, group, &platforms).await;
    exchange(phone, laptop, relay, group, cursors).await;
    for device in [phone, laptop] {
        device
            .runtime
            .session_mut()
            .reissue_superseded_own_commits_from_state()
            .unwrap();
    }
}

/// A device with no device group keeps the key its confirmed words derive,
/// writes the backups, and founds its device group with that key and
/// itself as writer. A sibling that joins reads backups as on and written
/// by the founder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lone_device_keeps_its_key_and_founds_its_device_group_with_it() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    assert_eq!(phone.backup_settings().unwrap(), BackupSettings::default());

    let shown = phone.begin_recovery_words().unwrap();
    assert_eq!(shown.words.len(), 12);
    assert_eq!(shown.confirm_positions.len(), 2);
    let public_key = key_pair_of(&shown).0;
    phone
        .confirm_recovery_words(&answers(&shown))
        .await
        .unwrap();
    assert_eq!(kept(&phone), lone(&public_key));
    settings(ON_WRITING, &mut phone);

    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let founded = AccountEntryV1 {
        backup_writer: Some(slot_of(&phone)),
        recovery_public_key: Some(public_key),
    };
    assert_eq!(account_entry(&phone, &group), founded);
    deliver_all(&mut laptop, &relay).await;
    assert_eq!(account_entry(&laptop, &group), founded);
    settings(ON_WRITING, &mut phone);
    settings(ON, &mut laptop);

    // Upkeep finds the key in the roster and sends nothing.
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(
        kept(&phone),
        confirmed(&founded.recovery_public_key.unwrap(), None)
    );
}

/// Confirming checks the typed words and keeps unconfirmed words for another
/// try; confirmed or cancelled words are forgotten. New words replace any
/// not yet confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_words_at_the_confirm_positions_confirm() {
    let Devices {
        _dirs, mut phone, ..
    } = phone_and_laptop().await;
    assert_eq!(
        refusal(phone.confirm_recovery_words(&[]).await.unwrap_err()),
        "recovery_words_not_started"
    );

    let first = phone.begin_recovery_words().unwrap();
    let second = phone.begin_recovery_words().unwrap();
    assert_ne!(first.words, second.words);
    let mut wrong = answers(&second);
    wrong.reverse();
    if wrong == answers(&second) {
        wrong[0] = if wrong[0] == "zoo" { "abandon" } else { "zoo" }.into();
    }
    for typed in [answers(&first), wrong, answers(&second)[..1].to_vec()] {
        if typed == answers(&second) {
            continue;
        }
        assert_eq!(
            refusal(phone.confirm_recovery_words(&typed).await.unwrap_err()),
            "recovery_words_mismatch"
        );
    }
    assert_eq!(kept(&phone), BackupRecoveryKeyRecord::Empty);

    phone.cancel_recovery_words();
    assert_eq!(
        refusal(
            phone
                .confirm_recovery_words(&answers(&second))
                .await
                .unwrap_err()
        ),
        "recovery_words_not_started"
    );

    let third = phone.begin_recovery_words().unwrap();
    let typed: Vec<String> = answers(&third)
        .iter()
        .map(|word| format!("  {} ", word.to_uppercase()))
        .collect();
    phone.confirm_recovery_words(&typed).await.unwrap();
    assert_eq!(
        refusal(
            phone
                .confirm_recovery_words(&answers(&third))
                .await
                .unwrap_err()
        ),
        "recovery_words_not_started"
    );
}

/// Confirming in a device group commits the account entry: turning backups
/// on makes the confirming device the writer, and new words from another
/// device keep that writer. The device whose words were replaced shows them
/// pending while its turn-on could still be selected, then not in use, until
/// the user dismisses the notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn words_confirmed_in_a_device_group_set_the_account_entry() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);
    settings(OFF, &mut laptop);

    let first = confirm_new_words(&mut laptop).await;
    assert_eq!(
        account_entry(&laptop, &group),
        AccountEntryV1 {
            backup_writer: Some(slot_of(&laptop)),
            recovery_public_key: Some(first.clone()),
        }
    );
    assert_eq!(kept(&laptop), confirmed(&first, None));
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(ON_WRITING, &mut laptop);
    settings(ON, &mut phone);

    let second = confirm_new_words(&mut phone).await;
    assert_eq!(
        account_entry(&phone, &group).recovery_public_key,
        Some(second.clone())
    );
    assert_eq!(kept(&phone), confirmed(&second, Some(&first)));
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let replaced = AccountEntryV1 {
        backup_writer: Some(slot_of(&laptop)),
        recovery_public_key: Some(second),
    };
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), replaced);
    }

    let before = published_count(&relay);
    laptop.try_recovery_key_upkeep().await.unwrap();
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before, "upkeep sends nothing");
    assert_eq!(kept(&laptop), confirmed(&first, None));
    settings((true, true, true, false, false), &mut laptop);
    settings(ON, &mut phone);
    // Words that may still be in use are not dismissed.
    laptop.dismiss_unused_recovery_words().unwrap();
    assert_eq!(kept(&laptop), confirmed(&first, None));

    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings((true, true, false, false, true), &mut laptop);
    settings(ON, &mut phone);
    laptop.dismiss_unused_recovery_words().unwrap();
    assert_eq!(kept(&laptop), BackupRecoveryKeyRecord::Empty);
    settings(ON_WRITING, &mut laptop);
}

/// Both devices turn backups on from the same epoch. The compare-and-set
/// keeps the loser's commit from undoing the winner's when the engine
/// re-issues it, so both rosters hold the winner's key and writer. The
/// loser's key had been in its roster before branch selection dropped it, so
/// its words stay pending until that branch is past the rewind horizon, and
/// only then read as not in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn of_two_concurrent_turn_ons_one_stands_and_the_other_is_unused() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);

    let phone_key = confirm_new_words(&mut phone).await;
    let laptop_key = confirm_new_words(&mut laptop).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let winner = account_entry(&phone, &group);
    assert_eq!(account_entry(&laptop, &group), winner);

    for device in [&mut phone, &mut laptop] {
        device.try_recovery_key_upkeep().await.unwrap();
    }
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(account_entry(&phone, &group), winner);
    let (won, lost) = if winner.recovery_public_key == Some(phone_key.clone()) {
        (&mut phone, &mut laptop)
    } else {
        assert_eq!(winner.recovery_public_key, Some(laptop_key));
        (&mut laptop, &mut phone)
    };
    assert_eq!(winner.backup_writer, Some(slot_of(won)));
    assert_eq!(
        kept(won),
        confirmed(winner.recovery_public_key.as_deref().unwrap(), None)
    );
    let lost_key = kept(lost);
    assert!(matches!(
        lost_key,
        BackupRecoveryKeyRecord::Confirmed { replaces: None, .. }
    ));
    settings(ON_WRITING, won);
    settings((true, false, true, false, false), lost);

    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let (won, lost) = if winner.backup_writer == Some(slot_of(&phone)) {
        (&mut phone, &mut laptop)
    } else {
        (&mut laptop, &mut phone)
    };
    assert_eq!(kept(lost), lost_key);
    settings(ON_WRITING, won);
    settings((true, false, false, false, true), lost);
}

/// A device group founded with a kept key holds it from the start, and words
/// that turned backups on are never carried again: a sibling that turns
/// backups off before any maintenance pass on the founder stands. The
/// founder shows its words pending while a branch that holds them can still
/// be selected, then not in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_turning_off_a_founded_key_stands() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let public_key = confirm_new_words(&mut phone).await;
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    assert_eq!(kept(&phone), lone(&public_key));
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let mut cursors = (cursor, cursor);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(ON, &mut laptop);

    laptop.turn_off_backups().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }
    settings((false, false, true, false, false), &mut phone);

    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(kept(&phone), confirmed(&public_key, None));
    settings((false, false, false, false, true), &mut phone);
}

/// A device that kept a key without a device group and then joins one
/// leaves the group's backups as they are, since its roster cannot tell
/// backups turned off from backups never on: nothing is sent, and the key is
/// retired. Its words stay pending while the group is younger on this device
/// than the rewind horizon, so no retained anchor shows what the oldest
/// selectable epoch held, and then read as not in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_joining_device_leaves_the_groups_backups_as_they_are() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let public_key = confirm_new_words(&mut laptop).await;
    assert_eq!(kept(&laptop), lone(&public_key));
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let mut cursors = (cursor, cursor);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;

    let before = published_count(&relay);
    laptop.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(kept(&laptop), confirmed(&public_key, None));
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }
    settings((false, false, true, false, false), &mut laptop);
    settings(OFF, &mut phone);

    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings((false, false, false, false, true), &mut laptop);
    // Founding a device group again would not bring the key back.
    assert_eq!(
        laptop.founding_account_entry(slot_of(&laptop)).unwrap(),
        AccountEntryV1::default()
    );
    let before = published_count(&relay);
    laptop.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
}

/// Upkeep reads only the key the winning roster holds, and carries only
/// while the engine keeps one of this device's account-entry commits: the
/// key new words replaced means their commit was lost, so they are carried
/// again (keeping the writer the roster names); any other means other words
/// won. Words that turned backups on are never carried again, even while the
/// roster holds no key, and once no commit of this device's is kept nothing
/// is carried, so the words read as not in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upkeep_carries_lost_words_again_and_lets_beaten_ones_go() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);

    // Words that turned backups on, over no key.
    keep(&phone, &confirmed(&[1; 32], None));
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(kept(&phone), confirmed(&[1; 32], None));
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());

    // The laptop turns backups on and the phone replaces its words, so the
    // engine keeps one of the phone's account-entry commits. Then words the
    // phone confirmed over its own are lost: the roster still holds the key
    // they replaced.
    let first = confirm_new_words(&mut laptop).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let own = confirm_new_words(&mut phone).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    keep(&phone, &confirmed(&[2; 32], Some(&own)));
    settings((true, false, true, false, false), &mut phone);
    phone.try_recovery_key_upkeep().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&phone, &laptop] {
        assert_eq!(
            account_entry(device, &group),
            AccountEntryV1 {
                backup_writer: Some(slot_of(&laptop)),
                recovery_public_key: Some(vec![2; 32]),
            }
        );
    }
    settings(ON, &mut phone);

    // Words confirmed over a key the roster no longer holds were beaten.
    keep(&laptop, &confirmed(&[3; 32], Some(&first)));
    let before = published_count(&relay);
    laptop.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(kept(&laptop), confirmed(&[3; 32], Some(&first)));
    settings((true, true, true, false, false), &mut laptop);

    // Past the rewind horizon the engine keeps none of the phone's commits:
    // words lost over the key the roster holds are not carried again.
    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    keep(&phone, &confirmed(&[4; 32], Some(&[2; 32])));
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(kept(&phone), confirmed(&[4; 32], Some(&[2; 32])));
    settings((true, false, false, false, true), &mut phone);
    settings((true, true, false, false, true), &mut laptop);
}

/// A commit the relays refuse for now stays for the runtime's retry: the
/// words are confirmed and wait as pending until it lands. Words that turned
/// backups on are never carried again, so a sibling that turns backups off
/// once the retry landed them is not undone. While a commit of this
/// device is in flight, confirming is refused as busy, nothing is kept, and
/// the words stay for another try.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirmed_words_wait_for_a_retry_and_a_busy_group_refuses() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);

    relay.fail_publishes_as_unavailable();
    let public_key = confirm_new_words(&mut phone).await;
    settings((false, false, true, false, false), &mut phone);
    assert_eq!(kept(&phone), confirmed(&public_key, None));

    // Newer words wait for the commit in flight.
    let newer = phone.begin_recovery_words().unwrap();
    for _ in 0..2 {
        assert_eq!(
            refusal(
                phone
                    .confirm_recovery_words(&answers(&newer))
                    .await
                    .unwrap_err()
            ),
            "device_group_busy"
        );
    }
    // Upkeep waits for the retry.
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(kept(&phone), confirmed(&public_key, None));

    relay.allow_publishes();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while account_entry(&phone, &group).recovery_public_key.as_ref() != Some(&public_key) {
            let effects = phone.runtime.advance_convergence(&group).await.unwrap();
            phone
                .observe_drained_session_events(&effects)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("the kept publish lands");
    assert_eq!(kept(&phone), confirmed(&public_key, None));
    settings(ON_WRITING, &mut phone);

    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    laptop.turn_off_backups().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    settings((false, false, true, false, false), &mut phone);

    phone
        .confirm_recovery_words(&answers(&newer))
        .await
        .unwrap();
    assert_eq!(
        account_entry(&phone, &group).recovery_public_key,
        Some(key_pair_of(&newer).0)
    );
}

/// Run `device`'s convergence until `done` holds of it. A pass whose
/// publish the relays refuse reports it as an error once its effects are
/// kept, and the next pass runs anyway.
async fn converge_until(
    device: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
    cursor: &mut usize,
    done: impl Fn(&mut AppClient) -> bool,
) {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while !done(device) {
            deliver_new(device, relay, cursor).await;
            if let Ok(effects) = device.runtime.advance_convergence(group).await {
                let _ = device.observe_drained_session_events(&effects).await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the device converges");
}

/// Words whose turn-on the runtime gives up on are not in use. While the
/// retry is in flight, upkeep waits and the words stay pending. Once the
/// relays refuse the commit for good, the engine keeps nothing of it, and
/// upkeep sends nothing. The words still read as pending while the group is
/// younger than the rewind horizon, since no retained anchor shows what its
/// oldest selectable epoch held, then as not in use, and no later pass turns
/// backups on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn words_whose_turn_on_the_runtime_gives_up_on_are_not_in_use() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);
    relay.fail_publishes_as_unavailable();
    let public_key = confirm_new_words(&mut phone).await;
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(kept(&phone), confirmed(&public_key, None));
    settings((false, false, true, false, false), &mut phone);

    relay.allow_publishes();
    relay.reject_next_publish();
    let mut cursor = published_count(&relay);
    converge_until(&mut phone, &relay, &group, &mut cursor, |phone| {
        phone
            .runtime
            .device_group_takes_commit(&group, &[])
            .unwrap()
    })
    .await;
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    assert!(
        !phone
            .runtime
            .own_account_entry_change_retained(&group)
            .unwrap()
    );
    settings((false, false, true, false, false), &mut phone);

    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    cursors.0 = cursor;
    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    cursor = cursors.0;
    settings((false, false, false, false, true), &mut phone);
    for _ in 0..2 {
        phone.run_due_maintenance().await.unwrap();
        converge_until(&mut phone, &relay, &group, &mut cursor, |phone| {
            phone
                .runtime
                .device_group_takes_commit(&group, &[])
                .unwrap()
        })
        .await;
    }
    assert_eq!(kept(&phone), confirmed(&public_key, None));
    settings((false, false, false, false, true), &mut phone);
    assert_eq!(
        account_entry(&phone, &group),
        AccountEntryV1::default(),
        "nothing turns backups on"
    );
}

/// The phone turns backups on while the laptop, from the same epoch, changes
/// its own entry twice. The laptop's longer branch wins without touching the
/// account entry, so the engine re-issues the phone's turn-on. While that
/// re-issue is in flight, upkeep waits: the roster holds no key, yet the
/// words stay pending and are not found unused. Once it lands, the laptop
/// turns backups off, and the phone, restarted before any maintenance pass,
/// never turns them on again: its words read as pending until its turn-on is
/// past the rewind horizon, then as not in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reissued_turn_on_is_awaited_and_a_later_turn_off_stands() {
    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);

    let public_key = confirm_new_words(&mut phone).await;
    edit_own_entry(&mut laptop, &group, &["macOS", "macOS 27"]).await;
    relay.fail_publishes_as_unavailable();
    converge_until(&mut phone, &relay, &group, &mut cursors.0, |phone| {
        roster(phone, &group).account == AccountEntryV1::default()
    })
    .await;
    assert!(
        !phone
            .runtime
            .device_group_takes_commit(&group, &[])
            .unwrap()
    );
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(kept(&phone), confirmed(&public_key, None));
    settings((false, false, true, false, false), &mut phone);

    relay.allow_publishes();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let turned_on = AccountEntryV1 {
        backup_writer: Some(slot_of(&phone)),
        recovery_public_key: Some(public_key.clone()),
    };
    let laptop_slot = slot_of(&laptop);
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), turned_on);
        assert_eq!(
            roster(device, &group).devices[&laptop_slot].platform,
            "macOS 27",
            "the laptop's own changes stay"
        );
    }
    settings(ON_WRITING, &mut phone);

    laptop.turn_off_backups().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    drop(phone);
    let mut phone = phone_app.client("alice").await.unwrap();
    phone.run_due_maintenance().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }
    assert_eq!(kept(&phone), confirmed(&public_key, None));
    settings((false, false, true, false, false), &mut phone);

    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    phone.run_due_maintenance().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    settings((false, false, false, false, true), &mut phone);
}

/// The phone's turn-on loses a fork to the laptop's longer branch, and the
/// announcement that would have the runtime re-issue it is lost, as when the
/// device stops, or a publish in the same pass fails, after the convergence
/// pass commits. The roster holds no key and nothing is queued, yet the
/// turn-on is still owed: the commit gate stays closed until maintenance
/// re-derives the re-issue, so the words stay pending, turning backups off
/// waits rather than finding them off already, and upkeep does not find
/// the words unused. Then the re-issue lands.
///
/// The test reaches that state the same way every run: the runtime decides
/// the re-issue and the relays refuse it for good, which leaves nothing
/// queued, and then, with the phone closed, the turn-on's intent is put back
/// as it was before the decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_turn_on_whose_reissue_announcement_was_lost_is_still_in_flight() {
    use cgka_traits::storage::OutboundIntentStorage;

    let (
        Devices {
            _dirs,
            relay,
            phone_app,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);

    let public_key = confirm_new_words(&mut phone).await;
    let turn_on = phone
        .app
        .account_storage(&phone.state.label)
        .unwrap()
        .list_own_commit_intents(Some(&group))
        .unwrap()
        .into_iter()
        .filter(|record| matches!(record.intent, SendIntent::ReplaceAccountEntry { .. }))
        .collect::<Vec<_>>();
    let [turn_on] = turn_on.as_slice() else {
        panic!("one turn-on intent: {turn_on:?}");
    };
    edit_own_entry(&mut laptop, &group, &["macOS", "macOS 27"]).await;
    // Up to the pass that switches branches and queues the re-issue, and
    // not one pass further, which would send it.
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            deliver_new(&mut phone, &relay, &mut cursors.0).await;
            if roster(&phone, &group).account == AccountEntryV1::default()
                && phone.runtime.has_queued_outbound_intents(&group).unwrap()
            {
                return;
            }
            let effects = phone.runtime.advance_convergence(&group).await.unwrap();
            phone
                .observe_drained_session_events(&effects)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the phone switches to the laptop's branch");
    let label = phone.state.label.clone();
    drop(phone);
    let storage = phone_app.account_storage(&label).unwrap();
    let queued = storage.list_queued_outbound_intents(&group).unwrap();
    let [reissue] = queued.as_slice() else {
        panic!("one re-issue: {queued:?}");
    };
    assert!(matches!(
        reissue.intent,
        SendIntent::ReplaceAccountEntry { .. }
    ));
    storage.delete_queued_outbound_intent(&reissue.id).unwrap();
    storage.put_own_commit_intent(turn_on).unwrap();
    drop(storage);
    let mut phone = phone_app.client(&label).await.unwrap();

    assert!(
        phone
            .runtime
            .session()
            .owes_superseded_own_commit_reissue(&group)
            .unwrap()
    );
    assert!(!phone.runtime.has_queued_outbound_intents(&group).unwrap());
    assert!(
        !phone
            .runtime
            .device_group_takes_commit(&group, &[])
            .unwrap(),
        "the turn-on has not reached its outcome"
    );
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    settings((false, false, true, false, false), &mut phone);
    assert_eq!(
        refusal(phone.turn_off_backups().await.unwrap_err()),
        "device_group_busy"
    );
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(kept(&phone), confirmed(&public_key, None));

    phone.run_due_maintenance().await.unwrap();
    assert_eq!(
        kept(&phone),
        confirmed(&public_key, None),
        "the words are not found unused"
    );
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let turned_on = AccountEntryV1 {
        backup_writer: Some(slot_of(&phone)),
        recovery_public_key: Some(public_key),
    };
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), turned_on);
    }
    settings(ON_WRITING, &mut phone);
}

/// Turning backups off clears the account entry, writer and key, as a
/// compare-and-set. The words in use had turned backups on, so maintenance
/// never carries them again over no key, and they read as not in use once
/// their turn-on is past the rewind horizon. Off already sends nothing, and
/// new words turn backups on again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_backups_off_clears_the_entry_and_keeps_it_clear() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);

    let laptop_key = confirm_new_words(&mut laptop).await;
    assert_eq!(kept(&laptop), confirmed(&laptop_key, None));
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(ON, &mut phone);

    phone.turn_off_backups().await.unwrap();
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    assert_eq!(
        kept(&phone),
        BackupRecoveryKeyRecord::TurningOff {
            replaces: laptop_key.clone(),
        }
    );
    settings(OFF, &mut phone);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(account_entry(&laptop, &group), AccountEntryV1::default());
    settings((false, false, true, false, false), &mut laptop);

    let before = published_count(&relay);
    for device in [&mut phone, &mut laptop] {
        device.try_recovery_key_upkeep().await.unwrap();
    }
    assert_eq!(
        kept(&phone),
        BackupRecoveryKeyRecord::TurningOff {
            replaces: laptop_key.clone(),
        }
    );
    phone.turn_off_backups().await.unwrap();
    assert_eq!(kept(&phone), BackupRecoveryKeyRecord::Empty);
    assert_eq!(
        published_count(&relay),
        before,
        "nothing turns them on again"
    );
    assert_eq!(kept(&laptop), confirmed(&laptop_key, None));
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }
    settings((false, false, true, false, false), &mut laptop);
    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings((false, false, false, false, true), &mut laptop);

    let phone_key = confirm_new_words(&mut phone).await;
    assert_ne!(phone_key, laptop_key);
    assert_eq!(
        account_entry(&phone, &group),
        AccountEntryV1 {
            backup_writer: Some(slot_of(&phone)),
            recovery_public_key: Some(phone_key),
        }
    );
    settings(ON_WRITING, &mut phone);
}

/// Upkeep carries a turn-off the roster lost again while the roster still
/// holds the key it was made over and the engine keeps one of this device's
/// account-entry commits, and leaves backups on once other words won. Words
/// confirmed over a key since turned off read as not in use once nothing
/// could bring them back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upkeep_carries_a_lost_turn_off_again_and_lets_a_beaten_one_go() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let start = published_count(&relay);
    let mut cursors = (start, start);
    confirm_new_words(&mut laptop).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    // The phone replaces the laptop's words, so the engine keeps one of its
    // account-entry commits. A turn-off it made over them was lost: the
    // roster still holds the key it was made over.
    let own = confirm_new_words(&mut phone).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let turning_off = BackupRecoveryKeyRecord::TurningOff {
        replaces: own.clone(),
    };
    keep(&phone, &turning_off);
    settings((true, false, false, true, false), &mut phone);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    assert_eq!(kept(&phone), turning_off);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(account_entry(&laptop, &group), AccountEntryV1::default());
    // The next pass finds it in the roster and sends nothing.
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(kept(&phone), turning_off);
    settings(OFF, &mut phone);

    // Other words won over a turn-off: backups stay on.
    let second = confirm_new_words(&mut laptop).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(ON, &mut phone);
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(kept(&phone), turning_off);
    assert_eq!(
        account_entry(&phone, &group).recovery_public_key,
        Some(second.clone())
    );

    // Words confirmed over a key since turned off.
    laptop.turn_off_backups().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    keep(&phone, &confirmed(&[3; 32], Some(&second)));
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(kept(&phone), confirmed(&[3; 32], Some(&second)));
    pass_the_rewind_horizon(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings((false, false, false, false, true), &mut phone);
}

/// A turn-off the relays refuse for now stays for the runtime's retry and
/// waits as pending until it lands. While a commit of this device is in
/// flight, turning off is refused as busy and nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_off_waits_for_a_retry_and_a_busy_group_refuses() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            ..
        },
        group,
    ) = linked_devices().await;
    let public_key = confirm_new_words(&mut phone).await;

    relay.fail_publishes_as_unavailable();
    phone.turn_off_backups().await.unwrap();
    assert_eq!(
        kept(&phone),
        BackupRecoveryKeyRecord::TurningOff {
            replaces: public_key.clone(),
        }
    );
    settings((true, true, false, true, false), &mut phone);
    for _ in 0..2 {
        assert_eq!(
            refusal(phone.turn_off_backups().await.unwrap_err()),
            "device_group_busy"
        );
    }
    assert_eq!(
        kept(&phone),
        BackupRecoveryKeyRecord::TurningOff {
            replaces: public_key.clone(),
        }
    );

    relay.allow_publishes();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while account_entry(&phone, &group) != AccountEntryV1::default() {
            let effects = phone.runtime.advance_convergence(&group).await.unwrap();
            phone
                .observe_drained_session_events(&effects)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("the kept publish lands");
    settings(OFF, &mut phone);
    let before = published_count(&relay);
    phone.try_recovery_key_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), before);
    assert_eq!(
        kept(&phone),
        BackupRecoveryKeyRecord::TurningOff {
            replaces: public_key,
        }
    );
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

/// Neither the words, their entropy nor the private half reaches the
/// account database: every statement the flow runs, with its values bound,
/// is free of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_words_and_the_private_half_never_reach_storage() {
    let (
        Devices {
            _dirs, mut phone, ..
        },
        _group,
    ) = linked_devices().await;
    phone
        .app
        .account_storage(&phone.state.label)
        .unwrap()
        .trace_queries_for_test(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(record_statement),
        )
        .unwrap();
    let shown = phone.begin_recovery_words().unwrap();
    phone
        .confirm_recovery_words(&answers(&shown))
        .await
        .unwrap();
    phone.run_due_maintenance().await.unwrap();
    let (public, private) = key_pair_of(&shown);

    let statements = std::mem::take(&mut *STATEMENTS.lock().unwrap());
    let public_hex = hex::encode(&public);
    assert!(
        statements
            .iter()
            .any(|sql| sql.to_lowercase().contains(&public_hex)),
        "the trace sees the public half written"
    );
    let secrets = [
        hex::encode(entropy_of(&shown)),
        hex::encode(private),
        shown.words.join(" "),
    ];
    for sql in &statements {
        let sql = sql.to_lowercase();
        for secret in &secrets {
            assert!(!sql.contains(secret.as_str()), "a secret reached storage");
        }
    }
}

/// Device groups off (release builds) refuse every step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_builds_refuse_recovery_words() {
    let Devices {
        _dirs,
        relay,
        phone,
        ..
    } = phone_and_laptop().await;
    drop(phone);
    let phone_app = MarmotApp::with_relay_and_config(
        _dirs[0].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay);
    let mut phone = phone_app.client("alice").await.unwrap();
    assert_eq!(
        refusal(phone.begin_recovery_words().unwrap_err()),
        "roster_unsupported"
    );
    assert_eq!(
        refusal(
            phone
                .confirm_recovery_words(&["abandon".into(), "about".into()])
                .await
                .unwrap_err()
        ),
        "roster_unsupported"
    );
    assert_eq!(
        refusal(phone.backup_settings().unwrap_err()),
        "roster_unsupported"
    );
    assert_eq!(
        refusal(phone.dismiss_unused_recovery_words().unwrap_err()),
        "roster_unsupported"
    );
    assert_eq!(
        refusal(phone.turn_off_backups().await.unwrap_err()),
        "roster_unsupported"
    );
}

/// The runtime runs the flow on the account's worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_confirms_recovery_words() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        phone,
        ..
    } = phone_and_laptop().await;
    drop(phone);
    let _eose = scripted_eose_pump(phone_app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    runtime.reconcile_accounts().await.unwrap();

    let shown = runtime.begin_recovery_words("alice").await.unwrap();
    runtime.cancel_recovery_words("alice").await.unwrap();
    assert!(matches!(
        runtime
            .confirm_recovery_words("alice", answers(&shown))
            .await,
        Err(AppError::DeviceGroupRefused("recovery_words_not_started"))
    ));
    let shown = runtime.begin_recovery_words("alice").await.unwrap();
    runtime
        .confirm_recovery_words("alice", answers(&shown))
        .await
        .unwrap();
    let read = runtime.backup_settings("alice").await.unwrap();
    assert!(read.enabled && read.this_device_writes && !read.words_pending);
    runtime
        .dismiss_unused_recovery_words("alice")
        .await
        .unwrap();
    // With no device group, turning off forgets the key this device keeps.
    runtime.turn_off_backups("alice").await.unwrap();
    assert_eq!(
        runtime.backup_settings("alice").await.unwrap(),
        BackupSettings::default()
    );
    runtime.shutdown().await;
}
