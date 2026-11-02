//! Backups' recovery words (mdk#2628 item 4.4a, D75). Confirming 12 words
//! makes their key the account's recovery key: kept by a device with no
//! device group and carried into the roster it founds, and otherwise
//! committed to the roster's account entry as a compare-and-set over the
//! entry this device read. Turning backups off clears the entry the same
//! way. Nothing sends a change again but the engine's re-issue of a commit a
//! fork dropped and the runtime's retry of one the relays refused. Settings
//! show the roster as it is, so a change lost for good shows, and the user
//! makes it again. The words and the private half never reach storage.

use super::devices::{edit_own_entry, exchange, published_count, refusal};
use super::*;
use crate::{BackupSettings, RecoveryWords};
use bip39::{Language, Mnemonic};
use cgka_engine::recovery_key::derive_recovery_key_pair;
use cgka_traits::app_components::AccountEntryV1;
use openmls_rust_crypto::RustCrypto;
use std::sync::Mutex;

/// The words at `shown`'s confirm positions, in order.
pub(super) fn answers(shown: &RecoveryWords) -> Vec<String> {
    shown
        .confirm_positions
        .iter()
        .map(|&at| shown.words[at as usize - 1].clone())
        .collect()
}

/// The entropy `shown`'s words carry, read back through their checksum.
pub(super) fn entropy_of(shown: &RecoveryWords) -> [u8; 16] {
    Mnemonic::parse_in(Language::English, shown.words.join(" "))
        .unwrap()
        .to_entropy()
        .try_into()
        .unwrap()
}

/// The recovery key pair `shown`'s words derive: (public, private).
pub(super) fn key_pair_of(shown: &RecoveryWords) -> (Vec<u8>, Vec<u8>) {
    let pair = derive_recovery_key_pair(&RustCrypto::default(), &entropy_of(shown)).unwrap();
    (pair.public, pair.private.to_vec())
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

/// The recovery key `device` keeps while it trusts no device group.
fn kept(device: &AppClient) -> Option<Vec<u8>> {
    device
        .app
        .account_storage(&device.state.label)
        .unwrap()
        .app_storage()
        .kept_recovery_key()
        .unwrap()
}

fn account_entry(device: &AppClient, group: &GroupId) -> AccountEntryV1 {
    roster(device, group).account
}

/// Backups on, written here.
type Settings = (bool, bool);

fn settings(expected: Settings, device: &mut AppClient) {
    let read = device.backup_settings().unwrap();
    assert_eq!(
        (read.enabled, read.this_device_writes),
        expected,
        "{read:?}"
    );
}

const OFF: Settings = (false, false);
const ON_WRITING: Settings = (true, true);
const ON: Settings = (true, false);

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

/// Converge `device` until the device group takes a commit from it again.
async fn converge_until_it_takes_a_commit(
    device: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
    cursor: &mut usize,
) {
    converge_until(device, relay, group, cursor, |device| {
        device
            .runtime
            .device_group_takes_commit(group, &[])
            .unwrap()
    })
    .await;
}

/// A device with no device group keeps the key its confirmed words derive,
/// writes the backups, and founds its device group with that key and
/// itself as writer; trusting the group forgets the kept key. A sibling
/// that joins reads backups as on and written by the founder.
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
    assert_eq!(kept(&phone), Some(public_key.clone()));
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
    assert_eq!(kept(&phone), None);
    deliver_all(&mut laptop, &relay).await;
    assert_eq!(account_entry(&laptop, &group), founded);
    settings(ON_WRITING, &mut phone);
    settings(ON, &mut laptop);
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
    assert_eq!(kept(&phone), None);

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

/// Confirming in a device group commits the account entry, and this device
/// keeps nothing: turning backups on makes the confirming device the writer,
/// and new words from another device keep that writer.
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
            recovery_public_key: Some(first),
        }
    );
    assert_eq!(kept(&laptop), None);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(ON_WRITING, &mut laptop);
    settings(ON, &mut phone);

    let second = confirm_new_words(&mut phone).await;
    assert_eq!(
        account_entry(&phone, &group).recovery_public_key,
        Some(second.clone())
    );
    assert_eq!(kept(&phone), None);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let replaced = AccountEntryV1 {
        backup_writer: Some(slot_of(&laptop)),
        recovery_public_key: Some(second),
    };
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), replaced);
    }
    settings(ON_WRITING, &mut laptop);
    settings(ON, &mut phone);
}

/// Both devices turn backups on from the same epoch. The engine does not
/// re-issue the loser's turn-on over the winner's key, so both rosters hold
/// the winner's key and writer, and the loser's settings show it. Its user
/// makes the change again with new words, which keep the winner writing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn of_two_concurrent_turn_ons_one_stands_and_the_other_is_redone() {
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
    let phone_won = winner.recovery_public_key == Some(phone_key);
    if !phone_won {
        assert_eq!(winner.recovery_public_key, Some(laptop_key));
    }
    let (won, lost) = if phone_won {
        (&mut phone, &mut laptop)
    } else {
        (&mut laptop, &mut phone)
    };
    let won_slot = slot_of(won);
    assert_eq!(winner.backup_writer, Some(won_slot));
    settings(ON_WRITING, won);
    settings(ON, lost);

    let redone = confirm_new_words(lost).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let expected = AccountEntryV1 {
        backup_writer: Some(won_slot),
        recovery_public_key: Some(redone),
    };
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), expected);
    }
}

/// A device group founded with a kept key holds it from the start, and a
/// sibling that turns backups off stands: nothing on the founder turns them
/// on again.
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
    confirm_new_words(&mut phone).await;
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let mut cursors = (cursor, cursor);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(ON, &mut laptop);

    laptop.turn_off_backups().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    phone.run_due_maintenance().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }
    settings(OFF, &mut phone);
}

/// A creation whose trust write failed leaves its row `creating` and the
/// kept key in place, though the roster it founded already carries that
/// key. Confirming new words, or turning backups off, settles that creation
/// first and changes the roster, never only the kept key that trusting the
/// group then forgets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsettled_creation_is_settled_before_backups_change() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let founded_key = confirm_new_words(&mut phone).await;
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let mut cursors = (cursor, cursor);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let as_if_trust_failed = |phone: &AppClient, key: &[u8]| {
        let storage = phone
            .app
            .account_storage(&phone.state.label)
            .unwrap()
            .app_storage();
        assert!(
            storage
                .set_device_group_trust(
                    &hex::encode(group.as_slice()),
                    DeviceGroupTrust::Created,
                    DeviceGroupTrust::Creating,
                    None,
                    1,
                )
                .unwrap()
        );
        storage.keep_recovery_key(key).unwrap();
    };

    as_if_trust_failed(&phone, &founded_key);
    let new_key = confirm_new_words(&mut phone).await;
    assert_eq!(kept(&phone), None);
    assert_eq!(
        account_entry(&phone, &group).recovery_public_key,
        Some(new_key.clone())
    );
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;

    as_if_trust_failed(&phone, &new_key);
    phone.turn_off_backups().await.unwrap();
    assert_eq!(kept(&phone), None);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }
    settings(OFF, &mut phone);
}

/// A device that kept a key without a device group and then joins one
/// leaves the group's backups as they are, since its roster cannot tell
/// backups turned off from backups never on: nothing is sent, and trusting
/// the group forgets the key, so founding a device group again would not
/// bring it back.
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
    assert_eq!(kept(&laptop), Some(public_key));
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let mut cursors = (cursor, cursor);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;

    assert_eq!(kept(&laptop), None);
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }
    settings(OFF, &mut laptop);
    settings(OFF, &mut phone);
    assert_eq!(
        laptop.founding_account_entry(slot_of(&laptop)).unwrap(),
        AccountEntryV1::default()
    );
}

/// A commit the relays refuse for now stays for the runtime's retry, and
/// confirming returns. Settings show backups off until it lands. While a
/// commit of this device is in flight, confirming newer words is refused as
/// busy and the words stay for another try.
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
    settings(OFF, &mut phone);

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

    relay.allow_publishes();
    converge_until(&mut phone, &relay, &group, &mut cursors.0, |phone| {
        account_entry(phone, &group).recovery_public_key.as_ref() == Some(&public_key)
    })
    .await;
    settings(ON_WRITING, &mut phone);

    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    laptop.turn_off_backups().await.unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(OFF, &mut phone);
    phone
        .confirm_recovery_words(&answers(&newer))
        .await
        .unwrap();
    assert_eq!(
        account_entry(&phone, &group).recovery_public_key,
        Some(key_pair_of(&newer).0)
    );
}

/// A turn-on the relays refuse for good is lost: the engine keeps nothing of
/// it, settings show backups off, and nothing turns them on later. The user
/// turns them on again with new words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_turn_on_the_relays_refuse_for_good_shows_as_off_and_is_redone() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            ..
        },
        group,
    ) = linked_devices().await;
    relay.fail_publishes_as_unavailable();
    confirm_new_words(&mut phone).await;
    settings(OFF, &mut phone);

    relay.allow_publishes();
    relay.reject_next_publish();
    let mut cursor = published_count(&relay);
    converge_until_it_takes_a_commit(&mut phone, &relay, &group, &mut cursor).await;
    for _ in 0..2 {
        phone.run_due_maintenance().await.unwrap();
        converge_until_it_takes_a_commit(&mut phone, &relay, &group, &mut cursor).await;
    }
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    settings(OFF, &mut phone);

    let redone = confirm_new_words(&mut phone).await;
    assert_eq!(
        account_entry(&phone, &group),
        AccountEntryV1 {
            backup_writer: Some(slot_of(&phone)),
            recovery_public_key: Some(redone),
        }
    );
    settings(ON_WRITING, &mut phone);
}

/// The phone turns backups on while the laptop, from the same epoch, changes
/// its own entry twice. The laptop's longer branch wins without touching the
/// account entry, so the engine re-issues the phone's turn-on. While that
/// re-issue is in flight, the roster holds no key, and turning backups off
/// waits rather than finding them off already. Once it lands, the laptop
/// turns backups off, and the phone, restarted, never turns them on again.
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
    settings(OFF, &mut phone);
    assert_eq!(
        refusal(phone.turn_off_backups().await.unwrap_err()),
        "device_group_busy"
    );

    relay.allow_publishes();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let turned_on = AccountEntryV1 {
        backup_writer: Some(slot_of(&phone)),
        recovery_public_key: Some(public_key),
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
    settings(OFF, &mut phone);
}

/// The phone's turn-on loses a fork to the laptop's longer branch, and the
/// announcement that would have the runtime re-issue it is lost, as when the
/// device stops, or a publish in the same pass fails, after the convergence
/// pass commits. The roster holds no key and nothing is queued, yet the
/// turn-on is still owed: the commit gate stays closed until maintenance
/// re-derives the re-issue, so turning backups off waits rather than
/// reporting them off while the turn-on can still land, and new words wait
/// too. Then the re-issue lands.
///
/// The test reaches that state the same way every run: it closes the phone
/// once the pass that switches branches has queued the re-issue, deletes it
/// and puts the turn-on's intent back as it was before the decision, then
/// finishes any work that pass left, so only the owed re-issue holds the
/// gate.
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
    // The phone may have stopped with that pass's work unfinished. Finishing
    // it announces nothing again, since a withdrawal is announced once, so
    // only the owed re-issue holds the gate after it.
    let mut cursor = cursors.0;
    converge_until(&mut phone, &relay, &group, &mut cursor, |phone| {
        !phone
            .runtime
            .has_pending_convergence_inputs(&group)
            .unwrap()
    })
    .await;

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
            .has_pending_convergence_inputs(&group)
            .unwrap()
    );
    assert!(
        !phone
            .runtime
            .device_group_takes_commit(&group, &[])
            .unwrap(),
        "the turn-on has not reached its outcome"
    );
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    settings(OFF, &mut phone);
    assert_eq!(
        refusal(phone.turn_off_backups().await.unwrap_err()),
        "device_group_busy"
    );
    let newer = phone.begin_recovery_words().unwrap();
    assert_eq!(
        refusal(
            phone
                .confirm_recovery_words(&answers(&newer))
                .await
                .unwrap_err()
        ),
        "device_group_busy"
    );

    phone.run_due_maintenance().await.unwrap();
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
/// compare-and-set. Off already sends nothing, nothing turns them on again,
/// and new words turn them on with the confirming device writing.
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
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settings(ON, &mut phone);

    phone.turn_off_backups().await.unwrap();
    assert_eq!(account_entry(&phone, &group), AccountEntryV1::default());
    settings(OFF, &mut phone);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(account_entry(&laptop, &group), AccountEntryV1::default());
    settings(OFF, &mut laptop);

    let before = published_count(&relay);
    phone.turn_off_backups().await.unwrap();
    assert_eq!(published_count(&relay), before, "off already");
    for device in [&mut phone, &mut laptop] {
        device.run_due_maintenance().await.unwrap();
    }
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&phone, &laptop] {
        assert_eq!(account_entry(device, &group), AccountEntryV1::default());
    }

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

/// A turn-off the relays refuse for now stays for the runtime's retry, and
/// settings show backups on until it lands. While a commit of this device is
/// in flight, turning off and confirming new words are refused as busy and
/// nothing changes.
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
    settings(ON_WRITING, &mut phone);
    for _ in 0..2 {
        assert_eq!(
            refusal(phone.turn_off_backups().await.unwrap_err()),
            "device_group_busy"
        );
    }
    let newer = phone.begin_recovery_words().unwrap();
    assert_eq!(
        refusal(
            phone
                .confirm_recovery_words(&answers(&newer))
                .await
                .unwrap_err()
        ),
        "device_group_busy"
    );
    assert_eq!(
        account_entry(&phone, &group).recovery_public_key,
        Some(public_key)
    );

    relay.allow_publishes();
    let mut cursor = published_count(&relay);
    converge_until(&mut phone, &relay, &group, &mut cursor, |phone| {
        account_entry(phone, &group) == AccountEntryV1::default()
    })
    .await;
    settings(OFF, &mut phone);
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
/// account database, whether this device keeps the key or commits it to its
/// device group: every statement the flow runs, with its values bound, is
/// free of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_words_and_the_private_half_never_reach_storage() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        mut laptop,
        link,
        ..
    } = phone_and_laptop().await;
    phone
        .app
        .account_storage(&phone.state.label)
        .unwrap()
        .trace_queries_for_test(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(record_statement),
        )
        .unwrap();
    let kept_words = phone.begin_recovery_words().unwrap();
    phone
        .confirm_recovery_words(&answers(&kept_words))
        .await
        .unwrap();
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, &relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    let mut cursors = (cursor, cursor);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let committed_words = phone.begin_recovery_words().unwrap();
    phone
        .confirm_recovery_words(&answers(&committed_words))
        .await
        .unwrap();
    phone.run_due_maintenance().await.unwrap();

    let statements = std::mem::take(&mut *STATEMENTS.lock().unwrap());
    let public_hex = hex::encode(key_pair_of(&kept_words).0);
    assert!(
        statements
            .iter()
            .any(|sql| sql.to_lowercase().contains(&public_hex)),
        "the trace sees the kept public half written"
    );
    let mut secrets = Vec::new();
    for shown in [&kept_words, &committed_words] {
        secrets.push(hex::encode(entropy_of(shown)));
        secrets.push(hex::encode(key_pair_of(shown).1));
        secrets.push(shown.words.join(" "));
    }
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
    assert!(read.enabled && read.this_device_writes);
    // With no device group, turning off forgets the key this device keeps.
    runtime.turn_off_backups("alice").await.unwrap();
    assert_eq!(
        runtime.backup_settings("alice").await.unwrap(),
        BackupSettings::default()
    );
    runtime.shutdown().await;
}
