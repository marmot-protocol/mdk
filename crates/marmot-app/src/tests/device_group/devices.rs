//! The Devices screen (mdk#2628 item 3.6a). Renaming a device is one roster
//! commit through the runtime's one roster write path, the one slot
//! announcements use: any device renames any device, and the commit replaces
//! only the label and the rename id. A rename whose commit loses a fork is
//! made again while the winning roster holds a rename id its renames
//! replaced; another rename the winning roster holds stands (D37).
//!
//! Convergence picks the longer valid branch, so a test that needs one
//! device's commits to lose gives the other device more of them. Where
//! nothing decides the winner, the test passes with either.

use super::*;
use cgka_traits::app_components::DeviceRenameId;
use marmot_session::DeviceRosterEdit;

fn label_of(reader: &mut AppClient, slot: &str) -> String {
    reader
        .linked_devices()
        .unwrap()
        .into_iter()
        .find(|device| device.slot_id_hex == slot)
        .expect("a listed device")
        .label
}

fn published_count(relay: &ScriptedPushRelayClient) -> usize {
    relay.published_events.lock().unwrap().len()
}

fn rename_id_of(reader: &mut AppClient, slot: &str) -> Option<DeviceRenameId> {
    let slot: [u8; 32] = hex::decode(slot).unwrap().try_into().unwrap();
    reader.trusted_device_roster().unwrap().unwrap().1.devices[&slot].rename_id
}

fn renames(device: &AppClient) -> Vec<storage_sqlite::DeviceRenameRecord> {
    device
        .app
        .account_storage(&device.state.label)
        .unwrap()
        .app_storage()
        .device_renames()
        .unwrap()
}

fn refusal(error: AppError) -> &'static str {
    match error {
        AppError::DeviceGroupRefused(reason) => reason,
        other => panic!("expected a device-group refusal, got {other:?}"),
    }
}

/// Any device renames any device, itself included, and every sibling follows
/// the roster. Each rename replaces only the label and writes a fresh rename
/// id: the announced KeyPackage stays. Renaming to the label the roster
/// already holds sends nothing, and an empty label clears it with a fresh id
/// too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn any_device_renames_any_device() {
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
    let phone_slot = own_slot(&phone);
    let laptop_slot = own_slot(&laptop);
    let laptop_announced = announced(&phone, &group, &laptop);
    assert!(laptop_announced.is_some());
    let mut laptop_cursor = published_count(&relay);
    phone.take_linked_devices_changed();

    assert_eq!(rename_id_of(&mut phone, &laptop_slot), None);
    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    assert!(phone.take_linked_devices_changed());
    assert_eq!(label_of(&mut phone, &laptop_slot), "Laptop");
    assert_eq!(announced(&phone, &group, &laptop), laptop_announced);
    let laptop_rename = rename_id_of(&mut phone, &laptop_slot);
    assert!(laptop_rename.is_some());
    let mut phone_cursor = published_count(&relay);
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(label_of(&mut laptop, &laptop_slot), "Laptop");
    assert_eq!(rename_id_of(&mut laptop, &laptop_slot), laptop_rename);
    assert_eq!(announced(&laptop, &group, &laptop), laptop_announced);

    laptop
        .rename_linked_device(&phone_slot, "Phone")
        .await
        .unwrap();
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert_eq!(label_of(&mut phone, &phone_slot), "Phone");

    let before = published_count(&relay);
    let phone_rename = rename_id_of(&mut phone, &phone_slot);
    phone
        .rename_linked_device(&phone_slot, "Phone")
        .await
        .unwrap();
    assert_eq!(
        published_count(&relay),
        before,
        "an unchanged label sends nothing"
    );
    phone.rename_linked_device(&phone_slot, "").await.unwrap();
    assert_eq!(label_of(&mut phone, &phone_slot), "");
    let cleared = rename_id_of(&mut phone, &phone_slot);
    assert!(cleared.is_some() && cleared != phone_rename);
}

/// A rename is refused, and nothing is sent, for a label over 64 bytes and
/// for a slot the roster doesn't list. A rename whose publish is rejected is
/// refused too, and the roster keeps the label it had.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_is_refused_with_nothing_sent() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            laptop,
            ..
        },
        _group,
    ) = linked_devices().await;
    let laptop_slot = own_slot(&laptop);
    let before = published_count(&relay);

    let too_long = "é".repeat(32) + "x";
    assert_eq!(
        refusal(
            phone
                .rename_linked_device(&laptop_slot, &too_long)
                .await
                .unwrap_err()
        ),
        "label_too_long"
    );
    for slot in ["07".repeat(32), "not a slot".to_owned()] {
        assert_eq!(
            refusal(phone.rename_linked_device(&slot, "Gone").await.unwrap_err()),
            "unknown_device"
        );
    }
    assert_eq!(published_count(&relay), before);

    // 64 bytes of UTF-8 fit.
    phone
        .rename_linked_device(&laptop_slot, &"é".repeat(32))
        .await
        .unwrap();
    let kept = renames(&phone);

    // The rejected commit rolls back, so its record goes back as it was.
    relay.reject_next_publish();
    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap_err();
    assert_eq!(label_of(&mut phone, &laptop_slot), "é".repeat(32));
    assert_eq!(renames(&phone), kept);
}

/// A rename whose publish reaches no relay yet is kept by the runtime for a
/// retry, and keeps its record: saving the label the roster still shows is
/// refused as busy meanwhile, and when the retry lands, the roster holds the
/// id that record wrote, so a later fork is still judged by it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_kept_for_a_retry_keeps_its_record() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let laptop_slot = own_slot(&laptop);

    relay.fail_publishes_as_unavailable();
    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    assert_eq!(label_of(&mut phone, &laptop_slot), "", "not landed yet");
    let kept = renames(&phone);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].label, "Laptop");

    // Saving the label the roster shows meanwhile waits for the rename in
    // flight rather than forgetting it.
    assert_eq!(
        refusal(
            phone
                .rename_linked_device(&laptop_slot, "")
                .await
                .unwrap_err()
        ),
        "device_group_busy"
    );
    assert_eq!(renames(&phone), kept);

    // The runtime retries the kept publish after its backoff.
    relay.allow_publishes();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while label_of(&mut phone, &laptop_slot) != "Laptop" {
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
    assert_eq!(label_of(&mut phone, &laptop_slot), "Laptop");
    let landed = rename_id_of(&mut phone, &laptop_slot).unwrap();
    assert_eq!(renames(&phone)[0].written, vec![landed]);
}

/// While a commit of this device in the device group is staged and not yet
/// confirmed, a rename is refused with `device_group_busy` and nothing is
/// sent: a whole-entry replacement then could build on a roster about to
/// change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_while_a_commit_is_in_flight_is_refused() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            laptop,
            ..
        },
        group,
    ) = linked_devices().await;
    let laptop_slot = own_slot(&laptop);
    phone
        .runtime
        .session_mut()
        .send(cgka_traits::engine::SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let before = published_count(&relay);

    assert_eq!(
        refusal(
            phone
                .rename_linked_device(&laptop_slot, "Laptop")
                .await
                .unwrap_err()
        ),
        "device_group_busy"
    );
    assert_eq!(published_count(&relay), before);
    assert_eq!(label_of(&mut phone, &laptop_slot), "");
}

/// Deliver everything new to both devices and let each settle the device
/// group, twice, so each has seen the other's answer to what it got. The
/// device group is hidden, so convergence runs through the runtime.
async fn exchange(
    phone: &mut AppClient,
    laptop: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
    cursors: &mut (usize, usize),
) {
    for _ in 0..2 {
        for (device, cursor) in [
            (&mut *phone, &mut cursors.0),
            (&mut *laptop, &mut cursors.1),
        ] {
            deliver_new(device, relay, cursor).await;
            let effects = device.runtime.advance_convergence(group).await.unwrap();
            device
                .observe_drained_session_events(&effects)
                .await
                .unwrap();
        }
    }
}

/// The phone and the laptop both rename the laptop from the same epoch. The
/// winning branch holds a rename of the laptop, so the losing one stands down:
/// both copies show the winner's label, upkeep sends nothing, and the loser
/// forgets its rename.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_rename_of_the_same_device_stands() {
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
    let laptop_slot = own_slot(&laptop);
    let start = published_count(&relay);
    let mut cursors = (start, start);

    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    laptop
        .rename_linked_device(&laptop_slot, "Mine")
        .await
        .unwrap();
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    let winner = label_of(&mut phone, &laptop_slot);
    assert!(winner == "Laptop" || winner == "Mine");
    assert_eq!(label_of(&mut laptop, &laptop_slot), winner);

    let settled = published_count(&relay);
    phone.try_device_rename_upkeep().await.unwrap();
    laptop.try_device_rename_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), settled, "the loser sends nothing");
    for device in [&mut phone, &mut laptop] {
        assert_eq!(label_of(device, &laptop_slot), winner);
        assert!(renames(device).iter().all(|rename| rename.label == winner));
    }
}

/// `device` changes its own roster entry once per platform, each its own
/// commit, without renaming itself.
async fn edit_own_entry(device: &mut AppClient, group: &GroupId, platforms: &[&str]) {
    let slot: [u8; 32] = hex::decode(own_slot(device)).unwrap().try_into().unwrap();
    for platform in platforms {
        let edit = device
            .runtime
            .edit_device_roster_entry(group, &slot, &[], |entry| {
                entry.platform = (*platform).to_owned();
            })
            .await
            .unwrap();
        assert!(matches!(edit, DeviceRosterEdit::Committed(_)));
    }
}

/// Run each device's rename upkeep, then exchange what it sent.
async fn settle_renames(
    phone: &mut AppClient,
    laptop: &mut AppClient,
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
    cursors: &mut (usize, usize),
) {
    phone.try_device_rename_upkeep().await.unwrap();
    laptop.try_device_rename_upkeep().await.unwrap();
    exchange(phone, laptop, relay, group, cursors).await;
}

/// The phone renames the laptop while the laptop, from the same epoch,
/// changes its own entry twice without renaming itself. The laptop's longer
/// branch wins, and since it changed the entry the phone's commit replaced,
/// the engine does not re-issue that commit. The winning roster still holds
/// the rename id the phone's rename replaced, so upkeep makes the rename
/// again with a fresh id, over the laptop's own changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_that_loses_a_fork_is_made_again() {
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
    let laptop_slot = own_slot(&laptop);
    let start = published_count(&relay);
    let mut cursors = (start, start);

    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    let lost = rename_id_of(&mut phone, &laptop_slot);
    // Nothing has lost yet, so upkeep sends nothing.
    let sent = published_count(&relay);
    phone.try_device_rename_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), sent);

    edit_own_entry(&mut laptop, &group, &["macOS", "macOS 27"]).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(
            label_of(device, &laptop_slot),
            "",
            "the phone's rename lost"
        );
        assert_eq!(rename_id_of(device, &laptop_slot), None);
    }

    settle_renames(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(label_of(device, &laptop_slot), "Laptop");
        let made_again = rename_id_of(device, &laptop_slot);
        assert!(made_again.is_some() && made_again != lost);
        let platform = device
            .linked_devices()
            .unwrap()
            .into_iter()
            .find(|device| device.slot_id_hex == laptop_slot)
            .unwrap()
            .platform;
        assert_eq!(platform, "macOS 27", "the laptop's own changes stay");
    }
    let sent = published_count(&relay);
    phone.try_device_rename_upkeep().await.unwrap();
    assert_eq!(published_count(&relay), sent, "an applied rename stays put");
}

/// The phone renames the laptop twice while the laptop changes its own entry
/// three times, all from the same epoch. Both of the phone's commits lose
/// together, and the winning roster holds the id the first one replaced: the
/// phone makes its latest rename again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_renames_that_lose_together_are_made_again() {
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
    let laptop_slot = own_slot(&laptop);
    let start = published_count(&relay);
    let mut cursors = (start, start);

    for label in ["Work", "Laptop"] {
        phone
            .rename_linked_device(&laptop_slot, label)
            .await
            .unwrap();
    }
    edit_own_entry(&mut laptop, &group, &["a", "b", "c"]).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(
            label_of(device, &laptop_slot),
            "",
            "both of the phone's renames lost"
        );
    }
    settle_renames(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(label_of(device, &laptop_slot), "Laptop");
    }
}

/// The phone renames the laptop `"" → Work → Laptop` while the laptop renames
/// itself `"" → Mine → Work` and changes its platform, from the same epoch.
/// The laptop's longer branch wins. It holds the laptop's own `Work`, a
/// rename the phone's renames never replaced, so it stands even though the
/// phone once wrote that label too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_with_a_label_the_loser_also_wrote_stands() {
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
    let laptop_slot = own_slot(&laptop);
    let start = published_count(&relay);
    let mut cursors = (start, start);

    for label in ["Work", "Laptop"] {
        phone
            .rename_linked_device(&laptop_slot, label)
            .await
            .unwrap();
    }
    for label in ["Mine", "Work"] {
        laptop
            .rename_linked_device(&laptop_slot, label)
            .await
            .unwrap();
    }
    edit_own_entry(&mut laptop, &group, &["macOS"]).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    settle_renames(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(label_of(device, &laptop_slot), "Work");
    }
    assert!(renames(&phone).is_empty());
}

/// Saving the label the roster already shows sends nothing, and keeps the
/// rename that set it: when that rename's commit then loses a fork, it is
/// still made again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saving_the_same_label_again_keeps_its_rename() {
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
    let laptop_slot = own_slot(&laptop);
    let start = published_count(&relay);
    let mut cursors = (start, start);

    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    edit_own_entry(&mut laptop, &group, &["a", "b"]).await;
    let sent = published_count(&relay);
    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    assert_eq!(published_count(&relay), sent);
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(
        label_of(&mut phone, &laptop_slot),
        "",
        "the phone's rename lost"
    );
    settle_renames(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(label_of(device, &laptop_slot), "Laptop");
    }
}

/// After a rename loses a fork, saving the label the screen now shows sends
/// nothing and is the user's choice: the lost rename is not made again over
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saving_the_shown_label_after_a_lost_rename_keeps_it() {
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
    let laptop_slot = own_slot(&laptop);
    let start = published_count(&relay);
    let mut cursors = (start, start);

    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    edit_own_entry(&mut laptop, &group, &["a", "b"]).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(
        label_of(&mut phone, &laptop_slot),
        "",
        "the phone's rename lost"
    );
    let sent = published_count(&relay);
    phone.rename_linked_device(&laptop_slot, "").await.unwrap();
    assert_eq!(published_count(&relay), sent);
    assert!(renames(&phone).is_empty());

    settle_renames(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(label_of(device, &laptop_slot), "");
    }
}

/// What a lost rename needs is kept on disk: a device that restarts after
/// the fork, before any upkeep, still makes its lost rename again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_rename_is_made_again_after_a_restart() {
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
    let laptop_slot = own_slot(&laptop);
    let start = published_count(&relay);
    let mut cursors = (start, start);

    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    edit_own_entry(&mut laptop, &group, &["a", "b"]).await;
    exchange(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    assert_eq!(
        label_of(&mut phone, &laptop_slot),
        "",
        "the phone's rename lost"
    );
    drop((phone, laptop));
    let phone_app = device_group_app_at(&_dirs[0], relay.clone());
    let laptop_app = device_group_app_at(&_dirs[1], relay.clone());
    let mut phone = phone_app.client("alice").await.unwrap();
    let mut laptop = laptop_app.client("alice").await.unwrap();

    settle_renames(&mut phone, &mut laptop, &relay, &group, &mut cursors).await;
    for device in [&mut phone, &mut laptop] {
        assert_eq!(label_of(device, &laptop_slot), "Laptop");
    }
}

/// Without a trusted device group there is nothing to rename, and with
/// device groups off, as in release builds, renaming is refused outright.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_needs_a_device_group() {
    let Devices {
        _dirs,
        relay,
        mut phone,
        laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let laptop_slot = own_slot(&laptop);
    assert_eq!(
        refusal(
            phone
                .rename_linked_device(&laptop_slot, "Laptop")
                .await
                .unwrap_err()
        ),
        "no_device_group"
    );
    phone.dev_create_device_group(link).await.unwrap();
    drop(phone);

    let phone_app = MarmotApp::with_relay_and_config(
        _dirs[0].path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay.clone());
    let mut phone = phone_app.client("alice").await.unwrap();
    let before = published_count(&relay);
    assert_eq!(
        refusal(
            phone
                .rename_linked_device(&laptop_slot, "Laptop")
                .await
                .unwrap_err()
        ),
        "roster_unsupported"
    );
    assert_eq!(published_count(&relay), before);
}

/// Through the runtime, a rename announces `LinkedDevicesChanged` and the
/// next list carries the new label.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_renames_a_device_and_announces_it() {
    let Devices {
        _dirs,
        relay,
        phone_app,
        mut phone,
        laptop,
        link,
        ..
    } = phone_and_laptop().await;
    let laptop_slot = own_slot(&laptop);
    phone.dev_create_device_group(link).await.unwrap();
    drop(phone);
    let account_id_hex = phone_app
        .account_home()
        .account("alice")
        .unwrap()
        .account_id_hex;
    let _eose = scripted_eose_pump(phone_app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    next_linked_devices_changed(&mut events, &account_id_hex).await;

    runtime
        .rename_linked_device("alice", laptop_slot.clone(), "Laptop".into())
        .await
        .unwrap();
    next_linked_devices_changed(&mut events, &account_id_hex).await;
    let devices = runtime.linked_devices("alice").await.unwrap();
    let laptop = devices
        .iter()
        .find(|device| device.slot_id_hex == laptop_slot)
        .unwrap();
    assert_eq!(laptop.label, "Laptop");
    runtime.shutdown().await;
}

/// Each device fills in its own client and platform from its config, with
/// its next announcement: here the next maintenance pass. A blank or
/// over-long value is left out, and a sibling's list carries what it wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_device_reports_its_own_client_and_platform() {
    let (
        Devices {
            _dirs,
            relay,
            mut phone,
            mut laptop,
            ..
        },
        _group,
    ) = linked_devices().await;
    let phone_slot = own_slot(&phone);
    let mut laptop_cursor = published_count(&relay);
    let device = |reader: &mut AppClient| {
        reader
            .linked_devices()
            .unwrap()
            .into_iter()
            .find(|device| device.slot_id_hex == phone_slot)
            .unwrap()
    };
    assert_eq!(device(&mut laptop).platform, "");

    phone.app.config.key_package_client_name = Some(" whitenoise ".into());
    phone.app.config.device_platform = Some("iOS".into());
    phone.run_due_maintenance().await.unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    let reported = device(&mut laptop);
    assert_eq!(
        (reported.client.as_str(), reported.platform.as_str()),
        ("whitenoise", "iOS")
    );

    let before = published_count(&relay);
    phone.run_due_maintenance().await.unwrap();
    assert!(
        !published_kinds(&relay, before)
            .contains(&transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE),
        "an unchanged report sends nothing"
    );

    phone.app.config.device_platform = Some("x".repeat(65));
    phone.run_due_maintenance().await.unwrap();
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(device(&mut laptop).platform, "");
}
