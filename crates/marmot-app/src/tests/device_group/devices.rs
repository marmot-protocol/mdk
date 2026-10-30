//! The Devices screen (mdk#2628 item 3.6a). Renaming a device is one roster
//! commit through the runtime's one roster write path, the one slot
//! announcements use: any device renames any device, and the commit replaces
//! only the label. A rename whose commit loses a fork to one that also
//! changes that device's entry is not made again: both copies show the
//! winner's label.
//!
//! Which commit wins a fork is up to branch selection, so the fork test passes
//! with either winner and checks where both copies end up.

use super::*;

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

fn refusal(error: AppError) -> &'static str {
    match error {
        AppError::DeviceGroupRefused(reason) => reason,
        other => panic!("expected a device-group refusal, got {other:?}"),
    }
}

/// Any device renames any device, itself included, and every sibling follows
/// the roster. Each rename replaces only the label: the announced KeyPackage
/// stays. Renaming to the label the roster already holds sends nothing, and
/// an empty label clears it.
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

    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap();
    assert!(phone.take_linked_devices_changed());
    assert_eq!(label_of(&mut phone, &laptop_slot), "Laptop");
    assert_eq!(announced(&phone, &group, &laptop), laptop_announced);
    let mut phone_cursor = published_count(&relay);
    deliver_new(&mut laptop, &relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(label_of(&mut laptop, &laptop_slot), "Laptop");
    assert_eq!(announced(&laptop, &group, &laptop), laptop_announced);

    laptop
        .rename_linked_device(&phone_slot, "Phone")
        .await
        .unwrap();
    deliver_new(&mut phone, &relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    assert_eq!(label_of(&mut phone, &phone_slot), "Phone");

    let before = published_count(&relay);
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

    relay.reject_next_publish();
    phone
        .rename_linked_device(&laptop_slot, "Laptop")
        .await
        .unwrap_err();
    assert_eq!(label_of(&mut phone, &laptop_slot), "é".repeat(32));
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
/// winning branch's rename stands: both copies show its label.
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
