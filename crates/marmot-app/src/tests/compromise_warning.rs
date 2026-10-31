//! The compromise warning and starting fresh (mdk#2628 item 3.7a): every
//! rejection a device makes, or finds in its device group's roster, warns
//! until the user dismisses it on that device; starting fresh puts off the
//! devices that were here first without rejecting them.

use super::canonical_membership::{deliver_new, published_key_package};
use super::sign_ins::{Account, commit_roster, link_for, own_slot, roster};
use super::*;
use crate::{CompromiseWarningItem, CompromiseWarningReason, SignInResponse};
use cgka_traits::app_components::{
    DeviceRosterOperationV1, RejectedKeyPackageV1, RejectedSlotReasonV1, RejectedSlotV1,
};
use storage_sqlite::SignInAnswer;

fn warned(client: &mut AppClient) -> Vec<(CompromiseWarningReason, String)> {
    client
        .compromise_warning()
        .unwrap()
        .into_iter()
        .map(|item| (item.reason, item.slot_id_hex))
        .collect()
}

fn slot_id(slot: &str) -> [u8; 32] {
    hex::decode(slot).unwrap().try_into().unwrap()
}

fn refused(result: Result<(), AppError>, code: &str) {
    assert!(
        matches!(&result, Err(AppError::DeviceGroupRefused(refused)) if *refused == code),
        "{code}: {result:?}"
    );
}

/// This wasn't me raises the warning, and Dismiss closes it for good: the
/// rejection is still gathered, but seen, after the device opens again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn this_wasnt_me_warns_until_dismissed() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    // Every client opens with the change set.
    assert!(phone.take_compromise_warning_changed());
    assert!(phone.compromise_warning().unwrap().is_empty());
    assert!(!phone.take_compromise_warning_changed());

    let mut tablet = account.open(1).await;
    published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    phone.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::NotNow)
        .await
        .unwrap();
    assert!(!phone.take_compromise_warning_changed());
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    assert!(phone.take_compromise_warning_changed());
    let warning = phone.compromise_warning().unwrap();
    let [
        CompromiseWarningItem {
            reason: CompromiseWarningReason::RejectedSignIn,
            slot_id_hex,
            key_package_ref_hex: None,
            occurred_at,
        },
    ] = warning.as_slice()
    else {
        panic!("{warning:?}");
    };
    assert_eq!(*slot_id_hex, tablet_slot);
    assert!(*occurred_at > 0);
    phone.note_compromise_warning_due();
    assert!(!phone.take_compromise_warning_changed());

    phone.dismiss_compromise_warning().unwrap();
    assert!(phone.take_compromise_warning_changed());
    assert!(phone.compromise_warning().unwrap().is_empty());
    phone.dismiss_compromise_warning().unwrap();
    assert!(!phone.take_compromise_warning_changed());
    drop(phone);
    let mut phone = account.open(0).await;
    assert!(phone.compromise_warning().unwrap().is_empty());
}

/// A rejection made on one device warns on every device of the group, at
/// the time its maker wrote, even one that takes the Welcome and the
/// rejection in one catch-up: its first roster is the Welcome's. Each device
/// dismisses its own warning, and a rejection the roster loses and gets back
/// stays seen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_warns_every_device_until_each_dismisses_it() {
    let account = Account::new(3, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    phone.check_sign_ins().await.unwrap();
    laptop.check_sign_ins().await.unwrap();
    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    assert!(phone.compromise_warning().unwrap().is_empty());

    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    phone.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    phone.commit_sign_in_rejections().await.unwrap();
    let rejected_at = roster(&phone, &group).rejected_slots[&slot_id(&tablet_slot)].rejected_at;
    let expected = [(CompromiseWarningReason::RejectedSignIn, tablet_slot.clone())];
    assert_eq!(warned(&mut phone), expected);

    let (mut phone_cursor, mut laptop_cursor) = (0, 0);
    laptop.take_compromise_warning_changed();
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));
    assert!(
        roster(&laptop, &group)
            .rejected_slots
            .contains_key(&slot_id(&tablet_slot))
    );
    assert!(laptop.take_compromise_warning_changed());
    let warning = laptop.compromise_warning().unwrap();
    assert_eq!(warning.len(), 1, "{warning:?}");
    assert_eq!(warning[0].slot_id_hex, tablet_slot);
    assert_eq!(warning[0].occurred_at, rejected_at);

    phone.dismiss_compromise_warning().unwrap();
    assert!(phone.compromise_warning().unwrap().is_empty());
    assert_eq!(warned(&mut laptop), expected);
    laptop.dismiss_compromise_warning().unwrap();
    assert!(laptop.compromise_warning().unwrap().is_empty());

    // The roster loses the rejection, as a losing branch would, and the
    // phone, which keeps its rejection, restores it.
    commit_roster(
        &mut laptop,
        &group,
        vec![DeviceRosterOperationV1::RemoveRejectedSlot(slot_id(
            &tablet_slot,
        ))],
    )
    .await;
    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    phone.commit_sign_in_rejections().await.unwrap();
    laptop.take_compromise_warning_changed();
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(
        roster(&laptop, &group)
            .rejected_slots
            .contains_key(&slot_id(&tablet_slot))
    );
    assert!(!laptop.take_compromise_warning_changed());
    assert!(laptop.compromise_warning().unwrap().is_empty());
    assert!(phone.compromise_warning().unwrap().is_empty());
}

/// Rejections already in the first roster a device trusts count as seen:
/// the user saw them on the devices that were there. A rejection the device
/// made before it joined still warns, and reaches the founder's warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejections_in_a_devices_first_roster_count_as_seen() {
    let account = Account::new(4, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    laptop.check_sign_ins().await.unwrap();

    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    phone.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    let mut kiosk = account.open(3).await;
    published_key_package(&mut kiosk, relay).await;
    let kiosk_slot = own_slot(&kiosk);
    laptop.check_sign_ins().await.unwrap();
    laptop
        .answer_sign_in(&kiosk_slot, SignInResponse::Reject)
        .await
        .unwrap();

    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    assert!(
        roster(&phone, &group)
            .rejected_slots
            .contains_key(&slot_id(&tablet_slot))
    );
    assert_eq!(
        warned(&mut phone),
        [(CompromiseWarningReason::RejectedSignIn, tablet_slot.clone())]
    );

    let (mut phone_cursor, mut laptop_cursor) = (0, 0);
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));
    assert_eq!(
        warned(&mut laptop),
        [(CompromiseWarningReason::RejectedSignIn, kiosk_slot.clone())]
    );
    laptop.commit_sign_in_rejections().await.unwrap();
    assert!(
        roster(&laptop, &group)
            .rejected_slots
            .contains_key(&slot_id(&kiosk_slot))
    );

    deliver_new(&mut phone, relay, &mut phone_cursor).await;
    phone.sync().await.unwrap();
    let mut phone_warning = warned(&mut phone);
    phone_warning.sort_by(|a, b| a.1.cmp(&b.1));
    let mut expected = vec![
        (CompromiseWarningReason::RejectedSignIn, tablet_slot),
        (CompromiseWarningReason::RejectedSignIn, kiosk_slot),
    ];
    expected.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(phone_warning, expected);
}

/// Of the roster's rejected slots only `not_me` ones warn, not a removed
/// device's; a rejected KeyPackage warns with the slot it appeared in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_key_package_warns_and_a_removed_slot_does_not() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    phone.check_sign_ins().await.unwrap();
    laptop.check_sign_ins().await.unwrap();
    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut laptop_cursor = 0;
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group.clone()));

    let (removed_slot, key_package_slot) = ([0x11; 32], [0x22; 32]);
    let key_package_ref = vec![0x33; 32];
    let rejected_at = crate::unix_now_seconds();
    commit_roster(
        &mut phone,
        &group,
        vec![
            DeviceRosterOperationV1::SetRejectedSlot(
                removed_slot,
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::Removed,
                    rejected_at,
                    tag_signature_key: None,
                },
            ),
            DeviceRosterOperationV1::SetRejectedKeyPackage(
                key_package_ref.clone(),
                RejectedKeyPackageV1 {
                    slot: key_package_slot,
                    rejected_at,
                },
            ),
        ],
    )
    .await;
    let expected = [CompromiseWarningItem {
        reason: CompromiseWarningReason::RejectedKeyPackage,
        slot_id_hex: hex::encode(key_package_slot),
        key_package_ref_hex: Some(hex::encode(&key_package_ref)),
        occurred_at: rejected_at,
    }];
    phone.note_compromise_warning_due();
    assert_eq!(phone.compromise_warning().unwrap(), expected);
    laptop.take_compromise_warning_changed();
    deliver_new(&mut laptop, relay, &mut laptop_cursor).await;
    laptop.sync().await.unwrap();
    assert!(laptop.take_compromise_warning_changed());
    assert_eq!(laptop.compromise_warning().unwrap(), expected);
}

/// A rejected sign-in the user goes on to link has ended: it leaves the
/// warning as soon as the roster holds its slot as a device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_sign_in_the_user_links_leaves_the_warning() {
    let account = Account::new(2, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let laptop_slot = own_slot(&laptop);
    phone.check_sign_ins().await.unwrap();
    phone
        .answer_sign_in(&laptop_slot, SignInResponse::Reject)
        .await
        .unwrap();
    assert_eq!(
        warned(&mut phone),
        [(CompromiseWarningReason::RejectedSignIn, laptop_slot.clone())]
    );

    let link = link_for(&laptop_key_package, 0x5a, &phone);
    let group = phone.dev_create_device_group(link).await.unwrap();
    assert!(
        roster(&phone, &group)
            .devices
            .contains_key(&slot_id(&laptop_slot))
    );
    assert!(phone.take_compromise_warning_changed());
    assert!(phone.compromise_warning().unwrap().is_empty());
    phone.commit_sign_in_rejections().await.unwrap();
    phone.note_compromise_warning_due();
    assert!(!phone.take_compromise_warning_changed());
    assert!(phone.compromise_warning().unwrap().is_empty());
}

/// Starting fresh answers each device that was here first Not now, rejects
/// nothing and warns of nothing. A later sign-in still asks whether it was
/// the user, and once one of the first devices links this one, it is no
/// longer fresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starting_fresh_puts_off_the_devices_here_first() {
    let account = Account::new(3, true);
    let relay = &account.relay;
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, relay).await;
    phone.check_sign_ins().await.unwrap();
    let mut laptop = account.open(1).await;
    let laptop_key_package = published_key_package(&mut laptop, relay).await;
    let phone_slot = own_slot(&phone);
    refused(laptop.start_fresh(), "sign_ins_unchecked");
    assert!(!laptop.started_fresh().unwrap());
    laptop.check_sign_ins().await.unwrap();
    laptop.take_unrecognized_sign_ins_changed();

    laptop.start_fresh().unwrap();
    assert!(laptop.started_fresh().unwrap());
    assert!(laptop.take_unrecognized_sign_ins_changed());
    let sign_ins = laptop.unrecognized_sign_ins().unwrap();
    let [sign_in] = sign_ins.as_slice() else {
        panic!("{sign_ins:?}");
    };
    assert_eq!(sign_in.slot_id_hex, phone_slot);
    assert!(sign_in.before_this_device);
    assert_eq!(sign_in.state, UnrecognizedSignInState::NotNow);
    let storage = laptop.app.account_storage("alice").unwrap().app_storage();
    assert_eq!(
        storage.sign_in(&phone_slot).unwrap().unwrap().answer,
        SignInAnswer::NotNow
    );
    assert!(laptop.compromise_warning().unwrap().is_empty());
    laptop.start_fresh().unwrap();
    assert!(!laptop.take_unrecognized_sign_ins_changed());

    let mut tablet = account.open(2).await;
    published_key_package(&mut tablet, relay).await;
    let tablet_slot = own_slot(&tablet);
    laptop.check_sign_ins().await.unwrap();
    let state = |client: &mut AppClient| {
        let mut sign_ins: Vec<_> = client
            .unrecognized_sign_ins()
            .unwrap()
            .into_iter()
            .map(|sign_in| {
                (
                    sign_in.slot_id_hex,
                    sign_in.before_this_device,
                    sign_in.state,
                )
            })
            .collect();
        sign_ins.sort_by(|a, b| a.0.cmp(&b.0));
        sign_ins
    };
    let mut expected = vec![
        (phone_slot.clone(), true, UnrecognizedSignInState::NotNow),
        (tablet_slot, false, UnrecognizedSignInState::Prompt),
    ];
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(state(&mut laptop), expected);

    let link = link_for(&laptop_key_package, 0x5a, &phone);
    laptop
        .dev_record_confirmed_device_link(link.clone())
        .unwrap();
    let group = phone.dev_create_device_group(link).await.unwrap();
    let mut cursor = 0;
    deliver_new(&mut laptop, relay, &mut cursor).await;
    laptop.sync().await.unwrap();
    assert_eq!(laptop.trusted_device_group().unwrap(), Some(group));
    assert!(!laptop.started_fresh().unwrap());
    refused(laptop.start_fresh(), "device_group_exists");
}

/// With device groups off there is no warning to read or dismiss, and no
/// starting fresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_warning_and_starting_fresh_stay_off_without_device_groups() {
    let account = Account::new(1, false);
    let mut phone = account.open(0).await;
    published_key_package(&mut phone, &account.relay).await;
    assert!(!phone.take_compromise_warning_changed());
    assert!(phone.compromise_warning().unwrap().is_empty());
    refused(phone.dismiss_compromise_warning(), "roster_unsupported");
    refused(phone.start_fresh(), "roster_unsupported");
    assert!(!phone.started_fresh().unwrap());
}

/// Hosts reach the warning and starting fresh through the runtime, with a
/// `CompromiseWarningChanged` at open and after each change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_reads_and_dismisses_the_warning() {
    let account = Account::new(2, true);
    drop(account.open(0).await);
    let phone_app = &account.apps[0];
    let _eose = scripted_eose_pump(
        phone_app.relay_plane.clone(),
        account.relay.clone(),
        every_subscription,
    );
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    next_warning_changed(&mut events, &account.alice_id).await;
    assert!(
        runtime
            .compromise_warning("alice")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!runtime.started_fresh("alice").await.unwrap());
    runtime.check_sign_ins("alice").await.unwrap();
    runtime.start_fresh("alice").await.unwrap();
    assert!(runtime.started_fresh("alice").await.unwrap());

    let mut tablet = account.open(1).await;
    published_key_package(&mut tablet, &account.relay).await;
    let tablet_slot = own_slot(&tablet);
    drop(tablet);
    runtime.check_sign_ins("alice").await.unwrap();
    runtime
        .answer_sign_in("alice", &tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    next_warning_changed(&mut events, &account.alice_id).await;
    let warning = runtime.compromise_warning("alice").await.unwrap();
    assert_eq!(
        warning
            .iter()
            .map(|item| (item.reason, item.slot_id_hex.as_str()))
            .collect::<Vec<_>>(),
        [(
            CompromiseWarningReason::RejectedSignIn,
            tablet_slot.as_str()
        )]
    );

    runtime.dismiss_compromise_warning("alice").await.unwrap();
    next_warning_changed(&mut events, &account.alice_id).await;
    assert!(
        runtime
            .compromise_warning("alice")
            .await
            .unwrap()
            .is_empty()
    );
    runtime.shutdown().await;
}

/// Waits for the account's next `CompromiseWarningChanged`.
async fn next_warning_changed(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_id_hex: &str,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::CompromiseWarningChanged {
                    account_id_hex: changed,
                    account_label,
                }) if changed == account_id_hex && account_label == "alice" => break,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => panic!("events closed"),
            }
        }
    })
    .await
    .expect("CompromiseWarningChanged");
}
