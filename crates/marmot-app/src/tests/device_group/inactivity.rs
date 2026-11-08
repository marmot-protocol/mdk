//! Marking and removing inactive siblings (mdk#2628 item 3.6b-2, D67(6),
//! D94, D95). A device acts only on passes that find it caught up with its
//! device group, counts time between them as running only across gaps of a
//! day or less, marks a sibling `inactive` 30 days after its clock last
//! restarted and removes it at 90 unless it is kept. A marked device clears
//! its own mark, and a device that can no longer catch up is offered the
//! explicit reset (D112).

use super::heartbeats::{devices_storage, entry_of, heartbeat_sent, listed};
use super::*;
use crate::DeviceLinkOp;
use crate::client::device_inactivity::{
    MARK_INACTIVE_AFTER_SECS, REMOVE_INACTIVE_AFTER_SECS, RUNNING_GAP_SECS,
};
use storage_sqlite::{DeviceInactivityClock, RecoveryCoverageProof, RecoveryCoverageSlice};

const DAY: u64 = 24 * 60 * 60;

/// Make `client`'s coverage ledger prove `group`'s history through a day
/// from now on every relay, as a completed catch-up leaves it.
fn prove_history(client: &AppClient, group: &GroupId) {
    let storage = devices_storage(client);
    let now = crate::unix_now_seconds();
    let routes = client
        .recovery_runner_routes()
        .into_iter()
        .filter(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .collect::<Vec<_>>();
    assert!(!routes.is_empty(), "the device group has a route");
    for route in routes {
        assert!(!route.required.is_empty());
        storage
            .widen_recovery_coverage_goals(std::slice::from_ref(&route.route), now - DAY)
            .unwrap();
        for relay in route.required.iter().chain(&route.best_effort) {
            storage
                .record_recovery_coverage(
                    &[RecoveryCoverageSlice {
                        route: &route.route,
                        relay,
                        since_seconds: 0,
                        until_seconds: now + DAY,
                        proof: RecoveryCoverageProof::Comparison,
                    }],
                    now + DAY,
                )
                .unwrap();
        }
    }
}

/// Make `reader` find `device` `age` ago and have counted no activity of it
/// since, with its own clock running for at least as long, its last
/// caught-up pass `last_caught_up` ago.
fn age_sibling(reader: &mut AppClient, device: &AppClient, age: u64, last_caught_up: u64) {
    let entry = entry_of(reader, device);
    let now = crate::unix_now_seconds();
    let storage = devices_storage(reader);
    storage.track_device_activity(&[], now).unwrap();
    storage.track_device_activity(&[entry], now - age).unwrap();
    storage
        .put_device_inactivity_clock(&DeviceInactivityClock {
            caught_up_at: now - last_caught_up,
            restarted_at: now - age,
        })
        .unwrap();
}

fn status_of(reader: &AppClient, group: &GroupId, device: &AppClient) -> DeviceStatusV1 {
    roster(reader, group).devices[&slot_of(device)].status
}

/// A sibling is marked `inactive` once its clock reaches 30 days, but only
/// on a pass that finds this device caught up: without the ledger's proof
/// nothing is committed. The marked device clears its own mark once caught
/// up, and the device that marked it then restarts its clock rather than
/// marking it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_is_marked_after_thirty_caught_up_days_and_clears_its_own_mark() {
    let (mut devices, group) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    age_sibling(
        &mut devices.phone,
        &devices.laptop,
        MARK_INACTIVE_AFTER_SECS + 60,
        60,
    );

    let before = removal::published_count(&devices.relay);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(removal::published_count(&devices.relay), before);
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Active
    );

    prove_history(&devices.phone, &group);
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Inactive
    );
    assert_eq!(
        listed(&mut devices.phone, &devices.laptop).status,
        LinkedDeviceStatus::Inactive
    );

    // The laptop has run all along, and sent a heartbeat since its clock
    // last restarted.
    deliver_all(&mut devices.laptop, &devices.relay).await;
    assert_eq!(
        status_of(&devices.laptop, &group, &devices.laptop),
        DeviceStatusV1::Inactive
    );
    let now = crate::unix_now_seconds();
    assert!(heartbeat_sent(&devices.laptop).is_some_and(|sent| sent.sent_at >= now - DAY));
    devices_storage(&devices.laptop)
        .put_device_inactivity_clock(&DeviceInactivityClock {
            caught_up_at: now - 60,
            restarted_at: now - DAY,
        })
        .unwrap();
    prove_history(&devices.laptop, &group);
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        status_of(&devices.laptop, &group, &devices.laptop),
        DeviceStatusV1::Active
    );

    // The phone has counted no heartbeat of the laptop's, so only the clear
    // keeps it from marking the laptop again.
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Active
    );
    let before = removal::published_count(&devices.relay);
    devices.phone.run_due_maintenance().await.unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(removal::published_count(&devices.relay), before);
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Active
    );
}

/// Time between caught-up passes counts only across gaps of a day or less:
/// after a longer one every sibling's clock restarts, so a sibling 30 days
/// quiet is not marked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gap_of_more_than_a_day_between_caught_up_passes_restarts_every_clock() {
    let (mut devices, group) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    prove_history(&devices.phone, &group);

    age_sibling(
        &mut devices.phone,
        &devices.laptop,
        MARK_INACTIVE_AFTER_SECS + 60,
        RUNNING_GAP_SECS + 60,
    );
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Active
    );
    let clock = devices_storage(&devices.phone)
        .device_inactivity_clock()
        .unwrap()
        .unwrap();
    assert_eq!(clock.restarted_at, clock.caught_up_at);

    age_sibling(
        &mut devices.phone,
        &devices.laptop,
        MARK_INACTIVE_AFTER_SECS + 60,
        RUNNING_GAP_SECS - 60,
    );
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Inactive
    );
}

/// A sibling still marked `inactive` is removed at 90 days with the
/// removal Commit a user's removal makes, unless "keep while inactive" is
/// on. Nothing is recorded for it, so its slot is left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inactive_sibling_is_removed_at_ninety_days_unless_kept() {
    let (mut devices, group) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    prove_history(&devices.phone, &group);
    let laptop_slot = own_slot(&devices.laptop);
    devices
        .phone
        .update_linked_device_settings(&laptop_slot, None, None, Some(true))
        .await
        .unwrap();
    age_sibling(
        &mut devices.phone,
        &devices.laptop,
        REMOVE_INACTIVE_AFTER_SECS + 60,
        60,
    );
    devices.phone.run_due_maintenance().await.unwrap();
    assert_eq!(
        status_of(&devices.phone, &group, &devices.laptop),
        DeviceStatusV1::Inactive
    );
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(
        roster(&devices.phone, &group)
            .devices
            .contains_key(&slot_of(&devices.laptop))
    );

    devices
        .phone
        .update_linked_device_settings(&laptop_slot, None, None, Some(false))
        .await
        .unwrap();
    devices.phone.run_due_maintenance().await.unwrap();
    let roster = roster(&devices.phone, &group);
    assert!(!roster.devices.contains_key(&slot_of(&devices.laptop)));
    assert_eq!(
        roster.rejected_slots[&slot_of(&devices.laptop)].reason,
        RejectedSlotReasonV1::Removed
    );
    assert_eq!(removal::pending_removals(&devices.phone_app), 0);
}

/// A device whose recovery gave up on a Commit it missed in its device
/// group shows its host that it is stalled, with one `DeviceLinkChanged`
/// from the pairing drive, and the explicit reset accepts that stuck copy
/// (D112) and forgets the inactivity clock with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_stuck_behind_a_missed_commit_is_offered_the_reset() {
    let (mut devices, group) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let epoch = devices.laptop.runtime.group_record(&group).unwrap().epoch;

    // The phone commits and then speaks at the next epoch; the laptop sees
    // only what came after the Commit.
    let phone_slot = own_slot(&devices.phone);
    devices
        .phone
        .rename_linked_device(&phone_slot, "Phone")
        .await
        .unwrap();
    let mut cursor = removal::published_count(&devices.relay);
    super::heartbeats::age_heartbeat(&devices.phone);
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(removal::published_count(&devices.relay) > cursor);
    deliver_new(&mut devices.laptop, &devices.relay, &mut cursor).await;
    devices.laptop.sync().await.unwrap();
    assert_eq!(
        devices.laptop.runtime.group_record(&group).unwrap().epoch,
        epoch
    );

    let storage = devices.laptop_app.account_storage("alice").unwrap();
    let app = storage.app_storage();
    // The epoch-stall detector arms the gap from evidence the harness does
    // not produce; the later message stays unreadable all the same.
    app.arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
        group_id_hex: hex::encode(group.as_slice()),
        stalled_epoch: epoch.0,
    }])
    .unwrap();
    devices.laptop.drive_device_pairing().await;
    devices.laptop.take_device_link_changed();
    assert!(!devices.laptop.device_group_stalled().unwrap());
    let gap = app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| {
            demand.cause == storage_sqlite::RecoveryCause::EpochGap
                && demand.group_id.as_deref() == Some(group.as_slice())
        })
        .expect("the missed Commit opened an epoch gap")
        .ticket
        .id;
    crate::client::history_notices::park_recovery_for_test(&storage, gap);

    let snapshot = devices
        .laptop
        .device_link(DeviceLinkOp::Read)
        .await
        .unwrap();
    assert!(snapshot.device_group_stalled);
    devices.laptop.drive_device_pairing().await;
    assert!(devices.laptop.take_device_link_changed());
    devices.laptop.drive_device_pairing().await;
    assert!(!devices.laptop.take_device_link_changed());

    // The reset forgets the inactivity clock with the device group.
    let now = crate::unix_now_seconds();
    devices_storage(&devices.laptop)
        .put_device_inactivity_clock(&DeviceInactivityClock {
            caught_up_at: now,
            restarted_at: now,
        })
        .unwrap();
    let reset = devices
        .laptop
        .device_link(DeviceLinkOp::ResetForRepair)
        .await
        .unwrap();
    assert!(!reset.device_group_stalled);
    assert_eq!(devices.laptop.trusted_device_group().unwrap(), None);
    assert_eq!(
        devices_storage(&devices.laptop)
            .device_inactivity_clock()
            .unwrap(),
        None
    );
}
