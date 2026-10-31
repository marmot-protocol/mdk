//! Heartbeats (mdk#2628 item 3.6, D35): once its leaf is tagged, each device
//! sends one in the device group at most hourly, with no push; a sibling
//! counts it whatever its content, only from the tree it holds when it reads
//! it, and shows the sibling inactive 30 days after its last activity.

use super::*;
use crate::client::device_heartbeats::{HEARTBEAT_INTERVAL_SECS, INACTIVE_AFTER_SECS};
use storage_sqlite::DeviceHeartbeatSent;

fn devices_storage(client: &AppClient) -> storage_sqlite::SqliteAppStorage {
    client.app.account_storage("alice").unwrap().app_storage()
}

fn heartbeat_sent(client: &AppClient) -> Option<DeviceHeartbeatSent> {
    devices_storage(client).device_heartbeat_sent().unwrap()
}

/// Make `client`'s last heartbeat an hour and a minute old.
fn age_heartbeat(client: &AppClient) {
    let mut sent = heartbeat_sent(client).expect("a heartbeat was sent");
    sent.sent_at -= HEARTBEAT_INTERVAL_SECS + 60;
    devices_storage(client)
        .put_device_heartbeat_sent(Some(&sent))
        .unwrap();
}

/// The device in `slot` as `reader` lists it.
fn listed_slot(reader: &mut AppClient, slot: &str) -> LinkedDevice {
    reader
        .linked_devices()
        .unwrap()
        .into_iter()
        .find(|listed| listed.slot_id_hex == slot)
        .expect("the roster lists the device")
}

/// `device` as `reader` lists it.
fn listed(reader: &mut AppClient, device: &AppClient) -> LinkedDevice {
    listed_slot(reader, &own_slot(device))
}

/// `device`'s entry as `reader`'s roster holds it: its slot and `linked_at`.
fn entry_of(reader: &mut AppClient, device: &AppClient) -> (String, u64) {
    (own_slot(device), listed(reader, device).linked_at)
}

/// Make `reader` forget every heartbeat of `device`, as if it had just found
/// it in the roster.
fn forget_activity(reader: &mut AppClient, device: &AppClient, now: u64) {
    let entry = entry_of(reader, device);
    let storage = devices_storage(reader);
    storage.track_device_activity(&[], now).unwrap();
    storage.track_device_activity(&[entry], now).unwrap();
}

fn group_messages_since(relay: &ScriptedPushRelayClient, since: usize) -> usize {
    published_kinds(relay, since)
        .into_iter()
        .filter(|kind| *kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .count()
}

/// Until its leaf is tagged, the joining laptop sends no heartbeat: its
/// siblings would count none from an untagged leaf. The pass that tags it
/// comes after; the next one sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_sends_no_heartbeat_until_its_leaf_is_tagged() {
    let (mut devices, _) = linked_devices().await;
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(heartbeat_sent(&devices.laptop), None);
    devices.laptop.run_due_maintenance().await.unwrap();
    assert!(heartbeat_sent(&devices.laptop).is_some());
}

/// Each device's heartbeat shows the other as active, never itself. A
/// device sends again only once its last heartbeat is an hour old, even
/// across a restart, and a heartbeat publishes no gift wrap, so no push.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siblings_see_each_others_heartbeats_at_most_hourly() {
    let (mut devices, group) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let now = crate::unix_now_seconds();
    let (phone_slot, laptop_slot) = (own_slot(&devices.phone), own_slot(&devices.laptop));
    for (reader, sibling_slot, own) in [
        (&mut devices.phone, &laptop_slot, &phone_slot),
        (&mut devices.laptop, &phone_slot, &laptop_slot),
    ] {
        let sent = heartbeat_sent(reader).expect("a settled device has sent one");
        assert_eq!(sent.group_id_hex, hex::encode(group.as_slice()));
        let sibling = listed_slot(reader, sibling_slot);
        let active = sibling.last_active_at.expect("its heartbeat counted");
        assert!(active <= now && now - active < 60);
        assert!(!sibling.inactive);
        let this = listed_slot(reader, own);
        assert_eq!(this.last_active_at, None);
        assert!(!this.inactive);
    }

    // Within the hour, nothing; restarting does not reset the hour.
    let before = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.run_due_maintenance().await.unwrap();
    drop(devices.laptop);
    let mut laptop = devices.laptop_app.client("alice").await.unwrap();
    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(group_messages_since(&devices.relay, before), 0);

    // An hour on, one heartbeat and nothing else.
    age_heartbeat(&laptop);
    forget_activity(&mut devices.phone, &laptop, crate::unix_now_seconds());
    assert_eq!(listed(&mut devices.phone, &laptop).last_active_at, None);
    laptop.run_due_maintenance().await.unwrap();
    assert_eq!(
        published_kinds(&devices.relay, before),
        vec![transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE]
    );
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(listed(&mut devices.phone, &laptop).last_active_at.is_some());
}

/// A receiver counts a heartbeat whatever its content. One read after the
/// receiver's epoch moved on counts for no device; the sibling's next one
/// counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_heartbeat_counts_whatever_its_content_but_only_in_the_current_tree() {
    let (mut devices, group) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;

    forget_activity(
        &mut devices.phone,
        &devices.laptop,
        crate::unix_now_seconds(),
    );
    devices
        .laptop
        .send_device_group_message(
            &group,
            crate::client::device_group::KIND_DEVICE_HEARTBEAT,
            r#"{"v":2,"later":"field"}"#.to_owned(),
        )
        .await
        .unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(
        listed(&mut devices.phone, &devices.laptop)
            .last_active_at
            .is_some()
    );

    // The laptop's heartbeat goes out at the epoch both hold; the phone
    // commits before it reads it.
    forget_activity(
        &mut devices.phone,
        &devices.laptop,
        crate::unix_now_seconds(),
    );
    age_heartbeat(&devices.laptop);
    let mut cursor = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.run_due_maintenance().await.unwrap();
    let heartbeat = devices.relay.published_events.lock().unwrap()[cursor..].to_vec();
    assert_eq!(heartbeat.len(), 1);
    let phone_slot = own_slot(&devices.phone);
    devices
        .phone
        .rename_linked_device(&phone_slot, "Phone")
        .await
        .unwrap();
    deliver_new(&mut devices.phone, &devices.relay, &mut cursor).await;
    devices.phone.sync().await.unwrap();
    assert_eq!(
        listed(&mut devices.phone, &devices.laptop).last_active_at,
        None
    );

    // Once the laptop has the commit, its next heartbeat counts.
    deliver_all(&mut devices.laptop, &devices.relay).await;
    age_heartbeat(&devices.laptop);
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    assert!(
        listed(&mut devices.phone, &devices.laptop)
            .last_active_at
            .is_some()
    );
}

/// A sibling shows inactive 30 days after the later of its last activity
/// and when this device first found it in the roster. A maintenance pass
/// that changes that owes hosts a `LinkedDevicesChanged`, and a heartbeat
/// makes it active again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_is_inactive_thirty_days_after_its_last_heartbeat() {
    let (mut devices, _) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let (laptop_slot, linked_at) = entry_of(&mut devices.phone, &devices.laptop);
    let now = crate::unix_now_seconds();
    let storage = devices_storage(&devices.phone);
    storage.track_device_activity(&[], now).unwrap();
    storage
        .track_device_activity(
            &[(laptop_slot.clone(), linked_at)],
            now - INACTIVE_AFTER_SECS - 10 * 24 * 60 * 60,
        )
        .unwrap();
    storage
        .note_device_active(&laptop_slot, linked_at, now - INACTIVE_AFTER_SECS - 60, now)
        .unwrap();
    let laptop = listed(&mut devices.phone, &devices.laptop);
    assert!(laptop.inactive);
    assert_eq!(laptop.last_active_at, Some(now - INACTIVE_AFTER_SECS - 60));

    devices.phone.take_linked_devices_changed();
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(devices.phone.take_linked_devices_changed());
    devices.phone.run_due_maintenance().await.unwrap();
    assert!(!devices.phone.take_linked_devices_changed());

    age_heartbeat(&devices.laptop);
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    let laptop = listed(&mut devices.phone, &devices.laptop);
    assert!(!laptop.inactive);
    assert!(laptop.last_active_at.unwrap() >= now);
}

/// Activity this device kept for an earlier entry of a slot, removed and
/// linked again before its next pass, does not carry over to the new entry
/// (a new `linked_at`): the sibling is not shown inactive, the next pass
/// first finds it then, and its next heartbeat counts for the new entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activity_kept_for_an_earlier_entry_of_the_slot_does_not_carry_over() {
    let (mut devices, _) = settled_linked_devices().await;
    deliver_all(&mut devices.laptop, &devices.relay).await;
    let (laptop_slot, linked_at) = entry_of(&mut devices.phone, &devices.laptop);
    let now = crate::unix_now_seconds();
    let long_ago = now - INACTIVE_AFTER_SECS - 10 * 24 * 60 * 60;
    let earlier = linked_at - 1;
    let storage = devices_storage(&devices.phone);
    storage.track_device_activity(&[], now).unwrap();
    storage
        .track_device_activity(&[(laptop_slot.clone(), earlier)], long_ago)
        .unwrap();
    storage
        .note_device_active(&laptop_slot, earlier, long_ago, long_ago)
        .unwrap();
    let laptop = listed(&mut devices.phone, &devices.laptop);
    assert!(!laptop.inactive);
    assert_eq!(laptop.last_active_at, None);

    devices.phone.run_due_maintenance().await.unwrap();
    let row = storage
        .device_activity()
        .unwrap()
        .into_iter()
        .find(|row| row.slot_id_hex == laptop_slot)
        .unwrap();
    assert_eq!(row.linked_at, linked_at);
    assert!(row.first_seen_at >= now && row.last_active_at.is_none());

    // Heard from before a pass reconciles: the heartbeat starts the row.
    storage
        .track_device_activity(&[(laptop_slot.clone(), earlier)], long_ago)
        .unwrap();
    storage
        .note_device_active(&laptop_slot, earlier, long_ago, long_ago)
        .unwrap();
    age_heartbeat(&devices.laptop);
    devices.laptop.run_due_maintenance().await.unwrap();
    deliver_all(&mut devices.phone, &devices.relay).await;
    let row = storage
        .device_activity()
        .unwrap()
        .into_iter()
        .find(|row| row.slot_id_hex == laptop_slot)
        .unwrap();
    assert_eq!(row.linked_at, linked_at);
    assert!(row.first_seen_at >= now && row.last_active_at.is_some_and(|at| at >= now));
}

/// A heartbeat every relay refused is sent at the next pass, not an hour
/// later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_heartbeat_that_reached_no_one_is_sent_again() {
    let (mut devices, _) = settled_linked_devices().await;
    age_heartbeat(&devices.laptop);
    let aged = heartbeat_sent(&devices.laptop);
    devices.relay.reject_next_publish();
    let before = devices.relay.published_events.lock().unwrap().len();
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(group_messages_since(&devices.relay, before), 0);
    assert_eq!(heartbeat_sent(&devices.laptop), aged);
    devices.laptop.run_due_maintenance().await.unwrap();
    assert_eq!(group_messages_since(&devices.relay, before), 1);
    assert_ne!(heartbeat_sent(&devices.laptop), aged);
}
