//! Push announces (mdk#2611). A device that joined announces once T has been
//! counted since its join completed, naming in `have` every record and
//! tombstone it holds; only time during which it could fetch counts. Inside
//! that window it shares in plain self-updates. After the window, a share is
//! an announce, and the first group message sent once the interval has passed
//! brings one along.

use super::push_token_reshare::{Device, Fixture};
use super::*;
use crate::client::{AcceptedPushAnnounce, PushAnnounceTiming};
use std::collections::BTreeSet;
use std::time::Duration;

/// Contents of the kind 447 events `device` sent from its `from`th gossip
/// event on.
fn sent_updates(device: &Device, from: usize) -> Vec<serde_json::Value> {
    device.client.test_sent_push_gossip[from..]
        .iter()
        .filter(|(_, event)| event.kind == notifications::MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE)
        .map(|(_, event)| serde_json::from_str(&event.content).unwrap())
        .collect()
}

fn gossip_sent(device: &Device) -> usize {
    device.client.test_sent_push_gossip.len()
}

/// The `have` of an announce, which a plain self-update lacks.
fn have(content: &serde_json::Value) -> Option<BTreeSet<String>> {
    content.get("have").map(|have| {
        have.as_array()
            .unwrap()
            .iter()
            .map(|element| element.as_str().unwrap().to_owned())
            .collect()
    })
}

/// `(member, leaf)` of each entry in `tokens`.
fn token_leaves(content: &serde_json::Value) -> Vec<(String, u32)> {
    content["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["member_id_hex"].as_str().unwrap().to_owned(),
                u32::try_from(entry["leaf_index"].as_u64().unwrap()).unwrap(),
            )
        })
        .collect()
}

/// The `have` elements of every record and tombstone `device` holds in the
/// group.
fn held(device: &Device, group_hex: &str) -> BTreeSet<String> {
    let app = &device.client.app;
    let records = app
        .stored_group_push_tokens(&device.label, group_hex)
        .unwrap()
        .into_iter()
        .map(|stored| stored.record_digest.unwrap());
    let tombstones = app
        .group_push_token_tombstones(&device.label, group_hex)
        .unwrap()
        .into_iter()
        .map(|tombstone| tombstone.record_digest);
    records
        .chain(tombstones)
        .map(|digest| notifications::push_have_element(&digest).unwrap())
        .collect()
}

fn gossip_state(device: &Device, group_hex: &str) -> storage_sqlite::AccountGroupPushGossipState {
    device
        .client
        .app
        .group_push_gossip_state(&device.label, group_hex)
        .unwrap()
        .unwrap()
}

/// `device`'s post-join history fetch in `group` has fetched and processed
/// the group's messages from its join epoch on. Returns when it ended. The
/// scripted relay sends no EOSE, so the test ends it.
fn finish_post_join_fetch(device: &Device, group: &GroupId) -> i64 {
    let runtime = &device.client.runtime;
    let fetch = runtime
        .start_post_join_history_fetch(group)
        .unwrap()
        .expect("the fetch is owed");
    let completion = runtime
        .finish_post_join_history_fetch(group, &fetch)
        .unwrap()
        .unwrap();
    i64::try_from(completion.completed_at_ms).unwrap()
}

/// T has been counted since every join of `device` completed.
fn end_join_windows(device: &mut Device) {
    device.client.push_announce_timing.join_window = Duration::ZERO;
}

async fn retry(device: &mut Device) -> bool {
    device
        .client
        .retry_pending_push_registration_shares_best_effort()
        .await
}

/// The creator has no join window and announces with its first share; a
/// joiner shares in a plain self-update while its window lasts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creator_announces_at_once_and_a_joiner_waits_for_its_window() {
    let fx = Fixture::new().await;
    let group_hex = fx.group_hex();

    let alice_sent = sent_updates(&fx.alice, 0);
    assert_eq!(alice_sent.len(), 1);
    let alice_have = have(&alice_sent[0]).expect("the creator's share is an announce");
    assert!(alice_have.is_subset(&held(&fx.alice, &group_hex)));
    assert_eq!(token_leaves(&alice_sent[0]), vec![fx.alice.leaf(&fx.group)]);
    let alice_state = gossip_state(&fx.alice, &group_hex);
    assert_eq!(alice_state.joining_since_ms, None);
    assert!(alice_state.last_announced_at_ms.is_some());

    let bob_sent = sent_updates(&fx.bob, 0);
    assert_eq!(bob_sent.len(), 1);
    assert_eq!(have(&bob_sent[0]), None, "no have inside the join window");
    assert_eq!(token_leaves(&bob_sent[0]), vec![fx.bob.leaf(&fx.group)]);
    let bob_state = gossip_state(&fx.bob, &group_hex);
    assert!(bob_state.joining_since_ms.is_some());
    assert_eq!(bob_state.last_announced_at_ms, None);
}

/// A member who joins after a snapshot announces once T has been counted
/// since its post-join history fetch ended, naming what the snapshot brought,
/// and members apply its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joiner_announces_once_when_its_join_window_ends() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    assert!(!fx.alice.client.send_owed_push_snapshots().await);
    fx.carol.join(&relay, &group).await;
    fx.carol.receive(&relay).await;

    // Inside the window Carol shares in a plain self-update.
    fx.carol.register("carol-token", &fx.server);
    let from = gossip_sent(&fx.carol);
    assert_eq!(fx.carol.share().await.succeeded_groups, 1);
    let shared = sent_updates(&fx.carol, from);
    assert_eq!(shared.len(), 1);
    assert_eq!(have(&shared[0]), None);

    // Her join completes when her post-join history fetch ends, and nothing
    // is owed until T has been counted since.
    let from = gossip_sent(&fx.carol);
    fx.carol.can_fetch().await;
    end_join_windows(&mut fx.carol);
    assert!(!retry(&mut fx.carol).await);
    assert_eq!(gossip_state(&fx.carol, &group_hex).joined_at_ms, None);
    fx.carol.client.push_announce_timing.join_window = PushAnnounceTiming::default().join_window;
    let fetched_at_ms = finish_post_join_fetch(&fx.carol, &group);
    assert!(!retry(&mut fx.carol).await);
    assert_eq!(
        gossip_state(&fx.carol, &group_hex).joined_at_ms,
        Some(fetched_at_ms)
    );
    assert!(sent_updates(&fx.carol, from).is_empty());
    assert!(!fx.carol.client.has_pending_push_registration_work());

    end_join_windows(&mut fx.carol);
    assert!(fx.carol.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.carol).await);
    let announced = sent_updates(&fx.carol, from);
    assert_eq!(announced.len(), 1);
    let carol_held = held(&fx.carol, &group_hex);
    assert_eq!(
        carol_held.len(),
        3,
        "Alice's and Bob's records, and her own"
    );
    assert_eq!(have(&announced[0]), Some(carol_held));
    assert_eq!(token_leaves(&announced[0]), vec![fx.carol.leaf(&group)]);
    let state = gossip_state(&fx.carol, &group_hex);
    assert_eq!(
        state.joining_since_ms, None,
        "the announce closes the window"
    );
    assert!(state.last_announced_at_ms.is_some());

    // Once only.
    assert!(!fx.carol.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.carol).await);
    assert_eq!(sent_updates(&fx.carol, from).len(), 1);

    // Members apply the announce as Carol's self-update.
    fx.alice.receive(&relay).await;
    assert!(
        fx.alice
            .token_leaves(&group)
            .contains(&fx.carol.leaf(&group))
    );
}

/// A joiner whose adder's snapshot never arrived, and who has no record of
/// its own, still announces at the end of its window, with `tokens: []`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joiner_without_a_snapshot_announces_with_no_tokens() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    // Alice never sends the snapshot she owes.
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    fx.carol.join(&relay, &group).await;
    finish_post_join_fetch(&fx.carol, &group);

    fx.carol.can_fetch().await;
    end_join_windows(&mut fx.carol);
    let from = gossip_sent(&fx.carol);
    assert!(!retry(&mut fx.carol).await);
    let announced = sent_updates(&fx.carol, from);
    assert_eq!(announced.len(), 1);
    assert_eq!(token_leaves(&announced[0]), Vec::new());
    assert_eq!(have(&announced[0]), Some(BTreeSet::new()));
    assert!(
        gossip_state(&fx.carol, &group_hex)
            .last_announced_at_ms
            .is_some()
    );
    // Members take it as a request, which changes nothing.
    fx.alice.receive(&relay).await;
}

/// The announce a join window owes survives a restart, and the reopened
/// client sends it only once its own catch-up has run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owed_join_window_announce_waits_for_the_catch_up_after_a_restart() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    fx.carol.join(&relay, &group).await;
    finish_post_join_fetch(&fx.carol, &group);
    fx.carol.client.advance_push_join_windows().await;
    let joined_at_ms = gossip_state(&fx.carol, &group_hex).joined_at_ms;
    assert!(joined_at_ms.is_some());

    let app = fx.carol.client.app.clone();
    let (label, account_id_hex, cursor) = (
        fx.carol.label.clone(),
        fx.carol.account_id_hex.clone(),
        fx.carol.cursor,
    );
    drop(fx.carol);
    let mut carol = Device::open(&app, &label, &account_id_hex, cursor).await;
    assert_eq!(gossip_state(&carol, &group_hex).joined_at_ms, joined_at_ms);
    assert!(!carol.client.has_pending_push_registration_work());

    // The window has ended, but the scripted relay serves the reopened
    // client's subscriptions no stored history, so its catch-up has not run.
    end_join_windows(&mut carol);
    carol.client.push_announce_timing.catch_up_settle = Duration::ZERO;
    assert!(!retry(&mut carol).await);
    assert!(!carol.client.has_pending_push_registration_work());
    assert!(sent_updates(&carol, 0).is_empty());

    carol.can_fetch().await;
    assert!(carol.client.has_pending_push_registration_work());
    assert!(!retry(&mut carol).await);
    assert_eq!(sent_updates(&carol, 0).len(), 1);
    let state = gossip_state(&carol, &group_hex);
    assert_eq!(state.joining_since_ms, None);
    assert!(state.last_announced_at_ms.is_some());
}

/// Only time during which the device could fetch counts toward T, and the
/// window ends once T has been counted, not T after the join completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_time_the_device_could_fetch_counts_toward_the_window() {
    let mut fx = Fixture::new().await;
    let group_hex = fx.group_hex();
    finish_post_join_fetch(&fx.bob, &fx.group);
    fx.bob.client.push_announce_timing.join_window = Duration::from_millis(200);
    fx.bob.client.push_announce_timing.catch_up_settle = Duration::ZERO;
    fx.bob.client.test_push_device_can_fetch = Some(false);
    fx.bob.client.advance_push_join_windows().await;
    assert!(gossip_state(&fx.bob, &group_hex).joined_at_ms.is_some());

    // Offline for longer than T.
    let from = gossip_sent(&fx.bob);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!retry(&mut fx.bob).await);
    assert_eq!(gossip_state(&fx.bob, &group_hex).join_window_counted_ms, 0);
    assert!(sent_updates(&fx.bob, from).is_empty());

    // Online: the first look begins the stretch, and T counts from there.
    fx.bob.client.test_push_device_can_fetch = Some(true);
    fx.bob.client.advance_push_join_windows().await;
    assert!(!retry(&mut fx.bob).await);
    assert!(sent_updates(&fx.bob, from).is_empty());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!retry(&mut fx.bob).await);
    let announced = sent_updates(&fx.bob, from);
    assert_eq!(announced.len(), 1);
    assert_eq!(have(&announced[0]), Some(held(&fx.bob, &group_hex)));
    let state = gossip_state(&fx.bob, &group_hex);
    assert!(state.join_window_counted_ms >= 200);
    assert_eq!(state.joining_since_ms, None);
}

/// After the window, a changed record is shared in an announce that names
/// the new record and not the one it replaces. Re-sharing the same record,
/// as after a member add, stays a plain self-update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_change_after_the_window_is_shared_in_an_announce() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    finish_post_join_fetch(&fx.bob, &group);
    fx.bob.can_fetch().await;
    end_join_windows(&mut fx.bob);
    assert!(!retry(&mut fx.bob).await);
    assert!(
        fx.bob
            .client
            .app
            .queue_current_push_registration_share_for_group(&fx.bob.label, &group_hex)
            .unwrap()
    );
    let from = gossip_sent(&fx.bob);
    assert_eq!(fx.bob.share().await.succeeded_groups, 1);
    let reshared = sent_updates(&fx.bob, from);
    assert_eq!(reshared.len(), 1);
    assert_eq!(have(&reshared[0]), None, "a re-share is no announce");
    let replaced = held(&fx.bob, &group_hex);

    tokio::time::sleep(Duration::from_millis(2)).await;
    let changed_at = notifications::unix_now_ms();
    fx.bob.register("bob-token-2", &fx.server);
    let from = gossip_sent(&fx.bob);
    assert_eq!(fx.bob.share().await.succeeded_groups, 1);
    let shared = sent_updates(&fx.bob, from);
    assert_eq!(shared.len(), 1);
    let bob_held = held(&fx.bob, &group_hex);
    assert_eq!(have(&shared[0]), Some(bob_held.clone()));
    assert_eq!(token_leaves(&shared[0]), vec![fx.bob.leaf(&group)]);
    assert_eq!(
        replaced.difference(&bob_held).count(),
        1,
        "the old record is not named"
    );
    assert!(
        gossip_state(&fx.bob, &group_hex)
            .last_announced_at_ms
            .unwrap()
            >= changed_at
    );

    fx.alice.receive(&relay).await;
    assert_eq!(held(&fx.alice, &group_hex), bob_held);
}

/// A changed record whose announce is left in the group's outbox is shared
/// again in a plain self-update: this client queues no other announce there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_record_left_in_the_outbox_is_reshared_without_an_announce() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    finish_post_join_fetch(&fx.bob, &group);
    fx.bob.can_fetch().await;
    end_join_windows(&mut fx.bob);
    assert!(!retry(&mut fx.bob).await);

    tokio::time::sleep(Duration::from_millis(2)).await;
    fx.bob.register("bob-token-2", &fx.server);
    let from = gossip_sent(&fx.bob);
    relay.zero_ack_next_publish();
    assert_eq!(fx.bob.share().await.succeeded_groups, 0);
    let announced = gossip_state(&fx.bob, &group_hex).last_announced_at_ms;
    assert_eq!(fx.bob.share().await.succeeded_groups, 1);
    let shared = sent_updates(&fx.bob, from);
    assert_eq!(shared.len(), 2);
    assert!(have(&shared[0]).is_some(), "the change is announced");
    assert_eq!(have(&shared[1]), None, "the retry is a plain self-update");
    assert_eq!(token_leaves(&shared[1]), vec![fx.bob.leaf(&group)]);
    assert_eq!(
        gossip_state(&fx.bob, &group_hex).last_announced_at_ms,
        announced,
        "the unpublished announce does not count"
    );
}

/// A changed record shared before this client's catch-up has run goes out at
/// once in a plain self-update, and the announce follows once the catch-up
/// has run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_shared_before_the_catch_up_is_announced_after_it() {
    let mut fx = Fixture::new().await;
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    finish_post_join_fetch(&fx.bob, &group);
    fx.bob.can_fetch().await;
    end_join_windows(&mut fx.bob);
    assert!(!retry(&mut fx.bob).await);
    let announced = gossip_state(&fx.bob, &group_hex)
        .last_announced_at_ms
        .unwrap();

    // The relays go away; the client's next catch-up has not run.
    fx.bob.client.test_push_device_can_fetch = Some(false);
    fx.bob.client.advance_push_join_windows().await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    fx.bob.register("bob-token-2", &fx.server);
    let from = gossip_sent(&fx.bob);
    assert_eq!(fx.bob.share().await.succeeded_groups, 1);
    let shared = sent_updates(&fx.bob, from);
    assert_eq!(shared.len(), 1);
    assert_eq!(
        have(&shared[0]),
        None,
        "the change goes in a plain self-update"
    );
    assert!(!retry(&mut fx.bob).await);
    assert_eq!(sent_updates(&fx.bob, from).len(), 1);

    fx.bob.can_fetch().await;
    assert!(fx.bob.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.bob).await);
    let sent = sent_updates(&fx.bob, from);
    assert_eq!(sent.len(), 2);
    assert_eq!(have(&sent[1]), Some(held(&fx.bob, &group_hex)));
    assert_eq!(token_leaves(&sent[1]), vec![fx.bob.leaf(&group)]);
    assert!(
        gossip_state(&fx.bob, &group_hex)
            .last_announced_at_ms
            .unwrap()
            >= announced
    );
    assert!(!fx.bob.client.has_pending_push_registration_work());
}

/// The periodic announce goes out with the first group message sent once the
/// interval has passed, even one left in the group's outbox, and never on its
/// own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn periodic_announce_rides_with_the_first_send_after_the_interval() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    let announced = gossip_state(&fx.alice, &group_hex)
        .last_announced_at_ms
        .unwrap();

    // Within the interval, a send owes nothing.
    let from = gossip_sent(&fx.alice);
    fx.alice.client.send(&group, b"soon after").await.unwrap();
    assert!(!fx.alice.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.alice).await);
    assert!(sent_updates(&fx.alice, from).is_empty());

    // Once the interval has passed, nothing goes out until Alice sends.
    fx.alice.client.push_announce_timing.interval = Duration::ZERO;
    assert!(!fx.alice.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.alice).await);
    assert!(sent_updates(&fx.alice, from).is_empty());

    relay.zero_ack_next_publish();
    let message = fx.alice.client.send(&group, b"a week later").await.unwrap();
    assert_ne!(
        message.accept_disposition,
        cgka_traits::SendAcceptDisposition::Published,
        "the message waits in the outbox"
    );
    assert!(fx.alice.client.take_queued_push_registration_share());
    assert!(fx.alice.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.alice).await);
    let sent = sent_updates(&fx.alice, from);
    assert_eq!(sent.len(), 1);
    assert_eq!(have(&sent[0]), Some(held(&fx.alice, &group_hex)));
    assert_eq!(token_leaves(&sent[0]), vec![fx.alice.leaf(&group)]);
    assert!(
        gossip_state(&fx.alice, &group_hex)
            .last_announced_at_ms
            .unwrap()
            >= announced
    );
    assert!(!fx.alice.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.alice).await);
    assert_eq!(sent_updates(&fx.alice, from).len(), 1);
}

/// A Welcome that invites the device again opens a new window. An announce
/// owed inside it waits for the window's end, where one announce settles
/// both, and an announce left in the outbox in the old window holds back no
/// other. (Storage drops what was owed before the Welcome.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_join_window_owes_its_own_announce() {
    let mut fx = Fixture::new().await;
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    finish_post_join_fetch(&fx.bob, &group);
    fx.bob.can_fetch().await;
    let window = gossip_state(&fx.bob, &group_hex);
    assert!(window.joined_at_ms.is_some());
    let from = gossip_sent(&fx.bob);
    fx.bob
        .client
        .app
        .record_group_push_announce_owed(&fx.bob.label, &group_hex, notifications::unix_now_ms())
        .unwrap();
    fx.bob.client.accepted_push_announces.insert(
        group.clone(),
        AcceptedPushAnnounce {
            joining_since_ms: Some(window.joining_since_ms.unwrap() - 1),
            app_event_id: "an announce from the old window".to_owned(),
            settles_owed: None,
        },
    );
    assert!(!fx.bob.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.bob).await);
    assert!(sent_updates(&fx.bob, from).is_empty(), "the window is open");

    end_join_windows(&mut fx.bob);
    assert!(fx.bob.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.bob).await);
    let sent = sent_updates(&fx.bob, from);
    assert_eq!(sent.len(), 1);
    assert_eq!(have(&sent[0]), Some(held(&fx.bob, &group_hex)));
    assert_eq!(gossip_state(&fx.bob, &group_hex).announce_owed_at_ms, None);
    assert!(fx.bob.client.accepted_push_announces.is_empty());
}

/// An announce counts only once it is published. A rejected one stays owed
/// and is sent again. One left in the group's outbox stays owed, but this
/// client queues no other there; after a restart it is sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_published_announce_counts() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group_hex = fx.group_hex();
    finish_post_join_fetch(&fx.bob, &fx.group);
    fx.bob.can_fetch().await;
    end_join_windows(&mut fx.bob);
    let unannounced = |device: &Device| {
        let state = gossip_state(device, &group_hex);
        state.last_announced_at_ms.is_none() && state.joining_since_ms.is_some()
    };

    let from = gossip_sent(&fx.bob);
    relay.reject_next_publish();
    assert!(retry(&mut fx.bob).await, "a rejected announce stays owed");
    assert!(unannounced(&fx.bob));
    assert!(fx.bob.client.has_pending_push_registration_work());
    assert!(sent_updates(&fx.bob, from).is_empty());

    relay.zero_ack_next_publish();
    assert!(!retry(&mut fx.bob).await);
    assert_eq!(
        sent_updates(&fx.bob, from).len(),
        1,
        "accepted into the outbox"
    );
    assert!(unannounced(&fx.bob));
    assert!(!fx.bob.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.bob).await);
    assert_eq!(sent_updates(&fx.bob, from).len(), 1, "no other is queued");

    let app = fx.bob.client.app.clone();
    let (label, account_id_hex, cursor) = (
        fx.bob.label.clone(),
        fx.bob.account_id_hex.clone(),
        fx.bob.cursor,
    );
    drop(fx.bob);
    let mut bob = Device::open(&app, &label, &account_id_hex, cursor).await;
    end_join_windows(&mut bob);
    bob.can_fetch().await;
    assert!(bob.client.has_pending_push_registration_work());
    assert!(!retry(&mut bob).await);
    assert_eq!(sent_updates(&bob, 0).len(), 1);
    let state = gossip_state(&bob, &group_hex);
    assert!(state.last_announced_at_ms.is_some());
    assert_eq!(state.joining_since_ms, None);
}

/// An announce left in the group's outbox counts once the outbox publishes
/// it: the join window closes, and the next announce owed is not held back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_announce_the_outbox_publishes_later_counts() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    finish_post_join_fetch(&fx.bob, &group);
    fx.bob.can_fetch().await;
    end_join_windows(&mut fx.bob);

    let from = gossip_sent(&fx.bob);
    relay.fail_publishes_as_unavailable();
    assert!(!retry(&mut fx.bob).await);
    assert_eq!(
        sent_updates(&fx.bob, from).len(),
        1,
        "accepted into the outbox"
    );
    assert_eq!(gossip_state(&fx.bob, &group_hex).last_announced_at_ms, None);

    relay.allow_publishes();
    let published = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            fx.bob.client.retry_group_convergence(&group).await.unwrap();
            if gossip_state(&fx.bob, &group_hex)
                .last_announced_at_ms
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
    assert!(published.is_ok(), "the outbox publishes it");
    assert_eq!(gossip_state(&fx.bob, &group_hex).joining_since_ms, None);
    assert!(fx.bob.client.accepted_push_announces.is_empty());
    assert_eq!(sent_updates(&fx.bob, from).len(), 1, "and it is not resent");
    assert!(!fx.bob.client.has_pending_push_registration_work());

    fx.bob.client.push_announce_timing.interval = Duration::ZERO;
    fx.bob.client.send(&group, b"a week later").await.unwrap();
    assert!(!retry(&mut fx.bob).await);
    let sent = sent_updates(&fx.bob, from);
    assert_eq!(sent.len(), 2, "the periodic announce goes out");
    assert_eq!(have(&sent[1]), Some(held(&fx.bob, &group_hex)));
}

/// An announce the outbox drops is sent again without another group message:
/// the announce it was sent for stays owed until one is published, which
/// settles it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_announce_the_outbox_drops_is_sent_again() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    fx.alice.client.push_announce_timing.interval = Duration::ZERO;
    fx.alice.client.send(&group, b"a week later").await.unwrap();
    let before = gossip_state(&fx.alice, &group_hex);
    assert!(
        before.announce_owed_at_ms.is_some(),
        "the periodic one is owed"
    );

    let from = gossip_sent(&fx.alice);
    relay.fail_publishes_as_unavailable();
    assert!(!retry(&mut fx.alice).await);
    assert_eq!(
        sent_updates(&fx.alice, from).len(),
        1,
        "accepted into the outbox"
    );
    assert!(!fx.alice.client.accepted_push_announces.is_empty());

    relay.allow_publishes();
    relay.reject_next_publish();
    let dropped = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let _ = fx.alice.client.retry_group_convergence(&group).await;
            if fx.alice.client.accepted_push_announces.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
    assert!(dropped.is_ok(), "the outbox drops it");
    let state = gossip_state(&fx.alice, &group_hex);
    assert_eq!(state.last_announced_at_ms, before.last_announced_at_ms);
    assert_eq!(state.announce_owed_at_ms, before.announce_owed_at_ms);

    assert!(fx.alice.client.has_pending_push_registration_work());
    assert!(!retry(&mut fx.alice).await);
    let sent = sent_updates(&fx.alice, from);
    assert_eq!(sent.len(), 2, "sent again");
    assert_eq!(have(&sent[1]), Some(held(&fx.alice, &group_hex)));
    let state = gossip_state(&fx.alice, &group_hex);
    assert!(state.last_announced_at_ms > before.last_announced_at_ms);
    assert_eq!(
        state.announce_owed_at_ms, None,
        "the published one settles it"
    );
    assert!(!fx.alice.client.has_pending_push_registration_work());
}

/// A change shared before the catch-up has run is still announced after a
/// restart: the announce is owed before the plain self-update goes out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_shared_before_the_catch_up_is_announced_after_a_restart() {
    let mut fx = Fixture::new().await;
    let group_hex = fx.group_hex();
    fx.alice.client.test_push_device_can_fetch = Some(false);
    fx.alice.client.advance_push_join_windows().await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    fx.alice.register("alice-token-2", &fx.server);
    let from = gossip_sent(&fx.alice);
    assert_eq!(fx.alice.share().await.succeeded_groups, 1);
    let shared = sent_updates(&fx.alice, from);
    assert_eq!(shared.len(), 1);
    assert_eq!(have(&shared[0]), None, "a plain self-update");
    assert!(
        gossip_state(&fx.alice, &group_hex)
            .announce_owed_at_ms
            .is_some()
    );

    let app = fx.alice.client.app.clone();
    let (label, account_id_hex, cursor) = (
        fx.alice.label.clone(),
        fx.alice.account_id_hex.clone(),
        fx.alice.cursor,
    );
    drop(fx.alice);
    let mut alice = Device::open(&app, &label, &account_id_hex, cursor).await;
    assert!(!retry(&mut alice).await);
    assert!(
        sent_updates(&alice, 0).is_empty(),
        "nothing before the catch-up"
    );
    alice.can_fetch().await;
    assert!(alice.client.has_pending_push_registration_work());
    assert!(!retry(&mut alice).await);
    let sent = sent_updates(&alice, 0);
    assert_eq!(sent.len(), 1);
    assert_eq!(have(&sent[0]), Some(held(&alice, &group_hex)));
    assert_eq!(token_leaves(&sent[0]), vec![alice.leaf(&fx.group)]);
    assert_eq!(gossip_state(&alice, &group_hex).announce_owed_at_ms, None);
}

/// A change whose owed announce cannot be recorded is not shared at all: no
/// plain self-update goes out and the share stays pending, so once storage
/// recovers its retry shares the change in an announce.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_whose_announce_debt_cannot_be_recorded_waits_for_its_retry() {
    let mut fx = Fixture::new().await;
    let group_hex = fx.group_hex();
    let before = gossip_state(&fx.alice, &group_hex);
    tokio::time::sleep(Duration::from_millis(2)).await;
    fx.alice.register("alice-token-2", &fx.server);
    fx.alice.client.test_fail_push_announce_owed_write = true;
    let from = gossip_sent(&fx.alice);
    assert_eq!(fx.alice.share().await.succeeded_groups, 0);
    assert!(sent_updates(&fx.alice, from).is_empty(), "nothing is sent");
    assert_eq!(gossip_state(&fx.alice, &group_hex), before);
    assert!(
        fx.alice.client.has_pending_push_registration_work(),
        "the share stays pending"
    );
    assert!(retry(&mut fx.alice).await, "the retry still waits");
    assert!(sent_updates(&fx.alice, from).is_empty());

    fx.alice.client.test_fail_push_announce_owed_write = false;
    assert!(!retry(&mut fx.alice).await);
    let sent = sent_updates(&fx.alice, from);
    assert_eq!(sent.len(), 1);
    assert_eq!(have(&sent[0]), Some(held(&fx.alice, &group_hex)));
    assert_eq!(token_leaves(&sent[0]), vec![fx.alice.leaf(&fx.group)]);
    let state = gossip_state(&fx.alice, &group_hex);
    assert!(state.last_announced_at_ms > before.last_announced_at_ms);
    assert_eq!(state.announce_owed_at_ms, None);
    assert!(!fx.alice.client.has_pending_push_registration_work());
}
