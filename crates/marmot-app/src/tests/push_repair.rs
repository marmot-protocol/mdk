//! Push repair (mdk#2611). A member that receives an announce works out what
//! the announcer lacks; if its leaf ranks in the top three for that announce,
//! it sends those records and tombstones in kind 448 and 449 lists after its
//! rank's slots, unless entries others carried meanwhile cover them. A
//! request counts as an announce with an empty `have`. A member answers each
//! announcer's leaf at most once per 24 hours.

use super::push_announce::{end_join_windows, finish_post_join_fetch};
use super::push_token_reshare::{Device, Fixture};
use super::*;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::time::Duration;

/// The kind 448 and 449 contents `device` sent from its `from`th gossip
/// event on.
fn replies(device: &Device, from: usize) -> Vec<(u64, serde_json::Value)> {
    device.client.test_sent_push_gossip[from..]
        .iter()
        .filter(|(_, event)| {
            event.kind == notifications::MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST
                || event.kind == notifications::MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL
        })
        .map(|(_, event)| (event.kind, serde_json::from_str(&event.content).unwrap()))
        .collect()
}

fn gossip_sent(device: &Device) -> usize {
    device.client.test_sent_push_gossip.len()
}

/// `(member, leaf, owner_sig)` of every token entry in `lists`.
fn listed_records(lists: &[(u64, serde_json::Value)]) -> BTreeSet<(String, u32, String)> {
    lists
        .iter()
        .filter(|(kind, _)| *kind == notifications::MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST)
        .flat_map(|(_, content)| content["tokens"].as_array().unwrap().clone())
        .map(|entry| {
            (
                entry["member_id_hex"].as_str().unwrap().to_owned(),
                u32::try_from(entry["leaf_index"].as_u64().unwrap()).unwrap(),
                entry["owner_sig"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// `(member, leaf, owner_sig)` of every record `device` holds in the group.
fn held_records(device: &Device, group_hex: &str) -> BTreeSet<(String, u32, String)> {
    device
        .client
        .app
        .group_push_tokens(&device.label, group_hex)
        .unwrap()
        .into_iter()
        .map(|record| (record.member_id_hex, record.leaf_index, record.owner_sig))
        .collect()
}

/// The leaves of `devices` other than `announcer`, in rank order for the
/// announce `announce_id_hex`.
fn ranked(devices: &[&Device], group: &GroupId, announce_id_hex: &str, announcer: u32) -> Vec<u32> {
    let announce_id = hex::decode(announce_id_hex).unwrap();
    let mut leaves = devices
        .iter()
        .map(|device| device.leaf(group).1)
        .filter(|leaf| *leaf != announcer)
        .map(|leaf| {
            let mut hasher = Sha256::new();
            hasher.update(&announce_id);
            hasher.update(leaf.to_be_bytes());
            (hasher.finalize().to_vec(), leaf)
        })
        .collect::<Vec<_>>();
    leaves.sort();
    leaves.into_iter().map(|(_, leaf)| leaf).collect()
}

/// `devices` ordered by the rank of their leaves in `order`.
fn by_rank<'a>(
    mut devices: Vec<&'a mut Device>,
    group: &GroupId,
    order: &[u32],
) -> Vec<&'a mut Device> {
    devices.sort_by_key(|device| {
        let leaf = device.leaf(group).1;
        order.iter().position(|ranked| *ranked == leaf).unwrap()
    });
    devices
}

/// Send a kind 447 with `content` from `device`; returns its event id.
async fn send_447(device: &mut Device, group: &GroupId, content: serde_json::Value) -> String {
    let (event, _) = device
        .client
        .send_app_event(
            group,
            AppMessageIntent::PushTokenUpdate {
                content: content.to_string(),
            },
        )
        .await
        .unwrap();
    event.id
}

/// A plain request: no `have`, and no records of the sender's own.
fn request() -> serde_json::Value {
    serde_json::json!({"v": notifications::PUSH_VERSION, "tokens": []})
}

fn announce_with_have(have: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"v": notifications::PUSH_VERSION, "tokens": [], "have": have})
}

/// Decide and send whatever repair work is due on `device`.
async fn repair(device: &mut Device) -> bool {
    device.client.send_due_push_repairs().await
}

async fn retry(device: &mut Device) -> bool {
    device
        .client
        .retry_pending_push_registration_shares_best_effort()
        .await
}

/// Every device receives everything published and shares its token where
/// an add queued a share, until nothing new is published.
async fn converge(relay: &ScriptedPushRelayClient, devices: &mut [&mut Device]) {
    loop {
        let before = relay.published_events.lock().unwrap().len();
        for device in devices.iter_mut() {
            device.receive(relay).await;
            device.share().await;
        }
        if relay.published_events.lock().unwrap().len() == before {
            break;
        }
    }
}

/// `devices` have settled, reply to an ask in their rank's slot without
/// waiting, and start with no repair work: the creator's first share was an
/// announce, which the fixture's other members would otherwise still answer.
async fn settle(devices: &mut [&mut Device]) {
    for device in devices.iter_mut() {
        device.can_fetch().await;
        device.client.push_announce_timing.repair_slot = Duration::ZERO;
        device.client.push_repairs = Default::default();
    }
}

/// The four fixture devices are members, each shared a token, and each
/// holds every record.
async fn four_members() -> Fixture {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    fx.carol.join(&relay, &group).await;
    fx.alice
        .client
        .invite_members(&group, &[fx.dave.account_id_hex.as_str()])
        .await
        .unwrap();
    fx.dave.join(&relay, &group).await;
    fx.carol.register("carol-token", &fx.server);
    fx.dave.register("dave-token", &fx.server);
    let mut devices = [&mut fx.alice, &mut fx.bob, &mut fx.carol, &mut fx.dave];
    converge(&relay, &mut devices).await;
    settle(&mut devices).await;
    let group_hex = fx.group_hex();
    let all = held_records(&fx.alice, &group_hex);
    assert_eq!(all.len(), 4);
    for device in [&fx.bob, &fx.carol, &fx.dave] {
        assert_eq!(held_records(device, &group_hex), all);
    }
    fx
}

/// An offline owner's record reaches a joiner through repair: the adder's
/// snapshot never came, so the joiner's announce at the end of its window
/// names nothing, and the adder relays Bob's record as Bob signed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_owners_record_reaches_a_joiner_through_repair() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    let before_add = held_records(&fx.alice, &group_hex);
    assert_eq!(before_add.len(), 2, "Alice's record and Bob's");

    // Bob is offline from here on, and Alice never sends the snapshot she
    // owes.
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    fx.carol.join(&relay, &group).await;
    finish_post_join_fetch(&fx.carol, &group);
    fx.carol.can_fetch().await;
    end_join_windows(&mut fx.carol);
    assert!(!retry(&mut fx.carol).await);
    assert!(held_records(&fx.carol, &group_hex).is_empty());

    settle(&mut [&mut fx.alice]).await;
    let from = gossip_sent(&fx.alice);
    fx.alice.receive(&relay).await;
    assert!(fx.alice.client.has_due_push_repair());
    assert!(!repair(&mut fx.alice).await);
    assert_eq!(listed_records(&replies(&fx.alice, from)), before_add);
    assert!(!fx.alice.client.has_due_push_repair());

    fx.carol.receive(&relay).await;
    assert_eq!(held_records(&fx.carol, &group_hex), before_add);
}

/// A request draws replies from the top three ranked leaves only, each
/// carrying every record, since a request names nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_draws_replies_from_at_most_the_top_three_leaves() {
    let mut fx = four_members().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    // A fifth member, so one of the requester's peers ranks fourth.
    let home = AccountHome::open(fx._dir.path());
    let mut erin = Device::create(&home, &fx.alice.client.app, "erin").await;
    fx.alice
        .client
        .invite_members(&group, &[erin.account_id_hex.as_str()])
        .await
        .unwrap();
    erin.join(&relay, &group).await;
    let mut devices = [
        &mut fx.alice,
        &mut fx.bob,
        &mut fx.carol,
        &mut fx.dave,
        &mut erin,
    ];
    converge(&relay, &mut devices).await;
    settle(&mut devices).await;
    let all = held_records(&fx.alice, &group_hex);
    assert_eq!(all.len(), 4, "Erin has no token");

    let requested = send_447(&mut erin, &group, request()).await;
    let order = ranked(
        &[&fx.alice, &fx.bob, &fx.carol, &fx.dave, &erin],
        &group,
        &requested,
        erin.leaf(&group).1,
    );
    assert_eq!(order.len(), 4);
    // Each decides and replies before any reply reaches it.
    let mut peers = [&mut fx.alice, &mut fx.bob, &mut fx.carol, &mut fx.dave];
    for device in peers.iter_mut() {
        device.receive(&relay).await;
    }
    let mut repliers = BTreeSet::new();
    for device in peers.iter_mut() {
        let from = gossip_sent(device);
        assert!(!repair(device).await);
        let sent = replies(device, from);
        if !sent.is_empty() {
            assert_eq!(listed_records(&sent), all, "a request names nothing");
            repliers.insert(device.leaf(&group).1);
        }
        assert!(!device.client.has_due_push_repair());
    }
    assert_eq!(repliers, order[..3].iter().copied().collect());
}

/// A lower rank waits its slots, and cancels once a higher rank's reply,
/// carried in the announce's epoch or later, covers what it would send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lower_rank_cancels_when_a_higher_ranks_reply_covers_it() {
    let mut fx = four_members().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let requested = send_447(&mut fx.dave, &group, request()).await;
    let order = ranked(
        &[&fx.alice, &fx.bob, &fx.carol, &fx.dave],
        &group,
        &requested,
        fx.dave.leaf(&group).1,
    );
    let mut ranks = by_rank(
        vec![&mut fx.alice, &mut fx.bob, &mut fx.carol],
        &group,
        &order,
    );
    let marks = ranks
        .iter()
        .map(|device| gossip_sent(device))
        .collect::<Vec<_>>();
    for device in ranks.iter_mut() {
        device.client.push_announce_timing.repair_slot = Duration::from_secs(3_600);
        device.receive(&relay).await;
    }
    for device in ranks.iter_mut() {
        assert!(!repair(device).await);
    }
    assert!(
        !replies(ranks[0], marks[0]).is_empty(),
        "rank 0 waits no slot"
    );
    for (device, from) in ranks[1..].iter().zip(&marks[1..]) {
        assert!(replies(device, *from).is_empty());
        assert!(
            !device.client.has_due_push_repair(),
            "its slots have not passed"
        );
    }

    // Rank 0's reply reaches the others before their slots pass.
    for (device, from) in ranks[1..].iter_mut().zip(&marks[1..]) {
        device.receive(&relay).await;
        device.client.push_repairs.test_make_replies_due();
        assert!(device.client.has_due_push_repair());
        assert!(!repair(device).await);
        assert!(replies(device, *from).is_empty(), "cancelled");
        assert!(!device.client.has_due_push_repair());
    }
}

/// A device catching up decides only after it has processed its backlog: a
/// reply another member sent while it was away cancels its own, though its
/// leaf ranks first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_catching_up_decides_after_its_backlog() {
    let mut fx = four_members().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let requested = send_447(&mut fx.dave, &group, request()).await;
    let order = ranked(
        &[&fx.alice, &fx.bob, &fx.carol, &fx.dave],
        &group,
        &requested,
        fx.dave.leaf(&group).1,
    );
    let mut ranks = by_rank(
        vec![&mut fx.alice, &mut fx.bob, &mut fx.carol],
        &group,
        &order,
    );

    // Rank 0 is offline; rank 1 replies.
    let from = gossip_sent(ranks[1]);
    ranks[1].receive(&relay).await;
    assert!(!repair(ranks[1]).await);
    assert!(!replies(ranks[1], from).is_empty());

    // Rank 0 comes back and processes the request and the reply in one batch
    // before its catch-up has settled.
    let first = &mut ranks[0];
    first.client.test_push_device_can_fetch = Some(false);
    first.client.advance_push_join_windows().await;
    let from = gossip_sent(first);
    first.receive(&relay).await;
    assert!(!first.client.has_due_push_repair(), "still catching up");
    assert!(!repair(first).await);
    assert!(replies(first, from).is_empty());

    first.can_fetch().await;
    assert!(first.client.has_due_push_repair());
    assert!(!repair(first).await);
    assert!(
        replies(first, from).is_empty(),
        "the reply it caught up on covers its own"
    );
    assert!(!first.client.has_due_push_repair());
}

/// A member answers each announcer's leaf at most once in 24 hours, however
/// many announces or requests that leaf sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_replies_to_each_leaf_at_most_once_a_day() {
    let mut fx = four_members().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    // With four members, each of the requester's three peers ranks in the
    // top three.
    for (round, expected) in [3, 0, 3].into_iter().enumerate() {
        if round == 2 {
            for device in [&mut fx.alice, &mut fx.bob, &mut fx.carol] {
                device
                    .client
                    .push_repairs
                    .test_age_replies_past_rate_limit();
            }
        }
        send_447(&mut fx.dave, &group, request()).await;
        let mut peers = [&mut fx.alice, &mut fx.bob, &mut fx.carol];
        for device in peers.iter_mut() {
            device.receive(&relay).await;
        }
        let mut repliers = 0;
        for device in peers.iter_mut() {
            let from = gossip_sent(device);
            assert!(!repair(device).await);
            repliers += usize::from(!replies(device, from).is_empty());
        }
        assert_eq!(repliers, expected, "round {round}");
    }
}

/// A `have` that is not an array, or has more than 4,096 elements, draws no
/// reply. Elements that are not 8 bytes in base64 name nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_or_oversized_have_draws_no_reply() {
    let mut fx = four_members().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    for have in [
        serde_json::json!("not an array"),
        serde_json::Value::Null,
        serde_json::json!({"0": 0}),
        serde_json::Value::Array(vec![serde_json::json!(0); 4_097]),
    ] {
        send_447(&mut fx.dave, &group, announce_with_have(have)).await;
        let mut peers = [&mut fx.alice, &mut fx.bob, &mut fx.carol];
        for device in peers.iter_mut() {
            let from = gossip_sent(device);
            device.receive(&relay).await;
            assert!(!device.client.has_due_push_repair());
            assert!(!repair(device).await);
            assert!(replies(device, from).is_empty());
        }
    }

    // At the cap, elements that name nothing leave the announcer lacking
    // everything.
    let mut junk = vec![
        serde_json::json!("not base64!"),
        serde_json::json!(7),
        serde_json::Value::Null,
        serde_json::json!(BASE64_STANDARD.encode([1_u8; 9])),
    ];
    junk.resize(4_096, serde_json::json!(0));
    send_447(
        &mut fx.dave,
        &group,
        announce_with_have(serde_json::Value::Array(junk)),
    )
    .await;
    let from = gossip_sent(&fx.alice);
    fx.alice.receive(&relay).await;
    assert!(!repair(&mut fx.alice).await);
    assert_eq!(
        listed_records(&replies(&fx.alice, from)),
        held_records(&fx.alice, &group_hex)
    );
}

/// An announce naming everything its peers hold draws no reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_converged_group_sends_no_repair() {
    let mut fx = four_members().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    let have = fx
        .dave
        .client
        .app
        .stored_group_push_tokens(&fx.dave.label, &group_hex)
        .unwrap()
        .into_iter()
        .map(|stored| notifications::push_have_element(&stored.record_digest.unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(have.len(), 4);
    send_447(&mut fx.dave, &group, announce_with_have(have.into())).await;
    for device in [&mut fx.alice, &mut fx.bob, &mut fx.carol] {
        let from = gossip_sent(device);
        device.receive(&relay).await;
        assert!(!repair(device).await);
        assert!(replies(device, from).is_empty());
        assert!(!device.client.has_due_push_repair());
    }
}

/// A repair reply is not an announce: it settles neither the announce a
/// device owes nor its join window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_reply_settles_no_announce_owed() {
    let mut fx = four_members().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    // Carol's join window is open, so the announce she owes waits for it.
    let owed = fx
        .carol
        .client
        .app
        .record_group_push_announce_owed(&fx.carol.label, &group_hex, notifications::unix_now_ms())
        .unwrap()
        .expect("Carol is a member");
    let gossip_state = |device: &Device| {
        device
            .client
            .app
            .group_push_gossip_state(&device.label, &group_hex)
            .unwrap()
            .unwrap()
    };
    let before = gossip_state(&fx.carol);
    assert!(before.joining_since_ms.is_some());
    assert_eq!(before.announce_owed_at_ms, Some(owed));

    send_447(&mut fx.dave, &group, request()).await;
    let from = gossip_sent(&fx.carol);
    fx.carol.receive(&relay).await;
    assert!(!retry(&mut fx.carol).await);
    assert!(!replies(&fx.carol, from).is_empty(), "Carol replied");
    let after = gossip_state(&fx.carol);
    assert_eq!(after.announce_owed_at_ms, Some(owed));
    assert_eq!(after.joining_since_ms, before.joining_since_ms);
    assert_eq!(after.last_announced_at_ms, before.last_announced_at_ms);
    assert!(
        fx.carol.client.test_sent_push_gossip[from..]
            .iter()
            .all(|(_, event)| event.kind != notifications::MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE),
        "no announce went out"
    );
}
