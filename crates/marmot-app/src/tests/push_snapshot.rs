//! Push snapshot on add (mdk#2611). A device whose Commit adds leaves owes the
//! group, once the Commit merges, kind 448 lists of every token record it holds
//! and kind 449 lists of every relayable tombstone, so a new member learns the
//! tokens of members who are offline.

use super::push_token_reshare::{Device, Fixture, group_message_count};
use super::*;
use std::collections::BTreeSet;

/// Bob's account keys, which sign the records and removals the tests plant.
fn bob_keys(fx: &Fixture) -> nostr::prelude::Keys {
    fx.bob
        .client
        .app
        .account_home()
        .load_signing_keys(&fx.bob.label)
        .unwrap()
}

/// A record or removal of Bob's leaf for a server other than the fixture's.
fn bob_record(fx: &Fixture, server_index: usize, relay_hint: String) -> GroupPushTokenRecord {
    let (member_id_hex, leaf_index) = fx.bob.leaf(&fx.group);
    let mut record = GroupPushTokenRecord {
        group_id_hex: fx.group_hex(),
        member_id_hex,
        leaf_index,
        platform: PushPlatform::Fcm,
        token_fingerprint: notifications::push_token_fingerprint(
            PushPlatform::Fcm,
            &server_index.to_be_bytes(),
        ),
        server_pubkey_hex: format!("{:064x}", server_index + 1),
        relay_hint: Some(relay_hint),
        encrypted_token: vec![0x5A; notifications::PUSH_ENCRYPTED_TOKEN_LEN],
        owner_ts: notifications::unix_now_ms(),
        owner_sig: String::new(),
        updated_at_ms: 0,
    };
    record.sign_owner(&bob_keys(fx)).unwrap();
    record
}

fn bob_removal(fx: &Fixture, server_index: usize) -> notifications::PushTokenRemovalRecord {
    let (member_id_hex, leaf_index) = fx.bob.leaf(&fx.group);
    let mut removal = notifications::PushTokenRemovalRecord {
        member_id_hex,
        leaf_index,
        platform: PushPlatform::Fcm,
        token_fingerprint: notifications::push_token_fingerprint(PushPlatform::Fcm, &[9]),
        server_pubkey_hex: format!("{:064x}", server_index + 1),
        owner_ts: notifications::unix_now_ms(),
        owner_sig: String::new(),
    };
    removal.sign_owner(&fx.group_hex(), &bob_keys(fx)).unwrap();
    removal
}

fn hold_tombstone(
    device: &Device,
    group_hex: &str,
    removal: &notifications::PushTokenRemovalRecord,
) {
    let tombstone =
        crate::conversions::account_push_token_tombstone_from_removal(group_hex, removal, 1)
            .unwrap();
    device
        .client
        .app
        .account_storage(&device.label)
        .unwrap()
        .app_storage()
        .apply_group_push_token_tombstone(&tombstone)
        .unwrap();
}

fn owed(device: &Device, group_hex: &str) -> Option<u64> {
    device
        .client
        .app
        .group_push_snapshot_owed(&device.label, group_hex)
        .unwrap()
}

fn current_epoch(device: &Device, group: &GroupId) -> u64 {
    device.client.runtime.epoch_state(group).unwrap().epoch().0
}

/// Published kind-445 events since `from`.
fn group_messages_since(relay: &ScriptedPushRelayClient, from: usize) -> Vec<NostrTransportEvent> {
    relay.published_events.lock().unwrap()[from..]
        .iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .cloned()
        .collect()
}

/// The adder relays an offline member's record and tombstone exactly as the
/// owner signed them, and the new member applies both after verifying Bob's
/// signatures, though Alice sent them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_relays_an_offline_members_record_and_tombstone() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    let removal = bob_removal(&fx, 7);
    hold_tombstone(&fx.alice, &group_hex, &removal);
    let bob_held_by_alice = fx
        .alice
        .client
        .app
        .group_push_tokens(&fx.alice.label, &group_hex)
        .unwrap()
        .into_iter()
        .find(|record| record.member_id_hex == fx.bob.account_id_hex)
        .unwrap();

    // Bob stays offline from here on, so he never re-shares to Carol.
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(
        owed(&fx.alice, &group_hex),
        Some(current_epoch(&fx.alice, &group) - 1),
        "owed once the epoch passes the one the add started from"
    );
    assert!(fx.alice.client.take_queued_push_registration_share());
    assert!(fx.alice.client.has_pending_push_registration_work());

    let before = group_message_count(&relay);
    assert!(!fx.alice.client.send_owed_push_snapshots().await);
    assert_eq!(
        group_message_count(&relay) - before,
        2,
        "one token list and one removal list"
    );
    assert_eq!(owed(&fx.alice, &group_hex), None);
    assert!(!fx.alice.client.send_owed_push_snapshots().await);
    assert_eq!(group_message_count(&relay) - before, 2, "sent once");

    fx.carol.join(&relay, &group).await;
    fx.carol.receive(&relay).await;
    let carol_records = fx
        .carol
        .client
        .app
        .group_push_tokens(&fx.carol.label, &group_hex)
        .unwrap();
    let bob_held_by_carol = carol_records
        .iter()
        .find(|record| record.member_id_hex == fx.bob.account_id_hex)
        .expect("Carol learned Bob's token from Alice");
    assert_eq!(bob_held_by_carol.owner_sig, bob_held_by_alice.owner_sig);
    assert_eq!(bob_held_by_carol.owner_ts, bob_held_by_alice.owner_ts);
    assert_eq!(
        fx.carol.token_leaves(&group),
        BTreeSet::from([fx.alice.leaf(&group), fx.bob.leaf(&group)])
    );
    let carol_tombstones = fx
        .carol
        .client
        .app
        .group_push_token_tombstones(&fx.carol.label, &group_hex)
        .unwrap();
    assert_eq!(carol_tombstones.len(), 1);
    assert_eq!(carol_tombstones[0].removal.as_ref(), Some(&removal));
}

/// Every group message of a snapshot too large for one fits 64 KiB as
/// published, and the new member applies every record in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_splits_into_group_messages_that_fit_64_kib() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    const PLANTED: usize = 70;
    for index in 0..PLANTED {
        let hint = format!("wss://relay.example/{}", "\"\\".repeat(index * 9));
        let record = bob_record(&fx, index, hint);
        fx.alice
            .client
            .app
            .upsert_group_push_token(&fx.alice.label, &record)
            .unwrap();
    }

    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    let before = relay.published_events.lock().unwrap().len();
    assert!(!fx.alice.client.send_owed_push_snapshots().await);
    let sent = group_messages_since(&relay, before);
    assert!(sent.len() >= 4, "{} lists", sent.len());
    for event in &sent {
        let len = serde_json::to_vec(event).unwrap().len();
        assert!(len <= 65_536, "a {len}-byte group message");
    }

    fx.carol.join(&relay, &group).await;
    fx.carol.receive(&relay).await;
    let held = fx
        .carol
        .client
        .app
        .group_push_tokens(&fx.carol.label, &group_hex)
        .unwrap();
    // Alice's own record, Bob's shared one, and every planted record.
    assert_eq!(held.len(), PLANTED + 2);
}

/// An owed snapshot survives a restart before it is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owed_snapshot_is_sent_after_a_restart() {
    let Fixture {
        _dir,
        relay,
        group,
        alice,
        bob,
        mut carol,
        ..
    } = Fixture::new().await;
    let group_hex = hex::encode(group.as_slice());
    let mut alice = alice;
    alice
        .client
        .invite_members(&group, &[carol.account_id_hex.as_str()])
        .await
        .unwrap();
    let app = alice.client.app.clone();
    let (label, account_id_hex, cursor) = (
        alice.label.clone(),
        alice.account_id_hex.clone(),
        alice.cursor,
    );
    drop(alice);

    let mut alice = Device::open(&app, &label, &account_id_hex, cursor).await;
    assert!(owed(&alice, &group_hex).is_some());
    assert!(alice.client.has_pending_push_registration_work());
    assert!(
        !alice
            .client
            .retry_pending_push_registration_shares_best_effort()
            .await
    );
    assert_eq!(owed(&alice, &group_hex), None);
    assert!(!alice.client.has_pending_push_registration_work());

    carol.join(&relay, &group).await;
    carol.receive(&relay).await;
    assert!(
        carol.token_leaves(&group).contains(&bob.leaf(&group)),
        "the offline member's record arrived in the snapshot"
    );
    alice.receive(&relay).await;
}

/// A device that holds no records or tombstones settles its owed snapshot
/// without sending anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_that_holds_nothing_sends_no_snapshot() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    fx.alice
        .raw_connection()
        .execute("DELETE FROM group_push_tokens", [])
        .unwrap();
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    assert!(owed(&fx.alice, &group_hex).is_some());

    let before = group_message_count(&relay);
    assert!(!fx.alice.client.send_owed_push_snapshots().await);
    assert_eq!(group_message_count(&relay), before);
    assert_eq!(owed(&fx.alice, &group_hex), None);
}

/// The owed snapshot is recorded before the Commit is staged, so a failure to
/// record it stages nothing and leaves the earlier owed snapshot as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_invite_persistence_leaves_the_owed_snapshot_as_it_was() {
    let mut fx = Fixture::new().await;
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    let epoch = current_epoch(&fx.alice, &group);
    // An earlier add still owes its snapshot.
    assert!(
        fx.alice
            .client
            .app
            .record_group_push_snapshot_owed(&fx.alice.label, &group_hex, 0)
            .unwrap()
    );
    let connection = fx.alice.raw_connection();

    connection
        .execute_batch(
            "CREATE TRIGGER fail_invite BEFORE UPDATE ON group_push_gossip_state
             BEGIN SELECT RAISE(FAIL, 'injected snapshot failure'); END;",
        )
        .unwrap();
    assert!(
        fx.alice
            .client
            .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
            .await
            .is_err()
    );
    connection
        .execute_batch("DROP TRIGGER fail_invite")
        .unwrap();
    assert_eq!(owed(&fx.alice, &group_hex), Some(0));
    assert_eq!(
        current_epoch(&fx.alice, &group),
        epoch,
        "no Commit was staged"
    );
}

/// A Commit the relay rejects never merges, so it owes no snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_commit_owes_no_snapshot() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    relay.reject_next_publish();
    assert!(
        fx.alice
            .client
            .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
            .await
            .is_err()
    );
    assert_eq!(owed(&fx.alice, &group_hex), None);
    let before = group_message_count(&relay);
    assert!(!fx.alice.client.send_owed_push_snapshots().await);
    assert_eq!(group_message_count(&relay), before);
}

/// A merged member add by this account records the epoch its Commit started
/// from, which a queued invite cannot know in advance; a failed write is
/// retried. Another member's add owes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_member_add_event_owes_a_snapshot() {
    let mut fx = Fixture::new().await;
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    let epoch = current_epoch(&fx.alice, &group);
    let added_by = |actor: &str| cgka_traits::engine::GroupEvent::GroupStateChanged {
        group_id: group.clone(),
        epoch: cgka_traits::EpochId(epoch),
        actor: Some(cgka_traits::MemberId::new(hex::decode(actor).unwrap())),
        change: cgka_traits::engine::GroupStateChange::MemberAdded {
            member: cgka_traits::MemberId::new(hex::decode(&fx.carol.account_id_hex).unwrap()),
        },
        origin_commit_id: None,
    };

    fx.alice
        .client
        .queue_push_registration_shares_for_member_adds(&[added_by(&fx.bob.account_id_hex)]);
    assert_eq!(owed(&fx.alice, &group_hex), None);

    let connection = fx.alice.raw_connection();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_owed BEFORE INSERT ON group_push_gossip_state
             BEGIN SELECT RAISE(FAIL, 'injected snapshot failure'); END;",
        )
        .unwrap();
    fx.alice
        .client
        .observe_event_projection_effects(
            &added_by(&fx.alice.account_id_hex),
            &mut SyncSummary::default(),
        )
        .unwrap();
    assert_eq!(owed(&fx.alice, &group_hex), None);
    connection.execute_batch("DROP TRIGGER fail_owed").unwrap();
    let _ = fx.alice.client.take_queued_push_registration_share();
    fx.alice.client.retry_pending_member_add_push_shares();
    assert_eq!(owed(&fx.alice, &group_hex), Some(epoch - 1));
    assert!(fx.alice.client.take_queued_push_registration_share());
    assert!(fx.alice.client.pending_own_add_push_snapshots.is_empty());
    assert!(fx.alice.client.has_pending_push_registration_work());
}

/// A queued invite owes its snapshot from the invite command on, so the
/// snapshot is sent after a restart even when the device never observed the
/// merge of the Commit that convergence made from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_invite_owes_a_snapshot_across_a_restart() {
    const QUIESCENCE_MS: u64 = 2_000;
    let Fixture {
        _dir,
        relay,
        group,
        mut alice,
        mut bob,
        mut carol,
        ..
    } = Fixture::with_settlement_quiescence_ms(QUIESCENCE_MS).await;
    let group_hex = hex::encode(group.as_slice());
    // Bob's Commit opens a settlement window on Alice, which holds her invite
    // back.
    bob.client
        .runtime
        .send(cgka_traits::SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    alice.receive(&relay).await;
    let epoch = current_epoch(&alice, &group);
    alice
        .client
        .invite_members(&group, &[carol.account_id_hex.as_str()])
        .await
        .unwrap();
    assert!(
        alice
            .client
            .runtime
            .has_queued_outbound_intents(&group)
            .unwrap()
    );
    assert_eq!(owed(&alice, &group_hex), Some(epoch));
    let before = group_message_count(&relay);
    assert!(!alice.client.send_owed_push_snapshots().await);
    assert_eq!(
        group_message_count(&relay),
        before,
        "the add has not merged"
    );
    assert_eq!(owed(&alice, &group_hex), Some(epoch));

    // Convergence commits the queued invite below the app, whose projection
    // never sees the merge.
    tokio::time::sleep(Duration::from_millis(QUIESCENCE_MS + 200)).await;
    alice
        .client
        .runtime
        .advance_convergence(&group)
        .await
        .unwrap();
    assert!(
        !alice
            .client
            .runtime
            .has_queued_outbound_intents(&group)
            .unwrap()
    );
    assert!(current_epoch(&alice, &group) > epoch);
    let app = alice.client.app.clone();
    let (label, account_id_hex, cursor) = (
        alice.label.clone(),
        alice.account_id_hex.clone(),
        alice.cursor,
    );
    drop(alice);

    let mut alice = Device::open(&app, &label, &account_id_hex, cursor).await;
    assert!(
        !alice
            .client
            .retry_pending_push_registration_shares_best_effort()
            .await
    );
    assert_eq!(owed(&alice, &group_hex), None);
    carol.join(&relay, &group).await;
    carol.receive(&relay).await;
    assert!(
        carol.token_leaves(&group).contains(&bob.leaf(&group)),
        "the offline member's record arrived in the snapshot"
    );
    alice.receive(&relay).await;
}

/// A group that is not hydrated yet keeps its owed snapshot, which is sent
/// once the group is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unhydrated_group_keeps_its_owed_snapshot() {
    let Fixture {
        _dir,
        relay,
        group,
        mut alice,
        bob,
        mut carol,
        ..
    } = Fixture::new().await;
    let group_hex = hex::encode(group.as_slice());
    alice
        .client
        .invite_members(&group, &[carol.account_id_hex.as_str()])
        .await
        .unwrap();
    // Leave the snapshot as the only push work.
    alice.client.share_push_registration().await.unwrap();
    let app = alice.client.app.clone();
    let (label, account_id_hex, cursor) = (
        alice.label.clone(),
        alice.account_id_hex.clone(),
        alice.cursor,
    );
    drop(alice);

    let plane = transport_nostr::MarmotRelayPlane::new(None, relay.clone());
    let mut alice = app
        .local_client_with_relay_plane_and_hydration(&label, &plane, None, true, None)
        .await
        .unwrap();
    assert!(alice.runtime.epoch_state(&group).is_none());
    let before = group_message_count(&relay);
    assert!(!alice.send_owed_push_snapshots().await);
    assert!(!alice.has_pending_push_registration_work());
    assert_eq!(group_message_count(&relay), before);
    assert!(
        alice
            .app
            .group_push_snapshot_owed(&label, &group_hex)
            .unwrap()
            .is_some()
    );

    assert!(alice.runtime.ensure_group_hydrated(&group).unwrap());
    assert!(
        alice.has_pending_push_registration_work(),
        "due once hydrated"
    );
    drop(alice);

    let mut alice = Device::open(&app, &label, &account_id_hex, cursor).await;
    assert!(!alice.client.send_owed_push_snapshots().await);
    assert!(group_message_count(&relay) > before);
    assert_eq!(owed(&alice, &group_hex), None);
    carol.join(&relay, &group).await;
    carol.receive(&relay).await;
    assert!(carol.token_leaves(&group).contains(&bob.leaf(&group)));
}

/// A disband that is still in progress can fail and leave the group going, so
/// it holds the owed snapshot back instead of settling it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disband_in_progress_keeps_the_owed_snapshot() {
    let mut fx = Fixture::new().await;
    let relay = fx.relay.clone();
    let group = fx.group.clone();
    let group_hex = fx.group_hex();
    fx.alice
        .client
        .invite_members(&group, &[fx.carol.account_id_hex.as_str()])
        .await
        .unwrap();
    // Leave the snapshot as the only push work.
    fx.alice.client.share_push_registration().await.unwrap();
    fx.alice.client.disband_group(&group).await.unwrap();
    assert!(
        fx.alice
            .client
            .runtime
            .disbanding_in_progress(&group)
            .unwrap()
    );

    let before = group_message_count(&relay);
    assert!(!fx.alice.client.send_owed_push_snapshots().await);
    assert!(!fx.alice.client.has_pending_push_registration_work());
    assert_eq!(group_message_count(&relay), before);
    assert!(owed(&fx.alice, &group_hex).is_some());
}
