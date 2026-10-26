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

/// The owed snapshot and the Welcome intents are recorded together before the
/// Commit is exposed: when either write fails, the other is undone and the
/// Commit rolls back.
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

    for trigger in [
        "CREATE TRIGGER fail_invite BEFORE INSERT ON app_pending_welcome_delivery
         BEGIN SELECT RAISE(FAIL, 'injected welcome intent failure'); END;",
        "CREATE TRIGGER fail_invite BEFORE UPDATE ON group_push_gossip_state
         BEGIN SELECT RAISE(FAIL, 'injected snapshot failure'); END;",
    ] {
        connection.execute_batch(trigger).unwrap();
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
            "the Commit rolled back"
        );
    }
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

/// A merged member add by this account owes a snapshot even without an invite
/// command, as when convergence commits a queued invite; a failed write is
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
