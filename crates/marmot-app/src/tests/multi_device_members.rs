//! Projections group members by account when one account holds several
//! leaves (mdk#2628, item 1.1). The invite path picks one KeyPackage per
//! account, so these tests add a second device through the engine's Invite
//! intent, as an ordinary admin Commit.

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::*;
use cgka_traits::app_event::{
    GROUP_SYSTEM_TYPE_MEMBER_ADDED, GROUP_SYSTEM_TYPE_MEMBER_LEFT, GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
};
use cgka_traits::engine::SendIntent;

/// Import `label`'s key into a fresh home: the account's second device.
fn second_device(home: &AccountHome, label: &str, dir: &tempfile::TempDir) {
    let secret = home
        .load_signing_keys(label)
        .unwrap()
        .secret_key()
        .to_secret_hex();
    AccountHome::open(dir.path())
        .import_account(label, &secret)
        .unwrap();
}

/// Add `key_package` to `group` in one admin Commit and project its effects.
async fn add_device(admin: &mut AppClient, group: &GroupId, key_package: cgka_traits::KeyPackage) {
    let effects = admin
        .runtime
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![key_package],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    admin
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
}

/// `(member, device_count)` rows from the member list, roster and conversation
/// snapshot, checked to agree; ids and counts from the id page and MLS state
/// must describe the same accounts.
fn member_view(client: &AppClient, group: &GroupId) -> Vec<(String, u32)> {
    let members: Vec<_> = client
        .members(group)
        .unwrap()
        .into_iter()
        .map(|member| (member.member_id_hex, member.device_count))
        .collect();
    let my_id = client
        .app
        .account_home()
        .account(&client.state.label)
        .unwrap()
        .account_id_hex;
    let roster = crate::groups::app_group_roster_from_session(
        client.group_roster_session(group).unwrap(),
        &my_id,
        std::collections::HashMap::new(),
    );
    assert_eq!(
        roster
            .members
            .iter()
            .map(|member| (member.member_id_hex.clone(), member.device_count))
            .collect::<Vec<_>>(),
        members
    );
    assert_eq!(roster.member_count, members.len());
    assert_eq!(
        client.group_mls_state(group).unwrap().member_count,
        members.len()
    );
    let ids = client.member_ids_page(std::slice::from_ref(group)).unwrap();
    assert_eq!(
        ids[0].member_ids_hex,
        members.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>()
    );
    let mut sorted = members;
    sorted.sort();
    sorted
}

fn sorted(mut rows: Vec<(String, u32)>) -> Vec<(String, u32)> {
    rows.sort();
    rows
}

fn stored_member_count(app: &MarmotApp, label: &str, group: &GroupId) -> Option<u64> {
    app.group(label, &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .member_count
}

/// Membership rows as `(type, subject)`, oldest first.
fn membership_rows(app: &MarmotApp, label: &str, group: &GroupId) -> Vec<(String, String)> {
    app.timeline_messages_with_query(
        label,
        storage_sqlite::TimelineMessageQuery {
            group_id_hex: Some(hex::encode(group.as_slice())),
            ..storage_sqlite::TimelineMessageQuery::default()
        },
    )
    .unwrap()
    .messages
    .into_iter()
    .filter_map(|row| row.group_system)
    .filter(|row| {
        [
            GROUP_SYSTEM_TYPE_MEMBER_ADDED,
            GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
            GROUP_SYSTEM_TYPE_MEMBER_LEFT,
        ]
        .contains(&row.system_type.as_str())
    })
    .map(|row| {
        (
            row.system_type,
            row.subject_account_id_hex.unwrap_or_default(),
        )
    })
    .collect()
}

/// The selected chat presentation's peer, and whether its title and avatar
/// come from that peer rather than from a group fallback.
fn presentation_peer(app: &MarmotApp, label: &str, group: &GroupId) -> Option<String> {
    let local = app.account_home().account(label).unwrap().account_id_hex;
    let input = app
        .account_storage(label)
        .unwrap()
        .app_storage()
        .chat_presentation_input(&hex::encode(group.as_slice()))
        .unwrap()
        .unwrap();
    let selected = crate::chat_presentation::select_chat_presentation(&input, &local, None);
    if let Some(peer) = &selected.peer_id {
        assert_eq!(
            selected.title_source,
            storage_sqlite::PresentationSource::PeerFallback
        );
        assert!(
            selected.title
                == storage_sqlite::PresentationText::Literal(crate::default_profile_pseudonym(
                    peer
                ))
        );
        assert_eq!(
            selected.avatar_source,
            storage_sqlite::PresentationSource::PeerFallback
        );
    }
    selected.peer_id
}

/// How long `admin` waits before committing a retained SelfRemove.
fn self_remove_delay_ms(admin: &mut AppClient, group: &GroupId) -> u64 {
    admin
        .runtime
        .scheduled_self_remove_auto_commit_delay_ms(group)
        .unwrap()
        .unwrap()
}

fn conversation_kind(app: &MarmotApp, label: &str, group: &GroupId) -> crate::ChatConversationKind {
    app.chat_list_row(label, &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .conversation_kind
}

/// A 1:1 chat stays a 1:1 when the other person has two devices in it, and
/// when this account does: on the adder, and on both of the other account's
/// devices. Its title and avatar come from the other account, and the second
/// device's arrival makes no join notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_chat_with_a_two_device_account_stays_direct() {
    let dir = tempfile::tempdir().unwrap();
    let bob_second_dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_id = home.create_account("alice").unwrap().account_id_hex;
    let bob_id = home.create_account("bob").unwrap().account_id_hex;
    second_device(&home, "bob", &bob_second_dir);
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_at(&dir, relay.clone());
    let bob_second_app = app_at(&bob_second_dir, relay.clone());
    remember_test_member_inbox(&app, &bob_id, "wss://relay.example");
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    bob.sync().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let mut bob_cursor = 0;
    let group = alice.create_group("", &[&bob_id]).await.unwrap();
    deliver_new(&mut bob, &relay, &mut bob_cursor).await;
    bob.sync().await.unwrap();
    bob.accept_group_invite(&group).unwrap();

    let one_device = sorted(vec![(alice_id.clone(), 1), (bob_id.clone(), 1)]);
    assert_eq!(member_view(&alice, &group), one_device);
    assert_eq!(
        conversation_kind(&app, "alice", &group),
        crate::ChatConversationKind::Direct
    );
    let alice_rows = membership_rows(&app, "alice", &group);

    let mut bob_second = bob_second_app.client("bob").await.unwrap();
    bob_second.sync().await.unwrap();
    let mut bob_second_cursor = relay.published_events.lock().unwrap().len();
    let key_package = published_key_package(&mut bob_second, &relay).await;
    add_device(&mut alice, &group, key_package).await;
    deliver_new(&mut bob_second, &relay, &mut bob_second_cursor).await;
    bob_second.sync().await.unwrap();
    bob_second.accept_group_invite(&group).unwrap();
    deliver_new(&mut bob, &relay, &mut bob_cursor).await;
    bob.sync().await.unwrap();
    let bob_rows = membership_rows(&app, "bob", &group);

    let two_devices = sorted(vec![(alice_id.clone(), 1), (bob_id.clone(), 2)]);
    for (app, client, peer) in [
        (&app, &alice, &bob_id),
        (&app, &bob, &alice_id),
        (&bob_second_app, &bob_second, &alice_id),
    ] {
        let label = client.state.label.clone();
        assert_eq!(member_view(client, &group), two_devices, "{label}");
        assert_eq!(stored_member_count(app, &label, &group), Some(2), "{label}");
        assert_eq!(
            conversation_kind(app, &label, &group),
            crate::ChatConversationKind::Direct,
            "{label}"
        );
        assert_eq!(
            presentation_peer(app, &label, &group).as_ref(),
            Some(peer),
            "{label}"
        );
    }
    assert_eq!(
        membership_rows(&app, "alice", &group),
        alice_rows,
        "a second device of a present account is not a join"
    );
    assert_eq!(membership_rows(&app, "bob", &group), bob_rows);
    let reusable = app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .direct_conversation_candidate_rows(&bob_id)
        .unwrap();
    assert_eq!(reusable.len(), 1, "the chat stays the direct chat with bob");
}

/// In a group of three, a second device of one account joining and then
/// leaving changes no one's member list beyond its device count, and makes no
/// membership notice; the account's last device leaving does. Checked on the
/// adder, on another member and on the two-device account's remaining device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_device_joins_and_leaves_without_membership_notices() {
    let dir = tempfile::tempdir().unwrap();
    let bob_second_dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_id = home.create_account("alice").unwrap().account_id_hex;
    let bob_id = home.create_account("bob").unwrap().account_id_hex;
    let carol_id = home.create_account("carol").unwrap().account_id_hex;
    second_device(&home, "bob", &bob_second_dir);
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_at(&dir, relay.clone());
    let bob_second_app = app_at(&bob_second_dir, relay.clone());
    remember_test_member_inbox(&app, &bob_id, "wss://relay.example");
    remember_test_member_inbox(&app, &carol_id, "wss://relay.example");
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    bob.sync().await.unwrap();
    let mut carol = app.client("carol").await.unwrap();
    carol.publish_key_package().await.unwrap();
    carol.sync().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let (mut alice_cursor, mut bob_cursor, mut carol_cursor) = (0, 0, 0);
    let group = alice
        .create_group("team", &[&bob_id, &carol_id])
        .await
        .unwrap();
    deliver_new(&mut bob, &relay, &mut bob_cursor).await;
    bob.sync().await.unwrap();
    bob.accept_group_invite(&group).unwrap();
    deliver_new(&mut carol, &relay, &mut carol_cursor).await;
    carol.sync().await.unwrap();
    carol.accept_group_invite(&group).unwrap();
    let rows_before: Vec<_> = ["alice", "bob", "carol"]
        .into_iter()
        .map(|label| membership_rows(&app, label, &group))
        .collect();

    // Alice adds bob's second device.
    let mut bob_second = bob_second_app.client("bob").await.unwrap();
    bob_second.sync().await.unwrap();
    let mut bob_second_cursor = relay.published_events.lock().unwrap().len();
    let key_package = published_key_package(&mut bob_second, &relay).await;
    add_device(&mut alice, &group, key_package).await;
    deliver_new(&mut bob_second, &relay, &mut bob_second_cursor).await;
    bob_second.sync().await.unwrap();
    bob_second.accept_group_invite(&group).unwrap();
    for client in [&mut bob, &mut carol] {
        let cursor = if client.state.label == "bob" {
            &mut bob_cursor
        } else {
            &mut carol_cursor
        };
        deliver_new(client, &relay, cursor).await;
        client.sync().await.unwrap();
    }
    let with_second_device = sorted(vec![
        (alice_id.clone(), 1),
        (bob_id.clone(), 2),
        (carol_id.clone(), 1),
    ]);
    for client in [&alice, &bob, &carol, &bob_second] {
        assert_eq!(
            member_view(client, &group),
            with_second_device,
            "{}",
            client.state.label
        );
    }
    for label in ["alice", "bob", "carol"] {
        assert_eq!(stored_member_count(&app, label, &group), Some(3), "{label}");
        assert_eq!(
            conversation_kind(&app, label, &group),
            crate::ChatConversationKind::Group
        );
        assert_eq!(presentation_peer(&app, label, &group), None);
    }
    let rows_after_add: Vec<_> = ["alice", "bob", "carol"]
        .into_iter()
        .map(|label| membership_rows(&app, label, &group))
        .collect();
    assert_eq!(rows_after_add, rows_before, "a second device is not a join");

    // Bob's second device leaves; alice commits its SelfRemove.
    bob_second.leave_group(&group).await.unwrap();
    deliver_new(&mut alice, &relay, &mut alice_cursor).await;
    alice.sync().await.unwrap();
    tokio::time::sleep(Duration::from_millis(
        self_remove_delay_ms(&mut alice, &group) + 1,
    ))
    .await;
    alice.retry_group_convergence(&group).await.unwrap();
    for client in [&mut bob, &mut carol] {
        let cursor = if client.state.label == "bob" {
            &mut bob_cursor
        } else {
            &mut carol_cursor
        };
        deliver_new(client, &relay, cursor).await;
        client.sync().await.unwrap();
    }
    let one_device_each = sorted(vec![
        (alice_id.clone(), 1),
        (bob_id.clone(), 1),
        (carol_id.clone(), 1),
    ]);
    for client in [&alice, &bob, &carol] {
        assert_eq!(
            member_view(client, &group),
            one_device_each,
            "{}",
            client.state.label
        );
    }
    let rows_after_device_left: Vec<_> = ["alice", "bob", "carol"]
        .into_iter()
        .map(|label| membership_rows(&app, label, &group))
        .collect();
    assert_eq!(
        rows_after_device_left, rows_before,
        "one of two devices leaving is not a departure"
    );

    // Bob's last device leaves: now bob has left.
    bob.leave_group(&group).await.unwrap();
    deliver_new(&mut alice, &relay, &mut alice_cursor).await;
    alice.sync().await.unwrap();
    tokio::time::sleep(Duration::from_millis(
        self_remove_delay_ms(&mut alice, &group) + 1,
    ))
    .await;
    alice.retry_group_convergence(&group).await.unwrap();
    deliver_new(&mut carol, &relay, &mut carol_cursor).await;
    carol.sync().await.unwrap();
    let without_bob = sorted(vec![(alice_id.clone(), 1), (carol_id.clone(), 1)]);
    for (index, client) in [(0, &alice), (2, &carol)] {
        let label = &client.state.label;
        assert_eq!(member_view(client, &group), without_bob, "{label}");
        assert_eq!(stored_member_count(&app, label, &group), Some(2), "{label}");
        let mut expected = rows_before[index].clone();
        expected.push((GROUP_SYSTEM_TYPE_MEMBER_LEFT.to_owned(), bob_id.clone()));
        assert_eq!(
            membership_rows(&app, label, &group),
            expected,
            "the last device leaving is bob's departure on {label}"
        );
    }
}
