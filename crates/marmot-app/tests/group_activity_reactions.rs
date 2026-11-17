//! Two-account reaction targets produced by actual MLS group changes.
#![cfg(feature = "test-policy-overrides")]

use std::time::Duration;

use marmot_account::AccountHome;
use marmot_app::{
    AppError, AppMessageQuery, MarmotApp, MarmotAppConfig, MarmotAppEvent,
    RuntimeTimelineMessagesSubscription, TimelineMessageQuery, TimelinePage,
};
use nostr_relay_builder::prelude::{MemoryDatabase, MemoryDatabaseOptions, RelayBuilder};

#[path = "support/limited_relay.rs"]
mod limited_relay;

/// Open an isolated account home against the fixture relay without development settlement delays.
fn open(dir: &tempfile::TempDir, relay: &str) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        relay.to_owned(),
        MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
}

/// Prove member-visible add/retract updates and target stability across independent encrypted-store reopens,
/// and that a reaction a live timeline showed survives a close made right after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn members_share_real_activity_targets_and_reactions_after_reopen() {
    storage_sqlite::relax_storage_for_test_process();
    // A relay that publishes its cap, as White Noise's do, so a reopened
    // member's catch-up is proven rather than held for an unreadable document.
    let (_relay, url) = limited_relay::mock_relay().await;
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let alice_id = AccountHome::open(alice_dir.path())
        .create_account("alice")
        .unwrap()
        .account_id_hex;
    let bob_id = AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap()
        .account_id_hex;
    let alice_app = open(&alice_dir, &url);
    let bob_app = open(&bob_dir, &url);
    bob_app
        .client("bob")
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap();
    let bob = bob_app.runtime();
    let mut events = bob.subscribe();
    bob.start().await.unwrap();
    let mut alice_client = alice_app.client("alice").await.unwrap();
    let group = alice_client
        .create_group("original", &[&bob_id])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if matches!(events.recv().await.unwrap(), MarmotAppEvent::GroupJoined { group_id, .. } if group_id == group) {
                break;
            }
        }
    }).await.unwrap();
    bob.accept_group_invite("bob", &group).await.unwrap();
    let query = TimelineMessageQuery {
        group_id_hex: Some(hex::encode(group.as_slice())),
        ..Default::default()
    };
    let mut bob_timeline = bob
        .subscribe_timeline_messages("bob", query.clone())
        .await
        .unwrap();
    alice_client
        .update_group_profile(&group, Some("renamed"), None)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while bob_timeline.take_snapshot().messages.is_empty() {
            bob_timeline.recv().await.unwrap();
        }
    })
    .await
    .unwrap();
    let alice_rows = alice_app
        .timeline_messages_with_query("alice", query.clone())
        .unwrap()
        .messages;
    let bob_rows = bob_timeline.take_snapshot().messages;
    assert_eq!(alice_rows.len(), 1);
    assert_eq!(bob_rows.len(), 1);
    assert_eq!(
        alice_rows[0].message_id_hex, bob_rows[0].message_id_hex,
        "the same authenticated rename must have the same reaction target on both accounts"
    );
    assert_eq!(bob_rows[0].sender, alice_id);
    let activity = bob_rows[0].group_system.as_ref().unwrap();
    assert_eq!(
        activity.provenance,
        marmot_app::GroupSystemEventProvenance::AuthenticatedGroupState
    );
    assert_eq!(
        activity.actor_account_id_hex.as_deref(),
        Some(alice_id.as_str())
    );
    let target = alice_rows[0].message_id_hex.clone();
    drop(alice_client);
    let alice = alice_app.runtime();
    alice.start().await.unwrap();
    let mut alice_timeline = alice
        .subscribe_timeline_messages("alice", query.clone())
        .await
        .unwrap();
    for (runtime, label, reactor, other) in [
        (&alice, "alice", &alice_id, &mut bob_timeline),
        (&bob, "bob", &bob_id, &mut alice_timeline),
    ] {
        runtime
            .react_to_message(label, &group, &target, "👍")
            .await
            .unwrap();
        wait_for_reactions(other, &[(reactor, "👍")]).await;
        runtime
            .unreact_from_message(label, &group, &target)
            .await
            .unwrap();
        wait_for_reactions(other, &[]).await;
    }
    // Keep a member-authored reaction live across both encrypted-store reopens.
    bob.react_to_message("bob", &group, &target, "❤️")
        .await
        .unwrap();
    let heart = [(bob_id.as_str(), "❤️")];
    wait_for_reactions(&mut alice_timeline, &heart).await;
    // Close the moment Alice's timeline shows the reaction. A live update is
    // published only after the ingest that produced it commits (mdk#2345).
    alice.shutdown_and_close().await.unwrap();
    bob.shutdown_and_close().await.unwrap();
    for (dir, label, source) in [
        (&alice_dir, "alice", "Alice's live timeline showed"),
        (&bob_dir, "bob", "Bob's completed send recorded"),
    ] {
        let app = open(dir, &url);
        // Read before any runtime starts, so no catch-up can restore it.
        let stored = app
            .timeline_messages_with_query(label, query.clone())
            .unwrap();
        assert_eq!(stored.messages.len(), 1);
        assert_eq!(stored.messages[0].message_id_hex, target);
        assert_eq!(
            reactions(&stored),
            heart,
            "{label}'s store must keep the reaction {source}"
        );
        let runtime = app.runtime();
        runtime.start().await.unwrap();
        let snapshot = runtime
            .subscribe_timeline_messages(label, query.clone())
            .await
            .unwrap()
            .take_snapshot();
        assert_eq!(snapshot.messages.len(), 1);
        assert_eq!(snapshot.messages[0].message_id_hex, target);
        assert_eq!(reactions(&snapshot), heart);
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_reactions_after_reopen() {
    storage_sqlite::relax_storage_for_test_process();
    let (_relay, url) = limited_relay::relay_publishing_with(
        RelayBuilder::default().database(MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(256),
        })),
        Some(500),
    )
    .await;
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let sibling_dir = tempfile::tempdir().unwrap();
    let alice_id = AccountHome::open(alice_dir.path())
        .create_account("alice")
        .unwrap()
        .account_id_hex;
    let bob_home = AccountHome::open(bob_dir.path());
    let bob_id = bob_home.create_account("bob").unwrap().account_id_hex;
    AccountHome::open(sibling_dir.path())
        .import_account("bob", &bob_home.reveal_nsec("bob").unwrap())
        .unwrap();
    let alice_app = open(&alice_dir, &url);
    let bob_app = open(&bob_dir, &url);
    let sibling_app = open(&sibling_dir, &url);
    let mut alice_client = alice_app.client("alice").await.unwrap();
    let mut bob_client = bob_app.client("bob").await.unwrap();
    let mut sibling_client = sibling_app.client("bob").await.unwrap();
    bob_client.publish_key_package().await.unwrap();
    sibling_client.publish_key_package().await.unwrap();
    let group = alice_client
        .create_group("scoped reactions", &[&bob_id])
        .await
        .unwrap()
        .operation
        .expect("both account devices have published KeyPackages");
    for client in [&mut bob_client, &mut sibling_client] {
        client.sync().await.unwrap();
        client.accept_group_invite(&group).unwrap();
    }
    let target = alice_client
        .send(&group, b"target")
        .await
        .unwrap()
        .message_ids[0]
        .clone();
    for client in [&mut bob_client, &mut sibling_client] {
        client.sync().await.unwrap();
    }
    // Directly owned clients project incoming events only when driven. Both
    // devices therefore add from a local view that has no account reaction.
    let first = bob_client
        .react_to_message(&group, &target, "👍")
        .await
        .unwrap();
    // Inner event ids include the account, content and authored second. Wait
    // for a different second so independent device sends cannot hash alike.
    let authored = nostr_sdk::prelude::Timestamp::now();
    let mut clock = tokio::time::interval(Duration::from_millis(10));
    while nostr_sdk::prelude::Timestamp::now() == authored {
        clock.tick().await;
    }
    let second = sibling_client
        .react_to_message(&group, &target, "👍")
        .await
        .unwrap();
    assert_ne!(first.message_ids, second.message_ids);
    alice_client
        .react_to_message(&group, &target, "👍")
        .await
        .unwrap();
    bob_client
        .react_to_message(&group, &target, "❤️")
        .await
        .unwrap();
    for client in [&mut alice_client, &mut bob_client, &mut sibling_client] {
        client.sync().await.unwrap();
    }
    drop((alice_client, bob_client, sibling_client));
    let alice = alice_app.runtime();
    let bob = bob_app.runtime();
    let sibling = sibling_app.runtime();
    for runtime in [&alice, &bob, &sibling] {
        runtime.start().await.unwrap();
    }
    let group_hex = hex::encode(group.as_slice());
    let query = TimelineMessageQuery {
        group_id_hex: Some(group_hex.clone()),
        ..Default::default()
    };
    let mut timelines = Vec::new();
    for (runtime, label) in [(&alice, "alice"), (&bob, "bob"), (&sibling, "bob")] {
        timelines.push(
            runtime
                .subscribe_timeline_messages(label, query.clone())
                .await
                .unwrap(),
        );
    }
    let initial = [
        (alice_id.as_str(), "👍"),
        (bob_id.as_str(), "👍"),
        (bob_id.as_str(), "👍"),
        (bob_id.as_str(), "❤️"),
    ];
    for timeline in &mut timelines {
        wait_for_reactions(timeline, &initial).await;
    }
    let removed = bob
        .unreact_from_message_matching("bob", &group, &target, Some("👍"))
        .await
        .unwrap();
    assert_eq!(removed.message_ids.len(), 1);
    let deletion = bob_app
        .message_by_id("bob", &group_hex, &removed.message_ids[0])
        .unwrap()
        .unwrap();
    assert_eq!(deletion.kind, 5);
    let mut deleted: Vec<_> = deletion
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "e"))
        .map(|tag| tag[1].clone())
        .collect();
    deleted.sort();
    let mut expected_ids = vec![first.message_ids[0].clone(), second.message_ids[0].clone()];
    expected_ids.sort();
    assert_eq!(deleted, expected_ids);
    let remaining = [(alice_id.as_str(), "👍"), (bob_id.as_str(), "❤️")];
    for timeline in &mut timelines {
        wait_for_reactions(timeline, &remaining).await;
    }
    assert!(matches!(
        bob.unreact_from_message_matching("bob", &group, &target, Some("👍"))
            .await,
        Err(AppError::ReactionNotFound)
    ));

    bob.react_to_message("bob", &group, &target, "👍")
        .await
        .unwrap();
    let before_offline = [
        (alice_id.as_str(), "👍"),
        (bob_id.as_str(), "❤️"),
        (bob_id.as_str(), "👍"),
    ];
    for timeline in &mut timelines {
        wait_for_reactions(timeline, &before_offline).await;
    }
    let saved_host_page = timelines[1].take_snapshot();
    bob.shutdown_and_close().await.unwrap();
    sibling
        .unreact_from_message_matching("bob", &group, &target, Some("👍"))
        .await
        .unwrap();
    let added = sibling
        .react_to_message("bob", &group, &target, "🔥")
        .await
        .unwrap();
    let after_offline = [
        (alice_id.as_str(), "👍"),
        (bob_id.as_str(), "❤️"),
        (bob_id.as_str(), "🔥"),
    ];
    wait_for_reactions(&mut timelines[0], &after_offline).await;
    wait_for_reactions(&mut timelines[2], &after_offline).await;

    let reopened_app = open(&bob_dir, &url);
    let stored = reopened_app
        .timeline_messages_with_query("bob", query.clone())
        .unwrap();
    assert_eq!(reactions(&stored), reactions(&saved_host_page));
    assert!(reactions(&saved_host_page).contains(&(bob_id.as_str(), "👍")));
    let reopened = reopened_app.runtime();
    reopened.start().await.unwrap();
    let mut refreshed = reopened
        .subscribe_timeline_messages("bob", query)
        .await
        .unwrap();
    wait_for_reactions(&mut refreshed, &after_offline).await;
    let events = || {
        reopened_app
            .messages_with_query(
                "bob",
                AppMessageQuery {
                    group_id_hex: Some(group_hex.clone()),
                    kinds: Some(vec![5, 7]),
                    limit: None,
                },
            )
            .unwrap()
    };
    let before_retry = events();
    for _ in 0..2 {
        assert!(matches!(
            reopened
                .unreact_from_message_matching("bob", &group, &target, Some("👍"))
                .await,
            Err(AppError::ReactionNotFound)
        ));
        let retried = reopened
            .react_to_message("bob", &group, &target, "🔥")
            .await
            .unwrap();
        assert_eq!(retried.published, 0);
        assert_eq!(retried.message_ids, added.message_ids);
    }
    assert_eq!(
        events(),
        before_retry,
        "retries create neither reactions nor deletions"
    );
    wait_for_reactions(&mut refreshed, &after_offline).await;
    for runtime in [&alice, &sibling, &reopened] {
        runtime.shutdown_and_close().await.unwrap();
    }
}

/// The `(sender, emoji)` reactions on the timeline's one row.
fn reactions(page: &TimelinePage) -> Vec<(&str, &str)> {
    let mut reactions: Vec<_> = page.messages[0]
        .reactions
        .user_reactions
        .iter()
        .map(|reaction| (reaction.sender.as_str(), reaction.emoji.as_str()))
        .collect();
    reactions.sort_unstable();
    reactions
}

/// Wait until the live timeline shows exactly `expected`. A timeline also
/// receives its own account's reactions, so a looser check such as "any
/// reaction" can pass on an update left over from an earlier step.
async fn wait_for_reactions(
    timeline: &mut RuntimeTimelineMessagesSubscription,
    expected: &[(&str, &str)],
) {
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    tokio::time::timeout(Duration::from_secs(15), async {
        while reactions(&timeline.take_snapshot()) != expected {
            timeline.recv().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeline never showed reactions {expected:?}"));
}
