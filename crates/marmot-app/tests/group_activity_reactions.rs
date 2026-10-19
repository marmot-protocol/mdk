//! Two-account reaction targets produced by actual MLS group changes.
#![cfg(feature = "test-policy-overrides")]

use std::time::Duration;

use marmot_account::AccountHome;
use marmot_app::{
    MarmotApp, MarmotAppConfig, MarmotAppEvent, RuntimeTimelineMessagesSubscription,
    TimelineMessageQuery, TimelinePage,
};
use nostr_relay_builder::MockRelay;

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
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
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
        .unwrap();
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

/// The `(sender, emoji)` reactions on the timeline's one row.
fn reactions(page: &TimelinePage) -> Vec<(&str, &str)> {
    page.messages[0]
        .reactions
        .user_reactions
        .iter()
        .map(|reaction| (reaction.sender.as_str(), reaction.emoji.as_str()))
        .collect()
}

/// Wait until the live timeline shows exactly `expected`. A timeline also
/// receives its own account's reactions, so a looser check such as "any
/// reaction" can pass on an update left over from an earlier step.
async fn wait_for_reactions(
    timeline: &mut RuntimeTimelineMessagesSubscription,
    expected: &[(&str, &str)],
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while reactions(&timeline.take_snapshot()) != expected {
            timeline.recv().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeline never showed reactions {expected:?}"));
}
