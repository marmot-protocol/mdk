//! mdk#3359: hosts hear of a chat only once its record is saved. A host that
//! opens a chat on `GroupJoined` reads its record, so a join whose state save
//! failed must wait for the save that writes it, whichever path produced or
//! publishes it.
use super::*;

const FAIL_JOIN_ROW: &str = "CREATE TRIGGER fail_join_row BEFORE INSERT ON account_groups
     BEGIN SELECT RAISE(ABORT, 'injected join row failure'); END;";
const MEND_JOIN_ROW: &str = "DROP TRIGGER fail_join_row";

fn bob_storage(app: &MarmotApp, sql: &str) {
    app.account_storage("bob")
        .unwrap()
        .app_storage()
        .execute_batch_for_test(sql)
        .unwrap();
}

fn readable(app: &MarmotApp, group: &GroupId) -> bool {
    app.group("bob", &hex::encode(group.as_slice()))
        .unwrap()
        .is_some()
}

/// The chat an event about one of bob's chats names, if it names one.
fn bobs_chat(event: &MarmotAppEvent, bob_id: &str) -> Option<String> {
    match event {
        MarmotAppEvent::GroupJoined {
            account_id_hex,
            group_id,
            ..
        } if account_id_hex == bob_id => Some(hex::encode(group_id.as_slice())),
        MarmotAppEvent::MessageReceived(update) if update.account_id_hex == bob_id => {
            Some(hex::encode(update.message.group_id.as_slice()))
        }
        MarmotAppEvent::ProjectionUpdated(update) if update.account_id_hex == bob_id => {
            Some(update.update.group_id_hex.clone())
        }
        MarmotAppEvent::GroupEvent(update) if update.account_id_hex == bob_id => {
            crate::groups::event_group_id(&update.event)
                .map(|group_id| hex::encode(group_id.as_slice()))
        }
        _ => None,
    }
}

/// What the worker would announce of `summary` now, batch by batch.
fn announced(client: &mut AppClient, summary: &SyncSummary) -> Vec<SyncSummary> {
    client
        .announceable_summaries(summary)
        .into_iter()
        .map(std::borrow::Cow::into_owned)
        .collect()
}

/// Alice invites bob to a new chat, and the relay has delivered it.
async fn invite(
    runtime: &MarmotAppRuntime,
    relay: &ScriptedPushRelayClient,
    bob_id: &str,
    name: &str,
) -> GroupId {
    let group = runtime
        .create_group("alice", name, &[bob_id.to_owned()], None)
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    relay.replies_handled().await;
    group
}

/// Wait for bob's next account error whose message starts with `prefix`,
/// asserting meanwhile that no host hears of `group` and no event is lost.
async fn account_error(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    bob_id: &str,
    group: &GroupId,
    prefix: &str,
) {
    let chat = hex::encode(group.as_slice());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.expect("every event is seen");
            assert_ne!(
                bobs_chat(&event, bob_id).as_ref(),
                Some(&chat),
                "no host hears of a chat before its record is saved: {event:?}"
            );
            if let MarmotAppEvent::AccountError(error) = &event
                && error.account_id_hex == bob_id
                && error.message.starts_with(prefix)
            {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("bob reports {prefix:?}"));
}

/// Assert that no host has heard of `group` yet, after a round trip through
/// bob's worker so everything it sent so far is in.
async fn assert_unheard_of(
    runtime: &MarmotAppRuntime,
    app: &MarmotApp,
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    bob_id: &str,
    group: &GroupId,
    after: &str,
) {
    crate::worker_fences::worker_round_trip(runtime, "bob")
        .await
        .unwrap();
    assert!(!readable(app, group));
    let chat = hex::encode(group.as_slice());
    let mut early = Vec::new();
    loop {
        match events.try_recv() {
            Ok(event) if bobs_chat(&event, bob_id).as_ref() == Some(&chat) => early.push(event),
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(error) => panic!("every event is seen: {error:?}"),
        }
    }
    assert!(
        early.is_empty(),
        "no host hears of a chat before its record is saved, even after {after}: {early:?}"
    );
}

/// While bob's saves fail, his worker joins a chat on a live receive, then
/// retries the save on its schedule, runs a catch-up and a full-history
/// repair, each failing to save and each publishing what it holds. No host
/// hears of the chat until the save that writes its record; then the join
/// goes out, readable.
#[test]
fn hosts_hear_of_a_joined_chat_only_once_its_record_is_saved() {
    run_composed_app_runtime_test("announce-after-save", || async {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let bob_id = home.create_account("bob").unwrap().account_id_hex;
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        remember_test_member_inbox(&app, &bob_id, "wss://relay.example");
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime.catch_up_accounts().await.unwrap();
        let mut events = runtime.subscribe();
        bob_storage(&app, FAIL_JOIN_ROW);

        let group = invite(&runtime, &relay, &bob_id, "joined while saves fail").await;
        account_error(&mut events, &bob_id, &group, "runtime receive failed").await;

        // The worker's scheduled retry projects again, then fails to save.
        let retry_failed = "runtime group subscription refresh failed";
        account_error(&mut events, &bob_id, &group, retry_failed).await;
        let after = "the scheduled retry";
        assert_unheard_of(&runtime, &app, &mut events, &bob_id, &group, after).await;

        // A catch-up refreshes the chat's subscriptions first, which saves.
        assert!(runtime.catch_up_accounts().await.is_err());
        assert_unheard_of(&runtime, &app, &mut events, &bob_id, &group, "a catch-up").await;

        // A full-history repair ends in failure.
        assert!(runtime.repair_full_history("bob").await.is_err());
        let after = "a full-history repair";
        assert_unheard_of(&runtime, &app, &mut events, &bob_id, &group, after).await;

        // Once saves work, the worker's next retry writes the record, and the
        // join goes out.
        bob_storage(&app, MEND_JOIN_ROW);
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let MarmotAppEvent::GroupJoined {
                    account_id_hex,
                    group_id,
                    ..
                } = events.recv().await.expect("the runtime keeps running")
                    && account_id_hex == bob_id
                    && group_id == group
                {
                    return;
                }
            }
        })
        .await
        .expect("the join goes out once its record is saved");
        assert!(readable(&app, &group), "the joined chat is readable");
        runtime.shutdown().await;
    });
}

/// A catch-up cancelled partway, as the KeyPackage catch-up's timeout cancels
/// one, loses nothing kept back for a chat whose save failed, and what is
/// kept back goes out after the save as it was, ahead of later output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_catch_up_keeps_a_join_kept_back_for_its_save() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_id = home.create_account("bob").unwrap().account_id_hex;
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &bob_id, "wss://relay.example");
    let plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let mut alice = app
        .client_with_relay_plane("alice", &plane, None)
        .await
        .unwrap();
    let mut bob = app
        .client_with_relay_plane("bob", &plane, None)
        .await
        .unwrap();
    bob.sync().await.unwrap();
    relay.replies_handled().await;
    while bob.admit_native_turn(None).await.unwrap() {}
    bob.take_pending_applied_sync_summary();

    bob_storage(&app, FAIL_JOIN_ROW);
    let group = alice
        .create_group("kept back", &[bob_id.as_str()])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    relay.replies_handled().await;
    let received = tokio::time::timeout(Duration::from_secs(5), bob.receive_next_delivery())
        .await
        .expect("the Welcome arrives")
        .unwrap();
    let transport_nostr::AccountDeliveryReceive::Delivery(welcome) = received else {
        panic!("no delivery loss here");
    };
    assert!(
        bob.ingest_received_delivery(*welcome).await.is_err(),
        "the Welcome's state save fails"
    );
    // The worker arms the save's retry and announces the buffer; the join
    // is kept back.
    assert!(bob.arm_failed_receive_projection_retry());
    let pending = bob.take_pending_applied_sync_summary();
    assert_eq!(pending.joined_groups, vec![group.clone()]);
    assert!(announced(&mut bob, &pending).is_empty());

    // Saves work again. A catch-up starts, waits on the relay and is
    // dropped there.
    bob_storage(&app, MEND_JOIN_ROW);
    {
        let catch_up = bob.sync_automatically_with_partial_progress();
        assert!(
            futures::FutureExt::now_or_never(catch_up).is_none(),
            "the catch-up waits on the relay"
        );
    }
    bob.retry_pending_runtime_group_subscription_refresh()
        .await
        .unwrap();
    assert!(readable(&app, &group));
    // Later output goes out after it, as a batch of its own.
    let mut later = bob.take_pending_applied_sync_summary();
    later.projection_updates.push(AppProjectionUpdate {
        group_id_hex: hex::encode(group.as_slice()),
        timeline_messages: Vec::new(),
        timeline_changes: Vec::new(),
        chat_list_row: None,
        chat_list_trigger: ChatListUpdateTrigger::NewLastMessage,
    });
    let batches = announced(&mut bob, &later);
    assert_eq!(
        batches.len(),
        2,
        "the kept-back output goes out after the save that writes its record"
    );
    assert_eq!(batches[0].joined_groups, vec![group]);
    assert!(batches[0].projection_updates.is_empty());
    assert_eq!(batches[1].projection_updates, later.projection_updates);
}
