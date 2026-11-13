//! Signing out on a single device from a chat its account and bob both
//! administer: it sends `StepDownAndLeave`, the engine steps it down and
//! then leaves, and the sign-out counts the chat as left only once it sees
//! the commit that removes it (mdk#2818). Device groups are off here; the
//! step-down happens anyway, since the device wipes once its sign-out ends.

use super::*;

const RELAY: &str = "wss://relay.example";

/// alice signs out through a managed runtime; bob is a separate app the
/// test drives by hand. Separate apps share no live relay, so the test
/// routes bob's traffic in.
struct AdminSignOut {
    relay: Arc<ScriptedPushRelayClient>,
    alice_app: MarmotApp,
    runtime: MarmotAppRuntime,
    bob: AppClient,
    bob_cursor: usize,
    alice_cursor: usize,
    alice_id: String,
    chat: GroupId,
    _dirs: [tempfile::TempDir; 2],
}

impl AdminSignOut {
    async fn new() -> Self {
        let relay = Arc::new(ScriptedPushRelayClient::default());
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
        let alice_app = app_at(&alice_dir, relay.clone());
        let bob_app = app_at(&bob_dir, relay.clone());
        remember_test_member_inbox(&alice_app, &bob_id, RELAY);
        let mut bob = bob_app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        let mut alice = alice_app.client("alice").await.unwrap();
        let chat = alice
            .create_group_with_options(
                "co-admin chat",
                &[&bob_id],
                crate::AppCreateGroupOptions {
                    initial_admins: vec![bob_id.clone()],
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let mut bob_cursor = 0;
        deliver_new(&mut bob, &relay, &mut bob_cursor).await;
        bob.accept_group_invite(&chat).unwrap();
        drop(alice);
        let runtime = MarmotAppRuntime::new(alice_app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime.catch_up_accounts().await.unwrap();
        let alice_cursor = relay.published_events.lock().unwrap().len();
        Self {
            relay,
            alice_app,
            runtime,
            bob,
            bob_cursor,
            alice_cursor,
            alice_id,
            chat,
            _dirs: [alice_dir, bob_dir],
        }
    }

    fn published(&self) -> usize {
        self.relay.published_events.lock().unwrap().len()
    }

    fn bob_sees_alice(&self) -> bool {
        self.bob
            .runtime
            .members(&self.chat)
            .unwrap()
            .iter()
            .any(|member| hex::encode(member.id.as_slice()) == self.alice_id)
    }

    /// bob receives what was published, commits a SelfRemove once its
    /// auto-commit delay has passed, and his traffic reaches alice.
    async fn bob_turn(&mut self) {
        deliver_new(&mut self.bob, &self.relay, &mut self.bob_cursor).await;
        if let Some(delay) = self
            .bob
            .runtime
            .scheduled_self_remove_auto_commit_delay_ms(&self.chat)
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(delay + 1)).await;
        }
        let effects = self
            .bob
            .runtime
            .advance_convergence(&self.chat)
            .await
            .unwrap();
        self.bob
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        self.bob.run_due_maintenance().await.unwrap();
        self.route_to_alice().await;
    }

    /// Route the group messages published since the last call into alice's
    /// relay plane. Her own echoes are skipped on ingest.
    async fn route_to_alice(&mut self) {
        let events = self.relay.published_events.lock().unwrap()[self.alice_cursor..].to_vec();
        self.alice_cursor += events.len();
        for event in events.into_iter().filter(|event| event.kind == 445) {
            self.alice_app
                .relay_plane
                .handle_relay_event_for_test(NostrRelayEvent {
                    endpoint: TransportEndpoint(RELAY.to_owned()),
                    subscription_id: Some("admin-sign-out".to_owned()),
                    event,
                })
                .await
                .unwrap();
        }
    }

    fn sign_out(&self) -> tokio::task::JoinHandle<Result<crate::WipeOutcome, AppError>> {
        let runtime = self.runtime.clone();
        tokio::spawn(async move { runtime.sign_out_and_wipe("alice").await })
    }
}

/// With bob online, alice's sign-out sends her step-down and then her
/// SelfRemove, bob commits the removal, and the wipe counts the chat as left
/// once alice sees that commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signing_out_steps_an_admin_down_and_leaves_once_its_removal_is_seen() {
    let mut test = AdminSignOut::new().await;
    let wipe = test.sign_out();
    tokio::time::timeout(Duration::from_secs(20), async {
        while !wipe.is_finished() {
            test.bob_turn().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the wipe finishes once bob removes alice");
    let outcome = wipe.await.unwrap().unwrap();
    assert_eq!(outcome.groups_left, 1);
    assert!(
        outcome.group_leave_failures.is_empty(),
        "{:?}",
        outcome.group_leave_failures
    );
    assert!(outcome.local_cleanup.completed);
    test.bob_turn().await;
    assert!(!test.bob_sees_alice(), "bob's commit removed alice");
    assert!(
        test.bob
            .runtime
            .admin_pubkeys(&test.chat)
            .unwrap()
            .iter()
            .all(|admin| hex::encode(admin) != test.alice_id),
        "alice stepped down first"
    );
    test.runtime.shutdown().await;
}

/// With bob offline, alice's step-down merges and her SelfRemove goes out,
/// but no one commits it: when the wait ends the chat is reported, and
/// alice stays in it as a member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signing_out_reports_an_admin_chat_whose_removal_it_never_sees() {
    let test = AdminSignOut::new().await;
    test.alice_app
        .set_sign_out_leaving_wait(Duration::from_secs(2));
    let before = test.published();
    let wipe = test.sign_out();
    tokio::time::timeout(Duration::from_secs(10), async {
        while test.relay.published_events.lock().unwrap()[before..]
            .iter()
            .filter(|event| event.kind == 445)
            .count()
            < 2
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("alice sends her step-down and her SelfRemove");
    // Well inside the wait: the chat does not read as left before its
    // removal is seen.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        test.alice_app
            .group("alice", &hex::encode(test.chat.as_slice()))
            .unwrap()
            .expect("the chat")
            .self_membership,
        SelfMembership::Member
    );
    let outcome = wipe.await.unwrap().unwrap();
    assert_eq!(outcome.groups_left, 0);
    assert_eq!(
        outcome.group_leave_failures,
        [crate::GroupLeaveFailure {
            group_id_hex: hex::encode(test.chat.as_slice()),
            reason: "account is not an admin and its removal was not seen in time".to_owned(),
        }]
    );
    assert!(outcome.local_cleanup.completed);
    assert_eq!(
        test.relay.published_events.lock().unwrap()[before..]
            .iter()
            .filter(|event| event.kind == 445)
            .count(),
        2,
        "the step-down and the SelfRemove"
    );
    test.runtime.shutdown().await;
}

/// bob steps down on a longer branch from the same epoch, which alice's
/// sign-out has not seen when it steps down and sends its SelfRemove. Once
/// that branch arrives and wins, alice is the chat's last admin, her leave is
/// blocked, and the wipe reports the chat with that reason without waiting
/// out its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signing_out_reports_an_admin_chat_a_rival_step_down_left_it_last_admin_of() {
    let mut test = AdminSignOut::new().await;
    for name in ["rival one", "rival two", "rival three"] {
        test.bob
            .update_group_profile(&test.chat, Some(name), None)
            .await
            .unwrap();
    }
    test.bob.self_demote_admin(&test.chat).await.unwrap();
    // alice's sign-out sees none of it yet.
    let rival_end = test.published();
    let wipe = test.sign_out();
    tokio::time::timeout(Duration::from_secs(10), async {
        while test.relay.published_events.lock().unwrap()[rival_end..]
            .iter()
            .filter(|event| event.kind == 445)
            .count()
            < 2
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("alice sends her step-down and her SelfRemove");
    let rival = test.relay.published_events.lock().unwrap()[rival_end - 4..rival_end].to_vec();
    for event in rival {
        test.alice_app
            .relay_plane
            .handle_relay_event_for_test(NostrRelayEvent {
                endpoint: TransportEndpoint(RELAY.to_owned()),
                subscription_id: Some("admin-sign-out-rival".to_owned()),
                event,
            })
            .await
            .unwrap();
    }
    let outcome = tokio::time::timeout(Duration::from_secs(20), wipe)
        .await
        .expect("a blocked leave ends the wait before its deadline")
        .unwrap()
        .unwrap();
    assert_eq!(outcome.groups_left, 0);
    assert_eq!(
        outcome.group_leave_failures,
        [crate::GroupLeaveFailure {
            group_id_hex: hex::encode(test.chat.as_slice()),
            reason: "account is the chat's last admin".to_owned(),
        }]
    );
    assert!(outcome.local_cleanup.completed);
    test.runtime.shutdown().await;
}

/// alice's step-down merges but the publish of her SelfRemove fails. Her
/// device keeps the SelfRemove owed, so the leave is not dropped before the
/// wait: the wait reports the chat as one her account stepped down in, now
/// a member's, whose removal it did not see.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selfremove_publish_that_fails_after_the_step_down_is_reported_by_the_wait() {
    let test = AdminSignOut::new().await;
    test.alice_app
        .set_sign_out_leaving_wait(Duration::from_secs(2));
    let before = test.relay.attempted_events().len();
    test.relay.script([true, false]);
    let outcome = test.sign_out().await.unwrap().unwrap();
    let attempted = test.relay.attempted_events()[before..]
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    assert_eq!(
        attempted.get(..2),
        Some(&[445, 445][..]),
        "the step-down, then the SelfRemove whose publish fails: {attempted:?}"
    );
    assert_eq!(outcome.groups_left, 0);
    assert_eq!(
        outcome.group_leave_failures,
        [crate::GroupLeaveFailure {
            group_id_hex: hex::encode(test.chat.as_slice()),
            reason: "account is not an admin and its removal was not seen in time".to_owned(),
        }]
    );
    test.runtime.shutdown().await;
}

/// alice's first sign-out sends her step-down and her SelfRemove and is
/// interrupted while it waits. Her next sign-out finds that leave in
/// progress, sends nothing new to the chat and waits for it: with bob
/// offline, the wait reports the chat as one whose removal it did not see.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retried_sign_out_waits_for_the_leave_an_interrupted_one_recorded() {
    let test = AdminSignOut::new().await;
    let before = test.published();
    let to_the_chat = |test: &AdminSignOut| {
        test.relay.published_events.lock().unwrap()[before..]
            .iter()
            .filter(|event| event.kind == 445)
            .count()
    };
    let first = test.sign_out();
    tokio::time::timeout(Duration::from_secs(10), async {
        while to_the_chat(&test) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("alice sends her step-down and her SelfRemove");
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    test.alice_app
        .set_sign_out_leaving_wait(Duration::from_secs(2));
    let outcome = test.sign_out().await.unwrap().unwrap();
    assert_eq!(outcome.groups_left, 0);
    assert_eq!(
        outcome.group_leave_failures,
        [crate::GroupLeaveFailure {
            group_id_hex: hex::encode(test.chat.as_slice()),
            reason: "account is not an admin and its removal was not seen in time".to_owned(),
        }]
    );
    assert!(outcome.local_cleanup.completed);
    assert_eq!(
        to_the_chat(&test),
        2,
        "the retry sends nothing new to the chat"
    );
    test.runtime.shutdown().await;
}

/// alice's step-down publish ends possibly exposed, so it never merges on
/// her device before the wait ends: the chat is reported as one whose
/// step-down was not accepted in time, and her account stays an admin there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_possibly_exposed_step_down_is_reported_as_not_accepted_in_time() {
    let test = AdminSignOut::new().await;
    test.alice_app
        .set_sign_out_leaving_wait(Duration::from_secs(2));
    let before = test.relay.attempted_events().len();
    test.relay.fail_publishes_as_possibly_exposed();
    let outcome = test.sign_out().await.unwrap().unwrap();
    assert!(
        test.relay.attempted_events()[before..]
            .iter()
            .any(|event| event.kind == 445),
        "the step-down was attempted"
    );
    assert_eq!(outcome.groups_left, 0);
    assert_eq!(
        outcome.group_leave_failures,
        [crate::GroupLeaveFailure {
            group_id_hex: hex::encode(test.chat.as_slice()),
            reason: "account's step-down as admin was not accepted in time".to_owned(),
        }]
    );
    test.runtime.shutdown().await;
}

/// A push token removal that does not go out ends alice's leave before it
/// is recorded: nothing else goes out to the chat, the chat is reported,
/// and her account keeps its admin rights and its leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_push_token_removal_leaves_the_admin_rights_alone() {
    let mut test = AdminSignOut::new().await;
    test.runtime
        .set_native_push_enabled("alice", true)
        .await
        .unwrap();
    test.runtime
        .upsert_push_registration(
            "alice",
            crate::PushPlatform::Fcm,
            "opaque-token",
            &nostr::prelude::Keys::generate().public_key().to_hex(),
            None,
        )
        .await
        .unwrap();
    let before = test.relay.attempted_events().len();
    // The token removal is the wipe's first publish to the chat.
    test.relay.script([false]);
    let outcome = test.sign_out().await.unwrap().unwrap();
    let to_the_chat = test.relay.attempted_events()[before..]
        .iter()
        .filter(|event| event.kind == 445)
        .count();
    assert_eq!(to_the_chat, 1, "only the token removal");
    assert_eq!(outcome.groups_left, 0);
    let [failure] = outcome.group_leave_failures.as_slice() else {
        panic!("the chat is reported: {outcome:?}");
    };
    assert_eq!(failure.group_id_hex, hex::encode(test.chat.as_slice()));
    test.bob_turn().await;
    assert!(test.bob_sees_alice());
    assert!(
        test.bob
            .runtime
            .admin_pubkeys(&test.chat)
            .unwrap()
            .iter()
            .any(|admin| hex::encode(admin) == test.alice_id),
        "alice's account is still an admin"
    );
    test.runtime.shutdown().await;
}
