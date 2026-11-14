//! The hydration request (mdk#3273 PR 4): a group read whose version of A
//! shows a named group awaiting hydration asks the worker to hydrate it and
//! answers from the version the worker acknowledges with. Groups await
//! hydration only while startup's hydration pipeline runs, so these tests
//! hold that pipeline with its batch-delay knob and read through the host
//! wrappers of a real account worker.
use super::*;
use cgka_traits::storage::GroupStorage;

/// Long enough that no hydration batch completes while a test runs.
const BATCH_HOLD_MS: u64 = 30_000;

fn held_app(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise()
            .with_dev_startup_hydration_batch_delay_ms(BATCH_HOLD_MS),
    )
    .with_test_relay_client(relay)
}

/// How many hydration requests and fallback commands of class R3 the worker
/// has taken.
fn r3_worker_waits(runtime: &crate::MarmotAppRuntime) -> u64 {
    runtime
        .shared_services()
        .observer
        .performance()
        .snapshot()
        .runtime_operations
        .into_iter()
        .find(|sample| sample.operation == RuntimeOp::ReadQueueR3)
        .map_or(0, |sample| sample.successes)
}

fn is_unknown_group(result: &Result<impl std::fmt::Debug, AppError>) -> bool {
    matches!(result, Err(AppError::UnknownGroup(_)))
        || matches!(
            result.as_ref().err().and_then(AppError::as_engine_error),
            Some(cgka_traits::error::EngineError::UnknownGroup(_))
        )
}

async fn within_hold<T>(read: &str, call: impl std::future::Future<Output = T>) -> T {
    timeout(Duration::from_millis(BATCH_HOLD_MS / 2), call)
        .await
        .unwrap_or_else(|_| panic!("{read} must not wait out the held hydration pipeline"))
}

/// A read answers from the acknowledging version: live for a group that
/// hydrates, `UnknownGroup` for one its hydration quarantines. Each asks
/// the worker once, and a read of a group already hydrated asks nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hydration_is_acknowledged_as_live_and_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let fixture = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut groups = Vec::new();
    {
        let mut client = fixture.client("alice").await.unwrap();
        for name in ["live", "damaged"] {
            groups.push(
                client
                    .create_group(name, &[])
                    .await
                    .unwrap()
                    .operation
                    .expect("a group with no other members"),
            );
        }
    }
    let [live, damaged] = groups.try_into().unwrap();
    // A protocol profile the stored MLS group does not carry fails its
    // hydration, which quarantines it.
    let storage = fixture.account_storage("alice").unwrap();
    let mut record = storage.get_group(&damaged).unwrap();
    assert_ne!(
        record.protocol_profile,
        cgka_traits::group::ProtocolProfile::Legacy
    );
    record.protocol_profile = cgka_traits::group::ProtocolProfile::Legacy;
    storage.put_group(&record).unwrap();
    drop(storage);

    let runtime = crate::MarmotAppRuntime::new(held_app(&dir, relay));
    runtime.reconcile_accounts().await.unwrap();

    let before = r3_worker_waits(&runtime);
    let members = within_hold("a live group's read", runtime.group_members("alice", &live))
        .await
        .unwrap();
    assert_eq!(members.len(), 1, "the live group answers its roster");
    assert_eq!(
        r3_worker_waits(&runtime),
        before + 1,
        "the read asked the worker to hydrate its group"
    );

    let quarantined = within_hold(
        "a quarantined group's read",
        runtime.group_members("alice", &damaged),
    )
    .await;
    assert!(
        is_unknown_group(&quarantined),
        "a group its hydration quarantined answers UnknownGroup: {quarantined:?}"
    );
    assert_eq!(
        r3_worker_waits(&runtime),
        before + 2,
        "the quarantined group awaited hydration until the read asked"
    );
    assert_eq!(
        runtime
            .quarantined_groups("alice")
            .await
            .unwrap()
            .into_iter()
            .map(|group| group.group_id_hex)
            .collect::<Vec<_>>(),
        vec![hex::encode(damaged.as_slice())],
        "the acknowledged version holds the quarantine"
    );

    // Both groups are settled now: reads answer from A with no request.
    within_hold(
        "a hydrated group's read",
        runtime.group_members("alice", &live),
    )
    .await
    .unwrap();
    let page = within_hold(
        "a page naming a quarantined group",
        runtime.group_member_ids_page("alice", &[live.clone(), damaged.clone()]),
    )
    .await;
    assert!(
        is_unknown_group(&page),
        "the page is all-or-error: {page:?}"
    );
    assert_eq!(
        r3_worker_waits(&runtime),
        before + 2,
        "a group that no longer awaits hydration asks the worker nothing"
    );

    assert_eq!(
        runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_group_hydration
            .attempts,
        1,
        "the hydration pipeline is still held"
    );
    runtime.shutdown().await;
}

/// Paced so a command sent once the account is ready runs in the hold before
/// the first batch, and short enough for the pipeline to finish.
const BATCH_PACE_MS: u64 = 2_500;

fn paced_app(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise()
            .with_dev_startup_hydration_batch_delay_ms(BATCH_PACE_MS),
    )
    .with_test_relay_client(relay)
}

/// `count` groups of alice's, each left with a staged commit and no record
/// of its publication, as a crash mid-publish leaves it. The group's
/// hydration clears the commit and reports `PendingCommitRecovered`.
async fn groups_with_stranded_commits(
    dir: &tempfile::TempDir,
    relay: Arc<ScriptedPushRelayClient>,
    count: usize,
) -> Vec<GroupId> {
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let fixture =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let mut client = fixture.client("alice").await.unwrap();
    let mut groups = Vec::new();
    for index in 0..count {
        let group = client
            .create_group(&format!("group {index}"), &[])
            .await
            .unwrap()
            .operation
            .expect("a group with no other members");
        // The session stages the commit without publishing it.
        client
            .runtime
            .session_mut()
            .send(cgka_traits::engine::SendIntent::SelfUpdate {
                group_id: group.clone(),
            })
            .await
            .unwrap();
        groups.push(group);
    }
    drop(client);
    // Without its durable evolution, hydration cannot resume the commit.
    fixture
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .execute_batch_for_test("DELETE FROM cgka_group_evolutions;")
        .unwrap();
    groups
}

fn hydration_attempts(runtime: &crate::MarmotAppRuntime) -> u64 {
    runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot()
        .account_group_hydration
        .attempts
}

/// Adds the groups whose recovered pending commit has reached the host.
fn note_recovered(
    events: &mut broadcast::Receiver<crate::MarmotAppEvent>,
    recovered: &mut HashSet<GroupId>,
) {
    loop {
        match events.try_recv() {
            Ok(crate::MarmotAppEvent::GroupEvent(event)) => {
                if let cgka_traits::engine::GroupEvent::PendingCommitRecovered {
                    group_id, ..
                } = event.event
                {
                    recovered.insert(group_id);
                }
            }
            Ok(_) => {}
            Err(broadcast::error::TryRecvError::Empty) => return,
            Err(error) => panic!("the host event stream must not {error:?}"),
        }
    }
}

/// The latest version of alice's read state the worker has published.
async fn published_read_state(
    runtime: &crate::MarmotAppRuntime,
) -> Arc<crate::client::read_state::ReadState> {
    let (respond, subscription) = oneshot::channel();
    runtime
        .accounts
        .worker_commands("alice")
        .await
        .unwrap()
        .send(AccountWorkerCommand::SubscribeReadStateForTest { respond })
        .await
        .unwrap();
    let published = subscription.await.unwrap().expect("the worker publishes A");
    published.borrow().clone()
}

/// Waits for the first batch to report a recovered commit.
async fn first_recovered(
    events: &mut broadcast::Receiver<crate::MarmotAppEvent>,
    recovered: &mut HashSet<GroupId>,
) -> GroupId {
    timeout(Duration::from_secs(30), async {
        loop {
            match events.recv().await {
                Ok(crate::MarmotAppEvent::GroupEvent(event)) => {
                    if let cgka_traits::engine::GroupEvent::PendingCommitRecovered {
                        group_id,
                        ..
                    } = event.event
                    {
                        recovered.insert(group_id.clone());
                        return group_id;
                    }
                }
                Ok(_) => {}
                Err(error) => panic!("the host event stream must not {error:?}"),
            }
        }
    })
    .await
    .expect("the first batch recovers its groups' pending commits")
}

/// Waits for the hydration phase to end, collecting the recovered commits.
/// A catch-up accepted during the phase is deferred until startup sync,
/// which runs after the last batch, so its answer marks the end.
async fn finish_hydration(
    runtime: &crate::MarmotAppRuntime,
    events: &mut broadcast::Receiver<crate::MarmotAppEvent>,
    recovered: &mut HashSet<GroupId>,
) {
    let (respond, caught_up) = oneshot::channel();
    runtime
        .accounts
        .worker_commands("alice")
        .await
        .unwrap()
        .send(AccountWorkerCommand::CatchUp { respond })
        .await
        .unwrap();
    let _ = timeout(Duration::from_secs(60), caught_up)
        .await
        .expect("the deferred catch-up answers once startup ends");
    assert_eq!(
        hydration_attempts(runtime),
        2,
        "the hydration pipeline completed"
    );
    note_recovered(events, recovered);
}

/// A forget that arrives while startup hydrates its groups runs at its
/// position (mdk#3273 PR 4). Run before its group's batch, it drops the
/// group before hydration recovers its pending commit, so the host never
/// sees that commit recovered, and the pipeline goes on to hydrate the rest.
/// Run after its group's batch, it answers as it does once startup ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forget_during_startup_hydration_runs_at_its_position() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    // Seven groups take two batches of four, even after the first forget.
    let groups = groups_with_stranded_commits(&dir, relay.clone(), 7).await;
    let early = groups[0].clone();

    let runtime = crate::MarmotAppRuntime::new(paced_app(&dir, relay));
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    let mut recovered = HashSet::new();

    assert!(
        runtime.forget_group_local("alice", &early).await.unwrap(),
        "the forget drops its group"
    );
    note_recovered(&mut events, &mut recovered);
    assert!(
        recovered.is_empty() && hydration_attempts(&runtime) == 1,
        "the forget ran in the hold before the first batch"
    );
    assert!(is_unknown_group(
        &runtime.group_members("alice", &early).await
    ));

    // Forget a group the first batch hydrated, in the hold before the second.
    let hydrated = first_recovered(&mut events, &mut recovered).await;
    assert!(
        runtime
            .forget_group_local("alice", &hydrated)
            .await
            .unwrap(),
        "a hydrated group is forgotten as after startup"
    );
    assert_eq!(
        hydration_attempts(&runtime),
        1,
        "the forget ran before the second batch"
    );
    assert!(is_unknown_group(
        &runtime.group_members("alice", &hydrated).await
    ));

    finish_hydration(&runtime, &mut events, &mut recovered).await;
    assert_eq!(
        recovered,
        groups[1..].iter().cloned().collect::<HashSet<_>>(),
        "every group but the one forgotten before its batch had its commit recovered"
    );
    runtime.shutdown().await;
}

/// A forget whose storage write fails partway in the hydration phase leaves
/// its group whole: still awaiting its batch, hydrated there, its recovered
/// commit reported and its roster readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forget_that_fails_during_startup_hydration_leaves_its_group_whole() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let groups = groups_with_stranded_commits(&dir, relay.clone(), 2).await;
    let kept = groups[0].clone();
    let app = paced_app(&dir, relay);
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .execute_batch_for_test(
            "CREATE TRIGGER fail_forget BEFORE INSERT ON locally_forgotten_groups
             BEGIN SELECT RAISE(ABORT, 'injected forget failure'); END;",
        )
        .unwrap();

    let runtime = crate::MarmotAppRuntime::new(app);
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    let mut recovered = HashSet::new();

    assert!(
        runtime.forget_group_local("alice", &kept).await.is_err(),
        "the injected write fails the forget"
    );
    note_recovered(&mut events, &mut recovered);
    assert!(
        recovered.is_empty() && hydration_attempts(&runtime) == 1,
        "the forget ran in the hold before the first batch"
    );
    assert_eq!(
        published_read_state(&runtime)
            .await
            .awaiting_hydration(std::slice::from_ref(&kept)),
        std::slice::from_ref(&kept),
        "the group still awaits its batch"
    );

    finish_hydration(&runtime, &mut events, &mut recovered).await;
    assert_eq!(
        recovered,
        groups.iter().cloned().collect::<HashSet<_>>(),
        "the pipeline hydrated the group the forget failed on"
    );
    assert_eq!(
        runtime.group_members("alice", &kept).await.unwrap().len(),
        1
    );
    runtime.shutdown().await;
}

/// A hydration request accepted behind a forget in the hydration phase runs
/// after it and acknowledges a version where the group is gone; a read of
/// another group waits only for that group, not for a deferred catch-up
/// accepted before both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hydration_request_behind_a_forget_answers_its_group_gone() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let groups = {
        let fixture = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = fixture.client("alice").await.unwrap();
        let mut groups = Vec::new();
        for name in ["forgotten", "read"] {
            groups.push(
                client
                    .create_group(name, &[])
                    .await
                    .unwrap()
                    .operation
                    .expect("a group with no other members"),
            );
        }
        groups
    };
    let [forgotten, read] = groups.try_into().unwrap();
    let runtime = crate::MarmotAppRuntime::new(held_app(&dir, relay));
    runtime.reconcile_accounts().await.unwrap();

    let commands = runtime.accounts.worker_commands("alice").await.unwrap();
    let (respond, mut caught_up) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::CatchUp { respond })
        .unwrap();
    let (respond, forget) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::ForgetGroupLocal {
            group_id: forgotten.clone(),
            respond,
        })
        .unwrap();
    let (respond, ack) = ReadReply::unobserved();
    commands
        .try_send(AccountWorkerCommand::HydrateGroups {
            group_ids: vec![forgotten.clone()],
            respond,
        })
        .unwrap();

    let ack = within_hold("the hydration request", ack)
        .await
        .unwrap()
        .unwrap();
    assert!(ack.failure.is_none());
    assert!(
        !ack.state.groups.contains_key(&forgotten),
        "the forget ran first, so the request acknowledges the group gone"
    );
    assert!(ack.state.awaiting_hydration(&[forgotten]).is_empty());
    assert!(forget.await.unwrap().unwrap());

    let members = within_hold(
        "a read of another awaiting group",
        runtime.group_members("alice", &read),
    )
    .await
    .unwrap();
    assert_eq!(members.len(), 1);
    assert!(
        matches!(
            caught_up.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "the catch-up accepted first stays deferred"
    );
    runtime.shutdown().await;
}

/// A delete that arrives while startup hydrates its groups waits for the
/// phase to end, as before mdk#3273 PR 4. Its route changes need the account
/// active in the transport, which startup sync makes it only after the
/// pipeline. So the deleted group's recovered pending commit still reaches
/// the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delete_during_startup_hydration_waits_for_the_phase_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let groups = groups_with_stranded_commits(&dir, relay.clone(), 1).await;
    let deleted = groups[0].clone();

    let runtime = crate::MarmotAppRuntime::new(paced_app(&dir, relay));
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();

    let result = timeout(
        Duration::from_secs(60),
        runtime.delete_group_local("alice", &deleted),
    )
    .await
    .expect("the delete answers once startup ends");
    assert_eq!(
        hydration_attempts(&runtime),
        2,
        "the delete waited for the hydration phase to end"
    );
    assert!(result.unwrap(), "the delete then drops its group");

    let mut recovered = HashSet::new();
    note_recovered(&mut events, &mut recovered);
    assert_eq!(
        recovered,
        HashSet::from([deleted.clone()]),
        "hydration ran first and reported the group's recovered commit"
    );
    runtime.shutdown().await;
}

/// Co-members leave out a group the engine froze by the engine's saved
/// flag, not by the app's mark (mdk#3273 PR 4). The engine saves the flag
/// before the app marks its record, and a failed save of that mark
/// followed by an exit leaves the app row saying the group is
/// recoverable. After the restart the mirror record says so too, until the
/// engine's re-emitted `GroupUnrecoverable` is projected. The read through A
/// and the worker's fallback both leave the group out from their first
/// answer, so the host never sees a frozen group come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn co_members_go_by_the_engine_flag_after_a_lost_app_save() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let fixture = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    // Each member has a home of their own, so the runtime runs only Alice's
    // worker.
    let mut members = Vec::new();
    let mut groups = Vec::new();
    let mut alice = fixture.client("alice").await.unwrap();
    for (name, member) in [("healthy", "bob"), ("frozen", "carol")] {
        let member_dir = tempfile::tempdir().unwrap();
        let member_id = AccountHome::open(member_dir.path())
            .create_account(member)
            .unwrap()
            .account_id_hex;
        crate::tests::remember_test_member_inbox(&fixture, &member_id, "wss://relay.example");
        MarmotApp::with_relay(member_dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone())
            .client(member)
            .await
            .unwrap()
            .publish_key_package()
            .await
            .unwrap();
        groups.push(
            alice
                .create_group(name, &[member_id.as_str()])
                .await
                .unwrap()
                .operation
                .expect("eligible fixture members"),
        );
        members.push(member_id);
    }
    drop(alice);
    let [bob, _carol] = members.try_into().unwrap();
    let [_healthy, frozen] = groups.try_into().unwrap();

    // What a crash after a failed save of the mark leaves: the engine's
    // flag saved, the app row still recoverable.
    let lose_the_app_save = || {
        let storage = fixture.account_storage("alice").unwrap();
        let mut halted = storage.get_group(&frozen).unwrap();
        halted.unrecoverable = true;
        storage.put_group(&halted).unwrap();
        let mut state = fixture.load_state("alice").unwrap();
        state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == hex::encode(frozen.as_slice()))
            .expect("the frozen group's row")
            .unrecoverable = false;
        fixture.save_state(&state).unwrap();
    };

    lose_the_app_save();
    let runtime = crate::MarmotAppRuntime::new(held_app(&dir, relay.clone()));
    runtime.reconcile_accounts().await.unwrap();
    let through_a = within_hold("co-members through A", runtime.group_co_members("alice"))
        .await
        .unwrap();
    assert_eq!(
        through_a,
        vec![bob.clone()],
        "the read through A leaves out the group the engine froze"
    );
    runtime.shutdown().await;
    drop(runtime);

    lose_the_app_save();
    let runtime = crate::MarmotAppRuntime::new(held_app(&dir, relay));
    runtime.reconcile_accounts().await.unwrap();
    let commands = runtime.accounts().worker_commands("alice").await.unwrap();
    let (respond, answer) = ReadReply::unobserved();
    commands
        .send(AccountWorkerCommand::GroupCoMembers { respond })
        .await
        .unwrap();
    let fallback = within_hold("co-members on the worker", answer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fallback,
        vec![bob],
        "the worker's fallback leaves out the group the engine froze"
    );
    runtime.shutdown().await;
}
