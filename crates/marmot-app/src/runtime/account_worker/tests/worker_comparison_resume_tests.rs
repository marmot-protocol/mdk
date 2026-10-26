//! A real relay holds the naturally selected maintenance comparison's exact
//! request while the same account worker serves an ordinary status command.

use super::*;
use nostr_relay_builder::prelude::{
    BoxedFuture, Filter as RelayFilter, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase,
    PolicyResult, QueryPolicy,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
use std::net::SocketAddr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Clone, Debug, Default)]
struct HeldComparisonId {
    target: Arc<Mutex<Option<String>>>,
    hold_exact: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    hits: Arc<AtomicUsize>,
    all_queries: Arc<AtomicUsize>,
    id_queries: Arc<AtomicUsize>,
}

impl QueryPolicy for HeldComparisonId {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            self.all_queries.fetch_add(1, Ordering::SeqCst);
            if query.ids.is_some() {
                self.id_queries.fetch_add(1, Ordering::SeqCst);
            }
            let wanted = self.target.lock().unwrap().clone();
            let matches = wanted.as_ref().is_some_and(|wanted| {
                query
                    .ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| id.to_hex() == *wanted))
            });
            if matches {
                self.hits.fetch_add(1, Ordering::SeqCst);
                if self.hold_exact.load(Ordering::SeqCst) {
                    let release = self.release.notified();
                    tokio::pin!(release);
                    release.as_mut().enable();
                    self.entered.notify_one();
                    release.await;
                }
            }
            PolicyResult::Accept
        })
    }
}

// `run_held_comparison` pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
async fn comparison_worker_held_sdk_request_keeps_status_command_ready() {
    run_held_comparison(false, HeldCaller::None, false).await;
}

/// A host catch-up only drains, so it and the commands behind it complete
/// while the worker's comparison is held, without joining or reserving
/// recovery work (mdk#2110).
// `run_held_comparison` pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
async fn catch_up_crosses_held_comparison_without_revising_it() {
    run_held_comparison(false, HeldCaller::CatchUp, false).await;
}

// `run_held_comparison` pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
async fn repair_waits_for_held_comparison_before_revising_it() {
    run_held_comparison(false, HeldCaller::Repair, false).await;
}

// `run_held_comparison` pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
async fn prebarrier_media_runs_before_deferred_repair() {
    run_held_comparison(false, HeldCaller::Repair, true).await;
}

// `run_held_comparison` pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
async fn comparison_shutdown_reaps_task_and_releases_credit() {
    run_held_comparison(true, HeldCaller::None, false).await;
}

/// The recovery caller queued while the comparison is held.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldCaller {
    None,
    CatchUp,
    Repair,
}

async fn run_held_comparison(
    shutdown_while_held: bool,
    held_caller: HeldCaller,
    prebarrier_media: bool,
) {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldComparisonId::default();
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(64),
    });
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .query_policy(gate.clone())
            .database(database.clone()),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let pool = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "held comparison",
            std::slice::from_ref(&bob.account_id_hex),
            AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if app
                .group(&bob.label, &hex::encode(&group))
                .unwrap()
                .is_some()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Bob joined before the target message");

    let storage = app.account_storage(&alice.label).unwrap().app_storage();
    let route: [u8; 32] = hex::decode(
        app.group(&alice.label, &hex::encode(&group))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let recovery_route = storage_sqlite::TransportReconciliationRoute::Group(route);
    // Save directly into relay history: no ordinary EVENT is published to the
    // worker, so only comparison can find this request-local candidate.
    let event = EventBuilder::new(Kind::MlsGroupMessage, "comparison-only probe")
        .tags([Tag::custom("h", [hex::encode(route)])])
        .finalize(&Keys::generate())
        .unwrap();
    let event_id = event.id.to_bytes();
    database
        .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
        .await
        .unwrap();
    *gate.target.lock().unwrap() = Some(event.id.to_hex());
    assert!(
        !storage
            .retained_recovery_event(&recovery_route, &event_id, None, crate::unix_now_seconds())
            .unwrap()
    );
    gate.hold_exact.store(true, Ordering::SeqCst);
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let commands = runtime
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, armed) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::RequestBoundedComparisonForTest { respond })
        .unwrap();
    timeout(Duration::from_secs(5), armed)
        .await
        .expect("serialized worker arms current comparison")
        .unwrap()
        .unwrap();
    let before_retry = storage.recovery_retry_state().unwrap().attempt_serial;
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    if timeout(Duration::from_secs(12), entered).await.is_err() {
        let slot = storage.recovery_comparison().unwrap();
        panic!(
            "maintenance exact-ID wait absent: hits={}, all_queries={}, id_queries={}, retained={}, pending={}, attempt_delta={}, credits={}, slot_attempt={}, frozen={}, routes={}, retries={}, stages={:?}",
            gate.hits.load(Ordering::SeqCst),
            gate.all_queries.load(Ordering::SeqCst),
            gate.id_queries.load(Ordering::SeqCst),
            storage
                .retained_recovery_event(
                    &recovery_route,
                    &event_id,
                    None,
                    crate::unix_now_seconds()
                )
                .unwrap(),
            slot.pending(),
            storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial
                .saturating_sub(before_retry),
            recovery_credits::available_credits(&pool),
            slot.attempt_serial,
            slot.frozen_revision,
            slot.plan.as_ref().map_or(0, |plan| plan.routes.len()),
            slot.plan.as_ref().map_or(0, |plan| plan.retry_routes.len()),
            runtime
                .shared_services()
                .comparison_test_trace
                .lock()
                .unwrap()
                .clone(),
        );
    }
    assert_eq!(
        recovery_credits::available_credits(&pool),
        recovery_credits::MAX_CONCURRENT_JOBS - 1
    );
    assert_eq!(
        storage.recovery_retry_state().unwrap().attempt_serial,
        before_retry + 1
    );
    let commands = runtime
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, status) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_millis(300), status)
        .await
        .expect("normal worker command completes during held SDK comparison")
        .unwrap()
        .unwrap();
    // The probe was inserted without an ordinary EVENT. No event or advisory
    // cursor is admitted before the worker joins the task.
    assert!(gate.hits.load(Ordering::SeqCst) > 0);
    assert!(storage.recovery_comparison().unwrap().pending());
    assert_eq!(
        storage
            .transport_reconciliation_replay_cursor(&recovery_route)
            .unwrap(),
        None
    );
    let mut held_media = Vec::new();
    let prebarrier = if prebarrier_media {
        let accounts = runtime.accounts();
        let workers = accounts.workers.lock().await;
        let admission = workers
            .get(&alice.account_id_hex)
            .expect("Alice worker is running")
            .media_admission
            .clone();
        drop(workers);
        for _ in 0..MEDIA_HTTP_IN_FLIGHT_LIMIT {
            let (started, entered) = oneshot::channel();
            let (release, wait) = oneshot::channel();
            let (respond, completed) = oneshot::channel();
            commands
                .try_send(AccountWorkerCommand::HoldMediaHttp {
                    admission: admission.clone().try_acquire_owned().unwrap(),
                    started,
                    release: wait,
                    respond,
                })
                .unwrap();
            timeout(Duration::from_secs(5), entered)
                .await
                .expect("media slot becomes held")
                .unwrap();
            held_media.push((release, completed));
        }
        let (started, mut entered) = oneshot::channel();
        let (release, wait) = oneshot::channel();
        let (respond, completed) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::HoldMediaHttp {
                admission: admission.try_acquire_owned().unwrap(),
                started,
                release: wait,
                respond,
            })
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), &mut entered)
                .await
                .is_err(),
            "earlier media command is parked before the repair"
        );
        Some((entered, release, completed))
    } else {
        None
    };
    let catch_up = if held_caller != HeldCaller::None {
        let revision = storage.recovery_comparison().unwrap().revision;
        let (respond, mut waiting) = oneshot::channel();
        let command = if held_caller == HeldCaller::CatchUp {
            AccountWorkerCommand::CatchUp { respond }
        } else {
            AccountWorkerCommand::RepairFullHistory { respond }
        };
        commands.try_send(command).unwrap();
        let (respond, mut mutation) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::ConnectivityRestored { respond })
            .unwrap();
        let (respond, mut drain) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::Drain { respond })
            .unwrap();
        let (respond, status) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::GroupRecoveryStatus {
                group_id: group.clone(),
                respond,
            })
            .unwrap();
        timeout(Duration::from_millis(300), status)
            .await
            .expect("read after queued catch-up stays serviceable")
            .unwrap()
            .unwrap();
        if held_caller == HeldCaller::CatchUp {
            timeout(Duration::from_secs(5), &mut waiting)
                .await
                .expect("catch-up completes while the comparison is held")
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), &mut mutation)
                .await
                .expect("later mutation is not deferred behind the comparison")
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), &mut drain)
                .await
                .expect("drain is not deferred behind the comparison")
                .unwrap();
            assert_eq!(
                recovery_credits::available_credits(&pool),
                recovery_credits::MAX_CONCURRENT_JOBS - 1,
                "the comparison is still held"
            );
            assert_eq!(
                storage.recovery_comparison().unwrap().revision,
                revision,
                "a draining catch-up does not join the comparison"
            );
            assert_eq!(
                storage.recovery_retry_state().unwrap().attempt_serial,
                before_retry + 1,
                "a draining catch-up does not reserve recovery work"
            );
        }
        if let Some((entered, release, completed)) = prebarrier {
            let (first_release, first_completed) = held_media.remove(0);
            first_release.send(()).unwrap();
            timeout(Duration::from_secs(5), first_completed)
                .await
                .expect("one media slot is released")
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), entered)
                .await
                .expect("pre-barrier media runs before the repair")
                .unwrap();
            assert_eq!(
                storage.recovery_comparison().unwrap().revision,
                revision,
                "earlier media work did not cross the deferred repair"
            );
            release.send(()).unwrap();
            timeout(Duration::from_secs(5), completed)
                .await
                .expect("pre-barrier media completes")
                .unwrap()
                .unwrap();
            for (release, completed) in held_media.drain(..) {
                release.send(()).unwrap();
                timeout(Duration::from_secs(5), completed)
                    .await
                    .expect("held media completes")
                    .unwrap()
                    .unwrap();
            }
        }
        if held_caller == HeldCaller::CatchUp {
            None
        } else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    mutation.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "later mutation stays behind queued repair"
            );
            assert!(matches!(
                drain.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(
                storage.recovery_comparison().unwrap().revision,
                revision,
                "repair stays queued until the live comparison joins"
            );
            assert_eq!(
                storage.recovery_retry_state().unwrap().attempt_serial,
                before_retry + 1,
                "waiting repair cannot spend another reservation"
            );
            Some((waiting, mutation, drain))
        }
    } else {
        None
    };
    if shutdown_while_held {
        runtime.shutdown_and_close().await.unwrap();
    } else {
        gate.hold_exact.store(false, Ordering::SeqCst);
        gate.release.notify_waiters();
        timeout(Duration::from_secs(12), async {
            loop {
                if recovery_credits::available_credits(&pool)
                    == recovery_credits::MAX_CONCURRENT_JOBS
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("worker finishes the result and releases its credit");
        if let Some((waiting, mutation, drain)) = catch_up {
            // The repair's own outcome (this relay's history is below the
            // retention window) is irrelevant; only its ordering is tested.
            let _repair_outcome = timeout(Duration::from_secs(20), waiting)
                .await
                .expect("repair follows comparison admission")
                .unwrap();
            assert!(
                storage
                    .transport_reconciliation_replay_cursor(&recovery_route)
                    .unwrap()
                    .is_some(),
                "the held comparison proposal was admitted before repair revised it"
            );
            timeout(Duration::from_secs(5), mutation)
                .await
                .expect("later mutation follows repair")
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), drain)
                .await
                .expect("drain follows repair")
                .unwrap();
        }
        runtime.shutdown_and_close().await.unwrap();
    }
    gate.hold_exact.store(false, Ordering::SeqCst);
    gate.release.notify_waiters();
    assert_eq!(
        recovery_credits::available_credits(&pool),
        recovery_credits::MAX_CONCURRENT_JOBS
    );
}

#[derive(Clone, Copy)]
enum JoinSummaryPath {
    Settled,
    Streamed,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_join_settles_routes() {
    verify_join_routing(JoinSummaryPath::Settled).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_join_streams_routes() {
    verify_join_routing(JoinSummaryPath::Streamed).await;
}

async fn verify_join_routing(path: JoinSummaryPath) {
    use crate::client::{
        CommittedSyncProgress, EpochBackfillRunOutcome, MAX_COMPARISON_ADMISSION_PER_TURN,
    };
    use crate::tests::{
        ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
        remember_test_member_inbox, report_scripted_eose, scripted_eose_pump,
    };
    use transport_nostr_adapter::{NostrRelayEvent, NostrSubscription};

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let endpoint = "wss://relay.example";
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), endpoint).with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &bob.account_id_hex, endpoint);
    let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
    let mut receiver = client_on_app_relay_plane(&app, &bob.label).await;
    // Startup's real KeyPackage lane does not activate Bob's inbox. His first
    // Welcome therefore cannot arrive through ordinary local publication.
    receiver.publish_setup_key_package().await.unwrap();
    let mut sender = client_on_app_relay_plane(&app, &alice.label).await;
    let welcome_count = match path {
        JoinSummaryPath::Settled => 1,
        JoinSummaryPath::Streamed => MAX_COMPARISON_ADMISSION_PER_TURN + 1,
    };
    let mut expected_groups = std::collections::HashSet::with_capacity(welcome_count);
    for index in 0..welcome_count {
        if index != 0 {
            receiver.runtime.publish_fresh_key_package().await.unwrap();
        }
        let group = sender
            .create_group("recovered join routing", &[&bob.account_id_hex])
            .await
            .unwrap();
        expected_groups.insert(group);
    }
    let welcomes = relay
        .attempted_events()
        .into_iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_NIP59_GIFT_WRAP)
        .collect::<Vec<_>>();
    let group_hexes = expected_groups.iter().map(hex::encode).collect::<Vec<_>>();
    assert!(
        group_hexes
            .iter()
            .all(|group_hex| app.group(&bob.label, group_hex).unwrap().is_none())
    );
    receiver.prepare_transport().await.unwrap();
    report_scripted_eose(&app.relay_plane, &relay, every_subscription).await;
    receiver.synchronize_native_replay().await.unwrap();
    receiver.request_bounded_comparison().unwrap();
    receiver
        .recovery_owner
        .test_advance_to_retry(&app.account_storage(&bob.label).unwrap());
    receiver.test_comparison_results =
        Some(crate::client::ScriptedComparisons::by_route(move |route| {
            let events = if *route == storage_sqlite::TransportReconciliationRoute::Inbox {
                welcomes
                    .iter()
                    .cloned()
                    .map(|event| NostrRelayEvent {
                        endpoint: cgka_traits::TransportEndpoint(endpoint.into()),
                        subscription_id: None,
                        event,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            Ok(Some((
                transport_nostr_adapter::NostrReconciliationSummary {
                    relays_succeeded: 1,
                    remote_items: events.len(),
                    received_items: events.len(),
                    ..Default::default()
                },
                events,
            )))
        }));
    let (events, mut consumer) = broadcast::channel(32);
    let shared = RuntimeSharedServices::default();
    relay.block_next_subscribe();
    let group = {
        let publish = |client: &AppClient, summary: &SyncSummary| {
            publish_app_runtime_summary_with_v5(
                client,
                &events,
                &bob.account_id_hex,
                &bob.label,
                summary,
            );
        };
        let errors = |live_error, history_error| {
            publish_join_errors(
                live_error,
                history_error,
                &events,
                &bob.account_id_hex,
                &bob.label,
            );
        };
        let progress = CommittedSyncProgress {
            publish: &publish,
            post_join_errors: &errors,
        };
        let reporting = async {
            match path {
                JoinSummaryPath::Settled => {
                    run_pending_epoch_backfill_reporting_arm(
                        &mut receiver,
                        &events,
                        &bob.account_id_hex,
                        &bob.label,
                        &shared,
                        EpochBackfillExecutionSeam::ExplicitCatchUp,
                    )
                    .await
                }
                JoinSummaryPath::Streamed => {
                    let grant = receiver
                        .authorize_account_recovery(
                            None,
                            EpochBackfillExecutionSeam::ExplicitCatchUp,
                        )
                        .await
                        .unwrap()
                        .expect("the pending comparison owns a grant");
                    let execution = receiver.begin_comparison_grant(&grant).await.unwrap();
                    let credit = Arc::new(tokio::sync::Semaphore::new(1))
                        .try_acquire_owned()
                        .unwrap();
                    let mut job = ComparisonNetworkJob::start(
                        &receiver,
                        &grant,
                        credit,
                        ComparisonNetworkJob::automatic_deadline(),
                        None,
                    )
                    .unwrap();
                    let (credit, network) = job.wait().await.unwrap();
                    let outcome = receiver
                        .admit_comparison_inline(Some(&progress), grant, execution, network)
                        .await
                        .unwrap();
                    drop(credit);
                    let (EpochBackfillRunOutcome::Completed(summary)
                    | EpochBackfillRunOutcome::Incomplete(summary)) = outcome
                    else {
                        panic!("the streamed comparison must admit its fetched Welcomes");
                    };
                    assert!(
                        summary.joined_groups.is_empty(),
                        "settlement must not repeat published joins"
                    );
                    Ok(())
                }
            }
        };
        tokio::pin!(reporting);
        let group = timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    biased;
                    event = consumer.recv() => {
                        if let MarmotAppEvent::GroupJoined { account_id_hex, group_id, .. } = event.unwrap() {
                            assert_eq!(account_id_hex, bob.account_id_hex);
                            assert!(expected_groups.contains(&group_id));
                            break group_id;
                        }
                    }
                    result = &mut reporting => panic!("settlement returned before visible join followup: {result:?}"),
                }
            }
        })
        .await
        .expect("the recovered Welcome publishes GroupJoined before subscription I/O");
        let group_hex = hex::encode(&group);
        assert!(
            app.group(&bob.label, &group_hex)
                .unwrap()
                .expect("GroupJoined has a durable public group projection")
                .pending_confirmation
        );
        timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                result = &mut reporting => panic!("settlement skipped recovered join routing: {result:?}"),
                () = relay.wait_for_blocked_subscribe() => {}
            }
        })
        .await
        .expect("the worker starts real group-subscription I/O before continuing");
        if matches!(path, JoinSummaryPath::Streamed) {
            assert!(
                group_hexes
                    .iter()
                    .any(|group_hex| app.group(&bob.label, group_hex).unwrap().is_none()),
                "subscription I/O must precede admission of the later Welcome turn"
            );
        }
        relay.release_subscribe();
        timeout(Duration::from_secs(5), &mut reporting)
            .await
            .expect("settlement continues after the subscription barrier releases")
            .unwrap();
        group
    };
    let bob_member = cgka_traits::MemberId::new(hex::decode(&bob.account_id_hex).unwrap());
    let subscriptions = relay.accepted_subscriptions();
    let joined = subscriptions.iter().filter(|subscription| {
        subscription.account_id() == &bob_member && subscription.carries_group(&group)
    });
    assert!(joined.clone().any(|subscription| matches!(
        subscription,
        NostrSubscription::Group { .. } | NostrSubscription::GroupBatch { .. }
    )));
    // The visible join requests history; only the recovery owner may install
    // that temporary subscription under its next grant.
    report_scripted_eose(&app.relay_plane, &relay, every_subscription).await;
    receiver
        .recovery_owner
        .test_advance_to_retry(&app.account_storage(&bob.label).unwrap());
    let grant = receiver
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
        .await
        .unwrap()
        .expect("the recovered join leaves a grant-owned history boundary");
    let backfill_armed = receiver.has_pending_epoch_backfill();
    let backfill_result = receiver.run_recovery_grant_for_test(grant).await;
    report_pending_epoch_backfill_result(
        &mut receiver,
        backfill_result,
        backfill_armed,
        None,
        EpochBackfillReportContext {
            events: &events,
            account_id_hex: &bob.account_id_hex,
            account_label: &bob.label,
            shared: &shared,
        },
    )
    .await
    .unwrap();
    assert!(relay.accepted_subscriptions().iter().any(|subscription| {
        subscription.account_id() == &bob_member
            && subscription.carries_group(&group)
            && matches!(
                subscription,
                NostrSubscription::GroupMaintenance { since: Some(_), .. }
            )
    }));
    report_scripted_eose(&app.relay_plane, &relay, every_subscription).await;
    let summary = receiver.sync().await.unwrap();
    publish_app_runtime_summary_with_v5(
        &receiver,
        &events,
        &bob.account_id_hex,
        &bob.label,
        &summary,
    );
    start_post_join_history_after_visibility(
        &mut receiver,
        &summary,
        &events,
        &bob.account_id_hex,
        &bob.label,
    )
    .await;
    let mut observed_groups = std::collections::HashSet::from([group]);
    while let Ok(event) = consumer.try_recv() {
        if let MarmotAppEvent::GroupJoined {
            account_id_hex,
            group_id,
            ..
        } = event
            && account_id_hex == bob.account_id_hex
        {
            assert!(
                observed_groups.insert(group_id),
                "settlement and repeated catch-up must not duplicate GroupJoined"
            );
        }
    }
    assert_eq!(observed_groups, expected_groups);
    assert!(
        group_hexes
            .iter()
            .all(|group_hex| app.group(&bob.label, group_hex).unwrap().is_some())
    );
}

// Pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
async fn comparison_credit_exhaustion_does_not_spend_reservation() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let pool = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let storage = app.account_storage(&account.label).unwrap().app_storage();
    let credits = recovery_credits::hold_all_credits_for_test(&pool);
    let commands = runtime
        .accounts()
        .worker_commands(&account.label)
        .await
        .unwrap();
    let (respond, armed) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::RequestBoundedComparisonForTest { respond })
        .unwrap();
    timeout(Duration::from_secs(5), armed)
        .await
        .expect("serialized worker arms current comparison")
        .unwrap()
        .unwrap();
    let before = storage.recovery_retry_state().unwrap();
    runtime
        .advance_recovery_clock_for_test(&account.label, Duration::from_secs(600))
        .await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    let (respond, status) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: GroupId::new(vec![7; 16]),
            respond,
        })
        .unwrap();
    let _ = timeout(Duration::from_secs(2), status)
        .await
        .unwrap()
        .unwrap();
    let after = storage.recovery_retry_state().unwrap();
    assert_eq!(after.attempt_serial, before.attempt_serial);
    assert_eq!(after.not_before_ms, before.not_before_ms);
    assert!(storage.recovery_comparison().unwrap().pending());
    drop(credits);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comparison_offworker_valid_result_admitted_only_after_owner_join() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(64),
    });
    let relay = LocalRelay::new(RelayBuilder::default().database(database.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let pool = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "offworker owned event",
            std::slice::from_ref(&bob.account_id_hex),
            AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if app
                .group(&bob.label, &hex::encode(&group))
                .unwrap()
                .is_some()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Bob joined before the target message");
    runtime
        .accounts()
        .workers
        .lock()
        .await
        .remove(&alice.account_id_hex)
        .unwrap()
        .shutdown()
        .await;
    let mut client = app.client(&alice.label).await.unwrap();
    client.prepare_transport().await.unwrap();
    timeout(Duration::from_secs(10), async {
        while !client.adapter.account_subscription_eose().await.complete() {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("startup replay reaches EOSE before checking comparison ownership");
    while matches!(
        timeout(Duration::from_millis(100), client.receive_next_delivery()).await,
        Ok(Ok(_))
    ) {}
    client.synchronize_native_replay().await.unwrap();
    runtime
        .accounts()
        .workers
        .lock()
        .await
        .remove(&bob.account_id_hex)
        .unwrap()
        .shutdown()
        .await;
    let mut sender = app.client(&bob.label).await.unwrap();
    let expected = (0..9)
        .map(|index| format!("offworker admission target {index}"))
        .collect::<std::collections::BTreeSet<_>>();
    // Save real encrypted MLS envelopes into relay history without notifying
    // live subscriptions. Only the owned comparison result can supply them.
    for text in &expected {
        let inner = crate::messages::build_inner_event(
            &AppMessageIntent::Chat {
                content: text.clone(),
            },
            &bob.account_id_hex,
            crate::unix_now_seconds(),
        )
        .unwrap();
        let effects = sender
            .runtime
            .session_mut()
            .send(cgka_traits::engine::SendIntent::AppMessage {
                group_id: group.clone(),
                payload: crate::messages::encode_inner_event(&inner).unwrap(),
                expected_epoch: None,
            })
            .await
            .unwrap();
        let Some(cgka_session::PublishWork::ApplicationMessage { msg, .. }) =
            effects.publish.into_iter().next()
        else {
            panic!("a real MLS send produces its encrypted envelope");
        };
        let event = transport_nostr_peeler::NostrTransportEvent::from_transport_message(&msg)
            .unwrap()
            .to_verified_nostr_event()
            .unwrap();
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
    }
    drop(sender);
    let storage = app.account_storage(&alice.label).unwrap();
    client.request_bounded_comparison().unwrap();
    client.recovery_owner.test_advance_to_retry(&storage);
    let grant = client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
        .await
        .unwrap()
        .unwrap();
    let attempt_serial = grant.reservation.attempt_serial;
    let mut execution = client.begin_comparison_grant(&grant).await.unwrap();
    let credit = recovery_credits::try_acquire_recovery_credit(&pool).unwrap();
    let mut job = ComparisonNetworkJob::start(
        &client,
        &grant,
        credit,
        ComparisonNetworkJob::automatic_deadline(),
        None,
    )
    .unwrap();
    let (credit, network) = timeout(Duration::from_secs(12), job.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), client.receive_next_delivery())
            .await
            .is_err()
    );
    let mut admission = client
        .accept_comparison_network(&grant, &mut execution, network)
        .await
        .unwrap()
        .unwrap();
    let (events, mut consumer) = broadcast::channel(128);
    assert!(
        !client
            .admit_comparison_turn(&grant, &mut execution, &mut admission)
            .await
            .unwrap(),
        "nine actual ingests require more than one bounded worker turn"
    );
    let first = admission.take_committed_summary();
    let durable_prefix = app
        .messages(&alice.label)
        .unwrap()
        .into_iter()
        .map(|message| message.plaintext)
        .filter(|text| expected.contains(text))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(durable_prefix.len(), 4);
    assert_eq!(
        first
            .messages
            .iter()
            .map(|message| message.plaintext.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        durable_prefix,
        "only the checkpointed first four plaintexts are publishable"
    );
    publish_app_runtime_summary_with_v5(
        &client,
        &events,
        &alice.account_id_hex,
        &alice.label,
        &first,
    );
    let mut received = std::collections::BTreeSet::new();
    while let Ok(event) = consumer.try_recv() {
        if let MarmotAppEvent::MessageReceived(update) = event {
            assert!(received.insert(update.message.plaintext));
        }
    }
    assert_eq!(
        received.len(),
        4,
        "the permanent consumer sees the committed first turn before settlement"
    );
    assert_eq!(received, durable_prefix);
    loop {
        let complete = client
            .admit_comparison_turn(&grant, &mut execution, &mut admission)
            .await
            .unwrap();
        let prefix = admission.take_committed_summary();
        publish_app_runtime_summary_with_v5(
            &client,
            &events,
            &alice.account_id_hex,
            &alice.label,
            &prefix,
        );
        if complete {
            break;
        }
    }
    let result = client
        .finish_comparison_grant(grant, execution, Some(admission))
        .await
        .unwrap();
    drop(credit);
    let shared = RuntimeSharedServices::default();
    report_pending_epoch_backfill_result(
        &mut client,
        Ok(result),
        false,
        None,
        EpochBackfillReportContext {
            events: &events,
            account_id_hex: &alice.account_id_hex,
            account_label: &alice.label,
            shared: &shared,
        },
    )
    .await
    .unwrap();
    while let Ok(event) = consumer.try_recv() {
        if let MarmotAppEvent::MessageReceived(update) = event {
            assert!(
                received.insert(update.message.plaintext),
                "settlement must not repeat an already published turn"
            );
        }
    }
    assert_eq!(received, expected);
    assert_eq!(
        app.messages(&alice.label)
            .unwrap()
            .into_iter()
            .map(|message| message.plaintext)
            .filter(|text| expected.contains(text))
            .collect::<std::collections::BTreeSet<_>>(),
        expected,
        "every published plaintext has its permanent public projection"
    );
    let mut retained = None;
    for file in app.audit_log_files().unwrap() {
        let contents = std::fs::read_to_string(file.path).unwrap();
        for line in contents.lines() {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            if row["event"]["type"] != "recovery_attempt_finished"
                || row["event"]["attempt_serial"] != attempt_serial
            {
                continue;
            }
            assert_eq!(
                retained.replace(row["event"]["events_retained"].as_u64().unwrap()),
                None,
                "the pass has one terminal accounting row"
            );
        }
    }
    assert_eq!(
        retained,
        Some(expected.len() as u64),
        "progressive publication must retain whole-pass admission accounting"
    );
    drop(client);
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}
