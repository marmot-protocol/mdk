//! A real relay holds the naturally selected maintenance comparison's exact
//! request while the same account worker serves an ordinary status command.

use super::*;
use nostr_relay_builder::prelude::{
    BoxedFuture, Filter as RelayFilter, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase,
    PolicyResult, QueryPolicy,
};
use nostr_relay_builder::{LocalRelay, MockRelay, RelayBuilder};
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

#[tokio::test]
async fn comparison_worker_held_sdk_request_keeps_status_command_ready() {
    run_held_comparison(false, false, false).await;
}

#[tokio::test]
async fn explicit_catch_up_waits_for_held_comparison_before_revising_it() {
    run_held_comparison(false, false, true).await;
}

#[tokio::test]
async fn comparison_shutdown_reaps_task_and_releases_credit() {
    run_held_comparison(true, false, false).await;
}

#[tokio::test]
async fn comparison_and_known_worker_share_two_credits_during_shutdown() {
    run_held_comparison(true, true, false).await;
}

async fn run_held_comparison(
    shutdown_while_held: bool,
    known_competes: bool,
    catch_up_while_held: bool,
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
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
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

    let storage = app.account_storage(&alice.label).unwrap();
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
    let known_fixture = if known_competes {
        Some(bounded_known_fixture_with_pool(pool.clone()).await)
    } else {
        None
    };
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
            bounded_recovery::available_credits(&pool),
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
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS - 1
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
    let catch_up = if catch_up_while_held {
        let revision = storage.recovery_comparison().unwrap().revision;
        let (respond, waiting) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::CatchUp { respond })
            .unwrap();
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            matches!(
                mutation.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "later mutation stays behind queued catch-up"
        );
        assert!(matches!(
            drain.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(
            storage.recovery_comparison().unwrap().revision,
            revision,
            "explicit catch-up stays queued until the live comparison joins"
        );
        assert_eq!(
            storage.recovery_retry_state().unwrap().attempt_serial,
            before_retry + 1,
            "waiting explicit work cannot spend another reservation"
        );
        Some((waiting, mutation, drain))
    } else {
        None
    };
    if known_competes {
        let fixture = known_fixture.as_ref().unwrap();
        fixture
            .relay
            .acquisition_block
            .store(true, Ordering::SeqCst);
        let entered = fixture.relay.acquisition_entered.notified();
        tokio::pin!(entered);
        entered.as_mut().enable();
        wake_bounded_fixture(fixture).await;
        timeout(Duration::from_secs(5), entered)
            .await
            .expect("known-event worker holds the second shared credit");
        assert_eq!(bounded_recovery::available_credits(&pool), 0);
        assert!(bounded_recovery::try_acquire_recovery_credit(&pool).is_none());

        // A separate ordinary runtime still receives the default process
        // pool while this fixture owns its private two-credit pool.
        let ordinary_dir = tempfile::tempdir().unwrap();
        let ordinary_account = AccountHome::open(ordinary_dir.path())
            .create_account("ordinary")
            .unwrap();
        let ordinary_app = MarmotApp::with_relay_and_config(
            ordinary_dir.path(),
            url.clone(),
            crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
        );
        let ordinary = crate::MarmotAppRuntime::new(ordinary_app);
        let another_dir = tempfile::tempdir().unwrap();
        let another = crate::MarmotAppRuntime::new(MarmotApp::with_relay_and_config(
            another_dir.path(),
            url.clone(),
            crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
        ));
        let ordinary_pool = ordinary.shared_services().recovery_credit_pool();
        assert!(Arc::ptr_eq(
            &ordinary_pool,
            &another.shared_services().recovery_credit_pool()
        ));
        assert!(Arc::ptr_eq(
            &ordinary_pool,
            &bounded_recovery::shared_recovery_credit_pool()
        ));
        assert!(!Arc::ptr_eq(&ordinary_pool, &pool));
        ordinary.reconcile_accounts().await.unwrap();
        let ordinary_commands = ordinary
            .accounts()
            .worker_commands(&ordinary_account.label)
            .await
            .unwrap();
        let (respond, status) = oneshot::channel();
        ordinary_commands
            .try_send(AccountWorkerCommand::GroupRecoveryStatus {
                group_id: GroupId::new(vec![9; 16]),
                respond,
            })
            .unwrap();
        let _ = timeout(Duration::from_secs(2), status)
            .await
            .expect("ordinary runtime command remains serviceable")
            .unwrap();
        ordinary.shutdown_and_close().await.unwrap();
        another.shutdown_and_close().await.unwrap();
    }
    if shutdown_while_held {
        runtime.shutdown_and_close().await.unwrap();
        if let Some(fixture) = known_fixture {
            fixture.runtime.shutdown_and_close().await.unwrap();
        }
    } else {
        gate.hold_exact.store(false, Ordering::SeqCst);
        gate.release.notify_waiters();
        timeout(Duration::from_secs(12), async {
            loop {
                if bounded_recovery::available_credits(&pool)
                    == bounded_recovery::MAX_CONCURRENT_JOBS
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("worker finishes the result and releases its credit");
        if let Some((waiting, mutation, drain)) = catch_up {
            timeout(Duration::from_secs(20), waiting)
                .await
                .expect("explicit catch-up follows comparison admission")
                .unwrap()
                .unwrap();
            assert!(
                storage
                    .transport_reconciliation_replay_cursor(&recovery_route)
                    .unwrap()
                    .is_some(),
                "the held comparison proposal was admitted before catch-up revised it"
            );
            timeout(Duration::from_secs(5), mutation)
                .await
                .expect("later mutation follows explicit catch-up")
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), drain)
                .await
                .expect("drain follows explicit catch-up")
                .unwrap();
        }
        runtime.shutdown_and_close().await.unwrap();
    }
    gate.hold_exact.store(false, Ordering::SeqCst);
    gate.release.notify_waiters();
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS
    );
}

#[tokio::test]
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
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let pool = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let storage = app.account_storage(&account.label).unwrap();
    let credits = bounded_recovery::hold_all_credits_for_test(&pool);
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

#[tokio::test]
async fn comparison_offworker_valid_result_admitted_only_after_owner_join() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
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
    runtime
        .send_message(&bob.label, &group, b"offworker admission target".to_vec())
        .await
        .unwrap();
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
    let storage = app.account_storage(&alice.label).unwrap();
    client.request_bounded_comparison().unwrap();
    client.recovery_owner.test_advance_to_retry(&storage);
    let grant = client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
        .unwrap()
        .unwrap();
    assert!(client.comparison_offload_eligible(&grant).unwrap());
    let attempt = client.activate_comparison_grant(&grant).await.unwrap();
    let credit = bounded_recovery::try_acquire_recovery_credit(&pool).unwrap();
    let mut job = ComparisonNetworkJob::start(&client, &grant, credit).unwrap();
    let (credit, network) = timeout(Duration::from_secs(12), job.wait())
        .await
        .unwrap()
        .unwrap();
    let inventory = storage
        .transport_reconciliation_inventory(&recovery_route, crate::unix_now_seconds())
        .unwrap();
    let before = inventory
        .items
        .iter()
        .map(|item| item.event_id)
        .collect::<std::collections::HashSet<_>>();
    assert!(
        timeout(Duration::from_millis(100), client.receive_next_delivery())
            .await
            .is_err()
    );
    let result = client
        .finish_comparison_grant(grant, attempt, network)
        .await
        .unwrap();
    drop(credit);
    assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
    let after = storage
        .transport_reconciliation_inventory(&recovery_route, crate::unix_now_seconds())
        .unwrap();
    assert!(
        after
            .items
            .iter()
            .any(|item| !before.contains(&item.event_id)),
        "one valid owned comparison event enters durable route inventory only after owner join"
    );
    drop(client);
    runtime.shutdown_and_close().await.unwrap();
}
