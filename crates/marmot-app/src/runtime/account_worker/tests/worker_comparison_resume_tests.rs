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
}

impl QueryPolicy for HeldComparisonId {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
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
    run_held_comparison(false).await;
}

#[tokio::test]
async fn comparison_shutdown_reaps_task_and_releases_credit() {
    run_held_comparison(true).await;
}

async fn run_held_comparison(shutdown_while_held: bool) {
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
    *gate.target.lock().unwrap() = Some(event.id.to_hex());
    assert!(
        !storage
            .retained_recovery_event(&recovery_route, &event_id, None, crate::unix_now_seconds())
            .unwrap()
    );
    let now = crate::client::recovery::wall_now_ms().unwrap();
    let goal = storage_sqlite::RecoveryScopePlan {
        scope_id: 0,
        route_kind: 1,
        route_role: 0,
        group_id: Some(group.as_slice().to_vec()),
        transport_group_id: Some(route),
        since_seconds: Some(now / 1000 - storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS),
        until_seconds: now / 1000,
        known_event_id: None,
        inventory_floor: None,
        required_endpoints: vec![url.clone()],
        admitted_endpoints: vec![url.clone()],
    };
    storage
        .join_recovery_comparison(&[5; 16], now, &[goal])
        .unwrap();
    let before_retry = storage.recovery_retry_state().unwrap().attempt_serial;
    gate.hold_exact.store(true, Ordering::SeqCst);
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    if timeout(Duration::from_secs(12), entered).await.is_err() {
        let slot = storage.recovery_comparison().unwrap();
        panic!(
            "maintenance exact-ID wait absent: hits={}, retained={}, pending={}, attempt_delta={}, credits={}, slot_attempt={}, frozen={}, routes={}, retries={}",
            gate.hits.load(Ordering::SeqCst),
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
            bounded_recovery::available_credits(),
            slot.attempt_serial,
            slot.frozen_revision,
            slot.plan.as_ref().map_or(0, |plan| plan.routes.len()),
            slot.plan.as_ref().map_or(0, |plan| plan.retry_routes.len()),
        );
    }
    assert_eq!(
        bounded_recovery::available_credits(),
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
    if shutdown_while_held {
        runtime.shutdown_and_close().await.unwrap();
    } else {
        gate.hold_exact.store(false, Ordering::SeqCst);
        gate.release.notify_waiters();
        timeout(Duration::from_secs(12), async {
            loop {
                if bounded_recovery::available_credits() == bounded_recovery::MAX_CONCURRENT_JOBS {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("worker finishes the result and releases its credit");
        runtime.shutdown_and_close().await.unwrap();
    }
    gate.hold_exact.store(false, Ordering::SeqCst);
    gate.release.notify_waiters();
    assert_eq!(
        bounded_recovery::available_credits(),
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
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let storage = app.account_storage(&account.label).unwrap();
    let now = crate::client::recovery::wall_now_ms().unwrap();
    let goal = storage_sqlite::RecoveryScopePlan {
        scope_id: 0,
        route_kind: 0,
        route_role: 0,
        group_id: None,
        transport_group_id: None,
        since_seconds: Some(now / 1000 - storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS),
        until_seconds: now / 1000,
        known_event_id: None,
        inventory_floor: None,
        required_endpoints: vec![url.clone()],
        admitted_endpoints: vec![url],
    };
    storage
        .join_recovery_comparison(&[6; 16], now, &[goal])
        .unwrap();
    let credits = bounded_recovery::hold_all_credits_for_test();
    let before = storage.recovery_retry_state().unwrap();
    runtime
        .advance_recovery_clock_for_test(&account.label, Duration::from_secs(600))
        .await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    let commands = runtime
        .accounts()
        .worker_commands(&account.label)
        .await
        .unwrap();
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
    let mut job = ComparisonNetworkJob::start(&client, &grant).unwrap();
    let network = timeout(Duration::from_secs(12), job.wait())
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
