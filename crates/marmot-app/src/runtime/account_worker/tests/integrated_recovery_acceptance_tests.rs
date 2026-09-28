//! Composed startup recovery with valid MLS history, a truthful relay inventory,
//! and a cold SQLCipher reopen. The relay fixture withholds one commit from
//! ordinary broad replay; the SDK's exact-ID and NIP-77 paths remain real.

use super::*;
use nostr_relay_builder::prelude::{
    Backend, BoxedFuture, DatabaseError, DatabaseEventStatus, Event, EventId, Events,
    Filter as RelayFilter, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, PolicyResult,
    QueryPolicy, SaveEventStatus, SingleLetterTag, Timestamp as RelayTimestamp,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{
    Client as NostrSdkClient, EventBuilder, Filter, FinalizeEvent, Keys, Kind, RelayCapabilities,
    ReqTarget, Tag,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Clone, Debug)]
struct RetainedHistoryRelay {
    inner: MemoryDatabase,
    route: Arc<Mutex<Option<String>>>,
    ordinary_cutoff: Arc<Mutex<Option<RelayTimestamp>>>,
    broad_queries: Arc<AtomicUsize>,
}

impl NostrDatabase for RetainedHistoryRelay {
    fn backend(&self) -> Backend {
        self.inner.backend()
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> BoxedFuture<'a, Result<SaveEventStatus, DatabaseError>> {
        self.inner.save_event(event)
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxedFuture<'a, Result<DatabaseEventStatus, DatabaseError>> {
        self.inner.check_id(event_id)
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxedFuture<'a, Result<Option<Event>, DatabaseError>> {
        self.inner.event_by_id(event_id)
    }

    fn count(&self, filter: RelayFilter) -> BoxedFuture<'_, Result<usize, DatabaseError>> {
        self.inner.count(filter)
    }

    fn query(&self, mut filter: RelayFilter) -> BoxedFuture<'_, Result<Events, DatabaseError>> {
        Box::pin(async move {
            let route = self.route.lock().unwrap().clone();
            let cutoff = *self.ordinary_cutoff.lock().unwrap();
            let ordinary_group = filter.ids.is_none()
                && route.as_ref().is_some_and(|route| {
                    filter
                        .generic_tags
                        .get(&SingleLetterTag::from_char('h').unwrap())
                        .is_some_and(|values| values.contains(route))
                });
            if ordinary_group && let Some(cutoff) = cutoff {
                self.broad_queries.fetch_add(1, Ordering::SeqCst);
                filter.since = Some(filter.since.map_or(cutoff, |since| since.max(cutoff)));
            }
            self.inner.query(filter).await
        })
    }

    fn negentropy_items(
        &self,
        filter: RelayFilter,
    ) -> BoxedFuture<'_, Result<Vec<(EventId, RelayTimestamp)>, DatabaseError>> {
        // Inventory is the backing relay's complete retained set, including
        // the withheld commit. A completed NEG exchange is therefore honest.
        self.inner.negentropy_items(filter)
    }

    fn delete(&self, filter: RelayFilter) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.delete(filter)
    }

    fn wipe(&self) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.wipe()
    }
}

#[derive(Clone, Debug, Default)]
struct HeldCommitRequest {
    target: Arc<Mutex<Option<String>>>,
    hold: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    active: Arc<AtomicUsize>,
    hits: Arc<AtomicUsize>,
}

struct ActiveRequest(Arc<AtomicUsize>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl HeldCommitRequest {
    fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

struct ReleaseOnDrop(HeldCommitRequest);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl QueryPolicy for HeldCommitRequest {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let target = self.target.lock().unwrap().clone();
            if target.as_ref().is_some_and(|wanted| {
                query
                    .ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| id.to_hex() == *wanted))
            }) {
                self.hits.fetch_add(1, Ordering::SeqCst);
                if self.hold.load(Ordering::SeqCst) {
                    let released = self.release.notified();
                    tokio::pin!(released);
                    released.as_mut().enable();
                    self.active.fetch_add(1, Ordering::SeqCst);
                    let _active = ActiveRequest(self.active.clone());
                    self.entered.notify_one();
                    released.await;
                }
            }
            PolicyResult::Accept
        })
    }
}

#[derive(Clone, Debug, Default)]
struct HeldBroadQuery {
    hold: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    active: Arc<AtomicUsize>,
}

impl HeldBroadQuery {
    fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

struct ReleaseBroadOnDrop(HeldBroadQuery);

impl Drop for ReleaseBroadOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl QueryPolicy for HeldBroadQuery {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if query.ids.is_none() && self.hold.load(Ordering::SeqCst) {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                self.active.fetch_add(1, Ordering::SeqCst);
                let _active = ActiveRequest(self.active.clone());
                self.entered.notify_one();
                released.await;
            }
            PolicyResult::Accept
        })
    }
}

async fn group_events(
    inspector: &NostrSdkClient,
    url: &str,
    route: &[u8; 32],
) -> Vec<nostr_sdk::prelude::Event> {
    inspector
        .fetch_events(ReqTarget::single(
            url,
            [Filter::new().kind(Kind::MlsGroupMessage)],
        ))
        .timeout(Duration::from_secs(5))
        .await
        .unwrap()
        .into_iter()
        .filter(|event| {
            let transport =
                transport_nostr_peeler::NostrTransportEvent::from_nostr_event(event).unwrap();
            matches!(
                transport.to_transport_message().unwrap().envelope,
                cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id }
                    if transport_group_id.as_slice() == route
            )
        })
        .collect()
}

#[tokio::test]
async fn startup_gap_recovers_real_mls_history_and_survives_sqlcipher_reopen() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldCommitRequest::default();
    let _release_on_drop = ReleaseOnDrop(gate.clone());
    let database = RetainedHistoryRelay {
        inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(256),
        }),
        route: Arc::new(Mutex::new(None)),
        ordinary_cutoff: Arc::new(Mutex::new(None)),
        broad_queries: Arc::new(AtomicUsize::new(0)),
    };
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .query_policy(gate.clone())
            .database(database.clone()),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let healthy_relay = LocalRelay::new(RelayBuilder::default());
    healthy_relay.run().await.unwrap();
    let healthy_url = healthy_relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let config = crate::MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_settlement_quiescence_ms(100)
        .with_dev_epoch_backfill_retry_backoff_ms(100);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let mut groups = Vec::new();
    for (title, group_relay) in [
        ("recovery target", &url),
        ("healthy live route", &healthy_url),
    ] {
        groups.push(
            runtime
                .create_group_with_options(
                    &alice.label,
                    title,
                    std::slice::from_ref(&bob.account_id_hex),
                    AppCreateGroupOptions {
                        relays: Some(vec![group_relay.clone()]),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        );
    }
    timeout(Duration::from_secs(20), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if groups.iter().all(|group| {
                app.group(&bob.label, &hex::encode(group))
                    .unwrap()
                    .is_some()
            }) {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Bob joins both real MLS groups");
    runtime
        .promote_admin(&alice.label, &groups[0], &bob.account_id_hex)
        .await
        .unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if runtime
                .group_mls_state(&alice.label, &groups[0])
                .await
                .unwrap()
                .epoch
                == runtime
                    .group_mls_state(&bob.label, &groups[0])
                    .await
                    .unwrap()
                    .epoch
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Bob receives admin promotion");
    let initial_epoch = runtime
        .group_mls_state(&alice.label, &groups[0])
        .await
        .unwrap()
        .epoch;
    let route: [u8; 32] = hex::decode(
        app.group(&alice.label, &hex::encode(&groups[0]))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    *database.route.lock().unwrap() = Some(hex::encode(route));
    let inspector = NostrSdkClient::builder().build();
    inspector
        .add_relay(url.clone())
        .capabilities(RelayCapabilities::READ)
        .await
        .unwrap();
    inspector.connect().await;
    let before = group_events(&inspector, &url, &route)
        .await
        .into_iter()
        .map(|event| event.id)
        .collect::<HashSet<_>>();
    runtime
        .accounts()
        .deactivate_account(&alice.label)
        .await
        .unwrap();
    runtime
        .update_group_profile(&bob.label, &groups[0], Some("missing commit".into()), None)
        .await
        .unwrap();
    let missing = group_events(&inspector, &url, &route)
        .await
        .into_iter()
        .find(|event| !before.contains(&event.id))
        .expect("first real MLS commit is retained by relay");
    // Nostr timestamps have one-second resolution. Put the later valid MLS
    // history strictly after the withheld commit so the broad-query fixture
    // can exclude only the earlier second without falsifying NEG inventory.
    sleep(Duration::from_secs(1)).await;
    runtime
        .update_group_profile(&bob.label, &groups[0], Some("later commit".into()), None)
        .await
        .unwrap();
    for index in 0..8 {
        runtime
            .send_message(
                &bob.label,
                &groups[0],
                format!("recovered future {index}").into_bytes(),
            )
            .await
            .unwrap();
    }
    let bob_epoch = runtime
        .group_mls_state(&bob.label, &groups[0])
        .await
        .unwrap()
        .epoch;
    assert!(bob_epoch >= initial_epoch + 2);
    let future = group_events(&inspector, &url, &route)
        .await
        .into_iter()
        .filter(|event| !before.contains(&event.id) && event.id != missing.id)
        .collect::<Vec<_>>();
    assert_eq!(
        future.len(),
        9,
        "one later commit plus eight encrypted messages"
    );
    assert!(
        future
            .iter()
            .all(|event| event.created_at > missing.created_at)
    );
    assert!(
        database
            .inner
            .event_by_id(&EventId::from_byte_array(missing.id.to_bytes()))
            .await
            .unwrap()
            .is_some(),
        "the relay retains the withheld event"
    );
    *database.ordinary_cutoff.lock().unwrap() =
        Some(RelayTimestamp::from_secs(missing.created_at.as_secs() + 1));
    *gate.target.lock().unwrap() = Some(missing.id.to_hex());
    gate.hold.store(true, Ordering::SeqCst);
    runtime
        .accounts()
        .deactivate_account(&bob.label)
        .await
        .unwrap();
    runtime.shutdown_and_close().await.unwrap();
    drop(runtime);
    drop(app);

    let reopened_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let reopened = crate::MarmotAppRuntime::new(reopened_app.clone());
    let pool = reopened
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    let activity = crate::client::TestComparisonActivityWitness::default();
    *reopened
        .shared_services()
        .comparison_activity_witness
        .lock()
        .unwrap() = Some((alice.label.clone(), activity.clone()));
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let starting = reopened.clone();
    let alice_label = alice.label.clone();
    let startup = tokio::spawn(async move {
        starting
            .accounts()
            .sign_in_account(&alice_label)
            .await
            .unwrap();
        starting.reconcile_accounts().await.unwrap();
    });
    if timeout(Duration::from_secs(30), &mut entered)
        .await
        .is_err()
    {
        let storage = reopened_app.account_storage(&alice.label).unwrap();
        panic!(
            "startup exact request absent: hits={} broad={} active={} epoch={} target={} retry={:?} comparison_pending={} comparison_attempt={} demands={:?} messages={:?}",
            gate.hits.load(Ordering::SeqCst),
            database.broad_queries.load(Ordering::SeqCst),
            gate.active.load(Ordering::SeqCst),
            reopened
                .group_mls_state(&alice.label, &groups[0])
                .await
                .unwrap()
                .epoch,
            bob_epoch,
            storage.recovery_retry_state().unwrap(),
            storage.recovery_comparison().unwrap().pending(),
            storage.recovery_comparison().unwrap().attempt_serial,
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .map(|d| (&d.cause, &d.eligibility))
                .collect::<Vec<_>>(),
            reopened_app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .map(|m| m.plaintext.clone())
                .collect::<Vec<_>>(),
        );
    }
    assert!(gate.active.load(Ordering::SeqCst) > 0);
    assert_eq!(activity.active_jobs.load(Ordering::SeqCst), 1);
    assert_eq!(activity.active_requests.load(Ordering::SeqCst), 1);
    assert!(activity.attempt_serial.load(Ordering::SeqCst) > 0);
    assert_eq!(
        activity.attempt_serial.load(Ordering::SeqCst),
        reopened_app
            .account_storage(&alice.label)
            .unwrap()
            .recovery_retry_state()
            .unwrap()
            .attempt_serial,
    );
    let entered_at = Instant::now();
    let commands = reopened
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, mut answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    let status_within_300_ms = match timeout(Duration::from_millis(300), &mut answer).await {
        Ok(response) => {
            response.unwrap().unwrap();
            true
        }
        Err(_) => false,
    };
    assert!(
        status_within_300_ms,
        "startup status serves during the owned SDK request"
    );
    assert!(gate.active.load(Ordering::SeqCst) > 0);
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS - 1,
        "the worker task still owns its shared credit after answering status"
    );
    assert!(entered_at.elapsed() < Duration::from_secs(2));
    timeout(
        Duration::from_secs(2),
        reopened.send_message(&alice.label, &groups[1], b"send while recovering".to_vec()),
    )
    .await
    .expect("healthy-group send finishes before the held recovery request")
    .expect("healthy-group send succeeds");
    assert_eq!(gate.active.load(Ordering::SeqCst), 1);
    assert_eq!(activity.active_jobs.load(Ordering::SeqCst), 1);
    assert_eq!(activity.active_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS - 1,
    );
    timeout(
        Duration::from_millis(300),
        reopened.group_mls_state(&alice.label, &groups[1]),
    )
    .await
    .expect("startup snapshot group read remains ready during acquisition")
    .unwrap();
    let (catch_up_respond, mut catch_up_answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::CatchUp {
            respond: catch_up_respond,
        })
        .unwrap();
    let (ordered_respond, mut ordered_answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond: ordered_respond,
        })
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), &mut ordered_answer)
            .await
            .is_err(),
        "a status behind a startup CatchUp barrier stays in FIFO"
    );
    assert!(
        timeout(Duration::from_millis(100), &mut catch_up_answer)
            .await
            .is_err(),
        "coalesced CatchUp waits for the initial comparison"
    );
    let mut bob_client = reopened_app.client(&bob.label).await.unwrap();
    bob_client
        .send_custom_event(
            &groups[1],
            22_222,
            Vec::new(),
            "live while recovering".into(),
        )
        .await
        .unwrap();
    drop(bob_client);
    let live_received = timeout(Duration::from_secs(2), async {
        loop {
            if reopened_app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .any(|message| {
                    message.kind == 22_222 && message.plaintext == "live while recovering"
                })
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if live_received.is_err() {
        let healthy_route: [u8; 32] = hex::decode(
            reopened_app
                .group(&alice.label, &hex::encode(&groups[1]))
                .unwrap()
                .unwrap()
                .nostr_routing
                .nostr_group_id_hex,
        )
        .unwrap()
        .try_into()
        .unwrap();
        inspector
            .add_relay(healthy_url.clone())
            .capabilities(RelayCapabilities::READ)
            .await
            .unwrap();
        inspector.connect().await;
        let relay_events = group_events(&inspector, &healthy_url, &healthy_route).await;
        panic!(
            "healthy live receipt absent: relay_events={} alice_messages={:?} credit={} exact_active={} comparison_pending={} demands={:?}",
            relay_events.len(),
            reopened_app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .map(|m| (m.kind, m.plaintext.clone()))
                .collect::<Vec<_>>(),
            bounded_recovery::available_credits(&pool),
            gate.active.load(Ordering::SeqCst),
            reopened_app
                .account_storage(&alice.label)
                .unwrap()
                .recovery_comparison()
                .unwrap()
                .pending(),
            reopened_app
                .account_storage(&alice.label)
                .unwrap()
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .map(|d| (&d.cause, &d.eligibility))
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(gate.active.load(Ordering::SeqCst), 1);
    assert_eq!(activity.active_jobs.load(Ordering::SeqCst), 1);
    assert_eq!(activity.active_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS - 1,
    );
    let storage = reopened_app.account_storage(&alice.label).unwrap();
    let route_key = storage_sqlite::TransportReconciliationRoute::Group(route);
    timeout(Duration::from_secs(15), async {
        loop {
            if storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == storage_sqlite::RecoveryCause::EpochGap)
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("ordinary later MLS deliveries durably arm a natural EpochGap");
    assert!(database.broad_queries.load(Ordering::SeqCst) > 0);
    assert!(
        !storage
            .retained_recovery_event(
                &route_key,
                &missing.id.to_bytes(),
                None,
                crate::unix_now_seconds(),
            )
            .unwrap()
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .all(|demand| demand.cause != storage_sqlite::RecoveryCause::KnownEvent)
    );
    gate.release();
    timeout(Duration::from_secs(20), catch_up_answer)
        .await
        .expect("coalesced catch-up completes after release")
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(20), ordered_answer)
        .await
        .expect("status after catch-up runs in arrival order")
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(15), startup)
        .await
        .expect("startup joins after release")
        .unwrap();
    assert_eq!(activity.active_jobs.load(Ordering::SeqCst), 0);
    assert_eq!(activity.active_requests.load(Ordering::SeqCst), 0);
    timeout(Duration::from_secs(45), async {
        loop {
            if reopened
                .group_mls_state(&alice.label, &groups[0])
                .await
                .unwrap()
                .epoch
                >= bob_epoch
                && (0..8).all(|index| {
                    reopened_app
                        .messages(&alice.label)
                        .unwrap()
                        .iter()
                        .any(|message| message.plaintext == format!("recovered future {index}"))
                })
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("natural worker recovery admits and decrypts genuine MLS history");
    assert!(
        storage
            .retained_recovery_event(
                &route_key,
                &missing.id.to_bytes(),
                None,
                crate::unix_now_seconds(),
            )
            .unwrap()
    );
    reopened.shutdown_and_close().await.unwrap();
    drop(reopened);
    drop(storage);
    drop(reopened_app);

    let final_app = MarmotApp::with_relay_and_config(dir.path(), url, config);
    let final_runtime = crate::MarmotAppRuntime::new(final_app.clone());
    final_runtime.reconcile_accounts().await.unwrap();
    assert!(
        final_runtime
            .group_mls_state(&alice.label, &groups[0])
            .await
            .unwrap()
            .epoch
            >= bob_epoch
    );
    assert!(
        (0..8).all(|index| {
            final_app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .any(|message| message.plaintext == format!("recovered future {index}"))
        }),
        "all decrypted timeline rows survive the SQLCipher reopen"
    );
    assert!(
        final_app
            .account_storage(&alice.label)
            .unwrap()
            .retained_recovery_event(
                &route_key,
                &missing.id.to_bytes(),
                None,
                crate::unix_now_seconds(),
            )
            .unwrap()
    );
    final_runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
    healthy_relay.shutdown();
}

#[tokio::test]
async fn startup_comparison_waits_for_credit_before_reserving_retry() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("capacity startup")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url,
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let pool = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    let held = bounded_recovery::hold_all_credits_for_test(&pool);
    runtime.reconcile_accounts().await.unwrap();
    let commands = runtime
        .accounts()
        .worker_commands(&account.label)
        .await
        .unwrap();
    let (respond, answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::NetworkStartupSettled { respond })
        .unwrap();
    timeout(Duration::from_secs(15), answer)
        .await
        .expect("startup serves deferred command with a saturated shared pool")
        .unwrap();
    let storage = app.account_storage(&account.label).unwrap();
    assert_eq!(storage.recovery_retry_state().unwrap().attempt_serial, 0);
    assert!(storage.recovery_comparison().unwrap().pending());
    assert_eq!(bounded_recovery::available_credits(&pool), 0);
    drop(held);
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}

#[tokio::test]
async fn startup_inline_wait_releases_unused_comparison_credit() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldBroadQuery::default();
    let _release_on_drop = ReleaseBroadOnDrop(gate.clone());
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(gate.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("inline startup")
        .unwrap();
    let config = crate::MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_cursor_persistence(crate::CursorPersistence::Frozen);
    let initial_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let initial = crate::MarmotAppRuntime::new(initial_app.clone());
    initial.reconcile_accounts().await.unwrap();
    initial
        .create_group_with_options(
            &account.label,
            "inline route",
            &[],
            AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    initial.shutdown_and_close().await.unwrap();
    drop(initial);
    drop(initial_app);

    // Frozen policy starts no comparison grant, but its ordinary startup
    // activation still issues a broad relay query and waits inline.
    gate.hold.store(true, Ordering::SeqCst);
    let app = MarmotApp::with_relay_and_config(dir.path(), url, config);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let pool = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .expect("ordinary startup query entered the held relay policy");
    assert!(gate.active.load(Ordering::SeqCst) > 0);
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        2,
        "inline startup returned its speculative credit before the held query finishes"
    );
    assert_eq!(
        app.account_storage(&account.label)
            .unwrap()
            .recovery_retry_state()
            .unwrap()
            .attempt_serial,
        0,
        "the no-grant fallback did not spend a recovery reservation"
    );

    let commands = runtime
        .accounts()
        .worker_commands(&account.label)
        .await
        .unwrap();
    let (respond, mut answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::NetworkStartupSettled { respond })
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), &mut answer)
            .await
            .is_err(),
        "the inline startup remains blocked while its credit is already free"
    );
    gate.release();
    timeout(Duration::from_secs(15), answer)
        .await
        .expect("inline startup completes after query release")
        .unwrap();
    assert_eq!(bounded_recovery::available_credits(&pool), 2);
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}

#[tokio::test]
async fn startup_comparison_shutdown_reaps_owned_request_and_keeps_debt() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldCommitRequest::default();
    let _release_on_drop = ReleaseOnDrop(gate.clone());
    let database = RetainedHistoryRelay {
        inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(64),
        }),
        route: Arc::new(Mutex::new(None)),
        ordinary_cutoff: Arc::new(Mutex::new(None)),
        broad_queries: Arc::new(AtomicUsize::new(0)),
    };
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .query_policy(gate.clone())
            .database(database.clone()),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("cancel startup")
        .unwrap();
    let config = crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let initial_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let initial = crate::MarmotAppRuntime::new(initial_app.clone());
    initial.reconcile_accounts().await.unwrap();
    let group = initial
        .create_group_with_options(
            &account.label,
            "cancel comparison",
            &[],
            AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let route = initial_app
        .group(&account.label, &hex::encode(&group))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    *database.route.lock().unwrap() = Some(route.clone());
    initial.shutdown_and_close().await.unwrap();
    drop(initial);
    drop(initial_app);

    let signed = EventBuilder::new(Kind::MlsGroupMessage, "request held at relay")
        .tags([Tag::custom("h", [route])])
        .finalize(&Keys::generate())
        .unwrap();
    database
        .inner
        .save_event(&serde_json::from_value(serde_json::to_value(&signed).unwrap()).unwrap())
        .await
        .unwrap();
    *database.ordinary_cutoff.lock().unwrap() =
        Some(RelayTimestamp::from_secs(signed.created_at.as_secs() + 1));
    *gate.target.lock().unwrap() = Some(signed.id.to_hex());
    gate.hold.store(true, Ordering::SeqCst);

    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let pool = runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    let activity = crate::client::TestComparisonActivityWitness::default();
    *runtime
        .shared_services()
        .comparison_activity_witness
        .lock()
        .unwrap() = Some((account.label.clone(), activity.clone()));
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    runtime
        .accounts()
        .sign_in_account(&account.label)
        .await
        .unwrap();
    runtime.reconcile_accounts().await.unwrap();
    if timeout(Duration::from_secs(20), &mut entered)
        .await
        .is_err()
    {
        let storage = app.account_storage(&account.label).unwrap();
        panic!(
            "startup cancellation request absent: hits={} active={} jobs={} requests={} retry={:?} comparison_pending={} demands={:?}",
            gate.hits.load(Ordering::SeqCst),
            gate.active.load(Ordering::SeqCst),
            activity.active_jobs.load(Ordering::SeqCst),
            activity.active_requests.load(Ordering::SeqCst),
            storage.recovery_retry_state().unwrap(),
            storage.recovery_comparison().unwrap().pending(),
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .map(|d| (&d.cause, &d.eligibility))
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(activity.active_jobs.load(Ordering::SeqCst), 1);
    assert_eq!(activity.active_requests.load(Ordering::SeqCst), 1);
    let retry = app
        .account_storage(&account.label)
        .unwrap()
        .recovery_retry_state()
        .unwrap()
        .attempt_serial;
    assert!(retry > 0);
    timeout(Duration::from_secs(15), runtime.shutdown_and_close())
        .await
        .expect("shutdown reaps the startup comparison without relay release")
        .unwrap();
    assert_eq!(activity.active_jobs.load(Ordering::SeqCst), 0);
    assert_eq!(activity.active_requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS,
    );
    drop(runtime);
    drop(app);
    gate.release();
    let reopened = MarmotApp::with_relay_and_config(dir.path(), url, config);
    let storage = reopened.account_storage(&account.label).unwrap();
    assert_eq!(
        storage.recovery_retry_state().unwrap().attempt_serial,
        retry
    );
    assert!(storage.recovery_comparison().unwrap().pending());
    relay.shutdown();
}
