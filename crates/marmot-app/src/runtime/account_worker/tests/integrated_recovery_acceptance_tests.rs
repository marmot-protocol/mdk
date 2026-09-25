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
use nostr_sdk::prelude::{Client as NostrSdkClient, Filter, Kind, RelayCapabilities, ReqTarget};
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
    for title in ["recovery target", "healthy live route"] {
        groups.push(
            runtime
                .create_group_with_options(
                    &alice.label,
                    title,
                    std::slice::from_ref(&bob.account_id_hex),
                    AppCreateGroupOptions {
                        relays: Some(vec![url.clone()]),
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
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    reopened
        .accounts()
        .sign_in_account(&alice.label)
        .await
        .unwrap();
    reopened.reconcile_accounts().await.unwrap();
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
    let attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    let commands = reopened
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_millis(500), answer)
        .await
        .expect("status responds while relay handler is held")
        .unwrap()
        .unwrap();
    assert_eq!(gate.active.load(Ordering::SeqCst), 1);
    assert_eq!(
        storage.recovery_retry_state().unwrap().attempt_serial,
        attempt
    );
    // The relay handler remains active; this does not establish that the SDK
    // caller still holds its request after an attempt deadline.
    reopened
        .send_message(&alice.label, &groups[1], b"send while recovering".to_vec())
        .await
        .expect("healthy-group send remains serviceable");
    gate.release();
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
}
