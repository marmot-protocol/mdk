//! A naturally requested startup comparison can remain pending when a stored
//! convergence pass becomes due. This fixture uses the real SDK relay path.

use super::*;
use cgka_traits::storage::ConvergencePassStorage;
use nostr_relay_builder::prelude::{
    Backend, BoxedFuture, DatabaseError, DatabaseEventStatus, Event, EventId, Events,
    Filter as RelayFilter, JsonUtil, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase,
    PolicyResult, QueryPolicy, SaveEventStatus, Timestamp as RelayTimestamp,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp as SdkTimestamp};
use std::net::SocketAddr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct HeldConvergence(String);

#[derive(Clone, Debug)]
struct ObservedNegentropyDatabase {
    inner: MemoryDatabase,
    route_hex: Arc<Mutex<Option<String>>>,
    hold: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl NostrDatabase for ObservedNegentropyDatabase {
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

    fn query(&self, filter: RelayFilter) -> BoxedFuture<'_, Result<Events, DatabaseError>> {
        self.inner.query(filter)
    }

    fn negentropy_items(
        &self,
        filter: RelayFilter,
    ) -> BoxedFuture<'_, Result<Vec<(EventId, RelayTimestamp)>, DatabaseError>> {
        Box::pin(async move {
            let target = self.route_hex.lock().unwrap().clone();
            if self.hold.load(Ordering::SeqCst)
                && target
                    .as_ref()
                    .is_some_and(|target| filter.as_json().contains(target))
            {
                let release = self.release.notified();
                tokio::pin!(release);
                release.as_mut().enable();
                self.entered.notify_one();
                release.await;
            }
            self.inner.negentropy_items(filter).await
        })
    }

    fn delete(&self, filter: RelayFilter) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.delete(filter)
    }

    fn wipe(&self) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.wipe()
    }
}

impl HeldConvergence {
    fn for_account(id: &str) -> Self {
        assert!(
            HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
                .lock()
                .unwrap()
                .insert(id.to_owned())
        );
        Self(id.to_owned())
    }
}

impl Drop for HeldConvergence {
    fn drop(&mut self) {
        HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
            .lock()
            .unwrap()
            .remove(&self.0);
    }
}

#[derive(Clone, Debug, Default)]
struct HeldExact {
    target: Arc<Mutex<Option<String>>>,
    held: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    hits: Arc<AtomicUsize>,
    exact_queries: Arc<AtomicUsize>,
}

impl QueryPolicy for HeldExact {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if query.ids.is_some() {
                self.exact_queries.fetch_add(1, Ordering::SeqCst);
            }
            let wanted = self.target.lock().unwrap().clone();
            if wanted.as_ref().is_some_and(|wanted| {
                query
                    .ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| id.to_hex() == *wanted))
            }) {
                self.hits.fetch_add(1, Ordering::SeqCst);
                if self.held.load(Ordering::SeqCst) {
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
async fn naturally_pending_startup_comparison_resumes_after_scheduled_convergence() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldExact::default();
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(64),
    });
    let negentropy = ObservedNegentropyDatabase {
        inner: database.clone(),
        route_hex: Arc::new(Mutex::new(None)),
        hold: Arc::new(AtomicBool::new(false)),
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
    };
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .query_policy(gate.clone())
            .database(negentropy.clone()),
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
        .with_dev_scheduled_convergence_delay_ms(500)
        .with_dev_epoch_backfill_retry_backoff_ms(100);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "due before reopen",
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
    .expect("Bob joins the real MLS group");
    runtime
        .promote_admin(&alice.label, &group, &bob.account_id_hex)
        .await
        .unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if runtime
                .group_mls_state(&alice.label, &group)
                .await
                .unwrap()
                .epoch
                == runtime
                    .group_mls_state(&bob.label, &group)
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
    let hold = HeldConvergence::for_account(&alice.account_id_hex);
    runtime
        .update_group_profile(&bob.label, &group, Some("changed".into()), None)
        .await
        .unwrap();
    let storage = app.account_storage(&alice.label).unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            if storage.convergence_pass(&group).unwrap().is_some() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ordinary delivery durably arms the scheduled pass");

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
    *negentropy.route_hex.lock().unwrap() = Some(hex::encode(route));
    let event = EventBuilder::new(Kind::MlsGroupMessage, "comparison-only probe")
        .tags([Tag::custom("h", [hex::encode(route)])])
        // This is inside the comparison inventory window, but older than the
        // ordinary reopened subscription's 120-second cursor overlap.
        .custom_created_at(SdkTimestamp::from_secs(crate::unix_now_seconds() - 3_600))
        .finalize(&Keys::generate())
        .unwrap();
    database
        .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
        .await
        .unwrap();
    *gate.target.lock().unwrap() = Some(event.id.to_hex());
    gate.held.store(true, Ordering::SeqCst);
    runtime.shutdown_and_close().await.unwrap();
    drop(runtime);
    drop(storage);
    drop(app);

    let reopened_app = MarmotApp::with_relay_and_config(dir.path(), url, config);
    let reopened = crate::MarmotAppRuntime::new(reopened_app.clone());
    let pool = reopened
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    let pass_barrier = Arc::new(tokio::sync::Barrier::new(2));
    reopened
        .shared_services()
        .set_next_scheduled_convergence_barrier(pass_barrier.clone());
    let first_request = gate.entered.notified();
    tokio::pin!(first_request);
    first_request.as_mut().enable();
    reopened.reconcile_accounts().await.unwrap();
    if timeout(Duration::from_secs(20), &mut first_request)
        .await
        .is_err()
    {
        let storage = reopened_app.account_storage(&alice.label).unwrap();
        let slot = storage.recovery_comparison().unwrap();
        panic!(
            "startup exact request absent: hits={} exact={} slot_pending={} slot_attempt={} slot_frozen={} retry={:?} demands={:?} trace={:?}",
            gate.hits.load(Ordering::SeqCst),
            gate.exact_queries.load(Ordering::SeqCst),
            slot.pending(),
            slot.attempt_serial,
            slot.frozen_revision,
            storage.recovery_retry_state().unwrap(),
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .map(|d| d.cause)
                .collect::<Vec<_>>(),
            reopened
                .shared_services()
                .comparison_test_trace
                .lock()
                .unwrap(),
        );
    }
    assert!(gate.hits.load(Ordering::SeqCst) >= 1);
    // The first periodic tick is immediately ready after startup. Keep the
    // already-durable local pass held until that first comparison attempt has
    // fully joined, so it cannot be mistaken for the scheduled caller.
    timeout(Duration::from_secs(35), async {
        loop {
            let trace = reopened
                .shared_services()
                .comparison_test_trace
                .lock()
                .unwrap()
                .clone();
            if trace.contains(&"task_started")
                && trace.contains(&"route_relay_failed")
                && bounded_recovery::available_credits(&pool)
                    == bounded_recovery::MAX_CONCURRENT_JOBS
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first periodic comparison joins before scheduled pass release");
    drop(hold);
    timeout(Duration::from_secs(20), pass_barrier.wait())
        .await
        .expect("stored scheduled convergence starts after startup comparison");
    let reopened_storage = reopened_app.account_storage(&alice.label).unwrap();
    let slot = reopened_storage.recovery_comparison().unwrap();
    assert!(slot.pending());
    assert_ne!(
        slot.blocked_route_revision,
        Some(
            reopened_storage
                .recovery_revision_fence()
                .unwrap()
                .route_revision
        ),
        "pending comparison is blocked on this route revision before the scheduled caller"
    );
    let before_attempt = slot.attempt_serial;
    let retry = reopened_storage.recovery_retry_state().unwrap();
    let now = crate::client::recovery::wall_now_ms().unwrap();
    let due_in = retry.not_before_ms.saturating_sub(now);
    sleep(Duration::from_millis(due_in + 200)).await;
    gate.held.store(false, Ordering::SeqCst);
    gate.release.notify_waiters();
    negentropy.hold.store(true, Ordering::SeqCst);
    let neg_entered = negentropy.entered.notified();
    tokio::pin!(neg_entered);
    neg_entered.as_mut().enable();
    pass_barrier.wait().await;
    timeout(Duration::from_secs(8), async {
        while reopened_storage
            .recovery_comparison()
            .unwrap()
            .attempt_serial
            <= before_attempt
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scheduled caller reserves the still-pending comparison");
    let selected = reopened_storage.recovery_comparison().unwrap();
    assert!(selected.pending());
    assert_eq!(selected.frozen_revision, selected.revision);
    assert!(selected.plan.is_some());
    timeout(Duration::from_secs(8), &mut neg_entered)
        .await
        .expect("selected scheduled comparison enters the relay NEG-OPEN database query");
    let commands = reopened
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(2), answer)
        .await
        .expect("status command completes during the held scheduled comparison")
        .unwrap()
        .unwrap();
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS - 1,
        "the scheduled comparison still owns its shared credit while the relay is held"
    );
    assert_eq!(
        reopened_storage
            .recovery_retry_state()
            .unwrap()
            .attempt_serial,
        selected.attempt_serial,
        "serving a command does not reserve another recovery grant"
    );
    assert!(reopened_storage.recovery_comparison().unwrap().pending());
    negentropy.hold.store(false, Ordering::SeqCst);
    negentropy.release.notify_waiters();
    timeout(Duration::from_secs(15), async {
        while bounded_recovery::available_credits(&pool) != bounded_recovery::MAX_CONCURRENT_JOBS {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the scheduled comparison joins and releases its shared credit");
    reopened.shutdown_and_close().await.unwrap();
    relay.shutdown();
}
