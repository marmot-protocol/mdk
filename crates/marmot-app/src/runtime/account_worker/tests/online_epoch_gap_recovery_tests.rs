//! Steady-state recovery experiment with a valid missing MLS commit.
//!
//! The focused baseline run at 22f9876f recovers the commit and eight later
//! plaintext rows, but fails the unchanged 300 ms status and 2 s healthy-send
//! bounds while a Receive-selected EpochGap grant waits inline. The held relay
//! handler proves server-side activity; it is not a client request-lifetime
//! witness. The fixture's 100 ms retry override requires test-policy-overrides;
//! production starts at 15 s and caps at 5 min.

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
            if ordinary_group
                && filter.since.is_some()
                && let Some(cutoff) = cutoff
            {
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

struct ActiveRequest(Arc<AtomicUsize>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, Default)]
struct HeldBroadQuery {
    route: Arc<Mutex<Option<String>>>,
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
            let route = self.route.lock().unwrap().clone();
            let selected_group = route.as_ref().is_some_and(|route| {
                query
                    .generic_tags
                    .get(&SingleLetterTag::from_char('h').unwrap())
                    .is_some_and(|values| values.contains(route))
            });
            if query.ids.is_none()
                && query.since.is_none()
                && selected_group
                && self.hold.load(Ordering::SeqCst)
            {
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
async fn online_epoch_gap_after_completed_startup_exposes_owner_wait() {
    run_online_epoch_gap_fixture(false, false).await;
}

#[tokio::test]
async fn online_epoch_gap_suspends_expired_bounded_probe_wake() {
    run_online_epoch_gap_fixture(true, false).await;
}

#[tokio::test]
async fn online_epoch_gap_queue_join_error_settles_and_releases_credit() {
    run_online_epoch_gap_fixture(false, true).await;
}

async fn run_online_epoch_gap_fixture(bounded_probe: bool, queue_panic: bool) {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldBroadQuery::default();
    let _release_on_drop = ReleaseBroadOnDrop(gate.clone());
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
    let port = url::Url::parse(&url).unwrap().port().unwrap();
    let healthy_relay = LocalRelay::new(RelayBuilder::default());
    healthy_relay.run().await.unwrap();
    let healthy_url = healthy_relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("online alice").unwrap();
    let bob = home.create_account("online bob").unwrap();
    let config = crate::MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_settlement_quiescence_ms(100)
        .with_dev_epoch_backfill_retry_backoff_ms(100);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    let activity = crate::client::TestComparisonActivityWitness::default();
    *runtime
        .shared_services()
        .comparison_activity_witness
        .lock()
        .unwrap() = Some((alice.label.clone(), activity.clone()));
    let selections = Arc::new(Mutex::new(Vec::new()));
    let phase_witness = crate::client::TestRecoveryPhaseWitness::default();
    *runtime
        .shared_services()
        .recovery_selection_witness
        .lock()
        .unwrap() = Some(crate::runtime::RecoverySelectionWitnessTarget {
        account_label: alice.label.clone(),
        sink: selections.clone(),
    });
    *runtime
        .shared_services()
        .recovery_phase_witness
        .lock()
        .unwrap() = Some((alice.label.clone(), phase_witness.clone()));
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
    *gate.route.lock().unwrap() = Some(hex::encode(route));
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
    let commands = runtime
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (startup_respond, startup_answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::NetworkStartupSettled {
            respond: startup_respond,
        })
        .unwrap();
    timeout(Duration::from_secs(15), startup_answer)
        .await
        .expect("Alice's original worker completed startup")
        .unwrap();
    let storage = app.account_storage(&alice.label).unwrap();
    assert!(
        !storage.recovery_comparison().unwrap().pending(),
        "Alice must finish startup comparison before the induced gap"
    );
    let baseline_demands = storage.pending_recovery_demands().unwrap();
    assert_eq!(baseline_demands.len(), 1);
    assert_eq!(
        baseline_demands[0].cause,
        storage_sqlite::RecoveryCause::IncrementalHistory
    );
    assert_eq!(
        baseline_demands[0].eligibility,
        storage_sqlite::RecoveryEligibility::NeedsDeepRepair
    );
    assert!(
        storage
            .recovery_eligible_revision_fence(false)
            .unwrap()
            .obligations
            .is_empty(),
        "startup has no automatically eligible grant, while deep-repair debt remains durable"
    );
    let baseline_ticket = baseline_demands[0].ticket.id;
    selections.lock().unwrap().clear();
    runtime
        .accounts()
        .deactivate_account(&bob.label)
        .await
        .unwrap();

    // A real relay outage closes Alice's subscribed socket, but her worker and
    // account-scoped SDK stay alive. Bob opens a fresh SDK on the same relay
    // port and publishes the missing commit before Alice's reconnect.
    relay.shutdown();
    timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("old local relay listener closes");
    let restarted = LocalRelay::new(
        RelayBuilder::default()
            .port(port)
            .query_policy(gate.clone())
            .database(database.clone()),
    );
    restarted.run().await.unwrap();
    let mut bob_client = app.client(&bob.label).await.unwrap();
    bob_client
        .update_group_profile(&groups[0], Some("missing commit"), None)
        .await
        .unwrap();
    let inspector_after = NostrSdkClient::builder().build();
    inspector_after
        .add_relay(url.clone())
        .capabilities(RelayCapabilities::READ)
        .await
        .unwrap();
    inspector_after.connect().await;
    let missing = group_events(&inspector_after, &url, &route)
        .await
        .into_iter()
        .find(|event| !before.contains(&event.id))
        .expect("Bob's first valid MLS commit is retained by the restarted relay");
    *activity.target_event_id.lock().unwrap() = Some(missing.id.to_hex());
    assert!(
        database
            .inner
            .event_by_id(&EventId::from_byte_array(missing.id.to_bytes()))
            .await
            .unwrap()
            .is_some()
    );
    *database.ordinary_cutoff.lock().unwrap() =
        Some(RelayTimestamp::from_secs(missing.created_at.as_secs() + 1));
    sleep(Duration::from_secs(1)).await;
    bob_client
        .update_group_profile(&groups[0], Some("later commit"), None)
        .await
        .unwrap();
    for index in 0..6 {
        bob_client
            .send_custom_event(&groups[0], 22_222, Vec::new(), format!("future {index}"))
            .await
            .unwrap();
    }
    let first_future = group_events(&inspector_after, &url, &route)
        .await
        .into_iter()
        .filter(|event| !before.contains(&event.id) && event.id != missing.id)
        .collect::<Vec<_>>();
    assert_eq!(first_future.len(), 7, "later commit and six MLS events");
    let route_key = storage_sqlite::TransportReconciliationRoute::Group(route);
    timeout(Duration::from_secs(15), async {
        loop {
            if first_future.iter().all(|event| {
                storage
                    .retained_recovery_event(
                        &route_key,
                        &event.id.to_bytes(),
                        None,
                        crate::unix_now_seconds(),
                    )
                    .unwrap()
            }) {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Alice durably retains seven future MLS deliveries while online");
    let comparison_before_gap = storage.recovery_comparison().unwrap().pending();
    let missing_before_gap = storage
        .retained_recovery_event(
            &route_key,
            &missing.id.to_bytes(),
            None,
            crate::unix_now_seconds(),
        )
        .unwrap();
    let epoch_before_gap = runtime
        .group_mls_state(&alice.label, &groups[0])
        .await
        .unwrap()
        .epoch;
    phase_witness.arm();
    phase_witness.set_target_event_id(missing.id.to_hex());
    phase_witness.set_target_group_id(groups[0].clone());
    assert!(phase_witness.is_target_group(&groups[0]));
    gate.hold.store(true, Ordering::SeqCst);
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    for index in 6..8 {
        bob_client
            .send_custom_event(&groups[0], 22_222, Vec::new(), format!("future {index}"))
            .await
            .unwrap();
    }
    let held = timeout(Duration::from_secs(15), &mut entered).await.is_ok();
    let phase_at_relay_entry = phase_witness.active();
    let phase_age_at_relay_entry = phase_at_relay_entry.map(|phase| phase.entered_at.elapsed());
    let request_active_at_relay_entry = activity.active_requests.load(Ordering::SeqCst);
    let request_attempt_at_relay_entry = activity.attempt_serial.load(Ordering::SeqCst);
    if bounded_probe {
        runtime
            .shared_services()
            .bounded_group_recovery_enabled
            .store(true, Ordering::SeqCst);
        // The worker's probe deadline starts at activation and is already
        // expired here. A short hold keeps the selected network request live;
        // the adapter's own quantum is shorter than PROBE_INTERVAL.
        sleep(Duration::from_millis(100)).await;
        assert!(
            gate.active.load(Ordering::SeqCst) > 0,
            "the online network request remains held past the expired bounded probe deadline"
        );
    }
    let (status_respond, mut status_answer) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond: status_respond,
        })
        .unwrap();
    let status_phase_before = phase_witness.active();
    let status_request_before = activity.active_requests.load(Ordering::SeqCst);
    let status_started = Instant::now();
    let status_within_300_ms = match timeout(Duration::from_millis(300), &mut status_answer).await {
        Ok(answer) => {
            answer.unwrap().unwrap();
            true
        }
        Err(_) => false,
    };
    let status_elapsed = status_started.elapsed();
    let status_phase_after = phase_witness.active();
    let status_request_after = activity.active_requests.load(Ordering::SeqCst);
    let healthy_send =
        runtime.send_message(&alice.label, &groups[1], b"send while recovering".to_vec());
    tokio::pin!(healthy_send);
    let send_phase_before = phase_witness.active();
    let send_request_before = activity.active_requests.load(Ordering::SeqCst);
    let send_started = Instant::now();
    let send_within_2s = match timeout(Duration::from_secs(2), &mut healthy_send).await {
        Ok(result) => {
            result.unwrap();
            true
        }
        Err(_) => false,
    };
    let send_elapsed = send_started.elapsed();
    let send_phase_after = phase_witness.active();
    let send_request_after = activity.active_requests.load(Ordering::SeqCst);
    let live_phase_before = phase_witness.active();
    let live_request_before = activity.active_requests.load(Ordering::SeqCst);
    let live_started = Instant::now();
    bob_client
        .send_custom_event(
            &groups[1],
            22_223,
            Vec::new(),
            "live while recovering".into(),
        )
        .await
        .unwrap();
    let live_within_2s = timeout(
        Duration::from_secs(2).saturating_sub(live_started.elapsed()),
        async {
            loop {
                if app.messages(&alice.label).unwrap().iter().any(|message| {
                    message.kind == 22_223 && message.plaintext == "live while recovering"
                }) {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        },
    )
    .await
    .is_ok();
    let live_elapsed = live_started.elapsed();
    let live_phase_after = phase_witness.active();
    let live_request_after = activity.active_requests.load(Ordering::SeqCst);
    let active_at_probe = gate.active.load(Ordering::SeqCst);
    let request_active_at_probe = activity.active_requests.load(Ordering::SeqCst);
    // Attribution reads follow the latency probes, so synchronous SQL cannot
    // spend any of their measured windows.
    let gap_armed = timeout(Duration::from_secs(15), async {
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
    .is_ok();
    let demands_at_hold = storage.pending_recovery_demands().unwrap();
    let eligible_at_hold = storage.recovery_eligible_revision_fence(false).unwrap();
    let comparison_at_hold = storage.recovery_comparison().unwrap().pending();
    let attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    let selected = selections.lock().unwrap().clone();
    let selected_gap_only = selected.iter().any(|selection| {
        selection.attempt_serial == attempt
            && selection.comparison_revision.is_none()
            && selection.obligation_count == 1
            && matches!(
                selection.seam,
                EpochBackfillExecutionSeam::Receive | EpochBackfillExecutionSeam::Maintenance
            )
    });
    let gap_only = !comparison_before_gap
        && !comparison_at_hold
        && !missing_before_gap
        && epoch_before_gap == initial_epoch
        && demands_at_hold.iter().any(|demand| {
            demand.ticket.id == baseline_ticket
                && demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory
                && demand.eligibility == storage_sqlite::RecoveryEligibility::NeedsDeepRepair
        })
        && eligible_at_hold.obligations.len() == 1
        && demands_at_hold.iter().any(|demand| {
            demand.cause == storage_sqlite::RecoveryCause::EpochGap
                && eligible_at_hold.obligations[0] == (demand.ticket.id, demand.ticket.revision)
        })
        && selected_gap_only;
    if queue_panic {
        activity
            .panic_after_queue_submission
            .store(true, Ordering::SeqCst);
    }
    gate.release();
    if !status_within_300_ms {
        timeout(Duration::from_secs(20), status_answer)
            .await
            .expect("queued status completes after release")
            .unwrap()
            .unwrap();
    }
    if !send_within_2s {
        timeout(Duration::from_secs(20), &mut healthy_send)
            .await
            .expect("queued healthy send completes after release")
            .unwrap();
    }
    if queue_panic {
        timeout(Duration::from_secs(20), async {
            loop {
                if phase_witness
                    .target_terminals()
                    .iter()
                    .any(|terminal| terminal.attempt_serial == attempt && !terminal.result_ok)
                {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("queue JoinError settles the selected grant as failed");
        assert!(
            runtime
                .accounts()
                .worker_commands(&alice.label)
                .await
                .unwrap()
                .same_channel(&commands),
            "the same account worker survives queue JoinError"
        );
        let (respond, answer) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::GroupRecoveryStatus {
                group_id: groups[0].clone(),
                respond,
            })
            .unwrap();
        timeout(Duration::from_secs(2), answer)
            .await
            .expect("Receive tail leaves the worker responsive")
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                if bounded_recovery::available_credits(
                    &runtime.shared_services().recovery_credit_pool(),
                ) == bounded_recovery::MAX_CONCURRENT_JOBS
                {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("failed queue releases its retained recovery credit");
        let terminal = phase_witness
            .target_terminals()
            .into_iter()
            .find(|terminal| terminal.attempt_serial == attempt)
            .unwrap();
        assert!(!terminal.qualified && !terminal.result_ok);
        assert!(
            activity.matching_queued_deliveries.load(Ordering::SeqCst) > 0,
            "the queue admitted the missing commit before its JoinError"
        );
        assert!(
            terminal.deliveries + terminal.skipped > 0,
            "failure settlement preserves the admitted drain prefix"
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == storage_sqlite::RecoveryCause::EpochGap)
        );
        let trace = runtime
            .shared_services()
            .comparison_test_trace
            .lock()
            .unwrap()
            .clone();
        assert!(
            trace.contains(&"online_queue_started") && trace.contains(&"online_terminal"),
            "the worker reached the failed queue completion and terminal"
        );
        assert!(gap_only && held && status_within_300_ms && send_within_2s && live_within_2s);
        drop(bob_client);
        runtime.shutdown_and_close().await.unwrap();
        restarted.shutdown();
        healthy_relay.shutdown();
        return;
    }
    timeout(Duration::from_secs(45), async {
        loop {
            if runtime
                .group_mls_state(&alice.label, &groups[0])
                .await
                .unwrap()
                .epoch
                >= initial_epoch + 2
                && (0..8).all(|index| {
                    app.messages(&alice.label).unwrap().iter().any(|message| {
                        message.kind == 22_222 && message.plaintext == format!("future {index}")
                    })
                })
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Alice admits the missing commit and decrypts later valid MLS events");
    let missing_retained = storage
        .retained_recovery_event(
            &route_key,
            &missing.id.to_bytes(),
            None,
            crate::unix_now_seconds(),
        )
        .unwrap();
    let same_worker = commands.same_channel(
        &runtime
            .accounts()
            .worker_commands(&alice.label)
            .await
            .unwrap(),
    );
    let transitions = phase_witness.transitions();
    let terminal = phase_witness.terminal();
    let target_terminals = phase_witness.target_terminals();
    let target = phase_witness.target_observations();
    let target_convergence = phase_witness.target_convergence();
    let target_stages = phase_witness.target_stages();
    let target_path = (
        target.ordinary_seen,
        target.ordinary_skipped,
        target.ordinary_returned,
        target.drain_seen,
        target.drain_skipped,
        target.drain_ingested,
        target.ordinary_outcome,
        target.ordinary_epoch_after,
    );
    let terminal_disposition = terminal.map(|terminal| {
        (
            terminal.attempt_serial,
            terminal.local_epoch_after,
            terminal.deliveries,
            terminal.skipped,
            terminal.qualified,
            terminal.result_ok,
        )
    });
    let network_returned = activity.returned_events.load(Ordering::SeqCst);
    let network_matched_missing = activity.matching_events.load(Ordering::SeqCst);
    let queue_matched_missing = activity.matching_queued_deliveries.load(Ordering::SeqCst);
    let phase_spans = transitions
        .chunks_exact(2)
        .map(|pair| {
            assert!(pair[0].entered && !pair[1].entered);
            assert_eq!(pair[0].phase, pair[1].phase);
            assert_eq!(pair[0].attempt_serial, pair[1].attempt_serial);
            (pair[0].phase, pair[1].at.duration_since(pair[0].at))
        })
        .collect::<Vec<(crate::client::TestRecoveryPhase, Duration)>>();
    let online_trace = runtime
        .shared_services()
        .comparison_test_trace
        .lock()
        .unwrap()
        .clone();
    eprintln!(
        "online_gap_probe gap_armed={gap_armed} held={held} gap_only={gap_only} comparison_before_gap={comparison_before_gap} comparison_at_hold={comparison_at_hold} missing_before_gap={missing_before_gap} epoch_before_gap={epoch_before_gap} initial_epoch={initial_epoch} attempt={attempt} selected={selected:?} active_at_probe={active_at_probe} request_active_at_relay_entry={request_active_at_relay_entry} request_attempt_at_relay_entry={request_attempt_at_relay_entry} request_active_at_probe={request_active_at_probe} network_returned={network_returned} network_matched_missing={network_matched_missing} queue_matched_missing={queue_matched_missing} target_path={target_path:?} target_convergence={target_convergence:?} target_terminals={target_terminals:?} target_stages={target_stages:?} phase_at_relay_entry={phase_at_relay_entry:?} phase_age_at_relay_entry={phase_age_at_relay_entry:?} status_300ms={status_within_300_ms} status_elapsed={status_elapsed:?} status_phase={status_phase_before:?}->{status_phase_after:?} status_request={status_request_before}->{status_request_after} send_2s={send_within_2s} send_elapsed={send_elapsed:?} send_phase={send_phase_before:?}->{send_phase_after:?} send_request={send_request_before}->{send_request_after} live_2s={live_within_2s} live_elapsed={live_elapsed:?} live_phase={live_phase_before:?}->{live_phase_after:?} live_request={live_request_before}->{live_request_after} phase_spans={phase_spans:?} terminal={terminal_disposition:?} online_trace={online_trace:?} missing_retained={missing_retained} same_worker={same_worker} broad_queries={}",
        database.broad_queries.load(Ordering::SeqCst),
    );
    drop(bob_client);
    runtime.shutdown_and_close().await.unwrap();
    assert!(
        gap_armed,
        "genuine later MLS input must arm durable EpochGap"
    );
    assert!(
        held && active_at_probe > 0,
        "real relay query stays active across responsiveness probes"
    );
    assert!(
        phase_at_relay_entry.is_some_and(|phase| phase.attempt_serial == attempt),
        "the selected EpochGap client phase was active when the relay entered"
    );
    assert!(
        request_active_at_relay_entry > 0 && request_attempt_at_relay_entry == attempt,
        "the selected immutable reconciliation request was active at the held relay"
    );
    assert!(
        [
            status_request_before,
            status_request_after,
            send_request_before,
            send_request_after,
            live_request_before,
            live_request_after,
        ]
        .into_iter()
        .all(|active| active > 0)
            && [
                status_phase_before,
                status_phase_after,
                send_phase_before,
                send_phase_after,
                live_phase_before,
                live_phase_after,
            ]
            .into_iter()
            .all(|phase| phase.is_some_and(|phase| {
                phase.attempt_serial == attempt
                    && phase.phase == crate::client::TestRecoveryPhase::Reconciliation
            })),
        "the selected adapter request and recovery phase span every latency probe"
    );
    assert!(
        network_matched_missing > 0 && queue_matched_missing > 0,
        "the selected network result must return and route the missing commit"
    );
    assert_eq!(
        target.ordinary_outcome,
        Some("buffered"),
        "the controlled missing commit must first enter durable engine buffering"
    );
    {
        let terminal = terminal.expect("selected grant records its terminal");
        assert_eq!(terminal.local_epoch_after, target.ordinary_epoch_after);
        assert!(
            target_convergence.windows(2).any(|passes| passes[0]
                == (Some(initial_epoch), Some(initial_epoch + 1))
                && passes[1] == (Some(initial_epoch + 1), Some(initial_epoch + 2))),
            "target group advances through the buffered commit and later valid commit"
        );
        assert!(
            target.ordinary_returned > 0 && target.drain_skipped > 0,
            "durably buffered ordinary input may be skipped as a drain duplicate"
        );
        let terminal_index = online_trace
            .iter()
            .position(|entry| *entry == "online_terminal")
            .expect("online terminal trace");
        let advance_index = online_trace
            .iter()
            .enumerate()
            .skip(terminal_index + 1)
            .find(|(_, entry)| **entry == "scheduled_convergence_advanced_epoch")
            .map(|(index, _)| index)
            .expect("buffered commit advances by a later local convergence pass");
        assert!(
            !online_trace[terminal_index + 1..advance_index].contains(&"grant_inline"),
            "local convergence must advance before a later network retry"
        );
    }
    assert!(
        online_trace.contains(&"online_network_started")
            && online_trace.contains(&"online_queue_started")
            && online_trace.contains(&"online_drain_slice")
            && online_trace.contains(&"online_terminal"),
        "the worker advanced the same online grant through queue, drain, and terminal"
    );
    assert!(
        gap_only,
        "the selected grant must belong solely to the post-startup EpochGap"
    );
    assert!(same_worker && missing_retained);
    assert!(
        status_within_300_ms,
        "status bound during active EpochGap acquisition"
    );
    assert!(
        send_within_2s,
        "healthy-route send bound during active EpochGap acquisition"
    );
    assert!(
        live_within_2s,
        "healthy-route live bound during active EpochGap acquisition"
    );
    restarted.shutdown();
    healthy_relay.shutdown();
}
