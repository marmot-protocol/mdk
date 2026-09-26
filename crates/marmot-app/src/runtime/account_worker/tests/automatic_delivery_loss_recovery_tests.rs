//! A naturally overflowing account queue with real SDK transport, SQLCipher,
//! and valid MLS history. The first execution records useful recovery and the
//! present incomplete-coverage behavior; EOSE is not a durable certificate.

use super::*;
use nostr_relay_builder::prelude::{
    Backend, BoxedFuture, DatabaseError, DatabaseEventStatus, EventId, Events,
    Filter as RelayFilter, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, PolicyResult,
    SaveEventStatus, Timestamp as RelayTimestamp,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{
    Client as NostrSdkClient, Event, Filter, Kind, RelayCapabilities, ReqTarget,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone, Debug, Default)]
struct HeldLossReplay {
    inner: MemoryDatabase,
    target_event_id: Arc<Mutex<Option<EventId>>>,
    hold: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    active: Arc<AtomicUsize>,
}

impl HeldLossReplay {
    fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

struct ReleaseReplayOnDrop(HeldLossReplay);

impl Drop for ReleaseReplayOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct ReleaseWorkerPauseOnDrop(watch::Sender<bool>);

impl Drop for ReleaseWorkerPauseOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

struct ActiveLossRequest(Arc<AtomicUsize>);

impl Drop for ActiveLossRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl NostrDatabase for HeldLossReplay {
    fn backend(&self) -> Backend {
        self.inner.backend()
    }

    fn save_event<'a>(
        &'a self,
        event: &'a nostr_relay_builder::prelude::Event,
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
    ) -> BoxedFuture<'a, Result<Option<nostr_relay_builder::prelude::Event>, DatabaseError>> {
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
        query: RelayFilter,
    ) -> BoxedFuture<'_, Result<Vec<(EventId, RelayTimestamp)>, DatabaseError>> {
        self.inner.negentropy_items(query)
    }

    fn delete(&self, filter: RelayFilter) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.delete(filter)
    }

    fn wipe(&self) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.wipe()
    }
}

impl nostr_relay_builder::prelude::QueryPolicy for HeldLossReplay {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let target = *self.target_event_id.lock().unwrap();
            if self.hold.load(Ordering::SeqCst)
                && target.is_some_and(|target| {
                    query.ids.as_ref().is_some_and(|ids| ids.contains(&target))
                })
            {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                self.active.fetch_add(1, Ordering::SeqCst);
                let _active = ActiveLossRequest(self.active.clone());
                self.entered.notify_one();
                released.await;
            }
            PolicyResult::Accept
        })
    }
}

async fn target_events(inspector: &NostrSdkClient, url: &str, route: &[u8; 32]) -> Vec<Event> {
    inspector
        .fetch_events(ReqTarget::single(
            url,
            [Filter::new().kind(Kind::MlsGroupMessage)],
        ))
        .timeout(Duration::from_secs(15))
        .await
        .unwrap()
        .into_iter()
        .filter(|event| {
            let event =
                transport_nostr_peeler::NostrTransportEvent::from_nostr_event(event).unwrap();
            matches!(
                event.to_transport_message().unwrap().envelope,
                cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id }
                    if transport_group_id.as_slice() == route
            )
        })
        .collect()
}

#[tokio::test]
async fn automatic_queue_loss_recovers_valid_missing_history_after_held_replay() {
    run_automatic_queue_loss_fixture(false).await;
}

#[tokio::test]
async fn automatic_queue_loss_receive_after_live_delivery_recovers_history() {
    run_automatic_queue_loss_fixture(true).await;
}

async fn run_automatic_queue_loss_fixture(stimulate_receive: bool) {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(4096),
    });
    let gate = HeldLossReplay {
        inner: database.clone(),
        ..Default::default()
    };
    let _release_on_drop = ReleaseReplayOnDrop(gate.clone());
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .query_policy(gate.clone())
            .database(gate.clone()),
    );
    relay.run().await.unwrap();
    let target_url = relay.url().await.to_string();
    let healthy = LocalRelay::new(RelayBuilder::default());
    healthy.run().await.unwrap();
    let healthy_url = healthy.url().await.to_string();

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("loss alice").unwrap();
    let bob = home.create_account("loss bob").unwrap();
    let config = crate::MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_settlement_quiescence_ms(100)
        .with_dev_epoch_backfill_retry_backoff_ms(100);
    let app = MarmotApp::with_relay_and_config(dir.path(), target_url.clone(), config);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &target_url);
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
    let phases = crate::client::TestRecoveryPhaseWitness::default();
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
        .unwrap() = Some((alice.label.clone(), phases.clone()));
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let mut groups = Vec::new();
    for (name, url) in [("loss target", &target_url), ("healthy live", &healthy_url)] {
        groups.push(
            runtime
                .create_group_with_options(
                    &alice.label,
                    name,
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
    timeout(Duration::from_secs(30), async {
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
    .expect("Bob joins both MLS groups");
    runtime
        .promote_admin(&alice.label, &groups[0], &bob.account_id_hex)
        .await
        .unwrap();
    timeout(Duration::from_secs(30), async {
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
    let inspector = NostrSdkClient::builder().build();
    inspector
        .add_relay(target_url.clone())
        .capabilities(RelayCapabilities::READ)
        .await
        .unwrap();
    inspector.connect().await;
    let commands = runtime
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (settled_tx, settled_rx) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::NetworkStartupSettled {
            respond: settled_tx,
        })
        .unwrap();
    timeout(Duration::from_secs(30), settled_rx)
        .await
        .expect("original Alice worker completes startup")
        .unwrap();
    let storage = app.account_storage(&alice.label).unwrap();
    assert!(!storage.recovery_comparison().unwrap().pending());
    assert!(
        storage
            .recovery_eligible_revision_fence(false)
            .unwrap()
            .obligations
            .is_empty()
    );
    runtime
        .accounts()
        .deactivate_account(&bob.label)
        .await
        .unwrap();
    let mut bob_client = app.client(&bob.label).await.unwrap();

    // This controlled test-only pause stops Alice at the steady-state loop
    // boundary with no recovery job active. Bob and the real SDK/router keep
    // running; the normal select and owner choose the next seam after release.
    let pre_burst_epoch = bob_client.group_mls_state(&groups[0]).unwrap().epoch;
    let (pause_entered_tx, pause_entered_rx) = oneshot::channel();
    let (pause_release_tx, pause_release_rx) = watch::channel(false);
    let _pause_release_on_drop = ReleaseWorkerPauseOnDrop(pause_release_tx.clone());
    *runtime
        .shared_services()
        .next_worker_loop_pause
        .lock()
        .unwrap() = Some(crate::runtime::WorkerLoopPause {
        account_label: alice.label.clone(),
        entered: pause_entered_tx,
        release: pause_release_rx,
        completed_direct_overflow: None,
    });
    let (wake_tx, _wake_rx) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[1].clone(),
            respond: wake_tx,
        })
        .unwrap();
    timeout(Duration::from_secs(10), pause_entered_rx)
        .await
        .expect("Alice reaches the controlled steady-state loop pause")
        .unwrap();
    let before_burst = app.relay_plane.relay_health().await;
    assert_eq!(before_burst.account_delivery_queue_depth, 0);
    assert_eq!(before_burst.account_delivery_dropped, 0);
    for index in 0..crate::relay_plane::ACCOUNT_DELIVERY_BUFFER {
        bob_client
            .send_custom_event(
                &groups[0],
                22_224,
                Vec::new(),
                format!("queue filler {index}"),
            )
            .await
            .unwrap();
    }
    timeout(Duration::from_secs(30), async {
        loop {
            let health = app.relay_plane.relay_health().await;
            assert_eq!(
                health.account_delivery_dropped, 0,
                "the missing commit must be the first omitted delivery"
            );
            if health.account_delivery_queue_depth == crate::relay_plane::ACCOUNT_DELIVERY_BUFFER {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("1024 valid MLS deliveries fill Alice's ordinary queue without loss");
    let before_missing = target_events(&inspector, &target_url, &route)
        .await
        .into_iter()
        .map(|event| event.id)
        .collect::<HashSet<_>>();
    bob_client
        .update_group_profile(&groups[0], Some("missing loss commit"), None)
        .await
        .unwrap();
    let overflow_seen = timeout(Duration::from_secs(30), async {
        loop {
            if app
                .relay_plane
                .relay_health()
                .await
                .account_delivery_dropped
                > 0
                && !storage
                    .recovery_loss_watermarks(
                        &alice.label,
                        storage_sqlite::RecoveryLossCause::Queue,
                    )
                    .unwrap()
                    .is_empty()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    if overflow_seen.is_err() {
        let health = app.relay_plane.relay_health().await;
        let retained = database.count(RelayFilter::new()).await.unwrap();
        panic!(
            "target commit did not cause first durable loss: dropped={}, queue_depth={}, max_depth={}, retained={}, watermark_count={}",
            health.account_delivery_dropped,
            health.account_delivery_queue_depth,
            health.account_delivery_max_queue_depth,
            retained,
            storage
                .recovery_loss_watermarks(&alice.label, storage_sqlite::RecoveryLossCause::Queue)
                .unwrap()
                .len(),
        );
    }
    let missing = target_events(&inspector, &target_url, &route)
        .await
        .into_iter()
        .find(|event| !before_missing.contains(&event.id))
        .expect("relay retains Bob's valid missing MLS commit");
    *gate.target_event_id.lock().unwrap() = Some(EventId::from_byte_array(missing.id.to_bytes()));
    *activity.target_event_id.lock().unwrap() = Some(missing.id.to_string());
    for index in 0..2 {
        bob_client
            .send_custom_event(
                &groups[0],
                22_225,
                Vec::new(),
                format!("after loss {index}"),
            )
            .await
            .unwrap();
    }
    let route_key = storage_sqlite::TransportReconciliationRoute::Group(route);
    assert!(
        database
            .event_by_id(&EventId::from_byte_array(missing.id.to_bytes()))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        !storage
            .retained_recovery_event(
                &route_key,
                &missing.id.to_bytes(),
                None,
                crate::unix_now_seconds()
            )
            .unwrap()
    );
    let loss = storage
        .recovery_loss_watermarks(&alice.label, storage_sqlite::RecoveryLossCause::Queue)
        .unwrap()
        .into_iter()
        .next()
        .expect("actual queue drop persisted as typed loss evidence");
    assert!(loss.observed_count > 0);
    selections.lock().unwrap().clear();
    runtime
        .shared_services()
        .comparison_test_trace
        .lock()
        .unwrap()
        .clear();
    phases.arm_queue_loss();
    *activity.network_deadline.lock().unwrap() = None;

    gate.hold.store(true, Ordering::SeqCst);
    let entered = gate.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    pause_release_tx.send(true).unwrap();
    let mut stimulated_receive = false;
    let held = timeout(Duration::from_secs(45), async {
        loop {
            tokio::select! {
                biased;
                _ = &mut entered => break true,
                _ = sleep(Duration::from_millis(20)) => {
                    // An online terminal is not guaranteed before this wake.
                    // Once the ordinary queue has capacity and no network job
                    // is active, enqueue a real event; the worker chooses its
                    // Receive seam when that delivery is actually claimed.
                    if stimulate_receive
                        && !stimulated_receive
                        && app.relay_plane.relay_health().await.account_delivery_queue_depth == 0
                        && activity.active_jobs.load(Ordering::SeqCst) == 0
                    {
                        bob_client
                            .send_custom_event(
                                &groups[1],
                                22_227,
                                Vec::new(),
                                "ordinary Receive wake after loss".into(),
                            )
                            .await
                            .unwrap();
                        stimulated_receive = true;
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    activity.matching_events.store(0, Ordering::SeqCst);
    activity
        .matching_queued_deliveries
        .store(0, Ordering::SeqCst);
    let phase_at_entry = phases.active();
    let active_attempt_at_entry = activity.attempt_serial.load(Ordering::SeqCst);
    let active_jobs_at_entry = activity.active_jobs.load(Ordering::SeqCst);
    let active_requests_at_entry = activity.active_requests.load(Ordering::SeqCst);
    let deadline_remaining_at_entry = activity
        .network_deadline
        .lock()
        .unwrap()
        .or_else(|| {
            phases
                .reconciliation_deadline_remaining()
                .map(|remaining| tokio::time::Instant::now() + remaining)
        })
        .map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()));
    let (status_tx, mut status_rx) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond: status_tx,
        })
        .unwrap();
    let status_before = phases.active();
    let send_before = phases.active();
    let live_before = phases.active();
    let healthy_send = runtime.send_message(
        &alice.label,
        &groups[1],
        b"send while loss replay waits".to_vec(),
    );
    tokio::pin!(healthy_send);
    let status_work = async {
        let probe = timeout(Duration::from_millis(300), &mut status_rx).await;
        (probe, phases.active())
    };
    let send_work = async {
        let probe = timeout(Duration::from_secs(2), &mut healthy_send).await;
        (probe, phases.active())
    };
    let live_work = async {
        let probe = timeout(Duration::from_secs(2), async {
            bob_client
                .send_custom_event(
                    &groups[1],
                    22_226,
                    Vec::new(),
                    "healthy live during loss".into(),
                )
                .await
                .unwrap();
            loop {
                if app.messages(&alice.label).unwrap().iter().any(|message| {
                    message.kind == 22_226 && message.plaintext == "healthy live during loss"
                }) {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        (probe.is_ok(), phases.active())
    };
    let ((status_probe, status_after), (send_probe, send_after), (live_ok, live_after)) =
        tokio::join!(status_work, send_work, live_work);
    let status_ok = matches!(&status_probe, Ok(Ok(Ok(_))));
    let status_timed_out = status_probe.is_err();
    let send_ok = matches!(&send_probe, Ok(Ok(_)));
    let send_timed_out = send_probe.is_err();
    let active_at_probe = gate.active.load(Ordering::SeqCst);
    let probe_phases = [
        phase_at_entry,
        status_before,
        status_after,
        send_before,
        send_after,
        live_before,
        live_after,
    ];
    let deadline_remaining_at_release = activity
        .network_deadline
        .lock()
        .unwrap()
        .as_ref()
        .map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()))
        .or_else(|| phases.reconciliation_deadline_remaining());
    let active_jobs_at_release = activity.active_jobs.load(Ordering::SeqCst);
    let active_requests_at_release = activity.active_requests.load(Ordering::SeqCst);
    gate.release();
    let selected = selections.lock().unwrap().clone();
    let trace_counts = {
        let shared = runtime.shared_services();
        let trace = shared.comparison_test_trace.lock().unwrap();
        [
            "grant_eligible",
            "grant_inline",
            "selection_deferred",
            "online_network_started",
            "online_terminal",
            "route_skipped",
            "route_timed_out",
            "route_relay_failed",
        ]
        .map(|kind| (kind, trace.iter().filter(|seen| **seen == kind).count()))
    };
    let loss_demands = storage.pending_recovery_demands().unwrap();
    let loss_demand_covers_missing = loss_demands.iter().any(|demand| {
        demand.cause == storage_sqlite::RecoveryCause::QueueLoss
            && missing.created_at.as_secs() <= demand.requested_at_ms / 1000
    });
    let selected_attempt = Some(active_attempt_at_entry);
    let selected_scopes = loss_demands
        .iter()
        .filter(|demand| demand.cause == storage_sqlite::RecoveryCause::QueueLoss)
        .flat_map(|demand| storage.recovery_scope_snapshots(demand.ticket.id).unwrap())
        .filter(|scope| Some(scope.attempt_serial) == selected_attempt)
        .map(|scope| {
            let plan = scope.plan;
            let target_route = plan.transport_group_id == Some(route);
            let target_time = plan
                .since_seconds
                .is_none_or(|since| missing.created_at.as_secs() >= since)
                && missing.created_at.as_secs() <= plan.until_seconds;
            (
                plan.route_kind,
                target_route,
                target_time,
                plan.since_seconds,
                plan.until_seconds,
                plan.required_endpoints.len(),
                plan.admitted_endpoints.len(),
            )
        })
        .collect::<Vec<_>>();
    let selected_target_scope_includes_missing = selected_scopes
        .iter()
        .any(|(_, target_route, target_time, _, _, _, _)| *target_route && *target_time);
    eprintln!(
        "loss_probe: stimulated_receive={stimulated_receive}, held={held}, relay_active={active_at_probe}, selected={selected:?}, trace_counts={trace_counts:?}, phases={probe_phases:?}, active_attempt={active_attempt_at_entry}, entry_remaining={deadline_remaining_at_entry:?}, release_remaining={deadline_remaining_at_release:?}, entry_jobs={active_jobs_at_entry}, entry_requests={active_requests_at_entry}, release_jobs={active_jobs_at_release}, release_requests={active_requests_at_release}, demand_covers_missing={loss_demand_covers_missing}, target_scope_includes_missing={selected_target_scope_includes_missing}, scopes={selected_scopes:?}, status_ok={status_ok}, send_ok={send_ok}, live_ok={live_ok}",
    );
    if status_timed_out {
        timeout(Duration::from_secs(30), status_rx)
            .await
            .expect("status finishes after held query release")
            .unwrap()
            .unwrap();
    }
    if send_timed_out {
        timeout(Duration::from_secs(30), &mut healthy_send)
            .await
            .expect("healthy send finishes after held query release")
            .unwrap();
    }
    let useful = timeout(Duration::from_secs(90), async {
        loop {
            let retained = storage
                .retained_recovery_event(
                    &route_key,
                    &missing.id.to_bytes(),
                    None,
                    crate::unix_now_seconds(),
                )
                .unwrap();
            let plaintext = (0..2).all(|index| {
                app.messages(&alice.label).unwrap().iter().any(|message| {
                    message.kind == 22_225 && message.plaintext == format!("after loss {index}")
                })
            });
            if retained && plaintext {
                let epoch = timeout(
                    Duration::from_millis(300),
                    runtime.group_mls_state(&alice.label, &groups[0]),
                )
                .await;
                if epoch
                    .ok()
                    .and_then(Result::ok)
                    .is_some_and(|state| state.epoch > pre_burst_epoch)
                {
                    break;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if useful.is_err() {
        let retained = storage
            .retained_recovery_event(
                &route_key,
                &missing.id.to_bytes(),
                None,
                crate::unix_now_seconds(),
            )
            .unwrap();
        let epoch = timeout(
            Duration::from_secs(2),
            runtime.group_mls_state(&alice.label, &groups[0]),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .map(|state| state.epoch);
        let plaintext = (0..2)
            .map(|index| {
                app.messages(&alice.label).unwrap().iter().any(|message| {
                    message.kind == 22_225 && message.plaintext == format!("after loss {index}")
                })
            })
            .collect::<Vec<_>>();
        let health = app.relay_plane.relay_health().await;
        panic!(
            "released replay incomplete: held={held}, relay_active={active_at_probe}, selections={selected:?}, probe_phases={probe_phases:?}, phase_now={:?}, active_attempt={active_attempt_at_entry}, entry_remaining={deadline_remaining_at_entry:?}, release_remaining={deadline_remaining_at_release:?}, entry_jobs={active_jobs_at_entry}, entry_requests={active_requests_at_entry}, release_jobs={active_jobs_at_release}, release_requests={active_requests_at_release}, target_scope_includes_missing={selected_target_scope_includes_missing}, scopes={selected_scopes:?}, status_ok={status_ok}, send_ok={send_ok}, live_ok={live_ok}, retained={retained}, epoch={epoch:?}, expected_epoch={}, plaintext={plaintext:?}, dropped={}, queue_depth={}, marker={}, demands={:?}",
            phases.active(),
            pre_burst_epoch + 1,
            health.account_delivery_dropped,
            health.account_delivery_queue_depth,
            storage
                .account_delivery_recovery(&alice.label)
                .unwrap()
                .is_some(),
            storage
                .pending_recovery_demands()
                .unwrap()
                .into_iter()
                .map(|demand| (demand.cause, demand.eligibility))
                .collect::<Vec<_>>(),
        );
    }
    let remaining = storage.pending_recovery_demands().unwrap();
    let selected_after_progress = selections.lock().unwrap().clone();
    let later_grants = selected_after_progress
        .iter()
        .filter(|selection| selection.attempt_serial > active_attempt_at_entry)
        .count();
    let target_returned = activity.matching_events.load(Ordering::SeqCst);
    let target_queued = activity.matching_queued_deliveries.load(Ordering::SeqCst);
    let marker_pending = storage
        .account_delivery_recovery(&alice.label)
        .unwrap()
        .is_some();
    eprintln!(
        "loss_terminal: active_attempt={active_attempt_at_entry}, later_grants={later_grants}, target_returned={target_returned}, target_queued={target_queued}, marker_pending={marker_pending}, queue_loss_demand={}",
        remaining
            .iter()
            .any(|demand| demand.cause == storage_sqlite::RecoveryCause::QueueLoss),
    );
    let same_worker = commands.same_channel(
        &runtime
            .accounts()
            .worker_commands(&alice.label)
            .await
            .unwrap(),
    );
    drop(bob_client);
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
    healthy.shutdown();
    let selected_loss = selected.iter().any(|selection| {
        selection.attempt_serial == active_attempt_at_entry
            && matches!(
                selection.seam,
                seam if seam == if stimulate_receive {
                    EpochBackfillExecutionSeam::Receive
                } else {
                    EpochBackfillExecutionSeam::Maintenance
                }
            )
            && selection.comparison_revision.is_none()
            && selection.causes == [storage_sqlite::RecoveryCause::QueueLoss]
    });
    assert!(
        held && active_at_probe > 0
            && active_jobs_at_entry > 0
            && active_requests_at_entry > 0
            && active_jobs_at_release > 0
            && active_requests_at_release > 0
            && selected_loss
            && same_worker
            && loss_demand_covers_missing
            && selected_target_scope_includes_missing
            && deadline_remaining_at_release.is_some_and(|remaining| !remaining.is_zero()),
        "actual QueueLoss grant must own the active target acquisition"
    );
    if stimulate_receive {
        assert!(
            stimulated_receive,
            "a real inbound delivery must wake Receive"
        );
        assert!(
            selected.iter().any(|selection| {
                selection.attempt_serial == active_attempt_at_entry
                    && selection.seam == EpochBackfillExecutionSeam::Receive
            }),
            "the new ordinary delivery must lead to a natural Receive selection"
        );
    }
    assert!(
        [
            phase_at_entry,
            status_before,
            status_after,
            send_before,
            send_after,
            live_before,
            live_after,
        ]
        .into_iter()
        .all(|phase| phase.is_some_and(|phase| {
            phase.attempt_serial == active_attempt_at_entry
                && phase.phase == crate::client::TestRecoveryPhase::Reconciliation
        })),
        "the selected AppClient reconciliation phase must span every probe"
    );
    assert!(
        marker_pending
            && remaining
                .iter()
                .any(|demand| demand.cause == storage_sqlite::RecoveryCause::QueueLoss),
        "EOSE without an admission certificate retains honest account-loss debt"
    );
    assert_eq!(
        later_grants, 0,
        "the held grant must provide the useful progress"
    );
    assert!(
        target_returned > 0 && target_queued > 0,
        "the held grant must return and queue the missing valid MLS commit"
    );
    assert!(
        status_ok && send_ok && live_ok,
        "status, send and live delivery must meet the existing 300ms/2s/2s bounds"
    );
}
