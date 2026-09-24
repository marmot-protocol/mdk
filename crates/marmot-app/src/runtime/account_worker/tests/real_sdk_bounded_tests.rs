//! Real SDK, relay-plane, worker and SQLCipher qualification for the exact-ID slice.

use super::*;
use futures::{SinkExt, StreamExt};
use nostr_relay_builder::prelude::{BoxedFuture, Filter as RelayFilter, PolicyResult, QueryPolicy};
use nostr_relay_builder::{LocalRelay, MockRelay, RelayBuilder};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[path = "real_sdk_bounded_tests/admission_interruption_tests.rs"]
mod admission_interruption_tests;

#[derive(Clone, Debug, Default)]
struct HeldExactQuery {
    event_id_hex: Arc<Mutex<String>>,
    hold_exact: Arc<AtomicBool>,
    reject_broad: Arc<AtomicBool>,
    exact_queries: Arc<AtomicUsize>,
    entered_at: Arc<Mutex<Option<Instant>>>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl QueryPolicy for HeldExactQuery {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let wanted = self.event_id_hex.lock().unwrap().clone();
            let exact = !wanted.is_empty()
                && query
                    .ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| id.to_hex() == wanted));
            if exact {
                self.exact_queries.fetch_add(1, Ordering::SeqCst);
                if self.hold_exact.load(Ordering::SeqCst) {
                    let released = self.release.notified();
                    tokio::pin!(released);
                    released.as_mut().enable();
                    *self.entered_at.lock().unwrap() = Some(Instant::now());
                    self.entered.notify_one();
                    released.await;
                }
                PolicyResult::Accept
            } else if self.reject_broad.load(Ordering::SeqCst) && query.ids.is_none() {
                PolicyResult::Reject("controlled ordinary-history gate".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

#[derive(Default, Clone, Debug)]
struct BoundaryCounts {
    received_text_bytes: usize,
    sent_text_bytes: usize,
    received_events: usize,
    sent_events: usize,
    received_event_json_bytes: usize,
    sent_event_json_bytes: usize,
    requests: usize,
    id_requests: usize,
    id_closes: usize,
    closes: usize,
}

#[derive(Clone)]
struct LiveInterest {
    connection: usize,
    id: String,
    route: String,
    sender: mpsc::UnboundedSender<Value>,
}

#[derive(Default)]
struct RelayState {
    events: Mutex<Vec<Value>>,
    counts: Mutex<BoundaryCounts>,
    live: Mutex<Vec<LiveInterest>>,
    id_subscriptions: Mutex<HashSet<(usize, String)>>,
    next_connection: AtomicUsize,
    omit_id_eose: AtomicBool,
    broadcast_live: AtomicBool,
    id_request_started: tokio::sync::Notify,
}

impl RelayState {
    fn counts(&self) -> BoundaryCounts {
        self.counts.lock().unwrap().clone()
    }

    fn id_request_active(&self) -> bool {
        !self.id_subscriptions.lock().unwrap().is_empty()
    }

    fn group_event(&self) -> Value {
        self.events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|event| event["kind"] == 445)
            .cloned()
            .expect("relay stored the encrypted group event")
    }
}

async fn counted_relay() -> (String, Arc<RelayState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let state = Arc::new(RelayState::default());
    let accept_state = state.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let state = accept_state.clone();
            tokio::spawn(async move {
                let Ok(socket) = accept_async(stream).await else {
                    return;
                };
                let connection = state.next_connection.fetch_add(1, Ordering::SeqCst);
                let (mut writer, mut reader) = socket.split();
                let (sender, mut outgoing) = mpsc::unbounded_channel::<Value>();
                let writer_state = state.clone();
                let writer_task = tokio::spawn(async move {
                    while let Some(frame) = outgoing.recv().await {
                        let text = frame.to_string();
                        if writer
                            .send(Message::Text(text.clone().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let mut counts = writer_state.counts.lock().unwrap();
                        counts.sent_text_bytes += text.len();
                        if frame[0] == "EVENT" {
                            counts.sent_events += 1;
                            counts.sent_event_json_bytes += frame[2].to_string().len();
                        }
                    }
                });
                while let Some(Ok(message)) = reader.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let Ok(frame) = serde_json::from_str::<Vec<Value>>(&text) else {
                        continue;
                    };
                    let kind = frame.first().and_then(Value::as_str).unwrap_or_default();
                    {
                        let mut counts = state.counts.lock().unwrap();
                        counts.received_text_bytes += text.len();
                        match kind {
                            "EVENT" => {
                                counts.received_events += 1;
                                counts.received_event_json_bytes += frame[1].to_string().len();
                            }
                            "REQ" => counts.requests += 1,
                            "CLOSE" => counts.closes += 1,
                            _ => {}
                        }
                    }
                    match kind {
                        "EVENT" => {
                            let Some(event) = frame.get(1) else { continue };
                            state.events.lock().unwrap().push(event.clone());
                            let _ = sender.send(json!(["OK", event["id"], true, ""]));
                            let route = event["tags"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .find(|tag| tag[0] == "h")
                                .and_then(|tag| tag[1].as_str());
                            if let Some(route) =
                                route.filter(|_| state.broadcast_live.load(Ordering::SeqCst))
                            {
                                for live in state.live.lock().unwrap().iter() {
                                    if live.route == route {
                                        let _ = live.sender.send(json!(["EVENT", live.id, event]));
                                    }
                                }
                            }
                        }
                        "REQ" => {
                            let Some(id) = frame.get(1).and_then(Value::as_str) else {
                                continue;
                            };
                            // Ordinary live subscriptions get an EOSE with no backlog.
                            // The exact-ID acquisition must recover the stored bytes.
                            let ids = frame
                                .iter()
                                .skip(2)
                                .flat_map(|filter| filter["ids"].as_array().into_iter().flatten())
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>();
                            if ids.is_empty() {
                                for route in frame
                                    .iter()
                                    .skip(2)
                                    .flat_map(|filter| {
                                        filter["#h"].as_array().into_iter().flatten()
                                    })
                                    .filter_map(Value::as_str)
                                {
                                    state.live.lock().unwrap().push(LiveInterest {
                                        connection,
                                        id: id.to_owned(),
                                        route: route.to_owned(),
                                        sender: sender.clone(),
                                    });
                                }
                            } else {
                                state.counts.lock().unwrap().id_requests += 1;
                                state
                                    .id_subscriptions
                                    .lock()
                                    .unwrap()
                                    .insert((connection, id.to_owned()));
                            }
                            let matching = state
                                .events
                                .lock()
                                .unwrap()
                                .iter()
                                .filter(|event| ids.iter().any(|want| event["id"] == *want))
                                .cloned()
                                .collect::<Vec<_>>();
                            for event in matching {
                                let _ = sender.send(json!(["EVENT", id, event]));
                            }
                            if !ids.is_empty() {
                                state.id_request_started.notify_one();
                            }
                            if ids.is_empty() || !state.omit_id_eose.load(Ordering::SeqCst) {
                                let _ = sender.send(json!(["EOSE", id]));
                            }
                        }
                        "CLOSE" => {
                            if let Some(id) = frame.get(1).and_then(Value::as_str) {
                                if state
                                    .id_subscriptions
                                    .lock()
                                    .unwrap()
                                    .remove(&(connection, id.to_owned()))
                                {
                                    state.counts.lock().unwrap().id_closes += 1;
                                }
                                state
                                    .live
                                    .lock()
                                    .unwrap()
                                    .retain(|live| live.connection != connection || live.id != id);
                            }
                        }
                        _ => {}
                    }
                }
                state
                    .live
                    .lock()
                    .unwrap()
                    .retain(|live| live.connection != connection);
                state
                    .id_subscriptions
                    .lock()
                    .unwrap()
                    .retain(|(active_connection, _)| *active_connection != connection);
                writer_task.abort();
            });
        }
    });
    (url, state)
}

#[tokio::test]
async fn bounded_real_sdk_two_relays_retain_one_encrypted_known_event() {
    run_real_sdk_known_event(false, false).await;
}

#[tokio::test]
async fn bounded_real_sdk_conforming_relay_services_competing_comparison() {
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
    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "conforming comparison",
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
    .unwrap();
    let routing = app
        .group(&alice.label, &hex::encode(&group))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let route = storage_sqlite::TransportReconciliationRoute::Group(
        hex::decode(routing).unwrap().try_into().unwrap(),
    );
    let storage = app.account_storage(&alice.label).unwrap();
    let before = storage
        .transport_reconciliation_inventory(&route, crate::unix_now_seconds())
        .unwrap();
    runtime
        .send_message(&bob.label, &group, b"conforming exact control".to_vec())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .any(|message| message.plaintext == "conforming exact control")
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let after = storage
        .transport_reconciliation_inventory(&route, crate::unix_now_seconds())
        .unwrap();
    let known = after
        .items
        .iter()
        .find(|item| !before.items.iter().any(|old| old.event_id == item.event_id))
        .expect("new encrypted message is retained in the route inventory");
    let event_id = known.event_id;
    let created_at = known.created_at;
    assert!(
        storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    let comparison_before = storage.recovery_comparison().unwrap();
    let fence_before = storage.recovery_revision_fence().unwrap();
    assert_ne!(
        comparison_before.blocked_route_revision,
        Some(fence_before.route_revision),
        "the conforming relay must leave comparison selectable"
    );
    let telemetry_before = app.relay_telemetry().await.metrics.reconciliation_attempts;
    let prior_routes = comparison_before
        .plan
        .as_ref()
        .expect("conforming startup comparison has a frozen route")
        .routes
        .clone();
    storage
        .join_recovery_comparison(
            &[0x77; 16],
            crate::client::recovery::wall_now_ms().unwrap(),
            &prior_routes,
        )
        .unwrap();
    assert!(storage.recovery_comparison().unwrap().pending());
    let shared = runtime.shared_services();
    let mut bounded_finished = Box::pin(shared.bounded_recovery_finished.notified());
    bounded_finished.as_mut().enable();
    storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: group.as_slice(),
                event_id: &event_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    // The worker probe and the 15-second maintenance tick may select either
    // obligation first. Observe which debt settles, then cross the shared
    // retry deadline again only if the other remains pending.
    timeout(Duration::from_secs(20), async {
        loop {
            let known_cleared = storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|d| d.known_event_id != Some(event_id));
            let comparison_settled = storage.recovery_comparison().unwrap().settled_revision
                > comparison_before.settled_revision;
            if known_cleared || comparison_settled {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("automatic worker service settles at least one competing demand");
    let known_cleared = storage
        .pending_recovery_demands()
        .unwrap()
        .iter()
        .all(|d| d.known_event_id != Some(event_id));
    let comparison_settled = storage.recovery_comparison().unwrap().settled_revision
        > comparison_before.settled_revision;
    if !known_cleared || !comparison_settled {
        if known_cleared {
            timeout(Duration::from_secs(10), bounded_finished.as_mut())
                .await
                .expect("the selected bounded KnownEvent attempt finishes before retry");
        }
        let (retry_before_next, remaining, comparison_pending) =
            runtime.recovery_retry_snapshot_for_test(&alice.label).await;
        assert!(remaining > Duration::ZERO);
        assert_eq!(
            comparison_pending, !comparison_settled,
            "the next opportunity observes the durable comparison state"
        );
        runtime
            .advance_recovery_clock_for_test(&alice.label, remaining + Duration::from_millis(1))
            .await;
        timeout(Duration::from_secs(20), async {
            loop {
                let known_cleared = storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|d| d.known_event_id != Some(event_id));
                let comparison_settled = storage.recovery_comparison().unwrap().settled_revision
                    > comparison_before.settled_revision;
                if known_cleared && comparison_settled {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|err| {
            panic!(
                "next automatic owner opportunity settles the other demand: {err:?}; comparison={:?}; retry={:?}; demands={:?}",
                {
                    let comparison = storage.recovery_comparison().unwrap();
                    (comparison.revision, comparison.settled_revision, comparison.attempt_serial)
                },
                (retry_before_next, storage.recovery_retry_state().unwrap(), storage.recovery_comparison().unwrap().blocked_route_revision, storage.recovery_revision_fence().unwrap().route_revision),
                storage.pending_recovery_demands().unwrap().iter().map(|d| (format!("{:?}", d.cause), d.known_event_id.is_some())).collect::<Vec<_>>(),
            )
        });
    }
    let after_tick = storage.recovery_comparison().unwrap();
    assert_eq!(after_tick.settled_revision, after_tick.revision);
    assert!(after_tick.attempt_serial > comparison_before.attempt_serial);
    assert!(
        app.relay_telemetry().await.metrics.reconciliation_attempts > telemetry_before,
        "the conforming relay was compared by the SDK"
    );
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}

#[tokio::test]
async fn bounded_real_sdk_cancel_reopen_reacquires_unretained_exact_id() {
    use base64::Engine as _;
    use nostr_sdk::prelude::{
        Client as NostrSdkClient, EventBuilder, FinalizeEvent, Keys, Kind, Tag,
    };
    use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};

    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldExactQuery::default();
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(gate.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let config = crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "conforming cancel",
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
    .unwrap();
    let route_hex = app
        .group(&alice.label, &hex::encode(&group))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let route = storage_sqlite::TransportReconciliationRoute::Group(
        hex::decode(&route_hex).unwrap().try_into().unwrap(),
    );
    let mut envelope = vec![0u8; 12];
    envelope.extend_from_slice(b"conforming-cancel-unretained-encrypted-probe");
    assert!(envelope.len() >= transport_nostr_peeler::NOSTR_GROUP_CONTENT_MIN_LEN);
    let signed = EventBuilder::new(
        Kind::MlsGroupMessage,
        base64::engine::general_purpose::STANDARD.encode(envelope),
    )
    .tags([Tag::custom("h", [route_hex])])
    .finalize(&Keys::generate())
    .unwrap();
    let event_id = signed.id.to_bytes();
    let created_at = signed.created_at.as_secs();
    *gate.event_id_hex.lock().unwrap() = signed.id.to_hex();
    gate.hold_exact.store(true, Ordering::SeqCst);
    // Suppress ordinary history REQs so only the bounded exact-ID path can
    // acquire this probe; NIP-77 comparison remains available on the relay.
    gate.reject_broad.store(true, Ordering::SeqCst);
    let storage = app.account_storage(&alice.label).unwrap();
    let shared = runtime.shared_services();
    let mut network_result = Box::pin(shared.bounded_result_ready.notified());
    network_result.as_mut().enable();
    storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: group.as_slice(),
                event_id: &event_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(10), gate.entered.notified())
        .await
        .expect("first exact-ID request enters the real relay's query gate");
    let entered_at = gate
        .entered_at
        .lock()
        .unwrap()
        .expect("relay entry timestamp");
    let first_retry = storage.recovery_retry_state().unwrap();
    assert_eq!(gate.exact_queries.load(Ordering::SeqCst), 1);
    assert!(first_retry.not_before_ms > first_retry.recorded_at_ms);
    let demand_id = storage
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|d| d.known_event_id == Some(event_id))
        .expect("exact demand remains pending while its query is held")
        .ticket
        .id;
    let scope_before = storage.recovery_scope_snapshots(demand_id).unwrap();
    assert!(!scope_before.is_empty());
    assert!(
        scope_before
            .iter()
            .all(|scope| scope.checkpoints.is_empty())
    );
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(
        futures::FutureExt::now_or_never(network_result.as_mut()).is_none(),
        "the worker has not accepted an SDK result before shutdown"
    );
    // The SDK request expires five seconds after its REQ. Shutdown must
    // finish earlier, while this exact query is still held by the relay.
    let remaining = Duration::from_secs(4)
        .checked_sub(entered_at.elapsed())
        .expect("shutdown starts inside the request-relative cancellation window");
    timeout(remaining, runtime.shutdown_and_close())
        .await
        .expect("shutdown interrupts the held SDK acquisition before its deadline")
        .unwrap();
    assert!(
        futures::FutureExt::now_or_never(network_result.as_mut()).is_none(),
        "shutdown did not accept a completed SDK result"
    );
    gate.release.notify_waiters();
    drop(storage);
    drop(runtime);
    drop(app);

    let reopened_app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let reopened_runtime = super::super::super::MarmotAppRuntime::new(reopened_app.clone());
    reopened_runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    timeout(
        Duration::from_secs(20),
        reopened_runtime.reconcile_accounts(),
    )
    .await
    .expect("reopened runtime starts")
    .unwrap();
    let reopened_storage = reopened_app.account_storage(&alice.label).unwrap();
    let reopened_retry = reopened_storage.recovery_retry_state().unwrap();
    assert_eq!(reopened_retry.attempt_serial, first_retry.attempt_serial);
    assert_eq!(gate.exact_queries.load(Ordering::SeqCst), 1);
    let scope_after = reopened_storage
        .recovery_scope_snapshots(demand_id)
        .unwrap();
    assert_eq!(scope_after.len(), scope_before.len());
    assert!(scope_after.iter().all(|scope| scope.checkpoints.is_empty()));
    assert!(
        !reopened_storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(
        reopened_storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.known_event_id == Some(event_id))
    );
    let comparison_before = reopened_storage.recovery_comparison().unwrap();
    reopened_runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(20), async {
        loop {
            if reopened_storage
                .recovery_comparison()
                .unwrap()
                .settled_revision
                > comparison_before.settled_revision
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("conforming comparison settles after reopening");
    let comparison_retry = reopened_storage.recovery_retry_state().unwrap();
    assert_eq!(
        comparison_retry.attempt_serial,
        first_retry.attempt_serial + 1
    );
    assert_eq!(
        reopened_storage
            .recovery_comparison()
            .unwrap()
            .attempt_serial,
        comparison_retry.attempt_serial
    );
    assert!(comparison_retry.not_before_ms > comparison_retry.recorded_at_ms);
    assert_eq!(gate.exact_queries.load(Ordering::SeqCst), 1);
    assert!(
        reopened_storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.known_event_id == Some(event_id))
    );
    assert!(
        !reopened_storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    let transport_event =
        transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap();
    let relay_client = NostrSdkRelayClient::new(NostrSdkClient::builder().build());
    relay_client
        .publish_event(&[cgka_traits::TransportEndpoint(url)], &transport_event, 1)
        .await
        .unwrap();
    gate.hold_exact.store(false, Ordering::SeqCst);
    reopened_runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(10), async {
        loop {
            if gate.exact_queries.load(Ordering::SeqCst) >= 2
                && reopened_storage
                    .retained_recovery_event(&route, &event_id, None, created_at)
                    .unwrap()
                && reopened_storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|d| d.known_event_id != Some(event_id))
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fresh exact request retains the Nostr event after reopen");
    let final_retry = reopened_storage.recovery_retry_state().unwrap();
    assert_eq!(
        final_retry.attempt_serial,
        comparison_retry.attempt_serial + 1
    );
    assert_eq!(gate.exact_queries.load(Ordering::SeqCst), 2);
    reopened_runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}

#[tokio::test]
async fn bounded_real_sdk_missing_eose_keeps_send_and_read_available() {
    run_real_sdk_known_event(true, false).await;
}

#[tokio::test]
async fn bounded_real_sdk_new_loss_rejects_stale_exact_checkpoint() {
    run_real_sdk_known_event(true, true).await;
}

async fn run_real_sdk_known_event(omit_right_eose: bool, new_loss: bool) {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let bootstrap = MockRelay::run().await.unwrap();
    let bootstrap_url = bootstrap.url().await.to_string();
    let (left_url, left) = counted_relay().await;
    let (right_url, right) = counted_relay().await;
    right.omit_id_eose.store(omit_right_eose, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        bootstrap_url.clone(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, std::sync::atomic::Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &bootstrap_url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "real SDK bounded",
            std::slice::from_ref(&bob.account_id_hex),
            AppCreateGroupOptions {
                relays: Some(vec![left_url.clone(), right_url.clone()]),
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
    .expect("Bob joins through the real SDK and MLS path");
    let signed_out = runtime
        .sign_out(
            &alice.label,
            super::super::super::SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    assert!(signed_out.local_cleanup.completed);
    runtime
        .send_message(&bob.label, &group, b"exact known gap".to_vec())
        .await
        .unwrap();
    let historical = left.group_event();
    assert_eq!(right.group_event()["id"], historical["id"]);
    let event_id: [u8; 32] = hex::decode(historical["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let created_at = historical["created_at"].as_u64().unwrap();
    let route: [u8; 32] = hex::decode(
        &app.group(&alice.label, &hex::encode(&group))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let route = storage_sqlite::TransportReconciliationRoute::Group(route);
    let storage = app.account_storage(&alice.label).unwrap();
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    runtime.sign_in_account(&alice.label).await.unwrap();
    timeout(Duration::from_secs(45), runtime.catch_up_accounts())
        .await
        .expect("real SDK startup catch-up finishes")
        .unwrap();
    if omit_right_eose {
        left.broadcast_live.store(true, Ordering::SeqCst);
        right.broadcast_live.store(true, Ordering::SeqCst);
    }
    storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: group.as_slice(),
                event_id: &event_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    let commands = runtime
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, advanced) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::AdvanceRecoveryClock {
            elapsed: Duration::from_secs(600),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), advanced)
        .await
        .unwrap()
        .unwrap();
    let (respond, status) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), status)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let requested = timeout(Duration::from_secs(8), left.id_request_started.notified()).await;
    assert!(
        requested.is_ok(),
        "known-event owner must issue a scoped real SDK request: left={:?}, right={:?}, demands={:?}, retry={:?}, probes={}",
        left.counts(),
        right.counts(),
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .map(|d| (format!("{:?}", d.cause), d.known_event_id.is_some()))
            .collect::<Vec<_>>(),
        storage.recovery_retry_state().unwrap(),
        runtime
            .shared_services()
            .bounded_preparation_probes
            .load(Ordering::SeqCst),
    );
    if omit_right_eose {
        timeout(Duration::from_secs(2), right.id_request_started.notified())
            .await
            .expect("real SDK requested the exact event from the delayed relay");
        let shared = runtime.shared_services();
        let mut network_result = Box::pin(shared.bounded_result_ready.notified());
        network_result.as_mut().enable();
        assert!(right.id_request_active());
        timeout(Duration::from_secs(2), async {
            runtime
                .send_message(
                    &alice.label,
                    &group,
                    b"send while EOSE is withheld".to_vec(),
                )
                .await
                .unwrap();
            let (respond, read) = oneshot::channel();
            commands
                .try_send(AccountWorkerCommand::QuarantinedGroups { respond })
                .unwrap();
            read.await.unwrap().unwrap();
            runtime
                .send_message(
                    &bob.label,
                    &group,
                    b"incoming while EOSE is withheld".to_vec(),
                )
                .await
                .unwrap();
            loop {
                if app
                    .messages(&alice.label)
                    .unwrap()
                    .iter()
                    .any(|message| message.plaintext == "incoming while EOSE is withheld")
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("send, read, and live projection finish within one outstanding acquisition");
        assert!(
            right.id_request_active(),
            "delayed exact-ID REQ is still open"
        );
        assert_eq!(right.counts().id_closes, 0);
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.known_event_id == Some(event_id))
        );
        assert!(
            futures::FutureExt::now_or_never(network_result.as_mut()).is_none(),
            "the worker has not accepted an SDK acquisition result"
        );
        if new_loss {
            let retained_before_loss = storage
                .retained_recovery_event(&route, &event_id, None, created_at)
                .unwrap();
            assert!(
                retained_before_loss,
                "the other relay already supplied valid retained evidence"
            );
            let demand_id = storage
                .pending_recovery_demands()
                .unwrap()
                .into_iter()
                .find(|d| d.known_event_id == Some(event_id))
                .unwrap()
                .ticket
                .id;
            let scope_before = storage.recovery_scope_snapshots(demand_id).unwrap();
            assert!(!scope_before.is_empty());
            assert!(scope_before.iter().all(|scope| !scope.retained_known_event));
            // finish() would report retained=true for this already-durable ID.
            // An accepted stale checkpoint would flip this frozen scope bit.
            let before = storage.recovery_revision_fence().unwrap();
            storage
                .record_account_delivery_loss(&alice.label, 777, 1, crate::unix_now_seconds())
                .unwrap();
            storage
                .synchronize_account_delivery_loss(&alice.label)
                .unwrap();
            let after = storage.recovery_revision_fence().unwrap();
            assert!(after.loss_revision > before.loss_revision);
            let retry_before_finish = storage.recovery_retry_state().unwrap();
            timeout(Duration::from_secs(10), async {
                loop {
                    if bounded_recovery::available_credits()
                        == bounded_recovery::MAX_CONCURRENT_JOBS
                    {
                        break;
                    }
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("bounded result releases capacity after the delayed relay");
            let scope_after = storage.recovery_scope_snapshots(demand_id).unwrap();
            assert_eq!(scope_after.len(), scope_before.len());
            for (prior, current) in scope_before.iter().zip(&scope_after) {
                assert!(current.token == prior.token);
                assert_eq!(current.attempt_serial, prior.attempt_serial);
                assert_eq!(current.loss_revision, prior.loss_revision);
                assert_eq!(current.retained_known_event, prior.retained_known_event);
                assert!(current.checkpoints == prior.checkpoints);
                assert!(current.loss_revision < after.loss_revision);
            }
            assert_eq!(
                storage.recovery_retry_state().unwrap().attempt_serial,
                retry_before_finish.attempt_serial,
                "no newer owner attempt may be confused with this stale result"
            );
            assert!(
                storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .any(|demand| demand.cause == storage_sqlite::RecoveryCause::QueueLoss)
            );
            assert!(
                storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .any(|demand| demand.known_event_id == Some(event_id))
            );
            runtime.shutdown_and_close().await.unwrap();
            bootstrap.shutdown();
            return;
        }
    }
    let completion = timeout(Duration::from_secs(10), async {
        loop {
            if storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|demand| demand.known_event_id != Some(event_id))
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        completion.is_ok(),
        "exact event must reach durable retention and clear demand: left={:?}, right={:?}, retained={}, demands={:?}, retry={:?}, probes={}",
        left.counts(),
        right.counts(),
        storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap(),
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .map(|d| (format!("{:?}", d.cause), d.known_event_id.is_some()))
            .collect::<Vec<_>>(),
        storage.recovery_retry_state().unwrap(),
        runtime
            .shared_services()
            .bounded_preparation_probes
            .load(std::sync::atomic::Ordering::SeqCst),
    );
    assert!(
        storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    let left_counts = left.counts();
    let right_counts = right.counts();
    for counts in [&left_counts, &right_counts] {
        assert_eq!(counts.id_requests, 1, "one exact-ID REQ per endpoint");
        assert!(
            counts.received_events <= 3,
            "fixture publication stays bounded"
        );
        assert!(counts.sent_events >= 1 && counts.sent_events <= 8);
        assert!(counts.received_text_bytes <= 6 * 1024);
        assert!(counts.sent_text_bytes <= 9 * 1024);
        assert!(counts.sent_event_json_bytes <= 8 * 1024);
    }
    if !omit_right_eose {
        assert_eq!(left_counts.sent_events, 1);
        assert_eq!(right_counts.sent_events, 1);
        assert_eq!(
            left_counts.sent_event_json_bytes,
            right_counts.sent_event_json_bytes
        );
        assert_eq!(
            left_counts.sent_event_json_bytes,
            historical.to_string().len()
        );
    }
    runtime.shutdown_and_close().await.unwrap();
    bootstrap.shutdown();
}
