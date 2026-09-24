//! Real SDK, relay-plane, worker and SQLCipher qualification for the exact-ID slice.

use super::*;
use futures::{SinkExt, StreamExt};
use nostr_relay_builder::MockRelay;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};

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
    timeout(Duration::from_secs(8), async {
        loop {
            if storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|d| d.known_event_id != Some(event_id))
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("retained KnownEvent clears under owner selection");
    let after_local = storage.recovery_comparison().unwrap();
    assert!(after_local.pending());
    assert_eq!(
        after_local.settled_revision,
        comparison_before.settled_revision
    );
    assert_eq!(
        app.relay_telemetry().await.metrics.reconciliation_attempts,
        telemetry_before,
        "clearing one retained ID did not service NIP-77 debt"
    );
    let comparison_wait_started = Instant::now();
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(20), async {
        loop {
            if storage.recovery_comparison().unwrap().settled_revision
                > comparison_before.settled_revision
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("automatic tick settles comparison on a conforming NIP-77 relay");
    let after_tick = storage.recovery_comparison().unwrap();
    assert_eq!(after_tick.settled_revision, after_tick.revision);
    assert!(after_tick.attempt_serial > after_local.attempt_serial);
    assert!(comparison_wait_started.elapsed() < Duration::from_secs(20));
    assert!(
        app.relay_telemetry().await.metrics.reconciliation_attempts > telemetry_before,
        "the conforming relay was compared by the SDK"
    );
    runtime.shutdown_and_close().await.unwrap();
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
            assert!(right.id_request_active());
            let demand_id = storage
                .pending_recovery_demands()
                .unwrap()
                .into_iter()
                .find(|d| d.known_event_id == Some(event_id))
                .unwrap()
                .ticket
                .id;
            let scope_before = storage.recovery_scope_snapshots(demand_id).unwrap();
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
