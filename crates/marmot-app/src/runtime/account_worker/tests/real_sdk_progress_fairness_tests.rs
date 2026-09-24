//! Real relay ordering witnesses for the inactive bounded recovery worker.

use super::*;
use nostr_relay_builder::prelude::{BoxedFuture, Filter as RelayFilter, PolicyResult, QueryPolicy};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client as NostrSdkClient, Filter, Kind, RelayCapabilities, ReqTarget};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "test-policy-overrides")]
struct HeldScheduledConvergence(String);

#[cfg(feature = "test-policy-overrides")]
impl HeldScheduledConvergence {
    fn for_account(account_id_hex: &str) -> Self {
        assert!(
            super::super::HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
                .lock()
                .unwrap()
                .insert(account_id_hex.to_owned()),
            "this account already has a scheduled-convergence hold"
        );
        Self(account_id_hex.to_owned())
    }
}

#[cfg(feature = "test-policy-overrides")]
impl Drop for HeldScheduledConvergence {
    fn drop(&mut self) {
        super::super::HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
            .lock()
            .unwrap()
            .remove(&self.0);
    }
}

#[derive(Clone, Debug, Default)]
struct ExactGate {
    reject_broad: Arc<AtomicBool>,
    exact: Arc<Mutex<HashMap<String, usize>>>,
    held_id: Arc<Mutex<Option<String>>>,
    hold_exact: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl ExactGate {
    fn count(&self, id: &[u8; 32]) -> usize {
        self.exact
            .lock()
            .unwrap()
            .get(&hex::encode(id))
            .copied()
            .unwrap_or(0)
    }
}

impl QueryPolicy for ExactGate {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if let Some(ids) = &query.ids {
                {
                    let mut counts = self.exact.lock().unwrap();
                    for id in ids {
                        *counts.entry(id.to_hex()).or_default() += 1;
                    }
                }
                if self.hold_exact.load(Ordering::SeqCst)
                    && self
                        .held_id
                        .lock()
                        .unwrap()
                        .as_ref()
                        .is_none_or(|held| ids.iter().any(|id| held == &id.to_hex()))
                {
                    let released = self.release.notified();
                    tokio::pin!(released);
                    released.as_mut().enable();
                    self.entered.notify_one();
                    released.await;
                }
                PolicyResult::Accept
            } else if self.reject_broad.load(Ordering::SeqCst) {
                PolicyResult::Reject("ordinary history held by fixture".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

#[tokio::test]
#[cfg(feature = "test-policy-overrides")]
async fn bounded_real_sdk_retained_epochs_and_other_group_progress_before_exact_completion() {
    use cgka_traits::storage::ConvergencePassStorage;
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = ExactGate::default();
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(gate.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let config = crate::MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_settlement_quiescence_ms(100)
        .with_dev_scheduled_convergence_delay_ms(500);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let mut groups = Vec::new();
    for title in ["held history", "retained epochs", "other due group"] {
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
    timeout(Duration::from_secs(15), async {
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
    .expect("Bob joined each real MLS group");
    for group in [&groups[1], &groups[2]] {
        runtime
            .promote_admin(&alice.label, group, &bob.account_id_hex)
            .await
            .unwrap();
    }
    timeout(Duration::from_secs(10), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            let mut ready = true;
            for group in [&groups[1], &groups[2]] {
                let alice_epoch = runtime
                    .group_mls_state(&alice.label, group)
                    .await
                    .unwrap()
                    .epoch;
                let bob_epoch = runtime
                    .group_mls_state(&bob.label, group)
                    .await
                    .unwrap()
                    .epoch;
                ready &= alice_epoch == bob_epoch;
            }
            if ready {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Bob receives admin promotions before publishing commits");
    let inspector = NostrSdkClient::builder().build();
    inspector
        .add_relay(url.clone())
        .capabilities(RelayCapabilities::READ)
        .await
        .unwrap();
    inspector.connect().await;
    runtime
        .send_message(&bob.label, &groups[0], b"retained history probe".to_vec())
        .await
        .unwrap();
    let request_route: [u8; 32] = hex::decode(
        app.group(&alice.label, &hex::encode(&groups[0]))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let history_id = timeout(Duration::from_secs(10), async {
        loop {
            let events = inspector
                .fetch_events(ReqTarget::single(
                    url.as_str(),
                    [Filter::new().kind(Kind::MlsGroupMessage)],
                ))
                .timeout(Duration::from_secs(5))
                .await
                .unwrap();
            let found = events.into_iter().find_map(|event| {
                let transport =
                    transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&event).unwrap();
                let matching = matches!(transport.to_transport_message().unwrap().envelope,
                    cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id }
                    if transport_group_id.as_slice() == request_route);
                matching.then_some(event.id.to_bytes())
            });
            if let Some(id) = found {
                break id;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("valid MLS event is available for the held request");
    let storage = app.account_storage(&alice.label).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if storage
                .retained_recovery_event(
                    &storage_sqlite::TransportReconciliationRoute::Group(request_route),
                    &history_id,
                    None,
                    crate::unix_now_seconds(),
                )
                .unwrap()
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("history probe is already durably retained");
    // Defer Alice's scheduled pass without blocking her receive or command
    // turns. All four peer commits must be retained before the measured pass.
    let convergence_hold = HeldScheduledConvergence::for_account(&alice.account_id_hex);
    let initial = runtime
        .group_mls_state(&alice.label, &groups[1])
        .await
        .unwrap()
        .epoch;
    let published_before = inspector
        .fetch_events(ReqTarget::single(
            url.as_str(),
            [Filter::new().kind(Kind::MlsGroupMessage)],
        ))
        .timeout(Duration::from_secs(5))
        .await
        .unwrap()
        .into_iter()
        .map(|event| event.id.to_bytes())
        .collect::<Vec<_>>();
    for profile in ["epoch one", "epoch two", "epoch three"] {
        runtime
            .update_group_profile(&bob.label, &groups[1], Some(profile.into()), None)
            .await
            .unwrap();
    }
    runtime
        .update_group_profile(&bob.label, &groups[2], Some("other progress".into()), None)
        .await
        .unwrap();
    let backlog_route: [u8; 32] = hex::decode(
        app.group(&alice.label, &hex::encode(&groups[1]))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let other_route: [u8; 32] = hex::decode(
        app.group(&alice.label, &hex::encode(&groups[2]))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let retained_before = timeout(Duration::from_secs(3), async {
        loop {
            let events = inspector
                .fetch_events(ReqTarget::single(
                    url.as_str(),
                    [Filter::new().kind(Kind::MlsGroupMessage)],
                ))
                .timeout(Duration::from_secs(2))
                .await
                .unwrap();
            let mut backlog = Vec::new();
            let mut other = Vec::new();
            for event in events {
                if published_before.contains(&event.id.to_bytes()) {
                    continue;
                }
                let transport =
                    transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&event).unwrap();
                if let cgka_traits::transport::TransportEnvelope::GroupMessage {
                    transport_group_id,
                } = transport.to_transport_message().unwrap().envelope
                {
                    if transport_group_id.as_slice() == backlog_route {
                        backlog.push((event.id.to_bytes(), event.created_at.as_secs()));
                    }
                    if transport_group_id.as_slice() == other_route {
                        other.push((event.id.to_bytes(), event.created_at.as_secs()));
                    }
                }
            }
            let retained = backlog.len() == 3
                && other.len() == 1
                && backlog.iter().all(|(id, at)| {
                    storage
                        .retained_recovery_event(
                            &storage_sqlite::TransportReconciliationRoute::Group(backlog_route),
                            id,
                            None,
                            *at,
                        )
                        .unwrap()
                })
                && other.iter().all(|(id, at)| {
                    storage
                        .retained_recovery_event(
                            &storage_sqlite::TransportReconciliationRoute::Group(other_route),
                            id,
                            None,
                            *at,
                        )
                        .unwrap()
                });
            if retained
                && storage.convergence_pass(&groups[1]).unwrap().is_some()
                && storage.convergence_pass(&groups[2]).unwrap().is_some()
            {
                break true;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all valid commit bytes are retained before local progress");
    assert!(retained_before);
    assert_eq!(
        runtime
            .group_mls_state(&alice.label, &groups[1])
            .await
            .unwrap()
            .epoch,
        initial,
        "all three valid dependencies precede the first local epoch advance"
    );
    assert_ne!(
        app.group(&alice.label, &hex::encode(&groups[2]))
            .unwrap()
            .unwrap()
            .profile
            .name,
        "other progress",
        "the second group is due but has not yet projected"
    );
    let exact_before = gate.exact.lock().unwrap().clone();
    gate.hold_exact.store(true, Ordering::SeqCst);
    let shared = runtime.shared_services();
    let mut network_result = Box::pin(shared.bounded_result_ready.notified());
    network_result.as_mut().enable();
    storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: groups[0].as_slice(),
                event_id: &history_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    let mut entered = Box::pin(gate.entered.notified());
    entered.as_mut().enable();
    let mut activated = false;
    for _ in 0..4 {
        let (_, remaining, _) = runtime.recovery_retry_snapshot_for_test(&alice.label).await;
        runtime
            .advance_recovery_clock_for_test(&alice.label, remaining + Duration::from_millis(1))
            .await;
        if timeout(Duration::from_secs(3), entered.as_mut())
            .await
            .is_ok()
        {
            activated = true;
            break;
        }
    }
    assert!(
        activated,
        "separate exact request is held at the conforming relay: exact_requests={}, comparison={:?}, retry={:?}, demands={:?}",
        gate.exact.lock().unwrap().values().sum::<usize>(),
        {
            let c = storage.recovery_comparison().unwrap();
            (c.revision, c.settled_revision, c.attempt_serial)
        },
        storage.recovery_retry_state().unwrap(),
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .map(|d| format!("{:?}", d.cause))
            .collect::<Vec<_>>(),
    );
    let held_at = TokioInstant::now();
    let selected_hex = gate
        .exact
        .lock()
        .unwrap()
        .iter()
        .find(|(id, count)| **count > exact_before.get(*id).copied().unwrap_or(0))
        .map(|(id, _)| id.clone())
        .expect("the held query names the actual selected event");
    let selected_id: [u8; 32] = hex::decode(selected_hex).unwrap().try_into().unwrap();
    let selected_ticket = storage
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|d| d.known_event_id == Some(selected_id))
        .expect("held exact request belongs to an outstanding known-event ticket")
        .ticket
        .id;
    let selected_scope = storage.recovery_scope_snapshots(selected_ticket).unwrap();
    assert_eq!(selected_scope.len(), 1);
    assert!(
        selected_scope[0].plan.known_event_id == Some(selected_id),
        "frozen scope selected the held event"
    );
    let attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    assert_eq!(selected_scope[0].attempt_serial, attempt);
    drop(convergence_hold);
    // Re-evaluate the already-due timer after removing the test-only guard.
    let _ = runtime.recovery_retry_snapshot_for_test(&alice.label).await;
    let bob_tip = runtime
        .group_mls_state(&bob.label, &groups[1])
        .await
        .unwrap()
        .epoch;
    assert!(bob_tip >= initial + 3);
    let mut observed = initial;
    let mut advances = Vec::new();
    timeout(Duration::from_secs(4), async {
        loop {
            let epoch = runtime
                .group_mls_state(&alice.label, &groups[1])
                .await
                .unwrap()
                .epoch;
            if epoch > observed {
                advances.push((epoch, Instant::now()));
                observed = epoch;
            }
            let other_ready = app
                .group(&alice.label, &hex::encode(&groups[2]))
                .unwrap()
                .unwrap()
                .profile
                .name
                == "other progress";
            if observed >= bob_tip && other_ready {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("retained epochs and another due group progress before exact completion");
    assert!(
        advances.len() >= 2,
        "successive local epoch advances were observed"
    );
    let max_useful_gap = advances
        .windows(2)
        .map(|pair| pair[1].1.duration_since(pair[0].1))
        .max()
        .unwrap();
    assert!(
        max_useful_gap <= Duration::from_secs(3),
        "eligible local epoch advances waited {max_useful_gap:?} apart"
    );
    assert_eq!(
        app.group(&alice.label, &hex::encode(&groups[1]))
            .unwrap()
            .unwrap()
            .profile
            .name,
        "epoch three"
    );
    runtime
        .send_message(&alice.label, &groups[1], b"queued send".to_vec())
        .await
        .unwrap();
    runtime.quarantined_groups(&alice.label).await.unwrap();
    runtime
        .send_message(&bob.label, &groups[1], b"live during held history".to_vec())
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .any(|message| message.plaintext == "live during held history")
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("live input projected before exact completion");
    assert_eq!(
        gate.count(&selected_id),
        exact_before
            .get(&hex::encode(selected_id))
            .copied()
            .unwrap_or(0)
            + 1
    );
    let held_for = held_at.elapsed();
    assert!(
        held_for < Duration::from_secs(4),
        "fixture progress took {held_for:?} after relay entry, beyond the four-second budget for a five-second SDK request"
    );
    assert!(
        futures::FutureExt::now_or_never(network_result.as_mut()).is_none(),
        "the SDK request has not completed before local progress, commands and live input"
    );
    assert_eq!(
        storage.recovery_retry_state().unwrap().attempt_serial,
        attempt,
        "local progress did not start another recovery attempt"
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.known_event_id == Some(selected_id)),
        "held history request is still pending after useful progress"
    );
    gate.hold_exact.store(false, Ordering::SeqCst);
    gate.release.notify_waiters();
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}

#[tokio::test]
async fn bounded_real_sdk_two_missing_known_ids_receive_distinct_owner_turns() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = ExactGate::default();
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(gate.clone()));
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
    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "two missing IDs",
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
    .expect("Bob joins via the real SDK and MLS");
    runtime
        .sign_out(
            &alice.label,
            super::super::super::SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    for body in [b"missing-one".as_slice(), b"missing-two".as_slice()] {
        runtime
            .send_message(&bob.label, &group, body.to_vec())
            .await
            .unwrap();
    }
    let inspector = NostrSdkClient::builder().build();
    inspector
        .add_relay(url.clone())
        .capabilities(RelayCapabilities::READ)
        .await
        .unwrap();
    inspector.connect().await;
    let events = inspector
        .fetch_events(ReqTarget::single(
            url.as_str(),
            [Filter::new().kind(Kind::MlsGroupMessage)],
        ))
        .timeout(Duration::from_secs(10))
        .await
        .unwrap();
    let mut published = events
        .iter()
        .map(|event| (event.id.to_bytes(), event.created_at.as_secs()))
        .collect::<Vec<_>>();
    published.sort_by_key(|(id, _)| *id);
    published.dedup_by_key(|(id, _)| *id);
    assert_eq!(
        published.len(),
        2,
        "fixture published two valid MLS group events"
    );
    let ids = published.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let event_times = published.into_iter().collect::<HashMap<_, _>>();
    inspector.disconnect().await;
    gate.reject_broad.store(true, Ordering::SeqCst);
    runtime.sign_in_account(&alice.label).await.unwrap();
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
    let retained = |id: [u8; 32]| {
        storage
            .retained_recovery_event(
                &storage_sqlite::TransportReconciliationRoute::Group(route),
                &id,
                None,
                event_times[&id],
            )
            .unwrap()
    };
    for id in &ids {
        storage
            .request_recovery(
                storage_sqlite::RecoveryRequest::KnownEvent {
                    group_id: group.as_slice(),
                    event_id: id,
                },
                crate::client::recovery::wall_now_ms().unwrap(),
            )
            .unwrap();
    }
    let demands = storage.pending_recovery_demands().unwrap();
    let selected = demands
        .iter()
        .filter(|d| d.known_event_id.is_some())
        .map(|d| (d.ticket.id, d.known_event_id.unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        selected.len(),
        2,
        "both missing IDs have separate durable tickets"
    );
    gate.hold_exact.store(true, Ordering::SeqCst);
    let mut entered = Box::pin(gate.entered.notified());
    entered.as_mut().enable();
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    timeout(Duration::from_secs(20), entered.as_mut())
        .await
        .expect("one exact request entered the conforming relay");
    let first = selected
        .iter()
        .find(|(_, id)| gate.count(id) > 0)
        .unwrap()
        .1;
    let second = selected.iter().find(|(_, id)| *id != first).unwrap().1;
    assert!(
        !retained(first) && !retained(second),
        "both published events are still durably missing when the first exact query is held"
    );
    assert_eq!(
        gate.count(&first),
        1,
        "one selected ticket receives one request"
    );
    assert_eq!(
        gate.count(&second),
        0,
        "unselected ticket has no duplicate grant"
    );
    let first_ticket = selected.iter().find(|(_, id)| *id == first).unwrap().0;
    let second_ticket = selected.iter().find(|(_, id)| *id == second).unwrap().0;
    let first_scope = storage.recovery_scope_snapshots(first_ticket).unwrap();
    assert_eq!(first_scope.len(), 1);
    assert!(
        first_scope[0].plan.known_event_id == Some(first),
        "first frozen scope selected the held event"
    );
    let first_attempt = first_scope[0].attempt_serial;
    assert_eq!(
        first_attempt,
        storage.recovery_retry_state().unwrap().attempt_serial,
        "the selected ticket owns the active frozen grant"
    );
    assert!(
        storage
            .recovery_scope_snapshots(second_ticket)
            .unwrap()
            .iter()
            .all(|scope| scope.attempt_serial < first_attempt),
        "the other ticket has not received this grant"
    );
    gate.hold_exact.store(false, Ordering::SeqCst);
    gate.release.notify_waiters();
    timeout(Duration::from_secs(20), async {
        loop {
            let remaining = storage.pending_recovery_demands().unwrap();
            if remaining.iter().all(|d| d.known_event_id != Some(first)) {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("first valid MLS event is durably admitted");
    assert!(
        retained(first),
        "the first event is durably present when its known-event demand clears"
    );
    *gate.held_id.lock().unwrap() = Some(hex::encode(second));
    gate.hold_exact.store(true, Ordering::SeqCst);
    let mut second_entered = Box::pin(gate.entered.notified());
    second_entered.as_mut().enable();
    let (_, remaining, _) = runtime.recovery_retry_snapshot_for_test(&alice.label).await;
    runtime
        .advance_recovery_clock_for_test(&alice.label, remaining + Duration::from_millis(1))
        .await;
    timeout(Duration::from_secs(20), second_entered.as_mut())
        .await
        .expect("other ticket receives the next owner opportunity");
    assert!(
        !retained(second),
        "the second event remains durably missing while its exact query is held"
    );
    assert_eq!(
        gate.count(&first),
        1,
        "unrelated first request was not restarted"
    );
    assert_eq!(
        gate.count(&second),
        1,
        "other ticket received one exact request"
    );
    let second_scope = storage.recovery_scope_snapshots(second_ticket).unwrap();
    assert_eq!(second_scope.len(), 1);
    assert!(
        second_scope[0].plan.known_event_id == Some(second),
        "second frozen scope selected the other held event"
    );
    assert!(
        second_scope[0].attempt_serial > first_attempt,
        "a later frozen grant selected the other durable ticket"
    );
    gate.hold_exact.store(false, Ordering::SeqCst);
    gate.release.notify_waiters();
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}
