//! A returned SDK result belongs to the worker and account client that requested it.
//! Replacing that session drops the old job before admission; the replacement
//! worker must establish its own transport and admission evidence.

use super::*;
use base64::Engine as _;
use cgka_traits::{MessageId, storage::MessageStorage};
use nostr_relay_builder::prelude::{
    Event as RelayEvent, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase,
};
use nostr_sdk::prelude::{
    EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp as NostrTimestamp,
};

#[derive(Clone, Debug, Default)]
struct ExactQueryPeers {
    event_id_hex: Arc<Mutex<String>>,
    route_hex: Arc<Mutex<String>>,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    group_queries: Arc<Mutex<Vec<SocketAddr>>>,
}

impl QueryPolicy for ExactQueryPeers {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let wanted = self.event_id_hex.lock().unwrap();
            if query
                .ids
                .as_ref()
                .is_some_and(|ids| ids.iter().any(|id| id.to_hex() == *wanted))
            {
                self.peers.lock().unwrap().push(*addr);
            }
            let route = self.route_hex.lock().unwrap();
            if query
                .generic_tags
                .iter()
                .any(|(tag, values)| tag.as_char() == 'h' && values.contains(route.as_str()))
            {
                self.group_queries.lock().unwrap().push(*addr);
            }
            PolicyResult::Accept
        })
    }
}

#[tokio::test]
async fn real_sdk_returned_result_is_dropped_on_account_restart_before_new_session_recovery() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let bootstrap = MockRelay::run().await.unwrap();
    let bootstrap_url = bootstrap.url().await.to_string();
    let left_peers = ExactQueryPeers::default();
    let right_peers = ExactQueryPeers::default();
    let left_db = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        ..Default::default()
    });
    let right_db = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        ..Default::default()
    });
    let left = LocalRelay::new(
        RelayBuilder::default()
            .database(left_db.clone())
            .query_policy(left_peers.clone()),
    );
    let right = LocalRelay::new(
        RelayBuilder::default()
            .database(right_db.clone())
            .query_policy(right_peers.clone()),
    );
    left.run().await.unwrap();
    right.run().await.unwrap();
    let left_url = left.url().await.to_string();
    let right_url = right.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        bootstrap_url.clone(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let shared = runtime.shared_services();
    shared
        .bounded_group_recovery_enabled
        .store(true, Ordering::SeqCst);
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &bootstrap_url);
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "session replacement",
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
    .expect("Bob joins before the historical event");

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
    *left_peers.route_hex.lock().unwrap() = hex::encode(route);
    *right_peers.route_hex.lock().unwrap() = hex::encode(route);
    let reference_now = crate::unix_now_seconds();
    let created_at = reference_now.saturating_sub(300);
    let ordinary_lookback = runtime
        .shared_services()
        .relay_plane()
        .subscription_rebuild_lookback_secs()
        .unwrap_or(120);
    assert!(
        created_at
            > reference_now.saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS)
    );
    assert!(created_at < reference_now.saturating_sub(ordinary_lookback));
    // This signed Nostr transport event is intentionally not decryptable MLS
    // input. Its timestamp is inside the finite comparison inventory but older
    // than the live subscription's cutoff.
    let mut envelope = vec![0u8; 12];
    envelope.extend_from_slice(b"old-known-session-replacement-probe");
    assert!(envelope.len() >= transport_nostr_peeler::NOSTR_GROUP_CONTENT_MIN_LEN);
    let signed = EventBuilder::new(
        Kind::MlsGroupMessage,
        base64::engine::general_purpose::STANDARD.encode(envelope),
    )
    .tags([Tag::custom("h", [hex::encode(route)])])
    .custom_created_at(NostrTimestamp::from_secs(created_at))
    .finalize(&Keys::generate())
    .unwrap();
    let event_id = signed.id.to_bytes();
    let event_id_hex = signed.id.to_hex();
    *left_peers.event_id_hex.lock().unwrap() = event_id_hex.clone();
    *right_peers.event_id_hex.lock().unwrap() = event_id_hex.clone();
    let route_id = route;
    let route = storage_sqlite::TransportReconciliationRoute::Group(route);
    let storage = app.account_storage(&alice.label).unwrap();
    timeout(Duration::from_secs(45), runtime.catch_up_accounts())
        .await
        .expect("startup catch-up ends before relay history import")
        .unwrap();
    timeout(Duration::from_secs(20), async {
        loop {
            if !storage.recovery_comparison().unwrap().pending() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the pre-import comparison settles with genuinely empty inventory");
    let empty_comparison = storage.recovery_comparison().unwrap();
    assert!(empty_comparison.revision > 0);
    assert_eq!(empty_comparison.settled_revision, empty_comparison.revision);
    assert!(
        empty_comparison
            .plan
            .as_ref()
            .is_some_and(|plan| plan.routes.iter().any(|scope| {
                scope.transport_group_id == Some(route_id)
                    && scope.since_seconds.is_some_and(|since| since <= created_at)
                    && created_at <= scope.until_seconds
            }))
    );
    let relay_signed: RelayEvent =
        serde_json::from_value(serde_json::to_value(&signed).unwrap()).unwrap();
    assert!(
        left_db
            .event_by_id(&relay_signed.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        right_db
            .event_by_id(&relay_signed.id)
            .await
            .unwrap()
            .is_none()
    );
    left_db.save_event(&relay_signed).await.unwrap();
    right_db.save_event(&relay_signed).await.unwrap();
    assert!(
        left_db
            .event_by_id(&relay_signed.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        right_db
            .event_by_id(&relay_signed.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(left_peers.peers.lock().unwrap().is_empty());
    assert!(right_peers.peers.lock().unwrap().is_empty());
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap(),
        "ordinary history did not retain the target"
    );

    let credits_before = bounded_recovery::available_credits();
    shared
        .bounded_pause_before_admission
        .store(true, Ordering::SeqCst);
    let mut old_ready = Box::pin(shared.bounded_result_ready.notified());
    old_ready.as_mut().enable();
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
    timeout(Duration::from_secs(5), status)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), old_ready.as_mut())
        .await
        .expect("old worker accepts the real SDK result before admission");
    let old_witness = shared
        .bounded_result_witness
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(old_witness.account_label, alice.label);
    assert_eq!(old_witness.event_id, event_id);
    assert_eq!(old_witness.matching_items, 2);
    let old_attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    assert_eq!(old_witness.attempt_serial, old_attempt);
    assert_eq!(bounded_recovery::available_credits() + 1, credits_before);
    let demand_id = storage
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.known_event_id == Some(event_id))
        .unwrap()
        .ticket
        .id;
    let old_scope = storage
        .recovery_scope_snapshots(demand_id)
        .unwrap()
        .remove(0);
    assert_eq!(old_scope.attempt_serial, old_attempt);
    assert!(old_scope.checkpoints.is_empty());
    assert!(old_scope.plan.since_seconds.is_none());
    assert!(old_scope.plan.until_seconds >= created_at);
    let cursor_before = storage
        .load_account_projection_state(&alice.label, 0)
        .unwrap()
        .last_transport_timestamp;
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    assert!(
        !storage
            .has_ingress_dedup_marker(&MessageId::new(event_id))
            .unwrap()
    );
    for peers in [&left_peers, &right_peers] {
        assert_eq!(peers.peers.lock().unwrap().len(), 1);
    }
    let old_exact_peers = [
        left_peers.peers.lock().unwrap()[0],
        right_peers.peers.lock().unwrap()[0],
    ];
    let group_queries_before_restart = [
        left_peers.group_queries.lock().unwrap().len(),
        right_peers.group_queries.lock().unwrap().len(),
    ];

    // This public lifecycle operation waits for the old worker and SDK account
    // client to retire before constructing their replacements. The old Job is
    // dropped; its already-returned event is never offered to admission.
    let comparison_before_restart = storage.recovery_comparison().unwrap().settled_revision;
    runtime
        .restart_account(&alice.account_id_hex)
        .await
        .unwrap();
    assert_eq!(bounded_recovery::available_credits(), credits_before);
    assert!(
        !storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap(),
        "teardown cannot admit the old result"
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|demand| demand.ticket.id == demand_id)
    );
    let scopes_after_restart = storage.recovery_scope_snapshots(demand_id).unwrap();
    assert!(
        scopes_after_restart
            .iter()
            .all(|scope| scope.checkpoints.is_empty())
    );
    assert!(scopes_after_restart[0].token == old_scope.token);
    assert_eq!(scopes_after_restart[0].attempt_serial, old_attempt);
    assert_eq!(
        storage
            .load_account_projection_state(&alice.label, 0)
            .unwrap()
            .last_transport_timestamp,
        cursor_before
    );

    // The replacement worker may use its ordinary finite comparison to find
    // the relay-store import. That work is independent of the cancelled exact
    // job; it must produce its own durable retained row.
    runtime
        .advance_recovery_clock_for_test(&alice.label, Duration::from_secs(600))
        .await;
    let recovered = timeout(Duration::from_secs(20), async {
        loop {
            let comparison = storage.recovery_comparison().unwrap();
            let retained = storage
                .retained_recovery_event(&route, &event_id, None, created_at)
                .unwrap();
            let raw = storage.get_message(&MessageId::new(event_id)).is_ok();
            if comparison.settled_revision > comparison_before_restart && retained && raw {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if recovered.is_err() {
        let comparison = storage.recovery_comparison().unwrap();
        eprintln!(
            "replacement comparison outcome: revision={}, settled={}, attempt={}, retained={}, raw_state={:?}, terminal={}, left_exact={}, right_exact={}, retry={:?}",
            comparison.revision,
            comparison.settled_revision,
            comparison.attempt_serial,
            storage
                .retained_recovery_event(&route, &event_id, None, created_at)
                .unwrap(),
            storage
                .get_message(&MessageId::new(event_id))
                .map(|row| row.state),
            storage
                .has_ingress_dedup_marker(&MessageId::new(event_id))
                .unwrap(),
            left_peers.peers.lock().unwrap().len(),
            right_peers.peers.lock().unwrap().len(),
            storage.recovery_retry_state(),
        );
    }
    recovered.expect("replacement session durably handles imported relay history");
    let comparison = storage.recovery_comparison().unwrap();
    assert!(comparison.settled_revision > comparison_before_restart);
    assert!(
        comparison
            .plan
            .as_ref()
            .is_some_and(|plan| plan.routes.iter().any(|scope| {
                scope.transport_group_id == old_scope.plan.transport_group_id
                    && scope.since_seconds.is_some_and(|since| since <= created_at)
                    && created_at <= scope.until_seconds
            })),
        "the replacement comparison covered the imported target timestamp"
    );
    let raw = storage.get_message(&MessageId::new(event_id)).unwrap();
    assert_eq!(raw.state, cgka_traits::MessageState::PeelDeferred);
    for (index, peers) in [&left_peers, &right_peers].into_iter().enumerate() {
        let queries = peers.group_queries.lock().unwrap();
        assert!(
            queries[group_queries_before_restart[index]..]
                .iter()
                .any(|peer| *peer != old_exact_peers[index]),
            "replacement group comparison uses a new socket"
        );
    }
    assert!(
        shared.bounded_pause_before_admission.load(Ordering::SeqCst),
        "replacement bounded admission remained paused"
    );
    assert!(
        storage
            .retained_recovery_event(&route, &event_id, None, created_at)
            .unwrap()
    );
    runtime.shutdown_and_close().await.unwrap();
    bootstrap.shutdown();
    left.shutdown();
    right.shutdown();
}
