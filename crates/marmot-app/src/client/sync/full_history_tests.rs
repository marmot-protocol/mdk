//! Explicit full-history repair runs the one comparison job in place. It
//! compares every route of its grant inside the repair budget, never installs
//! or replays a subscription, and succeeds only on certified coverage.
//! Cancellation and the deadline stop it at safe boundaries.
use super::*;
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
use crate::{MarmotApp, MarmotAppConfig};
use marmot_account::AccountHome;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture() -> (tempfile::TempDir, MarmotApp, Arc<ScriptedPushRelayClient>) {
    fixture_with_relays(vec!["wss://relay.example".to_owned()])
}

fn fixture_with_relays(
    relays: Vec<String>,
) -> (tempfile::TempDir, MarmotApp, Arc<ScriptedPushRelayClient>) {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays_and_config(dir.path(), relays, MarmotAppConfig::default())
        .with_test_relay_client(relay.clone());
    (dir, app, relay)
}

/// One scripted comparison per route the repair can select, each answered by
/// every relay the route compares.
fn answered(routes: usize) -> ScriptedComparisons {
    (0..routes)
        .map(|_| {
            Ok(Some((
                transport_nostr_adapter::NostrReconciliationSummary {
                    relays_succeeded: 1,
                    ..Default::default()
                },
                Vec::new(),
            )))
        })
        .collect()
}

fn explicit_pending(app: &MarmotApp) -> bool {
    app.account_storage("alice")
        .unwrap()
        .pending_recovery_demands()
        .unwrap()
        .iter()
        .any(|demand| demand.cause == storage_sqlite::RecoveryCause::ExplicitHistory)
}

fn control<'a>(
    timeout: Duration,
    cancelled: &'a (dyn Fn() -> bool + Sync),
) -> FullHistoryRepairControl<'a> {
    FullHistoryRepairControl {
        started: Instant::now(),
        timeout,
        cancelled,
    }
}

/// A relay may still hold an event older than the retained-inventory window.
/// No comparison searched below that floor, so a certified window must not
/// report full history: the repair names the unsearched history instead.
#[tokio::test]
async fn certified_window_reports_history_below_it_as_unsearched() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client.create_group("older history", &[]).await.unwrap();
    let route = app
        .group("alice", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let floor = crate::unix_now_seconds()
        .saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS);
    // The relay's older event sits a day below the floor. The comparison's
    // window starts at the floor, so its answer cannot name the event.
    let older = crate::tests::epoch_gap_probe(&route, floor - 24 * 60 * 60, "below-window");
    let before = relay.subscription_count();
    client.test_comparison_results = Some(ScriptedComparisons::by_route(|_| {
        Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            Vec::new(),
        )))
    }));
    let failure = client.repair_full_history().await.unwrap_err();
    assert_eq!(
        failure.source.full_history_repair_incomplete(),
        Some((
            crate::FullHistoryRepairIncompleteReason::BelowRetentionWindow,
            false
        ))
    );
    assert!(
        explicit_pending(&app),
        "history below the window stays explicit debt"
    );
    assert!(
        !client.state.seen_events.contains(&older.id),
        "nothing fetched the older event"
    );
    assert_eq!(
        relay.subscription_count(),
        before,
        "repair compares history; it never activates or replays"
    );
}

/// A comparison that returns just inside the budget can hand over a large
/// batch. Admission stops at the first turn boundary past the deadline: the
/// admitted prefix stays durable and the repair reports the deadline.
#[tokio::test]
async fn the_deadline_stops_admission_at_a_turn_boundary() {
    const FETCHED: usize = 200;
    let (_dir, app, _relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client.create_group("large batch", &[]).await.unwrap();
    let route = app
        .group("alice", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let route_id: [u8; 32] = hex::decode(&route).unwrap().try_into().unwrap();
    let now = crate::unix_now_seconds();
    let events = (0..FETCHED)
        .map(|index| transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
            subscription_id: None,
            event: crate::tests::epoch_gap_probe(&route, now - 60, &format!("batch-{index}")),
        })
        .collect::<Vec<_>>();
    let ids = events
        .iter()
        .map(|event| event.event.id.clone())
        .collect::<Vec<_>>();
    client.test_comparison_results = Some(ScriptedComparisons::by_route(move |compared| {
        Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            if *compared == TransportReconciliationRoute::Group(route_id) {
                events.clone()
            } else {
                Vec::new()
            },
        )))
    }));
    // The budget outlives the instant comparison but not a whole batch of
    // SQLCipher admissions.
    let budget = Duration::from_millis(300);
    let failure = client
        .repair_full_history_with_control(&control(budget, &|| false))
        .await
        .unwrap_err();
    assert_eq!(
        failure.source.full_history_repair_incomplete(),
        Some((crate::FullHistoryRepairIncompleteReason::Deadline, false))
    );
    let admitted = ids
        .iter()
        .filter(|id| client.state.seen_events.contains(id))
        .count();
    assert!(
        admitted < FETCHED,
        "admission stopped before the whole batch ({admitted} admitted)"
    );
    assert!(explicit_pending(&app), "an expired repair keeps its debt");
}

#[tokio::test]
async fn uncertified_repair_reports_unproven_coverage_and_keeps_its_debt() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    // No comparison backend: the relays cannot certify anything.
    let failure = client.repair_full_history().await.unwrap_err();
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_coverage_unproven")
    );
    assert_eq!(
        failure.classification().failure_stage,
        SyncFailureStage::RelayReceive
    );
    assert!(
        explicit_pending(&app),
        "uncertified explicit history stays debt"
    );
    assert_eq!(relay.subscription_count(), before);
}

#[tokio::test]
async fn cancelled_before_start_requests_nothing_and_keeps_overflow() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    let storage = app.account_storage("alice").unwrap();
    storage
        .mark_account_delivery_recovery("alice", 7, 1)
        .unwrap();
    client.delivery_overflow_recovery_pending = true;
    client.delivery_overflow_recovery_marker_token = Some(7);
    let retry = storage.recovery_retry_state().unwrap();
    let failure = client
        .repair_full_history_cancellable(&|| true)
        .await
        .unwrap_err();
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_repair_cancelled")
    );
    assert_eq!(relay.subscription_count(), before);
    assert_eq!(storage.recovery_retry_state().unwrap(), retry);
    assert!(!explicit_pending(&app));
    assert!(
        storage
            .account_delivery_recovery("alice")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn the_deadline_bounds_the_comparison_pass() {
    let (_dir, app, _relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    client.test_comparison_results = Some(answered(1));
    client.test_comparison_delay = Some(Duration::from_secs(30));
    let started = Instant::now();
    let failure = client
        .repair_full_history_with_control(&control(Duration::from_millis(200), &|| false))
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_repair_deadline")
    );
    assert!(explicit_pending(&app), "a timed-out route keeps its debt");
}

#[tokio::test]
async fn cancellation_stops_the_comparison_and_keeps_debt_and_cost() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    let storage = app.account_storage("alice").unwrap();
    client.test_comparison_results = Some(answered(1));
    client.test_comparison_delay = Some(Duration::from_secs(30));
    let checks = AtomicUsize::new(0);
    // The entry and credit checks pass; cancellation lands during the pass.
    let cancelled = || checks.fetch_add(1, Ordering::SeqCst) >= 4;
    let started = Instant::now();
    let failure = client
        .repair_full_history_with_control(&control(Duration::from_secs(20), &cancelled))
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_repair_cancelled")
    );
    assert_eq!(
        storage.recovery_retry_state().unwrap().attempt_serial,
        1,
        "the cancelled attempt keeps its retry cost"
    );
    assert!(explicit_pending(&app));
    assert_eq!(relay.subscription_count(), before);
}

#[tokio::test]
async fn unfinished_overflow_repair_survives_reopen() {
    let (dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    app.account_storage("alice")
        .unwrap()
        .mark_account_delivery_recovery("alice", 7, 1)
        .unwrap();
    client.delivery_overflow_recovery_pending = true;
    client.delivery_overflow_recovery_marker_token = Some(7);
    assert!(client.repair_full_history().await.is_err());
    drop(client);
    drop(app);
    let reopened =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    assert!(
        reopened
            .account_storage("alice")
            .unwrap()
            .account_delivery_recovery("alice")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn one_failed_required_relay_cannot_complete_full_history_repair() {
    let (_dir, app, relay) = fixture_with_relays(vec![
        "wss://fast.example".to_owned(),
        "wss://slow.example".to_owned(),
    ]);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    client.test_comparison_results = Some(
        [Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                relays_failed: 1,
                failed_endpoints: vec![cgka_traits::TransportEndpoint("wss://slow.example".into())],
                ..Default::default()
            },
            Vec::new(),
        )))]
        .into(),
    );
    assert!(client.repair_full_history().await.is_err());
    assert!(explicit_pending(&app));
    assert_eq!(relay.subscription_count(), before);
}

#[tokio::test]
async fn dropped_explicit_future_detaches_urgency_without_losing_other_debt_or_retry() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let storage = app.account_storage("alice").unwrap();
    storage
        .mark_account_delivery_recovery("alice", 42, 3)
        .unwrap();
    client.delivery_overflow_recovery_pending = true;
    client.delivery_overflow_recovery_marker_token = Some(42);
    client.test_comparison_results = Some(answered(1));
    client.test_comparison_delay = Some(Duration::from_secs(30));
    let before = relay.subscription_count();
    {
        let repair = client.repair_full_history();
        tokio::pin!(repair);
        tokio::select! {
            result = &mut repair => panic!("repair returned before cancellation: {result:?}"),
            () = async {
                timeout(Duration::from_secs(5), async {
                    while storage.recovery_retry_state().unwrap().attempt_serial == 0 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("repair must reserve its attempt before it is dropped");
                tokio::time::sleep(Duration::from_millis(100)).await;
            } => {}
        }
    }
    assert!(
        client.adapter.pending_delivery_overflow().is_some(),
        "dropping an active repair must release its transient plane recovery flag"
    );
    let demands = storage.pending_recovery_demands().unwrap();
    let explicit = demands
        .iter()
        .find(|d| d.cause == storage_sqlite::RecoveryCause::ExplicitHistory)
        .unwrap();
    assert!(
        !explicit.caller_waiting,
        "dropping the caller must remove foreground urgency"
    );
    assert!(
        demands
            .iter()
            .any(|d| d.cause == storage_sqlite::RecoveryCause::QueueLoss)
    );
    let pending_ids = demands.iter().map(|d| d.ticket.id).collect::<Vec<_>>();
    let retry = storage.recovery_retry_state().unwrap();
    assert_eq!(retry.attempt_serial, 1);
    assert!(retry.not_before_ms > retry.recorded_at_ms);
    assert_eq!(relay.subscription_count(), before);
    drop(client);
    let reopened = client_on_app_relay_plane(&app, "alice").await;
    let demands = storage.pending_recovery_demands().unwrap();
    assert_eq!(
        demands.iter().map(|d| d.ticket.id).collect::<Vec<_>>(),
        pending_ids,
        "reopen preserves every pending identity, including startup history demand"
    );
    assert!(!demands.iter().any(|d| d.caller_waiting));
    assert_eq!(storage.recovery_retry_state().unwrap(), retry);
    drop(reopened);
}

#[tokio::test]
async fn loss_handoff_active_attempt_does_not_advance_the_durable_cursor() {
    let (_dir, app, _relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let storage = app.account_storage("alice").unwrap();
    storage
        .mark_account_delivery_recovery("alice", 42, 3)
        .unwrap();
    client.delivery_overflow_recovery_pending = true;
    client.delivery_overflow_recovery_marker_token = Some(42);
    let _attempt = client.adapter.start_delivery_overflow_recovery(42);
    let old = client.checkpointed_transport_timestamp;
    client.state.last_transport_timestamp = Some(unix_now_seconds());
    assert!(
        client
            .checkpoint_sync_prefix(&mut SyncSummary::default(), false, 0)
            .await
            .is_ok()
    );
    assert_eq!(
        client.checkpointed_transport_timestamp, old,
        "an in-flight attempt is not acknowledged recovery"
    );
    drop(client);
    let reopened = client_on_app_relay_plane(&app, "alice").await;
    assert_eq!(reopened.checkpointed_transport_timestamp, old);
    assert!(
        storage
            .account_delivery_recovery("alice")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn qualified_loss_acknowledgment_persists_admitted_cursor_only_after_handoff() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let storage = app.account_storage("alice").unwrap();
    storage
        .mark_account_delivery_recovery("alice", 91, 1)
        .unwrap();
    client.delivery_overflow_recovery_pending = true;
    client.delivery_overflow_recovery_marker_token = Some(91);
    let before = relay.subscription_count();
    // An unbounded loss goal cannot certify by comparison; the synthetic
    // finite inventory supplies the qualified proof.
    client.test_recovery_evidence = Some(super::super::recovery::empty_finite_history);
    client.test_comparison_results = Some(answered(1));
    // The already admitted prefix is volatile while loss remains pending.
    client.state.last_transport_timestamp = Some(123);
    assert_ne!(
        app.load_state("alice").unwrap().last_transport_timestamp,
        Some(123)
    );
    client.repair_full_history().await.unwrap();
    assert!(!client.delivery_loss_blocks_cursor());
    assert!(
        storage
            .account_delivery_recovery("alice")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        app.load_state("alice").unwrap().last_transport_timestamp,
        Some(123)
    );
    assert_eq!(relay.subscription_count(), before);
}

/// Explicit synthetic backend evidence is separate from what a comparison
/// certifies. Empty finite endpoint inventories qualify; incomplete endpoint
/// admission/exhaustiveness or an omitted required endpoint must not qualify.
#[tokio::test]
async fn qualified_repair_requires_every_endpoint_and_complete_admission() {
    use super::super::recovery::{TestRecoveryEvidence, empty_finite_history};
    let cases: [(TestRecoveryEvidence, bool); 4] = [
        (
            |scope| {
                let mut proof = empty_finite_history(scope);
                proof.pop();
                proof
            },
            false,
        ),
        (
            |scope| {
                let mut proof = empty_finite_history(scope);
                proof[0].admission_complete = false;
                proof
            },
            false,
        ),
        (
            |scope| {
                let mut proof = empty_finite_history(scope);
                proof[0].exhaustive = false;
                proof
            },
            false,
        ),
        (empty_finite_history, true),
    ];
    for (evidence, qualifies) in cases {
        let (_dir, app, relay) =
            fixture_with_relays(vec!["wss://a.example".into(), "wss://b.example".into()]);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        client.test_recovery_evidence = Some(evidence);
        client.test_comparison_results = Some(answered(1));
        let before = relay.subscription_count();
        let result = client.repair_full_history().await;
        assert_eq!(result.is_ok(), qualifies, "{result:?}");
        assert_eq!(relay.subscription_count(), before);
        assert_eq!(explicit_pending(&app), !qualifies);
    }
}

/// A sync whose recovery debt no grant can select, here because the account
/// has no relay recovery may contact, never waits for a process credit, so a
/// busy pool cannot hold it behind another account's comparison.
#[tokio::test]
async fn a_sync_with_nothing_to_select_takes_no_recovery_credit() {
    use crate::runtime::account_worker::recovery_credits;
    let (_dir, app, _relay) = fixture_with_relays(Vec::new());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let _held = recovery_credits::hold_all_credits_for_test(&client.recovery_credits);
    assert!(
        client.recovery_pending().unwrap(),
        "startup history is debt"
    );
    tokio::time::timeout(Duration::from_secs(10), client.sync())
        .await
        .expect("the sync must not wait for a credit")
        .unwrap();
    assert_eq!(
        app.account_storage("alice")
            .unwrap()
            .recovery_retry_state()
            .unwrap()
            .attempt_serial,
        0,
        "no job ran"
    );
}

/// An in-place job counts against the process pool until its admission and
/// checkpoint finish, not only while its network request runs.
#[tokio::test]
async fn the_in_place_job_holds_its_credit_through_admission() {
    use crate::runtime::account_worker::recovery_credits;
    const FETCHED: usize = 12;
    let (_dir, app, _relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client.create_group("held credit", &[]).await.unwrap();
    let route = app
        .group("alice", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let route_id: [u8; 32] = hex::decode(&route).unwrap().try_into().unwrap();
    let now = crate::unix_now_seconds();
    let events = (0..FETCHED)
        .map(|index| transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
            subscription_id: None,
            event: crate::tests::epoch_gap_probe(&route, now - 60, &format!("held-{index}")),
        })
        .collect::<Vec<_>>();
    client.test_comparison_results = Some(ScriptedComparisons::by_route(move |compared| {
        Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            if *compared == TransportReconciliationRoute::Group(route_id) {
                events.clone()
            } else {
                Vec::new()
            },
        )))
    }));
    let pool = client.recovery_credits.clone();
    let available = std::sync::Mutex::new(Vec::new());
    // The repair's stop check runs at every admission turn boundary.
    let observe = || {
        available
            .lock()
            .unwrap()
            .push(recovery_credits::available_credits(&pool));
        false
    };
    let _ = client
        .repair_full_history_with_control(&control(Duration::from_secs(60), &observe))
        .await;
    let seen = available.into_inner().unwrap();
    assert!(
        seen.len() > FETCHED / 4,
        "the stop check ran at each admission turn: {seen:?}"
    );
    // The final entry is the repair's own verdict check, after settlement.
    let during_job = &seen[..seen.len() - 1];
    assert!(
        during_job
            .iter()
            .rev()
            .take(FETCHED / 4)
            .all(|&free| free == 1),
        "every admission turn still held the job's credit: {seen:?}"
    );
    assert_eq!(recovery_credits::available_credits(&pool), 2);
}
