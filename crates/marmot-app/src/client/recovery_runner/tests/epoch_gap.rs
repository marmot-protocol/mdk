//! Visit pacing/exhaustion runs the real runner and durable ledger with a clock.

use super::*;

// Paused time tests local-drain pacing without waiting on wall time.
#[tokio::test(start_paused = true)]
async fn epoch_gap_visit_waits_for_its_releasable_history() {
    let account = account();
    account
        .fault_connection()
        .execute_batch("INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');")
        .unwrap();
    let clock = Clock::new();
    let now = clock.now();
    let route = group(1);
    account.goal(&route, now - 100);
    account
        .app
        .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
            group_id_hex: "0a".into(),
            stalled_epoch: 1,
        }])
        .unwrap();
    let ticket = account.app.pending_recovery_demands().unwrap()[0].ticket;
    account
        .app
        .begin_recovery_epoch_gap_retry(ticket, &[(route.clone(), now - 100)], now)
        .unwrap();
    let count = test_policy().admission_per_turn as u64 * 4;
    let events = every([1; 32], now - count, now, 1);
    account.swept(&route, RELAY, &events, now - 100, now - 1);
    let mut owned = required(&route, &[RELAY]);
    owned.group_id = Some(vec![0x0a]);
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(events.clone())
        .build();
    let host = TestHost::new(&account, &clock, vec![owned], &[&relay]);
    host.tails.stand(&route, RELAY, now);
    host.ingest_seconds.store(5, Ordering::SeqCst);
    *host.debt_turn_latency.lock().unwrap() = Duration::from_millis(100);
    let (mut owner, _) = runner(&host, test_policy());
    // Observe a genuinely admitted prefix before its pass budget ends, rather
    // than assuming that a whole runner step means one worker batch.
    owner.run_pass(Duration::from_millis(100)).await;
    assert!(account.admitted_events() > 0);
    assert!(account.admitted_events() < events.len() as u64);
    assert!(
        account
            .app
            .recovery_epoch_gap_retry(ticket)
            .unwrap()
            .unwrap()
            .in_progress,
        "a visit must not finish while its own fetched history is ready for admission"
    );
    *host.debt_turn_latency.lock().unwrap() = Duration::ZERO;
    for _ in 0..events.len() {
        if account.admitted_events() == events.len() as u64 {
            break;
        }
        owner.step().await;
    }
    assert_eq!(account.admitted_events(), events.len() as u64);
    let state = account
        .app
        .recovery_epoch_gap_retry(ticket)
        .unwrap()
        .unwrap();
    assert_eq!(
        state.visits, 1,
        "local admission must not spend return visits"
    );
    assert!(!state.in_progress);
    assert_eq!(
        state.next_retry_at_seconds,
        clock.now() + test_policy().unit.backoff_base_seconds
    );
}

// Paused time covers an outage longer than the entire ordinary visit schedule.
#[tokio::test(start_paused = true)]
async fn epoch_gap_outage_does_not_spend_unanswered_visit_budget() {
    let account = account();
    account
        .fault_connection()
        .execute_batch("INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');")
        .unwrap();
    let clock = Clock::new();
    let now = clock.now();
    let route = group(1);
    account.goal(&route, now - 100);
    account
        .app
        .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
            group_id_hex: "0a".into(),
            stalled_epoch: 1,
        }])
        .unwrap();
    let ticket = account.app.pending_recovery_demands().unwrap()[0].ticket;
    let mut owned = required(&route, &[RELAY]);
    owned.group_id = Some(vec![0x0a]);
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .unreachable()
        .build();
    let host = TestHost::new(&account, &clock, vec![owned], &[&relay]);
    host.tails.stand(&route, RELAY, now);
    let (mut owner, _) = runner(&host, test_policy());
    assert_eq!(ran(owner.step().await).outcome, Outcome::Unreachable);
    owner.step().await;
    let state = account
        .app
        .recovery_epoch_gap_retry(ticket)
        .unwrap()
        .unwrap();
    assert!(
        state.in_progress,
        "an unanswered visit is still in progress during an outage"
    );
    clock.advance(3600);
    let (mut owner, handle) = runner(&host, test_policy());
    owner.step().await;
    let state = account
        .app
        .recovery_epoch_gap_retry(ticket)
        .unwrap()
        .unwrap();
    assert_eq!(state.visits, 1);
    assert!(!state.exhausted);
    relay.set_reachable(true);
    handle.relay_reconnected(RELAY);
    // A reconnect need not waive the unit's ordinary unreachable backoff.
    clock.advance_to(account.unit(&route, RELAY).next_attempt_at_seconds);
    assert_eq!(ran(owner.step().await).outcome, Outcome::Advanced);
    assert!(
        account
            .app
            .recovery_coverage_covers(&route, &[RELAY.into()], now - 100, now - 1)
            .unwrap(),
        "a reachable source resumes the unfinished visit without explicit repair"
    );
}

// Paused time makes a slow relay deterministic without a wall-clock wait.
#[tokio::test(start_paused = true)]
async fn ready_history_admission_does_not_wait_for_newer_network_debt() {
    for (gap_pending, turn_ms) in [(false, 0), (true, 0), (false, 100), (true, 100)] {
        let account = account();
        account
            .fault_connection()
            .execute_batch("INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');")
            .unwrap();
        let clock = Clock::new();
        let now = clock.now();
        let route = group(1);
        // Keep sixteen batches at every production batch size: enlarging a
        // batch must not accidentally erase the scheduling regression.
        let since = now - test_policy().admission_per_turn as u64 * 16 - 20;
        account.goal(&route, since);
        if gap_pending {
            account
                .app
                .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                    group_id_hex: "0a".into(),
                    stalled_epoch: 1,
                }])
                .unwrap();
            let ticket = account.app.pending_recovery_demands().unwrap()[0].ticket;
            account
                .app
                .begin_recovery_epoch_gap_retry(ticket, &[(route.clone(), since)], now)
                .unwrap();
        }
        // Every staged event is below the required source's frontier. Only
        // newer history still needs the network, so none of these deliveries
        // needs to wait for that request to answer.
        let events = every([1; 32], since, now - 20, 1);
        account.swept(&route, RELAY, &events, since, now - 20);
        let mut owned = required(&route, &[RELAY]);
        owned.group_id = Some(vec![0x0a]);
        let relay = ModelRelay::new(RELAY, caps(500, false))
            .with_latency(Duration::from_secs(2))
            .build();
        let host = TestHost::new(&account, &clock, vec![owned], &[&relay]);
        host.tails.stand(&route, RELAY, now);
        *host.debt_turn_latency.lock().unwrap() = Duration::from_millis(turn_ms);
        let (mut owner, _) = runner(&host, test_policy());
        // Ready history gets the same bounded pass when worker commands delay
        // its turns. A pending gap must not double its scheduling round trips.
        let budget = if turn_ms == 0 { 1 } else { 2 };
        owner.run_pass(Duration::from_secs(budget)).await;
        assert_eq!(
            account.admitted_events(),
            events.len() as u64,
            "ready history must drain before waiting on newer network debt; gap_pending={gap_pending}, turn_ms={turn_ms}"
        );
    }
}

// Paused time exercises relay backoff without waiting on wall time.
#[tokio::test(start_paused = true)]
async fn epoch_gap_revisits_a_healthy_source_while_another_is_unreachable() {
    let account = account();
    account
        .fault_connection()
        .execute_batch("INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');")
        .unwrap();
    let clock = Clock::new();
    let now = clock.now();
    let route = group(1);
    account.goal(&route, now - 100);
    let mut owned = required(&route, &[RELAY, OTHER_RELAY]);
    owned.group_id = Some(vec![0x0a]);
    let healthy = ModelRelay::new(RELAY, caps(500, false)).build();
    let unavailable = ModelRelay::new(OTHER_RELAY, caps(500, false))
        .unreachable()
        .build();
    let host = TestHost::new(&account, &clock, vec![owned], &[&healthy, &unavailable]);
    host.tails.stand(&route, RELAY, now);
    host.tails.stand(&route, OTHER_RELAY, now);
    account
        .app
        .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
            group_id_hex: "0a".into(),
            stalled_epoch: 1,
        }])
        .unwrap();
    let (mut owner, _) = runner(&host, test_policy());
    for _ in 0..16 {
        if healthy.requests.load(Ordering::SeqCst) >= 2 {
            break;
        }
        if let Step::Idle { next_due: Some(at) } = owner.step().await {
            clock.advance_to(at);
        }
    }
    assert!(unavailable.requests.load(Ordering::SeqCst) > 0);
    assert!(
        healthy.requests.load(Ordering::SeqCst) >= 2,
        "an unavailable source must not block return visits to a healthy one"
    );
    assert!(
        !account
            .app
            .recovery_coverage_covers(&route, &[OTHER_RELAY.into()], now - 100, now - 1)
            .unwrap(),
        "a failed source's debt must remain uncovered"
    );
}

// Paused time makes admission cost observable without waiting on wall time.
#[tokio::test(start_paused = true)]
async fn epoch_gap_retry_is_not_starved_by_a_large_staged_admission() {
    let account = account();
    account
        .fault_connection()
        .execute_batch("INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');")
        .unwrap();
    let clock = Clock::new();
    let now = clock.now();
    let route = group(1);
    account.goal(&route, now - 100);
    account
        .app
        .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
            group_id_hex: "0a".into(),
            stalled_epoch: 1,
        }])
        .unwrap();
    let ticket = account
        .app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|d| d.cause == storage_sqlite::RecoveryCause::EpochGap)
        .unwrap()
        .ticket;
    account
        .app
        .begin_recovery_epoch_gap_retry(ticket, &[(route.clone(), now - 100)], now)
        .unwrap();
    // The gap's own ready prefix must drain before another visit. This
    // separate group's backlog cannot postpone a due visit for the gap.
    let other_route = group(2);
    let count = test_policy().admission_per_turn as u64 * 4;
    let events = every([2; 32], now - count, now, 1);
    account.goal(&other_route, now - 100);
    account.swept(&route, RELAY, &[], now - 100, now - 1);
    account.swept(&other_route, RELAY, &events, now - 100, now - 1);
    let mut owned = required(&route, &[RELAY]);
    owned.group_id = Some(vec![0x0a]);
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(events.clone())
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![owned, required(&other_route, &[RELAY])],
        &[&relay],
    );
    host.tails.stand(&other_route, RELAY, now);
    host.tails.stand(&route, RELAY, now);
    host.ingest_seconds.store(5, Ordering::SeqCst);
    let policy = test_policy();
    let (mut owner, _) = runner(&host, policy);
    owner.step().await;
    assert!(
        host.largest_admission_batch.load(Ordering::SeqCst) <= policy.admission_per_turn,
        "each worker command must keep admission bounded while checking due visits"
    );
    for _ in 0..4 {
        if account
            .app
            .recovery_epoch_gap_retry(ticket)
            .unwrap()
            .unwrap()
            .visits
            >= 2
        {
            break;
        }
        owner.step().await;
    }
    assert_eq!(
        account
            .app
            .recovery_epoch_gap_retry(ticket)
            .unwrap()
            .unwrap()
            .visits,
        2
    );
    assert!(
        account.admitted_events() < events.len() as u64,
        "the due missing-epoch visit must not wait for every newer staged event"
    );
}

// Paused time needs the current-thread runtime; network answers are immediate.
#[tokio::test(start_paused = true)]
async fn unresolved_epoch_gap_revisits_are_paced_bounded_and_suspendable() {
    for resolve_early in [false, true] {
        let account = account();
        account
            .fault_connection()
            .execute_batch("INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');")
            .unwrap();
        let route = group(1);
        let clock = Clock::new();
        let now = clock.now();
        account.goal(&route, now - 100);
        account.live_boundary(&route, RELAY, now - 100, now - 1);
        let mut owned = required(&route, &[RELAY]);
        owned.group_id = Some(vec![0x0a]);
        let relay = Arc::new(ModelRelay::new(RELAY, caps(500, false)));
        let host = TestHost::new(&account, &clock, vec![owned], &[&relay]);
        host.tails.stand(&route, RELAY, now);
        let intent = storage_sqlite::StoredEpochBackfillIntent {
            group_id_hex: "0a".into(),
            stalled_epoch: 1,
        };
        account
            .app
            .arm_epoch_backfill_intents(std::slice::from_ref(&intent))
            .unwrap();
        let ticket = account
            .app
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|d| d.cause == storage_sqlite::RecoveryCause::EpochGap)
            .unwrap()
            .ticket;
        let policy = test_policy();
        let (mut owner, _) = runner(&host, policy);
        for visit in 1..=u64::from(policy.unit.break_after_no_progress) {
            let result = ran(owner.step().await);
            assert!(
                !result.recheck,
                "normal bounded runner quanta serve the reopened goal"
            );
            assert_eq!(
                account
                    .app
                    .recovery_epoch_gap_retry(ticket)
                    .unwrap()
                    .unwrap()
                    .visits,
                visit
            );
            assert!(matches!(owner.step().await, Step::Idle { .. }));
            let state = account
                .app
                .recovery_epoch_gap_retry(ticket)
                .unwrap()
                .unwrap();
            let requests = relay.requests.load(Ordering::SeqCst);
            if resolve_early && visit == 2 {
                account
                    .app
                    .clear_epoch_backfill_intents(std::slice::from_ref(&intent))
                    .unwrap();
                clock.advance(3600);
                assert!(matches!(owner.step().await, Step::Idle { next_due: None }));
                assert_eq!(relay.requests.load(Ordering::SeqCst), requests);
                break;
            }
            if visit == u64::from(policy.unit.break_after_no_progress) {
                let notices = account
                    .app
                    .parked_group_recovery_obligations(&[0x0a])
                    .unwrap();
                assert_eq!(notices.len(), 1);
                assert_eq!(notices[0].cause, storage_sqlite::RecoveryCause::EpochGap);
                clock.advance(3600);
                assert!(matches!(owner.step().await, Step::Idle { next_due: None }));
                assert_eq!(
                    relay.requests.load(Ordering::SeqCst),
                    requests,
                    "exhaustion stops network work"
                );
                break;
            }
            let delay = (policy.unit.backoff_base_seconds << (visit - 1))
                .min(policy.unit.backoff_cap_seconds);
            assert_eq!(state.next_retry_at_seconds, clock.now() + delay);
            account
                .app
                .arm_epoch_backfill_intents(std::slice::from_ref(&intent))
                .unwrap();
            let (replacement, _) = runner(&host, policy);
            owner = replacement;
            clock.advance_to(state.next_retry_at_seconds - 1);
            assert!(
                matches!(owner.step().await,Step::Idle{next_due:Some(at)} if at == state.next_retry_at_seconds)
            );
            assert_eq!(
                relay.requests.load(Ordering::SeqCst),
                requests,
                "restart and duplicate observations cannot bypass pacing"
            );
            if visit == 1 {
                host.routes.lock().unwrap()[0].unrecoverable = true;
                clock.advance_to(state.next_retry_at_seconds + 1);
                assert!(matches!(owner.step().await, Step::Idle { next_due: None }));
                assert_eq!(
                    relay.requests.load(Ordering::SeqCst),
                    requests,
                    "suspension grants no visit"
                );
                host.routes.lock().unwrap()[0].unrecoverable = false;
            } else {
                clock.advance_to(state.next_retry_at_seconds);
            }
        }
    }
}
