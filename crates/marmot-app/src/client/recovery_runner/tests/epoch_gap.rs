//! Visit pacing/exhaustion runs the real runner and durable ledger with a clock.

use super::*;

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
    let events = every([1; 32], now - 16, now, 1);
    account.swept(&route, RELAY, &events, now - 100, now - 1);
    let mut owned = required(&route, &[RELAY]);
    owned.group_id = Some(vec![0x0a]);
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(events.clone())
        .build();
    let host = TestHost::new(&account, &clock, vec![owned], &[&relay]);
    host.tails.stand(&route, RELAY, now);
    host.ingest_seconds.store(5, Ordering::SeqCst);
    let policy = test_policy();
    let (mut owner, _) = runner(&host, policy);
    owner.step().await;
    assert!(
        account.admitted_events() <= policy.admission_per_turn as u64,
        "an admission batch must return to the runner's retry selection"
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
