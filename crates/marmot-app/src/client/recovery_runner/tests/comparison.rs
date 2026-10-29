//! Comparison and re-check units (PR 4c) over real account storage, against
//! the model relay answering NIP-77.

use super::*;
use storage_sqlite::TransportReconciliationItem;

impl Account {
    /// The account holds `events` on `route`: its reconciliation inventory.
    fn hold(&self, route: &Route, events: &[Event]) {
        let items = events
            .iter()
            .map(|event| TransportReconciliationItem {
                event_id: event.id.to_bytes(),
                created_at: event.created_at.as_secs(),
            })
            .collect::<Vec<_>>();
        self.app
            .record_reconciliation_items(items.iter().map(|item| (route, item)))
            .unwrap();
    }

    fn record_caps(&self, relay: &str, caps: RelayCaps, now: u64) {
        self.app
            .record_recovery_relay_caps(
                relay,
                Some(RecoveryRelayCaps {
                    max_limit: caps.max_limit,
                    negentropy: caps.negentropy,
                }),
                now,
            )
            .unwrap();
    }

    fn staged_events(&self, route: &Route) -> u64 {
        self.app
            .staged_recovery_usage(std::slice::from_ref(route), None)
            .unwrap()
            .events
    }
}

/// `count` events spread evenly over `[since, until)`.
fn spread(group: [u8; 32], since: u64, until: u64, count: u64) -> Vec<Event> {
    (0..count)
        .map(|index| event(group, since + index * (until - since) / count))
        .collect()
}

fn ids(events: &[Event]) -> BTreeSet<EventId> {
    events.iter().map(|event| event.id).collect()
}

/// A difference six times what one quantum may fetch, in a range whose relay
/// set is past the truncation limit: each quantum certifies a prefix under
/// the production item and byte limits, the next resumes after it, and no id
/// is fetched twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_compares_a_large_difference_in_prefixes_over_several_quanta() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - DAY;
    let held = spread([1; 32], floor, t0, 5_000);
    let missing = spread([1; 32], floor, t0, 12_000);
    account.hold(&route, &held);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(held.iter().chain(&missing).cloned().collect())
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    account.rechecked(&route, RELAY, t0);
    host.tails.stand(&route, RELAY, t0);
    let policy = test_policy();
    let per_quantum = usize::try_from(policy.staging.group_events).unwrap();
    let (mut runner, _handle) = runner(&host, policy);

    let mut quanta = 0;
    let mut owed_from = floor;
    while let Some(first) = account.debt(&route, RELAY, t0 - 1).first() {
        assert_eq!(
            first.since_seconds, owed_from,
            "the debt's prefix moved alone"
        );
        quanta += 1;
        assert!(quanta <= 12, "the difference never finished");
        let fetched_before = relay.fetched_ids().len();
        let summary = ran(runner.step().await);
        assert_eq!(
            (summary.outcome, summary.recheck),
            (Outcome::Advanced, false)
        );
        assert!(relay.fetched_ids().len() - fetched_before <= per_quantum);
        owed_from = account
            .debt(&route, RELAY, t0 - 1)
            .first()
            .map_or(t0, |owed| owed.since_seconds);
        assert!(
            owed_from > first.since_seconds,
            "a quantum certified no prefix"
        );
    }

    assert!(quanta >= 6, "the difference fit in {quanta} quanta");
    assert!(relay.queries().is_empty(), "a comparison unit swept");
    let comparisons = relay.comparisons();
    assert_eq!(
        (comparisons[0].since, comparisons[0].until),
        (floor, t0 - 1),
        "the first window is the whole debt"
    );
    let fetched = relay.fetched_ids();
    assert_eq!(fetched.len(), missing.len(), "an id was fetched twice");
    assert_eq!(fetched.into_iter().collect::<BTreeSet<_>>(), ids(&missing));
    assert_eq!(account.staged_events(&route), missing.len() as u64);
}

/// A unit compares only where the account already holds events in the owed
/// range; with nothing held, a sweep fetches the same events for fewer
/// requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_compares_where_the_account_holds_events_and_sweeps_elsewhere() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let (holding, empty) = (group(1), group(2));
    let floor = t0 - HOUR;
    let held = every([1; 32], floor, t0, 60);
    let missing = every([1; 32], floor + 30, t0, 60);
    account.hold(&holding, &held);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(
            held.iter()
                .chain(&missing)
                .cloned()
                .chain(every([2; 32], floor, t0, 60))
                .collect(),
        )
        .build();
    let routes = vec![required(&holding, &[RELAY]), required(&empty, &[RELAY])];
    let host = TestHost::new(&account, &clock, routes, &[&relay]);
    for route in [&holding, &empty] {
        account.goal(route, floor);
        account.rechecked(route, RELAY, t0);
        host.tails.stand(route, RELAY, t0);
    }
    let (mut runner, _handle) = runner(&host, test_policy());

    assert_eq!(run_until_idle(&mut runner, 4).await, [Outcome::Advanced; 2]);

    assert!(!relay.comparisons().is_empty());
    assert_eq!(
        relay.fetched_ids().into_iter().collect::<BTreeSet<_>>(),
        ids(&missing)
    );
    let swept = relay.queries();
    assert!(!swept.is_empty());
    assert!(swept.iter().all(|query| query.route
        == SweepRoute::Group {
            nostr_group_id: [2; 32]
        }));
    for route in [&holding, &empty] {
        assert!(account.debt(route, RELAY, t0 - 1).is_empty());
    }
}

/// Re-checks run only on required relays whose caps show NIP-77: a cap-only
/// relay's count proofs re-check nothing, and a best-effort relay is never
/// re-checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_never_rechecks_a_cap_only_relay() {
    const BEST_EFFORT: &str = "wss://c.example";
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - DAY;
    let events = every([1; 32], floor, t0, HOUR);
    account.hold(&route, &events);
    let cap_only = ModelRelay::new(RELAY, caps(500, false))
        .with_events(events.clone())
        .build();
    let compares = ModelRelay::new(OTHER_RELAY, caps(500, true))
        .with_events(events.clone())
        .build();
    let best_effort = ModelRelay::new(BEST_EFFORT, caps(500, true))
        .with_events(events)
        .build();
    let routes = vec![RunnerRoute {
        best_effort: vec![BEST_EFFORT.to_owned()],
        ..required(&route, &[RELAY, OTHER_RELAY])
    }];
    let host = TestHost::new(
        &account,
        &clock,
        routes,
        &[&cap_only, &compares, &best_effort],
    );
    account.goal(&route, floor);
    for relay in [RELAY, OTHER_RELAY, BEST_EFFORT] {
        account.live_boundary(&route, relay, floor, t0 - 1);
        host.tails.stand(&route, relay, t0);
    }
    account.record_caps(RELAY, caps(500, false), t0);
    account.record_caps(OTHER_RELAY, caps(500, true), t0);
    account.record_caps(BEST_EFFORT, caps(500, true), t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    let rechecked = ran(runner.step().await);
    assert_eq!(
        (rechecked.key.relay.as_str(), rechecked.recheck),
        (OTHER_RELAY, true)
    );
    assert_eq!(rechecked.outcome, Outcome::NoProgress);
    let done = clock.now();
    assert_eq!(
        idle(runner.step().await),
        Some(done + RUNNER_RECHECK_INTERVAL_SECS)
    );

    assert!(!compares.comparisons().is_empty());
    for untouched in [&cap_only, &best_effort] {
        assert_eq!(untouched.requests(), 0);
    }
    assert!(account.app.recovery_unit(&route, RELAY).unwrap().is_none());
    assert!(
        account
            .app
            .recovery_unit(&route, BEST_EFFORT)
            .unwrap()
            .is_none()
    );
}

/// A full pass is due again six hours after it finished, and at once after an
/// epoch gap, from the gap's bound. What it finds inside covered ranges
/// arrived late: it is staged and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_rechecks_six_hours_after_a_full_pass_and_at_once_after_an_epoch_gap() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - DAY;
    let held = every([1; 32], floor, t0, HOUR);
    let late = event([1; 32], floor + 90 * 60);
    account.hold(&route, &held);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(held.iter().cloned().chain([late.clone()]).collect())
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, floor);
    account.live_boundary(&route, RELAY, floor, t0 - 1);
    host.tails.stand(&route, RELAY, t0);
    account.record_caps(RELAY, caps(500, true), t0);
    let (mut runner, handle) = runner(&host, test_policy());

    // No pass has finished yet, so one is due at once. It finds the late
    // event and finishes.
    let first = ran(runner.step().await);
    assert!(first.recheck);
    assert_eq!(relay.fetched_ids(), [late.id]);
    assert_eq!(handle.late_findings(), 1);
    assert_eq!(account.staged_events(&route), 1);
    let finished = account.unit(&route, RELAY).recheck.completed_at_seconds;
    let finished = finished.expect("the pass finished");
    let due = finished + RUNNER_RECHECK_INTERVAL_SECS;
    assert_eq!(idle(runner.step().await), Some(due));

    // Due six hours on, and not before.
    clock.advance_to(due - 1);
    assert_eq!(idle(runner.step().await), Some(due));
    clock.advance_to(due);
    let again = ran(runner.step().await);
    assert_eq!((again.recheck, again.outcome), (true, Outcome::NoProgress));
    assert_eq!(handle.late_findings(), 1, "nothing new arrived late");
    assert!(idle(runner.step().await) > Some(clock.now()));

    // An epoch gap makes the group's re-check due at once, from its bound.
    let bound = floor + 12 * HOUR;
    account
        .app
        .make_recovery_recheck_due(&route, None, Some(bound))
        .unwrap();
    handle.bump();
    assert_eq!(
        account.unit(&route, RELAY).recheck.completed_at_seconds,
        None
    );
    let compared_before = relay.comparisons().len();
    let gap = ran(runner.step().await);
    assert!(gap.recheck);
    let windows = &relay.comparisons()[compared_before..];
    assert!(!windows.is_empty());
    assert!(windows.iter().all(|window| window.since >= bound));
    assert!(
        account
            .unit(&route, RELAY)
            .recheck
            .completed_at_seconds
            .is_some()
    );
}

/// A pass the relay fails mid-way keeps every range covered and resumes
/// where it got to, not from the window's floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_resumes_a_failed_recheck_pass_and_uncovers_nothing() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - DAY;
    // Two covered ranges with a gap the goal does not reach: two comparison
    // calls in one pass.
    let older = (floor, floor + HOUR - 1);
    let newer = (floor + 2 * HOUR, t0 - 1);
    let held = every([1; 32], floor, t0, HOUR);
    account.hold(&route, &held);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(held)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&route, &[RELAY])],
        &[&relay],
    );
    account.goal(&route, newer.0);
    account.live_boundary(&route, RELAY, older.0, older.1);
    account.live_boundary(&route, RELAY, newer.0, newer.1);
    host.tails.stand(&route, RELAY, t0);
    account.record_caps(RELAY, caps(500, true), t0);
    let still_covered = |account: &Account| {
        [older, newer].iter().all(|&(since, until)| {
            account
                .app
                .recovery_unit_cursor(&route, RELAY, since, until)
                .unwrap()
                .is_none()
        })
    };
    assert!(still_covered(&account));
    let (mut runner, _handle) = runner(&host, test_policy());

    // The older range compares; the relay drops before the newer one does.
    relay.gate.hold_from(1);
    let stepping = tokio::spawn(async move {
        let summary = ran(runner.step().await);
        (runner, summary)
    });
    wait_until("the second comparison", WAIT, || relay.gate.waiting() == 1).await;
    relay.set_reachable(false);
    relay.gate.open();
    let (mut runner, failed) = stepping.await.unwrap();
    assert_eq!(
        (failed.recheck, failed.outcome),
        (true, Outcome::Unreachable)
    );

    assert!(still_covered(&account), "a failed pass un-covered");
    assert!(account.debt(&route, RELAY, t0 - 1).is_empty());
    let pass = account.unit(&route, RELAY).recheck;
    assert_eq!(pass.position_seconds, Some(older.1 + 1));
    assert_eq!(pass.completed_at_seconds, None);

    // Held back while it moves nowhere, then it resumes past the older range.
    relay.set_reachable(true);
    let held_until = idle(runner.step().await).expect("the pass is held, not done");
    clock.advance_to(held_until);
    let compared_before = relay.comparisons().len();
    let resumed = ran(runner.step().await);
    assert_eq!(
        (resumed.recheck, resumed.outcome),
        (true, Outcome::NoProgress)
    );
    let windows = &relay.comparisons()[compared_before..];
    assert_eq!(windows.first().map(|window| window.since), Some(newer.0));
    assert!(
        account
            .unit(&route, RELAY)
            .recheck
            .completed_at_seconds
            .is_some()
    );
    assert!(still_covered(&account));
}
