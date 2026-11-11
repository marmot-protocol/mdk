//! The account inbox's units (PR 5e): compared only, never swept, admitted
//! as a group of their own, and never fencing.

use super::comparison::{ids, spread};
use super::*;

/// Gift wraps to the account, every `step` seconds in `[since, until)`.
fn wraps(since: u64, until: u64, step: u64) -> Vec<Event> {
    (since..until)
        .step_by(usize::try_from(step).unwrap())
        .map(|at| wrap(INBOX_KEY, at))
        .collect()
}

/// The inbox's debt is compared even where the account holds nothing: only
/// the account's own gift wraps are fetched, by id, and admitted, and its
/// re-check runs too. Another recipient's wraps and a group event tagged
/// with the same bytes are not the inbox's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_compares_the_inbox_never_sweeps_it_and_admits_its_wraps() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let floor = t0 - DAY;
    let ours = wraps(floor, t0, HOUR);
    let mut events = ours.clone();
    events.extend([
        wrap([0xBB; 32], floor + HOUR),
        event(INBOX_KEY, floor + HOUR),
    ]);
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .with_events(events)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&Route::Inbox, &[RELAY])],
        &[&relay],
    );
    account.goal(&Route::Inbox, floor);
    host.tails.stand(&Route::Inbox, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    let outcomes = run_until_idle(&mut runner, 8).await;

    assert_eq!(outcomes.first(), Some(&Outcome::Advanced));
    assert!(relay.queries().is_empty(), "the inbox was swept");
    assert!(relay.seconds().is_empty(), "the inbox was swept");
    assert_eq!(
        relay.fetched_ids().into_iter().collect::<BTreeSet<_>>(),
        ids(&ours)
    );
    assert!(account.debt(&Route::Inbox, RELAY, t0 - 1).is_empty());
    // Admission took every wrap: none was given back as unlisted, which
    // would have owed its seconds again.
    assert_eq!(account.staged_events(&Route::Inbox), 0);
    assert_eq!(account.admitted_events(), ours.len() as u64);
    assert!(
        account
            .unit(&Route::Inbox, RELAY)
            .recheck
            .completed_at_seconds
            .is_some(),
        "the inbox was never re-checked"
    );
}

/// An inbox relay that does not speak NIP-77 refuses the inbox's unit, which
/// has no sweep to fall back on, so the route parks for a notice. A group on
/// the same relay is swept as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_breaks_an_inbox_unit_whose_relay_will_not_compare() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let floor = t0 - DAY;
    let group_route = group(1);
    let mut events = wraps(floor, t0, HOUR);
    events.extend(every([1; 32], floor, t0, HOUR));
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(events)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![
            required(&Route::Inbox, &[RELAY]),
            required(&group_route, &[RELAY]),
        ],
        &[&relay],
    );
    for route in [&Route::Inbox, &group_route] {
        account.goal(route, floor);
        host.tails.stand(route, RELAY, t0);
    }
    let (mut runner, _handle) = runner(&host, test_policy());

    run_until_idle(&mut runner, 8).await;

    assert_eq!(
        account.unit(&Route::Inbox, RELAY).state,
        RecoveryUnitState::Broken(RecoveryUnitBreak::Refused)
    );
    assert!(relay.fetched_ids().is_empty());
    assert!(!relay.queries().is_empty(), "the group was not swept");
    assert!(account.debt(&group_route, RELAY, t0 - 1).is_empty());
    let parked = account.app.parked_recovery_routes().unwrap();
    assert_eq!(
        parked
            .iter()
            .map(|parked| parked.route.clone())
            .collect::<Vec<_>>(),
        [Route::Inbox]
    );
}

/// A relay that restricts the inbox's gift wraps refuses only the inbox's
/// unit: its groups still compare there, not sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_keeps_comparing_groups_on_a_relay_that_refuses_the_inbox() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let floor = t0 - DAY;
    let group_route = group(1);
    let held = spread([1; 32], floor, t0, 20);
    let missing = spread([1; 32], floor + 1, t0, 20);
    account.hold(&group_route, &held);
    let mut events = wraps(floor, t0, HOUR);
    events.extend(held.iter().chain(&missing).cloned());
    let relay = ModelRelay::new(RELAY, caps(500, true))
        .refusing_inbox()
        .with_events(events)
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![
            required(&Route::Inbox, &[RELAY]),
            required(&group_route, &[RELAY]),
        ],
        &[&relay],
    );
    for route in [&Route::Inbox, &group_route] {
        account.goal(route, floor);
        account.rechecked(route, RELAY, t0);
        host.tails.stand(route, RELAY, t0);
    }
    let (mut runner, _handle) = runner(&host, test_policy());

    // The inbox goes first, with the open conversation windows.
    let first = ran(runner.step().await);
    assert_eq!(
        (first.key.route, first.outcome),
        (Route::Inbox, Outcome::Refused)
    );
    assert_eq!(run_until_idle(&mut runner, 4).await, [Outcome::Advanced]);

    assert_eq!(
        account.unit(&Route::Inbox, RELAY).state,
        RecoveryUnitState::Broken(RecoveryUnitBreak::Refused)
    );
    assert!(relay.queries().is_empty(), "the group was swept");
    assert_eq!(
        relay.fetched_ids().into_iter().collect::<BTreeSet<_>>(),
        ids(&missing)
    );
    assert!(account.debt(&group_route, RELAY, t0 - 1).is_empty());
}

/// No live frames wait on the inbox's history: a live count's capture on the
/// inbox raises no fence, stored or read, and does not put the inbox first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_never_fences_the_inbox() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let requested = t0 - HOUR;
    let since = requested - HOUR;
    let relay = ModelRelay::new(RELAY, caps(500, true)).build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![required(&Route::Inbox, &[RELAY])],
        &[&relay],
    );
    account.goal(&Route::Inbox, t0 - DAY);
    account.live_boundary(&Route::Inbox, RELAY, t0 - DAY, since - 1);
    host.tails.stand(&Route::Inbox, RELAY, requested);
    host.set_counts(vec![LiveCount {
        routes: vec![Route::Inbox],
        relay: RELAY.to_owned(),
        since,
        oldest_seen: Some(since + 60),
    }]);
    assert_eq!(
        account.debt(&Route::Inbox, RELAY, requested - 1),
        vec![range(since, requested - 1)]
    );

    assert!(host.fences().await.is_empty());
    assert!(host.survey(test_policy()).await.fenced.is_empty());
    let (mut runner, _handle) = runner(&host, test_policy());
    assert!(matches!(
        runner.admit(None).await,
        Ok(Drained { due: None, .. })
    ));
    assert!(account.fences().is_empty());
}
