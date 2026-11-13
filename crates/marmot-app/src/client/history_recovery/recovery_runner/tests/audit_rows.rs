//! The runner's v5 audit rows: one per quantum it settles, one per unit or
//! route transition, raced begins coalesced per route, and none per survey.

use marmot_forensics::{
    RECOVERY_RUNNER_RACED_WINDOW_SECS, RecoveryRunnerBreak, RecoveryRunnerChange,
    RecoveryRunnerFetch, RecoveryRunnerFetchEnd, RecoveryRunnerOutcome, RecoveryRunnerPurpose,
    RecoveryRunnerRoute,
};

use super::*;
use crate::client::recovery_runner::audit;
use crate::history_notices::ledger_route_tag;

const GROUP_ID: [u8; 16] = [0x47; 16];

/// `route`'s required route on `relays`, carrying the MLS group [`GROUP_ID`].
fn grouped(route: &Route, relays: &[&str]) -> RunnerRoute {
    RunnerRoute {
        group_id: Some(GROUP_ID.to_vec()),
        ..required(route, relays)
    }
}

/// The fetch rows recorded so far, each with its group, taken with every
/// other row.
fn fetched(host: &TestHost) -> Vec<(Option<Vec<u8>>, AuditEventKind)> {
    host.take_audited()
        .into_iter()
        .filter(|(_, kind)| matches!(kind, AuditEventKind::RecoveryRunnerFetched { .. }))
        .collect()
}

/// A sweep that catches a group up writes one row for its group: what was
/// owed, how it fetched, and what it covered and staged. Idle surveys after
/// it write nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_audits_each_sweep_for_its_group() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(every([1; 32], floor, t0, 60))
        .build();
    let host = TestHost::new(&account, &clock, vec![grouped(&route, &[RELAY])], &[&relay]);
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
    let rows = fetched(&host);
    let [(group, row)] = rows.as_slice() else {
        panic!("one row per quantum, got {}", rows.len());
    };
    assert_eq!(group.as_deref(), Some(&GROUP_ID[..]));
    let AuditEventKind::RecoveryRunnerFetched {
        route_kind,
        obligation_id,
        retained_route,
        relay_url,
        best_effort,
        fetch,
        purpose,
        probe,
        owed_secs,
        owed_since_secs,
        owed_until_secs,
        outcome,
        end,
        newly_covered_secs,
        events_fetched,
        events_staged,
        raced,
        ..
    } = row
    else {
        unreachable!()
    };
    assert_eq!(
        (*route_kind, *fetch, *purpose, *outcome, *end),
        (
            RecoveryRunnerRoute::Group,
            RecoveryRunnerFetch::Sweep,
            RecoveryRunnerPurpose::Debt,
            RecoveryRunnerOutcome::Advanced,
            RecoveryRunnerFetchEnd::Finished,
        )
    );
    assert!(!retained_route && !best_effort && !probe);
    assert_eq!(*obligation_id, hex::encode(ledger_route_tag(&route)));
    assert!(relay_url.starts_with(RELAY));
    assert_eq!((*owed_since_secs, *owed_until_secs), (floor, t0 - 1));
    assert_eq!(*owed_secs, HOUR);
    assert_eq!(*newly_covered_secs, HOUR);
    assert_eq!((*events_fetched, *events_staged), (60, 60));
    assert_eq!(*raced, 0);

    for _ in 0..3 {
        idle(runner.step().await);
    }
    assert!(host.take_audited().is_empty(), "surveys write no rows");
}

/// A relay that cannot be reached is a row too, with how it failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_audits_a_fetch_its_relay_never_answered() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .unreachable()
        .build();
    let host = TestHost::new(&account, &clock, vec![grouped(&route, &[RELAY])], &[&relay]);
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());

    assert_eq!(ran(runner.step().await).outcome, Outcome::Unreachable);
    let rows = fetched(&host);
    let [
        (
            Some(_),
            AuditEventKind::RecoveryRunnerFetched {
                outcome,
                end,
                newly_covered_secs,
                ..
            },
        ),
    ] = rows.as_slice()
    else {
        panic!("one group row for the failed quantum");
    };
    assert_eq!(
        (*outcome, *end, *newly_covered_secs),
        (
            RecoveryRunnerOutcome::Unreachable,
            RecoveryRunnerFetchEnd::TimedOut,
            0
        )
    );
}

/// A unit that answers without progress until its budget runs out writes
/// its six quanta and one break, with its park's revision. The broken unit
/// then writes nothing until its timed probe, which writes one probe fetch
/// and one failed probe under the same park.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_audits_a_unit_breaking_and_parking() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let floor = t0 - HOUR;
    let relay = stalling_relay([1; 32], floor).build();
    let host = TestHost::new(&account, &clock, vec![grouped(&route, &[RELAY])], &[&relay]);
    account.goal(&route, floor);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());
    let broken = RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress);
    while account
        .app
        .recovery_unit(&route, RELAY)
        .unwrap()
        .map(|unit| unit.state)
        != Some(broken)
    {
        match runner.step().await {
            Step::Ran(summary) => assert_eq!(summary.outcome, Outcome::NoProgress),
            Step::Idle { next_due } => clock.advance_to(next_due.unwrap()),
            Step::Raced | Step::Stopped => panic!("the unit runs until it breaks"),
        }
    }

    let rows = host.take_audited();
    let quanta = rows
        .iter()
        .filter(|(_, kind)| {
            matches!(
                kind,
                AuditEventKind::RecoveryRunnerFetched {
                    outcome: RecoveryRunnerOutcome::NoProgress,
                    end: RecoveryRunnerFetchEnd::SaturatedSecond,
                    ..
                }
            )
        })
        .count();
    assert_eq!(quanta, 6);
    let changes = rows
        .iter()
        .filter_map(|(group, kind)| match kind {
            AuditEventKind::RecoveryRunnerChanged {
                change,
                obligation_id,
                relay_url,
                break_reason,
                park_revision,
                ..
            } => Some((
                group.clone(),
                *change,
                obligation_id.clone(),
                relay_url.is_some(),
                *break_reason,
                *park_revision,
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    let park = account
        .unit(&route, RELAY)
        .park
        .expect("a broken unit parks");
    assert_eq!(
        changes,
        [(
            Some(GROUP_ID.to_vec()),
            RecoveryRunnerChange::Broken,
            Some(hex::encode(ledger_route_tag(&route))),
            true,
            Some(RecoveryRunnerBreak::NoProgress),
            Some(park.revision),
        )]
    );

    let probe_at = idle(runner.step().await).expect("a broken unit waits for its timed probe");
    assert!(
        host.take_audited().is_empty(),
        "a parked unit writes nothing until its probe is due"
    );

    clock.advance_to(probe_at);
    assert_eq!(ran(runner.step().await).outcome, Outcome::NoProgress);
    let rows = host.take_audited();
    let probes = rows
        .iter()
        .filter(|(_, kind)| {
            matches!(
                kind,
                AuditEventKind::RecoveryRunnerFetched {
                    probe: true,
                    outcome: RecoveryRunnerOutcome::NoProgress,
                    ..
                }
            )
        })
        .count();
    assert_eq!(probes, 1, "the due probe is one fetch row");
    let changes = rows
        .iter()
        .filter_map(|(_, kind)| match kind {
            AuditEventKind::RecoveryRunnerChanged {
                change,
                break_reason,
                park_revision,
                ..
            } => Some((*change, *break_reason, *park_revision)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        changes,
        [(
            RecoveryRunnerChange::ProbeFailed,
            Some(RecoveryRunnerBreak::NoProgress),
            Some(park.revision),
        )],
        "a failed probe stays under the same park"
    );
}

/// A route whose group froze is recorded once as suspended, and once as
/// resumed when it thaws; the surveys in between write nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_runner_audits_a_route_suspended_and_resumed() {
    let account = account();
    let clock = Clock::new();
    let t0 = clock.now();
    let route = group(1);
    let relay = ModelRelay::new(RELAY, caps(500, false))
        .with_events(every([1; 32], t0 - HOUR, t0, 60))
        .build();
    let host = TestHost::new(
        &account,
        &clock,
        vec![RunnerRoute {
            unrecoverable: true,
            ..grouped(&route, &[RELAY])
        }],
        &[&relay],
    );
    account.goal(&route, t0 - HOUR);
    host.tails.stand(&route, RELAY, t0);
    let (mut runner, _handle) = runner(&host, test_policy());
    let changes = |host: &TestHost| {
        host.take_audited()
            .into_iter()
            .filter_map(|(group, kind)| match kind {
                AuditEventKind::RecoveryRunnerChanged { change, .. } => Some((group, change)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    idle(runner.step().await);
    idle(runner.step().await);
    assert_eq!(
        changes(&host),
        [(Some(GROUP_ID.to_vec()), RecoveryRunnerChange::Suspended)]
    );

    host.routes.lock().unwrap()[0].unrecoverable = false;
    assert_eq!(ran(runner.step().await).outcome, Outcome::Advanced);
    assert_eq!(
        changes(&host),
        [(Some(GROUP_ID.to_vec()), RecoveryRunnerChange::Resumed)]
    );
}

/// Raced begins are counted per route and written at most once per window;
/// a route's next fetch row takes what its open window holds.
#[test]
fn recovery_runner_coalesces_raced_begins_per_route() {
    let (route, other) = (group(1), group(2));
    let mut races = audit::Races::default();
    let t0 = 1_000;
    for at in t0..t0 + RECOVERY_RUNNER_RACED_WINDOW_SECS {
        assert!(races.raced(&route, at).is_none(), "the window is open");
    }
    assert!(races.raced(&other, t0).is_none());
    let Some(AuditEventKind::RecoveryRunnerRaced {
        route_kind,
        obligation_id,
        raced,
        window_secs,
    }) = races.raced(&route, t0 + RECOVERY_RUNNER_RACED_WINDOW_SECS)
    else {
        panic!("the race that ends the window writes its row");
    };
    assert_eq!(route_kind, RecoveryRunnerRoute::Group);
    assert_eq!(obligation_id, hex::encode(ledger_route_tag(&route)));
    assert_eq!(
        (raced, window_secs),
        (
            RECOVERY_RUNNER_RACED_WINDOW_SECS + 1,
            RECOVERY_RUNNER_RACED_WINDOW_SECS
        )
    );
    // A new window opens; the fetch row takes it and the other route's.
    assert!(races.raced(&route, t0 + 100).is_none());
    assert_eq!(races.take(&route), 1);
    assert_eq!(races.take(&route), 0);
    assert_eq!(races.take(&other), 1);
}

/// The retention prune's remainder changes, over real storage: a route that
/// gains a parked remainder, then one whose remainder a later prune widens.
#[test]
fn recovery_runner_audits_a_remainder_the_retention_floor_parked_and_widened() {
    let account = account();
    let route = group(1);
    let now = crate::unix_now_seconds();
    let floor = now - 30 * DAY;
    account.goal(&route, floor - DAY);
    let routes = [(route.clone(), vec![RELAY.to_owned()])];
    let recorded: Mutex<Vec<(Option<Vec<u8>>, AuditEventKind)>> = Mutex::default();
    let hook = |group: Option<&[u8]>, kind| {
        recorded
            .lock()
            .unwrap()
            .push((group.map(<[u8]>::to_vec), kind));
    };
    let group_of = |_: &Route| Some(GROUP_ID.to_vec());
    let prune = |floor| {
        let before = account.app.recovery_coverage_remainders().unwrap();
        account.app.prune_recovery_coverage(floor, &routes).unwrap();
        let after = account.app.recovery_coverage_remainders().unwrap();
        audit::remainders_changed(&hook, group_of, &before, &after);
    };

    prune(floor);
    // Nothing more below the same floor: the remainder stands, no row.
    prune(floor);
    // The floor moves on over seconds still owed: the remainder widens.
    prune(floor + HOUR);

    let rows = recorded.into_inner().unwrap();
    let changes = rows
        .iter()
        .map(|(group, kind)| match kind {
            AuditEventKind::RecoveryRunnerChanged {
                change,
                remainder_since_secs: Some(since),
                remainder_until_secs: Some(until),
                park_revision: Some(_),
                ..
            } => (group.clone(), *change, *since, *until),
            other => panic!("unexpected row {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert_eq!(
        changes[0],
        (
            Some(GROUP_ID.to_vec()),
            RecoveryRunnerChange::RemainderParked,
            floor - DAY,
            floor - 1
        )
    );
    assert_eq!(
        changes[1],
        (
            Some(GROUP_ID.to_vec()),
            RecoveryRunnerChange::RemainderWidened,
            floor - DAY,
            floor + HOUR - 1
        )
    );
}
