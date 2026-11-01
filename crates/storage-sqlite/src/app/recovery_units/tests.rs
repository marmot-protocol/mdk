//! Retry state tests.

use super::*;
use crate::{RecoveryCoverageProof, RecoveryCoverageSlice, SqlCipherKey, SqliteAccountStorage};
use cgka_traits::storage::StorageError;

const RELAY: &str = "wss://a.example";
const OTHER: &str = "wss://b.example";
const NOW: u64 = 1_000_000;

const POLICY: RecoveryUnitPolicy = RecoveryUnitPolicy {
    backoff_base_seconds: 30,
    backoff_cap_seconds: 3_600,
    break_after_no_progress: 6,
    unreachable_retry_seconds: 30,
    cooldown_after_unreachable: 3,
    cooldown_base_seconds: 60,
    cooldown_cap_seconds: 3_600,
    max_attempts_per_hour: 720,
    max_event_bytes_per_hour: 256 << 20,
    recheck_after_cooldown_seconds: 3_600,
};

fn group(byte: u8) -> TransportReconciliationRoute {
    TransportReconciliationRoute::Group([byte; 32])
}

fn range(since: u64, until: u64) -> RecoveryCoverageRange {
    RecoveryCoverageRange {
        since_seconds: since,
        until_seconds: until,
    }
}

fn cover(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
    relay: &str,
    covered: (u64, u64),
) {
    app.record_recovery_coverage(
        &[RecoveryCoverageSlice {
            route,
            relay,
            since_seconds: covered.0,
            until_seconds: covered.1,
            proof: RecoveryCoverageProof::SweepSlice,
        }],
        NOW,
    )
    .unwrap();
}

/// A route owing from `since`, with `covered` proved on `RELAY`.
fn owing(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
    since: u64,
    covered: (u64, u64),
) {
    app.widen_recovery_coverage_goals(std::slice::from_ref(route), since)
        .unwrap();
    cover(app, route, RELAY, covered);
}

fn settle(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
    relay: &str,
    outcome: RecoveryUnitOutcome,
    now: u64,
) -> RecoveryUnit {
    app.begin_recovery_unit_attempt(route, relay, None, now)
        .unwrap();
    app.settle_recovery_unit(route, relay, outcome, &POLICY, now)
        .unwrap()
}

/// Spend a unit's no-progress budget, which breaks it.
fn break_unit(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
    now: u64,
) -> RecoveryUnit {
    let mut unit = None;
    for _ in 0..POLICY.break_after_no_progress {
        unit = Some(settle(
            app,
            route,
            RELAY,
            RecoveryUnitOutcome::NoProgress,
            now,
        ));
    }
    unit.unwrap()
}

fn health(app: &SqliteAppStorage, relay: &str) -> RecoveryRelayHealth {
    app.recovery_relay_health(relay).unwrap().unwrap()
}

fn unit(app: &SqliteAppStorage, route: &TransportReconciliationRoute, relay: &str) -> RecoveryUnit {
    app.recovery_unit(route, relay).unwrap().unwrap()
}

/// Each outcome settles the unit, its relay and the account's budget in one
/// way. Progress rearms the unit and ends the relay's streak; nothing owed
/// refunds the attempt and resets an active unit; a rate limit cools the
/// relay without charging the unit; a refusal breaks the unit at once
/// without spending its budget; a preempted call and a local failure change
/// nothing and refund the attempt.
#[test]
fn each_outcome_settles_the_unit_its_relay_and_the_budget() {
    use RecoveryUnitOutcome as Outcome;
    struct Row {
        name: &'static str,
        earlier: &'static [Outcome],
        outcome: Outcome,
        at: u64,
        /// state, no_progress, backoff_step, next_attempt_at_seconds,
        /// parked, last_served_at_seconds
        unit: (RecoveryUnitState, u32, u32, u64, bool, Option<u64>),
        /// unreachable_streak, cooldown_step, cooldown
        relay: (u32, u32, Option<(u64, u64)>),
        attempts: u64,
    }
    let active = RecoveryUnitState::Active;
    let rows = [
        Row {
            name: "advanced",
            earlier: &[Outcome::NoProgress, Outcome::Unreachable],
            outcome: Outcome::Advanced,
            at: NOW + 1,
            unit: (active, 0, 0, 0, false, Some(NOW + 1)),
            relay: (0, 0, None),
            attempts: 3,
        },
        Row {
            name: "nothing owed",
            earlier: &[Outcome::NoProgress],
            outcome: Outcome::NothingOwed,
            at: NOW,
            unit: (active, 0, 0, 0, false, Some(NOW)),
            relay: (0, 0, None),
            attempts: 1,
        },
        Row {
            name: "rate limited",
            earlier: &[],
            outcome: Outcome::RateLimited,
            at: NOW,
            unit: (active, 0, 0, 0, false, Some(NOW)),
            relay: (0, 1, Some((NOW, NOW + 60))),
            attempts: 1,
        },
        Row {
            name: "refused",
            earlier: &[Outcome::NoProgress],
            outcome: Outcome::Refused,
            at: NOW,
            unit: (
                RecoveryUnitState::Broken(RecoveryUnitBreak::Refused),
                1,
                1,
                NOW + 30,
                true,
                Some(NOW),
            ),
            relay: (0, 0, None),
            attempts: 2,
        },
        Row {
            name: "unanswered",
            earlier: &[Outcome::NoProgress],
            outcome: Outcome::Unanswered,
            at: NOW + 5,
            // As the earlier answer left it: one backoff of the base.
            unit: (active, 1, 1, NOW + 30, false, Some(NOW + 5)),
            relay: (0, 0, None),
            attempts: 1,
        },
        Row {
            name: "local failure",
            earlier: &[Outcome::NoProgress],
            outcome: Outcome::LocalFailure,
            at: NOW + 5,
            // As the earlier answer left it: one backoff of the base.
            unit: (active, 1, 1, NOW + 30, false, Some(NOW + 5)),
            relay: (0, 0, None),
            attempts: 1,
        },
    ];
    for row in rows {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        for earlier in row.earlier {
            settle(&app, &route, RELAY, *earlier, NOW);
        }
        let settled = settle(&app, &route, RELAY, row.outcome, row.at);
        assert_eq!(
            (
                settled.state,
                settled.no_progress,
                settled.backoff_step,
                settled.next_attempt_at_seconds,
                settled.park.is_some(),
                settled.last_served_at_seconds,
            ),
            row.unit,
            "{}",
            row.name
        );
        let (unreachable_streak, cooldown_step, cooldown) = row.relay;
        assert!(
            health(&app, RELAY)
                == RecoveryRelayHealth {
                    relay: RELAY.to_owned(),
                    unreachable_streak,
                    cooldown_step,
                    cooldown,
                    caps: None,
                    caps_fetched_at_seconds: None,
                },
            "{}",
            row.name
        );
        assert_eq!(
            app.recovery_account_usage(row.at).unwrap().attempts,
            row.attempts,
            "{}",
            row.name
        );
    }
}

/// A broken unit that holds no probe keeps its park and its spans whatever
/// it answers.
#[test]
fn a_broken_unit_without_a_probe_keeps_its_park_whatever_it_answers() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let broken = break_unit(&app, &route, NOW);
    let spans = app.recovery_unit_spans(&route, RELAY).unwrap();
    assert!(!spans.is_empty());
    let still = settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::NothingOwed,
        NOW + 10,
    );
    assert_eq!(still.state, broken.state);
    assert_eq!(still.park, broken.park);
    assert_eq!(app.recovery_unit_spans(&route, RELAY).unwrap(), spans);
}

/// Each answer without progress doubles the backoff from its base, and the
/// budget's last one breaks the unit and parks what it still owes.
#[test]
fn no_progress_backs_off_doubling_and_breaks_at_the_budget() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let mut waits = Vec::new();
    for _ in 1..POLICY.break_after_no_progress {
        let backing_off = settle(&app, &route, RELAY, RecoveryUnitOutcome::NoProgress, NOW);
        assert_eq!(backing_off.state, RecoveryUnitState::Active);
        waits.push(backing_off.next_attempt_at_seconds - NOW);
    }
    assert_eq!(waits, vec![30, 60, 120, 240, 480]);
    let broken = settle(&app, &route, RELAY, RecoveryUnitOutcome::NoProgress, NOW);
    assert_eq!(
        broken.state,
        RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress)
    );
    assert_eq!(
        broken.park,
        Some(RecoveryUnitPark {
            revision: 1,
            parked_at_seconds: NOW
        })
    );
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 500, NOW),
            retired: None
        }]
    );
    assert!(
        app.recovery_unit_debt(&route, RELAY, NOW)
            .unwrap()
            .is_empty(),
        "parked debt is not pursued"
    );
}

/// An unreachable relay costs the unit no budget and the unit retries after
/// the relay delay; the third in a row cools the relay down, each further
/// cooldown in the spell doubles, and a reconnect ends the spell.
#[test]
fn unreachable_waits_and_cools_the_relay_after_three() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    for _ in 0..2 {
        let waiting = settle(&app, &route, RELAY, RecoveryUnitOutcome::Unreachable, NOW);
        assert_eq!(waiting.no_progress, 0);
        assert_eq!(waiting.next_attempt_at_seconds, NOW + 30);
    }
    assert_eq!(health(&app, RELAY).cooldown, None);
    settle(&app, &route, RELAY, RecoveryUnitOutcome::Unreachable, NOW);
    assert_eq!(health(&app, RELAY).cooldown, Some((NOW, NOW + 60)));
    settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::Unreachable,
        NOW + 60,
    );
    let cooled = health(&app, RELAY);
    assert_eq!(cooled.unreachable_streak, 4);
    assert_eq!(
        cooled.cooldown,
        Some((NOW, NOW + 180)),
        "the spell keeps its start"
    );
    assert_eq!(app.recovery_account_usage(NOW + 60).unwrap().attempts, 4);
    assert_eq!(
        app.record_recovery_relay_reconnected(RELAY, &POLICY, NOW + 60)
            .unwrap(),
        Some(NOW)
    );
    let reconnected = health(&app, RELAY);
    assert_eq!(
        (reconnected.unreachable_streak, reconnected.cooldown),
        (0, None)
    );
    assert_eq!(
        app.record_recovery_relay_reconnected(RELAY, &POLICY, NOW + 60)
            .unwrap(),
        None
    );
}

/// A cooldown spell longer than the bound makes every re-check on its relay
/// due in the write that ends it, by an answer or a reconnect; a shorter one
/// and other relays' passes are left alone.
#[test]
fn a_long_cooldown_makes_the_relays_rechecks_due_as_it_ends() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (first, second) = (group(1), group(2));
    let finished = |app: &SqliteAppStorage, route, relay, at| {
        app.begin_recovery_unit_attempt(route, relay, None, at)
            .unwrap();
        let revision = unit(app, route, relay).recheck.revision;
        assert!(
            app.record_recovery_recheck(route, relay, revision, 0, true, at)
                .unwrap()
        );
    };
    let cool = |app: &SqliteAppStorage, at| {
        for _ in 0..3 {
            settle(app, &first, RELAY, RecoveryUnitOutcome::Unreachable, at);
        }
    };
    let pass = |app: &SqliteAppStorage, route, relay| {
        let pass = unit(app, route, relay).recheck;
        (pass.position_seconds, pass.completed_at_seconds)
    };
    let done = |at| (None, Some(at));
    let due = (None, None);

    // A short spell ended by an answer changes no pass.
    finished(&app, &second, RELAY, NOW);
    cool(&app, NOW);
    settle(
        &app,
        &first,
        RELAY,
        RecoveryUnitOutcome::NoProgress,
        NOW + 3_600,
    );
    assert_eq!(pass(&app, &second, RELAY), done(NOW));

    // A long one ended by a re-check's answer makes every pass on the relay
    // due, and leaves another relay's alone.
    finished(&app, &second, RELAY, NOW + 3_600);
    finished(&app, &second, OTHER, NOW + 3_600);
    cool(&app, NOW + 3_600);
    settle_recheck(
        &app,
        &first,
        RELAY,
        RecoveryUnitOutcome::Advanced,
        NOW + 7_201,
    );
    assert_eq!(pass(&app, &second, RELAY), due);
    assert_eq!(pass(&app, &first, RELAY), due);
    assert_eq!(pass(&app, &second, OTHER), done(NOW + 3_600));

    // So does one ended by a reconnect.
    finished(&app, &second, RELAY, NOW + 7_201);
    cool(&app, NOW + 7_201);
    assert_eq!(
        app.record_recovery_relay_reconnected(RELAY, &POLICY, NOW + 10_802)
            .unwrap(),
        Some(NOW + 7_201)
    );
    assert_eq!(pass(&app, &second, RELAY), due);
}

/// A request that makes a pass due while a quantum runs wins, even when it
/// leaves the pass looking as it did: the quantum's progress, recorded under
/// the revision it began on, is refused, and the pass runs again.
#[test]
fn a_recheck_request_outlives_the_quantum_it_interrupts() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    app.begin_recovery_unit_attempt(&route, RELAY, None, NOW)
        .unwrap();
    let began = unit(&app, &route, RELAY).recheck;
    assert_eq!(began, RecoveryRecheckPass::default());
    app.make_recovery_recheck_due(&route, None, None).unwrap();
    let requested = unit(&app, &route, RELAY).recheck;
    assert_eq!(
        (requested.position_seconds, requested.completed_at_seconds),
        (None, None)
    );
    assert!(
        !app.record_recovery_recheck(&route, RELAY, began.revision, 0, true, NOW)
            .unwrap()
    );
    assert!(
        !app.record_recovery_recheck(&route, RELAY, began.revision, NOW - 100, false, NOW)
            .unwrap()
    );
    assert_eq!(unit(&app, &route, RELAY).recheck, requested);
    assert!(
        app.record_recovery_recheck(&route, RELAY, requested.revision, 0, true, NOW)
            .unwrap()
    );
    assert_eq!(
        unit(&app, &route, RELAY).recheck.completed_at_seconds,
        Some(NOW)
    );
}

/// New loss over a parked span earns one probe under the same park: a probe
/// without progress re-parks with the same revision, and progress clears the
/// park. Loss on another route earns nothing.
#[test]
fn new_loss_over_a_park_earns_one_probe() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let park = break_unit(&app, &route, NOW).park.unwrap();
    app.uncover_recovery_coverage(&[group(2)], NOW - 800)
        .unwrap();
    assert!(!unit(&app, &route, RELAY).probe, "another route's loss");
    app.uncover_recovery_coverage(std::slice::from_ref(&route), NOW - 700)
        .unwrap();
    assert!(unit(&app, &route, RELAY).probe);
    assert_eq!(
        app.recovery_unit_debt(&route, RELAY, NOW).unwrap(),
        vec![range(NOW - 700, NOW)],
        "a probe owes its park and the new loss"
    );
    let reparked = settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::NoProgress,
        NOW + 10,
    );
    assert!(!reparked.probe);
    assert_eq!(reparked.park, Some(park), "the notice keeps its identity");
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 700, NOW + 10),
            retired: None
        }]
    );
    app.uncover_recovery_coverage(std::slice::from_ref(&route), NOW - 600)
        .unwrap();
    let cleared = settle(&app, &route, RELAY, RecoveryUnitOutcome::Advanced, NOW + 20);
    assert_eq!(cleared.state, RecoveryUnitState::Active);
    assert_eq!(cleared.park, None);
    assert!(app.recovery_unit_spans(&route, RELAY).unwrap().is_empty());
}

/// A relay added to the route re-arms its broken unit fully; an active unit
/// is left as it is.
#[test]
fn a_relay_added_rearms_its_unit_fully() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    break_unit(&app, &route, NOW);
    settle(&app, &route, OTHER, RecoveryUnitOutcome::NoProgress, NOW);
    assert!(app.rearm_recovery_unit(&route, RELAY).unwrap());
    assert!(!app.rearm_recovery_unit(&route, OTHER).unwrap());
    let rearmed = unit(&app, &route, RELAY);
    assert_eq!(
        (rearmed.state, rearmed.no_progress, rearmed.park),
        (RecoveryUnitState::Active, 0, None)
    );
    assert_eq!(unit(&app, &route, OTHER).no_progress, 1);
    assert_eq!(
        app.recovery_unit_debt(&route, RELAY, NOW).unwrap(),
        vec![range(NOW - 500, NOW)]
    );
}

/// A known caps read re-arms a broken unit planned with different or unknown
/// caps. An unknown read is never evidence, and neither are the same caps
/// again.
#[test]
fn caps_changes_rearm_and_unknown_reads_do_not() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (planned, unknown) = (group(1), group(2));
    let caps = RecoveryRelayCaps {
        max_limit: Some(500),
        negentropy: false,
    };
    for _ in 0..POLICY.break_after_no_progress {
        app.begin_recovery_unit_attempt(&planned, RELAY, Some(caps), NOW)
            .unwrap();
        app.settle_recovery_unit(
            &planned,
            RELAY,
            RecoveryUnitOutcome::NoProgress,
            &POLICY,
            NOW,
        )
        .unwrap();
    }
    settle(&app, &unknown, RELAY, RecoveryUnitOutcome::Refused, NOW);
    assert_eq!(app.record_recovery_relay_caps(RELAY, None, NOW).unwrap(), 0);
    assert_eq!(health(&app, RELAY).caps, None);
    assert_eq!(
        app.record_recovery_relay_caps(RELAY, Some(caps), NOW)
            .unwrap(),
        1,
        "only the unit planned without caps"
    );
    assert_eq!(unit(&app, &unknown, RELAY).state, RecoveryUnitState::Active);
    assert_eq!(
        app.record_recovery_relay_caps(RELAY, None, NOW + 1)
            .unwrap(),
        0
    );
    assert_eq!(
        health(&app, RELAY).caps,
        Some(caps),
        "an unknown read keeps the known caps"
    );
    let negentropy = RecoveryRelayCaps {
        negentropy: true,
        ..caps
    };
    assert_eq!(
        app.record_recovery_relay_caps(RELAY, Some(negentropy), NOW + 2)
            .unwrap(),
        1,
        "negentropy support appeared"
    );
    assert_eq!(unit(&app, &planned, RELAY).state, RecoveryUnitState::Active);
}

/// Explicit repair re-arms every broken and retired unit, ends an active
/// unit's backoff, owes every parked and retired span again and makes every
/// re-check due.
#[test]
fn explicit_repair_rearms_everything() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (parked, retired, backing_off) = (group(1), group(2), group(3));
    for route in [&parked, &retired] {
        owing(&app, route, NOW - 1_000, (NOW - 1_000, NOW - 501));
        break_unit(&app, route, NOW);
        app.record_recovery_recheck(route, RELAY, 0, 0, true, NOW)
            .unwrap();
    }
    let revision = unit(&app, &retired, RELAY).park.unwrap().revision;
    assert!(app.dismiss_recovery_route_park(&retired, revision).unwrap());
    owing(&app, &backing_off, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let before = settle(
        &app,
        &backing_off,
        RELAY,
        RecoveryUnitOutcome::NoProgress,
        NOW,
    );
    assert!(before.next_attempt_at_seconds > NOW);
    // A rate limit elsewhere cools the relay; the repair leaves the cooldown
    // and the account's budget as they are.
    settle(
        &app,
        &group(4),
        RELAY,
        RecoveryUnitOutcome::RateLimited,
        NOW,
    );
    let (relay_before, usage_before) = (
        health(&app, RELAY),
        app.recovery_account_usage(NOW).unwrap(),
    );
    assert!(relay_before.cooldown.is_some());
    assert_eq!(app.rearm_all_recovery_units().unwrap(), 2);
    assert!(health(&app, RELAY) == relay_before);
    assert_eq!(app.recovery_account_usage(NOW).unwrap(), usage_before);
    let due = unit(&app, &backing_off, RELAY);
    assert_eq!(
        (
            due.state,
            due.no_progress,
            due.backoff_step,
            due.next_attempt_at_seconds
        ),
        (RecoveryUnitState::Active, 0, 0, 0),
        "an active unit backing off is due again"
    );
    for route in [&parked, &retired] {
        let repaired = unit(&app, route, RELAY);
        assert_eq!(
            (repaired.state, repaired.no_progress),
            (RecoveryUnitState::Active, 0)
        );
        assert_eq!(
            repaired.recheck,
            RecoveryRecheckPass {
                revision: 1,
                ..RecoveryRecheckPass::default()
            }
        );
        assert!(app.recovery_unit_spans(route, RELAY).unwrap().is_empty());
        assert_eq!(
            app.recovery_unit_debt(route, RELAY, NOW).unwrap(),
            vec![range(NOW - 500, NOW)]
        );
    }
}

/// A dismissal scoped to some relays checks its revision against their parks
/// and the remainder only, and leaves a broken unit on any other relay as it
/// is.
#[test]
fn a_dismissal_on_some_relays_leaves_the_others_broken() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let first = break_unit(&app, &route, NOW).park.unwrap().revision;
    let second = settle(&app, &route, OTHER, RecoveryUnitOutcome::Refused, NOW + 5)
        .park
        .unwrap()
        .revision;
    let relay = [RELAY.to_owned()];
    assert!(
        !app.dismiss_recovery_route_park_on(&route, &relay, second)
            .unwrap()
    );
    assert!(
        app.dismiss_recovery_route_park_on(&route, &relay, first)
            .unwrap()
    );
    assert_eq!(unit(&app, &route, RELAY).state, RecoveryUnitState::Retired);
    assert!(matches!(
        unit(&app, &route, OTHER).state,
        RecoveryUnitState::Broken(_)
    ));
    let notices = app.parked_recovery_routes().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].relays, vec![OTHER.to_owned()]);
}

/// Dismissal checks the route's newest park: a stale revision does nothing.
/// The current one retires the route's broken units and their parked spans,
/// which never become coverage.
#[test]
fn a_stale_dismissal_returns_false() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let first = break_unit(&app, &route, NOW).park.unwrap().revision;
    let second = settle(&app, &route, OTHER, RecoveryUnitOutcome::Refused, NOW + 5)
        .park
        .unwrap()
        .revision;
    let notices = app.parked_recovery_routes().unwrap();
    assert_eq!(notices.len(), 1, "one notice per route");
    assert_eq!(
        (notices[0].revision, notices[0].parked_at_seconds),
        (second, NOW)
    );
    assert_eq!(notices[0].relays, vec![RELAY.to_owned(), OTHER.to_owned()]);
    assert!(!app.dismiss_recovery_route_park(&route, first).unwrap());
    assert!(matches!(
        unit(&app, &route, RELAY).state,
        RecoveryUnitState::Broken(_)
    ));
    assert!(app.dismiss_recovery_route_park(&route, second).unwrap());
    assert!(!app.dismiss_recovery_route_park(&route, second).unwrap());
    assert!(app.parked_recovery_routes().unwrap().is_empty());
    let retired = unit(&app, &route, RELAY);
    assert_eq!(
        (retired.state, retired.park),
        (RecoveryUnitState::Retired, None)
    );
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 500, NOW),
            retired: Some(RecoverySpanRetirement::Dismissed),
        }]
    );
    assert!(
        app.recovery_unit_debt(&route, RELAY, NOW)
            .unwrap()
            .is_empty()
    );
    assert!(
        !app.recovery_coverage_covers(&route, &[RELAY.to_owned()], NOW - 500, NOW)
            .unwrap(),
        "a retired span is not coverage"
    );
}

/// The breaker pauses at either cap until enough of the rolling hour has
/// rolled off.
#[test]
fn the_account_breaker_pauses_until_the_hour_rolls() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    let attempts = RecoveryUnitPolicy {
        max_attempts_per_hour: 3,
        ..POLICY
    };
    for minute in 0..3 {
        app.begin_recovery_unit_attempt(&route, RELAY, None, NOW + minute * 60)
            .unwrap();
    }
    let now = NOW + 150;
    assert_eq!(app.recovery_account_usage(now).unwrap().attempts, 3);
    let rolls_off = (NOW / 60 + 1) * 60 + 3_600;
    assert_eq!(
        app.recovery_account_paused_until(&attempts, now).unwrap(),
        Some(rolls_off)
    );
    assert_eq!(
        app.recovery_account_paused_until(&attempts, rolls_off - 1)
            .unwrap(),
        Some(rolls_off)
    );
    assert_eq!(
        app.recovery_account_paused_until(&attempts, rolls_off)
            .unwrap(),
        None
    );
    assert_eq!(app.recovery_account_usage(rolls_off).unwrap().attempts, 2);
    let bytes = RecoveryUnitPolicy {
        max_event_bytes_per_hour: 100,
        ..POLICY
    };
    app.connection
        .with_transaction(|| charge_event_bytes_tx(&*app.lock()?, 100, rolls_off))
        .unwrap();
    assert_eq!(
        app.recovery_account_paused_until(&bytes, rolls_off)
            .unwrap(),
        Some((rolls_off / 60 + 1) * 60 + 3_600),
        "until the bytes' minute rolls off"
    );
}

/// The cursor is the first second of a requested range this relay does not
/// cover, whoever else covers it.
#[test]
fn the_cursor_is_the_first_second_the_relay_leaves_uncovered() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, 100, (100, 199));
    cover(&app, &route, OTHER, (200, 300));
    assert_eq!(
        app.recovery_unit_cursor(&route, RELAY, 100, 300).unwrap(),
        Some(200)
    );
    assert_eq!(
        app.recovery_unit_cursor(&route, RELAY, 150, 199).unwrap(),
        None
    );
    assert_eq!(
        app.recovery_unit_cursor(&route, OTHER, 100, 300).unwrap(),
        Some(100)
    );
}

/// A fence, slicing, re-check progress, parks, relay health and the budget
/// survive closing and reopening the database.
#[test]
fn state_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::raw([0x5c; 32]);
    let path = dir.path().join("session.sqlite");
    let route = group(1);
    let caps = RecoveryRelayCaps {
        max_limit: Some(500),
        negentropy: true,
    };
    let (dismissed, gone, overtaken) = (group(2), group(3), group(4));
    let (before, relay_before, usage_before, spans_before, remainders_before, highest) = {
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = storage.app_storage();
        // A remainder the prune parked, below every other route's goal.
        app.widen_recovery_coverage_goals(std::slice::from_ref(&overtaken), NOW - 3_000)
            .unwrap();
        app.prune_recovery_coverage(NOW - 2_000, &[(overtaken.clone(), vec![RELAY.to_owned()])])
            .unwrap();
        // A dismissed span and a route-gone span.
        let mut revisions = Vec::new();
        for route in [&dismissed, &gone] {
            owing(&app, route, NOW - 1_000, (NOW - 1_000, NOW - 501));
            revisions.push(break_unit(&app, route, NOW).park.unwrap().revision);
        }
        assert!(
            app.dismiss_recovery_route_park(&dismissed, revisions[0])
                .unwrap()
        );
        app.retire_gone_recovery_units(&gone, None, NOW).unwrap();
        owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
        app.set_recovery_unit_fences(&route, RELAY, &[range(NOW - 1_000, NOW - 900)])
            .unwrap();
        app.record_recovery_unit_slicing(&route, RELAY, 3_600, Some(500))
            .unwrap();
        app.record_recovery_recheck(&route, RELAY, 0, NOW - 400, false, NOW)
            .unwrap();
        app.record_recovery_relay_caps(RELAY, Some(caps), NOW)
            .unwrap();
        for _ in 0..POLICY.break_after_no_progress {
            app.begin_recovery_unit_attempt(&route, RELAY, Some(caps), NOW)
                .unwrap();
            app.settle_recovery_unit(&route, RELAY, RecoveryUnitOutcome::NoProgress, &POLICY, NOW)
                .unwrap();
        }
        settle(&app, &route, OTHER, RecoveryUnitOutcome::RateLimited, NOW);
        let remainders = app.recovery_coverage_remainders().unwrap();
        assert_eq!(remainders.len(), 1);
        revisions.push(remainders[0].revision);
        let main = unit(&app, &route, RELAY);
        revisions.push(main.park.unwrap().revision);
        let spans = [&dismissed, &gone].map(|route| app.recovery_unit_spans(route, RELAY).unwrap());
        assert!(spans.iter().all(|spans| !spans.is_empty()));
        let state = (
            main,
            [health(&app, RELAY), health(&app, OTHER)],
            app.recovery_account_usage(NOW).unwrap(),
            spans,
            remainders,
            revisions.into_iter().max().unwrap(),
        );
        storage.close().unwrap();
        state
    };
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = storage.app_storage();
    let after = unit(&app, &route, RELAY);
    assert!(after == before);
    assert_eq!(
        fences(&app),
        vec![(
            route.clone(),
            RELAY.to_owned(),
            range(NOW - 1_000, NOW - 900)
        )]
    );
    assert_eq!(after.planned_caps, Some(caps));
    assert_eq!(
        (after.slice_width_seconds, after.observed_cap),
        (Some(3_600), Some(500))
    );
    assert_eq!(after.recheck.position_seconds, Some(NOW - 400));
    assert!(matches!(after.state, RecoveryUnitState::Broken(_)));
    assert!([health(&app, RELAY), health(&app, OTHER)] == relay_before);
    assert_eq!(health(&app, RELAY).caps, Some(caps));
    assert_eq!(app.recovery_account_usage(NOW).unwrap(), usage_before);
    assert_eq!(
        [&dismissed, &gone].map(|route| app.recovery_unit_spans(route, RELAY).unwrap()),
        spans_before
    );
    assert!(app.recovery_coverage_remainders().unwrap() == remainders_before);
    // The park counter is durable: a park made now is a new notice.
    let fresh = settle(&app, &group(5), RELAY, RecoveryUnitOutcome::Refused, NOW);
    assert!(fresh.park.unwrap().revision > highest);
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 500, NOW),
            retired: None
        }]
    );
}

/// A unit keeps every range it fences, until it drops them; ranges must be
/// ordered and must not overlap.
#[test]
fn fenced_ranges_are_listed_until_their_unit_drops_them() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (fenced, other) = (group(1), group(2));
    settle(&app, &other, RELAY, RecoveryUnitOutcome::Advanced, NOW);
    let kept = [range(NOW - 30, NOW - 20), range(NOW - 10, NOW - 5)];
    app.set_recovery_unit_fences(&fenced, OTHER, &kept).unwrap();
    assert_eq!(
        fences(&app),
        kept.iter()
            .map(|range| (fenced.clone(), OTHER.to_owned(), *range))
            .collect::<Vec<_>>()
    );
    for refused in [
        vec![range(NOW - 5, NOW - 10)],
        vec![range(NOW - 10, NOW - 5), range(NOW - 30, NOW - 20)],
        vec![range(NOW - 30, NOW - 10), range(NOW - 10, NOW - 5)],
    ] {
        assert!(matches!(
            app.set_recovery_unit_fences(&fenced, OTHER, &refused),
            Err(StorageError::Serialization(message)) if message == "invalid recovery coverage"
        ));
    }
    assert_eq!(fences(&app).len(), 2, "a refused write keeps the ranges");
    app.set_recovery_unit_fences(&fenced, OTHER, &kept[1..])
        .unwrap();
    assert_eq!(fences(&app).len(), 1);
    app.set_recovery_unit_fences(&fenced, OTHER, &[]).unwrap();
    assert!(fences(&app).is_empty());
}

fn fences(
    app: &SqliteAppStorage,
) -> Vec<(TransportReconciliationRoute, String, RecoveryCoverageRange)> {
    app.recovery_unit_fences()
        .unwrap()
        .into_iter()
        .map(|fence| (fence.route, fence.relay, fence.range))
        .collect()
}

fn remainder(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
) -> Option<RecoveryRouteRemainder> {
    app.recovery_coverage_remainders()
        .unwrap()
        .into_iter()
        .find(|remainder| &remainder.route == route)
}

/// The retention prune trims parked and retired spans at its floor, as it
/// does coverage and goals, so a later re-arm owes exactly what the window
/// still holds. The parked seconds it overtakes join the route's remainder;
/// dismissed ones do not.
#[test]
fn the_retention_prune_trims_spans_at_its_floor() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (parked, retired) = (group(1), group(2));
    for route in [&parked, &retired] {
        owing(&app, route, NOW - 1_000, (NOW - 1_000, NOW - 501));
        break_unit(&app, route, NOW);
    }
    let revision = unit(&app, &retired, RELAY).park.unwrap().revision;
    assert!(app.dismiss_recovery_route_park(&retired, revision).unwrap());
    app.set_recovery_unit_fences(
        &parked,
        OTHER,
        &[range(NOW - 900, NOW - 201), range(NOW - 200, NOW - 100)],
    )
    .unwrap();
    let routes = [
        (parked.clone(), vec![RELAY.to_owned()]),
        (retired.clone(), vec![RELAY.to_owned()]),
    ];
    app.prune_recovery_coverage(NOW - 200, &routes).unwrap();
    assert_eq!(
        fences(&app),
        vec![(
            parked.clone(),
            OTHER.to_owned(),
            range(NOW - 200, NOW - 100)
        )],
        "a fenced range wholly below the floor goes"
    );
    assert_eq!(
        remainder(&app, &parked).unwrap().range,
        range(NOW - 500, NOW - 201)
    );
    assert!(remainder(&app, &retired).is_none());
    assert_eq!(
        app.recovery_unit_spans(&parked, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 200, NOW),
            retired: None
        }]
    );
    assert_eq!(
        app.recovery_unit_spans(&retired, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 200, NOW),
            retired: Some(RecoverySpanRetirement::Dismissed),
        }]
    );
    assert_eq!(app.rearm_all_recovery_units().unwrap(), 2);
    for route in [&parked, &retired] {
        assert_eq!(
            app.recovery_unit_debt(route, RELAY, NOW).unwrap(),
            vec![range(NOW - 200, NOW)],
            "repair owes the window's part of every span"
        );
    }
    app.prune_recovery_coverage(NOW + 1, &routes).unwrap();
    for route in [&parked, &retired] {
        assert!(app.recovery_unit_spans(route, RELAY).unwrap().is_empty());
    }
    assert_eq!(
        remainder(&app, &parked).unwrap().range,
        range(NOW - 500, NOW)
    );
    assert_eq!(
        remainder(&app, &retired).unwrap().range,
        range(NOW - 200, NOW),
        "repair made the dismissed span owed again"
    );
}

/// The prune parks, before raising a goal, what any certifying relay still
/// owes below the floor: one range per route, from the earliest to the latest
/// such second, under one revision however often it widens. A route the
/// caller leaves out, or one every relay covers, parks nothing.
#[test]
fn the_retention_prune_parks_overtaken_debt() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (owed, covered, left_out, bare) = (group(1), group(2), group(3), group(4));
    for route in [&owed, &covered, &left_out, &bare] {
        app.widen_recovery_coverage_goals(std::slice::from_ref(route), NOW - 1_000)
            .unwrap();
    }
    cover(&app, &owed, RELAY, (NOW - 1_000, NOW - 701));
    cover(&app, &owed, RELAY, (NOW - 600, NOW));
    cover(&app, &owed, OTHER, (NOW - 1_000, NOW - 801));
    cover(&app, &owed, OTHER, (NOW - 700, NOW));
    cover(&app, &covered, RELAY, (NOW - 1_000, NOW));
    let both = vec![RELAY.to_owned(), OTHER.to_owned()];
    let routes = [
        (owed.clone(), both.clone()),
        (covered.clone(), vec![RELAY.to_owned()]),
        (bare.clone(), Vec::new()),
    ];
    app.prune_recovery_coverage(NOW - 500, &routes).unwrap();
    let first = remainder(&app, &owed).unwrap();
    assert_eq!(first.range, range(NOW - 800, NOW - 601));
    assert!(first.parked_at_seconds >= NOW, "parked when the prune ran");
    assert!(first.revision > 0);
    assert!(remainder(&app, &covered).is_none());
    assert!(remainder(&app, &left_out).is_none());
    assert_eq!(
        remainder(&app, &bare).unwrap().range,
        range(NOW - 1_000, NOW - 501),
        "a route no relay certifies owes all of it"
    );
    assert_eq!(app.recovery_coverage_goal(&owed).unwrap(), Some(NOW - 500));

    // Coverage the prune keeps parks nothing more; new loss above it does.
    app.prune_recovery_coverage(NOW - 400, &routes).unwrap();
    assert!(remainder(&app, &owed).unwrap() == first);
    app.uncover_recovery_coverage(std::slice::from_ref(&owed), NOW - 450)
        .unwrap();
    app.prune_recovery_coverage(NOW - 300, &routes).unwrap();
    let widened = remainder(&app, &owed).unwrap();
    assert_eq!(widened.range, range(NOW - 800, NOW - 301));
    assert_eq!(widened.revision, first.revision);
}

/// Loss from below the window, or from an unknown bound, owes the window and
/// parks the rest at the next prune.
#[test]
fn loss_below_the_window_parks_the_rest() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (known, unknown) = (group(1), group(2));
    for route in [&known, &unknown] {
        owing(&app, route, NOW - 500, (NOW - 500, NOW));
    }
    app.uncover_recovery_coverage(std::slice::from_ref(&known), NOW - 2_000)
        .unwrap();
    app.uncover_recovery_coverage(std::slice::from_ref(&unknown), 0)
        .unwrap();
    let routes = [
        (known.clone(), vec![RELAY.to_owned()]),
        (unknown.clone(), vec![RELAY.to_owned()]),
    ];
    app.prune_recovery_coverage(NOW - 500, &routes).unwrap();
    assert_eq!(
        remainder(&app, &known).unwrap().range,
        range(NOW - 2_000, NOW - 501)
    );
    assert_eq!(
        remainder(&app, &unknown).unwrap().range,
        range(0, NOW - 501)
    );
    for route in [&known, &unknown] {
        assert_eq!(
            app.recovery_unit_debt(route, RELAY, NOW).unwrap(),
            vec![range(NOW - 500, NOW)]
        );
    }
}

/// Nothing below the retention window is owed, so releasing an event from
/// there reopens no dismissed span and breaks no retired unit. (`NOW` is far
/// below the real window.)
#[test]
fn a_release_below_the_window_reopens_no_span() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let revision = break_unit(&app, &route, NOW).park.unwrap().revision;
    assert!(app.dismiss_recovery_route_park(&route, revision).unwrap());
    let retired = app.recovery_unit_spans(&route, RELAY).unwrap();
    storage
        .connection
        .with_transaction(|| {
            crate::app::recovery_coverage::uncover_second_tx(&*storage.lock()?, &route, NOW - 300)
        })
        .unwrap();
    assert!(matches!(
        unit(&app, &route, RELAY).state,
        RecoveryUnitState::Retired
    ));
    assert!(app.recovery_unit_spans(&route, RELAY).unwrap() == retired);
    assert_eq!(
        app.recovery_coverage_goal(&route).unwrap(),
        Some(NOW - 1_000)
    );
}

/// A route's notice covers its broken units and its remainder under the
/// newest revision among them; dismissing it with that revision clears
/// both, and a stale revision, or another route's, clears nothing.
#[test]
fn dismissal_clears_the_remainder_under_the_routes_newest_park() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (alone, both) = (group(1), group(2));
    for route in [&alone, &both] {
        app.widen_recovery_coverage_goals(std::slice::from_ref(route), NOW - 1_000)
            .unwrap();
    }
    owing(&app, &both, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let park = break_unit(&app, &both, NOW).park.unwrap().revision;
    let routes = [
        (alone.clone(), vec![RELAY.to_owned()]),
        (both.clone(), vec![RELAY.to_owned()]),
    ];
    // `both` owes nothing below the floor until new loss lands there.
    app.uncover_recovery_coverage(std::slice::from_ref(&both), NOW - 900)
        .unwrap();
    app.prune_recovery_coverage(NOW - 800, &routes).unwrap();
    let alone_revision = remainder(&app, &alone).unwrap().revision;
    let both_revision = remainder(&app, &both).unwrap().revision;
    assert!(both_revision > park);
    let parked = app.parked_recovery_routes().unwrap();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].revision, both_revision);

    assert!(!app.dismiss_recovery_route_park(&both, park).unwrap());
    assert!(!app.dismiss_recovery_route_park(&alone, park).unwrap());
    assert!(
        app.dismiss_recovery_route_park(&both, both_revision)
            .unwrap()
    );
    assert!(remainder(&app, &both).is_none());
    assert!(matches!(
        unit(&app, &both, RELAY).state,
        RecoveryUnitState::Retired
    ));
    assert!(
        app.dismiss_recovery_route_park(&alone, alone_revision)
            .unwrap()
    );
    assert!(remainder(&app, &alone).is_none());
    assert!(
        !app.dismiss_recovery_route_park(&alone, alone_revision)
            .unwrap()
    );
}

/// A prune settles each route below its floor. Widening a goal back below
/// it, as the report does for pending loss every time, parks nothing twice:
/// not history that was covered before the prune dropped its coverage, and
/// not a remainder that was dismissed. Only new loss reopens it.
#[test]
fn a_goal_widened_back_below_the_settled_floor_parks_nothing_twice() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (partial, covered) = (group(1), group(2));
    for route in [&partial, &covered] {
        app.uncover_recovery_coverage(std::slice::from_ref(route), NOW - 1_000)
            .unwrap();
    }
    cover(&app, &partial, RELAY, (NOW - 1_000, NOW - 801));
    cover(&app, &partial, RELAY, (NOW - 600, NOW));
    cover(&app, &covered, RELAY, (NOW - 1_000, NOW));
    let routes = [
        (partial.clone(), vec![RELAY.to_owned()]),
        (covered.clone(), vec![RELAY.to_owned()]),
    ];
    app.prune_recovery_coverage(NOW - 500, &routes).unwrap();
    let first = remainder(&app, &partial).unwrap();
    assert_eq!(first.range, range(NOW - 800, NOW - 601));
    assert!(remainder(&app, &covered).is_none());

    // The report restores the pending loss's goal before every prune.
    for floor in [NOW - 500, NOW - 400] {
        app.widen_recovery_coverage_goals(&[partial.clone(), covered.clone()], NOW - 1_000)
            .unwrap();
        app.prune_recovery_coverage(floor, &routes).unwrap();
        assert!(remainder(&app, &partial).unwrap() == first);
        assert!(
            remainder(&app, &covered).is_none(),
            "covered before the prune"
        );
    }

    assert!(
        app.dismiss_recovery_route_park(&partial, first.revision)
            .unwrap()
    );
    app.widen_recovery_coverage_goals(std::slice::from_ref(&partial), NOW - 1_000)
        .unwrap();
    app.prune_recovery_coverage(NOW - 400, &routes).unwrap();
    assert!(remainder(&app, &partial).is_none(), "a dismissal sticks");

    // New loss from below the settled floor parks again, under a new notice.
    app.uncover_recovery_coverage(std::slice::from_ref(&partial), NOW - 900)
        .unwrap();
    app.prune_recovery_coverage(NOW - 400, &routes).unwrap();
    let reopened = remainder(&app, &partial).unwrap();
    assert_eq!(reopened.range, range(NOW - 900, NOW - 401));
    assert!(reopened.revision > first.revision);
}

/// A prune settles a route it was not given too: what it owed below the floor
/// is dropped once, and widening its goal back later parks none of it.
#[test]
fn a_route_left_out_stays_settled_when_its_goal_widens_back() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    app.uncover_recovery_coverage(std::slice::from_ref(&route), NOW - 1_000)
        .unwrap();
    cover(&app, &route, RELAY, (NOW - 1_000, NOW));
    app.prune_recovery_coverage(NOW - 500, &[]).unwrap();
    app.widen_recovery_coverage_goals(std::slice::from_ref(&route), NOW - 1_000)
        .unwrap();
    app.prune_recovery_coverage(NOW - 500, &[(route.clone(), vec![RELAY.to_owned()])])
        .unwrap();
    assert!(remainder(&app, &route).is_none());
}

/// Any coverage write on the unit's relay trims its spans, and covering the
/// last parked part re-arms a broken unit and ends its notice.
#[test]
fn covering_the_whole_park_rearms_the_unit() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    break_unit(&app, &route, NOW);
    cover(&app, &route, OTHER, (NOW - 500, NOW));
    assert!(
        matches!(
            unit(&app, &route, RELAY).state,
            RecoveryUnitState::Broken(_)
        ),
        "another relay's coverage proves nothing here"
    );
    cover(&app, &route, RELAY, (NOW - 500, NOW - 300));
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 299, NOW),
            retired: None
        }]
    );
    assert_eq!(app.parked_recovery_routes().unwrap().len(), 1);
    cover(&app, &route, RELAY, (NOW - 299, NOW));
    let rearmed = unit(&app, &route, RELAY);
    assert_eq!(
        (rearmed.state, rearmed.park),
        (RecoveryUnitState::Active, None)
    );
    assert!(app.recovery_unit_spans(&route, RELAY).unwrap().is_empty());
    assert!(app.parked_recovery_routes().unwrap().is_empty());
}

/// A retired unit's remaining debt is served like an active unit's, with a
/// fresh budget: it backs off, and progress makes it active, while its
/// retired spans stay retired.
#[test]
fn a_retired_unit_is_served_like_an_active_one() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let revision = break_unit(&app, &route, NOW).park.unwrap().revision;
    assert!(app.dismiss_recovery_route_park(&route, revision).unwrap());
    let retired = unit(&app, &route, RELAY);
    assert_eq!((retired.no_progress, retired.backoff_step), (0, 0));
    assert_eq!(
        app.recovery_unit_debt(&route, RELAY, NOW + 100).unwrap(),
        vec![range(NOW + 1, NOW + 100)],
        "newer seconds are owed"
    );
    let backing_off = settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::NoProgress,
        NOW + 100,
    );
    assert_eq!(backing_off.state, RecoveryUnitState::Retired);
    assert_eq!(
        (backing_off.no_progress, backing_off.next_attempt_at_seconds),
        (1, NOW + 130)
    );
    let advanced = settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::Advanced,
        NOW + 130,
    );
    assert_eq!(advanced.state, RecoveryUnitState::Active);
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 500, NOW),
            retired: Some(RecoverySpanRetirement::Dismissed),
        }]
    );
    let broken = break_unit(&app, &route, NOW + 200);
    assert!(broken.park.unwrap().revision > revision, "a new notice");
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![
            RecoveryUnitSpan {
                range: range(NOW - 500, NOW),
                retired: Some(RecoverySpanRetirement::Dismissed),
            },
            RecoveryUnitSpan {
                range: range(NOW + 1, NOW + 200),
                retired: None
            },
        ]
    );
}

/// New loss inside a retired span reopens it whatever the unit's state: an
/// active unit owes it as ordinary debt, and a broken one adds it to its park
/// and earns a probe.
#[test]
fn new_loss_reopens_retired_spans_in_any_state() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (active, broken, retired) = (group(1), group(2), group(3));
    for route in [&active, &broken] {
        owing(&app, route, NOW - 1_000, (NOW - 1_000, NOW - 501));
        let revision = break_unit(&app, route, NOW).park.unwrap().revision;
        assert!(app.dismiss_recovery_route_park(route, revision).unwrap());
        settle(&app, route, RELAY, RecoveryUnitOutcome::Advanced, NOW + 10);
    }
    owing(&app, &retired, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let dismissed = break_unit(&app, &retired, NOW).park.unwrap().revision;
    assert!(
        app.dismiss_recovery_route_park(&retired, dismissed)
            .unwrap()
    );
    let revision = break_unit(&app, &broken, NOW + 20).park.unwrap().revision;
    for route in [&active, &broken, &retired] {
        app.uncover_recovery_coverage(std::slice::from_ref(route), NOW - 300)
            .unwrap();
    }
    let still_active = unit(&app, &active, RELAY);
    assert_eq!(still_active.state, RecoveryUnitState::Active);
    assert_eq!(
        app.recovery_unit_debt(&active, RELAY, NOW).unwrap(),
        vec![range(NOW - 300, NOW)],
        "the reopened seconds are ordinary debt"
    );
    let probing = unit(&app, &broken, RELAY);
    assert!(probing.probe);
    assert_eq!(probing.park.unwrap().revision, revision);
    assert_eq!(
        app.recovery_unit_spans(&broken, RELAY).unwrap(),
        vec![
            RecoveryUnitSpan {
                range: range(NOW - 500, NOW - 301),
                retired: Some(RecoverySpanRetirement::Dismissed),
            },
            RecoveryUnitSpan {
                range: range(NOW - 300, NOW + 20),
                retired: None,
            },
        ],
        "the reopened seconds join the park"
    );
    // On a retired unit the reopened part parks under a new notice, with one
    // probe; the rest stays retired.
    let reopened = unit(&app, &retired, RELAY);
    assert_eq!(
        reopened.state,
        RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress)
    );
    assert!(reopened.probe);
    assert!(reopened.park.unwrap().revision > dismissed, "a new park");
    assert_eq!(
        app.recovery_unit_spans(&retired, RELAY).unwrap(),
        vec![
            RecoveryUnitSpan {
                range: range(NOW - 500, NOW - 301),
                retired: Some(RecoverySpanRetirement::Dismissed),
            },
            RecoveryUnitSpan {
                range: range(NOW - 300, NOW),
                retired: None,
            },
        ]
    );
    assert_eq!(
        app.recovery_unit_debt(&retired, RELAY, NOW).unwrap(),
        vec![range(NOW - 300, NOW)]
    );
}

/// A failed or refused probe re-parks under the same notice, keeping its
/// park and adding what else is owed now.
#[test]
fn a_failed_probe_re_parks_under_the_same_notice() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    for (byte, outcome) in [
        (1, RecoveryUnitOutcome::NoProgress),
        (2, RecoveryUnitOutcome::Refused),
    ] {
        let route = group(byte);
        owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
        let park = break_unit(&app, &route, NOW).park.unwrap();
        app.uncover_recovery_coverage(std::slice::from_ref(&route), NOW - 100)
            .unwrap();
        assert!(unit(&app, &route, RELAY).probe);
        let reparked = settle(&app, &route, RELAY, outcome, NOW + 10);
        assert!(!reparked.probe);
        assert_eq!(reparked.park, Some(park), "the same notice");
        assert_eq!(
            app.recovery_unit_spans(&route, RELAY).unwrap(),
            vec![RecoveryUnitSpan {
                range: range(NOW - 500, NOW + 10),
                retired: None
            }]
        );
    }
}

/// An unreachable or rate-limited probe was not answered, so it keeps its
/// allowance; the relay's retry delay and cooldown pace it as they pace every
/// unit on that relay.
#[test]
fn an_unanswered_probe_keeps_its_allowance() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let park = break_unit(&app, &route, NOW).park;
    app.uncover_recovery_coverage(std::slice::from_ref(&route), NOW - 700)
        .unwrap();
    let unreachable = settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::Unreachable,
        NOW + 10,
    );
    assert!(unreachable.probe);
    assert_eq!(unreachable.next_attempt_at_seconds, NOW + 40);
    let limited = settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::RateLimited,
        NOW + 40,
    );
    assert!(limited.probe);
    assert_eq!(limited.park, park);
    assert!(health(&app, RELAY).cooldown.is_some());
}

/// A zero cap holds the account with nothing spent, and the pause never
/// ends.
#[test]
fn a_zero_cap_pauses_without_end() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    for policy in [
        RecoveryUnitPolicy {
            max_attempts_per_hour: 0,
            ..POLICY
        },
        RecoveryUnitPolicy {
            max_event_bytes_per_hour: 0,
            ..POLICY
        },
    ] {
        assert_eq!(
            app.recovery_account_paused_until(&policy, NOW).unwrap(),
            Some(u64::MAX)
        );
    }
    app.begin_recovery_unit_attempt(&group(1), RELAY, None, NOW)
        .unwrap();
    let zero = RecoveryUnitPolicy {
        max_attempts_per_hour: 0,
        ..POLICY
    };
    assert_eq!(
        app.recovery_account_paused_until(&zero, NOW).unwrap(),
        Some(u64::MAX)
    );
}

/// Nothing owed resets a retired unit's backoff but leaves it retired, so
/// newer loss inside its retired span still opens a new notice.
#[test]
fn nothing_owed_keeps_a_retired_unit_retired() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    let revision = break_unit(&app, &route, NOW).park.unwrap().revision;
    assert!(app.dismiss_recovery_route_park(&route, revision).unwrap());
    settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::NoProgress,
        NOW + 10,
    );
    let owed_nothing = settle(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::NothingOwed,
        NOW + 20,
    );
    assert_eq!(owed_nothing.state, RecoveryUnitState::Retired);
    assert_eq!(
        (
            owed_nothing.no_progress,
            owed_nothing.next_attempt_at_seconds
        ),
        (0, 0)
    );
    app.uncover_recovery_coverage(std::slice::from_ref(&route), NOW - 300)
        .unwrap();
    let reopened = unit(&app, &route, RELAY);
    assert!(matches!(reopened.state, RecoveryUnitState::Broken(_)) && reopened.probe);
    assert!(reopened.park.unwrap().revision > revision, "a new notice");
}

/// A granted probe is due at once, not after a backoff from before.
#[test]
fn a_granted_probe_does_not_wait_out_an_old_backoff() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (broken, retired) = (group(1), group(2));
    for route in [&broken, &retired] {
        owing(&app, route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    }
    break_unit(&app, &broken, NOW);
    settle(&app, &broken, RELAY, RecoveryUnitOutcome::Unreachable, NOW);
    assert_eq!(unit(&app, &broken, RELAY).next_attempt_at_seconds, NOW + 30);
    let revision = break_unit(&app, &retired, NOW).park.unwrap().revision;
    assert!(app.dismiss_recovery_route_park(&retired, revision).unwrap());
    settle(&app, &retired, RELAY, RecoveryUnitOutcome::NoProgress, NOW);
    assert_eq!(
        unit(&app, &retired, RELAY).next_attempt_at_seconds,
        NOW + 30
    );
    for route in [&broken, &retired] {
        app.uncover_recovery_coverage(std::slice::from_ref(route), NOW - 700)
            .unwrap();
        let probing = unit(&app, route, RELAY);
        assert!(probing.probe);
        assert_eq!(probing.next_attempt_at_seconds, 0);
    }
}

fn settle_recheck(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
    relay: &str,
    outcome: RecoveryUnitOutcome,
    now: u64,
) {
    app.begin_recovery_unit_attempt(route, relay, None, now)
        .unwrap();
    app.settle_recovery_recheck(route, relay, outcome, &POLICY, now)
        .unwrap();
}

/// A re-check reads ranges the unit does not owe: no outcome touches the
/// unit's backoff, budget or park, while the relay and the account see it as
/// they see any quantum.
#[test]
fn a_recheck_never_touches_the_units_retry_state() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    settle(&app, &route, RELAY, RecoveryUnitOutcome::NoProgress, NOW);
    let before = unit(&app, &route, RELAY);
    for outcome in [
        RecoveryUnitOutcome::NoProgress,
        RecoveryUnitOutcome::Advanced,
        RecoveryUnitOutcome::Refused,
        RecoveryUnitOutcome::NothingOwed,
    ] {
        settle_recheck(&app, &route, RELAY, outcome, NOW + 10);
    }
    let after = unit(&app, &route, RELAY);
    assert_eq!(after.state, RecoveryUnitState::Active);
    assert_eq!(
        (
            after.no_progress,
            after.backoff_step,
            after.next_attempt_at_seconds
        ),
        (
            before.no_progress,
            before.backoff_step,
            before.next_attempt_at_seconds
        )
    );
    // NothingOwed was refunded; the other three stay charged.
    assert_eq!(app.recovery_account_usage(NOW + 10).unwrap().attempts, 4);

    for _ in 0..POLICY.cooldown_after_unreachable {
        settle_recheck(
            &app,
            &route,
            RELAY,
            RecoveryUnitOutcome::Unreachable,
            NOW + 20,
        );
    }
    assert!(health(&app, RELAY).cooldown.is_some());
    assert_eq!(
        unit(&app, &route, RELAY).next_attempt_at_seconds,
        before.next_attempt_at_seconds
    );
    settle_recheck(
        &app,
        &route,
        OTHER,
        RecoveryUnitOutcome::RateLimited,
        NOW + 20,
    );
    assert!(health(&app, OTHER).cooldown.is_some());
    settle_recheck(
        &app,
        &route,
        RELAY,
        RecoveryUnitOutcome::NoProgress,
        NOW + 30,
    );
    assert_eq!(health(&app, RELAY).unreachable_streak, 0);
    assert_eq!(health(&app, RELAY).cooldown, None);
}

/// An epoch gap's bound never narrows a pass that is due or running: it only
/// moves a finished unit's next pass to start at the bound.
#[test]
fn an_epoch_gap_keeps_what_a_due_pass_would_check() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let fresh = group(1);
    let running = group(2);
    let finished = group(3);
    for route in [&fresh, &running, &finished] {
        app.begin_recovery_unit_attempt(route, RELAY, None, NOW)
            .unwrap();
    }
    app.record_recovery_recheck(&running, RELAY, 0, NOW - 400, false, NOW)
        .unwrap();
    app.record_recovery_recheck(&finished, RELAY, 0, 0, true, NOW)
        .unwrap();
    for route in [&fresh, &running, &finished] {
        app.make_recovery_recheck_due(route, None, Some(NOW - 200))
            .unwrap();
    }
    let pass = |route| unit(&app, route, RELAY).recheck;
    assert_eq!(
        pass(&fresh),
        RecoveryRecheckPass {
            revision: 1,
            ..RecoveryRecheckPass::default()
        }
    );
    assert_eq!(
        pass(&running),
        RecoveryRecheckPass {
            position_seconds: Some(NOW - 400),
            completed_at_seconds: None,
            revision: 1,
        }
    );
    assert_eq!(
        pass(&finished),
        RecoveryRecheckPass {
            position_seconds: Some(NOW - 200),
            completed_at_seconds: None,
            revision: 1,
        }
    );
    // An earlier bound reaches further back; no bound starts from the floor.
    app.make_recovery_recheck_due(&finished, Some(RELAY), Some(NOW - 300))
        .unwrap();
    assert_eq!(pass(&finished).position_seconds, Some(NOW - 300));
    app.make_recovery_recheck_due(&finished, Some(RELAY), None)
        .unwrap();
    assert_eq!(
        pass(&finished),
        RecoveryRecheckPass {
            revision: 3,
            ..RecoveryRecheckPass::default()
        }
    );
}

fn gone(range: RecoveryCoverageRange) -> RecoveryUnitSpan {
    RecoveryUnitSpan {
        range,
        retired: Some(RecoverySpanRetirement::RouteGone),
    }
}

/// A relay that left a route retires what it parked, retired and still owes
/// there as route gone: its notice ends, nothing is owed, and another relay
/// of the route is left as it is.
#[test]
fn a_gone_relay_retires_what_it_owes_and_parks() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 701));
    let revision = break_unit(&app, &route, NOW - 600).park.unwrap().revision;
    assert!(app.dismiss_recovery_route_park(&route, revision).unwrap());
    break_unit(&app, &route, NOW - 100);
    settle(&app, &route, OTHER, RecoveryUnitOutcome::NoProgress, NOW);
    app.set_recovery_unit_fences(&route, RELAY, &[range(NOW - 50, NOW - 40)])
        .unwrap();
    assert_eq!(app.parked_recovery_routes().unwrap().len(), 1);

    assert_eq!(
        app.retire_gone_recovery_units(&route, Some(&[RELAY.to_owned()]), NOW)
            .unwrap(),
        1
    );

    let retired = unit(&app, &route, RELAY);
    assert_eq!(
        (
            retired.state,
            retired.no_progress,
            retired.park,
            retired.probe
        ),
        (RecoveryUnitState::Retired, 0, None, false)
    );
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![gone(range(NOW - 700, NOW))]
    );
    assert_eq!(app.recovery_unit_debt(&route, RELAY, NOW).unwrap(), []);
    assert!(app.parked_recovery_routes().unwrap().is_empty());
    assert!(fences(&app).is_empty());
    assert_eq!(unit(&app, &route, OTHER).no_progress, 1);
}

/// New loss reopens nothing a gone relay retired: it raises no probe or
/// notice for a route that no longer carries it.
#[test]
fn loss_reopens_nothing_a_gone_relay_retired() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    owing(&app, &route, NOW - 1_000, (NOW - 1_000, NOW - 501));
    break_unit(&app, &route, NOW);
    app.retire_gone_recovery_units(&route, None, NOW).unwrap();

    app.uncover_recovery_coverage(std::slice::from_ref(&route), NOW - 800)
        .unwrap();

    let retired = unit(&app, &route, RELAY);
    assert_eq!(
        (retired.state, retired.probe, retired.park),
        (RecoveryUnitState::Retired, false, None)
    );
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![gone(range(NOW - 500, NOW))]
    );
    assert!(app.parked_recovery_routes().unwrap().is_empty());
}

/// An ended route's remainder goes with its units, so it raises no notice.
#[test]
fn an_ended_route_drops_its_remainder() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    app.widen_recovery_coverage_goals(std::slice::from_ref(&route), NOW - 1_000)
        .unwrap();
    app.prune_recovery_coverage(NOW - 800, &[(route.clone(), vec![RELAY.to_owned()])])
        .unwrap();
    assert!(remainder(&app, &route).is_some());

    app.retire_gone_recovery_units(&route, Some(&[RELAY.to_owned()]), NOW)
        .unwrap();
    assert!(remainder(&app, &route).is_some(), "the route goes on");
    app.retire_gone_recovery_units(&route, None, NOW).unwrap();
    assert!(remainder(&app, &route).is_none());
    assert!(app.parked_recovery_routes().unwrap().is_empty());
}

/// A relay that carries its route again owes the whole goal: what it retired
/// as gone is owed again with a fresh budget. A relay still gone stays
/// retired.
#[test]
fn a_returning_relay_owes_its_whole_goal_again() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (back, still_gone) = (group(1), group(2));
    for route in [&back, &still_gone] {
        owing(&app, route, NOW - 1_000, (NOW - 1_000, NOW - 501));
        break_unit(&app, route, NOW);
        app.retire_gone_recovery_units(route, None, NOW).unwrap();
    }

    assert_eq!(
        app.reopen_returned_recovery_units(|route, relay| route == &back && relay == RELAY)
            .unwrap(),
        1
    );

    let returned = unit(&app, &back, RELAY);
    assert_eq!(
        (returned.state, returned.no_progress, returned.park),
        (RecoveryUnitState::Active, 0, None)
    );
    assert!(app.recovery_unit_spans(&back, RELAY).unwrap().is_empty());
    assert_eq!(
        app.recovery_unit_debt(&back, RELAY, NOW).unwrap(),
        vec![range(NOW - 500, NOW)]
    );
    assert_eq!(
        unit(&app, &still_gone, RELAY).state,
        RecoveryUnitState::Retired
    );
    assert_eq!(
        app.reopen_returned_recovery_units(|_, _| true).unwrap(),
        1,
        "only the still-gone unit is left to reopen"
    );
}
