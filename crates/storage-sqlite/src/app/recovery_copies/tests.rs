//! Rejoin settlement tests.

use super::*;
use crate::app::recovery_coverage::RecoveryCoverageRange;
use crate::{
    RecoveryCoverageProof, RecoveryCoverageSlice, RecoverySpanRetirement, RecoveryUnitOutcome,
    RecoveryUnitPolicy, RecoveryUnitSpan, RecoveryUnitState, SqliteAccountStorage,
};

const RELAY: &str = "wss://a.example";
const OTHER: &str = "wss://b.example";
const NOW: u64 = 1_000_000;
const GROUP: &[u8] = &[7; 16];

const POLICY: RecoveryUnitPolicy = RecoveryUnitPolicy {
    backoff_base_seconds: 30,
    backoff_cap_seconds: 3_600,
    break_after_no_progress: 2,
    unreachable_retry_seconds: 30,
    cooldown_after_unreachable: 3,
    cooldown_base_seconds: 60,
    cooldown_cap_seconds: 3_600,
    max_attempts_per_hour: 720,
    max_event_bytes_per_hour: 256 << 20,
    recheck_after_cooldown_seconds: 3_600,
};

fn route(byte: u8) -> TransportReconciliationRoute {
    TransportReconciliationRoute::Group([byte; 32])
}

fn range(since: u64, until: u64) -> RecoveryCoverageRange {
    RecoveryCoverageRange {
        since_seconds: since,
        until_seconds: until,
    }
}

fn before_copy(since: u64, until: u64) -> RecoveryUnitSpan {
    RecoveryUnitSpan {
        range: range(since, until),
        retired: Some(RecoverySpanRetirement::BeforeThisCopy),
    }
}

fn cover(app: &SqliteAppStorage, route: &TransportReconciliationRoute, covered: (u64, u64)) {
    app.record_recovery_coverage(
        &[RecoveryCoverageSlice {
            route,
            relay: RELAY,
            since_seconds: covered.0,
            until_seconds: covered.1,
            proof: RecoveryCoverageProof::SweepSlice,
        }],
        NOW,
    )
    .unwrap();
}

/// Break `route`'s unit on `RELAY`, which parks what it owes.
fn park(app: &SqliteAppStorage, route: &TransportReconciliationRoute) -> u64 {
    let mut revision = None;
    for _ in 0..POLICY.break_after_no_progress {
        app.begin_recovery_unit_attempt(route, RELAY, None, NOW)
            .unwrap();
        revision = app
            .settle_recovery_unit(route, RELAY, RecoveryUnitOutcome::NoProgress, &POLICY, NOW)
            .unwrap()
            .park
            .map(|park| park.revision);
    }
    revision.expect("the budget breaks the unit")
}

fn settle(
    app: &SqliteAppStorage,
    routes: &[(TransportReconciliationRoute, Vec<String>)],
    install_epoch: u64,
    floor_seconds: u64,
) -> bool {
    app.settle_recovery_rejoin(&RecoveryRejoin {
        group_id: GROUP,
        install_epoch,
        routes,
        floor_seconds,
        now_seconds: NOW,
    })
    .unwrap()
}

/// A rejoin retires, on every relay of every route, what was owed or parked
/// below the new copy's floor as before this copy, never as coverage: the
/// covered seconds stay covered and nothing below the floor is owed. Each
/// unit starts over active, owing what is above the floor, and keeps its
/// earlier retirements. Settling the same copy again changes nothing.
#[test]
fn a_rejoin_retires_what_lay_before_its_copy() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (current, prior) = (route(1), route(2));
    app.widen_recovery_coverage_goals(
        &[current.clone(), prior.clone()],
        NOW - 1_000,
        crate::CopyFloorReason::Clamp,
    )
    .unwrap();
    cover(&app, &current, (NOW - 1_000, NOW - 801));
    let parked = park(&app, &current);
    assert!(app.dismiss_recovery_route_park(&current, parked).unwrap());
    app.uncover_recovery_coverage(
        std::slice::from_ref(&current),
        NOW - 600,
        crate::CopyFloorReason::Loss,
    )
    .unwrap();
    let reparked = park(&app, &current);
    let both = vec![RELAY.to_owned(), OTHER.to_owned()];
    let routes = [(current.clone(), both.clone()), (prior.clone(), both)];

    assert!(settle(&app, &routes, 5, NOW - 300));
    let unit = app.recovery_unit(&current, RELAY).unwrap().unwrap();
    assert_eq!(unit.state, RecoveryUnitState::Active);
    assert!(unit.park.is_none());
    assert_eq!(unit.no_progress, 0);
    assert_eq!(
        app.recovery_unit_spans(&current, RELAY).unwrap(),
        vec![
            RecoveryUnitSpan {
                range: range(NOW - 800, NOW - 601),
                retired: Some(RecoverySpanRetirement::Dismissed),
            },
            before_copy(NOW - 600, NOW - 301),
        ],
        "the dismissal keeps its reason and the re-park retires below the floor"
    );
    for (route, relay) in [(&current, OTHER), (&prior, RELAY), (&prior, OTHER)] {
        assert_eq!(
            app.recovery_unit_spans(route, relay).unwrap(),
            vec![before_copy(NOW - 1_000, NOW - 301)],
            "a relay with no unit yet holds what it retires"
        );
    }
    for (route, relay) in [(&current, RELAY), (&current, OTHER), (&prior, RELAY)] {
        assert_eq!(
            app.recovery_unit_debt(route, relay, NOW).unwrap(),
            vec![range(NOW - 300, NOW)],
            "only the new copy's span is owed"
        );
    }
    assert_eq!(
        app.recovery_coverage_goal(&current).unwrap(),
        Some(NOW - 1_000),
        "goals keep their start"
    );
    let notices = app.recovery_rejoin_notices().unwrap();
    assert!(
        notices
            == [RecoveryRejoinNotice {
                group_id: GROUP.to_vec(),
                revision: notices[0].revision,
                noticed_at_seconds: NOW,
            }]
    );
    assert!(notices[0].revision > reparked, "a new notice");
    assert_eq!(
        app.recovery_copy(GROUP).unwrap(),
        Some(RecoveryCopy::Settled(5))
    );

    let spans = app.recovery_unit_spans(&current, RELAY).unwrap();
    assert!(!settle(&app, &routes, 5, NOW - 100));
    assert_eq!(app.recovery_unit_spans(&current, RELAY).unwrap(), spans);
    assert!(app.recovery_rejoin_notices().unwrap() == notices);
}

/// What a rejoin retired is not owed by the new copy, but it is not lost for
/// good: new loss inside it reopens it as ordinary debt on the active unit,
/// and explicit repair re-arms all of it.
#[test]
fn loss_reopens_a_retired_span_and_repair_rearms_it() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let current = route(1);
    app.widen_recovery_coverage_goals(
        std::slice::from_ref(&current),
        NOW - 1_000,
        crate::CopyFloorReason::Clamp,
    )
    .unwrap();
    cover(&app, &current, (NOW - 1_000, NOW - 801));
    let routes = [(current.clone(), vec![RELAY.to_owned()])];
    assert!(settle(&app, &routes, 5, NOW - 300));
    cover(&app, &current, (NOW - 300, NOW));

    app.uncover_recovery_coverage(
        std::slice::from_ref(&current),
        NOW - 500,
        crate::CopyFloorReason::Loss,
    )
    .unwrap();
    assert_eq!(
        app.recovery_unit_spans(&current, RELAY).unwrap(),
        vec![before_copy(NOW - 800, NOW - 501)]
    );
    assert_eq!(
        app.recovery_unit_debt(&current, RELAY, NOW).unwrap(),
        vec![range(NOW - 500, NOW)]
    );

    // Only what the rejoin retired leaves the copy's debt; the reopened
    // seconds stay owed until fetched.
    assert_eq!(
        app.recovery_coverage_debt(&current, &[RELAY.to_owned()], NOW)
            .unwrap(),
        vec![range(NOW - 800, NOW)]
    );
    assert_eq!(
        app.recovery_copy_debt(&current, RELAY, NOW).unwrap(),
        vec![range(NOW - 500, NOW)]
    );

    app.rearm_all_recovery_units().unwrap();
    assert!(app.recovery_unit_spans(&current, RELAY).unwrap().is_empty());
    assert_eq!(
        app.recovery_unit_debt(&current, RELAY, NOW).unwrap(),
        vec![range(NOW - 800, NOW)]
    );
}

/// A route's remainder is debt the retention floor overtook, so the rejoin's
/// notice replaces it; a remainder reaching above a floor keeps only that
/// part.
#[test]
fn a_rejoin_clears_the_remainder_below_its_floor() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (overtaken, straddling) = (route(1), route(2));
    app.widen_recovery_coverage_goals(
        &[overtaken.clone(), straddling.clone()],
        NOW - 3_000,
        crate::CopyFloorReason::Clamp,
    )
    .unwrap();
    let routes = [
        (overtaken.clone(), vec![RELAY.to_owned()]),
        (straddling.clone(), vec![RELAY.to_owned()]),
    ];
    app.prune_recovery_coverage(NOW - 2_000, &routes).unwrap();
    assert_eq!(app.recovery_coverage_remainders().unwrap().len(), 2);

    assert!(settle(&app, &routes[..1], 5, NOW - 300));
    let left = app.recovery_coverage_remainders().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].route, straddling);

    let settled = app
        .settle_recovery_rejoin(&RecoveryRejoin {
            group_id: &[8; 16],
            install_epoch: 2,
            routes: &routes[1..],
            floor_seconds: NOW - 2_500,
            now_seconds: NOW,
        })
        .unwrap();
    assert!(settled);
    assert_eq!(
        app.recovery_coverage_remainders().unwrap()[0].range,
        range(NOW - 2_500, NOW - 2_001)
    );
}

/// One notice per new copy: a copy settled without a rejoin raises none, a
/// rejoin raises one, a dismissal sticks and a stale one changes nothing, a
/// later rejoin raises a new one, and a copy that replaced none takes an
/// earlier rejoin's notice with it. A group copies were not recorded for
/// reads as unknown.
#[test]
fn a_rejoin_notice_is_raised_once_per_copy() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let routes = [(route(1), vec![RELAY.to_owned()])];
    assert_eq!(app.recovery_copy(GROUP).unwrap(), None);
    app.record_recovery_copy(GROUP, 0).unwrap();
    assert_eq!(
        app.recovery_copy(GROUP).unwrap(),
        Some(RecoveryCopy::Settled(0))
    );
    assert!(app.recovery_rejoin_notices().unwrap().is_empty());

    assert!(settle(&app, &routes, 5, NOW - 300));
    let first = app.recovery_rejoin_notices().unwrap()[0].revision;
    assert!(
        !app.dismiss_recovery_rejoin_notice(GROUP, first + 1)
            .unwrap()
    );
    assert!(app.dismiss_recovery_rejoin_notice(GROUP, first).unwrap());
    assert!(!app.dismiss_recovery_rejoin_notice(GROUP, first).unwrap());
    assert!(app.recovery_rejoin_notices().unwrap().is_empty());
    assert!(
        !settle(&app, &routes, 5, NOW - 300),
        "dismissed stays dismissed"
    );
    assert!(app.recovery_rejoin_notices().unwrap().is_empty());

    assert!(settle(&app, &routes, 9, NOW - 200));
    let second = app.recovery_rejoin_notices().unwrap()[0].revision;
    assert!(second > first);
    app.record_recovery_copy(GROUP, 12).unwrap();
    assert!(app.recovery_rejoin_notices().unwrap().is_empty());
    assert_eq!(
        app.recovery_copy(GROUP).unwrap(),
        Some(RecoveryCopy::Settled(12))
    );

    app.lock()
        .unwrap()
        .execute(
            "INSERT INTO account_recovery_copies (group_id) VALUES (x'09')",
            [],
        )
        .unwrap();
    assert_eq!(
        app.recovery_copy(&[9]).unwrap(),
        Some(RecoveryCopy::Unknown)
    );
}

/// The inbox route belongs to no group, and a group id is never empty.
#[test]
fn a_rejoin_takes_only_a_groups_routes() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let inbox = [(TransportReconciliationRoute::Inbox, vec![RELAY.to_owned()])];
    assert!(
        app.settle_recovery_rejoin(&RecoveryRejoin {
            group_id: GROUP,
            install_epoch: 1,
            routes: &inbox,
            floor_seconds: NOW,
            now_seconds: NOW,
        })
        .is_err()
    );
    assert!(app.record_recovery_copy(&[], 1).is_err());
    assert_eq!(app.recovery_copy(GROUP).unwrap(), None);
}

/// What lay before a rejoined copy belongs to the group's copy, not to its
/// route's relays: a relay that leaves the route and returns, or a whole
/// route that ends and comes back, owes its goal again from the new copy's
/// floor, never what lay before the copy. That holds for what the rejoin
/// retired and for what was dismissed before it, which keeps its own reason
/// below the floor; only what lay above the floor goes with the relay.
#[test]
fn a_rejoins_retirement_outlasts_its_relay_leaving_and_returning() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (current, ended) = (route(1), route(2));
    app.widen_recovery_coverage_goals(
        &[current.clone(), ended.clone()],
        NOW - 1_000,
        crate::CopyFloorReason::Clamp,
    )
    .unwrap();
    // Both routes dismissed what they owed before the rejoin; `ended` then
    // lost what lay after NOW - 600, and `current`'s dismissal straddles the
    // floor.
    for route in [&current, &ended] {
        let parked = park(&app, route);
        assert!(app.dismiss_recovery_route_park(route, parked).unwrap());
    }
    app.uncover_recovery_coverage(
        std::slice::from_ref(&ended),
        NOW - 600,
        crate::CopyFloorReason::Loss,
    )
    .unwrap();
    assert!(settle(
        &app,
        &[
            (current.clone(), vec![RELAY.to_owned()]),
            (ended.clone(), vec![RELAY.to_owned()])
        ],
        5,
        NOW - 300
    ));
    let retired = |since, until, reason| RecoveryUnitSpan {
        range: range(since, until),
        retired: Some(reason),
    };
    let dismissed = |since, until| retired(since, until, RecoverySpanRetirement::Dismissed);
    let gone = retired(NOW - 300, NOW, RecoverySpanRetirement::RouteGone);
    assert_eq!(
        app.retire_gone_recovery_units(&ended, None, NOW).unwrap(),
        1
    );
    assert_eq!(
        app.recovery_unit_spans(&ended, RELAY).unwrap(),
        vec![
            dismissed(NOW - 1_000, NOW - 601),
            before_copy(NOW - 600, NOW - 301),
            gone,
        ]
    );

    let relays = [RELAY.to_owned()];
    assert_eq!(
        app.retire_gone_recovery_units(&current, Some(&relays), NOW)
            .unwrap(),
        1
    );
    assert_eq!(
        app.recovery_unit_spans(&current, RELAY).unwrap(),
        vec![dismissed(NOW - 1_000, NOW - 301), gone],
        "only what lay above the floor goes with the relay"
    );
    assert_eq!(app.reopen_returned_recovery_units(|_, _| true).unwrap(), 2);
    assert_eq!(
        app.recovery_unit_spans(&current, RELAY).unwrap(),
        vec![dismissed(NOW - 1_000, NOW - 301)]
    );
    assert_eq!(
        app.recovery_unit_spans(&ended, RELAY).unwrap(),
        vec![
            dismissed(NOW - 1_000, NOW - 601),
            before_copy(NOW - 600, NOW - 301)
        ]
    );
    for route in [&current, &ended] {
        assert_eq!(
            app.recovery_unit_debt(route, RELAY, NOW).unwrap(),
            vec![range(NOW - 300, NOW)],
            "the returned relay owes the new copy's span"
        );
    }
}

#[test]
fn a_second_rejoin_retires_up_to_its_own_floor() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let current = route(1);
    app.widen_recovery_coverage_goals(
        std::slice::from_ref(&current),
        NOW - 1_000,
        crate::CopyFloorReason::Clamp,
    )
    .unwrap();
    let both = [(current.clone(), vec![RELAY.to_owned(), OTHER.to_owned()])];
    assert!(settle(&app, &both, 5, NOW - 600));
    let others = [OTHER.to_owned()];
    assert_eq!(
        app.retire_gone_recovery_units(&current, Some(&others), NOW - 400)
            .unwrap(),
        1
    );

    assert!(settle(
        &app,
        &[(current.clone(), vec![RELAY.to_owned()])],
        9,
        NOW - 300
    ));
    assert_eq!(app.recovery_copy_floor(GROUP).unwrap(), Some(NOW - 300));
    assert_eq!(
        app.reopen_returned_recovery_units(|_, relay| relay == OTHER)
            .unwrap(),
        1
    );
    assert_eq!(app.retire_before_recovery_copy(GROUP, &both).unwrap(), 1);
    for relay in [RELAY, OTHER] {
        assert_eq!(
            app.recovery_unit_spans(&current, relay).unwrap(),
            vec![
                before_copy(NOW - 1_000, NOW - 601),
                before_copy(NOW - 600, NOW - 301)
            ]
        );
        assert_eq!(
            app.recovery_unit_debt(&current, relay, NOW).unwrap(),
            vec![range(NOW - 300, NOW)],
            "only the second copy's span is owed"
        );
    }
}

/// A rejoined group's epoch gap is in its new copy's epochs. Whoever begins a
/// visit, sync arming a stall or the runner returning, and from whatever
/// floor it passes, the visit reopens the new copy's span and never what the
/// rejoin retired.
#[test]
fn an_epoch_gap_visit_never_reopens_what_a_rejoin_retired() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    app.lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 1, x'00')",
            [GROUP],
        )
        .unwrap();
    let current = route(1);
    app.widen_recovery_coverage_goals(
        std::slice::from_ref(&current),
        NOW - 1_000,
        crate::CopyFloorReason::Clamp,
    )
    .unwrap();
    assert!(settle(
        &app,
        &[(current.clone(), vec![RELAY.to_owned()])],
        5,
        NOW - 300
    ));
    cover(&app, &current, (NOW - 300, NOW - 100));
    app.arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
        group_id_hex: hex::encode(GROUP),
        stalled_epoch: 1,
    }])
    .unwrap();
    let ticket = app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.cause == crate::RecoveryCause::EpochGap)
        .expect("an armed epoch gap")
        .ticket;

    assert!(
        app.begin_recovery_epoch_gap_retry(ticket, &[(current.clone(), NOW - 1_000)], NOW)
            .unwrap()
    );
    assert_eq!(
        app.recovery_unit_spans(&current, RELAY).unwrap(),
        vec![before_copy(NOW - 1_000, NOW - 301)],
        "what the rejoin retired stays retired"
    );
    assert_eq!(
        app.recovery_unit_debt(&current, RELAY, NOW).unwrap(),
        vec![range(NOW - 300, NOW)],
        "the visit reopens the new copy's span"
    );
}

/// What a rejoin retires belongs to every relay of the group's routes, not
/// only those carried at the rejoin: a relay that joins a route afterwards,
/// and one that left before the rejoin and returns, each retire below the
/// rejoin's floor once and owe only from it. Loss that later reopens a
/// relay's retirement stays reopened, and a copy that replaced none retires
/// nothing.
#[test]
fn relays_that_join_or_return_after_a_rejoin_owe_only_from_its_floor() {
    const RETURNING: &str = "wss://c.example";
    const LATER: &str = "wss://d.example";
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let current = route(1);
    app.widen_recovery_coverage_goals(
        std::slice::from_ref(&current),
        NOW - 1_000,
        crate::CopyFloorReason::Clamp,
    )
    .unwrap();
    app.begin_recovery_unit_attempt(&current, RETURNING, None, NOW - 950)
        .unwrap();
    let left = [RETURNING.to_owned()];
    assert_eq!(
        app.retire_gone_recovery_units(&current, Some(&left), NOW - 900)
            .unwrap(),
        1
    );
    assert!(settle(
        &app,
        &[(current.clone(), vec![RELAY.to_owned()])],
        5,
        NOW - 300
    ));

    assert_eq!(
        app.reopen_returned_recovery_units(|_, relay| relay == RETURNING)
            .unwrap(),
        1
    );
    assert_eq!(
        app.recovery_unit_debt(&current, RETURNING, NOW).unwrap(),
        vec![range(NOW - 1_000, NOW)],
        "a returned relay owes its whole goal until it settles the rejoin"
    );
    let carried = [(
        current.clone(),
        vec![RELAY.to_owned(), OTHER.to_owned(), RETURNING.to_owned()],
    )];
    assert_eq!(app.retire_before_recovery_copy(GROUP, &carried).unwrap(), 2);
    for relay in [OTHER, RETURNING] {
        assert_eq!(
            app.recovery_unit_spans(&current, relay).unwrap(),
            vec![before_copy(NOW - 1_000, NOW - 301)]
        );
        assert_eq!(
            app.recovery_unit_debt(&current, relay, NOW).unwrap(),
            vec![range(NOW - 300, NOW)],
            "only the new copy's span is owed"
        );
    }

    app.uncover_recovery_coverage(
        std::slice::from_ref(&current),
        NOW - 500,
        crate::CopyFloorReason::Loss,
    )
    .unwrap();
    assert_eq!(app.retire_before_recovery_copy(GROUP, &carried).unwrap(), 0);
    assert_eq!(
        app.recovery_unit_debt(&current, OTHER, NOW).unwrap(),
        vec![range(NOW - 500, NOW)],
        "loss reopened what the relay retired, and it stays reopened"
    );

    app.record_recovery_copy(GROUP, 6).unwrap();
    let later = [(current.clone(), vec![LATER.to_owned()])];
    assert_eq!(app.retire_before_recovery_copy(GROUP, &later).unwrap(), 0);
    assert_eq!(
        app.recovery_unit_debt(&current, LATER, NOW).unwrap(),
        vec![range(NOW - 1_000, NOW)]
    );
}

/// Forgetting a group, or deleting a terminal one, drops its copy and the
/// routes and relays that hold its floor with the engine record: a later join
/// of the same group is a fresh copy, with no rejoin floor, settled route or
/// relay, or notice.
#[test]
fn forgetting_or_deleting_a_group_drops_its_copy() {
    for terminal in [false, true] {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let current = route(1);
        app.widen_recovery_coverage_goals(
            std::slice::from_ref(&current),
            NOW - 1_000,
            crate::CopyFloorReason::Clamp,
        )
        .unwrap();
        assert!(settle(
            &app,
            &[(current.clone(), vec![RELAY.to_owned()])],
            5,
            NOW - 300
        ));
        assert_eq!(app.recovery_rejoin_notices().unwrap().len(), 1);
        let recorded = || -> Vec<i64> {
            [
                "account_recovery_copy_routes",
                "account_recovery_copy_units",
            ]
            .into_iter()
            .map(|table| {
                app.lock()
                    .unwrap()
                    .query_row(
                        &format!("SELECT count(*) FROM {table} WHERE group_id = ?1"),
                        [GROUP],
                        |row| row.get(0),
                    )
                    .unwrap()
            })
            .collect()
        };
        assert_eq!(recorded(), [1, 1]);

        if terminal {
            app.lock()
                .unwrap()
                .execute(
                    "INSERT INTO cgka_disband_tombstones (group_id, record) VALUES (?1, x'00')",
                    [GROUP],
                )
                .unwrap();
            storage
                .delete_local_group_data(&hex::encode(GROUP))
                .unwrap();
        } else {
            storage
                .forget_group_local_data(&hex::encode(GROUP), cgka_traits::Timestamp(NOW))
                .unwrap();
        }
        assert_eq!(
            app.recovery_copy(GROUP).unwrap(),
            None,
            "terminal: {terminal}"
        );
        assert_eq!(recorded(), [0, 0], "terminal: {terminal}");
        assert!(app.recovery_rejoin_notices().unwrap().is_empty());
        let later = [(current.clone(), vec![OTHER.to_owned()])];
        assert_eq!(app.retire_before_recovery_copy(GROUP, &later).unwrap(), 0);
    }
}
