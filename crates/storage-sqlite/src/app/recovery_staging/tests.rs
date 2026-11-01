//! Staging tests.

use super::*;
use crate::{
    RecoveryUnitOutcome, RecoveryUnitPolicy, RecoveryUnitSpan, SqlCipherKey, SqliteAccountStorage,
};
use cgka_traits::storage::StorageError;
use cgka_traits::transport::{TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{MemberId, MessageId, TransportDeliveryPlane, TransportDeliverySource};

const RELAY: &str = "wss://a.example";
const OTHER: &str = "wss://b.example";
const NOW: u64 = 1_000_000;

fn group(byte: u8) -> TransportReconciliationRoute {
    TransportReconciliationRoute::Group([byte; 32])
}

fn range(since: u64, until: u64) -> RecoveryCoverageRange {
    RecoveryCoverageRange {
        since_seconds: since,
        until_seconds: until,
    }
}

/// An event sent at second `id`.
fn delivery(id: u8) -> TransportDelivery {
    delivery_at(id, u64::from(id))
}

/// Event `id`, sent at second `at`.
fn delivery_at(id: u8, at: u64) -> TransportDelivery {
    TransportDelivery {
        account_id: MemberId::new(vec![0xAA; 32]),
        group_id_hint: None,
        message: TransportMessage {
            id: MessageId::new(vec![id; 32]),
            payload: vec![id; 64],
            timestamp: cgka_traits::transport::Timestamp(at),
            causal_deps: Vec::new(),
            source: TransportSource("nostr".to_owned()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![0x42; 32],
            },
        },
        received_at: cgka_traits::transport::Timestamp(7),
        source: TransportDeliverySource {
            transport: TransportSource("nostr".to_owned()),
            plane: TransportDeliveryPlane::Group,
            endpoint: None,
            subscription_id: Some("recovery".to_owned()),
            wire: None,
        },
    }
}

fn mark_seen(app: &SqliteAppStorage, id: u8) {
    app.lock()
        .unwrap()
        .execute_cached(
            "INSERT INTO seen_events(event_id, seen_at) VALUES (?1, 1)",
            [hex::encode([id; 32])],
        )
        .unwrap();
}

fn stage(
    app: &SqliteAppStorage,
    route: &TransportReconciliationRoute,
    relay: &str,
    events: &[TransportDelivery],
    covered: RecoveryCoverageRange,
    mark: RecoveryCoverageMark,
) -> RecoveryStaged {
    app.stage_recovery_slice(
        &RecoveryStagedSlice {
            route,
            relay,
            events,
            fetched_bytes: 1_000,
            covered: &[covered],
            proof: RecoveryCoverageProof::SweepSlice,
            mark,
        },
        NOW,
    )
    .unwrap()
}

fn staged_ids(read: &StagedRecoveryEvents) -> Vec<u8> {
    read.events
        .iter()
        .map(|event| event.delivery.message.id.as_slice()[0])
        .collect()
}

/// A slice stages its unseen events and records its coverage and its fetched
/// bytes; staging it again stages nothing new.
#[test]
fn a_slice_stages_unseen_events_and_its_coverage_together() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    mark_seen(&app, 2);
    let events = [delivery(1), delivery(2), delivery(3)];
    let mark = app.recovery_coverage_mark().unwrap();
    let staged = stage(&app, &route, RELAY, &events, range(0, 100), mark);
    assert_eq!(
        staged,
        RecoveryStaged {
            staged: 2,
            covered: true
        }
    );
    let read = app
        .staged_recovery_events(std::slice::from_ref(&route), NOW, 10)
        .unwrap();
    assert_eq!(staged_ids(&read), vec![1, 3]);
    assert!(read.events[0].delivery == delivery(1), "it round-trips");
    assert!(read.events[0].route == route && read.events[0].relay == RELAY);
    assert_eq!(
        app.recovery_unit_cursor(&route, RELAY, 0, 100).unwrap(),
        None
    );
    assert_eq!(app.recovery_account_usage(NOW).unwrap().event_bytes, 1_000);
    let again = stage(&app, &route, OTHER, &events, range(0, 100), mark);
    assert_eq!(again.staged, 0, "staging is keyed by event id");
    assert_eq!(
        app.staged_recovery_usage(std::slice::from_ref(&route), Some(RELAY))
            .unwrap()
            .events,
        2
    );
    assert_eq!(
        app.staged_recovery_usage(std::slice::from_ref(&route), Some(OTHER))
            .unwrap()
            .events,
        0
    );
}

/// A live boundary never stages, and neither does a slice with no relay.
#[test]
fn a_live_boundary_cannot_stage() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    let mark = app.recovery_coverage_mark().unwrap();
    for (relay, proof) in [
        (RELAY, RecoveryCoverageProof::LiveBoundary),
        ("", RecoveryCoverageProof::SweepSlice),
    ] {
        let result = app.stage_recovery_slice(
            &RecoveryStagedSlice {
                route: &route,
                relay,
                events: &[delivery(1)],
                fetched_bytes: 0,
                covered: &[range(0, 100)],
                proof,
                mark,
            },
            NOW,
        );
        assert!(
            matches!(result, Err(StorageError::Serialization(ref message)) if message == "invalid recovery coverage")
        );
    }
    assert_eq!(
        app.staged_recovery_total().unwrap(),
        RecoveryStagedUsage::default()
    );
}

/// New loss after the fetch began is subtracted from what the slice proves;
/// its events stay staged.
#[test]
fn loss_since_the_mark_is_not_recorded_as_coverage() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    let mark = app.recovery_coverage_mark().unwrap();
    app.uncover_recovery_coverage(std::slice::from_ref(&route), 50)
        .unwrap();
    let staged = stage(&app, &route, RELAY, &[delivery(60)], range(0, 100), mark);
    assert_eq!(staged.staged, 1);
    assert_eq!(
        app.recovery_unit_cursor(&route, RELAY, 0, 100).unwrap(),
        Some(50)
    );
}

/// Reads merge routes oldest first by `(created_at, event id)`, stop before
/// `before_seconds` and honour the limit.
#[test]
fn reads_are_oldest_first_across_routes() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (a, b) = (group(1), group(2));
    let mark = app.recovery_coverage_mark().unwrap();
    stage(
        &app,
        &a,
        RELAY,
        &[delivery(9), delivery(3)],
        range(0, 10),
        mark,
    );
    stage(&app, &b, RELAY, &[delivery(5)], range(0, 10), mark);
    let routes = [a.clone(), b.clone()];
    assert_eq!(app.staged_recovery_routes().unwrap(), routes);
    assert_eq!(
        staged_ids(&app.staged_recovery_events(&routes, NOW, 10).unwrap()),
        vec![3, 5, 9]
    );
    assert_eq!(
        staged_ids(&app.staged_recovery_events(&routes, 9, 10).unwrap()),
        vec![3, 5]
    );
    assert_eq!(
        staged_ids(&app.staged_recovery_events(&routes, NOW, 2).unwrap()),
        vec![3, 5]
    );
    assert_eq!(
        staged_ids(
            &app.staged_recovery_events(std::slice::from_ref(&b), NOW, 10)
                .unwrap()
        ),
        vec![5]
    );
}

/// Only rows whose events are in the seen index leave.
#[test]
fn only_seen_rows_leave_staging() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    let mark = app.recovery_coverage_mark().unwrap();
    stage(
        &app,
        &route,
        RELAY,
        &[delivery(1), delivery(3)],
        range(0, 10),
        mark,
    );
    mark_seen(&app, 1);
    let (one, three) = ([1u8; 32], [3u8; 32]);
    assert_eq!(
        app.remove_seen_staged_recovery_events(&[&one, &three])
            .unwrap(),
        1
    );
    assert_eq!(
        staged_ids(
            &app.staged_recovery_events(std::slice::from_ref(&route), NOW, 10)
                .unwrap()
        ),
        vec![3]
    );
    assert_eq!(app.staged_recovery_total().unwrap().events, 1);
}

/// A row that no longer decodes is reported, and discarding it owes its
/// second again on its route (inside the retention window; below it nothing
/// is owed).
#[test]
fn an_undecodable_row_is_discarded_and_its_second_owed_again() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    let base = i64_to_u64(crate::base::codec::unix_now_seconds_i64()).unwrap() - 1_000;
    let mark = app.recovery_coverage_mark().unwrap();
    stage(
        &app,
        &route,
        RELAY,
        &[delivery_at(5, base + 5), delivery_at(6, base + 6)],
        range(base, base + 10),
        mark,
    );
    app.lock()
        .unwrap()
        .execute_cached(
            "UPDATE account_recovery_staged SET metadata = X'00' WHERE event_id = ?1",
            [vec![5u8; 32]],
        )
        .unwrap();
    let read = app
        .staged_recovery_events(std::slice::from_ref(&route), base + 10, 10)
        .unwrap();
    assert_eq!(staged_ids(&read), vec![6]);
    assert_eq!(read.undecodable, vec![vec![5u8; 32]]);
    assert!(
        app.discard_undecodable_staged_recovery_event(&[5u8; 32])
            .unwrap()
    );
    assert!(
        !app.discard_undecodable_staged_recovery_event(&[5u8; 32])
            .unwrap()
    );
    let relays = [RELAY.to_owned()];
    assert!(
        !app.recovery_coverage_covers(&route, &relays, base + 5, base + 5)
            .unwrap()
    );
    assert!(
        app.recovery_coverage_covers(&route, &relays, base + 6, base + 10)
            .unwrap()
    );
    assert_eq!(
        app.recovery_unit_cursor(&route, RELAY, base, base + 10)
            .unwrap(),
        Some(base + 5)
    );
}

/// A route given back loses its staged rows, and each row's second is owed
/// again on it; other routes keep theirs.
#[test]
fn a_reclaimed_route_gives_back_its_rows_and_owes_their_seconds() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let (gone, kept) = (group(1), group(2));
    let base = i64_to_u64(crate::base::codec::unix_now_seconds_i64()).unwrap() - 1_000;
    let mark = app.recovery_coverage_mark().unwrap();
    stage(
        &app,
        &gone,
        RELAY,
        &[delivery_at(5, base + 5), delivery_at(6, base + 5)],
        range(base, base + 10),
        mark,
    );
    stage(
        &app,
        &kept,
        RELAY,
        &[delivery_at(7, base + 7)],
        range(base, base + 10),
        mark,
    );
    assert_eq!(
        app.reclaim_staged_recovery_routes(std::slice::from_ref(&gone))
            .unwrap(),
        2
    );
    assert_eq!(app.staged_recovery_routes().unwrap(), vec![kept.clone()]);
    let relays = [RELAY.to_owned()];
    assert!(
        !app.recovery_coverage_covers(&gone, &relays, base + 5, base + 5)
            .unwrap()
    );
    assert!(
        app.recovery_coverage_covers(&gone, &relays, base + 6, base + 10)
            .unwrap()
    );
    assert!(
        app.recovery_coverage_covers(&kept, &relays, base, base + 10)
            .unwrap()
    );
}

/// Coverage a slice proves stops being parked debt.
#[test]
fn staging_trims_the_units_parked_spans() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    let policy = RecoveryUnitPolicy {
        backoff_base_seconds: 30,
        backoff_cap_seconds: 3_600,
        break_after_no_progress: 1,
        unreachable_retry_seconds: 30,
        cooldown_after_unreachable: 3,
        cooldown_base_seconds: 60,
        cooldown_cap_seconds: 3_600,
        max_attempts_per_hour: 720,
        max_event_bytes_per_hour: 256 << 20,
        recheck_after_cooldown_seconds: 3_600,
    };
    app.widen_recovery_coverage_goals(std::slice::from_ref(&route), NOW - 100)
        .unwrap();
    app.begin_recovery_unit_attempt(&route, RELAY, None, NOW)
        .unwrap();
    app.settle_recovery_unit(&route, RELAY, RecoveryUnitOutcome::NoProgress, &policy, NOW)
        .unwrap();
    let mark = app.recovery_coverage_mark().unwrap();
    stage(&app, &route, RELAY, &[], range(NOW - 100, NOW - 51), mark);
    assert_eq!(
        app.recovery_unit_spans(&route, RELAY).unwrap(),
        vec![RecoveryUnitSpan {
            range: range(NOW - 50, NOW),
            retired: None
        }]
    );
}

/// A process that dies after staging and before settling keeps the events
/// and the coverage, and its unit is as the attempt began: the cursor is
/// past the slice, so nothing is fetched again, and the attempt stays
/// charged.
#[test]
fn a_crash_between_staging_and_settling_refetches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::raw([0x5c; 32]);
    let path = dir.path().join("session.sqlite");
    let route = group(1);
    {
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = storage.app_storage();
        app.widen_recovery_coverage_goals(std::slice::from_ref(&route), 0)
            .unwrap();
        app.begin_recovery_unit_attempt(&route, RELAY, None, NOW)
            .unwrap();
        let mark = app.recovery_coverage_mark().unwrap();
        stage(&app, &route, RELAY, &[delivery(5)], range(0, 100), mark);
    }
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = storage.app_storage();
    assert_eq!(
        staged_ids(
            &app.staged_recovery_events(std::slice::from_ref(&route), NOW, 10)
                .unwrap()
        ),
        vec![5]
    );
    assert_eq!(
        app.recovery_unit_cursor(&route, RELAY, 0, 200).unwrap(),
        Some(101)
    );
    let unit = app.recovery_unit(&route, RELAY).unwrap().unwrap();
    assert_eq!((unit.no_progress, unit.next_attempt_at_seconds), (0, 0));
    assert_eq!(unit.last_served_at_seconds, Some(NOW));
    assert_eq!(app.recovery_account_usage(NOW).unwrap().attempts, 1);
}

/// A comparison's held set includes what any relay staged on the route in
/// its range, oldest first, and nothing from another route.
#[test]
fn staged_items_are_the_routes_from_every_relay_in_range() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let app = storage.app_storage();
    let route = group(1);
    let mark = app.recovery_coverage_mark().unwrap();
    stage(
        &app,
        &route,
        RELAY,
        &[delivery_at(1, 50), delivery_at(2, 10)],
        range(0, 100),
        mark,
    );
    stage(
        &app,
        &route,
        OTHER,
        &[delivery_at(3, 30)],
        range(0, 100),
        mark,
    );
    stage(
        &app,
        &route,
        RELAY,
        &[delivery_at(4, 200)],
        range(101, 300),
        mark,
    );
    stage(
        &app,
        &group(2),
        RELAY,
        &[delivery_at(5, 40)],
        range(0, 100),
        mark,
    );

    let items = app.staged_recovery_items(&route, 10, 50).unwrap();

    assert_eq!(
        items
            .iter()
            .map(|item| (item.event_id[0], item.created_at))
            .collect::<Vec<_>>(),
        vec![(2, 10), (3, 30), (1, 50)]
    );
}
