//! The upgrade conversion (mdk#2660 phase 4, PR 5d) against two fixtures.
//!
//! The 0.14.0 fixture is an account database at schema 116, the last release
//! before the coverage ledger, holding the old owner's rows of every kind:
//! each cause, each state (pending, parked, dismissed, satisfied), and loss
//! evidence live with a known bound, retired and legacy-retired. The
//! nightly-shaped fixture holds the same kinds at the current schema with
//! phase 2's shadow ledger beside them: live-boundary, comparison and sweep
//! ranges, goals below the window, shadow remainders, the un-cover log,
//! released seconds and routed loss. Both are written as SQL, the way those
//! builds left the rows.

use super::convert::FAIL_STEP;
use super::*;
use crate::base::migrations::run_through;
use crate::{
    RecoveryConversionInput, RecoveryConversionRoute, RecoveryConvertedLoss,
    RecoveryConvertedObligations, RecoveryLossCause, RecoveryLossWatermark, RecoveryRelayCaps,
    RecoverySpanRetirement, RecoveryUnitBreak, RecoveryUnitOutcome, RecoveryUnitPolicy,
    RecoveryUnitState, SqlCipherHardening, SqlCipherKey, SqliteAccountStorage,
    TransportReconciliationRoute, open_hardened_sqlcipher,
};
use rusqlite::types::Value;

const KEY: &str = "mdk recovery conversion fixture key";
const NOW: u64 = 10_000_000;
/// The retained window's floor.
const W: u64 = NOW - 1_000_000;
const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB1; 32];
/// A route the account has left.
const C: [u8; 32] = [0xC1; 32];
const R1: &str = "wss://r1.example";
const R2: &str = "wss://r2.example";
/// How the old owner's scope plans spelled the same relays.
const PLAN_R1: &str = "wss://R1.example/";
const PLAN_R2: &str = "wss://R2.example/";

fn canonical(relay: &str) -> String {
    relay.trim_end_matches('/').to_ascii_lowercase()
}

fn group(id: [u8; 32]) -> TransportReconciliationRoute {
    TransportReconciliationRoute::Group(id)
}

fn routes() -> Vec<RecoveryConversionRoute> {
    vec![
        RecoveryConversionRoute {
            route: TransportReconciliationRoute::Inbox,
            required_relays: vec![R1.into(), R2.into()],
            standing_floor_seconds: W,
        },
        RecoveryConversionRoute {
            route: group(A),
            required_relays: vec![R1.into(), R2.into()],
            standing_floor_seconds: W,
        },
        // Joined recently: its standing goal starts at its Welcome.
        RecoveryConversionRoute {
            route: group(B),
            required_relays: vec![R2.into()],
            standing_floor_seconds: W + 20_000,
        },
    ]
}

fn convert(store: &SqliteAccountStorage) -> StorageResult<()> {
    let routes = routes();
    store
        .app_storage()
        .convert_recovery_obligations(&input(&routes))
}

fn input(routes: &[RecoveryConversionRoute]) -> RecoveryConversionInput<'_> {
    RecoveryConversionInput {
        routes,
        canonical_relay: &canonical,
        retention_floor_seconds: W,
        now_seconds: NOW,
    }
}

fn id(n: u8) -> String {
    format!("x'{n:032x}'")
}

fn hex32(id: [u8; 32]) -> String {
    format!("x'{}'", hex::encode(id))
}

/// A scope payload as the old owner froze it: these required relays, all
/// admitted, and a covered, exhaustive checkpoint on each of `covered`.
fn payload(required: &[&str], covered: &[&str], replay_admitted: bool) -> String {
    let checkpoints = covered
        .iter()
        .map(|endpoint| {
            serde_json::json!({
                "endpoint": endpoint, "outcome": "covered", "exhaustive": true,
                "admission_complete": true, "first_boundary": false,
            })
        })
        .collect::<Vec<_>>();
    let mut payload = serde_json::json!({
        "required_endpoints": required, "admitted_endpoints": required,
        "checkpoints": checkpoints, "retained_known_event": false, "attempt_serial": 1,
        "obligation_revision": 1, "loss_revision": 0, "route_revision": 0,
        "inventory_revision": 0,
    });
    if replay_admitted {
        payload["replay_admitted"] = true.into();
    }
    format!("CAST('{payload}' AS BLOB)")
}

/// One frozen scope row: route (`None` for the inbox), window and payload.
fn scope(
    obligation: u8,
    scope: u8,
    route: Option<([u8; 32], u8)>,
    window: (u64, u64),
    payload: &str,
) -> String {
    let (kind, group, transport) = match route {
        None => (0, "NULL".to_owned(), "NULL".to_owned()),
        Some((transport, group)) => (1, format!("x'{group:02x}'"), hex32(transport)),
    };
    format!(
        "INSERT INTO account_recovery_scopes (obligation_id, scope_id, route_kind, route_role,
            group_id, transport_group_id, since_seconds, until_seconds, snapshot_state,
            scope_format, scope_payload)
         VALUES ({}, {scope}, {kind}, 0, {group}, {transport}, {}, {}, 1, 1, {payload});",
        id(obligation),
        window.0,
        window.1,
    )
}

/// The rows every fixture shares, at schema 116: the account, two groups, and
/// the obligations the conversion leaves alone (epoch gaps pending and parked,
/// maintenance, a known event).
fn untouched_rows() -> String {
    format!(
        "INSERT INTO account_state (label, updated_at) VALUES ('alice', 0), ('bob', 0);
         INSERT INTO cgka_groups (id, epoch, record) VALUES (x'0a', 7, x'00'), (x'0b', 3, x'00');
         INSERT INTO account_recovery_obligations (id, demand_key, cause, group_id, stalled_epoch,
             predicate, created_at_ms, updated_at_ms, state, eligibility, parked_at_ms)
         VALUES ({}, 'epoch:0a', 1, x'0a', 7, 0, 1000, 2000, 0, 1, NULL),
                ({}, 'epoch:0b', 1, x'0b', 3, 0, 1000, 2000, 0, 4, 1500);
         INSERT INTO account_recovery_obligations (id, demand_key, cause, group_id, predicate,
             created_at_ms, updated_at_ms)
         VALUES ({}, 'maintenance:0a:01:2', 2, x'0a', 2, 1000, 1000),
                ({}, 'known:0b:{}', 4, x'0b', 1, 1000, 1000);
         {}",
        id(0xE1),
        id(0xE2),
        id(0xE3),
        id(0xE4),
        "ee".repeat(32),
        scope(
            0xE1,
            0,
            Some((A, 0x0A)),
            (W, NOW - 10),
            &payload(&[PLAN_R1], &[], false)
        ),
    )
}

/// The 0.14.0 rows: a pending queue loss bounded inside the window (beside a
/// retired and a legacy-retired generation), a parked notification loss, a
/// parked explicit repair that froze no scope, a dismissed incremental
/// history, a pending native replay, and another account's satisfied queue
/// loss whose evidence the plane acknowledged.
fn v0_14_0_rows() -> String {
    let mut sql = untouched_rows();
    sql.push_str(&format!(
        "INSERT INTO account_recovery_obligations (id, demand_key, cause, account_label,
             marker_token, pending_since, dropped_count, predicate, created_at_ms, updated_at_ms,
             state, eligibility, parked_at_ms, incomplete_reason)
         VALUES ({q}, 'overflow:alice', 0, 'alice', 7, 100, 3, 0, 1000, 3000, 0, 1, NULL, NULL),
                ({n}, 'notification:alice', 6, 'alice', 9, 100, 2, 0, 1000, 3000, 0, 4,
                 {n_parked}, NULL),
                ({b}, 'overflow:bob', 0, 'bob', 4, 100, 1, 0, 1000, 3000, 1, 0, NULL, NULL);
         INSERT INTO account_recovery_obligations (id, demand_key, cause, predicate, urgency,
             created_at_ms, updated_at_ms, state, eligibility, parked_at_ms, incomplete_reason,
             dismissed_scopes)
         VALUES ({x}, 'explicit:{op}', 3, 0, 1, 1000, 3000, 0, 4, {x_parked}, NULL, NULL),
                ({i}, 'incremental', 5, 0, 0, 1000, 3000, 2, 4, 2500, 0,
                 CAST('[]' AS BLOB)),
                ({r}, 'replay:{snapshot}', 7, 3, 0, 1000, 3000, 0, 1, NULL, NULL, NULL);
         INSERT INTO account_delivery_loss_evidence (account_label, cause, marker_token,
             pending_since, dropped_count, imported_count, legacy_retired_count, retired_count,
             bound_state, bound_seconds)
         VALUES ('alice', 0, 7, 100, 3, 3, NULL, NULL, 1, {q_bound}),
                ('alice', 0, 5, 90, 4, 4, NULL, 4, 1, {retired_bound}),
                ('alice', 0, 3, 80, 2, 2, 2, NULL, 2, NULL),
                ('alice', 1, 9, 100, 2, 2, NULL, NULL, 1, {n_bound});
         INSERT INTO account_recovery_scopes (obligation_id, scope_id) VALUES ({x}, 0);
         UPDATE account_recovery_comparison SET revision = 3, settled_revision = 2
             WHERE singleton = 1;
         {q_inbox}{q_a}{n_inbox}{n_b}{n_a}{i_a}{i_inbox}{r_b}",
        q = id(1),
        n = id(2),
        b = id(3),
        x = id(4),
        i = id(5),
        r = id(6),
        op = "11".repeat(16),
        snapshot = "22".repeat(32),
        n_parked = (NOW - 50_000) * 1000,
        x_parked = (NOW - 40_000) * 1000,
        q_bound = W + 500,
        retired_bound = W + 100,
        n_bound = W + 40_000,
        q_inbox = scope(
            1,
            0,
            None,
            (W + 500, NOW - 100),
            &payload(&[PLAN_R1], &[], false)
        ),
        q_a = scope(
            1,
            1,
            Some((A, 0x0A)),
            (W + 500, NOW - 100),
            &payload(&[PLAN_R1], &[], false)
        ),
        n_inbox = scope(
            2,
            0,
            None,
            (W + 40_000, NOW - 100),
            &payload(&[PLAN_R1, PLAN_R2], &[], false)
        ),
        n_b = scope(
            2,
            1,
            Some((B, 0x0B)),
            (W + 40_000, NOW - 100),
            &payload(&[PLAN_R2], &[], false)
        ),
        n_a = scope(
            2,
            2,
            Some((A, 0x0A)),
            (W + 40_000, NOW - 100),
            &payload(&[PLAN_R1], &[PLAN_R1], false)
        ),
        i_a = scope(
            5,
            0,
            Some((A, 0x0A)),
            (W - 1000, NOW - 10_000),
            &payload(&[PLAN_R1, PLAN_R2], &[], false)
        ),
        i_inbox = scope(
            5,
            1,
            None,
            (W - 1000, NOW - 10_000),
            &payload(&[PLAN_R1], &[PLAN_R1], false)
        ),
        r_b = scope(
            6,
            0,
            Some((B, 0x0B)),
            (NOW - 300, NOW - 100),
            &payload(&[PLAN_R2], &[], false)
        ),
    ));
    sql
}

/// The nightly rows: a dismissed queue loss with retired evidence, a pending
/// notification loss with one generation whose bound is unknown and one that
/// named its route, a satisfied explicit repair, a pending incremental history
/// holding the comparison slot, and a parked native replay; beside them the
/// shadow ledger.
fn nightly_rows() -> String {
    let mut sql = untouched_rows();
    sql.push_str(&format!(
        "INSERT INTO account_recovery_obligations (id, demand_key, cause, account_label,
             marker_token, pending_since, dropped_count, predicate, created_at_ms, updated_at_ms,
             state, eligibility, parked_at_ms, incomplete_reason)
         VALUES ({q}, 'overflow:alice', 0, 'alice', 11, 100, 5, 0, 1000, 3000, 2, 4, 2000, 0),
                ({n}, 'notification:alice', 6, 'alice', 21, 100, 2, 0, 1000, 3000, 0, 1,
                 NULL, NULL);
         INSERT INTO account_recovery_obligations (id, demand_key, cause, predicate,
             created_at_ms, updated_at_ms, state, eligibility, parked_at_ms)
         VALUES ({x}, 'explicit:{op}', 3, 0, 1000, 3000, 1, 0, NULL),
                ({i}, 'incremental', 5, 0, 1000, 3000, 0, 1, NULL),
                ({r}, 'replay:{snapshot}', 7, 3, 1000, {r_updated}, 0, 4, NULL);
         INSERT INTO account_delivery_loss_evidence (account_label, cause, marker_token,
             pending_since, dropped_count, imported_count, retired_count, bound_state,
             bound_seconds, route_state, import_revision)
         VALUES ('alice', 0, 11, 100, 5, 5, 5, 1, {q_bound}, 0, 1),
                ('alice', 1, 21, 100, 2, 1, NULL, 2, NULL, 0, 2),
                ('alice', 1, 20, 100, 3, 3, NULL, 1, {routed_bound}, 1, 2);
         INSERT INTO account_delivery_loss_evidence_routes (account_label, cause, marker_token,
             route_kind, route_id, bound_seconds)
         VALUES ('alice', 1, 20, 1, {a}, {routed_bound});
         INSERT INTO account_recovery_coverage (route_kind, route_id, relay, proof,
             since_seconds, until_seconds, recorded_at_seconds)
         VALUES (1, {a}, '{R1}', 1, {lb_since}, {lb_until}, 5),
                (1, {c}, '{R1}', 1, {lb_since}, {lb_until}, 5),
                (0, x'', '{R1}', 2, {W}, {cmp_until}, 6),
                (1, {b}, '{R2}', 3, {sweep_since}, {sweep_until}, 7);
         INSERT INTO account_recovery_coverage_goals (route_kind, route_id, since_seconds,
             settled_below_seconds)
         VALUES (0, x'', {strip}, {strip}), (1, {a}, {W}, {W}), (1, {c}, {W}, {W});
         INSERT INTO account_recovery_coverage_remainders (route_kind, route_id, since_seconds,
             until_seconds, park_revision, parked_at_seconds)
         VALUES (1, {a}, {rem_since}, {rem_until}, 1, 50), (1, {c}, {rem_since}, {rem_until}, 2, 50);
         UPDATE account_recovery_park_revision SET revision = 2 WHERE singleton = 1;
         INSERT INTO account_recovery_coverage_uncovers (generation, route_kind, route_id,
             since_seconds, until_seconds, recorded_at_seconds)
         VALUES (3, NULL, NULL, {W}, NULL, {uncovered_at});
         UPDATE account_recovery_coverage_uncover_state SET generation = 3, pruned_through = 2
             WHERE singleton = 1;
         INSERT INTO account_recovery_coverage_released (route_kind, route_id, second)
             VALUES (1, {a}, {released});
         UPDATE account_recovery_comparison SET revision = 3, settled_revision = 2
             WHERE singleton = 1;
         {q_inbox}{r_b}{x_inbox}",
        q = id(1),
        n = id(2),
        x = id(4),
        i = id(5),
        r = id(6),
        a = hex32(A),
        b = hex32(B),
        c = hex32(C),
        op = "33".repeat(16),
        snapshot = "44".repeat(32),
        r_updated = (NOW - 30_000) * 1000,
        q_bound = W + 100,
        routed_bound = W + 70_000,
        lb_since = W + 10,
        lb_until = NOW - 5,
        cmp_until = NOW - 1000,
        sweep_since = W - 500,
        sweep_until = W + 50,
        strip = W - 5000,
        rem_since = W - 9000,
        rem_until = W - 8000,
        uncovered_at = NOW - 10,
        released = NOW - 20,
        q_inbox = scope(1, 0, None, (W + 100, NOW - 2000), &payload(&[PLAN_R1], &[], false)),
        r_b = scope(6, 0, Some((B, 0x0B)), (NOW - 300, NOW - 100), &payload(&[PLAN_R2], &[], false)),
        x_inbox = scope(4, 0, None, (W, NOW - 100), &payload(&[PLAN_R1], &[PLAN_R1], false)),
    ));
    sql
}

/// Write an encrypted account database at `version` (the last migration
/// applied) holding `rows`, then open it through the production open path,
/// which migrates it to the current schema.
fn fixture(directory: &tempfile::TempDir, version: i64, rows: &str) -> SqliteAccountStorage {
    let path = directory.path().join("account.sqlite3");
    {
        let key = SqlCipherKey::new(KEY).unwrap();
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
        run_through(&mut conn, version).unwrap();
        conn.execute_batch(rows).unwrap();
    }
    reopen(directory)
}

fn reopen(directory: &tempfile::TempDir) -> SqliteAccountStorage {
    let key = SqlCipherKey::new(KEY).unwrap();
    SqliteAccountStorage::open_encrypted(directory.path().join("account.sqlite3"), &key).unwrap()
}

fn v0_14_0(directory: &tempfile::TempDir) -> SqliteAccountStorage {
    fixture(directory, 116, &v0_14_0_rows())
}

fn nightly(directory: &tempfile::TempDir) -> SqliteAccountStorage {
    fixture(directory, i64::MAX, &nightly_rows())
}

/// Every table the conversion reads or writes, row by row in a canonical
/// order, so two databases can be compared whole.
const TABLES: &[&str] = &[
    "account_recovery_obligations",
    "account_recovery_scopes",
    "account_recovery_comparison",
    "account_delivery_loss_evidence",
    "account_delivery_loss_evidence_routes",
    "account_recovery_coverage",
    "account_recovery_coverage_goals",
    "account_recovery_coverage_remainders",
    "account_recovery_coverage_uncovers",
    "account_recovery_coverage_uncover_state",
    "account_recovery_coverage_released",
    "account_recovery_units",
    "account_recovery_unit_spans",
    "account_recovery_park_revision",
    "account_recovery_conversion",
    "account_recovery_conversion_counts",
    "account_recovery_conversion_loss",
];

fn dump(store: &SqliteAccountStorage) -> Vec<(&'static str, Vec<Vec<Value>>)> {
    let conn = store.lock().unwrap();
    TABLES
        .iter()
        .map(|table| (*table, rows(&conn, &format!("SELECT * FROM {table}"))))
        .collect()
}

fn rows(conn: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = conn.prepare(sql).unwrap();
    let width = statement.column_count();
    let mut rows: Vec<Vec<Value>> = statement
        .query_map([], |row| (0..width).map(|index| row.get(index)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    rows.sort_by_cached_key(|row| format!("{row:?}"));
    rows
}

/// The obligations the conversion must leave as they were, with their scopes.
fn untouched(store: &SqliteAccountStorage) -> (Vec<Vec<Value>>, Vec<Vec<Value>>) {
    let conn = store.lock().unwrap();
    (
        rows(
            &conn,
            "SELECT * FROM account_recovery_obligations WHERE cause IN (1, 2, 4)",
        ),
        rows(
            &conn,
            "SELECT s.* FROM account_recovery_scopes s JOIN account_recovery_obligations o
             ON o.id = s.obligation_id WHERE o.cause IN (1, 2, 4)",
        ),
    )
}

fn causes(store: &SqliteAccountStorage) -> Vec<i64> {
    let conn = store.lock().unwrap();
    rows(&conn, "SELECT cause FROM account_recovery_obligations")
        .into_iter()
        .map(|row| match row[0] {
            Value::Integer(cause) => cause,
            _ => unreachable!(),
        })
        .collect()
}

fn scope_count(store: &SqliteAccountStorage) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM account_recovery_scopes s JOIN account_recovery_obligations o
             ON o.id = s.obligation_id WHERE o.cause IN (0, 3, 5, 6, 7)",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn orphan_scopes(store: &SqliteAccountStorage) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM account_recovery_scopes WHERE obligation_id NOT IN
             (SELECT id FROM account_recovery_obligations)",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn goal(store: &SqliteAccountStorage, route: &TransportReconciliationRoute) -> Option<u64> {
    store.app_storage().recovery_coverage_goal(route).unwrap()
}

fn range(since: u64, until: u64) -> crate::RecoveryCoverageRange {
    crate::RecoveryCoverageRange {
        since_seconds: since,
        until_seconds: until,
    }
}

fn counted(
    pending: u64,
    parked: u64,
    dismissed: u64,
    settled: u64,
) -> RecoveryConvertedObligations {
    RecoveryConvertedObligations {
        pending,
        parked,
        dismissed,
        settled,
    }
}

fn converted_loss(cause: RecoveryLossCause, watermarks: &[(u64, u64)]) -> RecoveryConvertedLoss {
    RecoveryConvertedLoss {
        account_label: "alice".into(),
        cause,
        watermarks: watermarks
            .iter()
            .map(|&(marker_token, observed_count)| RecoveryLossWatermark {
                marker_token,
                observed_count,
            })
            .collect(),
    }
}

fn evidence(store: &SqliteAccountStorage) -> Vec<Vec<Value>> {
    let conn = store.lock().unwrap();
    rows(
        &conn,
        "SELECT cause, marker_token, dropped_count, imported_count FROM account_delivery_loss_evidence",
    )
}

/// A 0.14.0 database: live loss inside the window, so the dismissal retires
/// the part below it and nothing parks into a remainder.
#[test]
fn a_v0_14_0_database_converts_every_row_kind() {
    let directory = tempfile::tempdir().unwrap();
    let store = v0_14_0(&directory);
    let app = store.app_storage();
    let untouched_before = untouched(&store);
    assert!(app.recovery_conversion_pending().unwrap());
    assert!(app.recovery_conversion_report().unwrap().is_none());

    convert(&store).unwrap();

    assert!(!app.recovery_conversion_pending().unwrap());
    // Epoch gaps, maintenance and known events are left with their scopes.
    assert_eq!(untouched(&store), untouched_before);
    let mut left = causes(&store);
    left.sort_unstable();
    assert_eq!(left, vec![1, 1, 2, 4]);
    assert_eq!(scope_count(&store), 0);
    assert_eq!(orphan_scopes(&store), 0);

    // Standing goals, then the live queue loss's bound inside the window
    // (W + 500), then the parked explicit repair's whole window.
    for route in [TransportReconciliationRoute::Inbox, group(A), group(B)] {
        assert_eq!(goal(&store, &route), Some(W));
    }
    assert!(app.recovery_coverage_remainders().unwrap().is_empty());
    assert_eq!(
        evidence(&store),
        vec![
            vec![
                Value::Integer(0),
                Value::Integer(3),
                Value::Integer(2),
                Value::Integer(2)
            ],
            vec![
                Value::Integer(0),
                Value::Integer(5),
                Value::Integer(4),
                Value::Integer(4)
            ],
            vec![
                Value::Integer(0),
                Value::Integer(7),
                Value::Integer(3),
                Value::Integer(3)
            ],
            vec![
                Value::Integer(1),
                Value::Integer(9),
                Value::Integer(2),
                Value::Integer(2)
            ],
        ]
    );

    // The dismissed incremental history could not certify group A on either
    // relay. Its window inside the retained window, below where live loss
    // reaches, stays retired; the certified inbox scope retires nothing. The
    // parked explicit repair parks the rest of group A on both relays.
    for relay in [R1, R2] {
        assert_eq!(
            app.recovery_unit_spans(&group(A), relay).unwrap(),
            vec![
                crate::RecoveryUnitSpan {
                    range: range(W, W + 499),
                    retired: Some(RecoverySpanRetirement::Dismissed),
                },
                crate::RecoveryUnitSpan {
                    range: range(W + 500, NOW),
                    retired: None,
                },
            ],
            "{relay}"
        );
    }

    // The parked notification loss could not certify the inbox and group B;
    // the parked explicit repair froze no scope, so it parks every route.
    // Each required relay owing history breaks, keeping the earliest park.
    let parked = app.parked_recovery_routes().unwrap();
    let parked_at = |route: &TransportReconciliationRoute| {
        parked
            .iter()
            .find(|parked| &parked.route == route)
            .map(|parked| (parked.parked_at_seconds, parked.relays.clone()))
    };
    assert_eq!(
        parked_at(&TransportReconciliationRoute::Inbox),
        Some((NOW - 50_000, vec![R1.to_owned(), R2.to_owned()]))
    );
    assert_eq!(
        parked_at(&group(A)),
        Some((NOW - 40_000, vec![R1.to_owned(), R2.to_owned()]))
    );
    assert_eq!(
        parked_at(&group(B)),
        Some((NOW - 50_000, vec![R2.to_owned()]))
    );
    let unit = app.recovery_unit(&group(A), R1).unwrap().unwrap();
    assert_eq!(
        unit.state,
        RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress)
    );

    // Converting the incremental history settled the comparison slot it held.
    assert!(!app.recovery_comparison().unwrap().pending());

    let report = app.recovery_conversion_report().unwrap().unwrap();
    assert_eq!(
        report.obligations,
        vec![
            (RecoveryCause::QueueLoss, counted(1, 0, 0, 1)),
            (RecoveryCause::ExplicitHistory, counted(0, 1, 0, 0)),
            (RecoveryCause::IncrementalHistory, counted(0, 0, 1, 0)),
            (RecoveryCause::NotificationLoss, counted(0, 1, 0, 0)),
            (RecoveryCause::SubscriptionReplay, counted(1, 0, 0, 0)),
        ]
    );
    assert!(
        report.loss
            == vec![
                // The retired and legacy-retired generations go with the live
                // one: acknowledgment reclaims a cause's evidence whole.
                converted_loss(RecoveryLossCause::Queue, &[(3, 2), (5, 4), (7, 3)]),
                converted_loss(RecoveryLossCause::NotificationConsumer, &[(9, 2)]),
            ]
    );
    assert_eq!((report.shadow_ranges, report.shadow_remainders), (0, 0));
    assert_eq!(report.units_broken, 5);
    assert!(app.recovery_conversion_notices_changed().unwrap());
    app.acknowledge_recovery_conversion_report().unwrap();
    app.acknowledge_recovery_conversion_notices().unwrap();
    assert!(app.recovery_conversion_report().unwrap().is_none());
    assert!(!app.recovery_conversion_notices_changed().unwrap());

    // Nothing became coverage.
    for route in [TransportReconciliationRoute::Inbox, group(A), group(B)] {
        for relay in [R1, R2] {
            assert!(
                app.recovery_coverage_ranges(&route, relay)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

/// A nightly database: the shadow ledger is quarantined, and live loss with
/// an unknown bound un-covers every route from the window floor and parks the
/// rest into remainders.
#[test]
fn a_nightly_database_quarantines_the_shadow_ledger_and_converts_every_row_kind() {
    let directory = tempfile::tempdir().unwrap();
    let store = nightly(&directory);
    let app = store.app_storage();
    let untouched_before = untouched(&store);

    convert(&store).unwrap();

    assert!(!app.recovery_conversion_pending().unwrap());
    assert_eq!(untouched(&store), untouched_before);
    assert_eq!(scope_count(&store), 0);
    assert_eq!(orphan_scopes(&store), 0);

    // Live boundaries are dropped; the unknown bound un-covers the comparison
    // range and the sweep, below the window floor too.
    let ledger = |route: &TransportReconciliationRoute, relay: &str| {
        app.recovery_coverage_ranges(route, relay)
            .unwrap()
            .into_iter()
            .map(|proved| (proved.range, proved.proof))
            .collect::<Vec<_>>()
    };
    assert!(ledger(&group(A), R1).is_empty());
    assert!(ledger(&group(C), R1).is_empty());
    assert!(ledger(&TransportReconciliationRoute::Inbox, R1).is_empty());
    assert!(ledger(&group(B), R2).is_empty());

    // The shadow strip below the window was settled, not parked; every
    // current route owes from the window floor, a route the account left
    // keeps its own goal.
    for route in [TransportReconciliationRoute::Inbox, group(A), group(B)] {
        assert_eq!(goal(&store, &route), Some(W));
    }
    assert_eq!(goal(&store, &group(C)), Some(W));

    // The unknown bound parks everything below the window on each current
    // route, whatever the sweep proved there before the loss. Shadow
    // remainders are gone.
    let remainders = app
        .recovery_coverage_remainders()
        .unwrap()
        .into_iter()
        .map(|remainder| {
            (
                remainder.route,
                remainder.range,
                remainder.revision,
                remainder.parked_at_seconds,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        remainders,
        vec![
            (TransportReconciliationRoute::Inbox, range(0, W - 1), 3, NOW),
            (group(A), range(0, W - 1), 4, NOW),
            (group(B), range(0, W - 1), 5, NOW),
        ]
    );

    // The un-cover is logged once, for every route, from the unknown bound.
    {
        let conn = store.lock().unwrap();
        let logged = rows(
            &conn,
            "SELECT generation, route_kind, since_seconds, until_seconds
             FROM account_recovery_coverage_uncovers ORDER BY generation",
        );
        assert_eq!(
            logged.last().unwrap(),
            &vec![
                Value::Integer(4),
                Value::Null,
                Value::Integer(0),
                Value::Null
            ]
        );
    }

    // The dismissed queue loss's window lies above where live loss reaches
    // (the window floor), so nothing of it stays retired.
    assert!(
        app.recovery_unit_spans(&TransportReconciliationRoute::Inbox, R1)
            .unwrap()
            .is_empty()
    );

    // The parked native replay could not certify group B: its relay breaks,
    // parked at the time the row last changed.
    let parked = app.parked_recovery_routes().unwrap();
    assert_eq!(parked.len(), 1);
    assert_eq!(
        (&parked[0].route, &parked[0].relays),
        (&group(B), &vec![R2.to_owned()])
    );
    let unit = app.recovery_unit(&group(B), R2).unwrap().unwrap();
    assert_eq!(
        unit.park
            .map(|park| (park.revision, park.parked_at_seconds)),
        Some((5, NOW - 30_000)),
        "the route's remainder revision: one notice for the route"
    );

    // Both live generations count as imported; the retired one is unchanged.
    assert_eq!(
        evidence(&store),
        vec![
            vec![
                Value::Integer(0),
                Value::Integer(11),
                Value::Integer(5),
                Value::Integer(5)
            ],
            vec![
                Value::Integer(1),
                Value::Integer(20),
                Value::Integer(3),
                Value::Integer(3)
            ],
            vec![
                Value::Integer(1),
                Value::Integer(21),
                Value::Integer(2),
                Value::Integer(2)
            ],
        ]
    );
    assert!(!app.recovery_comparison().unwrap().pending());

    let report = app.recovery_conversion_report().unwrap().unwrap();
    assert_eq!(
        report.obligations,
        vec![
            (RecoveryCause::QueueLoss, counted(0, 0, 1, 0)),
            (RecoveryCause::ExplicitHistory, counted(0, 0, 0, 1)),
            (RecoveryCause::IncrementalHistory, counted(1, 0, 0, 0)),
            (RecoveryCause::NotificationLoss, counted(1, 0, 0, 0)),
            (RecoveryCause::SubscriptionReplay, counted(0, 1, 0, 0)),
        ]
    );
    assert!(
        report.loss
            == vec![
                // Queue loss was all retired: the plane guards none of it.
                converted_loss(RecoveryLossCause::NotificationConsumer, &[(20, 3), (21, 2)]),
            ]
    );
    assert_eq!((report.shadow_ranges, report.shadow_remainders), (2, 2));
    assert_eq!(report.units_broken, 1);
    assert!(app.recovery_conversion_notices_changed().unwrap());
}

/// A crash inside any step leaves exactly what the steps before it wrote,
/// and the next run ends where an uninterrupted conversion does.
fn a_crash_at_each_step_resumes_to_the_same_result(
    build: fn(&tempfile::TempDir) -> SqliteAccountStorage,
) {
    let routes = routes();
    // What each step starts from, stepping one transaction at a time.
    let (starts, reference) = {
        let directory = tempfile::tempdir().unwrap();
        let store = build(&directory);
        let mut starts = Vec::new();
        for _ in 0..6 {
            starts.push(dump(&store));
            store
                .app_storage()
                .convert_recovery_steps(&input(&routes), 1)
                .unwrap();
        }
        assert!(!store.app_storage().recovery_conversion_pending().unwrap());
        (starts, dump(&store))
    };
    {
        let directory = tempfile::tempdir().unwrap();
        let store = build(&directory);
        convert(&store).unwrap();
        assert_eq!(dump(&store), reference, "one run equals one step at a time");
    }
    for (step, start) in starts.iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        let store = build(&directory);
        FAIL_STEP.set(Some(step));
        let crashed = convert(&store);
        FAIL_STEP.set(None);
        assert!(crashed.is_err(), "step {step}");
        assert_eq!(&dump(&store), start, "step {step} rolled back whole");
        assert!(store.app_storage().recovery_conversion_pending().unwrap());
        // The next process resumes from the marker.
        drop(store);
        let store = reopen(&directory);
        convert(&store).unwrap();
        assert_eq!(dump(&store), reference, "resumed after step {step}");
    }
}

#[test]
fn a_crash_converting_a_v0_14_0_database_resumes_to_the_same_result() {
    a_crash_at_each_step_resumes_to_the_same_result(v0_14_0);
}

#[test]
fn a_crash_converting_a_nightly_database_resumes_to_the_same_result() {
    a_crash_at_each_step_resumes_to_the_same_result(nightly);
}

/// A finished conversion does nothing when run again, even after its report
/// and notice change were acknowledged and the ledger moved on.
#[test]
fn running_the_conversion_twice_changes_nothing() {
    for build in [
        v0_14_0 as fn(&tempfile::TempDir) -> SqliteAccountStorage,
        nightly,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = build(&directory);
        convert(&store).unwrap();
        let once = dump(&store);
        convert(&store).unwrap();
        assert_eq!(dump(&store), once);

        let app = store.app_storage();
        app.acknowledge_recovery_conversion_report().unwrap();
        app.acknowledge_recovery_conversion_notices().unwrap();
        app.request_recovery(RecoveryRequest::IncrementalHistory, NOW * 1000)
            .unwrap();
        let acknowledged = dump(&store);
        convert(&store).unwrap();
        assert_eq!(dump(&store), acknowledged);
        assert!(app.recovery_conversion_report().unwrap().is_none());
    }
}

/// A pending explicit repair becomes the runner's re-arm, after every other
/// step: parked relays are active again and dismissed ranges owed again.
#[test]
fn a_pending_explicit_repair_rearms_every_unit_last() {
    let directory = tempfile::tempdir().unwrap();
    let mut rows = v0_14_0_rows();
    rows.push_str(&format!(
        "UPDATE account_recovery_obligations SET eligibility = 0, parked_at_ms = NULL
         WHERE id = {};",
        id(4)
    ));
    let store = fixture(&directory, 116, &rows);
    let app = store.app_storage();
    convert(&store).unwrap();

    let parked = app.parked_recovery_routes().unwrap();
    assert!(parked.is_empty(), "the re-arm ended every park");
    for route in [TransportReconciliationRoute::Inbox, group(A), group(B)] {
        assert_eq!(goal(&store, &route), Some(W));
        for relay in [R1, R2] {
            assert!(app.recovery_unit_spans(&route, relay).unwrap().is_empty());
            if let Some(unit) = app.recovery_unit(&route, relay).unwrap() {
                assert_eq!(unit.state, RecoveryUnitState::Active);
                assert_eq!(unit.recheck.completed_at_seconds, None);
            }
        }
    }
    let report = app.recovery_conversion_report().unwrap().unwrap();
    assert_eq!(
        report.obligations[1],
        (RecoveryCause::ExplicitHistory, counted(1, 0, 0, 0))
    );
}

/// Input the conversion cannot trust changes nothing: routing without the
/// inbox (not hydrated), a duplicate route, an empty relay, or a floor
/// after now.
#[test]
fn invalid_input_converts_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let store = v0_14_0(&directory);
    let before = dump(&store);
    let mut duplicate = routes();
    duplicate.push(duplicate[1].clone());
    let mut empty_relay = routes();
    empty_relay[0].required_relays.push(String::new());
    let without_inbox = routes()[1..].to_vec();
    for routes in [duplicate, empty_relay, without_inbox] {
        assert!(
            store
                .app_storage()
                .convert_recovery_obligations(&input(&routes))
                .is_err()
        );
    }
    let routes = routes();
    let mut late_floor = input(&routes);
    late_floor.retention_floor_seconds = NOW + 1;
    assert!(
        store
            .app_storage()
            .convert_recovery_obligations(&late_floor)
            .is_err()
    );
    assert_eq!(dump(&store), before);
}

/// The quarantine settles every goal at the window floor before loss runs, so
/// only loss parks below it: a 0.14.0 database whose live loss has an unknown
/// bound ends with each current route's remainder, and one without live loss
/// ends with none.
#[test]
fn only_loss_parks_below_the_window_floor() {
    let unknown_bound = format!(
        "{}UPDATE account_delivery_loss_evidence SET bound_state = 2, bound_seconds = NULL
         WHERE cause = 1 AND marker_token = 9;",
        v0_14_0_rows()
    );
    let no_live_loss = format!(
        "{}UPDATE account_delivery_loss_evidence SET retired_count = dropped_count;",
        v0_14_0_rows()
    );
    for (rows, parked) in [(unknown_bound, true), (no_live_loss, false)] {
        let directory = tempfile::tempdir().unwrap();
        let store = fixture(&directory, 116, &rows);
        convert(&store).unwrap();
        let remainders = store
            .app_storage()
            .recovery_coverage_remainders()
            .unwrap()
            .into_iter()
            .map(|remainder| (remainder.route, remainder.range))
            .collect::<Vec<_>>();
        let expected = if parked {
            vec![
                (TransportReconciliationRoute::Inbox, range(0, W - 1)),
                (group(A), range(0, W - 1)),
                (group(B), range(0, W - 1)),
            ]
        } else {
            Vec::new()
        };
        assert_eq!(remainders, expected, "parked: {parked}");
        for route in [TransportReconciliationRoute::Inbox, group(A), group(B)] {
            assert_eq!(goal(&store, &route), Some(W));
        }
    }
}

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

/// A converted park is planned with unknown caps, as the old owner never read
/// any. Its notice takes a new id at conversion; an unknown caps read leaves
/// it; the relay's first known read re-arms it and clears the notice, while a
/// relay whose caps stay unknown keeps its park; and a runner that then gets
/// nowhere parks it again under a newer notice.
#[test]
fn a_converted_park_rearms_once_on_known_caps_and_parks_again_without_progress() {
    let directory = tempfile::tempdir().unwrap();
    let store = v0_14_0(&directory);
    let app = store.app_storage();
    convert(&store).unwrap();
    let notices = |app: &SqliteAppStorage| {
        app.parked_recovery_routes()
            .unwrap()
            .into_iter()
            .map(|parked| (parked.route, parked.revision, parked.relays))
            .collect::<Vec<_>>()
    };
    let converted = notices(&app);
    assert_eq!(converted.len(), 3);
    let highest = converted
        .iter()
        .map(|(_, revision, _)| *revision)
        .max()
        .unwrap();

    for relay in [R1, R2] {
        assert_eq!(app.record_recovery_relay_caps(relay, None, NOW).unwrap(), 0);
    }
    assert_eq!(notices(&app), converted, "an unknown read is no evidence");

    let caps = RecoveryRelayCaps {
        max_limit: Some(500),
        negentropy: false,
    };
    assert_eq!(
        app.record_recovery_relay_caps(R2, Some(caps), NOW + 1)
            .unwrap(),
        3,
        "the inbox, group A and group B on the relay that answered"
    );
    let rearmed = notices(&app);
    let keep_r1 = |route: TransportReconciliationRoute| {
        let (_, revision, _) = converted
            .iter()
            .find(|(parked, ..)| *parked == route)
            .unwrap();
        (route, *revision, vec![R1.to_owned()])
    };
    assert_eq!(
        rearmed,
        vec![
            keep_r1(TransportReconciliationRoute::Inbox),
            keep_r1(group(A))
        ],
        "group B's notice cleared; R1's caps are still unknown"
    );
    assert_eq!(
        app.recovery_unit(&group(B), R2).unwrap().unwrap().state,
        RecoveryUnitState::Active
    );

    for _ in 0..POLICY.break_after_no_progress {
        app.begin_recovery_unit_attempt(&group(B), R2, Some(caps), NOW + 2)
            .unwrap();
        app.settle_recovery_unit(
            &group(B),
            R2,
            RecoveryUnitOutcome::NoProgress,
            &POLICY,
            NOW + 2,
        )
        .unwrap();
    }
    let unit = app.recovery_unit(&group(B), R2).unwrap().unwrap();
    assert_eq!(
        unit.state,
        RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress)
    );
    let park = unit.park.unwrap();
    assert!(park.revision > highest, "a newer notice");
    assert_eq!(park.parked_at_seconds, NOW + 2);
    assert!(
        notices(&app)
            .iter()
            .any(|(route, revision, _)| *route == group(B) && *revision == park.revision)
    );
    // Planned with the caps it read, the new park waits for different ones.
    assert_eq!(
        app.record_recovery_relay_caps(R2, Some(caps), NOW + 3)
            .unwrap(),
        0
    );
}

/// Converted loss evidence stays until the worker reclaims it at exactly the
/// watermarks the report gave, and never while the conversion runs or after
/// new loss of that cause arrived.
#[test]
fn converted_loss_is_reclaimed_only_at_its_exact_watermarks() {
    let directory = tempfile::tempdir().unwrap();
    let store = v0_14_0(&directory);
    let app = store.app_storage();
    let queue = converted_loss(RecoveryLossCause::Queue, &[(3, 2), (5, 4), (7, 3)]);
    let notification = converted_loss(RecoveryLossCause::NotificationConsumer, &[(9, 2)]);
    let routes = routes();
    // Through the loss step only.
    app.convert_recovery_steps(&input(&routes), 3).unwrap();
    assert!(!app.reclaim_converted_recovery_loss(&notification).unwrap());
    convert(&store).unwrap();
    let report = app.recovery_conversion_report().unwrap().unwrap();
    assert!(report.loss == vec![queue.clone(), notification.clone()]);

    // New queue loss after the conversion changes that cause's set.
    app.record_account_recovery_loss_bounded(
        "alice",
        RecoveryLossCause::Queue,
        8,
        1,
        NOW,
        Some(NOW - 5),
    )
    .unwrap();
    assert!(!app.reclaim_converted_recovery_loss(&queue).unwrap());
    let mut stale = notification.clone();
    stale.watermarks[0].observed_count = 1;
    assert!(!app.reclaim_converted_recovery_loss(&stale).unwrap());

    assert!(app.reclaim_converted_recovery_loss(&notification).unwrap());
    let causes = evidence(&store)
        .into_iter()
        .map(|row| (row[0].clone(), row[1].clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        causes,
        [3, 5, 7, 8]
            .map(|token| (Value::Integer(0), Value::Integer(token)))
            .to_vec(),
        "queue evidence, with the new generation, stays"
    );
    assert!(!app.reclaim_converted_recovery_loss(&notification).unwrap());
}

/// Loss bounded below the window parks the whole strip from its bound up to
/// the window floor, as a live import and the next prune would: coverage that
/// proved part of it before the loss does not shrink the remainder.
#[test]
fn loss_below_the_window_parks_what_old_coverage_proved() {
    let rows = format!(
        "{}UPDATE account_delivery_loss_evidence SET bound_state = 1, bound_seconds = {bound}
             WHERE cause = 1 AND marker_token = 21;
         INSERT INTO account_recovery_coverage (route_kind, route_id, relay, proof,
             since_seconds, until_seconds, recorded_at_seconds)
         VALUES (0, x'', '{R1}', 3, {bound}, {below}, 6), (0, x'', '{R2}', 2, {bound}, {below}, 6);",
        nightly_rows(),
        bound = W - 1000,
        below = W - 1,
    );
    let directory = tempfile::tempdir().unwrap();
    let store = fixture(&directory, i64::MAX, &rows);
    let app = store.app_storage();
    convert(&store).unwrap();
    for relay in [R1, R2] {
        assert!(
            app.recovery_coverage_ranges(&TransportReconciliationRoute::Inbox, relay)
                .unwrap()
                .is_empty(),
            "{relay}"
        );
    }
    let remainders = app
        .recovery_coverage_remainders()
        .unwrap()
        .into_iter()
        .map(|remainder| (remainder.route, remainder.range))
        .collect::<Vec<_>>();
    assert_eq!(
        remainders,
        [TransportReconciliationRoute::Inbox, group(A), group(B)]
            .map(|route| (route, range(W - 1000, W - 1)))
            .to_vec()
    );
}
