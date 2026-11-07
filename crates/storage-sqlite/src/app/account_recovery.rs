//! The old recovery owner's account-private tables (mdk#2660 phase 4). The
//! account-open conversion reads them, the recovery runner serves the
//! epoch-gap obligations that stay, and the narrow loss writer appends
//! monotonically increasing evidence that the runner imports into the
//! coverage ledger.
mod convert;
#[cfg(test)]
pub(crate) use convert::{finish_conversion_for_test, import_loss_for_test};
#[cfg(test)]
mod convert_tests;
pub use convert::{
    RecoveryConversionInput, RecoveryConversionReport, RecoveryConversionRoute,
    RecoveryConvertedLoss, RecoveryConvertedObligations,
};
mod demand;
pub use demand::{RecoveryCause, RecoveryDemand, RecoveryDemandTicket, RecoveryPredicate};
mod loss;
mod notice;
mod plan;
pub use loss::{
    MAX_LOSS_ROUTES, RecoveryLossCause, RecoveryLossReach, RecoveryLossSnapshot,
    RecoveryLossWatermark,
};
pub use notice::ParkedRecoveryObligation;
pub use plan::RecoveryEligibility;

#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};

fn sqlite_integer(value: u64) -> StorageResult<i64> {
    i64::try_from(value)
        .map_err(|_| StorageError::Serialization("recovery value outside supported range".into()))
}

/// Delete inventory and void only the old owner's frozen scopes whose
/// route/window (and, for a known-event predicate, exact event) overlap the
/// removed input, so the account-open conversion never counts removed input
/// as coverage. Callers must already own the surrounding transaction.
/// Predicates are internal SQL.
pub(crate) fn delete_inventory_tx(
    conn: &Connection,
    predicate: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> StorageResult<usize> {
    // This indexed no-op probe never reads the recovery tables. Ordinary live
    // admission stays independent of the number of retained recovery scopes.
    if conn
        .query_row_cached(
            &format!("SELECT 1 FROM transport_reconciliation_items WHERE {predicate}"),
            parameters,
            |_| Ok(()),
        )
        .optional()
        .storage()?
        .is_none()
    {
        return Ok(0);
    }
    let removed = conn
        .prepare_cached(&format!(
            "DELETE FROM transport_reconciliation_items WHERE {predicate}
        RETURNING route_kind,route_id,event_id,created_at"
        ))
        .storage()?
        .query_map(parameters, |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let count = removed.len();
    let mut routes = std::collections::BTreeMap::<_, Vec<_>>::new();
    for (kind, route, event, at) in removed {
        routes.entry((kind, route)).or_default().push((at, event));
    }
    for items in routes.values_mut() {
        items.sort_unstable();
    }
    let rows=conn.prepare_cached("SELECT s.obligation_id,s.scope_id,s.scope_format,s.scope_payload,
        s.route_kind,COALESCE(s.transport_group_id,x''),COALESCE(s.since_seconds,0),s.until_seconds,s.known_event_id,o.predicate
        FROM account_recovery_scopes s JOIN account_recovery_obligations o ON o.id=s.obligation_id
        WHERE s.snapshot_state=1 AND o.predicate!=2").storage()?
        .query_map([],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,Vec<u8>>(3)?,
            r.get::<_,i64>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,i64>(6)?,r.get::<_,i64>(7)?,r.get::<_,Option<Vec<u8>>>(8)?,r.get::<_,i64>(9)?)))
        .storage()?.collect::<Result<Vec<_>,_>>().storage()?;
    let mut affected = std::collections::BTreeSet::new();
    for (id, scope, format, payload, kind, route, since, until, known, predicate) in rows {
        let Some(items) = routes.get(&(kind, route)) else {
            continue;
        };
        let lower = items.partition_point(|(at, _)| *at < since);
        let upper = items.partition_point(|(at, _)| *at <= until);
        if lower == upper
            || (predicate == 1
                && !items[lower..upper]
                    .iter()
                    .any(|(_, event)| known.as_ref() == Some(event)))
        {
            continue;
        }
        conn.execute_cached(
            "UPDATE account_recovery_scopes SET scope_revision=scope_revision+1,scope_payload=?3
            WHERE obligation_id=?1 AND scope_id=?2",
            params![
                id,
                scope,
                plan::invalidate_retained_scope(format, &payload)?
            ],
        )
        .storage()?;
        affected.insert(id);
    }
    for id in affected {
        reopen_invalidated_obligation_tx(conn, &id)?;
    }
    Ok(count)
}

fn reopen_invalidated_obligation_tx(conn: &Connection, id: &[u8]) -> StorageResult<()> {
    let (state, predicate) = conn
        .query_row_cached(
            "SELECT state,predicate FROM account_recovery_obligations WHERE id=?1",
            [id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .storage()?;
    if state == 1 && !plan::retained_predicate_qualifies(conn, id, predicate)? {
        conn.execute_cached("UPDATE account_recovery_obligations SET state=0,eligibility=1,revision=revision+1 WHERE id=?1",[id]).storage()?;
    }
    Ok(())
}

/// Released receipt journals may outlive their inventory rows and contain no
/// trustworthy route/time bound. Keep conservative invalidation for that case.
/// Maintenance's observed session boundary is independent of retained inventory.
pub(crate) fn invalidate_inventory_tx(conn: &Connection) -> StorageResult<()> {
    let rows = conn.prepare_cached(
        "SELECT s.obligation_id,s.scope_id,s.scope_format,s.scope_payload FROM account_recovery_scopes s
         JOIN account_recovery_obligations o ON o.id=s.obligation_id WHERE s.snapshot_state=1 AND o.predicate!=2",
    ).storage()?.query_map([], |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,i64>(1)?,
        row.get::<_,i64>(2)?,row.get::<_,Vec<u8>>(3)?))).storage()?
        .collect::<Result<Vec<_>,_>>().storage()?;
    let mut affected = std::collections::BTreeSet::new();
    for (id, scope, format, payload) in rows {
        conn.execute_cached(
            "UPDATE account_recovery_scopes SET scope_revision=scope_revision+1,scope_payload=?3 WHERE obligation_id=?1 AND scope_id=?2",
            params![id,scope,plan::invalidate_retained_scope(format,&payload)?],
        ).storage()?;
        affected.insert(id);
    }
    for id in affected {
        reopen_invalidated_obligation_tx(conn, &id)?;
    }
    Ok(())
}

fn milliseconds(seconds: i64) -> StorageResult<i64> {
    seconds
        .checked_mul(1000)
        .filter(|value| *value >= 0)
        .ok_or_else(|| {
            StorageError::Serialization("recovery timestamp outside supported range".into())
        })
}

pub(crate) fn arm_epoch_tx(
    conn: &Connection,
    group: &[u8],
    epoch: i64,
    now: i64,
) -> StorageResult<()> {
    join_epoch_tx(conn, group, epoch, now, false)
}

pub(crate) fn arm_released_epoch_tx(
    conn: &Connection,
    group: &[u8],
    epoch: i64,
    now: i64,
) -> StorageResult<()> {
    join_epoch_tx(conn, group, epoch, now, true)
}

fn join_epoch_tx(
    conn: &Connection,
    group: &[u8],
    epoch: i64,
    now: i64,
    released_input: bool,
) -> StorageResult<()> {
    let key = format!("epoch:{}", hex::encode(group));
    conn.execute_cached(
        "INSERT INTO account_recovery_obligations
         (demand_key, cause, group_id, stalled_epoch, created_at_ms, updated_at_ms)
         VALUES (?1, 1, ?2, ?3, ?4, ?4)
         ON CONFLICT(demand_key) DO UPDATE SET
             stalled_epoch = MAX(stalled_epoch, excluded.stalled_epoch),
             revision = revision + 1, state = 0, eligibility = 0, incomplete_reason = NULL,
             updated_at_ms = excluded.updated_at_ms
         WHERE excluded.stalled_epoch > stalled_epoch OR ?5",
        params![key, group, epoch, milliseconds(now)?, released_input],
    )
    .storage()?;
    conn.execute_cached(
        "INSERT OR IGNORE INTO account_recovery_scopes(obligation_id, scope_id, group_id)
         SELECT id, 0, group_id FROM account_recovery_obligations WHERE demand_key = ?1",
        [key],
    )
    .storage()?;
    Ok(())
}

/// Merges one charge into a generation's `created_at` bound: a running
/// minimum while every charge is known, and unknown for good once one is not.
/// SQLite evaluates each assignment against the row before the update.
pub(crate) const LOSS_BOUND_MERGE: &str = "
    bound_state = CASE WHEN bound_state = 1 AND excluded.bound_state = 1 THEN 1 ELSE 2 END,
    bound_seconds = CASE WHEN bound_state = 1 AND excluded.bound_state = 1
        THEN MIN(bound_seconds, excluded.bound_seconds) END";

pub(crate) fn loss_bound_values(
    earliest_created_at: Option<u64>,
) -> StorageResult<(i64, Option<i64>)> {
    Ok(match earliest_created_at {
        Some(seconds) => (1, Some(sqlite_integer(seconds)?)),
        None => (2, None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TRANSPORT_RECONCILIATION_RETENTION_SECS, TransportReconciliationItem,
        TransportReconciliationRoute,
    };

    fn fixture() -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .app_storage()
            .ensure_account_projection("alice")
            .unwrap();
        store
    }

    /// Panics unless `result` failed with a backend error containing `text`,
    /// such as an injected trigger's message.
    #[track_caller]
    pub(super) fn assert_backend<T>(result: StorageResult<T>, text: &str) {
        match result.map(|_| ()) {
            Err(StorageError::Backend(message)) if message.contains(text) => {}
            other => panic!("expected a backend error containing {text:?}, got {other:?}"),
        }
    }

    /// Panics unless `result` failed with exactly the serialization error
    /// `text` a guard raises.
    #[track_caller]
    pub(super) fn assert_serialization<T>(result: StorageResult<T>, text: &str) {
        match result.map(|_| ()) {
            Err(StorageError::Serialization(message)) if message == text => {}
            other => panic!("expected the serialization error {text:?}, got {other:?}"),
        }
    }

    /// Every obligation's (cause, state, eligibility, revision), in id order.
    fn obligations(store: &SqliteAccountStorage) -> Vec<(i64, i64, i64, i64)> {
        store
            .lock()
            .unwrap()
            .prepare("SELECT cause, state, eligibility, revision FROM account_recovery_obligations ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn duplicate_and_stale_epoch_observations_preserve_quiescence() {
        let store = fixture();
        let app = store.app_storage();
        store
            .lock()
            .unwrap()
            .execute_batch("INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 7, x'00')")
            .unwrap();
        let arm = |epoch| {
            app.arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
                group_id_hex: "01".into(),
                stalled_epoch: epoch,
            }])
            .unwrap()
        };
        arm(7);
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET eligibility = 3")
            .unwrap();
        let before = obligations(&store);
        arm(7);
        arm(6);
        assert_eq!(obligations(&store), before, "nothing new to recover");
        arm(8);
        let (_, state, eligibility, revision) = obligations(&store)[0];
        assert_eq!(state, 0);
        assert!(matches!(eligibility, 0 | 1), "a higher epoch rearms");
        assert!(revision > before[0].3);
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET state = 1")
            .unwrap();
        arm(8);
        assert_eq!(
            obligations(&store)[0].1,
            1,
            "the same epoch reopens nothing"
        );
    }

    #[test]
    fn same_epoch_release_rearms_its_gap_and_rolls_back_as_one_unit() {
        let store = fixture();
        let app = store.app_storage();
        store
            .lock()
            .unwrap()
            .execute_batch("INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 7, x'00')")
            .unwrap();
        app.arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
            group_id_hex: "01".into(),
            stalled_epoch: 7,
        }])
        .unwrap();
        let before = obligations(&store);
        store
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO cgka_released_transport_receipts(id,group_id,epoch) VALUES (x'02', x'01', 7);
             CREATE TRIGGER fail_release_ack BEFORE DELETE ON cgka_released_transport_receipts
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert_backend(store.consume_released_transport_receipts(), "injected");
        assert_eq!(obligations(&store), before);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_release_ack")
            .unwrap();
        assert_eq!(
            store.consume_released_transport_receipts().unwrap().len(),
            1
        );
        let after = obligations(&store);
        assert_eq!(after[0].3, before[0].3 + 1, "the release rearms the gap");
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert_eq!(obligations(&store), after);
    }

    /// A frozen scope payload as the old owner wrote it: relays `a` and `b`
    /// required and admitted, each checkpointed covered, exhaustive and past
    /// the maintenance boundary.
    fn certified() -> String {
        let checkpoint = |endpoint: &str| {
            serde_json::json!({
                "endpoint": endpoint, "outcome": "covered", "exhaustive": true,
                "admission_complete": true, "first_boundary": true,
            })
        };
        let payload = serde_json::json!({
            "required_endpoints": ["a", "b"], "admitted_endpoints": ["a", "b"],
            "checkpoints": [checkpoint("a"), checkpoint("b")],
            "retained_known_event": false, "attempt_serial": 1, "obligation_revision": 1,
            "loss_revision": 0, "route_revision": 0, "inventory_revision": 0,
        });
        format!("CAST('{payload}' AS BLOB)")
    }

    /// Obligation `n` of `cause` and `predicate`, satisfied, with `scopes`
    /// certified inbox scopes over `since..=until`, as a build from before
    /// the recovery runner left it for the conversion to read.
    fn seed_satisfied(
        store: &SqliteAccountStorage,
        n: u8,
        (cause, predicate): (i64, i64),
        (since, until): (u64, u64),
        scopes: u64,
    ) {
        let group = if cause == 2 { "x'0a'" } else { "NULL" };
        let conn = store.lock().unwrap();
        conn.execute_batch(&format!(
            "INSERT OR IGNORE INTO cgka_groups (id, epoch, record) VALUES (x'0a', 1, x'00');
             INSERT INTO account_recovery_obligations (id, demand_key, cause, group_id,
                 predicate, created_at_ms, updated_at_ms, state)
             VALUES (x'{n:032x}', 'seed:{n}', {cause}, {group}, {predicate}, 0, 0, 1);"
        ))
        .unwrap();
        conn.execute(
            &format!(
                "WITH RECURSIVE n(x) AS (SELECT 0 UNION ALL SELECT x + 1 FROM n WHERE x + 1 < ?1)
                 INSERT INTO account_recovery_scopes (obligation_id, scope_id, route_kind,
                     route_role, since_seconds, until_seconds, snapshot_state, scope_format,
                     scope_payload)
                 SELECT x'{n:032x}', x, 0, 0, {since}, {until}, 1, 1, {} FROM n",
                certified()
            ),
            [scopes as i64],
        )
        .unwrap();
    }

    /// Each seeded obligation's state and revision, with whether every one
    /// of its scopes still holds its checkpoints, in id order.
    fn standing(store: &SqliteAccountStorage) -> Vec<(i64, i64, bool)> {
        store
            .lock()
            .unwrap()
            .prepare(
                "SELECT o.state, o.revision, MIN(COALESCE(json_array_length(
                     CAST(s.scope_payload AS TEXT), '$.checkpoints'), 0) > 0)
                 FROM account_recovery_obligations o
                 JOIN account_recovery_scopes s ON s.obligation_id = o.id
                 WHERE o.demand_key LIKE 'seed:%'
                 GROUP BY o.id ORDER BY o.id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn admit(store: &SqliteAccountStorage, created_at: u64) -> StorageResult<()> {
        store
            .app_storage()
            .record_reconciliation_items(std::iter::once((
                &TransportReconciliationRoute::Inbox,
                &TransportReconciliationItem {
                    event_id: [9; 32],
                    created_at,
                },
            )))
    }

    /// Retention removing inventory voids the frozen scopes whose window
    /// held it, so the conversion never reads removed input as coverage, and
    /// reopens the completion those scopes proved. A scope whose window it
    /// missed, and a maintenance boundary, which no inventory proves, keep
    /// their checkpoints. A failure rolls the removal back whole.
    #[test]
    fn removing_inventory_voids_the_frozen_scopes_it_overlaps() {
        let now = crate::unix_now_seconds();
        let store = fixture();
        seed_satisfied(&store, 1, (3, 0), (0, now), 1);
        seed_satisfied(&store, 2, (5, 0), (now - 5, now), 1);
        seed_satisfied(&store, 3, (2, 2), (0, now), 1);
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO transport_reconciliation_items VALUES (0,x'',zeroblob(32),?1)",
                [(now - TRANSPORT_RECONCILIATION_RETENTION_SECS - 1) as i64],
            )
            .unwrap();
        let before = standing(&store);
        assert_eq!(before, vec![(1, 1, true); 3]);
        store.lock().unwrap().execute_batch("CREATE TRIGGER reject_scope_invalidation BEFORE UPDATE ON account_recovery_scopes BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        assert_backend(admit(&store, now + 1), "injected");
        assert_eq!(standing(&store), before);
        assert!(
            store
                .app_storage()
                .retained_recovery_event(&TransportReconciliationRoute::Inbox, &[0; 32], None, now)
                .unwrap(),
            "the failed removal kept its inventory"
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_scope_invalidation")
            .unwrap();
        admit(&store, now + 1).unwrap();
        assert_eq!(
            standing(&store),
            vec![(0, 2, false), (1, 1, true), (1, 1, true)]
        );
    }

    /// A released receipt names no trustworthy route or time, so it voids
    /// every frozen history scope; a maintenance boundary keeps its own.
    #[test]
    fn a_released_receipt_voids_every_frozen_history_scope() {
        let now = crate::unix_now_seconds();
        let store = fixture();
        seed_satisfied(&store, 1, (3, 0), (0, now), 1);
        seed_satisfied(&store, 2, (5, 0), (now - 5, now), 1);
        seed_satisfied(&store, 3, (2, 2), (0, now), 1);
        store
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO cgka_released_transport_receipts(id,group_id,epoch)
                 VALUES (zeroblob(32),x'0a',1)",
            )
            .unwrap();
        assert_eq!(
            store.consume_released_transport_receipts().unwrap().len(),
            1
        );
        assert_eq!(
            standing(&store),
            vec![(0, 2, false), (0, 2, false), (1, 1, true)]
        );
    }

    /// Admitting live input costs the same however many frozen scopes the
    /// account still holds: the removal probe never reads them.
    #[test]
    fn live_admission_work_is_independent_of_retained_scope_count() {
        use crate::base::query_work_test_support::{QUERY_MEASUREMENT, measure};
        let _measurement = QUERY_MEASUREMENT.lock().unwrap();
        let now = crate::unix_now_seconds();
        let mut previous = None;
        for count in [1, 1024] {
            let store = fixture();
            seed_satisfied(&store, 1, (3, 0), (0, now), count);
            admit(&store, now).unwrap();
            let (_, steps) = measure(&store, || admit(&store, now).unwrap());
            if let Some(old) = previous {
                assert_eq!(
                    steps, old,
                    "live admission must not scan retained recovery scopes"
                );
            }
            previous = Some(steps);
        }
    }
}
