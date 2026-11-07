//! The evidence-only loss writer and the reads over its generations: the
//! goal floor and reach the account-open conversion un-covers, and the
//! constant-size snapshot the app opens an account's overflow guard from.
use std::collections::BTreeMap;

use super::*;
#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::{SqliteAppStorage, TransportReconciliationRoute};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum RecoveryLossCause {
    Queue = 0,
    NotificationConsumer = 1,
}

/// Capture before execution; never log account labels or marker identities.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryLossWatermark {
    pub marker_token: u64,
    pub observed_count: u64,
}

/// Constant-size commitment to a captured token/count set. The runtime retains
/// at most two of these even when unresolved durable generations accumulate.
/// No token identifiers or digest belong in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryLossSnapshot {
    rows: u64,
    digest: [u8; 32],
}
impl RecoveryLossSnapshot {
    pub fn is_empty(&self) -> bool {
        self.rows == 0
    }
}

fn snapshot(
    conn: &Connection,
    label: &str,
    cause: RecoveryLossCause,
) -> StorageResult<RecoveryLossSnapshot> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"mdk-recovery-loss-snapshot-v1");
    hash.update([cause as u8]);
    hash.update((label.len() as u64).to_be_bytes());
    hash.update(label.as_bytes());
    let mut statement = conn
        .prepare_cached(
            "SELECT marker_token,dropped_count FROM account_delivery_loss_evidence
        WHERE account_label=?1 AND cause=?2 ORDER BY marker_token",
        )
        .storage()?;
    let mut records = statement.query(params![label, cause as i64]).storage()?;
    let mut rows = 0_u64;
    while let Some(row) = records.next().storage()? {
        hash.update(i64_to_u64(row.get(0).storage()?)?.to_be_bytes());
        hash.update(i64_to_u64(row.get(1).storage()?)?.to_be_bytes());
        rows += 1;
    }
    hash.update(rows.to_be_bytes());
    Ok(RecoveryLossSnapshot {
        rows,
        digest: hash.finalize().into(),
    })
}

fn watermarks(
    conn: &Connection,
    label: &str,
    cause: RecoveryLossCause,
) -> StorageResult<Vec<RecoveryLossWatermark>> {
    let rows = conn
        .prepare_cached(
            "SELECT marker_token, dropped_count FROM account_delivery_loss_evidence
         WHERE account_label=?1 AND cause=?2 ORDER BY marker_token",
        )
        .storage()?
        .query_map(params![label, cause as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    rows.into_iter()
        .map(|(token, count)| {
            Ok(RecoveryLossWatermark {
                marker_token: i64_to_u64(token)?,
                observed_count: i64_to_u64(count)?,
            })
        })
        .collect()
}

/// The earliest `created_at` every unresolved charge of this cause is known to
/// cover, or `None` when any charge had no known time.
pub(super) fn goal_floor(
    conn: &Connection,
    label: &str,
    cause: RecoveryLossCause,
) -> StorageResult<Option<u64>> {
    let (rows, known, earliest): (i64, i64, Option<i64>) = conn
        .query_row_cached(
            "SELECT COUNT(*), COALESCE(SUM(bound_state = 1), 0), MIN(bound_seconds)
                 FROM account_delivery_loss_evidence
                 WHERE account_label = ?1 AND cause = ?2
                   AND (legacy_retired_count IS NULL OR legacy_retired_count < dropped_count)
                   AND (retired_count IS NULL OR retired_count < dropped_count)",
            params![label, cause as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .storage()?;
    Ok((rows > 0 && known == rows)
        .then_some(earliest)
        .flatten()
        .and_then(|seconds| u64::try_from(seconds).ok()))
}

/// The most routes one loss generation lists. A generation that touches more
/// is un-covered on every route, as if a charge had named none.
pub const MAX_LOSS_ROUTES: usize = 256;

/// The routes one generation's import un-covers: every route its writes
/// named, each from the earliest `created_at` it could have lost there. `None` when it un-covers every route from its floor: some charge
/// named no route or time, or it touched more than [`MAX_LOSS_ROUTES`].
pub(super) fn evidence_routes(
    conn: &Connection,
    label: &str,
    cause: i64,
    token: i64,
) -> StorageResult<Option<Vec<(TransportReconciliationRoute, u64)>>> {
    let routed: Option<i64> = conn
        .query_row_cached(
            "SELECT route_state FROM account_delivery_loss_evidence
             WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3 AND bound_state = 1",
            params![label, cause, token],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    if routed != Some(1) {
        return Ok(None);
    }
    conn.prepare_cached(
        "SELECT route_kind, route_id, bound_seconds FROM account_delivery_loss_evidence_routes
         WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3",
    )
    .storage()?
    .query_map(params![label, cause, token], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })
    .storage()?
    .map(|row| {
        let (kind, id, bound) = row.storage()?;
        Ok((
            crate::app::recovery_coverage::route_from(kind, &id)?,
            i64_to_u64(bound)?,
        ))
    })
    .collect::<StorageResult<Vec<_>>>()
    .map(Some)
}

/// The floor one generation's import un-covers the coverage ledger from: the
/// earliest `created_at` it charged, or zero when any charge had no known
/// time. Generations imported earlier were un-covered by their own import, so
/// a newer one never re-opens a range that a fetch since then proved.
pub(super) fn evidence_floor(
    conn: &Connection,
    label: &str,
    cause: i64,
    token: i64,
) -> StorageResult<u64> {
    let bound: Option<(i64, Option<i64>)> = conn
        .query_row_cached(
            "SELECT bound_state, bound_seconds FROM account_delivery_loss_evidence
             WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3",
            params![label, cause, token],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .storage()?;
    Ok(match bound {
        Some((1, Some(seconds))) => u64::try_from(seconds).unwrap_or(0),
        _ => 0,
    })
}

/// Where loss may have lost events: every route from `every_route_from`,
/// and each listed route from its own bound. A generation that names its
/// routes reaches only those; one that names none reaches every route from
/// its floor, or from zero when a charge had no known time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryLossReach {
    pub every_route_from: Option<u64>,
    pub routes: BTreeMap<TransportReconciliationRoute, u64>,
}

impl RecoveryLossReach {
    /// The earliest `created_at` the loss may have lost on `route`.
    pub fn floor(&self, route: &TransportReconciliationRoute) -> Option<u64> {
        match (self.every_route_from, self.routes.get(route)) {
            (Some(every), Some(own)) => Some(every.min(*own)),
            (every, own) => every.or(own.copied()),
        }
    }

    /// Whether the loss may have lost an event on `route` created at or
    /// before `until`.
    pub fn reaches(&self, route: &TransportReconciliationRoute, until: u64) -> bool {
        self.floor(route).is_some_and(|floor| floor <= until)
    }
}

/// Where one cause's generations that still carry debt may have lost events.
pub(super) fn reach(
    conn: &Connection,
    label: &str,
    cause: RecoveryLossCause,
) -> StorageResult<RecoveryLossReach> {
    let counted = "account_label = ?1 AND cause = ?2
               AND (legacy_retired_count IS NULL OR legacy_retired_count < dropped_count)
               AND (retired_count IS NULL OR retired_count < dropped_count)";
    let value = cause as i64;
    let every_route_from: Option<i64> = conn
        .query_row_cached(
            &format!(
                "SELECT MIN(CASE WHEN bound_state = 1 THEN COALESCE(bound_seconds, 0) ELSE 0 END)
                 FROM account_delivery_loss_evidence
                 WHERE {counted} AND NOT (route_state = 1 AND bound_state = 1)"
            ),
            params![label, value],
            |row| row.get(0),
        )
        .storage()?;
    let routes = conn
        .prepare_cached(&format!(
            "SELECT r.route_kind, r.route_id, MIN(r.bound_seconds)
             FROM account_delivery_loss_evidence_routes AS r
             JOIN account_delivery_loss_evidence USING (account_label, cause, marker_token)
             WHERE {counted} AND route_state = 1 AND bound_state = 1
             GROUP BY r.route_kind, r.route_id"
        ))
        .storage()?
        .query_map(params![label, value], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .storage()?
        .map(|row| {
            let (kind, id, bound) = row.storage()?;
            Ok((
                crate::app::recovery_coverage::route_from(kind, &id)?,
                i64_to_u64(bound)?,
            ))
        })
        .collect::<StorageResult<BTreeMap<_, _>>>()?;
    Ok(RecoveryLossReach {
        every_route_from: every_route_from.map(i64_to_u64).transpose()?,
        routes,
    })
}

/// Make a generation account-wide: every route lost coverage from its floor,
/// so it lists none.
pub(super) fn unroute_tx(
    conn: &Connection,
    label: &str,
    cause: i64,
    token: i64,
) -> StorageResult<()> {
    conn.execute_cached(
        "UPDATE account_delivery_loss_evidence SET route_state = 0
         WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3",
        params![label, cause, token],
    )
    .storage()?;
    drop_unrouted_routes_tx(conn, label, cause, token)
}

/// The routes one write may list: `None` for none, or for more than
/// [`MAX_LOSS_ROUTES`], since either makes its generation account-wide.
pub(super) fn listed_routes(
    routes: Option<&[(TransportReconciliationRoute, u64)]>,
) -> Option<&[(TransportReconciliationRoute, u64)]> {
    routes.filter(|routes| !routes.is_empty() && routes.len() <= MAX_LOSS_ROUTES)
}

/// Merge one write's routes into its generation, once its evidence row
/// holds the write's `route_state`: each route at its lowest bound, while the
/// generation still lists its routes. A generation that lists more than
/// [`MAX_LOSS_ROUTES`] becomes account-wide.
pub(super) fn merge_routes_tx(
    conn: &Connection,
    label: &str,
    cause: i64,
    token: i64,
    routes: Option<&[(TransportReconciliationRoute, u64)]>,
) -> StorageResult<()> {
    for (route, bound) in routes.unwrap_or_default() {
        let (kind, id) = route.storage_key();
        conn.execute_cached(
            "INSERT INTO account_delivery_loss_evidence_routes
             (account_label, cause, marker_token, route_kind, route_id, bound_seconds)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6 FROM account_delivery_loss_evidence
             WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3
               AND route_state = 1
             ON CONFLICT DO UPDATE SET
                 bound_seconds = MIN(bound_seconds, excluded.bound_seconds)",
            params![label, cause, token, kind, id, sqlite_integer(*bound)?],
        )
        .storage()?;
    }
    let listed: i64 = conn
        .query_row_cached(
            "SELECT COUNT(*) FROM account_delivery_loss_evidence_routes
             WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3",
            params![label, cause, token],
            |row| row.get(0),
        )
        .storage()?;
    if usize::try_from(listed).map_or(true, |listed| listed > MAX_LOSS_ROUTES) {
        unroute_tx(conn, label, cause, token)
    } else {
        drop_unrouted_routes_tx(conn, label, cause, token)
    }
}

/// An account-wide generation needs no route rows.
fn drop_unrouted_routes_tx(
    conn: &Connection,
    label: &str,
    cause: i64,
    token: i64,
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM account_delivery_loss_evidence_routes
         WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3
           AND NOT EXISTS (SELECT 1 FROM account_delivery_loss_evidence
               WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3
                 AND route_state = 1)",
        params![label, cause, token],
    )
    .storage()?;
    Ok(())
}

impl SqliteAppStorage {
    /// Typed evidence only. A notification count is an observation count, never
    /// a claim about how many encrypted events the receiver missed.
    pub fn record_account_recovery_loss(
        &self,
        label: &str,
        cause: RecoveryLossCause,
        marker_token: u64,
        observed_count: u64,
        observed_at_seconds: u64,
    ) -> StorageResult<()> {
        self.record_account_recovery_loss_bounded(
            label,
            cause,
            marker_token,
            observed_count,
            observed_at_seconds,
            None,
        )
    }

    /// Like [`Self::record_account_recovery_loss`], also charging the earliest
    /// wire `created_at` among the lost deliveries, or an unknown time, to the
    /// generation's bound.
    pub fn record_account_recovery_loss_bounded(
        &self,
        label: &str,
        cause: RecoveryLossCause,
        marker_token: u64,
        observed_count: u64,
        observed_at_seconds: u64,
        earliest_created_at: Option<u64>,
    ) -> StorageResult<()> {
        self.record_account_recovery_loss_routed(
            label,
            cause,
            marker_token,
            observed_count,
            observed_at_seconds,
            earliest_created_at,
            None,
        )
    }

    /// Like [`Self::record_account_recovery_loss_bounded`], also naming the
    /// routes these charges lost on, each with the earliest `created_at` it
    /// could have lost there. `None`, or an empty list, means some charge
    /// named no route, and the generation un-covers every route from then on.
    #[allow(clippy::too_many_arguments)]
    pub fn record_account_recovery_loss_routed(
        &self,
        label: &str,
        cause: RecoveryLossCause,
        marker_token: u64,
        observed_count: u64,
        observed_at_seconds: u64,
        earliest_created_at: Option<u64>,
        routes: Option<&[(TransportReconciliationRoute, u64)]>,
    ) -> StorageResult<()> {
        let (bound_state, bound_seconds) =
            crate::app::account_recovery::loss_bound_values(earliest_created_at)?;
        let token = sqlite_integer(marker_token)?;
        let routes = listed_routes(routes);
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                &format!(
                    "INSERT INTO account_delivery_loss_evidence
                     (account_label,cause,marker_token,pending_since,dropped_count,
                      bound_state,bound_seconds,route_state)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                     ON CONFLICT(account_label,cause,marker_token) DO UPDATE SET
                         dropped_count=MAX(dropped_count,excluded.dropped_count),
                         route_state=MIN(route_state,excluded.route_state),
                         {}",
                    crate::app::account_recovery::LOSS_BOUND_MERGE
                ),
                params![
                    label,
                    cause as i64,
                    token,
                    sqlite_integer(observed_at_seconds)?,
                    sqlite_integer(observed_count)?,
                    bound_state,
                    bound_seconds,
                    i64::from(routes.is_some())
                ],
            )
            .storage()?;
            merge_routes_tx(&conn, label, cause as i64, token, routes)
        })
    }

    /// The earliest `created_at` every unresolved charge of this cause is
    /// known to cover, or `None` when any charge had no known time. Legacy
    /// retired watermarks and loss the user retired no longer carry debt and
    /// are ignored.
    pub fn recovery_loss_goal_floor(
        &self,
        label: &str,
        cause: RecoveryLossCause,
    ) -> StorageResult<Option<u64>> {
        let conn = self.lock()?;
        goal_floor(&conn, label, cause)
    }

    /// Where this cause's unresolved loss may have lost events, by route.
    /// Loss the user retired, or a legacy retirement covered, carries no debt
    /// and is left out.
    pub fn recovery_loss_reach(
        &self,
        label: &str,
        cause: RecoveryLossCause,
    ) -> StorageResult<RecoveryLossReach> {
        let conn = self.lock()?;
        reach(&conn, label, cause)
    }

    pub fn recovery_loss_watermarks(
        &self,
        label: &str,
        cause: RecoveryLossCause,
    ) -> StorageResult<Vec<RecoveryLossWatermark>> {
        let conn = self.lock()?;
        watermarks(&conn, label, cause)
    }

    /// Read all durable generations with constant Rust memory, retaining only
    /// a commitment to them.
    pub fn recovery_loss_snapshot(
        &self,
        label: &str,
        cause: RecoveryLossCause,
    ) -> StorageResult<RecoveryLossSnapshot> {
        let conn = self.lock()?;
        snapshot(&conn, label, cause)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_goal_floor_is_a_running_minimum_until_any_charge_is_unknown() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .app_storage()
            .ensure_account_projection("alice")
            .unwrap();
        let floor = |store: &SqliteAccountStorage| {
            store
                .app_storage()
                .recovery_loss_goal_floor("alice", RecoveryLossCause::Queue)
                .unwrap()
        };
        assert_eq!(floor(&store), None, "no loss has no bound to certify");
        store
            .app_storage()
            .record_account_recovery_loss_bounded(
                "alice",
                RecoveryLossCause::Queue,
                7,
                1,
                1,
                Some(500),
            )
            .unwrap();
        assert_eq!(floor(&store), Some(500));
        // A later drop can carry an earlier timestamp, as NIP-59 wraps do.
        store
            .app_storage()
            .record_account_recovery_loss_bounded(
                "alice",
                RecoveryLossCause::Queue,
                7,
                2,
                1,
                Some(300),
            )
            .unwrap();
        store
            .app_storage()
            .record_account_recovery_loss_bounded(
                "alice",
                RecoveryLossCause::Queue,
                7,
                3,
                1,
                Some(900),
            )
            .unwrap();
        assert_eq!(floor(&store), Some(300));
        store
            .app_storage()
            .record_account_recovery_loss_bounded(
                "alice",
                RecoveryLossCause::Queue,
                8,
                1,
                1,
                Some(200),
            )
            .unwrap();
        assert_eq!(floor(&store), Some(200), "every generation contributes");
        // A charge with no known time leaves the whole goal unbounded.
        store
            .app_storage()
            .record_account_recovery_loss_bounded("alice", RecoveryLossCause::Queue, 8, 2, 1, None)
            .unwrap();
        assert_eq!(floor(&store), None);
        store
            .app_storage()
            .record_account_recovery_loss_bounded(
                "alice",
                RecoveryLossCause::Queue,
                8,
                3,
                1,
                Some(100),
            )
            .unwrap();
        assert_eq!(floor(&store), None, "an unknown charge stays unknown");
        // Rows written without a bound, including every pre-migration row,
        // are unknown too.
        store
            .app_storage()
            .record_account_recovery_loss("alice", RecoveryLossCause::NotificationConsumer, 9, 0, 1)
            .unwrap();
        assert_eq!(
            store
                .app_storage()
                .recovery_loss_goal_floor("alice", RecoveryLossCause::NotificationConsumer)
                .unwrap(),
            None
        );
    }

    /// Unresolved loss reaches each route its generations named from that
    /// route's lowest bound, and every route from the floor of a generation
    /// that named none; loss the user retired reaches nothing.
    #[test]
    fn loss_reach_is_each_routes_lowest_unresolved_bound() {
        use RecoveryLossCause::{NotificationConsumer, Queue};
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        app.ensure_account_projection("alice").unwrap();
        let reach = |cause| app.recovery_loss_reach("alice", cause).unwrap();
        let group = |byte| TransportReconciliationRoute::Group([byte; 32]);
        let inbox = TransportReconciliationRoute::Inbox;
        let lose = |cause, token, floor, routes: Option<&[(TransportReconciliationRoute, u64)]>| {
            app.record_account_recovery_loss_routed("alice", cause, token, 1, 1, floor, routes)
                .unwrap();
        };
        assert_eq!(reach(Queue), RecoveryLossReach::default());

        lose(Queue, 7, Some(400), Some(&[(group(1), 500)]));
        lose(
            Queue,
            8,
            Some(300),
            Some(&[(group(1), 400), (group(2), 300)]),
        );
        let routed = reach(Queue);
        assert_eq!(routed.every_route_from, None);
        assert_eq!(routed.floor(&group(1)), Some(400));
        assert_eq!(routed.floor(&group(2)), Some(300));
        assert_eq!(routed.floor(&inbox), None, "no generation named the inbox");
        assert!(routed.reaches(&group(1), 400));
        assert!(
            !routed.reaches(&group(1), 399),
            "nothing lost before its bound"
        );
        assert_eq!(reach(NotificationConsumer), RecoveryLossReach::default());

        // A generation that names no route reaches every route from its
        // floor, and one with no known time from zero.
        lose(Queue, 9, Some(350), None);
        let wide = reach(Queue);
        assert_eq!(wide.floor(&inbox), Some(350));
        assert_eq!(wide.floor(&group(1)), Some(350));
        assert_eq!(wide.floor(&group(2)), Some(300));
        lose(NotificationConsumer, 3, None, None);
        assert_eq!(reach(NotificationConsumer).floor(&group(9)), Some(0));

        // Retired loss reaches nothing.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE account_delivery_loss_evidence
                 SET imported_count = dropped_count, retired_count = dropped_count
                 WHERE cause = 0 AND marker_token IN (8, 9)",
            )
            .unwrap();
        let left = reach(Queue);
        assert_eq!(left.every_route_from, None);
        assert_eq!(left.floor(&group(1)), Some(500));
        assert_eq!(left.floor(&group(2)), None);
    }

    #[test]
    fn loss_snapshot_preserves_every_generation_with_constant_capture_memory() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        app.ensure_account_projection("alice").unwrap();
        store.lock().unwrap().execute_batch("WITH RECURSIVE n(x) AS (SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<1023)
            INSERT INTO account_delivery_loss_evidence(account_label,cause,marker_token,pending_since,dropped_count)
            SELECT 'alice',x%2,x,1,0 FROM n;").unwrap();
        let before = app
            .recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
            .unwrap();
        assert_eq!(before.rows, 512);
        assert_eq!(std::mem::size_of_val(&before), 40);
        assert!(
            app.recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
                .unwrap()
                == before
        );
        assert_eq!(
            app.recovery_loss_watermarks("alice", RecoveryLossCause::NotificationConsumer)
                .unwrap()
                .len(),
            512
        );
        app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 0, 1, 2)
            .unwrap();
        assert!(
            app.recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
                .unwrap()
                != before,
            "the earliest generation is still part of the commitment"
        );
        let changed = app
            .recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
            .unwrap();
        app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 0, 1, 3)
            .unwrap();
        assert!(
            app.recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
                .unwrap()
                == changed,
            "a duplicate observation creates no other generation"
        );
        assert_eq!(
            app.recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .len(),
            512
        );
    }

    /// A generation's evidence survives reopen, and re-observing it raises
    /// its count monotonically without moving its detection time.
    #[test]
    fn loss_evidence_survives_reopen_and_merges_monotonically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loss-evidence.sqlite");
        let key = crate::SqlCipherKey::raw([0x11; 32]);
        let generations = |app: &SqliteAppStorage| {
            let conn = app.lock().unwrap();
            conn.prepare(
                "SELECT marker_token, pending_since, dropped_count
                 FROM account_delivery_loss_evidence WHERE account_label = 'alice'
                 ORDER BY marker_token",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<(i64, i64, i64)>, _>>()
            .unwrap()
        };
        {
            let app = SqliteAccountStorage::open_encrypted(&path, &key)
                .unwrap()
                .app_storage();
            app.ensure_account_projection("alice").unwrap();
            app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 11, 3, 5)
                .unwrap();
            app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 11, 7, 9)
                .unwrap();
            app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 11, 2, 10)
                .unwrap();
            app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 12, 1, 11)
                .unwrap();
            assert_eq!(generations(&app), vec![(11, 5, 7), (12, 11, 1)]);
        }
        let app = SqliteAccountStorage::open_encrypted(&path, &key)
            .unwrap()
            .app_storage();
        assert_eq!(
            generations(&app),
            vec![(11, 5, 7), (12, 11, 1)],
            "restart must retain unresolved loss"
        );
        assert_eq!(
            app.recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .len(),
            2
        );
    }
}
