//! Completion handoff between the account worker and the evidence-only writer.
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

/// Which generations a reach read counts.
#[derive(Clone, Copy)]
enum ReachOf {
    /// One cause's generations that still carry debt.
    Cause(RecoveryLossCause),
    /// Every generation an import charged after this loss revision, retired
    /// or not: retiring loss proves nothing about what it reached.
    ImportedAfter(i64),
}

fn reach(conn: &Connection, label: &str, of: ReachOf) -> StorageResult<RecoveryLossReach> {
    let (filter, value) = match of {
        ReachOf::Cause(cause) => (
            "cause = ?2
               AND (legacy_retired_count IS NULL OR legacy_retired_count < dropped_count)
               AND (retired_count IS NULL OR retired_count < dropped_count)",
            cause as i64,
        ),
        ReachOf::ImportedAfter(revision) => ("import_revision > ?2", revision),
    };
    let counted = format!("account_label = ?1 AND {filter}");
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
        reach(&conn, label, ReachOf::Cause(cause))
    }

    /// Where loss of every cause that an import charged after `loss_revision`
    /// may have lost events, by route: what a checkpoint captured at that
    /// revision has not seen. Retired loss still counts, since retiring it
    /// proves nothing. Loss no import has charged yet is left out; its import
    /// raises the revision first. `None` when an acknowledgment has since
    /// deleted loss charged after `loss_revision`: where that loss reached is
    /// no longer known.
    pub fn recovery_loss_reach_after(
        &self,
        label: &str,
        loss_revision: u64,
    ) -> StorageResult<Option<RecoveryLossReach>> {
        let loss_revision = sqlite_integer(loss_revision)?;
        let conn = self.lock()?;
        let acknowledged: i64 = conn
            .query_row_cached(
                "SELECT acknowledged_import_revision FROM account_recovery_state
                 WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if acknowledged > loss_revision {
            return Ok(None);
        }
        reach(&conn, label, ReachOf::ImportedAfter(loss_revision)).map(Some)
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
    /// a commitment for the later guarded acknowledgment transaction.
    pub fn recovery_loss_snapshot(
        &self,
        label: &str,
        cause: RecoveryLossCause,
    ) -> StorageResult<RecoveryLossSnapshot> {
        let conn = self.lock()?;
        snapshot(&conn, label, cause)
    }

    /// Same guarded handoff as `acknowledge_recovery_loss`, using a constant-size
    /// snapshot rather than copying every unresolved watermark into the owner.
    pub fn acknowledge_recovery_loss_snapshot(
        &self,
        expected: &RecoveryRevisionFence,
        obligation_id: [u8; 16],
        captured: &RecoveryLossSnapshot,
    ) -> StorageResult<bool> {
        if captured.is_empty() {
            return Ok(false);
        }
        self.acknowledge_recovery_loss_matching(expected, obligation_id, |conn, label, cause| {
            Ok(snapshot(conn, label, cause)? == *captured)
        })
    }

    /// Run once when constructing the owner, before selecting work. A satisfied
    /// row with unreclaimed evidence means the prior process could have stopped
    /// before plane acknowledgment. Rearm conservatively without changing pacing.
    /// An absent row is a supported low-level retirement, not an interrupted
    /// owner completion; retaining its watermark does not recreate that demand.
    pub fn restore_unacknowledged_recovery_loss(&self) -> StorageResult<usize> {
        self.lock()?
            .execute_cached(
                "UPDATE account_recovery_obligations AS o SET state=0, eligibility=1, revision=revision+1
             WHERE state=1 AND cause IN (0,6) AND EXISTS(
                 SELECT 1 FROM account_delivery_loss_evidence AS e
                 WHERE e.account_label=o.account_label
                 AND e.cause=CASE o.cause WHEN 0 THEN 0 ELSE 1 END)",
                [],
            )
            .storage()
    }

    /// Call only after the matching plane generation/count is acknowledged and
    /// every writer for captured tokens has finished. SQL cannot prove that
    /// external prerequisite. Reclaim the exact captured set after checking the
    /// satisfied obligation and all invalidation fences; new evidence refuses
    /// reclamation. Do not publish completion if this returns false or errors.
    pub fn acknowledge_recovery_loss(
        &self,
        expected: &RecoveryRevisionFence,
        obligation_id: [u8; 16],
        captured: &[RecoveryLossWatermark],
    ) -> StorageResult<bool> {
        if captured.is_empty()
            || captured
                .windows(2)
                .any(|pair| pair[0].marker_token >= pair[1].marker_token)
        {
            return Ok(false);
        }
        self.acknowledge_recovery_loss_matching(expected, obligation_id, |conn, label, cause| {
            Ok(watermarks(conn, label, cause)? == captured)
        })
    }

    fn acknowledge_recovery_loss_matching(
        &self,
        expected: &RecoveryRevisionFence,
        obligation_id: [u8; 16],
        matches: impl FnOnce(&Connection, &str, RecoveryLossCause) -> StorageResult<bool>,
    ) -> StorageResult<bool> {
        let Some((_, revision)) = expected
            .obligations
            .iter()
            .find(|(id, _)| *id == obligation_id)
        else {
            return Ok(false);
        };
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let current = revision_fence(&conn)?;
            if current.loss_revision != expected.loss_revision
                || current.route_revision != expected.route_revision
                || !plan::no_unimported_loss(&conn)?
            {
                return Ok(false);
            }
            use rusqlite::OptionalExtension;
            let row: Option<(String, i64)> = conn
                .query_row_cached(
                    "SELECT account_label,cause FROM account_recovery_obligations
                 WHERE id=?1 AND revision=?2 AND state=1 AND cause IN (0,6)",
                    params![obligation_id.as_slice(), sqlite_integer(*revision)?],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .storage()?;
            let Some((label, cause)) = row else {
                return Ok(false);
            };
            let cause = if cause == 0 {
                RecoveryLossCause::Queue
            } else {
                RecoveryLossCause::NotificationConsumer
            };
            if !plan::scopes_qualify(&conn, expected, None, obligation_id, 0)? {
                return Ok(false);
            }
            if !matches(&conn, &label, cause)? {
                return Ok(false);
            }
            // The rows say where this loss reached; keep how recent it was.
            conn.execute_cached(
                "UPDATE account_recovery_state SET acknowledged_import_revision =
                    MAX(acknowledged_import_revision, COALESCE(
                        (SELECT MAX(import_revision) FROM account_delivery_loss_evidence
                         WHERE account_label=?1 AND cause=?2), 0))
                 WHERE singleton=1",
                params![label, cause as i64],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM account_delivery_loss_evidence WHERE account_label=?1 AND cause=?2",
                params![label, cause as i64],
            )
            .storage()?;
            Ok(true)
        })
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
            .mark_account_delivery_recovery_bounded("alice", 7, 1, Some(500))
            .unwrap();
        assert_eq!(floor(&store), Some(500));
        // A later drop can carry an earlier timestamp, as NIP-59 wraps do.
        store
            .app_storage()
            .mark_account_delivery_recovery_bounded("alice", 7, 2, Some(300))
            .unwrap();
        store
            .app_storage()
            .mark_account_delivery_recovery_bounded("alice", 7, 3, Some(900))
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
        app.synchronize_account_delivery_loss("alice").unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE account_delivery_loss_evidence SET retired_count = imported_count
                 WHERE cause = 0 AND marker_token IN (8, 9)",
            )
            .unwrap();
        let left = reach(Queue);
        assert_eq!(left.every_route_from, None);
        assert_eq!(left.floor(&group(1)), Some(500));
        assert_eq!(left.floor(&group(2)), None);
    }

    /// Each import stamps the generations it charged with the loss revision
    /// it left, so a checkpoint's revision separates the loss it saw from loss
    /// imported after it.
    #[test]
    fn loss_reach_after_a_revision_is_what_later_imports_charged() {
        use RecoveryLossCause::{NotificationConsumer, Queue};
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        app.ensure_account_projection("alice").unwrap();
        let group = |byte| TransportReconciliationRoute::Group([byte; 32]);
        let after = |revision| {
            app.recovery_loss_reach_after("alice", revision)
                .unwrap()
                .expect("nothing acknowledged")
        };
        let import = || {
            app.synchronize_account_delivery_loss("alice").unwrap();
            app.recovery_revision_fence().unwrap().loss_revision
        };
        app.record_account_recovery_loss_routed(
            "alice",
            Queue,
            7,
            1,
            1,
            Some(500),
            Some(&[(group(1), 500)]),
        )
        .unwrap();
        assert_eq!(
            after(0),
            RecoveryLossReach::default(),
            "no import charged it"
        );
        let first = import();
        assert_eq!(after(first - 1).floor(&group(1)), Some(500));
        assert_eq!(after(first), RecoveryLossReach::default());

        app.record_account_recovery_loss_routed(
            "alice",
            NotificationConsumer,
            3,
            0,
            1,
            Some(800),
            None,
        )
        .unwrap();
        let second = import();
        assert!(second > first);
        let newer = after(first);
        assert_eq!(newer.every_route_from, Some(800));
        assert_eq!(newer.floor(&group(1)), Some(800), "only the newer loss");
        assert_eq!(after(second), RecoveryLossReach::default());

        // A newer charge to an older generation stamps all of it again.
        app.record_account_recovery_loss_routed(
            "alice",
            Queue,
            7,
            2,
            1,
            Some(900),
            Some(&[(group(2), 900)]),
        )
        .unwrap();
        let third = import();
        let recharged = after(second);
        assert_eq!(recharged.every_route_from, None);
        assert_eq!(recharged.floor(&group(1)), Some(500));
        assert_eq!(recharged.floor(&group(2)), Some(900));
        assert_eq!(after(third), RecoveryLossReach::default());

        // Retiring loss carries no debt, but proves nothing about what it
        // reached.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE account_delivery_loss_evidence SET retired_count = imported_count",
            )
            .unwrap();
        assert_eq!(
            app.recovery_loss_reach("alice", Queue).unwrap(),
            RecoveryLossReach::default()
        );
        assert_eq!(after(first).every_route_from, Some(800));
        assert_eq!(after(first).floor(&group(1)), Some(500));
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
        app.synchronize_account_delivery_loss("alice").unwrap();
        let fence = app.recovery_revision_fence().unwrap();
        assert_eq!(fence.obligations.len(), 2);
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
        app.record_account_delivery_loss("alice", 0, 1, 2).unwrap();
        assert!(
            app.recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
                .unwrap()
                != before,
            "the earliest generation is still part of the commitment"
        );
        app.synchronize_account_delivery_loss("alice").unwrap();
        assert!(app.recovery_revision_fence().unwrap().loss_revision > fence.loss_revision);
        let changed = app
            .recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
            .unwrap();
        app.record_account_delivery_loss("alice", 0, 1, 3).unwrap();
        app.synchronize_account_delivery_loss("alice").unwrap();
        assert!(
            app.recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
                .unwrap()
                == changed,
            "duplicate observations cannot create another generation or rearm debt"
        );
        assert_eq!(
            app.recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .len(),
            512
        );
    }
}
