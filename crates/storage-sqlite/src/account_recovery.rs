//! Account-private recovery demand. The worker owns demand and completion;
//! the narrow loss writer may only append monotonically increasing evidence.
mod comparison;
pub use comparison::{RecoveryComparison, RecoveryComparisonOutcome, RecoveryComparisonPlan};
mod demand;
pub use demand::{
    RecoveryCause, RecoveryDemand, RecoveryDemandTicket, RecoveryPredicate, RecoveryRequest,
};
mod loss;
mod plan;
mod stall;
pub use loss::{RecoveryLossCause, RecoveryLossSnapshot, RecoveryLossWatermark};
pub use plan::{
    RecoveryEligibility, RecoveryEndpointCheckpoint, RecoveryScopeCheckpoint, RecoveryScopeOutcome,
    RecoveryScopePlan, RecoveryScopeToken, StoredRecoveryScope,
};
pub use stall::QualifiedRecoveryStallSample;

use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, i64_to_u64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};

/// Durable account-wide pacing, independent of any process's monotonic clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRetryState {
    pub attempt_serial: u64,
    pub ordinal: u64,
    pub recorded_at_ms: u64,
    pub delay_ms: u64,
    pub not_before_ms: u64,
}

/// Immutable revision snapshot. Positive completion also requires qualified
/// scope/admission evidence from the account owner; this is only the CAS fence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRevisionFence {
    pub loss_revision: u64,
    pub route_revision: u64,
    pub inventory_revision: u64,
    pub obligations: Vec<([u8; 16], u64)>,
}

fn sqlite_integer(value: u64) -> StorageResult<i64> {
    i64::try_from(value)
        .map_err(|_| StorageError::Serialization("recovery value outside supported range".into()))
}

fn retry_state(conn: &Connection) -> StorageResult<RecoveryRetryState> {
    let (serial, ordinal, recorded, delay, due): (i64, i64, i64, i64, i64) = conn
        .query_row_cached(
            "SELECT next_attempt, retry_ordinal, retry_recorded_at_ms, retry_delay_ms,
         retry_not_before_ms FROM account_recovery_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .storage()?;
    Ok(RecoveryRetryState {
        attempt_serial: i64_to_u64(serial)?,
        ordinal: i64_to_u64(ordinal)?,
        recorded_at_ms: i64_to_u64(recorded)?,
        delay_ms: i64_to_u64(delay)?,
        not_before_ms: i64_to_u64(due)?,
    })
}

fn revision_fence(conn: &Connection) -> StorageResult<RecoveryRevisionFence> {
    let (loss, route, inventory): (i64, i64, i64) = conn
        .query_row_cached(
            "SELECT loss_revision, route_revision, inventory_revision
         FROM account_recovery_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .storage()?;
    let rows = conn
        .prepare_cached(
            "SELECT id, revision FROM account_recovery_obligations WHERE state = 0 ORDER BY id",
        )
        .storage()?
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let obligations = rows
        .into_iter()
        .map(|(id, revision)| {
            let id = id.try_into().map_err(|_| {
                StorageError::Serialization("invalid recovery obligation id".into())
            })?;
            Ok((id, i64_to_u64(revision)?))
        })
        .collect::<StorageResult<_>>()?;
    Ok(RecoveryRevisionFence {
        loss_revision: i64_to_u64(loss)?,
        route_revision: i64_to_u64(route)?,
        inventory_revision: i64_to_u64(inventory)?,
        obligations,
    })
}

/// Delete inventory and invalidate only frozen scopes whose route/window (and,
/// for a known-event predicate, exact event) overlap the removed input. The
/// account revision still fences reservations and plan installation. Callers
/// must already own the surrounding transaction. Predicates are internal SQL.
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
    conn.execute_cached("UPDATE account_recovery_state SET inventory_revision=inventory_revision+1 WHERE singleton=1",[]).storage()?;
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
    conn.execute_cached("UPDATE account_recovery_state SET inventory_revision=inventory_revision+1 WHERE singleton=1",[]).storage()?;
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
             revision = revision + 1, state = 0, eligibility = 0,
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

/// A serialized worker observation chooses the current live plane token.
/// Imports also replace the compatibility pointer to fence an older clear;
/// random tokens do not order generations and each retains its own watermark.
pub(crate) fn arm_overflow_tx(
    conn: &Connection,
    label: &str,
    token: i64,
    dropped: i64,
    now: i64,
) -> StorageResult<()> {
    // Import may have joined this generation before its queued control record
    // reaches the worker. Changing the represented identity must fence old
    // grants even though it grants no permission to reset quiescence.
    let adopted = conn.execute_cached(
        "UPDATE account_recovery_obligations SET marker_token = ?2, revision = revision + 1, state = 0,
             dropped_count = (SELECT imported_count FROM account_delivery_loss_evidence
                 WHERE account_label = ?4 AND cause = 0 AND marker_token = ?2),
             pending_since = (SELECT pending_since FROM account_delivery_loss_evidence
                 WHERE account_label = ?4 AND cause = 0 AND marker_token = ?2)
         WHERE demand_key = ?1 AND marker_token != ?2 AND EXISTS(
             SELECT 1 FROM account_delivery_loss_evidence
             WHERE account_label = ?4 AND cause = 0 AND marker_token = ?2 AND imported_count >= ?3)",
        params![format!("overflow:{label}"), token, dropped, label],
    ).storage()?;
    if adopted == 0 {
        join_loss_tx(conn, label, 0, token, dropped, now, true)?;
    } else {
        conn.execute_cached(
            "UPDATE account_recovery_state SET loss_revision=loss_revision+1 WHERE singleton=1",
            [],
        )
        .storage()?;
    }
    // Preserve what the worker already observed, even when this token's marker
    // callback has not committed yet. A delayed duplicate cannot rearm debt.
    conn.execute_cached(
        "INSERT INTO account_delivery_loss_evidence
         (account_label, cause, marker_token, pending_since, dropped_count, imported_count)
         VALUES (?1, 0, ?2, ?3, ?4, ?4)
         ON CONFLICT(account_label, cause, marker_token) DO UPDATE SET
             dropped_count = MAX(dropped_count, excluded.dropped_count),
             imported_count = MAX(COALESCE(imported_count, 0), excluded.imported_count)",
        params![label, token, now, dropped],
    )
    .storage()?;
    Ok(())
}

fn join_loss_tx(
    conn: &Connection,
    label: &str,
    cause: i64,
    token: i64,
    dropped: i64,
    now: i64,
    adopt_token: bool,
) -> StorageResult<()> {
    let (prefix, demand_cause) = match cause {
        0 => ("overflow", 0),
        1 => ("notification", 6),
        _ => {
            return Err(StorageError::Serialization(
                "unsupported recovery loss cause".into(),
            ));
        }
    };
    let key = format!("{prefix}:{label}");
    let changed = conn.execute_cached(
        "INSERT INTO account_recovery_obligations
         (demand_key, cause, account_label, marker_token, pending_since, dropped_count, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT(demand_key) DO UPDATE SET
             revision = revision + 1, state = 0, eligibility = 0,
             pending_since = CASE WHEN ?8 AND marker_token != excluded.marker_token
                 THEN excluded.pending_since ELSE MIN(pending_since, excluded.pending_since) END,
             dropped_count = CASE WHEN marker_token = excluded.marker_token THEN MAX(dropped_count, excluded.dropped_count)
                 WHEN ?8 THEN excluded.dropped_count ELSE dropped_count END,
             marker_token = CASE WHEN ?8 THEN excluded.marker_token ELSE marker_token END,
             updated_at_ms = excluded.updated_at_ms
         WHERE marker_token != excluded.marker_token OR dropped_count < excluded.dropped_count",
        params![key, demand_cause, label, token, now, dropped, milliseconds(now)?, adopt_token],
    ).storage()?;
    conn.execute_cached(
        "INSERT OR IGNORE INTO account_recovery_scopes(obligation_id, scope_id)
         SELECT id, 0 FROM account_recovery_obligations WHERE demand_key = ?1",
        [key],
    )
    .storage()?;
    if changed > 0 {
        conn.execute_cached(
            "UPDATE account_recovery_state SET loss_revision = loss_revision + 1 WHERE singleton = 1", [],
        ).storage()?;
    }
    Ok(())
}

/// Token-only legacy retirement cannot certify other generations joined into
/// the same account demand. Reconstitute those generations in this transaction;
/// their imported watermark remains distinct from low-level retirement.
pub(crate) fn restore_legacy_loss_tx(conn: &Connection, label: &str) -> StorageResult<bool> {
    let rows = conn
        .prepare_cached(
            "SELECT marker_token,pending_since,dropped_count FROM account_delivery_loss_evidence
         WHERE account_label=?1 AND cause=0
           AND (legacy_retired_count IS NULL OR dropped_count>legacy_retired_count)
         ORDER BY marker_token",
        )
        .storage()?
        .query_map([label], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    for (token, since, dropped) in &rows {
        join_loss_tx(conn, label, 0, *token, *dropped, *since, true)?;
        conn.execute_cached(
            "UPDATE account_delivery_loss_evidence SET imported_count=dropped_count
            WHERE account_label=?1 AND cause=0 AND marker_token=?2",
            params![label, token],
        )
        .storage()?;
    }
    Ok(!rows.is_empty())
}

/// Selection may cover a subset. Additional unrelated obligations do not
/// invalidate it; account-wide loss/route/inventory fences remain conservative.
fn selected_fence_matches(
    current: &RecoveryRevisionFence,
    selected: &RecoveryRevisionFence,
) -> bool {
    current.inventory_revision == selected.inventory_revision
        && selected_completion_fence_matches(current, selected)
}

// Installed scopes carry their own inventory invalidation tokens. Global
// inventory churn still fences installing a plan, but not unrelated completion.
fn selected_completion_fence_matches(
    current: &RecoveryRevisionFence,
    selected: &RecoveryRevisionFence,
) -> bool {
    current.loss_revision == selected.loss_revision
        && current.route_revision == selected.route_revision
        && !selected.obligations.is_empty()
        && selected
            .obligations
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        && selected.obligations.iter().all(|(id, revision)| {
            current
                .obligations
                .binary_search_by_key(id, |(candidate, _)| *candidate)
                .is_ok_and(|index| current.obligations[index].1 == *revision)
        })
}

impl SqliteAccountStorage {
    pub fn recovery_retry_state(&self) -> StorageResult<RecoveryRetryState> {
        let conn = self.lock()?;
        retry_state(&conn)
    }

    pub fn recovery_revision_fence(&self) -> StorageResult<RecoveryRevisionFence> {
        let conn = self.lock()?;
        revision_fence(&conn)
    }

    /// Observe current desired route/capability policy, not a historical goal.
    /// Reconnect/open with an identical snapshot is a read-equivalent no-op.
    /// Changed policy invalidates in-flight results and rechecks pending demand,
    /// but never forgives its durable retry reservation.
    pub fn observe_recovery_route_snapshot(&self, snapshot: [u8; 32]) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let previous: Option<Vec<u8>> = conn.query_row_cached(
                "SELECT route_snapshot FROM account_recovery_state WHERE singleton=1", [], |row| row.get(0),
            ).storage()?;
            if previous.as_deref() == Some(snapshot.as_slice()) { return Ok(false); }
            let changed = previous.is_some() || conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_recovery_scopes WHERE snapshot_state=1)", [], |row| row.get::<_,bool>(0),
            ).storage()?;
            conn.execute_cached("UPDATE account_recovery_state SET route_snapshot=?1,route_revision=route_revision+?2 WHERE singleton=1",
                params![snapshot.as_slice(),i64::from(changed)]).storage()?;
            if changed {
                conn.execute_cached("UPDATE account_recovery_obligations SET revision=revision+1,eligibility=0 WHERE state=0", []).storage()?;
            }
            Ok(changed)
        })
    }

    /// Automatic plans omit quiescent demand even when unrelated eligible work
    /// is present. Explicit selection may investigate that demand once.
    pub fn recovery_eligible_revision_fence(
        &self,
        explicit: bool,
    ) -> StorageResult<RecoveryRevisionFence> {
        let conn = self.lock()?;
        let mut fence = revision_fence(&conn)?;
        let mut selected = Vec::new();
        for (id, revision) in fence.obligations {
            let eligible: bool = conn.query_row_cached(
                "SELECT eligibility IN (0,1) OR ?2 FROM account_recovery_obligations WHERE id=?1",
                params![id.as_slice(), explicit], |row| row.get(0),
            ).storage()?;
            if eligible {
                selected.push((id, revision));
            }
        }
        fence.obligations = selected;
        Ok(fence)
    }

    /// Reserve pacing before an executor can have external effects. No policy
    /// constant lives in storage: the owner supplies the already-selected delay.
    /// A cancelled caller leaves both demand and this reservation durable.
    pub fn reserve_recovery_attempt(
        &self,
        expected: &RecoveryRevisionFence,
        now_ms: u64,
        delay_ms: u64,
        explicit_override: bool,
    ) -> StorageResult<Option<RecoveryRetryState>> {
        self.reserve_recovery_work(expected, None, now_ms, delay_ms, explicit_override)
    }

    /// One account reservation for coverage, bounded comparison, or both.
    pub fn reserve_recovery_work(
        &self,
        expected: &RecoveryRevisionFence,
        comparison_revision: Option<u64>,
        now_ms: u64,
        delay_ms: u64,
        explicit_override: bool,
    ) -> StorageResult<Option<RecoveryRetryState>> {
        let now = sqlite_integer(now_ms)?;
        let delay = sqlite_integer(delay_ms)?;
        let due = now.checked_add(delay).ok_or_else(|| {
            StorageError::Serialization("recovery deadline outside supported range".into())
        })?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let state = retry_state(&conn)?;
            let unimported: bool = conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_delivery_loss_evidence WHERE (imported_count IS NULL OR dropped_count > imported_count))",
                [], |row| row.get(0),
            ).storage()?;
            // One account-device identity per database: all loss causes must
            // be imported by that account owner before any scoped reservation.
            if unimported || !comparison::work_fence_matches(&revision_fence(&conn)?, expected, comparison_revision.is_some())
                || !comparison::selection_matches(&conn, comparison_revision, explicit_override)?
                || (!explicit_override && now_ms < state.not_before_ms)
            {
                return Ok(None);
            }
            let mut eligible = true;
            for (id, _) in &expected.obligations {
                let unknown_format: bool = conn.query_row_cached(
                    "SELECT EXISTS(SELECT 1 FROM account_recovery_scopes
                     WHERE obligation_id = ?1 AND scope_format != 1)",
                    [id.as_slice()], |row| row.get(0),
                ).storage()?;
                if unknown_format {
                    return Err(StorageError::Serialization("unsupported recovery scope format".into()));
                }
                eligible &= conn.query_row_cached(
                    "SELECT EXISTS(SELECT 1 FROM account_recovery_obligations
                     WHERE id = ?1 AND state = 0 AND (eligibility IN (0, 1) OR ?2))",
                    params![id.as_slice(), explicit_override], |row| row.get::<_, bool>(0),
                ).storage()?;
            }
            if !eligible { return Ok(None); }
            conn.execute_cached(
                "UPDATE account_recovery_state SET next_attempt = next_attempt + 1,
                 retry_ordinal = retry_ordinal + 1, retry_recorded_at_ms = ?1,
                 retry_delay_ms = ?2, retry_not_before_ms = ?3 WHERE singleton = 1",
                params![now, delay, due],
            ).storage()?;
            Ok(Some(retry_state(&conn)?))
        })
    }

    /// The worker calls this only for newly and durably retained input inside
    /// the grant's scope. Engine progress, duplicate delivery and SDK counters
    /// are not admission. Reset backoff without allowing a new activation less
    /// than the minimum delay after this progress checkpoint.
    pub fn checkpoint_recovery_progress(
        &self,
        expected: &RecoveryRevisionFence,
        attempt_serial: u64,
        now_ms: u64,
        minimum_delay_ms: u64,
    ) -> StorageResult<bool> {
        let due = now_ms.checked_add(minimum_delay_ms).ok_or_else(|| {
            StorageError::Serialization("recovery deadline outside supported range".into())
        })?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let prior = retry_state(&conn)?;
            if attempt_serial == 0
                || prior.attempt_serial != attempt_serial
                || prior.ordinal <= 1
                || !selected_fence_matches(&revision_fence(&conn)?, expected)
                || !plan::no_unimported_loss(&conn)?
            {
                return Ok(false);
            }
            conn.execute_cached(
                "UPDATE account_recovery_state SET retry_ordinal=1,retry_recorded_at_ms=?1,
                 retry_delay_ms=?2,retry_not_before_ms=?3 WHERE singleton=1",
                params![
                    sqlite_integer(now_ms)?,
                    sqlite_integer(minimum_delay_ms)?,
                    sqlite_integer(due)?
                ],
            )
            .storage()?;
            Ok(true)
        })
    }

    /// Reconstruct one process-local deadline at open. A backward clock rebases
    /// once; forward movement permits at most one subsequent reservation.
    pub fn restore_recovery_retry(
        &self,
        now_ms: u64,
        maximum_delay_ms: u64,
    ) -> StorageResult<RecoveryRetryState> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let state = retry_state(&conn)?;
            if now_ms < state.recorded_at_ms || state.delay_ms > maximum_delay_ms {
                let delay = state.delay_ms.min(maximum_delay_ms);
                let due = now_ms.checked_add(delay).ok_or_else(|| {
                    StorageError::Serialization("recovery deadline outside supported range".into())
                })?;
                conn.execute_cached(
                    "UPDATE account_recovery_state SET retry_recorded_at_ms = ?1,
                     retry_delay_ms = ?2, retry_not_before_ms = ?3 WHERE singleton = 1",
                    params![
                        sqlite_integer(now_ms)?,
                        sqlite_integer(delay)?,
                        sqlite_integer(due)?
                    ],
                )
                .storage()?;
            }
            retry_state(&conn)
        })
    }

    /// Called only at the account mutation boundary. Evidence acknowledgment and
    /// demand creation share a transaction, so cancellation cannot lose either.
    pub fn synchronize_account_delivery_loss(&self, label: &str) -> StorageResult<()> {
        let pending: bool = self
            .lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_delivery_loss_evidence
             WHERE account_label = ?1 AND (imported_count IS NULL OR dropped_count > imported_count))",
                [label],
                |row| row.get(0),
            )
            .storage()?;
        if !pending {
            return Ok(());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            // Import one row at a time in this transaction. The unresolved
            // evidence set is deliberately not disk-capped; do not mirror it
            // into an unbounded temporary Vec on reopen.
            let mut cursor = (-1_i64, -1_i64);
            loop {
                let row = conn.query_row_cached(
                    "SELECT cause,marker_token,pending_since,dropped_count FROM account_delivery_loss_evidence
                     WHERE account_label=?1 AND (cause,marker_token)>(?2,?3)
                     AND (imported_count IS NULL OR dropped_count>imported_count)
                     ORDER BY cause,marker_token LIMIT 1", params![label,cursor.0,cursor.1],
                    |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?))
                ).optional().storage()?;
                let Some((cause, token, observed_at, dropped)) = row else { break; };
                cursor = (cause, token);
                join_loss_tx(&conn, label, cause, token, dropped, observed_at, true)?;
                conn.execute_cached(
                    "UPDATE account_delivery_loss_evidence SET imported_count = ?3
                     WHERE account_label = ?1 AND cause = ?4 AND marker_token = ?2",
                    params![label, token, dropped, cause],
                ).storage()?;
            }
            Ok(())
        })
    }

    /// Evidence-only write for the approved account-local overflow marker task.
    /// Distinct generations cannot overwrite each other; count growth is monotonic.
    pub fn record_account_delivery_loss(
        &self,
        label: &str,
        marker_token: u64,
        dropped_count: u64,
        observed_at_seconds: u64,
    ) -> StorageResult<()> {
        self.record_account_recovery_loss(
            label,
            RecoveryLossCause::Queue,
            marker_token,
            dropped_count,
            observed_at_seconds,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlCipherKey;

    fn fixture() -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("alice").unwrap();
        store
    }

    #[test]
    fn review_legacy_clear_preserves_each_generation_across_reopen() {
        for (old, newer) in [(10, 90), (90, 10)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("loss.sqlite");
            let key = SqlCipherKey::new("generation retirement test").unwrap();
            {
                let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
                store.ensure_account_projection("alice").unwrap();
                store
                    .mark_account_delivery_recovery("alice", old, 2)
                    .unwrap();
                store
                    .record_account_delivery_loss("alice", newer, 15, 10)
                    .unwrap();
                store.synchronize_account_delivery_loss("alice").unwrap();
                assert!(!store.clear_account_delivery_recovery("alice", old).unwrap());
            }
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.synchronize_account_delivery_loss("alice").unwrap();
            let pending = store.account_delivery_recovery("alice").unwrap().unwrap();
            assert_eq!((pending.marker_token, pending.dropped_count), (newer, 15));
            // A low-level retirement covers only its token, never all joined loss.
            assert!(
                !store
                    .clear_account_delivery_recovery("alice", newer)
                    .unwrap()
            );
            assert_eq!(
                store
                    .account_delivery_recovery("alice")
                    .unwrap()
                    .unwrap()
                    .marker_token,
                old
            );
            assert!(store.clear_account_delivery_recovery("alice", old).unwrap());
            assert!(store.account_delivery_recovery("alice").unwrap().is_none());
            store
                .record_account_delivery_loss("alice", newer, 15, 11)
                .unwrap();
            store.synchronize_account_delivery_loss("alice").unwrap();
            assert!(store.account_delivery_recovery("alice").unwrap().is_none());
            store
                .record_account_delivery_loss("alice", newer, 16, 12)
                .unwrap();
            store.synchronize_account_delivery_loss("alice").unwrap();
            assert_eq!(
                store
                    .account_delivery_recovery("alice")
                    .unwrap()
                    .unwrap()
                    .dropped_count,
                16
            );
        }
    }

    #[test]
    fn review_legacy_clear_rollback_preserves_retirement_and_pending_loss() {
        let store = fixture();
        store
            .mark_account_delivery_recovery("alice", 10, 2)
            .unwrap();
        store
            .record_account_delivery_loss("alice", 90, 15, 10)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        let before = store.recovery_revision_fence().unwrap();
        store.lock().unwrap().execute_batch("CREATE TRIGGER reject_rejoin BEFORE INSERT ON account_recovery_obligations BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        assert!(store.clear_account_delivery_recovery("alice", 90).is_err());
        assert_eq!(store.recovery_revision_fence().unwrap(), before);
        assert_eq!(
            store
                .account_delivery_recovery("alice")
                .unwrap()
                .unwrap()
                .marker_token,
            90
        );
        assert!(store.lock().unwrap().query_row("SELECT legacy_retired_count IS NULL FROM account_delivery_loss_evidence WHERE marker_token=90",[],|r|r.get::<_,bool>(0)).unwrap());
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_rejoin")
            .unwrap();
        assert!(!store.clear_account_delivery_recovery("alice", 90).unwrap());
        assert!(store.clear_account_delivery_recovery("alice", 10).unwrap());
    }

    #[test]
    fn review_adoption_fences_prior_generation_without_resetting_quiescence() {
        let store = fixture();
        store
            .mark_account_delivery_recovery("alice", 20, 4)
            .unwrap();
        store
            .mark_account_delivery_recovery("alice", 10, 6)
            .unwrap();
        store
            .mark_account_delivery_recovery("alice", 20, 4)
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET eligibility=3")
            .unwrap();
        let before = store.recovery_revision_fence().unwrap();
        let retry = store.recovery_retry_state().unwrap();
        store
            .mark_account_delivery_recovery("alice", 10, 6)
            .unwrap();
        let after = store.recovery_revision_fence().unwrap();
        assert!(after.loss_revision > before.loss_revision);
        assert!(after.obligations[0].1 > before.obligations[0].1);
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT eligibility FROM account_recovery_obligations",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            3
        );
        assert!(
            store
                .reserve_recovery_attempt(&before, 1000, 15000, true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn review_mixed_selection_cannot_reserve_for_quiescent_demand() {
        let store = fixture();
        store.mark_account_delivery_recovery("alice", 1, 4).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE account_recovery_obligations SET eligibility=3;
            INSERT INTO cgka_groups(id,epoch,record) VALUES(x'01',7,x'00')",
            )
            .unwrap();
        store
            .arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
                group_id_hex: "01".into(),
                stalled_epoch: 7,
            }])
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        let retry = store.recovery_retry_state().unwrap();
        assert_eq!(fence.obligations.len(), 2);
        assert!(
            store
                .reserve_recovery_attempt(&fence, 1000, 15000, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        assert!(
            store
                .reserve_recovery_attempt(&fence, 1000, 15000, true)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn duplicate_and_stale_epoch_observations_preserve_quiescence() {
        let store = fixture();
        store
            .lock()
            .unwrap()
            .execute_batch("INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 7, x'00')")
            .unwrap();
        let arm = |epoch| {
            store
                .arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
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
        let before = store.recovery_revision_fence().unwrap();
        arm(7);
        arm(6);
        assert_eq!(store.recovery_revision_fence().unwrap(), before);
        assert!(
            store
                .reserve_recovery_attempt(&before, 1000, 15000, false)
                .unwrap()
                .is_none()
        );
        arm(8);
        assert!(
            store
                .reserve_recovery_attempt(
                    &store.recovery_revision_fence().unwrap(),
                    1000,
                    15000,
                    false
                )
                .unwrap()
                .is_some()
        );
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET state = 1")
            .unwrap();
        arm(8);
        assert!(
            store
                .recovery_revision_fence()
                .unwrap()
                .obligations
                .is_empty()
        );
    }

    #[test]
    fn notification_loss_imports_independent_demand_without_blocking_forever() {
        let store = fixture();
        store.lock().unwrap().execute_batch(
            "INSERT INTO account_delivery_loss_evidence(account_label,cause,marker_token,pending_since,dropped_count)
             VALUES ('alice',1,7,10,0)"
        ).unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        assert_eq!(fence.obligations.len(), 1);
        assert!(store.account_delivery_recovery("alice").unwrap().is_none());
        assert!(
            store
                .reserve_recovery_attempt(&fence, 1000, 15000, false)
                .unwrap()
                .is_some()
        );
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), fence);
    }

    #[test]
    fn late_old_marker_does_not_replace_current_token_or_duplicate_loss_revision() {
        let store = fixture();
        store
            .mark_account_delivery_recovery("alice", 90, 4)
            .unwrap();
        let first = store.recovery_revision_fence().unwrap();
        store
            .record_account_delivery_loss("alice", 90, 4, 10)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), first);
        store
            .mark_account_delivery_recovery("alice", 10, 6)
            .unwrap();
        let current = store.recovery_revision_fence().unwrap();
        store
            .record_account_delivery_loss("alice", 90, 4, 20)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(
            store
                .account_delivery_recovery("alice")
                .unwrap()
                .unwrap()
                .marker_token,
            10
        );
        assert_eq!(store.recovery_revision_fence().unwrap(), current);
        // A newly imported token must replace the compatibility pointer so an
        // older token-only clear fails. Its numerical value is not an ordering;
        // all generations retain separate evidence and retirement watermarks.
        store
            .record_account_delivery_loss("alice", 80, 3, 30)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(
            store
                .account_delivery_recovery("alice")
                .unwrap()
                .unwrap()
                .marker_token,
            80
        );
        assert!(store.recovery_revision_fence().unwrap().loss_revision > current.loss_revision);
    }

    #[test]
    fn worker_adopts_already_imported_generation_without_rearming_it() {
        let store = fixture();
        store
            .mark_account_delivery_recovery("alice", 20, 4)
            .unwrap();
        store
            .record_account_delivery_loss("alice", 10, 6, 10)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET eligibility = 3")
            .unwrap();
        let before = store.recovery_revision_fence().unwrap();
        store
            .mark_account_delivery_recovery("alice", 10, 6)
            .unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), before);
        assert_eq!(
            store
                .account_delivery_recovery("alice")
                .unwrap()
                .unwrap()
                .marker_token,
            10
        );
        assert!(
            store
                .reserve_recovery_attempt(&before, 1000, 15000, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn legacy_retirement_keeps_evidence_watermark_for_a_late_writer() {
        let store = fixture();
        store
            .record_account_delivery_loss("alice", 3, 9, 10)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert!(store.clear_account_delivery_recovery("alice", 3).unwrap());
        let before = store.recovery_revision_fence().unwrap();
        store
            .record_account_delivery_loss("alice", 3, 9, 11)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), before);
        store
            .record_account_delivery_loss("alice", 3, 10, 12)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(
            store.recovery_revision_fence().unwrap().obligations.len(),
            1
        );
    }

    #[test]
    fn reservation_fences_selected_demand_without_blocking_on_unrelated_joins() {
        let store = fixture();
        store.mark_account_delivery_recovery("alice", 1, 1).unwrap();
        let selected = store.recovery_revision_fence().unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 7, x'00')")
            .unwrap();
        store
            .arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
                group_id_hex: "01".into(),
                stalled_epoch: 7,
            }])
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE account_recovery_obligations SET eligibility = 3 WHERE cause = 0",
            )
            .unwrap();
        assert!(
            store
                .reserve_recovery_attempt(&selected, 1000, 15000, false)
                .unwrap()
                .is_none(),
            "unselected eligible demand cannot authorize the selected quiescent scope"
        );
        assert!(
            store
                .reserve_recovery_attempt(&selected, 1000, 15000, true)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store.recovery_revision_fence().unwrap().obligations.len(),
            2
        );
    }

    #[test]
    fn same_epoch_release_fences_old_plans_and_rolls_back_as_one_unit() {
        let store = fixture();
        store
            .lock()
            .unwrap()
            .execute_batch("INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 7, x'00')")
            .unwrap();
        store
            .arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
                group_id_hex: "01".into(),
                stalled_epoch: 7,
            }])
            .unwrap();
        let before = store.recovery_revision_fence().unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO cgka_released_transport_receipts(id,group_id,epoch) VALUES (x'02', x'01', 7);
             CREATE TRIGGER fail_release_ack BEFORE DELETE ON cgka_released_transport_receipts
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert!(store.consume_released_transport_receipts().is_err());
        assert_eq!(store.recovery_revision_fence().unwrap(), before);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_release_ack")
            .unwrap();
        assert_eq!(
            store.consume_released_transport_receipts().unwrap().len(),
            1
        );
        let after = store.recovery_revision_fence().unwrap();
        assert_eq!(after.inventory_revision, before.inventory_revision + 1);
        assert_eq!(after.obligations[0].1, before.obligations[0].1 + 1);
        assert!(
            store
                .reserve_recovery_attempt(&before, 1000, 15000, true)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.recovery_revision_fence().unwrap(), after);
    }

    #[test]
    fn legacy_read_does_not_take_mutation_ownership_from_the_worker() {
        let store = fixture();
        store
            .record_account_delivery_loss("alice", 9, 1, 10)
            .unwrap();
        assert!(store.account_delivery_recovery("alice").unwrap().is_none());
        assert!(
            store
                .recovery_revision_fence()
                .unwrap()
                .obligations
                .is_empty()
        );
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert!(store.account_delivery_recovery("alice").unwrap().is_some());
    }

    #[test]
    fn zero_count_loss_is_still_imported_as_pending_evidence() {
        let store = fixture();
        store
            .record_account_delivery_loss("alice", 9, 0, 10)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(
            store.recovery_revision_fence().unwrap().obligations.len(),
            1
        );
        assert_eq!(store.recovery_revision_fence().unwrap().loss_revision, 1);
    }

    #[test]
    fn unknown_scope_format_cannot_authorize_an_attempt() {
        let store = fixture();
        store.mark_account_delivery_recovery("alice", 1, 1).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_scopes SET scope_format = 2")
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        assert!(
            store
                .reserve_recovery_attempt(&fence, 1000, 15000, true)
                .is_err()
        );
        assert_eq!(store.recovery_retry_state().unwrap().attempt_serial, 0);
    }

    #[test]
    fn loss_writer_is_evidence_only_and_cannot_overwrite_another_generation() {
        let store = fixture();
        store
            .record_account_delivery_loss("alice", 1, 4, 10)
            .unwrap();
        store
            .record_account_delivery_loss("alice", 2, 7, 11)
            .unwrap();
        store
            .record_account_delivery_loss("alice", 1, 2, 12)
            .unwrap();
        let before = store.recovery_revision_fence().unwrap();
        assert!(before.obligations.is_empty());
        assert!(
            store
                .reserve_recovery_attempt(&before, 1000, 15000, true)
                .unwrap()
                .is_none()
        );
        store.synchronize_account_delivery_loss("alice").unwrap();
        let joined = store.recovery_revision_fence().unwrap();
        assert_eq!(joined.obligations.len(), 1);
        assert_eq!(joined.loss_revision, 2);
        let counts: Vec<i64> = store
            .lock()
            .unwrap()
            .prepare(
                "SELECT dropped_count FROM account_delivery_loss_evidence ORDER BY marker_token",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(counts, vec![4, 7]);
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), joined);
        store
            .record_account_delivery_loss("alice", 2, 8, 13)
            .unwrap();
        assert!(
            store
                .reserve_recovery_attempt(&joined, 1000, 15000, true)
                .unwrap()
                .is_none()
        );
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap().loss_revision, 3);
        assert!(
            store
                .reserve_recovery_attempt(&joined, 1000, 15000, true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn evidence_import_failure_rolls_back_demand_and_acknowledgment() {
        let store = fixture();
        store
            .record_account_delivery_loss("alice", 3, 9, 10)
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_loss_import BEFORE UPDATE ON account_delivery_loss_evidence
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert!(store.synchronize_account_delivery_loss("alice").is_err());
        assert!(
            store
                .recovery_revision_fence()
                .unwrap()
                .obligations
                .is_empty()
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT imported_count FROM account_delivery_loss_evidence",
                    [],
                    |r| r.get::<_, Option<i64>>(0),
                )
                .unwrap(),
            None
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_loss_import")
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(
            store.recovery_revision_fence().unwrap().obligations.len(),
            1
        );
    }

    #[test]
    fn reservation_survives_reopen_and_clock_changes_without_free_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.sqlite");
        let key = SqlCipherKey::new("owner retry test").unwrap();
        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.ensure_account_projection("alice").unwrap();
            store.mark_account_delivery_recovery("alice", 1, 1).unwrap();
            let fence = store.recovery_revision_fence().unwrap();
            let reservation = store
                .reserve_recovery_attempt(&fence, 100000, 15000, false)
                .unwrap()
                .unwrap();
            assert_eq!(reservation.attempt_serial, 1);
            assert_eq!(reservation.not_before_ms, 115000);
        }
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        assert_eq!(
            store
                .restore_recovery_retry(105000, 300000)
                .unwrap()
                .not_before_ms,
            115000
        );
        assert!(
            store
                .reserve_recovery_attempt(&fence, 105000, 30000, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .restore_recovery_retry(90000, 300000)
                .unwrap()
                .not_before_ms,
            105000
        );
        assert_eq!(
            store
                .restore_recovery_retry(91000, 300000)
                .unwrap()
                .not_before_ms,
            105000
        );
        assert!(
            store
                .reserve_recovery_attempt(&fence, 104999, 30000, false)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .reserve_recovery_attempt(&fence, 1000000, 30000, false)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .reserve_recovery_attempt(&fence, 1000000, 30000, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.recovery_retry_state().unwrap().ordinal, 2);
        assert_eq!(store.recovery_revision_fence().unwrap(), fence);
    }

    #[test]
    fn duplicate_joins_do_not_move_retry_but_new_count_fences_old_plans() {
        let store = fixture();
        store.mark_account_delivery_recovery("alice", 1, 4).unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        let reserved = store
            .reserve_recovery_attempt(&fence, 100000, 15000, false)
            .unwrap()
            .unwrap();
        store.mark_account_delivery_recovery("alice", 1, 4).unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), fence);
        assert_eq!(store.recovery_retry_state().unwrap(), reserved);
        store.mark_account_delivery_recovery("alice", 1, 5).unwrap();
        assert_ne!(store.recovery_revision_fence().unwrap(), fence);
        assert_eq!(store.recovery_retry_state().unwrap(), reserved);
        assert!(
            store
                .reserve_recovery_attempt(&fence, 115000, 15000, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn incapable_pending_scope_does_not_wake_on_retry_deadline() {
        let store = fixture();
        store.mark_account_delivery_recovery("alice", 1, 4).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET eligibility = 3;")
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        for now in [0, 300000, 600000, 1000000] {
            assert!(
                store
                    .reserve_recovery_attempt(&fence, now, 300000, false)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            store
                .reserve_recovery_attempt(&fence, 1000000, 300000, true)
                .unwrap()
                .is_some()
        );
        assert_eq!(store.recovery_revision_fence().unwrap(), fence);
    }
}
