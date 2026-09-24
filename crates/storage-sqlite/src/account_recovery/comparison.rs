//! Bounded operational comparison. This slot is never a coverage predicate.
use super::*;
use cgka_traits::StorageProvider;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryComparisonPlan {
    pub fence: RecoveryRevisionFence,
    pub live_since_seconds: Option<u64>,
    pub routes: Vec<RecoveryScopePlan>,
    /// Only transiently failed selected routes survive settlement. Empty after
    /// a serviced unknown/partial pass; unattempted routes remain coverage debt.
    pub retry_routes: Vec<u64>,
}

pub struct RecoveryComparison {
    pub revision: u64,
    pub settled_revision: u64,
    pub requested_until_seconds: u64,
    pub attempt_serial: u64,
    pub frozen_revision: u64,
    pub plan: Option<RecoveryComparisonPlan>,
    pub blocked_route_revision: Option<u64>,
}

impl RecoveryComparison {
    pub fn pending(&self) -> bool {
        self.revision > self.settled_revision
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecoveryComparisonOutcome {
    ServicedUnknown,
    ServicedPartial,
    TransientFailure,
    /// Only affirmative backend-wide capability evidence qualifies.
    Unsupported,
}

fn invalid() -> StorageError {
    StorageError::Serialization("invalid recovery comparison".into())
}

fn read(conn: &Connection) -> StorageResult<RecoveryComparison> {
    let (revision, settled, until, attempt, frozen, format, bytes, blocked) = conn.query_row_cached(
        "SELECT revision,settled_revision,requested_until_seconds,attempt_serial,frozen_revision,
         plan_format,plan_payload,blocked_route_revision FROM account_recovery_comparison WHERE singleton=1",
        [], |r| Ok((r.get::<_, i64>(0)?,r.get::<_, i64>(1)?,r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,r.get::<_, i64>(4)?,r.get::<_, i64>(5)?,
            r.get::<_, Option<Vec<u8>>>(6)?,r.get::<_, Option<i64>>(7)?)),
    ).storage()?;
    if format != 1 {
        return Err(invalid());
    }
    let plan: Option<RecoveryComparisonPlan> = bytes
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| invalid()))
        .transpose()?;
    if let Some(plan) = &plan {
        validate_plan(plan)?;
    }
    Ok(RecoveryComparison {
        revision: i64_to_u64(revision)?,
        settled_revision: i64_to_u64(settled)?,
        requested_until_seconds: i64_to_u64(until)?,
        attempt_serial: i64_to_u64(attempt)?,
        frozen_revision: i64_to_u64(frozen)?,
        plan,
        blocked_route_revision: blocked.map(i64_to_u64).transpose()?,
    })
}

fn validate_plan(plan: &RecoveryComparisonPlan) -> StorageResult<()> {
    if plan
        .routes
        .windows(2)
        .any(|r| r[0].scope_id >= r[1].scope_id)
        || plan.routes.iter().any(|r| {
            r.route_kind > 1
                || r.since_seconds.is_none_or(|since| since > r.until_seconds)
                || (r.route_kind == 1 && (r.group_id.is_none() || r.transport_group_id.is_none()))
                || r.admitted_endpoints.is_empty()
                || r.admitted_endpoints.windows(2).any(|e| e[0] >= e[1])
        })
        || plan.retry_routes.windows(2).any(|r| r[0] >= r[1])
        || plan
            .retry_routes
            .iter()
            .any(|id| !plan.routes.iter().any(|r| r.scope_id == *id))
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn work_fence_matches(
    current: &RecoveryRevisionFence,
    expected: &RecoveryRevisionFence,
    comparison: bool,
) -> bool {
    if !expected.obligations.is_empty() {
        return selected_fence_matches(current, expected);
    }
    comparison
        && current.loss_revision == expected.loss_revision
        && current.route_revision == expected.route_revision
        && current.inventory_revision == expected.inventory_revision
}

pub(super) fn selection_matches(
    conn: &Connection,
    revision: Option<u64>,
    explicit: bool,
) -> StorageResult<bool> {
    let Some(revision) = revision else {
        return Ok(true);
    };
    let slot = read(conn)?;
    let route = revision_fence(conn)?.route_revision;
    Ok(slot.pending()
        && slot.revision == revision
        && (explicit || slot.blocked_route_revision.is_none_or(|r| r != route)))
}

impl SqliteAccountStorage {
    pub fn recovery_comparison(&self) -> StorageResult<RecoveryComparison> {
        {
            let conn = self.lock()?;
            read(&conn)
        }
    }

    /// Join once per startup/caller. Debt is durable before a comparison can be reserved.
    pub fn join_recovery_comparison(
        &self,
        key: &[u8; 16],
        now_ms: u64,
        goals: &[RecoveryScopePlan],
    ) -> StorageResult<u64> {
        if goals.is_empty() {
            return Err(invalid());
        }
        self.with_transaction(|storage| {
            {
                let conn = storage.lock()?;
                let duplicate: bool = conn.query_row_cached(
                    "SELECT request_key IS ?1 FROM account_recovery_comparison WHERE singleton=1", [key.as_slice()], |r| r.get(0),
                ).storage()?;
                if duplicate { return Ok(read(&conn)?.revision); }
            }
            let unresolved_prior = {
                let conn = storage.lock()?;
                conn.query_row_cached("SELECT EXISTS(SELECT 1 FROM account_recovery_obligations o
                    JOIN account_recovery_scopes s ON s.obligation_id=o.id
                    WHERE o.demand_key='incremental' AND o.state=0 AND s.snapshot_state=0)",
                    [], |row| row.get::<_,bool>(0)).storage()?
            };
            let ticket = storage.request_recovery(RecoveryRequest::IncrementalHistory, now_ms)?;
            let stored = storage.recovery_scope_snapshots(ticket.id)?;
            let mut merged: Vec<_> = stored.iter().map(|s| s.plan.clone()).collect();
            for goal in goals {
                let mut goal = goal.clone();
                // An existing unresolved placeholder carries no proven lower
                // bound. Hydration cannot replace that older debt with the
                // newer comparison floor; only acquisition stays bounded.
                if unresolved_prior { goal.since_seconds = None; }
                if let Some(old) = merged.iter_mut().find(|s| s.route_kind == goal.route_kind
                    && s.group_id == goal.group_id && s.transport_group_id == goal.transport_group_id) {
                    old.since_seconds = old.since_seconds.zip(goal.since_seconds).map(|(a,b)| a.min(b));
                    old.until_seconds = old.until_seconds.max(goal.until_seconds);
                    old.required_endpoints.extend(goal.required_endpoints.iter().cloned());
                    old.required_endpoints.sort(); old.required_endpoints.dedup();
                    old.admitted_endpoints = goal.admitted_endpoints.clone();
                } else {
                    let mut goal = goal.clone();
                    goal.scope_id = merged.last().map_or(Ok(0), |s| s.scope_id.checked_add(1).ok_or_else(invalid))?;
                    merged.push(goal);
                }
            }
            {
                let conn = storage.lock()?;
                // Extending debt invalidates old coverage proof, never its parked
                // eligibility. The comparison slot owns only operational intent.
                conn.execute_cached("UPDATE account_recovery_obligations SET revision=revision+1,
                    state=0,eligibility=CASE WHEN eligibility IN (0,1) THEN 4 ELSE eligibility END,
                    updated_at_ms=MAX(updated_at_ms,?2) WHERE id=?1",
                    params![ticket.id.as_slice(), sqlite_integer(now_ms)?]).storage()?;
            }
            let mut fence = storage.recovery_revision_fence()?;
            fence.obligations.retain(|(id,_)| *id == ticket.id);
            if storage.install_recovery_scope_plan_inner(&fence, 0, ticket.id, &merged, false)?.is_none() {
                return Err(StorageError::Backend("comparison debt changed during join".into()));
            }
            let conn = storage.lock()?;
            conn.execute_cached("UPDATE account_recovery_comparison SET revision=revision+1,
                request_key=?1,requested_at_ms=?2,requested_until_seconds=MAX(requested_until_seconds,?3)
                WHERE singleton=1", params![key.as_slice(),sqlite_integer(now_ms)?,sqlite_integer(now_ms/1000)?]).storage()?;
            Ok(read(&conn)?.revision)
        })
    }

    /// Freeze this operational plan in the same transaction as any coverage
    /// scopes. The caller must roll back the whole transaction on a false result.
    pub fn install_recovery_comparison_plan(
        &self,
        revision: u64,
        attempt: u64,
        plan: &RecoveryComparisonPlan,
    ) -> StorageResult<bool> {
        validate_plan(plan)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if attempt == 0
                || retry_state(&conn)?.attempt_serial != attempt
                || !selection_matches(&conn, Some(revision), true)?
                || !work_fence_matches(&revision_fence(&conn)?, &plan.fence, true)
                || !plan::no_unimported_loss(&conn)?
            {
                return Ok(false);
            }
            // An operational grant cannot introduce a route/window/endpoint
            // that was never recorded as unresolved coverage debt.
            for route in &plan.routes {
                let payloads = conn
                    .prepare_cached(
                        "SELECT s.scope_format,s.scope_payload FROM account_recovery_scopes s
                     JOIN account_recovery_obligations o ON o.id=s.obligation_id
                     WHERE o.cause=5 AND o.state=0 AND s.snapshot_state=1
                     AND s.route_kind=?1 AND s.group_id IS ?2 AND s.transport_group_id IS ?3
                     AND (s.since_seconds IS NULL OR s.since_seconds<=?4) AND s.until_seconds>=?5",
                    )
                    .storage()?
                    .query_map(
                        params![
                            route.route_kind,
                            route.group_id,
                            route.transport_group_id.as_ref().map(|r| r.as_slice()),
                            route.since_seconds.map(sqlite_integer).transpose()?,
                            sqlite_integer(route.until_seconds)?
                        ],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
                    )
                    .storage()?
                    .collect::<Result<Vec<_>, _>>()
                    .storage()?;
                let mut covered = false;
                for (format, bytes) in payloads {
                    let debt = plan::decode_scope(format, &bytes)?;
                    covered |= route
                        .admitted_endpoints
                        .iter()
                        .all(|endpoint| debt.required_endpoints.contains(endpoint));
                }
                if !covered {
                    return Err(invalid());
                }
            }
            let mut frozen = plan.clone();
            // A cancelled executor has not serviced any selected route yet.
            frozen.retry_routes = frozen.routes.iter().map(|r| r.scope_id).collect();
            conn.execute_cached(
                "UPDATE account_recovery_comparison SET attempt_serial=?1,
                frozen_revision=?2,plan_format=1,plan_payload=?3 WHERE singleton=1",
                params![
                    sqlite_integer(attempt)?,
                    sqlite_integer(revision)?,
                    serde_json::to_vec(&frozen).map_err(|_| invalid())?
                ],
            )
            .storage()?;
            Ok(true)
        })
    }

    /// Only newly retained input in a frozen comparison can reset the account
    /// cost. This method grants no coverage or loss-acknowledgment authority.
    pub fn checkpoint_recovery_comparison_progress(
        &self,
        revision: u64,
        attempt: u64,
        expected: &RecoveryRevisionFence,
        now_ms: u64,
        minimum_delay_ms: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let slot = read(&conn)?;
            let retry = retry_state(&conn)?;
            if slot.settled_revision >= revision
                || slot.frozen_revision != revision
                || slot.attempt_serial != attempt
                || attempt == 0
                || retry.attempt_serial != attempt
                || retry.ordinal <= 1
                || slot.plan.as_ref().is_none_or(|p| p.fence != *expected)
                || !work_fence_matches(&revision_fence(&conn)?, expected, true)
                || !plan::no_unimported_loss(&conn)?
            {
                return Ok(false);
            }
            let due = now_ms.checked_add(minimum_delay_ms).ok_or_else(invalid)?;
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

    /// Servicing bounded unknown work never completes history. Persist a failed
    /// route subset before clearing any operational opportunity. Backend-wide
    /// Unsupported requires a separate affirmative capability key.
    pub fn settle_recovery_comparison(
        &self,
        revision: u64,
        attempt: u64,
        outcomes: &[(u64, RecoveryComparisonOutcome)],
        unsupported_key: Option<&[u8]>,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let slot = read(&conn)?;
            let Some(mut frozen) = slot.plan else { return Ok(false); };
            if slot.settled_revision >= revision || attempt == 0 || slot.attempt_serial != attempt || slot.frozen_revision != revision
                || retry_state(&conn)?.attempt_serial != attempt
                || !work_fence_matches(&revision_fence(&conn)?, &frozen.fence, true)
                || !plan::no_unimported_loss(&conn)? { return Ok(false); }
            if outcomes.len() != frozen.routes.len() || outcomes.windows(2).any(|x| x[0].0 >= x[1].0)
                || outcomes.iter().zip(&frozen.routes).any(|((id,_),r)| *id != r.scope_id)
                || outcomes.iter().any(|(_,o)| *o == RecoveryComparisonOutcome::Unsupported) != unsupported_key.is_some()
                || unsupported_key.is_some_and(|key| key.is_empty() || outcomes.iter().any(|(_,o)| *o != RecoveryComparisonOutcome::Unsupported))
            { return Err(invalid()); }
            frozen.retry_routes = outcomes.iter().filter(|(_,o)| *o == RecoveryComparisonOutcome::TransientFailure)
                .map(|(id,_)| *id).collect();
            let complete = frozen.retry_routes.is_empty() && unsupported_key.is_none();
            let outcome = if unsupported_key.is_some() { 3 } else if !frozen.retry_routes.is_empty() { 2 }
                else if outcomes.iter().any(|(_,o)| *o == RecoveryComparisonOutcome::ServicedPartial) { 1 } else { 0 };
            conn.execute_cached("UPDATE account_recovery_comparison SET
                settled_revision=CASE WHEN ?1 THEN MAX(settled_revision,?2) ELSE settled_revision END,
                blocked_route_revision=?3,blocked_capability_key=?4,plan_payload=?5,last_outcome=?6 WHERE singleton=1",
                params![complete,sqlite_integer(revision)?,unsupported_key.map(|_| sqlite_integer(frozen.fence.route_revision)).transpose()?,
                    unsupported_key,serde_json::to_vec(&frozen).map_err(|_| invalid())?,outcome]).storage()?;
            Ok(true)
        })
    }

    /// No capability is inferred from traffic. Call only when the backend's
    /// explicit capability contract changes; an unchanged key remains blocked.
    pub fn observe_recovery_comparison_capability(&self, key: &[u8]) -> StorageResult<()> {
        if key.is_empty() {
            return Err(invalid());
        }
        self.lock()?.execute_cached("UPDATE account_recovery_comparison SET blocked_route_revision=NULL,
            blocked_capability_key=NULL WHERE singleton=1 AND blocked_capability_key IS NOT NULL AND blocked_capability_key!=?1", [key]).storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> SqliteAccountStorage {
        SqliteAccountStorage::in_memory().unwrap()
    }
    fn scope() -> RecoveryScopePlan {
        RecoveryScopePlan {
            scope_id: 0,
            route_kind: 0,
            route_role: 0,
            group_id: None,
            transport_group_id: None,
            since_seconds: Some(10),
            until_seconds: 100,
            known_event_id: None,
            inventory_floor: None,
            required_endpoints: vec!["wss://relay.example".into()],
            admitted_endpoints: vec!["wss://relay.example".into()],
        }
    }

    #[test]
    fn comparison_join_persists_debt_before_reserving_and_coalesces_duplicates() {
        let s = storage();
        let before = s.recovery_retry_state().unwrap();
        let revision = s
            .join_recovery_comparison(&[1; 16], 100_000, &[scope()])
            .unwrap();
        assert!(s.recovery_comparison().unwrap().pending());
        let debt = s.pending_recovery_demands().unwrap();
        assert_eq!(debt.len(), 1);
        assert_eq!(debt[0].cause, RecoveryCause::IncrementalHistory);
        let plans = s.recovery_scope_snapshots(debt[0].ticket.id).unwrap();
        assert_eq!(plans[0].plan.until_seconds, 100);
        assert_eq!(plans[0].attempt_serial, 0);
        assert_eq!(
            revision,
            s.join_recovery_comparison(&[1; 16], 200_000, &[scope()])
                .unwrap()
        );
        assert_eq!(s.recovery_retry_state().unwrap(), before);
    }

    fn reserve(
        s: &SqliteAccountStorage,
        now: u64,
        routes: Vec<RecoveryScopePlan>,
    ) -> (u64, u64, RecoveryRevisionFence) {
        let revision = s.recovery_comparison().unwrap().revision;
        let mut fence = s.recovery_revision_fence().unwrap();
        fence.obligations.clear();
        let attempt = s
            .reserve_recovery_work(&fence, Some(revision), now, 15_000, false)
            .unwrap()
            .unwrap()
            .attempt_serial;
        assert!(
            s.install_recovery_comparison_plan(
                revision,
                attempt,
                &RecoveryComparisonPlan {
                    fence: fence.clone(),
                    live_since_seconds: Some(90),
                    routes,
                    retry_routes: vec![],
                }
            )
            .unwrap()
        );
        (revision, attempt, fence)
    }

    #[test]
    fn mixed_comparison_settlement_preserves_only_failed_selected_routes() {
        let s = storage();
        s.lock()
            .unwrap()
            .execute_batch("INSERT INTO cgka_groups(id,epoch,record) VALUES(x'07',0,x'00')")
            .unwrap();
        let first = scope();
        let mut second = scope();
        second.scope_id = 1;
        second.route_kind = 1;
        second.group_id = Some(vec![7]);
        second.transport_group_id = Some([7; 32]);
        s.join_recovery_comparison(&[1; 16], 100_000, &[first.clone(), second.clone()])
            .unwrap();
        let (revision, attempt, fence) = reserve(&s, 100_000, vec![first, second.clone()]);
        let cost = s.recovery_retry_state().unwrap();
        assert!(
            s.settle_recovery_comparison(
                revision,
                attempt,
                &[
                    (0, RecoveryComparisonOutcome::ServicedUnknown),
                    (1, RecoveryComparisonOutcome::TransientFailure),
                ],
                None
            )
            .unwrap()
        );
        let slot = s.recovery_comparison().unwrap();
        assert!(slot.pending());
        assert_eq!(slot.plan.unwrap().retry_routes, vec![1]);
        assert!(
            s.reserve_recovery_work(&fence, Some(revision), 114_999, 30_000, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(s.recovery_retry_state().unwrap(), cost);
        let (_, next, _) = reserve(&s, 115_000, vec![second]);
        assert!(
            s.settle_recovery_comparison(
                revision,
                next,
                &[(1, RecoveryComparisonOutcome::ServicedPartial)],
                None
            )
            .unwrap()
        );
        assert!(!s.recovery_comparison().unwrap().pending());
        assert!(
            !s.settle_recovery_comparison(
                revision,
                next,
                &[(1, RecoveryComparisonOutcome::TransientFailure)],
                None
            )
            .unwrap(),
            "a duplicate settlement cannot rewrite a serviced opportunity"
        );
        let debt = s.pending_recovery_demands().unwrap();
        assert_eq!(debt.len(), 1);
        assert_eq!(debt[0].eligibility, RecoveryEligibility::NeedsDeepRepair);
        assert!(
            !s.recovery_obligation_is_satisfied(debt[0].ticket.id, debt[0].ticket.revision)
                .unwrap()
        );
    }

    #[test]
    fn settlement_preserves_successor_and_rejects_loss_or_inventory_changes() {
        let s = storage();
        s.join_recovery_comparison(&[1; 16], 100_000, &[scope()])
            .unwrap();
        let (revision, attempt, _) = reserve(&s, 100_000, vec![scope()]);
        let cost = s.recovery_retry_state().unwrap();
        let mut successor = scope();
        successor.until_seconds = 101;
        s.join_recovery_comparison(&[2; 16], 101_000, &[successor])
            .unwrap();
        assert!(
            s.settle_recovery_comparison(
                revision,
                attempt,
                &[(0, RecoveryComparisonOutcome::ServicedUnknown)],
                None
            )
            .unwrap()
        );
        assert!(s.recovery_comparison().unwrap().pending());
        assert_eq!(s.recovery_retry_state().unwrap(), cost);
        let (revision, attempt, fence) = reserve(&s, 115_000, vec![scope()]);
        s.ensure_account_projection("alice").unwrap();
        s.mark_account_delivery_recovery("alice", 42, 100).unwrap();
        assert!(
            !s.settle_recovery_comparison(
                revision,
                attempt,
                &[(0, RecoveryComparisonOutcome::ServicedUnknown)],
                None
            )
            .unwrap()
        );
        assert!(
            !s.checkpoint_recovery_comparison_progress(revision, attempt, &fence, 116_000, 15_000)
                .unwrap()
        );
        assert!(s.account_delivery_recovery("alice").unwrap().is_some());
        assert!(s.recovery_comparison().unwrap().pending());
    }

    #[test]
    fn comparison_join_and_settlement_failures_roll_back_without_forgiving_cost() {
        let s = storage();
        s.lock().unwrap().execute_batch("CREATE TRIGGER reject_comparison BEFORE UPDATE ON account_recovery_comparison BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        assert!(
            s.join_recovery_comparison(&[1; 16], 100_000, &[scope()])
                .is_err()
        );
        assert!(s.pending_recovery_demands().unwrap().is_empty());
        assert!(!s.recovery_comparison().unwrap().pending());
        s.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_comparison")
            .unwrap();
        s.join_recovery_comparison(&[1; 16], 100_000, &[scope()])
            .unwrap();
        let (revision, attempt, _) = reserve(&s, 100_000, vec![scope()]);
        let cost = s.recovery_retry_state().unwrap();
        s.lock().unwrap().execute_batch("CREATE TRIGGER reject_comparison BEFORE UPDATE ON account_recovery_comparison BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        assert!(
            s.settle_recovery_comparison(
                revision,
                attempt,
                &[(0, RecoveryComparisonOutcome::ServicedUnknown)],
                None
            )
            .is_err()
        );
        assert!(s.recovery_comparison().unwrap().pending());
        assert_eq!(s.recovery_retry_state().unwrap(), cost);
    }

    #[test]
    fn comparison_cancellation_and_cost_survive_encrypted_reopen_and_repeated_starts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comparison.sqlite");
        let key = crate::SqlCipherKey::new("comparison reopen").unwrap();
        let cost;
        {
            let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            s.join_recovery_comparison(&[1; 16], 100_000, &[scope()])
                .unwrap();
            reserve(&s, 100_000, vec![scope()]);
            cost = s.recovery_retry_state().unwrap();
            s.close().unwrap(); // Future dropped after freeze: no settlement.
        }
        for boot in 2..5 {
            let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            let revision = s
                .join_recovery_comparison(&[boot; 16], 101_000, &[scope()])
                .unwrap();
            let slot = s.recovery_comparison().unwrap();
            assert!(slot.pending());
            assert_eq!(slot.plan.unwrap().retry_routes, vec![0]);
            let mut fence = s.recovery_revision_fence().unwrap();
            fence.obligations.clear();
            assert!(
                s.reserve_recovery_work(&fence, Some(revision), 101_000, 30_000, false)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(s.recovery_retry_state().unwrap(), cost);
            assert_eq!(s.pending_recovery_demands().unwrap().len(), 1);
            s.close().unwrap();
        }
    }

    #[test]
    fn unsupported_requires_backend_evidence_and_reopen_does_not_rearm_it() {
        let s = storage();
        s.join_recovery_comparison(&[1; 16], 100_000, &[scope()])
            .unwrap();
        let (revision, attempt, mut fence) = reserve(&s, 100_000, vec![scope()]);
        let unsupported = [(0, RecoveryComparisonOutcome::Unsupported)];
        assert!(
            s.settle_recovery_comparison(revision, attempt, &unsupported, None)
                .is_err()
        );
        assert!(
            s.settle_recovery_comparison(revision, attempt, &unsupported, Some(b"unsupported-v1"))
                .unwrap()
        );
        let revision = s
            .join_recovery_comparison(&[2; 16], 101_000, &[scope()])
            .unwrap();
        assert!(
            s.reserve_recovery_work(&fence, Some(revision), 900_000, 30_000, false)
                .unwrap()
                .is_none()
        );
        s.observe_recovery_comparison_capability(b"unsupported-v1")
            .unwrap();
        assert!(
            s.reserve_recovery_work(&fence, Some(revision), 900_000, 30_000, false)
                .unwrap()
                .is_none()
        );
        s.observe_recovery_comparison_capability(b"supported-v2")
            .unwrap();
        fence.obligations.clear();
        assert!(
            s.reserve_recovery_work(&fence, Some(revision), 900_000, 30_000, false)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn comparison_goal_extension_preserves_old_bounds_and_rejects_unknown_formats() {
        let s = storage();
        let mut old = scope();
        old.since_seconds = None;
        s.join_recovery_comparison(&[1; 16], 100_000, &[old])
            .unwrap();
        let mut new = scope();
        new.until_seconds = 200;
        new.required_endpoints.push("wss://second.example".into());
        s.join_recovery_comparison(&[2; 16], 200_000, &[new])
            .unwrap();
        let debt = s.pending_recovery_demands().unwrap();
        let plan = s
            .recovery_scope_snapshots(debt[0].ticket.id)
            .unwrap()
            .remove(0)
            .plan;
        assert_eq!(plan.since_seconds, None);
        assert_eq!(plan.until_seconds, 200);
        assert_eq!(plan.required_endpoints.len(), 2);
        s.lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_comparison SET plan_format=99")
            .unwrap();
        assert!(s.recovery_comparison().is_err());
        assert!(
            s.join_recovery_comparison(&[3; 16], 300_000, &[scope()])
                .is_err()
        );
        assert_eq!(
            s.recovery_scope_snapshots(debt[0].ticket.id).unwrap()[0]
                .plan
                .until_seconds,
            200
        );
    }

    #[test]
    fn comparison_cannot_freeze_unrecorded_debt_or_reset_after_inventory_invalidation() {
        let s = storage();
        let revision = s
            .join_recovery_comparison(&[1; 16], 100_000, &[scope()])
            .unwrap();
        let mut fence = s.recovery_revision_fence().unwrap();
        fence.obligations.clear();
        let attempt = s
            .reserve_recovery_work(&fence, Some(revision), 100_000, 15_000, false)
            .unwrap()
            .unwrap()
            .attempt_serial;
        let mut wider = scope();
        wider.since_seconds = Some(0);
        assert!(
            s.install_recovery_comparison_plan(
                revision,
                attempt,
                &RecoveryComparisonPlan {
                    fence: fence.clone(),
                    live_since_seconds: Some(90),
                    routes: vec![wider],
                    retry_routes: vec![],
                }
            )
            .is_err()
        );
        assert!(s.recovery_comparison().unwrap().plan.is_none());
        let (_, attempt, fence) = reserve(&s, 115_000, vec![scope()]);
        s.lock()
            .unwrap()
            .execute_batch(
                "UPDATE account_recovery_state SET inventory_revision=inventory_revision+1",
            )
            .unwrap();
        assert!(
            !s.checkpoint_recovery_comparison_progress(revision, attempt, &fence, 116_000, 15_000)
                .unwrap()
        );
        assert!(
            !s.settle_recovery_comparison(
                revision,
                attempt,
                &[(0, RecoveryComparisonOutcome::ServicedUnknown)],
                None
            )
            .unwrap()
        );
        assert!(s.recovery_comparison().unwrap().pending());
    }

    #[test]
    fn comparison_request_second_must_be_covered_by_joined_debt_window() {
        let old = RecoveryScopePlan {
            since_seconds: None,
            ..scope()
        };
        let mut current = scope();
        current.until_seconds = 101;

        let stale = storage();
        let revision = stale
            .join_recovery_comparison(&[1; 16], 101_000, std::slice::from_ref(&old))
            .unwrap();
        assert_eq!(
            stale.recovery_comparison().unwrap().requested_until_seconds,
            101
        );
        let debt = stale.pending_recovery_demands().unwrap();
        let debt_route = &stale.recovery_scope_snapshots(debt[0].ticket.id).unwrap()[0].plan;
        assert_eq!(debt_route.since_seconds, None);
        assert_eq!(debt_route.until_seconds, 100);
        assert_eq!(debt_route.required_endpoints, old.required_endpoints);
        let mut fence = stale.recovery_revision_fence().unwrap();
        fence.obligations.clear();
        let attempt = stale
            .reserve_recovery_work(&fence, Some(revision), 101_000, 15_000, false)
            .unwrap()
            .unwrap()
            .attempt_serial;
        assert!(
            stale
                .install_recovery_comparison_plan(
                    revision,
                    attempt,
                    &RecoveryComparisonPlan {
                        fence: fence.clone(),
                        live_since_seconds: None,
                        routes: vec![current.clone()],
                        retry_routes: Vec::new(),
                    },
                )
                .is_err(),
            "a newer request timestamp cannot extend operational coverage past debt"
        );

        let aligned = storage();
        let aligned_debt = RecoveryScopePlan {
            until_seconds: 101,
            ..old
        };
        aligned
            .join_recovery_comparison(&[1; 16], 101_000, std::slice::from_ref(&aligned_debt))
            .unwrap();
        // reserve asserts that the same operational route now installs.
        reserve(&aligned, 101_000, vec![current]);
    }

    #[test]
    fn comparison_join_does_not_narrow_preexisting_unresolved_history() {
        let s = storage();
        let prior = s
            .request_recovery(RecoveryRequest::IncrementalHistory, 1)
            .unwrap();
        assert!(s.recovery_scope_snapshots(prior.id).unwrap().is_empty());
        s.join_recovery_comparison(&[1; 16], 100_000, &[scope()])
            .unwrap();
        let debt = s.recovery_scope_snapshots(prior.id).unwrap();
        assert_eq!(
            debt[0].plan.since_seconds, None,
            "an unresolved earlier goal has no proven lower bound"
        );
        let (revision, attempt, _) = reserve(&s, 100_000, vec![scope()]);
        assert!(
            s.settle_recovery_comparison(
                revision,
                attempt,
                &[(0, RecoveryComparisonOutcome::ServicedUnknown)],
                None
            )
            .unwrap()
        );
        assert!(
            s.pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|d| d.ticket.id == prior.id)
        );
        assert_eq!(
            s.recovery_scope_snapshots(prior.id).unwrap()[0]
                .plan
                .since_seconds,
            None
        );
    }
}
