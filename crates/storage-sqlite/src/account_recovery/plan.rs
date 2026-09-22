//! Frozen recovery scopes and atomic, revision-checked outcome checkpoints.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryScopeOutcome {
    Covered,
    Partial,
    Unavailable,
    Unsupported,
    Excluded,
    Cancelled,
    BudgetExhausted,
    LossInvalidated,
    Unknown,
}

/// Endpoint identity is account-private and must never be logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEndpointCheckpoint {
    pub endpoint: String,
    pub outcome: RecoveryScopeOutcome,
    /// A bounded comparison or acquisition explicitly established exhaustiveness.
    /// EOSE, SDK seen-state, and aggregate success do not establish this fact.
    pub exhaustive: bool,
    /// Every input needed by this endpoint's comparison was durably retained.
    pub admission_complete: bool,
    /// The limited protocol-maintenance boundary for this current session.
    pub first_boundary: bool,
}

/// SQL columns are authoritative for route identity and historical bounds.
/// Only endpoint policy, attempt fences and outcomes live in the versioned blob.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryScopePlan {
    pub scope_id: u64,
    pub route_kind: u8,
    pub route_role: u8,
    pub group_id: Option<Vec<u8>>,
    pub transport_group_id: Option<[u8; 32]>,
    pub since_seconds: Option<u64>,
    pub until_seconds: u64,
    pub known_event_id: Option<[u8; 32]>,
    pub inventory_floor: Option<u64>,
    pub required_endpoints: Vec<String>,
    pub admitted_endpoints: Vec<String>,
}

/// Frozen goal and the latest qualified checkpoints. Unresolved migration rows
/// are deliberately omitted; callers must resolve them from hydrated routing.
pub struct StoredRecoveryScope {
    pub plan: RecoveryScopePlan,
    pub token: RecoveryScopeToken,
    pub checkpoints: Vec<RecoveryEndpointCheckpoint>,
    pub retained_known_event: bool,
    pub attempt_serial: u64,
    pub obligation_revision: u64,
    pub route_revision: u64,
    pub inventory_revision: u64,
    pub loss_revision: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryScopeToken {
    pub obligation_id: [u8; 16],
    pub scope_id: u64,
    pub revision: u64,
}

#[derive(Clone)]
pub struct RecoveryScopeCheckpoint {
    pub token: RecoveryScopeToken,
    pub endpoints: Vec<RecoveryEndpointCheckpoint>,
    /// The owner may set this only after validation and durable retention of the
    /// exact known event in the frozen plan. It is not an SDK receipt.
    pub retained_known_event: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum RecoveryEligibility {
    Ready = 0,
    Retry = 1,
    WaitingCapacity = 2,
    WaitingCapability = 3,
    NeedsDeepRepair = 4,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopePayloadV1 {
    required_endpoints: Vec<String>,
    admitted_endpoints: Vec<String>,
    checkpoints: Vec<RecoveryEndpointCheckpoint>,
    retained_known_event: bool,
    attempt_serial: u64,
    pub(super) obligation_revision: u64,
    pub(super) loss_revision: u64,
    pub(super) route_revision: u64,
    pub(super) inventory_revision: u64,
}

fn invalid_scope() -> StorageError {
    StorageError::Serialization("invalid recovery scope checkpoint".into())
}

pub(super) fn decode_scope(format: i64, bytes: &[u8]) -> StorageResult<ScopePayloadV1> {
    if format != 1 {
        return Err(StorageError::Serialization(
            "unsupported recovery scope format".into(),
        ));
    }
    let payload: ScopePayloadV1 = serde_json::from_slice(bytes).map_err(|_| invalid_scope())?;
    validate_endpoints(&payload.required_endpoints, &payload.admitted_endpoints)?;
    validate_checkpoints(&payload, &payload.checkpoints)?;
    Ok(payload)
}

fn encode_scope(payload: &ScopePayloadV1) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(payload).map_err(|_| invalid_scope())
}

fn validate_endpoints(required: &[String], admitted: &[String]) -> StorageResult<()> {
    let canonical = |values: &[String]| {
        values.iter().all(|value| !value.is_empty())
            && values.windows(2).all(|pair| pair[0] < pair[1])
    };
    if !canonical(required)
        || !canonical(admitted)
        || admitted
            .iter()
            .any(|endpoint| required.binary_search(endpoint).is_err())
    {
        return Err(invalid_scope());
    }
    Ok(())
}

fn validate_checkpoints(
    payload: &ScopePayloadV1,
    checkpoints: &[RecoveryEndpointCheckpoint],
) -> StorageResult<()> {
    let mut seen = std::collections::BTreeSet::new();
    for checkpoint in checkpoints {
        if payload
            .required_endpoints
            .binary_search(&checkpoint.endpoint)
            .is_err()
            || !seen.insert(&checkpoint.endpoint)
        {
            return Err(invalid_scope());
        }
    }
    Ok(())
}

pub(super) fn payload_is_qualified(payload: &ScopePayloadV1, predicate: i64, known_event: bool) -> bool {
    match predicate {
        0 => {
            !payload.required_endpoints.is_empty()
                && payload.required_endpoints == payload.admitted_endpoints
                && payload.required_endpoints.iter().all(|endpoint| {
                    payload.checkpoints.iter().any(|checkpoint| {
                        &checkpoint.endpoint == endpoint
                            && checkpoint.outcome == RecoveryScopeOutcome::Covered
                            && checkpoint.exhaustive
                            && checkpoint.admission_complete
                    })
                })
        }
        1 => known_event && payload.retained_known_event,
        2 => payload.checkpoints.iter().any(|checkpoint| {
            checkpoint.first_boundary
                && payload
                    .admitted_endpoints
                    .binary_search(&checkpoint.endpoint)
                    .is_ok()
                && checkpoint.outcome != RecoveryScopeOutcome::LossInvalidated
        }),
        _ => false,
    }
}

pub(super) fn no_unimported_loss(conn: &Connection) -> StorageResult<bool> {
    conn.query_row_cached(
        "SELECT NOT EXISTS(SELECT 1 FROM account_delivery_loss_evidence
         WHERE imported_count IS NULL OR dropped_count > imported_count)",
        [],
        |row| row.get(0),
    )
    .storage()
}

impl SqliteAccountStorage {
    pub fn recovery_scope_snapshots(
        &self,
        obligation_id: [u8; 16],
    ) -> StorageResult<Vec<StoredRecoveryScope>> {
        let conn = self.lock()?;
        let rows = conn.prepare_cached(
            "SELECT scope_id,scope_revision,route_kind,route_role,group_id,transport_group_id,
             since_seconds,until_seconds,known_event_id,inventory_floor,scope_format,scope_payload,snapshot_state
             FROM account_recovery_scopes WHERE obligation_id=?1 ORDER BY scope_id",
        ).storage()?.query_map([obligation_id.as_slice()], |row| Ok((
            row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,Option<u8>>(2)?,row.get::<_,Option<u8>>(3)?,
            row.get::<_,Option<Vec<u8>>>(4)?,row.get::<_,Option<Vec<u8>>>(5)?,row.get::<_,Option<i64>>(6)?,
            row.get::<_,Option<i64>>(7)?,row.get::<_,Option<Vec<u8>>>(8)?,row.get::<_,Option<i64>>(9)?,
            row.get::<_,i64>(10)?,row.get::<_,Option<Vec<u8>>>(11)?,row.get::<_,i64>(12)?,
        ))).storage()?.collect::<Result<Vec<_>,_>>().storage()?;
        let mut scopes = Vec::new();
        for (
            id,
            revision,
            kind,
            role,
            group,
            route,
            since,
            until,
            known,
            floor,
            format,
            bytes,
            ready,
        ) in rows
        {
            if format != 1 {
                return Err(invalid_scope());
            }
            if ready == 0 {
                continue;
            }
            let payload = decode_scope(format, &bytes.ok_or_else(invalid_scope)?)?;
            let plan = RecoveryScopePlan {
                scope_id: i64_to_u64(id)?,
                route_kind: kind.ok_or_else(invalid_scope)?,
                route_role: role.ok_or_else(invalid_scope)?,
                group_id: group,
                transport_group_id: route
                    .map(|id| id.try_into().map_err(|_| invalid_scope()))
                    .transpose()?,
                since_seconds: since.map(i64_to_u64).transpose()?,
                until_seconds: i64_to_u64(until.ok_or_else(invalid_scope)?)?,
                known_event_id: known
                    .map(|id| id.try_into().map_err(|_| invalid_scope()))
                    .transpose()?,
                inventory_floor: floor.map(i64_to_u64).transpose()?,
                required_endpoints: payload.required_endpoints,
                admitted_endpoints: payload.admitted_endpoints,
            };
            scopes.push(StoredRecoveryScope {
                token: RecoveryScopeToken {
                    obligation_id,
                    scope_id: plan.scope_id,
                    revision: i64_to_u64(revision)?,
                },
                plan,
                checkpoints: payload.checkpoints,
                retained_known_event: payload.retained_known_event,
                attempt_serial: payload.attempt_serial,
                obligation_revision: payload.obligation_revision,
                route_revision: payload.route_revision,
                inventory_revision: payload.inventory_revision,
                loss_revision: payload.loss_revision,
            });
        }
        Ok(scopes)
    }

    /// Freeze all scopes for one selected obligation before external effects.
    /// Existing ready scopes cannot disappear from the plan. A fresh attempt
    /// invalidates session-bound EOSE; compatible qualified coverage is retained.
    pub fn install_recovery_scope_plan(
        &self,
        expected: &RecoveryRevisionFence,
        attempt_serial: u64,
        obligation_id: [u8; 16],
        plans: &[RecoveryScopePlan],
    ) -> StorageResult<Option<Vec<RecoveryScopeToken>>> {
        let Some((_, revision)) = expected
            .obligations
            .iter()
            .find(|(id, _)| *id == obligation_id)
        else {
            return Err(invalid_scope());
        };
        if attempt_serial == 0
            || plans.is_empty()
            || plans
                .windows(2)
                .any(|pair| pair[0].scope_id >= pair[1].scope_id)
        {
            return Err(invalid_scope());
        }
        for plan in plans {
            sqlite_integer(plan.scope_id)?;
            validate_endpoints(&plan.required_endpoints, &plan.admitted_endpoints)?;
            if plan.route_kind > 2
                || plan.route_role > 2
                || plan
                    .since_seconds
                    .is_some_and(|since| since > plan.until_seconds)
                || (plan.route_kind == 1
                    && (plan.group_id.is_none() || plan.transport_group_id.is_none()))
            {
                return Err(invalid_scope());
            }
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if retry_state(&conn)?.attempt_serial != attempt_serial
                || !selected_fence_matches(&revision_fence(&conn)?, expected)
                || !no_unimported_loss(&conn)?
            {
                return Ok(None);
            }
            let existing = conn.prepare_cached(
                "SELECT scope_id, scope_revision, scope_format, scope_payload, snapshot_state
                 FROM account_recovery_scopes WHERE obligation_id = ?1 ORDER BY scope_id",
            ).storage()?.query_map([obligation_id.as_slice()], |row| Ok((
                row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?, row.get::<_, i64>(4)?,
            ))).storage()?.collect::<Result<Vec<_>, _>>().storage()?;
            if existing.iter().any(|(_, _, format, _, _)| *format != 1) {
                return Err(StorageError::Serialization("unsupported recovery scope format".into()));
            }
            if existing.iter().any(|(id, _, _, _, ready)| *ready == 1 && !plans.iter().any(|plan| i64::try_from(plan.scope_id).ok() == Some(*id))) {
                return Err(invalid_scope());
            }
            for (_, _, format, bytes, ready) in &existing {
                if *ready != 1 { continue; }
                let previous = decode_scope(*format, bytes.as_deref().ok_or_else(invalid_scope)?)?;
                if previous.obligation_revision == *revision && previous.route_revision == expected.route_revision
                    && plans.iter().any(|plan| !existing.iter().any(|(id, ..)| i64::try_from(plan.scope_id).ok() == Some(*id)))
                {
                    return Err(StorageError::Serialization("recovery scopes expanded without a new revision".into()));
                }
            }
            let mut tokens = Vec::with_capacity(plans.len());
            for plan in plans {
                let prior = existing.iter().find(|(id, ..)| Some(*id) == i64::try_from(plan.scope_id).ok());
                let scope_revision = prior.map_or(Ok(1), |(_, revision, ..)| {
                    revision.checked_add(1).ok_or_else(invalid_scope)
                })?;
                let mut payload = ScopePayloadV1 {
                    required_endpoints: plan.required_endpoints.clone(),
                    admitted_endpoints: plan.admitted_endpoints.clone(),
                    checkpoints: Vec::new(), retained_known_event: false, attempt_serial,
                    obligation_revision: *revision,
                    loss_revision: expected.loss_revision, route_revision: expected.route_revision,
                    inventory_revision: expected.inventory_revision,
                };
                if let Some((_, _, format, Some(bytes), 1)) = prior {
                    let previous = decode_scope(*format, bytes)?;
                    let compatible_columns: bool = conn.query_row_cached(
                        "SELECT route_kind = ?3 AND route_role = ?4 AND group_id IS ?5
                         AND transport_group_id IS ?6 AND since_seconds IS ?7 AND until_seconds = ?8
                         AND known_event_id IS ?9 AND (inventory_floor IS ?10 OR inventory_floor IS NULL OR ?11)
                         FROM account_recovery_scopes WHERE obligation_id = ?1 AND scope_id = ?2",
                        params![obligation_id.as_slice(), sqlite_integer(plan.scope_id)?, plan.route_kind,
                            plan.route_role, plan.group_id, plan.transport_group_id.as_ref().map(|id| id.as_slice()),
                            plan.since_seconds.map(sqlite_integer).transpose()?, sqlite_integer(plan.until_seconds)?,
                            plan.known_event_id.as_ref().map(|id| id.as_slice()), plan.inventory_floor.map(sqlite_integer).transpose()?,
                            previous.inventory_revision != expected.inventory_revision],
                        |row| row.get(0),
                    ).storage()?;
                    if previous.obligation_revision == *revision && previous.route_revision == expected.route_revision
                        && (!compatible_columns || previous.required_endpoints != plan.required_endpoints)
                    {
                        return Err(StorageError::Serialization("recovery goal changed without a new revision".into()));
                    }
                    if compatible_columns && previous.obligation_revision == *revision
                        && previous.loss_revision == expected.loss_revision
                        && previous.route_revision == expected.route_revision
                        && previous.inventory_revision == expected.inventory_revision
                        && previous.required_endpoints == plan.required_endpoints
                    {
                        payload.checkpoints = previous.checkpoints.into_iter().filter(|checkpoint| {
                            checkpoint.outcome == RecoveryScopeOutcome::Covered
                                && checkpoint.exhaustive && checkpoint.admission_complete
                        }).map(|mut checkpoint| { checkpoint.first_boundary = false; checkpoint }).collect();
                        for checkpoint in &payload.checkpoints {
                            payload.admitted_endpoints.push(checkpoint.endpoint.clone());
                        }
                        payload.admitted_endpoints.sort();
                        payload.admitted_endpoints.dedup();
                        payload.retained_known_event = previous.retained_known_event;
                    }
                }
                conn.execute_cached(
                    "INSERT INTO account_recovery_scopes(obligation_id, scope_id, route_kind, route_role,
                     group_id, transport_group_id, route_revision, since_seconds, until_seconds,
                     known_event_id, scope_revision, snapshot_state, inventory_floor, scope_format, scope_payload)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,1,?12,1,?13)
                     ON CONFLICT(obligation_id,scope_id) DO UPDATE SET route_kind=excluded.route_kind,
                     route_role=excluded.route_role, group_id=excluded.group_id,
                     transport_group_id=excluded.transport_group_id, route_revision=excluded.route_revision,
                     since_seconds=excluded.since_seconds, until_seconds=excluded.until_seconds,
                     known_event_id=excluded.known_event_id, scope_revision=excluded.scope_revision,
                     snapshot_state=1, inventory_floor=excluded.inventory_floor, progress_after=NULL,
                     scope_format=1, scope_payload=excluded.scope_payload",
                    params![obligation_id.as_slice(), sqlite_integer(plan.scope_id)?, plan.route_kind, plan.route_role,
                        plan.group_id, plan.transport_group_id.as_ref().map(|id| id.as_slice()), sqlite_integer(expected.route_revision)?,
                        plan.since_seconds.map(sqlite_integer).transpose()?, sqlite_integer(plan.until_seconds)?,
                        plan.known_event_id.as_ref().map(|id| id.as_slice()), scope_revision,
                        plan.inventory_floor.map(sqlite_integer).transpose()?, encode_scope(&payload)?],
                ).storage()?;
                tokens.push(RecoveryScopeToken { obligation_id, scope_id: plan.scope_id, revision: i64_to_u64(scope_revision)? });
            }
            Ok(Some(tokens))
        })
    }

    /// Checkpoint owned, validated endpoint/admission facts and conditionally
    /// satisfy one obligation in the same transaction. Loss watermarks remain:
    /// the owner must still conditionally acknowledge the plane before reclaiming
    /// them or publishing completion. A failed commit leaves demand pending.
    pub fn checkpoint_recovery_obligation(
        &self,
        expected: &RecoveryRevisionFence,
        attempt_serial: u64,
        obligation_id: [u8; 16],
        checkpoints: &[RecoveryScopeCheckpoint],
        incomplete: RecoveryEligibility,
    ) -> StorageResult<bool> {
        let Some((_, revision)) = expected
            .obligations
            .iter()
            .find(|(id, _)| *id == obligation_id)
        else {
            return Err(invalid_scope());
        };
        if attempt_serial == 0 {
            return Err(invalid_scope());
        }
        let mut selected = expected.clone();
        selected.obligations.retain(|(id, _)| *id == obligation_id);
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !selected_fence_matches(&revision_fence(&conn)?, &selected)
                || !no_unimported_loss(&conn)?
            {
                return Ok(false);
            }
            let mut seen = std::collections::BTreeSet::new();
            for checkpoint in checkpoints {
                let token = &checkpoint.token;
                if token.obligation_id != obligation_id || !seen.insert(token.scope_id) {
                    return Err(invalid_scope());
                }
                let record = conn.query_row_cached(
                    "SELECT scope_revision, scope_format, scope_payload FROM account_recovery_scopes
                     WHERE obligation_id = ?1 AND scope_id = ?2 AND snapshot_state = 1",
                    params![obligation_id.as_slice(), sqlite_integer(token.scope_id)?],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?)),
                ).storage()?;
                if i64_to_u64(record.0)? != token.revision {
                    return Ok(false);
                }
                let mut payload = decode_scope(record.1, &record.2)?;
                if payload.attempt_serial != attempt_serial || payload.obligation_revision != *revision
                    || payload.loss_revision != expected.loss_revision || payload.route_revision != expected.route_revision
                    || payload.inventory_revision != expected.inventory_revision
                {
                    return Ok(false);
                }
                validate_checkpoints(&payload, &checkpoint.endpoints)?;
                for incoming in &checkpoint.endpoints {
                    if let Some(existing) = payload.checkpoints.iter_mut().find(|existing| existing.endpoint == incoming.endpoint) {
                        *existing = incoming.clone();
                    } else {
                        payload.checkpoints.push(incoming.clone());
                    }
                }
                payload.retained_known_event |= checkpoint.retained_known_event;
                conn.execute_cached(
                    "UPDATE account_recovery_scopes SET scope_payload = ?3
                     WHERE obligation_id = ?1 AND scope_id = ?2",
                    params![obligation_id.as_slice(), sqlite_integer(token.scope_id)?, encode_scope(&payload)?],
                ).storage()?;
            }
            let predicate: i64 = conn.query_row_cached(
                "SELECT predicate FROM account_recovery_obligations WHERE id = ?1",
                [obligation_id.as_slice()], |row| row.get(0),
            ).storage()?;
            let rows = conn.prepare_cached(
                "SELECT snapshot_state, scope_format, scope_payload, known_event_id IS NOT NULL
                 FROM account_recovery_scopes WHERE obligation_id = ?1",
            ).storage()?.query_map([obligation_id.as_slice()], |row| Ok((
                row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<Vec<u8>>>(2)?, row.get::<_, bool>(3)?,
            ))).storage()?.collect::<Result<Vec<_>, _>>().storage()?;
            let mut valid = !rows.is_empty();
            let mut all_qualified = true;
            let mut any_qualified = false;
            for (ready, format, bytes, known_event) in rows {
                let Some(bytes) = bytes.filter(|_| ready == 1) else { valid = false; continue; };
                let payload = decode_scope(format, &bytes)?;
                valid &= payload.attempt_serial == attempt_serial
                    && payload.obligation_revision == *revision
                    && payload.loss_revision == expected.loss_revision
                    && payload.route_revision == expected.route_revision
                    && payload.inventory_revision == expected.inventory_revision;
                let qualified = payload_is_qualified(&payload, predicate, known_event);
                all_qualified &= qualified;
                any_qualified |= qualified;
            }
            // One retained eligible copy satisfies an exact known event across
            // its alternative routes. Historical coverage requires every scope.
            let qualified = valid && if predicate == 1 { any_qualified } else { all_qualified };
            conn.execute_cached(
                "UPDATE account_recovery_obligations SET state = ?2, eligibility = CASE WHEN eligibility=2 AND ?2=0 THEN 2 ELSE ?3 END WHERE id = ?1",
                params![obligation_id.as_slice(), if qualified { 1 } else { 0 }, incomplete as i64],
            ).storage()?;
            Ok(qualified)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SqliteAccountStorage, RecoveryRevisionFence, u64, [u8; 16]) {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("alice").unwrap();
        store.mark_account_delivery_recovery("alice", 1, 1).unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        let id = fence.obligations[0].0;
        let attempt = store
            .reserve_recovery_attempt(&fence, 1000, 15000, false)
            .unwrap()
            .unwrap()
            .attempt_serial;
        (store, fence, attempt, id)
    }

    fn plan(admitted: &[&str]) -> RecoveryScopePlan {
        RecoveryScopePlan {
            scope_id: 0,
            route_kind: 0,
            route_role: 0,
            group_id: None,
            transport_group_id: None,
            since_seconds: Some(1),
            until_seconds: 10,
            known_event_id: None,
            inventory_floor: Some(1),
            required_endpoints: vec!["a".into(), "b".into()],
            admitted_endpoints: admitted.iter().map(|value| (*value).into()).collect(),
        }
    }

    fn covered(endpoint: &str) -> RecoveryEndpointCheckpoint {
        RecoveryEndpointCheckpoint {
            endpoint: endpoint.into(),
            outcome: RecoveryScopeOutcome::Covered,
            exhaustive: true,
            admission_complete: true,
            first_boundary: true,
        }
    }

    fn checkpoint(
        token: &RecoveryScopeToken,
        endpoints: Vec<RecoveryEndpointCheckpoint>,
    ) -> RecoveryScopeCheckpoint {
        RecoveryScopeCheckpoint {
            token: token.clone(),
            endpoints,
            retained_known_event: false,
        }
    }

    #[test]
    fn eose_is_not_coverage_and_partial_qualified_coverage_survives_new_attempt() {
        let (store, fence, attempt, id) = fixture();
        let token = store
            .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a", "b"])])
            .unwrap()
            .unwrap()
            .remove(0);
        let mut eose_only = covered("a");
        eose_only.exhaustive = false;
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![eose_only])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![covered("a")])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        let next = store
            .reserve_recovery_attempt(&fence, 16000, 30000, false)
            .unwrap()
            .unwrap();
        let token = store
            .install_recovery_scope_plan(&fence, next.attempt_serial, id, &[plan(&["b"])])
            .unwrap()
            .unwrap()
            .remove(0);
        assert!(
            store
                .checkpoint_recovery_obligation(
                    &fence,
                    next.attempt_serial,
                    id,
                    &[checkpoint(&token, vec![covered("b")])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        assert!(store.account_delivery_recovery("alice").unwrap().is_none());
        // Plane acknowledgment is still required before reclaiming this guard.
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM account_delivery_loss_evidence",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn same_token_count_growth_fences_completion_before_owner_import() {
        let (store, fence, attempt, id) = fixture();
        let token = store
            .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a", "b"])])
            .unwrap()
            .unwrap()
            .remove(0);
        store
            .record_account_delivery_loss("alice", 1, 2, 11)
            .unwrap();
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![covered("a"), covered("b")])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        assert!(store.account_delivery_recovery("alice").unwrap().is_some());
    }

    #[test]
    fn failed_completion_rolls_back_its_checkpoint_and_keeps_pending_intent() {
        let (store, fence, attempt, id) = fixture();
        let token = store
            .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a", "b"])])
            .unwrap()
            .unwrap()
            .remove(0);
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_completion BEFORE UPDATE ON account_recovery_obligations
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert!(
            store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![covered("a"), covered("b")])],
                    RecoveryEligibility::Retry
                )
                .is_err()
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_completion")
            .unwrap();
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[],
                    RecoveryEligibility::Retry
                )
                .unwrap(),
            "failed transaction must not leave qualified endpoint checkpoints behind"
        );
        assert!(store.account_delivery_recovery("alice").unwrap().is_some());
    }

    #[test]
    fn domain_write_failure_rolls_back_qualified_boundary_and_endpoint_evidence() {
        use cgka_traits::StorageProvider;
        let (store, fence, attempt, id) = fixture();
        store.lock().unwrap().execute("UPDATE account_recovery_obligations SET predicate=2 WHERE id=?1", [id.as_slice()]).unwrap();
        let token = store.install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a"])])
            .unwrap().unwrap().remove(0);
        let result: StorageResult<()> = store.with_transaction(|storage| {
            assert!(storage.checkpoint_recovery_obligation(&fence, attempt, id,
                &[checkpoint(&token, vec![covered("a")])], RecoveryEligibility::Retry)?);
            Err(StorageError::Serialization("injected domain persistence failure".into()))
        });
        assert!(result.is_err());
        assert!(!store.checkpoint_recovery_obligation(&fence, attempt, id, &[], RecoveryEligibility::Retry).unwrap());
        assert!(store.recovery_scope_snapshots(id).unwrap()[0].checkpoints.is_empty());
    }

    #[test]
    fn unversioned_goal_expansion_and_unknown_formats_fail_closed() {
        let (store, fence, attempt, id) = fixture();
        store
            .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a", "b"])])
            .unwrap()
            .unwrap();
        let mut additional = plan(&["a", "b"]);
        additional.scope_id = 1;
        assert!(
            store
                .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a", "b"]), additional])
                .is_err()
        );
        let mut widened = plan(&["a", "b"]);
        widened.until_seconds = 11;
        assert!(
            store
                .install_recovery_scope_plan(&fence, attempt, id, &[widened])
                .is_err()
        );
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_scopes SET scope_format = 2")
            .unwrap();
        assert!(
            store
                .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a", "b"])])
                .is_err()
        );
    }

    #[test]
    fn maintenance_boundary_is_independent_from_history_and_known_event_predicates() {
        let (store, fence, attempt, id) = fixture();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_recovery_obligations SET predicate = 2 WHERE id = ?1",
                [id.as_slice()],
            )
            .unwrap();
        let token = store
            .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a"])])
            .unwrap()
            .unwrap()
            .remove(0);
        let mut boundary = covered("a");
        boundary.exhaustive = false;
        boundary.admission_complete = false;
        boundary.outcome = RecoveryScopeOutcome::Partial;
        assert!(
            store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![boundary])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );

        let (store, fence, attempt, id) = fixture();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_recovery_obligations SET predicate = 1 WHERE id = ?1",
                [id.as_slice()],
            )
            .unwrap();
        let mut known = plan(&["a"]);
        known.known_event_id = Some([7; 32]);
        let mut alternate = known.clone();
        alternate.scope_id = 1;
        alternate.required_endpoints = vec!["b".into()];
        alternate.admitted_endpoints = vec!["b".into()];
        let token = store
            .install_recovery_scope_plan(&fence, attempt, id, &[known, alternate])
            .unwrap()
            .unwrap()
            .remove(0);
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![covered("a")])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        let mut retained = checkpoint(&token, vec![]);
        retained.retained_known_event = true;
        assert!(
            store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[retained],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
    }
    fn qualify_loss(
        store: &SqliteAccountStorage,
        fence: &RecoveryRevisionFence,
        attempt: u64,
        id: [u8; 16],
    ) {
        let token = store
            .install_recovery_scope_plan(fence, attempt, id, &[plan(&["a", "b"])])
            .unwrap()
            .unwrap()
            .remove(0);
        assert!(
            store
                .checkpoint_recovery_obligation(
                    fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![covered("a"), covered("b")])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
    }

    #[test]
    fn interrupted_plane_ack_rearms_on_open_without_forgiving_retry_cost() {
        let (store, fence, attempt, id) = fixture();
        let retry = store.recovery_retry_state().unwrap();
        qualify_loss(&store, &fence, attempt, id);
        assert_eq!(store.restore_unacknowledged_recovery_loss().unwrap(), 1);
        assert!(store.account_delivery_recovery("alice").unwrap().is_some());
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        assert!(store.recovery_revision_fence().unwrap().obligations[0].1 > fence.obligations[0].1);
        assert_eq!(store.restore_unacknowledged_recovery_loss().unwrap(), 0);
    }

    #[test]
    fn plane_ack_reclaims_exact_evidence_only_after_qualified_completion() {
        let (store, fence, attempt, id) = fixture();
        let watermarks = store
            .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
            .unwrap();
        assert!(
            !store
                .acknowledge_recovery_loss(&fence, id, &watermarks)
                .unwrap()
        );
        qualify_loss(&store, &fence, attempt, id);
        assert!(
            store
                .acknowledge_recovery_loss(&fence, id, &watermarks)
                .unwrap()
        );
        assert_eq!(store.restore_unacknowledged_recovery_loss().unwrap(), 0);
        assert!(
            store
                .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .is_empty()
        );
        assert!(store.account_delivery_recovery("alice").unwrap().is_none());
    }

    #[test]
    fn failed_ack_commit_and_new_loss_preserve_the_reopen_guard() {
        let (store, fence, attempt, id) = fixture();
        let watermarks = store
            .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
            .unwrap();
        qualify_loss(&store, &fence, attempt, id);
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_ack BEFORE DELETE ON account_delivery_loss_evidence
            BEGIN SELECT RAISE(ABORT,'injected'); END;",
            )
            .unwrap();
        assert!(
            store
                .acknowledge_recovery_loss(&fence, id, &watermarks)
                .is_err()
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_ack")
            .unwrap();
        assert_eq!(
            store
                .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .len(),
            1
        );
        store
            .record_account_delivery_loss("alice", 1, 2, 11)
            .unwrap();
        assert!(
            !store
                .acknowledge_recovery_loss(&fence, id, &watermarks)
                .unwrap()
        );
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert!(store.account_delivery_recovery("alice").unwrap().is_some());
        assert!(
            !store
                .acknowledge_recovery_loss(&fence, id, &watermarks)
                .unwrap()
        );
    }

    #[test]
    fn low_level_retirement_does_not_become_an_interrupted_completion() {
        let (store, _, _, _) = fixture();
        assert!(store.clear_account_delivery_recovery("alice", 1).unwrap());
        assert_eq!(store.restore_unacknowledged_recovery_loss().unwrap(), 0);
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert!(store.account_delivery_recovery("alice").unwrap().is_none());
        assert_eq!(
            store
                .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn quiescent_demand_does_not_hitchhike_on_an_eligible_obligation() {
        let (store, _, _, _) = fixture();
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET eligibility=3")
            .unwrap();
        store
            .record_account_recovery_loss(
                "alice",
                RecoveryLossCause::NotificationConsumer,
                5,
                0,
                10,
            )
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        let all = store.recovery_revision_fence().unwrap();
        assert_eq!(all.obligations.len(), 2);
        assert!(
            store
                .reserve_recovery_attempt(&all, 16000, 30000, false)
                .unwrap()
                .is_none()
        );
        let eligible = store.recovery_eligible_revision_fence(false).unwrap();
        assert_eq!(eligible.obligations.len(), 1);
        assert!(
            store
                .reserve_recovery_attempt(&eligible, 16000, 30000, false)
                .unwrap()
                .is_some()
        );
        assert_eq!(store.recovery_eligible_revision_fence(true).unwrap(), all);
    }
    #[test]
    fn file_reopen_restores_completion_guard_and_frozen_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery.sqlite");
        let key = crate::SqlCipherKey::new("recovery scope reopen test").unwrap();
        let (fence, retry, id) = {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.ensure_account_projection("alice").unwrap();
            store.mark_account_delivery_recovery("alice", 1, 1).unwrap();
            let fence = store.recovery_revision_fence().unwrap();
            let retry = store
                .reserve_recovery_attempt(&fence, 1000, 15000, false)
                .unwrap()
                .unwrap();
            let id = fence.obligations[0].0;
            qualify_loss(&store, &fence, retry.attempt_serial, id);
            (fence, retry, id)
        };
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let scopes = reopened.recovery_scope_snapshots(id).unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].plan.until_seconds, 10);
        assert_eq!(scopes[0].checkpoints.len(), 2);
        assert_eq!(reopened.restore_unacknowledged_recovery_loss().unwrap(), 1);
        assert_eq!(reopened.recovery_retry_state().unwrap(), retry);
        assert!(
            reopened
                .account_delivery_recovery("alice")
                .unwrap()
                .is_some()
        );
        let evidence = reopened
            .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
            .unwrap();
        assert!(
            !reopened
                .acknowledge_recovery_loss(&fence, id, &evidence)
                .unwrap()
        );
    }
    #[test]
    fn compatible_late_scope_evidence_survives_unrelated_attempt_but_not_replacement() {
        let (store, fence, attempt, id) = fixture();
        let token = store
            .install_recovery_scope_plan(&fence, attempt, id, &[plan(&["a", "b"])])
            .unwrap()
            .unwrap()
            .remove(0);
        let other = store
            .request_recovery(RecoveryRequest::IncrementalHistory, 1000)
            .unwrap();
        let mut selected = store.recovery_revision_fence().unwrap();
        selected.obligations.retain(|(id, _)| *id == other.id);
        store
            .reserve_recovery_attempt(&selected, 16000, 30000, false)
            .unwrap()
            .unwrap();
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![covered("a")])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        let current = store.recovery_revision_fence().unwrap();
        let next = store
            .reserve_recovery_attempt(&current, 46000, 30000, false)
            .unwrap()
            .unwrap();
        store
            .install_recovery_scope_plan(&current, next.attempt_serial, id, &[plan(&["a", "b"])])
            .unwrap()
            .unwrap();
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint(&token, vec![covered("b")])],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
        assert!(store.account_delivery_recovery("alice").unwrap().is_some());
    }

    #[test]
    fn unchanged_route_policy_reopen_does_not_rearm_but_changed_policy_preserves_retry_cost() {
        let (store, _, _, _) = fixture();
        assert!(!store.observe_recovery_route_snapshot([1; 32]).unwrap());
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET eligibility=3")
            .unwrap();
        let before = store.recovery_revision_fence().unwrap();
        let retry = store.recovery_retry_state().unwrap();
        assert!(!store.observe_recovery_route_snapshot([1; 32]).unwrap());
        assert!(
            store
                .recovery_eligible_revision_fence(false)
                .unwrap()
                .obligations
                .is_empty()
        );
        assert!(store.observe_recovery_route_snapshot([2; 32]).unwrap());
        let after = store.recovery_revision_fence().unwrap();
        assert_eq!(after.route_revision, before.route_revision + 1);
        assert!(after.obligations[0].1 > before.obligations[0].1);
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        assert_eq!(
            store.recovery_eligible_revision_fence(false).unwrap(),
            after
        );
    }
}
