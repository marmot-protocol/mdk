//! The old recovery owner's frozen scope payloads (mdk#2660). Nothing writes
//! a new one: the account-open conversion reads them, and an inventory
//! removal voids the checkpoints of the ones that overlap it, so the
//! conversion never counts removed input as coverage.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecoveryScopeOutcome {
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

/// One relay's checkpoint in a frozen scope. Endpoint identity is
/// account-private and must never be logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryEndpointCheckpoint {
    endpoint: String,
    outcome: RecoveryScopeOutcome,
    /// A bounded comparison or acquisition explicitly established exhaustiveness.
    exhaustive: bool,
    /// Every input needed by this endpoint's comparison was durably retained.
    admission_complete: bool,
    /// The old owner received the limited protocol-maintenance boundary in
    /// this session. Independent of history coverage.
    first_boundary: bool,
}

/// A pending obligation's eligibility. `WaitingCapacity` and
/// `WaitingCapability` are waits the old owner wrote and nothing writes now
/// (mdk#2660). An upgraded epoch gap in either is visited like a ready one:
/// only a park (`NeedsDeepRepair`) stops its visits.
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
    pub(super) required_endpoints: Vec<String>,
    pub(super) admitted_endpoints: Vec<String>,
    checkpoints: Vec<RecoveryEndpointCheckpoint>,
    retained_known_event: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    replay_admitted: bool,
    attempt_serial: u64,
    pub(super) obligation_revision: u64,
    pub(super) loss_revision: u64,
    pub(super) route_revision: u64,
    pub(super) inventory_revision: u64,
    /// Comparisons of this scope in a row, for this goal, that answered and
    /// neither certified nor admitted anything.
    #[serde(default, skip_serializing_if = "is_zero")]
    quiet_passes: u64,
    /// Comparisons of this scope in a row, for this goal, whose required
    /// relays did not all answer, on passes that could otherwise retry.
    #[serde(default, skip_serializing_if = "is_zero")]
    unserved_passes: u64,
    /// A comparison certified this goal's retained window. It never counts as
    /// coverage and keeps the scope off the quiet streak.
    #[serde(default, skip_serializing_if = "is_false")]
    window_certified: bool,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
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

/// Required endpoints certify a scope; admitted endpoints are the ones its
/// comparison may contact. Either may hold an endpoint the other lacks: a
/// best-effort relay is admitted without being required, and a required
/// relay the dial policy refuses is required without being admitted.
fn validate_endpoints(required: &[String], admitted: &[String]) -> StorageResult<()> {
    let canonical = |values: &[String]| {
        values.iter().all(|value| !value.is_empty())
            && values.windows(2).all(|pair| pair[0] < pair[1])
    };
    if !canonical(required) || !canonical(admitted) {
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
        let known = payload
            .required_endpoints
            .binary_search(&checkpoint.endpoint)
            .is_ok()
            || payload
                .admitted_endpoints
                .binary_search(&checkpoint.endpoint)
                .is_ok();
        if !known || !seen.insert(&checkpoint.endpoint) {
            return Err(invalid_scope());
        }
    }
    Ok(())
}

pub(super) fn payload_is_qualified(
    payload: &ScopePayloadV1,
    predicate: i64,
    known_event: bool,
) -> bool {
    match predicate {
        // Only required endpoints certify. Each must also have been admitted:
        // a relay the dial policy refused cannot vouch for anything.
        0 => {
            !payload.required_endpoints.is_empty()
                && payload
                    .required_endpoints
                    .iter()
                    .all(|endpoint| payload.admitted_endpoints.binary_search(endpoint).is_ok())
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
        3_i64 => payload.replay_admitted && !payload.admitted_endpoints.is_empty(),
        _ => false,
    }
}

pub(super) fn invalidate_retained_scope(format: i64, bytes: &[u8]) -> StorageResult<Vec<u8>> {
    let mut payload = decode_scope(format, bytes)?;
    payload.checkpoints.clear();
    payload.retained_known_event = false;
    payload.replay_admitted = false;
    encode_scope(&payload)
}

/// Re-check a satisfied obligation's predicate after a removal voided some of
/// its scopes' checkpoints. It never establishes completion.
pub(super) fn retained_predicate_qualifies(
    conn: &Connection,
    obligation_id: &[u8],
    predicate: i64,
) -> StorageResult<bool> {
    let rows = conn
        .prepare_cached(
            "SELECT snapshot_state, scope_format, scope_payload, known_event_id IS NOT NULL
                 FROM account_recovery_scopes WHERE obligation_id = ?1",
        )
        .storage()?
        .query_map([obligation_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut valid = !rows.is_empty();
    let mut all_qualified = true;
    let mut any_qualified = false;
    for (ready, format, bytes, known_event) in rows {
        let Some(bytes) = bytes.filter(|_| ready == 1) else {
            valid = false;
            continue;
        };
        let qualified =
            payload_is_qualified(&decode_scope(format, &bytes)?, predicate, known_event);
        all_qualified &= qualified;
        any_qualified |= qualified;
    }
    // One retained eligible copy satisfies an exact known event across
    // its alternative routes. Historical coverage requires every scope.
    Ok(valid
        && if predicate == 1 {
            any_qualified
        } else {
            all_qualified
        })
}
