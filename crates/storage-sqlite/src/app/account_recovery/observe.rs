//! Read-only transition facts for the account recovery owner's audit rows.
//! Nothing here changes demand: each helper reports what a write already did,
//! or reads an obligation's current standing after an owner decision.
use super::demand::{invalid_demand, recovery_cause};
use super::*;

/// Where an obligation stands in storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryObligationState {
    Pending,
    Satisfied,
    /// Retired by an explicit, user-authorized dismissal ("history may be
    /// incomplete"), never by coverage.
    Retired,
}

/// One obligation's current durable standing. Identities stay private to the
/// account database; the owner turns them into hashed audit references.
/// Deliberately not `Debug`: it carries the group identity.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryObligationStatus {
    pub revision: u64,
    pub cause: RecoveryCause,
    pub state: RecoveryObligationState,
    pub eligibility: RecoveryEligibility,
    pub group_id: Option<Vec<u8>>,
}

/// How one durable demand write changed an obligation, compared with its row
/// immediately before the write, in the same transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryDemandTransition {
    /// No pending obligation existed for the key: a new row, or a satisfied
    /// one reopened as fresh debt.
    Recorded,
    /// Charged to an obligation that was already pending and not parked.
    Joined,
    /// Reopened an obligation that was parked for deep repair or retired by a
    /// dismissal.
    Resumed,
    /// The write left the obligation's revision unchanged, for example a
    /// duplicate of loss a dismissal already retired.
    Unchanged,
}

/// Loss one import charged to its cause's obligation. At most one per cause.
/// Deliberately not `Debug`: it carries the obligation identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoveryLossImport {
    pub cause: RecoveryLossCause,
    pub obligation: RecoveryDemandTicket,
    pub transition: RecoveryDemandTransition,
    /// Deliveries (queue loss) or lagged notifications (notification loss)
    /// newly charged by this import, summed over the generations it imported.
    pub charged: u64,
    /// The goal's lower bound after this import, read in the same
    /// transaction: the lowest bound charged by any unresolved generation of
    /// the cause, or `None` when any charge had no known time.
    pub goal_floor: Option<u64>,
}

/// `(revision, cause, state, eligibility, group_id)` as stored.
type StatusRow = (i64, i64, i64, i64, Option<Vec<u8>>);

pub(super) fn eligibility(value: i64) -> StorageResult<RecoveryEligibility> {
    Ok(match value {
        0 => RecoveryEligibility::Ready,
        1 => RecoveryEligibility::Retry,
        2 => RecoveryEligibility::WaitingCapacity,
        3 => RecoveryEligibility::WaitingCapability,
        4 => RecoveryEligibility::NeedsDeepRepair,
        _ => return Err(invalid_demand()),
    })
}

/// The row a demand key names, as `(id, revision, state, eligibility)`.
pub(super) type DemandRow = (Vec<u8>, i64, i64, i64);

pub(super) fn demand_row(conn: &Connection, key: &str) -> StorageResult<Option<DemandRow>> {
    conn.query_row_cached(
        "SELECT id, revision, state, eligibility FROM account_recovery_obligations
         WHERE demand_key = ?1",
        [key],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .optional()
    .storage()
}

/// Classify a demand write from the rows before and after it.
pub(super) fn transition(
    before: Option<&DemandRow>,
    after: &DemandRow,
) -> RecoveryDemandTransition {
    let Some((before_id, revision, state, eligibility)) = before else {
        return RecoveryDemandTransition::Recorded;
    };
    if *before_id != after.0 {
        return RecoveryDemandTransition::Recorded;
    }
    if *revision == after.1 {
        return RecoveryDemandTransition::Unchanged;
    }
    match (state, eligibility) {
        (1, _) => RecoveryDemandTransition::Recorded,
        (2, _) | (0, 4) => RecoveryDemandTransition::Resumed,
        _ => RecoveryDemandTransition::Joined,
    }
}

pub(super) fn ticket(row: &DemandRow) -> StorageResult<RecoveryDemandTicket> {
    Ok(RecoveryDemandTicket {
        id: row.0.clone().try_into().map_err(|_| invalid_demand())?,
        revision: i64_to_u64(row.1)?,
    })
}

impl SqliteAccountStorage {
    /// One obligation's current standing, or `None` once it was reclaimed.
    pub fn recovery_obligation_status(
        &self,
        id: [u8; 16],
    ) -> StorageResult<Option<RecoveryObligationStatus>> {
        let row: Option<StatusRow> = self
            .lock()?
            .query_row_cached(
                "SELECT revision, cause, state, eligibility, group_id
                 FROM account_recovery_obligations WHERE id = ?1",
                [id.as_slice()],
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
            .optional()
            .storage()?;
        row.map(|(revision, cause, state, eligibility_value, group_id)| {
            Ok(RecoveryObligationStatus {
                revision: i64_to_u64(revision)?,
                cause: recovery_cause(cause)?,
                state: match state {
                    0 => RecoveryObligationState::Pending,
                    1 => RecoveryObligationState::Satisfied,
                    2 => RecoveryObligationState::Retired,
                    _ => return Err(invalid_demand()),
                },
                eligibility: eligibility(eligibility_value)?,
                group_id,
            })
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("alice").unwrap();
        store
    }

    #[test]
    fn requests_report_recorded_then_unchanged_duplicates() {
        let store = store();
        let (ticket, first) = store
            .request_recovery_observed(RecoveryRequest::IncrementalHistory, 1)
            .unwrap();
        assert_eq!(first, RecoveryDemandTransition::Recorded);
        let (again, second) = store
            .request_recovery_observed(RecoveryRequest::IncrementalHistory, 2)
            .unwrap();
        assert_eq!(second, RecoveryDemandTransition::Unchanged);
        assert!(again == ticket, "a duplicate request joins nothing new");
        let status = store
            .recovery_obligation_status(ticket.id)
            .unwrap()
            .unwrap();
        assert_eq!(status.cause, RecoveryCause::IncrementalHistory);
        assert_eq!(status.state, RecoveryObligationState::Pending);
        assert_eq!(status.revision, ticket.revision);
    }

    #[test]
    fn explicit_requests_share_one_obligation_and_join_it() {
        let store = store();
        let (first, recorded) = store
            .request_recovery_observed(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &[1; 16],
                },
                1,
            )
            .unwrap();
        let (second, joined) = store
            .request_recovery_observed(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &[2; 16],
                },
                2,
            )
            .unwrap();
        assert_eq!(recorded, RecoveryDemandTransition::Recorded);
        assert_eq!(joined, RecoveryDemandTransition::Joined);
        assert_eq!(first.id, second.id);
        assert!(second.revision > first.revision);
    }

    #[test]
    fn loss_imports_sum_generations_per_cause() {
        let store = store();
        assert!(
            store
                .synchronize_account_delivery_loss("alice")
                .unwrap()
                .is_empty()
        );
        store
            .record_account_delivery_loss_bounded("alice", 1, 2, 10, Some(5))
            .unwrap();
        store
            .record_account_delivery_loss_bounded("alice", 2, 3, 11, Some(6))
            .unwrap();
        store
            .record_account_recovery_loss(
                "alice",
                RecoveryLossCause::NotificationConsumer,
                9,
                4,
                12,
            )
            .unwrap();
        let imports = store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(imports.len(), 2, "one entry per cause, not per generation");
        assert_eq!(imports[0].cause, RecoveryLossCause::Queue);
        assert_eq!(imports[0].charged, 5);
        assert_eq!(imports[0].transition, RecoveryDemandTransition::Recorded);
        assert_eq!(imports[1].cause, RecoveryLossCause::NotificationConsumer);
        assert_eq!(imports[1].charged, 4);
        // The bound is read in the import's own transaction: the lowest known
        // charge for queue loss, unknown for a lag with no floor.
        assert_eq!(imports[0].goal_floor, Some(5));
        assert_eq!(imports[1].goal_floor, None);
        // Nothing new: nothing reported.
        assert!(
            store
                .synchronize_account_delivery_loss("alice")
                .unwrap()
                .is_empty()
        );
        store
            .record_account_delivery_loss_bounded("alice", 2, 7, 13, Some(6))
            .unwrap();
        let imports = store.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].charged, 4, "only the growth is charged");
        assert_eq!(imports[0].transition, RecoveryDemandTransition::Joined);
    }
}
