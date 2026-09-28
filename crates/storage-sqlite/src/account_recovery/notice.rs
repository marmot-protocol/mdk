//! Parked recovery that hosts show as "history may be incomplete", and its one
//! ending besides qualified completion: explicit, user-authorized retirement.
use super::*;

/// `incomplete_reason` recorded with `state = 2` when the user retires a parked
/// obligation: the history may be incomplete. Retirement is its own outcome and
/// is never coverage. The value is meaningful only while `state = 2`; any new
/// demand that reopens the row clears it.
pub(crate) const RETIRED_HISTORY_MAY_BE_INCOMPLETE: i64 = 0;

/// One parked occurrence: automatic recovery stopped without proving this
/// history complete and waits for new evidence, an explicit deep repair, or a
/// retirement. `ticket.revision` identifies the occurrence; new evidence rearms
/// the obligation under a newer revision, so a later parking is a new
/// occurrence. These identities are account-private and never belong in logs.
pub struct ParkedRecoveryObligation {
    pub ticket: RecoveryDemandTicket,
    pub cause: RecoveryCause,
    /// Set for group-scoped demand, such as an epoch gap.
    pub group_id: Option<Vec<u8>>,
    /// Wall-clock milliseconds when it parked; `None` for rows parked before
    /// the time was recorded.
    pub parked_at_ms: Option<u64>,
}

type ParkedRow = (Vec<u8>, i64, i64, Option<Vec<u8>>, Option<i64>);

fn parked(rows: Vec<ParkedRow>) -> StorageResult<Vec<ParkedRecoveryObligation>> {
    rows.into_iter()
        .map(|(id, revision, cause, group_id, parked_at)| {
            Ok(ParkedRecoveryObligation {
                ticket: RecoveryDemandTicket {
                    id: id.try_into().map_err(|_| demand::invalid_demand())?,
                    revision: i64_to_u64(revision)?,
                },
                cause: demand::recovery_cause(cause)?,
                group_id,
                parked_at_ms: parked_at.map(i64_to_u64).transpose()?,
            })
        })
        .collect()
}

impl SqliteAccountStorage {
    /// Every pending obligation parked for explicit deep repair, oldest first.
    /// The set is input-relative to unresolved demand keys, never a history log.
    pub fn parked_recovery_obligations(&self) -> StorageResult<Vec<ParkedRecoveryObligation>> {
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT id,revision,cause,group_id,parked_at_ms FROM account_recovery_obligations
                 WHERE state=0 AND eligibility=4 ORDER BY parked_at_ms,id",
            )
            .storage()?
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        parked(rows)
    }

    /// Parked occurrences scoped to one group, oldest first. Account-wide
    /// demand (loss, incremental or explicit history) is not included.
    pub fn parked_group_recovery_obligations(
        &self,
        group_id: &[u8],
    ) -> StorageResult<Vec<ParkedRecoveryObligation>> {
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT id,revision,cause,group_id,parked_at_ms FROM account_recovery_obligations
                 WHERE state=0 AND eligibility=4 AND group_id=?1 ORDER BY parked_at_ms,id",
            )
            .storage()?
            .query_map([group_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        parked(rows)
    }

    /// Retire exactly one parked occurrence because the user accepted that its
    /// history may be incomplete. In one transaction, and only while the
    /// obligation still has this revision and is still parked, this records
    /// `state = 2` with [`RETIRED_HISTORY_MAY_BE_INCOMPLETE`] and a new revision.
    /// It never marks coverage: completion reads and loss acknowledgment keep
    /// requiring `state = 1`.
    ///
    /// For queue or notification loss, every evidence generation of that
    /// cause is retired with it, at its imported count. Evidence not yet
    /// imported is newer loss that rearms the obligation instead, so this
    /// returns false and changes nothing. For incremental history, the
    /// operational comparison slot that served only this debt is settled.
    ///
    /// Returns false for an unknown, stale or no-longer-parked notice. A later
    /// new demand for the same key (new loss, a higher epoch, a new join or
    /// request) reopens the row as fresh pending debt. The caller owns any
    /// process-local fence the retired loss held.
    pub fn retire_parked_recovery_obligation(
        &self,
        id: [u8; 16],
        revision: u64,
        now_ms: u64,
    ) -> StorageResult<bool> {
        let revision = sqlite_integer(revision)?;
        let now = sqlite_integer(now_ms)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let row: Option<(i64, Option<String>)> = conn
                .query_row_cached(
                    "SELECT cause,account_label FROM account_recovery_obligations
                     WHERE id=?1 AND revision=?2 AND state=0 AND eligibility=4",
                    params![id.as_slice(), revision],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .storage()?;
            let Some((cause, label)) = row else {
                return Ok(false);
            };
            let evidence_cause = match cause {
                0 => Some(RecoveryLossCause::Queue),
                6 => Some(RecoveryLossCause::NotificationConsumer),
                _ => None,
            };
            if let Some(evidence_cause) = evidence_cause {
                let label = label.ok_or_else(demand::invalid_demand)?;
                let unimported: bool = conn
                    .query_row_cached(
                        "SELECT EXISTS(SELECT 1 FROM account_delivery_loss_evidence
                         WHERE account_label=?1 AND cause=?2
                           AND (imported_count IS NULL OR dropped_count>imported_count))",
                        params![label, evidence_cause as i64],
                        |row| row.get(0),
                    )
                    .storage()?;
                if unimported {
                    return Ok(false);
                }
                conn.execute_cached(
                    "UPDATE account_delivery_loss_evidence SET retired_count=imported_count
                     WHERE account_label=?1 AND cause=?2",
                    params![label, evidence_cause as i64],
                )
                .storage()?;
            }
            if cause == RecoveryCause::IncrementalHistory as i64 {
                // The dismissal covers the routes it could not certify. A
                // later parking on none but these is the same condition.
                let predicate: i64 = conn
                    .query_row_cached(
                        "SELECT predicate FROM account_recovery_obligations WHERE id=?1",
                        [id.as_slice()],
                        |row| row.get(0),
                    )
                    .storage()?;
                let dismissed = plan::uncertified_scope_keys(&conn, &id, predicate)?;
                conn.execute_cached(
                    "UPDATE account_recovery_obligations SET dismissed_scopes=?2 WHERE id=?1",
                    params![
                        id.as_slice(),
                        serde_json::to_vec(&dismissed).map_err(|_| demand::invalid_demand())?
                    ],
                )
                .storage()?;
            }
            retire_obligation_tx(&conn, &id, now)?;
            Ok(true)
        })
    }
}

/// Record a user-authorized retirement: its own outcome, never coverage. For
/// incremental history, the comparison slot that served only this debt is
/// settled with it.
pub(super) fn retire_obligation_tx(conn: &Connection, id: &[u8], now_ms: i64) -> StorageResult<()> {
    let cause: i64 = conn
        .query_row_cached(
            "SELECT cause FROM account_recovery_obligations WHERE id=?1",
            [id],
            |row| row.get(0),
        )
        .storage()?;
    if cause == RecoveryCause::IncrementalHistory as i64 {
        conn.execute_cached(
            "UPDATE account_recovery_comparison SET settled_revision=revision WHERE singleton=1",
            [],
        )
        .storage()?;
    }
    conn.execute_cached(
        "UPDATE account_recovery_obligations SET state=2,incomplete_reason=?2,urgency=0,
             revision=revision+1,updated_at_ms=MAX(updated_at_ms,?3)
         WHERE id=?1",
        params![id, RETIRED_HISTORY_MAY_BE_INCOMPLETE, now_ms],
    )
    .storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlCipherKey;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    fn fixture() -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("alice").unwrap();
        store
    }

    fn scope() -> RecoveryScopePlan {
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
            required_endpoints: vec!["a".into()],
            admitted_endpoints: vec!["a".into()],
        }
    }

    /// Run one attempt for the selected obligation that certifies nothing and
    /// parks it, as the owner does after its fruitless comparison budget.
    fn park(store: &SqliteAccountStorage, id: [u8; 16]) -> RecoveryDemandTicket {
        let mut fence = store.recovery_revision_fence().unwrap();
        fence.obligations.retain(|(candidate, _)| *candidate == id);
        let attempt = store
            .reserve_recovery_attempt(&fence, 1_000, 15_000, true)
            .unwrap()
            .unwrap()
            .attempt_serial;
        let token = store
            .install_recovery_scope_plan(&fence, attempt, id, &[scope()])
            .unwrap()
            .unwrap()
            .remove(0);
        let checkpoint = RecoveryScopeCheckpoint {
            token,
            endpoints: vec![RecoveryEndpointCheckpoint {
                endpoint: "a".into(),
                outcome: RecoveryScopeOutcome::Unknown,
                exhaustive: false,
                admission_complete: false,
                first_boundary: false,
            }],
            retained_known_event: false,
        };
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &[checkpoint],
                    RecoveryEligibility::NeedsDeepRepair,
                )
                .unwrap()
        );
        let notice = store
            .parked_recovery_obligations()
            .unwrap()
            .into_iter()
            .find(|notice| notice.ticket.id == id)
            .expect("parked occurrence");
        notice.ticket
    }

    /// One attempt that certifies nothing and parks `id` with these scopes.
    /// Returns the notice it raised, if any.
    fn try_park(
        store: &SqliteAccountStorage,
        id: [u8; 16],
        scopes: &[RecoveryScopePlan],
    ) -> Option<RecoveryDemandTicket> {
        let mut fence = store.recovery_revision_fence().unwrap();
        fence.obligations.retain(|(candidate, _)| *candidate == id);
        let attempt = store
            .reserve_recovery_attempt(&fence, 1_000, 15_000, true)
            .unwrap()
            .unwrap()
            .attempt_serial;
        let tokens = store
            .install_recovery_scope_plan(&fence, attempt, id, scopes)
            .unwrap()
            .unwrap();
        let checkpoints = tokens
            .into_iter()
            .map(|token| RecoveryScopeCheckpoint {
                token,
                endpoints: Vec::new(),
                retained_known_event: false,
            })
            .collect::<Vec<_>>();
        assert!(
            !store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt,
                    id,
                    &checkpoints,
                    RecoveryEligibility::NeedsDeepRepair,
                )
                .unwrap()
        );
        store
            .parked_recovery_obligations()
            .unwrap()
            .into_iter()
            .find(|notice| notice.ticket.id == id)
            .map(|notice| notice.ticket)
    }

    #[test]
    fn a_dismissed_incremental_notice_returns_only_for_a_new_stuck_route() {
        let store = fixture();
        let incremental = store
            .request_recovery(RecoveryRequest::IncrementalHistory, 1)
            .unwrap();
        let ticket = try_park(&store, incremental.id, &[scope()]).expect("first notice");
        assert!(
            store
                .retire_parked_recovery_obligation(incremental.id, ticket.revision, 2_000)
                .unwrap()
        );
        // The next start's comparison still runs against the dismissed debt.
        store
            .join_recovery_comparison(&[1; 16], 3_000, &[scope()])
            .unwrap();
        assert!(
            store
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.ticket.id == incremental.id),
            "dismissal never stops the comparison"
        );
        assert!(
            try_park(&store, incremental.id, &[scope()]).is_none(),
            "the same stuck route is the condition the user dismissed"
        );
        assert!(
            !store
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.ticket.id == incremental.id),
            "it is retired again, never counted as coverage"
        );
        assert!(
            !store
                .recovery_obligation_is_satisfied(incremental.id, ticket.revision)
                .unwrap()
        );
        // A route whose required relays changed is a new condition.
        let mut moved = scope();
        moved.required_endpoints = vec!["b".into()];
        moved.admitted_endpoints = vec!["b".into()];
        store
            .join_recovery_comparison(&[2; 16], 4_000, &[moved.clone()])
            .unwrap();
        assert!(
            try_park(&store, incremental.id, &[moved]).is_some(),
            "a route stuck on relays the user never dismissed raises a new notice"
        );
    }

    fn loss_obligation(store: &SqliteAccountStorage) -> [u8; 16] {
        store
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == RecoveryCause::QueueLoss)
            .unwrap()
            .ticket
            .id
    }

    fn row(store: &SqliteAccountStorage, id: [u8; 16]) -> (i64, Option<i64>, i64) {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT state,incomplete_reason,revision FROM account_recovery_obligations WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    #[test]
    fn parking_lists_one_occurrence_with_cause_and_time() {
        let store = fixture();
        store
            .mark_account_delivery_recovery_bounded("alice", 7, 3, Some(5))
            .unwrap();
        let id = loss_obligation(&store);
        assert!(store.parked_recovery_obligations().unwrap().is_empty());
        let before = crate::codec::unix_now_ms() as u64;
        let ticket = park(&store, id);
        let notices = store.parked_recovery_obligations().unwrap();
        assert_eq!(notices.len(), 1);
        assert!(notices[0].ticket == ticket);
        assert_eq!(notices[0].cause, RecoveryCause::QueueLoss);
        assert!(notices[0].group_id.is_none());
        assert!(notices[0].parked_at_ms.unwrap() >= before);
        // A later failed deep repair of the same occurrence keeps its time.
        let first = notices[0].parked_at_ms;
        let again = park(&store, id);
        assert!(again == ticket);
        assert_eq!(
            store.parked_recovery_obligations().unwrap()[0].parked_at_ms,
            first
        );
    }

    #[test]
    fn retirement_is_its_own_outcome_and_never_coverage() {
        let store = fixture();
        store
            .mark_account_delivery_recovery_bounded("alice", 7, 3, Some(5))
            .unwrap();
        let id = loss_obligation(&store);
        let ticket = park(&store, id);
        let fence = store.recovery_revision_fence().unwrap();
        let snapshot = store
            .recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
            .unwrap();
        assert!(
            !store
                .retire_parked_recovery_obligation(id, ticket.revision + 1, 2_000)
                .unwrap(),
            "an unknown occurrence changes nothing"
        );
        assert!(
            store
                .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap()
        );
        assert_eq!(
            row(&store, id),
            (
                2,
                Some(RETIRED_HISTORY_MAY_BE_INCOMPLETE),
                ticket.revision as i64 + 1
            )
        );
        assert!(store.parked_recovery_obligations().unwrap().is_empty());
        assert!(store.pending_recovery_demands().unwrap().is_empty());
        assert!(store.account_delivery_recovery("alice").unwrap().is_none());
        for revision in [ticket.revision, ticket.revision + 1] {
            assert!(
                !store
                    .recovery_obligation_is_satisfied(id, revision)
                    .unwrap()
            );
        }
        assert!(
            !store
                .acknowledge_recovery_loss_snapshot(&fence, id, &snapshot)
                .unwrap(),
            "retired loss can never be acknowledged as covered"
        );
        assert_eq!(store.restore_unacknowledged_recovery_loss().unwrap(), 0);
        assert!(
            store
                .recovery_revision_fence()
                .unwrap()
                .obligations
                .is_empty(),
            "retired debt is not selectable, not even by an explicit repair"
        );
        // The retired watermark stays so a delayed duplicate cannot rearm it,
        // but it no longer bounds any loss goal.
        assert_eq!(
            store
                .recovery_loss_watermarks("alice", RecoveryLossCause::Queue)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .recovery_loss_goal_floor("alice", RecoveryLossCause::Queue)
                .unwrap(),
            None
        );
        assert!(
            !store
                .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap(),
            "a second dismissal of the same occurrence is stale"
        );
    }

    #[test]
    fn duplicate_observations_cannot_rearm_retired_loss() {
        let store = fixture();
        store.mark_account_delivery_recovery("alice", 7, 3).unwrap();
        store
            .record_account_delivery_loss("alice", 9, 2, 10)
            .unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        let id = loss_obligation(&store);
        let ticket = park(&store, id);
        assert!(
            store
                .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap()
        );
        let retired = store.recovery_revision_fence().unwrap();
        // The same generations observed again by the writer, the worker and
        // an import, in either token order, change nothing.
        for token in [7, 9] {
            let count = if token == 7 { 3 } else { 2 };
            store
                .record_account_delivery_loss("alice", token, count, 11)
                .unwrap();
            store
                .mark_account_delivery_recovery("alice", token, count)
                .unwrap();
            store.synchronize_account_delivery_loss("alice").unwrap();
        }
        assert_eq!(store.recovery_revision_fence().unwrap(), retired);
        assert_eq!(row(&store, id).0, 2);
        assert!(store.parked_recovery_obligations().unwrap().is_empty());
    }

    #[test]
    fn new_loss_after_retirement_is_a_new_occurrence() {
        for grown in [false, true] {
            let store = fixture();
            store.mark_account_delivery_recovery("alice", 7, 3).unwrap();
            let id = loss_obligation(&store);
            let first = park(&store, id);
            assert!(
                store
                    .retire_parked_recovery_obligation(id, first.revision, 2_000)
                    .unwrap()
            );
            if grown {
                // More drops in the retired generation are loss the
                // retirement never covered.
                store
                    .record_account_delivery_loss_bounded("alice", 7, 4, 12, Some(8))
                    .unwrap();
            } else {
                store
                    .record_account_delivery_loss_bounded("alice", 11, 1, 12, Some(8))
                    .unwrap();
            }
            store.synchronize_account_delivery_loss("alice").unwrap();
            let (state, reason, revision) = row(&store, id);
            assert_eq!((state, reason), (0, None));
            assert!(revision as u64 > first.revision + 1);
            assert!(store.account_delivery_recovery("alice").unwrap().is_some());
            // Only the new charge bounds the reopened goal.
            assert_eq!(
                store
                    .recovery_loss_goal_floor("alice", RecoveryLossCause::Queue)
                    .unwrap(),
                if grown { None } else { Some(8) }
            );
            let second = park(&store, id);
            assert!(second != first);
            assert!(
                !store
                    .retire_parked_recovery_obligation(id, first.revision, 3_000)
                    .unwrap()
            );
            assert!(
                store
                    .retire_parked_recovery_obligation(id, second.revision, 3_000)
                    .unwrap()
            );
        }
    }

    #[test]
    fn unimported_loss_makes_a_retirement_stale() {
        let store = fixture();
        store.mark_account_delivery_recovery("alice", 7, 3).unwrap();
        let id = loss_obligation(&store);
        let ticket = park(&store, id);
        // The off-worker writer recorded more loss that no import joined yet.
        store
            .record_account_delivery_loss("alice", 7, 5, 11)
            .unwrap();
        assert!(
            !store
                .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap()
        );
        assert_eq!(row(&store, id).0, 0);
        store.synchronize_account_delivery_loss("alice").unwrap();
        assert!(
            !store
                .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap(),
            "the import rearmed the obligation under a new revision"
        );
        assert!(store.parked_recovery_obligations().unwrap().is_empty());
    }

    #[test]
    fn retirement_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retire.sqlite");
        let key = SqlCipherKey::new("history notice retirement").unwrap();
        let (id, ticket) = {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.ensure_account_projection("alice").unwrap();
            store.mark_account_delivery_recovery("alice", 7, 3).unwrap();
            let id = loss_obligation(&store);
            let ticket = park(&store, id);
            assert!(
                store
                    .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                    .unwrap()
            );
            (id, ticket)
        };
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store.restore_unacknowledged_recovery_loss().unwrap();
        store.synchronize_account_delivery_loss("alice").unwrap();
        store.restore_recovery_waiters().unwrap();
        assert_eq!(row(&store, id).0, 2);
        assert!(store.parked_recovery_obligations().unwrap().is_empty());
        assert!(store.account_delivery_recovery("alice").unwrap().is_none());
        assert!(
            !store
                .retire_parked_recovery_obligation(id, ticket.revision, 3_000)
                .unwrap()
        );
    }

    #[test]
    fn retired_epoch_gap_reopens_only_for_a_higher_epoch() {
        let store = fixture();
        store.put_group(&sample_group(gid(1), 7, 2)).unwrap();
        let arm = |epoch| {
            store
                .arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
                    group_id_hex: hex::encode(gid(1).as_slice()),
                    stalled_epoch: epoch,
                }])
                .unwrap()
        };
        arm(7);
        let id = store.pending_recovery_demands().unwrap()[0].ticket.id;
        let ticket = park(&store, id);
        let group = store
            .parked_group_recovery_obligations(gid(1).as_slice())
            .unwrap();
        assert_eq!(group.len(), 1);
        assert_eq!(group[0].cause, RecoveryCause::EpochGap);
        assert_eq!(group[0].group_id.as_deref(), Some(gid(1).as_slice()));
        assert!(
            store
                .parked_group_recovery_obligations(gid(2).as_slice())
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .retire_parked_recovery_obligation(id, ticket.revision, 2_000)
                .unwrap()
        );
        arm(7);
        assert_eq!(row(&store, id).0, 2);
        assert!(store.pending_epoch_backfill_intents().unwrap().is_empty());
        arm(8);
        assert_eq!(row(&store, id).0, 0);
        assert_eq!(store.pending_epoch_backfill_intents().unwrap().len(), 1);
        assert!(
            store
                .parked_group_recovery_obligations(gid(1).as_slice())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn retired_history_requests_reopen_as_fresh_demand() {
        let store = fixture();
        let incremental = store
            .request_recovery(RecoveryRequest::IncrementalHistory, 1)
            .unwrap();
        let stale = park(&store, incremental.id);
        // A startup comparison join is new evidence: it unparks the debt.
        store
            .join_recovery_comparison(&[1; 16], 1_000, &[scope()])
            .unwrap();
        assert!(store.parked_recovery_obligations().unwrap().is_empty());
        assert!(
            !store
                .retire_parked_recovery_obligation(incremental.id, stale.revision, 2_000)
                .unwrap()
        );
        let ticket = park(&store, incremental.id);
        assert!(store.recovery_comparison().unwrap().pending());
        assert!(
            store
                .retire_parked_recovery_obligation(incremental.id, ticket.revision, 2_000)
                .unwrap()
        );
        assert!(
            !store.recovery_comparison().unwrap().pending(),
            "the comparison slot served only the retired debt"
        );
        let reopened = store
            .request_recovery(RecoveryRequest::IncrementalHistory, 3_000)
            .unwrap();
        assert_eq!(reopened.id, incremental.id);
        assert_eq!(row(&store, incremental.id).0, 0);
        assert!(reopened.revision > ticket.revision + 1);

        let operation = [5; 16];
        let explicit = store
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &operation,
                },
                1,
            )
            .unwrap();
        let ticket = park(&store, explicit.id);
        assert!(
            store
                .retire_parked_recovery_obligation(explicit.id, ticket.revision, 2_000)
                .unwrap()
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT urgency FROM account_recovery_obligations WHERE id=?1",
                    [explicit.id.as_slice()],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let next = store
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &[6; 16],
                },
                4_000,
            )
            .unwrap();
        assert_eq!(next.id, explicit.id);
        assert_eq!(row(&store, explicit.id), (0, None, next.revision as i64));
    }
}
