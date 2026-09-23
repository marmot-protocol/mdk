//! Typed joins for non-legacy recovery callers. Duplicate requests do not rearm
//! capability-blocked work, alter frozen scopes, or forgive account retry cost.
use super::*;

/// Identities are private to this account database. Job/operation identities
/// come from their existing owner; recovery does not allocate another scheduler.
pub enum RecoveryRequest<'a> {
    MaintenanceBoundary {
        job_id: &'a [u8],
        group_id: &'a [u8],
    },
    ExplicitHistory {
        operation_id: &'a [u8; 16],
    },
    KnownEvent {
        group_id: &'a [u8],
        event_id: &'a [u8; 32],
    },
    IncrementalHistory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum RecoveryPredicate {
    AllEndpoints = 0,
    RetainedKnownEvent = 1,
    MaintenanceBoundary = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum RecoveryCause {
    QueueLoss = 0,
    EpochGap = 1,
    Maintenance = 2,
    ExplicitHistory = 3,
    KnownEvent = 4,
    IncrementalHistory = 5,
    NotificationLoss = 6,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoveryDemandTicket {
    pub id: [u8; 16],
    pub revision: u64,
}

/// Durable demand inspection; none of these identities belong in telemetry.
pub struct RecoveryDemand {
    pub ticket: RecoveryDemandTicket,
    pub cause: RecoveryCause,
    pub predicate: RecoveryPredicate,
    pub eligibility: RecoveryEligibility,
    pub group_id: Option<Vec<u8>>,
    pub stalled_epoch: Option<u64>,
    pub marker_token: Option<u64>,
    pub known_event_id: Option<[u8; 32]>,
    pub requested_at_ms: u64,
    /// A live explicit caller owns transient foreground urgency.
    pub caller_waiting: bool,
}

fn invalid_demand() -> StorageError {
    StorageError::Serialization("invalid recovery demand".into())
}

impl SqliteAccountStorage {
    pub fn request_recovery(
        &self,
        request: RecoveryRequest<'_>,
        now_ms: u64,
    ) -> StorageResult<RecoveryDemandTicket> {
        let (key, cause, predicate, group, event, caller) = match request {
            RecoveryRequest::MaintenanceBoundary { job_id, group_id } => {
                if job_id.is_empty() || group_id.is_empty() {
                    return Err(invalid_demand());
                }
                (
                    format!(
                        "maintenance:{}:{}:2",
                        hex::encode(group_id),
                        hex::encode(job_id)
                    ),
                    2,
                    2,
                    Some(group_id),
                    None,
                    false,
                )
            }
            RecoveryRequest::ExplicitHistory { operation_id } => (
                format!("explicit:{}", hex::encode(operation_id)),
                3,
                0,
                None,
                None,
                true,
            ),
            RecoveryRequest::KnownEvent { group_id, event_id } => {
                if group_id.is_empty() {
                    return Err(invalid_demand());
                }
                (
                    format!("known:{}:{}", hex::encode(group_id), hex::encode(event_id)),
                    4,
                    1,
                    Some(group_id),
                    Some(event_id.as_slice()),
                    false,
                )
            }
            RecoveryRequest::IncrementalHistory => ("incremental".into(), 5, 0, None, None, false),
        };
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if cause == 3 {
                // Serialized foreground operations share one account-history
                // obligation. A new caller expands its revision/goal without
                // forgiving retry cost; stale cancellation tickets cannot
                // detach the new caller. The most recent operation key makes
                // duplicate joins idempotent without an unbounded waiter log.
                conn.execute_cached(
                    "UPDATE account_recovery_obligations SET demand_key=?1,
                     revision=revision+1,state=0,eligibility=0,urgency=1,updated_at_ms=?2
                     WHERE cause=3 AND demand_key!=?1",
                    params![key,sqlite_integer(now_ms)?],
                ).storage()?;
            }
            conn.execute_cached(
                "INSERT INTO account_recovery_obligations
                 (demand_key,cause,predicate,group_id,created_at_ms,updated_at_ms,caller_origin,urgency)
                 VALUES (?1,?2,?3,?4,?5,?5,?6,?6)
                 ON CONFLICT(demand_key) DO UPDATE SET state=0,revision=revision+1,
                     eligibility=0,updated_at_ms=excluded.updated_at_ms
                 WHERE account_recovery_obligations.state=1 AND account_recovery_obligations.cause IN (4,5)",
                params![key,cause,predicate,group,sqlite_integer(now_ms)?,caller],
            ).storage()?;
            let (id,revision): (Vec<u8>,i64) = conn.query_row_cached(
                "SELECT id,revision FROM account_recovery_obligations WHERE demand_key=?1",
                [&key], |row| Ok((row.get(0)?,row.get(1)?)),
            ).storage()?;
            conn.execute_cached(
                "INSERT OR IGNORE INTO account_recovery_scopes(obligation_id,scope_id,group_id,known_event_id)
                 VALUES (?1,0,?2,?3)", params![id,group,event],
            ).storage()?;
            Ok(RecoveryDemandTicket { id: id.try_into().map_err(|_| invalid_demand())?, revision: i64_to_u64(revision)? })
        })
    }

    /// Restore the temporary session for an existing maintenance job after
    /// physical session loss. This rearms only its limited boundary predicate;
    /// history debt, domain grace timers and account retry cost are untouched.
    /// The worker calls this only when no matching live session exists.
    pub fn restore_recovery_maintenance_session(
        &self,
        ticket: RecoveryDemandTicket,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE account_recovery_obligations SET state=0,eligibility=1,revision=revision+1
             WHERE id=?1 AND revision=?2 AND cause=2 AND predicate=2 AND state=1",
                params![ticket.id.as_slice(), sqlite_integer(ticket.revision)?],
            )
            .storage()?;
        Ok(())
    }

    /// A selected account activation replaces all physical subscriptions.
    /// Include its still-needed maintenance sessions in that same reservation.
    /// Call within the reservation transaction, only once other work is due.
    pub fn rearm_recovery_maintenance_for_activation(&self, ids: &[[u8; 16]]) -> StorageResult<()> {
        let conn = self.lock()?;
        for id in ids {
            conn.execute_cached(
                "UPDATE account_recovery_obligations SET state=0,eligibility=1,revision=revision+1
                 WHERE id=?1 AND cause=2 AND predicate=2 AND state IN (0,1)",
                [id.as_slice()],
            )
            .storage()?;
        }
        Ok(())
    }

    /// Remove prerequisites whose owning domain job no longer needs a session.
    /// The caller supplies the complete current domain set; independent history
    /// and loss obligations are never included in this reclamation.
    pub fn retain_recovery_maintenance_jobs(
        &self,
        jobs: &[(Vec<u8>, Vec<u8>)],
    ) -> StorageResult<()> {
        let keys = jobs
            .iter()
            .map(|(job, group)| {
                format!("maintenance:{}:{}:2", hex::encode(group), hex::encode(job))
            })
            .collect::<std::collections::HashSet<_>>();
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let existing = conn.prepare_cached("SELECT demand_key FROM account_recovery_obligations WHERE cause=2 AND predicate=2")
                .storage()?.query_map([], |row| row.get::<_, String>(0)).storage()?
                .collect::<Result<Vec<_>, _>>().storage()?;
            for key in existing {
                if !keys.contains(&key) {
                    conn.execute_cached("DELETE FROM account_recovery_obligations WHERE demand_key=?1 AND cause=2 AND predicate=2", [&key]).storage()?;
                }
            }
            Ok(())
        })
    }

    /// The serialized owner calls this only with no live attempt or caller
    /// referring to known-event completion. Pending debt is never reclaimed;
    /// epoch certificates and maintenance jobs have their own longer lifetimes.
    pub fn reclaim_completed_recovery_events(&self) -> StorageResult<usize> {
        self.lock()?.execute_cached(
            "DELETE FROM account_recovery_obligations WHERE cause=4 AND predicate=1 AND state=1 AND urgency=0",
            [],
        ).storage()
    }

    /// A cancelled last foreground waiter loses urgency, not durable work.
    /// System demand and other callers have independent identities/predicates.
    pub fn detach_recovery_waiter(&self, ticket: RecoveryDemandTicket) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached("DELETE FROM account_recovery_obligations WHERE id=?1 AND revision=?2 AND caller_origin=1 AND state=1",
                params![ticket.id.as_slice(),sqlite_integer(ticket.revision)?]).storage()?;
            conn.execute_cached("UPDATE account_recovery_obligations SET urgency=0 WHERE id=?1 AND revision=?2 AND caller_origin=1",
                params![ticket.id.as_slice(),sqlite_integer(ticket.revision)?]).storage()?;
            Ok(())
        })
    }

    /// A recreated owner has no live caller from the previous session. Retain
    /// incomplete debt and pacing; reclaim only already-satisfied caller rows.
    pub fn restore_recovery_waiters(&self) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "DELETE FROM account_recovery_obligations WHERE caller_origin=1 AND state=1",
                [],
            )
            .storage()?;
            conn.execute_cached(
                "UPDATE account_recovery_obligations SET urgency=0 WHERE caller_origin=1",
                [],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Read a completion verdict at the exact obligation revision; superseded
    /// or reclaimed rows cannot become evidence for an older attempt.
    pub fn recovery_obligation_is_satisfied(
        &self,
        id: [u8; 16],
        revision: u64,
    ) -> StorageResult<bool> {
        self.lock()?.query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM account_recovery_obligations WHERE id=?1 AND revision=?2 AND state=1)",
            params![id.as_slice(),sqlite_integer(revision)?], |row| row.get(0),
        ).storage()
    }

    pub fn pending_recovery_demands(&self) -> StorageResult<Vec<RecoveryDemand>> {
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT id,revision,cause,predicate,eligibility,group_id,stalled_epoch,marker_token,
             (SELECT known_event_id FROM account_recovery_scopes WHERE obligation_id=account_recovery_obligations.id AND known_event_id IS NOT NULL LIMIT 1), updated_at_ms, urgency
             FROM account_recovery_obligations WHERE state=0 ORDER BY id",
            )
            .storage()?
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, bool>(10)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(
                |(
                    id,
                    revision,
                    cause,
                    predicate,
                    eligibility,
                    group_id,
                    epoch,
                    token,
                    known,
                    requested_at,
                    caller_waiting,
                )| {
                    Ok(RecoveryDemand {
                        ticket: RecoveryDemandTicket {
                            id: id.try_into().map_err(|_| invalid_demand())?,
                            revision: i64_to_u64(revision)?,
                        },
                        cause: match cause {
                            0 => RecoveryCause::QueueLoss,
                            1 => RecoveryCause::EpochGap,
                            2 => RecoveryCause::Maintenance,
                            3 => RecoveryCause::ExplicitHistory,
                            4 => RecoveryCause::KnownEvent,
                            5 => RecoveryCause::IncrementalHistory,
                            6 => RecoveryCause::NotificationLoss,
                            _ => return Err(invalid_demand()),
                        },
                        predicate: match predicate {
                            0 => RecoveryPredicate::AllEndpoints,
                            1 => RecoveryPredicate::RetainedKnownEvent,
                            2 => RecoveryPredicate::MaintenanceBoundary,
                            _ => return Err(invalid_demand()),
                        },
                        eligibility: match eligibility {
                            0 => RecoveryEligibility::Ready,
                            1 => RecoveryEligibility::Retry,
                            2 => RecoveryEligibility::WaitingCapacity,
                            3 => RecoveryEligibility::WaitingCapability,
                            4 => RecoveryEligibility::NeedsDeepRepair,
                            _ => return Err(invalid_demand()),
                        },
                        group_id,
                        requested_at_ms: i64_to_u64(requested_at)?,
                        caller_waiting,
                        known_event_id: known
                            .map(|bytes| bytes.try_into().map_err(|_| invalid_demand()))
                            .transpose()?,
                        stalled_epoch: epoch.map(i64_to_u64).transpose()?,
                        marker_token: token.map(i64_to_u64).transpose()?,
                    })
                },
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelling_one_caller_preserves_independent_demand_and_quiescence() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let operation = [7; 16];
        let caller = store
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &operation,
                },
                1000,
            )
            .unwrap();
        store
            .request_recovery(RecoveryRequest::IncrementalHistory, 1000)
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        store
            .reserve_recovery_attempt(&fence, 1000, 15000, true)
            .unwrap()
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("UPDATE account_recovery_obligations SET eligibility=3")
            .unwrap();
        store.detach_recovery_waiter(caller).unwrap();
        let joined = store
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &operation,
                },
                999999,
            )
            .unwrap();
        assert!(joined == caller);
        store
            .request_recovery(RecoveryRequest::IncrementalHistory, 999999)
            .unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), fence);
        assert_eq!(store.pending_recovery_demands().unwrap().len(), 2);
        assert!(
            store
                .recovery_eligible_revision_fence(false)
                .unwrap()
                .obligations
                .is_empty()
        );
        assert_eq!(store.recovery_retry_state().unwrap().not_before_ms, 16000);
    }
    #[test]
    fn maintenance_session_restore_and_reclamation_preserve_other_debt_and_retry() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_groups(id,epoch,record) VALUES (?1,0,x'00')",
                [b"group".as_slice()],
            )
            .unwrap();
        let ticket = store
            .request_recovery(
                RecoveryRequest::MaintenanceBoundary {
                    job_id: b"job",
                    group_id: b"group",
                },
                1,
            )
            .unwrap();
        let other = store
            .request_recovery(RecoveryRequest::IncrementalHistory, 1)
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        store
            .reserve_recovery_attempt(&fence, 1, 15000, false)
            .unwrap()
            .unwrap();
        let retry = store.recovery_retry_state().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_recovery_obligations SET state=1 WHERE id=?1",
                [ticket.id.as_slice()],
            )
            .unwrap();
        store.restore_recovery_maintenance_session(ticket).unwrap();
        let restored = store.pending_recovery_demands().unwrap();
        assert_eq!(
            restored
                .iter()
                .find(|demand| demand.ticket.id == ticket.id)
                .unwrap()
                .ticket
                .revision,
            ticket.revision + 1
        );
        store.restore_recovery_maintenance_session(ticket).unwrap();
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        store
            .retain_recovery_maintenance_jobs(&[(b"job".to_vec(), b"group".to_vec())])
            .unwrap();
        assert_eq!(store.pending_recovery_demands().unwrap().len(), 2);
        store.retain_recovery_maintenance_jobs(&[]).unwrap();
        let retained = store.pending_recovery_demands().unwrap();
        assert_eq!(retained.len(), 1);
        assert!(retained[0].ticket == other);
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        let count: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM account_recovery_scopes WHERE obligation_id=?1",
                [ticket.id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn successive_explicit_callers_reuse_debt_without_free_retry_or_stale_detach() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let first = store
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &[0; 16],
                },
                1,
            )
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        store
            .reserve_recovery_attempt(&fence, 1, 15000, true)
            .unwrap()
            .unwrap();
        let retry = store.recovery_retry_state().unwrap();
        for index in 1..100 {
            let ticket = store
                .request_recovery(
                    RecoveryRequest::ExplicitHistory {
                        operation_id: &[index; 16],
                    },
                    u64::from(index),
                )
                .unwrap();
            assert_eq!(ticket.id, first.id);
            assert_eq!(ticket.revision, first.revision + u64::from(index));
            store.detach_recovery_waiter(first).unwrap();
            assert_eq!(store.pending_recovery_demands().unwrap().len(), 1);
            assert_eq!(store.recovery_retry_state().unwrap(), retry);
        }
        let urgency: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT urgency FROM account_recovery_obligations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(urgency, 1);
    }
}

#[cfg(test)]
mod waiter_tests {
    use super::*;
    #[test]
    fn abandoned_waiter_keeps_debt_and_satisfied_waiter_is_reclaimed() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let ticket = store
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &[7; 16],
                },
                1,
            )
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        let retry = store
            .reserve_recovery_attempt(&fence, 1, 15_000, true)
            .unwrap()
            .unwrap();
        store.restore_recovery_waiters().unwrap();
        assert_eq!(
            store.pending_recovery_demands().unwrap()[0].ticket.id,
            ticket.id
        );
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT urgency FROM account_recovery_obligations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        store
            .lock()
            .unwrap()
            .execute("UPDATE account_recovery_obligations SET state=1", [])
            .unwrap();
        store.detach_recovery_waiter(ticket).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM account_recovery_obligations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
    }
}

impl SqliteAccountStorage {
    /// Admission pressure is demand, not permission for immediate replay into
    /// the same queue. Duplicate pressure joins one row and one waiting period.
    pub fn record_recovery_capacity_pressure(
        &self,
        group: &[u8],
        epoch: u64,
        now_ms: u64,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let qualified: bool = conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_recovery_obligations WHERE cause=1 AND group_id=?1 AND state=1)",
                [group], |row| row.get(0),
            ).storage()?;
            join_epoch_tx(&conn, group, sqlite_integer(epoch)?, sqlite_integer(now_ms / 1000)?, qualified)?;
            conn.execute_cached(
                "UPDATE account_recovery_obligations SET eligibility=2,updated_at_ms=?2
                 WHERE cause=1 AND group_id=?1 AND stalled_epoch=?3 AND state=0 AND eligibility!=2",
                params![group,sqlite_integer(now_ms)?,sqlite_integer(epoch)?],
            ).storage()?;
            Ok(())
        })
    }

    /// The existing owner tick may authorize a bounded pressure probe after the
    /// minimum relief interval. The account retry reservation still applies;
    /// this does not reset pacing, increment attempts or start network work.
    pub fn release_due_recovery_capacity_probes(
        &self,
        now_ms: u64,
        minimum_delay_ms: u64,
    ) -> StorageResult<()> {
        let Some(before) = now_ms.checked_sub(minimum_delay_ms) else {
            return Ok(());
        };
        self.lock()?
            .execute_cached(
                "UPDATE account_recovery_obligations SET eligibility=1
             WHERE state=0 AND eligibility=2 AND updated_at_ms<=?1",
                [sqlite_integer(before)?],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    #[test]
    fn admission_pressure_waits_before_a_probe_without_resetting_retry_cost() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        store
            .record_recovery_capacity_pressure(gid(1).as_slice(), 1, 1_000)
            .unwrap();
        let original = store.recovery_revision_fence().unwrap();
        store
            .record_recovery_capacity_pressure(gid(1).as_slice(), 1, 5_000)
            .unwrap();
        assert_eq!(store.recovery_revision_fence().unwrap(), original);
        store
            .release_due_recovery_capacity_probes(15_999, 15_000)
            .unwrap();
        assert!(
            store
                .recovery_eligible_revision_fence(false)
                .unwrap()
                .obligations
                .is_empty()
        );
        assert_eq!(store.recovery_retry_state().unwrap().attempt_serial, 0);
        store
            .release_due_recovery_capacity_probes(16_000, 15_000)
            .unwrap();
        let fence = store.recovery_eligible_revision_fence(false).unwrap();
        let first = store
            .reserve_recovery_attempt(&fence, 16_000, 15_000, false)
            .unwrap()
            .unwrap();
        store
            .record_recovery_capacity_pressure(gid(1).as_slice(), 1, 16_001)
            .unwrap();
        store
            .release_due_recovery_capacity_probes(31_000, 15_000)
            .unwrap();
        assert!(
            store
                .recovery_eligible_revision_fence(false)
                .unwrap()
                .obligations
                .is_empty()
        );
        assert_eq!(store.recovery_retry_state().unwrap(), first);
        store
            .release_due_recovery_capacity_probes(31_001, 15_000)
            .unwrap();
        let second = store
            .reserve_recovery_attempt(&fence, 31_001, 30_000, false)
            .unwrap()
            .unwrap();
        assert_eq!(second.ordinal, 2);
        assert_eq!(store.pending_recovery_demands().unwrap().len(), 1);
    }

    #[test]
    fn abandoned_waiter_keeps_debt_and_satisfied_waiter_is_reclaimed() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let ticket = store
            .request_recovery(
                RecoveryRequest::ExplicitHistory {
                    operation_id: &[7; 16],
                },
                1,
            )
            .unwrap();
        let fence = store.recovery_revision_fence().unwrap();
        let retry = store
            .reserve_recovery_attempt(&fence, 1, 15_000, true)
            .unwrap()
            .unwrap();
        store.restore_recovery_waiters().unwrap();
        assert_eq!(
            store.pending_recovery_demands().unwrap()[0].ticket.id,
            ticket.id
        );
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT urgency FROM account_recovery_obligations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        store
            .lock()
            .unwrap()
            .execute("UPDATE account_recovery_obligations SET state=1", [])
            .unwrap();
        store.detach_recovery_waiter(ticket).unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM account_recovery_obligations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
    }
}
