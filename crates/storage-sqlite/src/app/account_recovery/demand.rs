//! The old recovery owner's obligations that the runner still reads: the
//! pending demand read, maintenance reclamation, terminal-group retirement and
//! epoch-gap capacity pressure. Duplicate pressure joins one row and one
//! waiting period.
use super::*;
#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::SqliteAppStorage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum RecoveryPredicate {
    AllEndpoints = 0,
    RetainedKnownEvent = 1,
    MaintenanceBoundary = 2,
    ReplayAdmission = 3,
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
    SubscriptionReplay = 7,
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

pub(super) fn invalid_demand() -> StorageError {
    StorageError::Serialization("invalid recovery demand".into())
}

pub(super) fn recovery_cause(value: i64) -> StorageResult<RecoveryCause> {
    Ok(match value {
        0_i64 => RecoveryCause::QueueLoss,
        1_i64 => RecoveryCause::EpochGap,
        2_i64 => RecoveryCause::Maintenance,
        3_i64 => RecoveryCause::ExplicitHistory,
        4_i64 => RecoveryCause::KnownEvent,
        5_i64 => RecoveryCause::IncrementalHistory,
        6_i64 => RecoveryCause::NotificationLoss,
        7_i64 => RecoveryCause::SubscriptionReplay,
        _ => return Err(invalid_demand()),
    })
}

impl SqliteAppStorage {
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

    /// Retire group-scoped recovery only after the account owner observes a
    /// terminal group. Account-wide loss evidence survives.
    pub fn retire_terminal_group_recovery(
        &self,
        group: &cgka_traits::GroupId,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            self.lock()?
                .execute_cached(
                    "DELETE FROM account_recovery_obligations WHERE group_id=?1 AND cause IN (1,2,4)",
                    [group.as_slice()],
                )
                .storage()?;
            self.clear_recovery_failure(group)
        })
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
                        cause: recovery_cause(cause)?,
                        predicate: match predicate {
                            0_i64 => RecoveryPredicate::AllEndpoints,
                            1_i64 => RecoveryPredicate::RetainedKnownEvent,
                            2_i64 => RecoveryPredicate::MaintenanceBoundary,
                            3_i64 => RecoveryPredicate::ReplayAdmission,
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

impl SqliteAppStorage {
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
mod tests {
    use super::*;
    use crate::RecoveryLossCause;
    use crate::app::account_recovery::tests::assert_backend;
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    fn group_obligations(store: &SqliteAccountStorage) -> i64 {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM account_recovery_obligations WHERE group_id=?1",
                [gid(1).as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn terminal_retirement_failure_preserves_all_group_debt_and_independent_loss() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        let group = gid(1);
        app.ensure_account_projection("alice").unwrap();
        store.put_group(&sample_group(group.clone(), 1, 2)).unwrap();
        app.arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
            group_id_hex: hex::encode(group.as_slice()),
            stalled_epoch: 1,
        }])
        .unwrap();
        app.record_epoch_stall_evidence(&[crate::StoredEpochStallEvidence {
            group_id_hex: hex::encode(group.as_slice()),
            stalled_epoch: 1,
            fruitless_completions: 2,
            fruitless_reported: false,
            last_arm_at_ms: 1,
        }])
        .unwrap();
        // An upgraded database can still hold the old owner's known-event and
        // maintenance obligations for the group.
        app.execute_batch_for_test(&format!(
            "INSERT INTO account_recovery_obligations (id, demand_key, cause, predicate, group_id, created_at_ms, updated_at_ms)
             VALUES (x'{known}', 'known', 4, 1, x'{group}', 1, 1), (x'{job}', 'maintenance', 2, 2, x'{group}', 1, 1);",
            known = "08".repeat(16),
            job = "09".repeat(16),
            group = hex::encode(group.as_slice()),
        ))
        .unwrap();
        app.record_account_recovery_loss("alice", RecoveryLossCause::Queue, 55, 1, 1)
            .unwrap();
        let loss = app
            .recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
            .unwrap();
        assert_eq!(group_obligations(&store), 3);

        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_terminal_retire BEFORE DELETE ON app_epoch_stall_evidence BEGIN SELECT RAISE(ABORT, 'injected terminal retire failure'); END;").unwrap();
        assert_backend(
            app.retire_terminal_group_recovery(&group),
            "injected terminal retire failure",
        );
        assert_eq!(group_obligations(&store), 3);
        assert_eq!(app.epoch_stall_evidence().unwrap().len(), 1);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_terminal_retire")
            .unwrap();

        app.retire_terminal_group_recovery(&group).unwrap();
        assert_eq!(group_obligations(&store), 0);
        assert!(app.epoch_stall_evidence().unwrap().is_empty());
        assert!(
            app.recovery_loss_snapshot("alice", RecoveryLossCause::Queue)
                .unwrap()
                == loss
        );
        assert!(!app.retire_terminal_group_recovery(&group).unwrap());
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    fn only_demand(app: &SqliteAppStorage) -> (RecoveryDemandTicket, RecoveryEligibility) {
        let demands = app.pending_recovery_demands().unwrap();
        assert_eq!(demands.len(), 1, "duplicate pressure joins one row");
        (demands[0].ticket, demands[0].eligibility)
    }

    #[test]
    fn admission_pressure_waits_its_relief_interval_before_a_probe() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        store.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        app.record_recovery_capacity_pressure(gid(1).as_slice(), 1, 1_000)
            .unwrap();
        let (original, eligibility) = only_demand(&app);
        assert_eq!(eligibility, RecoveryEligibility::WaitingCapacity);
        app.record_recovery_capacity_pressure(gid(1).as_slice(), 1, 5_000)
            .unwrap();
        assert!(only_demand(&app) == (original, RecoveryEligibility::WaitingCapacity));

        // The waiting period runs from the first pressure, not the duplicate.
        app.release_due_recovery_capacity_probes(15_999, 15_000)
            .unwrap();
        assert_eq!(only_demand(&app).1, RecoveryEligibility::WaitingCapacity);
        app.release_due_recovery_capacity_probes(16_000, 15_000)
            .unwrap();
        assert_eq!(only_demand(&app).1, RecoveryEligibility::Retry);

        // New pressure on the probe starts a new waiting period.
        app.record_recovery_capacity_pressure(gid(1).as_slice(), 1, 16_001)
            .unwrap();
        assert_eq!(only_demand(&app).1, RecoveryEligibility::WaitingCapacity);
        app.release_due_recovery_capacity_probes(31_000, 15_000)
            .unwrap();
        assert_eq!(only_demand(&app).1, RecoveryEligibility::WaitingCapacity);
        app.release_due_recovery_capacity_probes(31_001, 15_000)
            .unwrap();
        assert_eq!(only_demand(&app).1, RecoveryEligibility::Retry);
    }
}
