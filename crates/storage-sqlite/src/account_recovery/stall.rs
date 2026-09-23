//! Qualified coverage plus a separately performed local evaluation. Timers and
//! relay EOSE never create a certificate. The account worker supplies the epoch
//! actually observed after evaluating eligible local convergence work.
use super::*;
use cgka_traits::storage::StorageProvider;
use rusqlite::OptionalExtension;

pub struct QualifiedRecoveryStallSample {
    pub evidence: crate::StoredEpochStallEvidence,
    pub escalated: bool,
    pub warning_changed: bool,
}

impl SqliteAccountStorage {
    /// Retire group-scoped recovery only after the account owner observes a
    /// terminal group. Account-wide history/loss debt and retry cost survive.
    pub fn retire_terminal_group_recovery(
        &self,
        group: &cgka_traits::GroupId,
    ) -> StorageResult<bool> {
        self.with_transaction(|storage| {
            storage.lock()?.execute_cached(
                "DELETE FROM account_recovery_obligations WHERE group_id=?1 AND cause IN (1,2,4)",
                [group.as_slice()],
            ).storage()?;
            storage.clear_recovery_failure(group)
        })
    }

    /// Allocate only after a real local convergence evaluation, not when polling
    /// its result. A repeated certificate must reuse the returned revision.
    pub fn next_recovery_engine_observation(&self) -> StorageResult<u64> {
        let value = self.lock()?.query_row_cached(
            "UPDATE account_recovery_state SET next_engine_observation=next_engine_observation+1
             WHERE singleton=1 RETURNING next_engine_observation", [], |row| row.get::<_, i64>(0),
        ).storage()?;
        i64_to_u64(value)
    }

    /// Count at most one distinct evaluation per interval under still-qualified
    /// group coverage. Coverage, sample identity, counter and one-shot warning
    /// commit together. Legacy EOSE counters are not qualified samples; the first
    /// certificate starts at one while preserving any warning already reported.
    pub fn sample_qualified_recovery_stall(
        &self,
        group: &[u8],
        stalled_epoch: u64,
        engine_observation: u64,
        now_ms: u64,
        interval_ms: u64,
        threshold: u32,
    ) -> StorageResult<Option<QualifiedRecoveryStallSample>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if engine_observation == 0 || !plan::no_unimported_loss(&conn)? { return Ok(None); }
            let issued: i64 = conn.query_row_cached("SELECT next_engine_observation FROM account_recovery_state WHERE singleton=1", [], |row| row.get(0)).storage()?;
            if engine_observation > i64_to_u64(issued)? { return Ok(None); }
            let current = revision_fence(&conn)?;
            let obligation: Option<(Vec<u8>, i64)> = conn.query_row_cached(
                "SELECT id,revision FROM account_recovery_obligations
                 WHERE cause=1 AND group_id=?1 AND stalled_epoch=?2 AND predicate=0 AND state=1",
                params![group, sqlite_integer(stalled_epoch)?], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().storage()?;
            let Some((id, revision)) = obligation else { return Ok(None); };
            let scopes = conn.prepare_cached(
                "SELECT scope_id,scope_revision,scope_format,scope_payload,snapshot_state
                 FROM account_recovery_scopes WHERE obligation_id=?1 ORDER BY scope_id",
            ).storage()?.query_map([&id], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,Option<Vec<u8>>>(3)?,row.get::<_,i64>(4)?)))
                .storage()?.collect::<Result<Vec<_>,_>>().storage()?;
            if scopes.is_empty() { return Ok(None); }
            let mut coverage = Vec::with_capacity(scopes.len());
            for (scope, scope_revision, format, bytes, ready) in scopes {
                let Some(bytes) = bytes.filter(|_| ready == 1) else { return Ok(None); };
                let payload = plan::decode_scope(format, &bytes)?;
                // Retention invalidates the affected scope token/proof. An
                // unrelated account inventory change cannot erase a valid
                // local blocked-engine observation under this installed scope.
                if payload.obligation_revision != i64_to_u64(revision)?
                    || payload.loss_revision != current.loss_revision
                    || payload.route_revision != current.route_revision
                    || !plan::payload_is_qualified(&payload, 0, false)
                { return Ok(None); }
                coverage.push((scope, scope_revision));
            }
            // An absent or epoch-mismatched detector row cannot be invented by
            // arbitrary ciphertext, a completed unrelated scope or this timer.
            type StallEvidenceRow = (i64, i64, bool, i64, Option<Vec<u8>>, i64, Option<i64>);
            let prior: Option<StallEvidenceRow> = conn.query_row_cached(
                "SELECT stalled_epoch,fruitless_completions,fruitless_reported,last_arm_at_ms,
                 qualified_certificate,last_engine_observation,last_sample_at_ms
                 FROM app_epoch_stall_evidence WHERE group_id=?1", [group],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            ).optional().storage()?;
            let Some((epoch,count,reported,last_arm,certificate,last_engine,last_sample)) = prior else { return Ok(None); };
            if i64_to_u64(epoch)? != stalled_epoch || engine_observation <= i64_to_u64(last_engine)? { return Ok(None); }
            // Even an observation made too early is consumed. Polling that
            // same engine result after the interval is not a new evaluation.
            conn.execute_cached("UPDATE app_epoch_stall_evidence SET last_engine_observation=?2 WHERE group_id=?1",
                params![group,sqlite_integer(engine_observation)?]).storage()?;
            if let Some(last) = last_sample {
                // Rebase a backward clock once and consume this observation;
                // reopening or polling cannot turn the correction into credit.
                if now_ms < i64_to_u64(last)? {
                    conn.execute_cached("UPDATE app_epoch_stall_evidence SET last_sample_at_ms=?2,last_engine_observation=?3 WHERE group_id=?1",
                        params![group,sqlite_integer(now_ms)?,sqlite_integer(engine_observation)?]).storage()?;
                    return Ok(None);
                }
                if now_ms.saturating_sub(i64_to_u64(last)?) < interval_ms { return Ok(None); }
            }
            let count = if certificate.is_some() { i64_to_u64(count)?.saturating_add(1) } else { 1 };
            let count = count.min(u64::from(u32::MAX)) as u32;
            let escalated = count >= threshold.max(1) && !reported;
            let sequence: i64 = conn.query_row_cached(
                "UPDATE account_recovery_state SET next_stall_sample=next_stall_sample+1 WHERE singleton=1 RETURNING next_stall_sample",
                [], |row| row.get(0),
            ).storage()?;
            let certificate = serde_json::to_vec(&(1_u8, &id, revision, stalled_epoch, coverage,
                current.loss_revision,current.route_revision,current.inventory_revision,engine_observation,sequence))
                .map_err(|_| StorageError::Serialization("invalid qualified stall certificate".into()))?;
            conn.execute_cached(
                "UPDATE app_epoch_stall_evidence SET fruitless_completions=?2,fruitless_reported=?3,
                 qualified_certificate=?4,last_engine_observation=?5,last_sample_sequence=?6,last_sample_at_ms=?7,
                 updated_at=?8 WHERE group_id=?1",
                params![group,i64::from(count),reported || escalated,certificate,sqlite_integer(engine_observation)?,sequence,sqlite_integer(now_ms)?,sqlite_integer(now_ms/1000)?],
            ).storage()?;
            let warning_changed = if escalated {
                conn.execute_cached("INSERT OR IGNORE INTO app_group_recovery_failures(group_id) VALUES (?1)",[group]).storage()? > 0
            } else { false };
            Ok(Some(QualifiedRecoveryStallSample {
                evidence: crate::StoredEpochStallEvidence { group_id_hex: hex::encode(group), stalled_epoch,
                    fruitless_completions: count, fruitless_reported: reported || escalated, last_arm_at_ms: i64_to_u64(last_arm)? },
                escalated, warning_changed,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    #[test]
    fn terminal_retirement_failure_preserves_all_group_debt_and_independent_loss() {
        let store = fixture();
        let group = gid(1);
        store
            .request_recovery(
                RecoveryRequest::KnownEvent {
                    group_id: group.as_slice(),
                    event_id: &[8; 32],
                },
                1,
            )
            .unwrap();
        store
            .request_recovery(
                RecoveryRequest::MaintenanceBoundary {
                    group_id: group.as_slice(),
                    job_id: &[9],
                },
                1,
            )
            .unwrap();
        store
            .mark_account_delivery_recovery("alice", 55, 1)
            .unwrap();
        let before = store.recovery_revision_fence().unwrap();
        let retry = store.recovery_retry_state().unwrap();
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_terminal_retire BEFORE DELETE ON app_epoch_stall_evidence BEGIN SELECT RAISE(ABORT, 'injected terminal retire failure'); END;").unwrap();
        assert!(store.retire_terminal_group_recovery(&group).is_err());
        assert_eq!(store.recovery_revision_fence().unwrap(), before);
        assert_eq!(store.epoch_stall_evidence().unwrap().len(), 1);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_terminal_retire")
            .unwrap();
        store.retire_terminal_group_recovery(&group).unwrap();
        assert!(store.epoch_stall_evidence().unwrap().is_empty());
        assert!(
            store
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|d| d.group_id.is_none())
        );
        assert!(store.account_delivery_recovery("alice").unwrap().is_some());
        assert_eq!(store.recovery_retry_state().unwrap(), retry);
        assert!(!store.retire_terminal_group_recovery(&group).unwrap());
    }

    fn fixture() -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store);
        store
    }

    fn seed(store: &SqliteAccountStorage) {
        store.ensure_account_projection("alice").unwrap();
        store.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        store
            .arm_epoch_backfill_intents(&[crate::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(gid(1).as_slice()),
                stalled_epoch: 1,
            }])
            .unwrap();
        store
            .record_epoch_stall_evidence(&[crate::StoredEpochStallEvidence {
                group_id_hex: hex::encode(gid(1).as_slice()),
                stalled_epoch: 1,
                fruitless_completions: 2,
                fruitless_reported: false,
                last_arm_at_ms: 1,
            }])
            .unwrap();
    }

    fn qualify(store: &SqliteAccountStorage) {
        let fence = store.recovery_revision_fence().unwrap();
        let attempt = store
            .reserve_recovery_attempt(&fence, 1, 15_000, true)
            .unwrap()
            .unwrap();
        let id = fence.obligations[0].0;
        let goal = RecoveryScopePlan {
            scope_id: 0,
            route_kind: 1,
            route_role: 0,
            group_id: Some(gid(1).as_slice().to_vec()),
            transport_group_id: Some([3; 32]),
            since_seconds: None,
            until_seconds: 100,
            known_event_id: None,
            inventory_floor: Some(1),
            required_endpoints: vec!["relay".into()],
            admitted_endpoints: vec!["relay".into()],
        };
        let token = store
            .install_recovery_scope_plan(&fence, attempt.attempt_serial, id, &[goal])
            .unwrap()
            .unwrap()
            .remove(0);
        assert!(
            store
                .checkpoint_recovery_obligation(
                    &fence,
                    attempt.attempt_serial,
                    id,
                    &[RecoveryScopeCheckpoint {
                        token,
                        retained_known_event: false,
                        endpoints: vec![RecoveryEndpointCheckpoint {
                            endpoint: "relay".into(),
                            outcome: RecoveryScopeOutcome::Covered,
                            exhaustive: true,
                            admission_complete: true,
                            first_boundary: false
                        }],
                    }],
                    RecoveryEligibility::Retry
                )
                .unwrap()
        );
    }

    fn observe(store: &SqliteAccountStorage, time: u64) -> Option<QualifiedRecoveryStallSample> {
        let revision = store.next_recovery_engine_observation().unwrap();
        store
            .sample_qualified_recovery_stall(gid(1).as_slice(), 1, revision, time, 3_600_000, 3)
            .unwrap()
    }

    #[test]
    fn qualified_stall_needs_three_distinct_paced_evaluations_without_replay() {
        let store = fixture();
        assert!(
            observe(&store, 1).is_none(),
            "legacy EOSE evidence and an evaluation do not prove coverage"
        );
        qualify(&store);
        let first = observe(&store, 1).unwrap();
        assert_eq!(
            first.evidence.fruitless_completions, 1,
            "legacy unqualified samples are not carried forward"
        );
        assert!(!first.escalated);
        let too_early = store.next_recovery_engine_observation().unwrap();
        assert!(
            store
                .sample_qualified_recovery_stall(gid(1).as_slice(), 1, too_early, 2, 3_600_000, 3)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .sample_qualified_recovery_stall(
                    gid(1).as_slice(),
                    1,
                    too_early,
                    3_600_001,
                    3_600_000,
                    3
                )
                .unwrap()
                .is_none(),
            "polling the same observation after the interval is not new evidence"
        );
        assert_eq!(
            observe(&store, 3_600_001)
                .unwrap()
                .evidence
                .fruitless_completions,
            2
        );
        let third = observe(&store, 7_200_001).unwrap();
        assert!(third.escalated && third.warning_changed);
        assert!(store.automatic_recovery_failed(&gid(1)).unwrap());
        assert!(!observe(&store, 10_800_001).unwrap().escalated);
        assert_eq!(
            store.recovery_retry_state().unwrap().attempt_serial,
            1,
            "local observations never purchase replay"
        );
        store.clear_recovery_failure(&gid(1)).unwrap();
        assert!(
            observe(&store, 14_400_001).is_none(),
            "authenticated recovery retires detector certificates"
        );
    }

    #[test]
    fn qualified_stall_survives_unrelated_inventory_retirement() {
        for (route, at) in [([4_u8; 32], 50_i64), ([3_u8; 32], 101_i64)] {
            let store = fixture();
            qualify(&store);
            assert!(observe(&store, 1).is_some());
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO transport_reconciliation_items VALUES(1,?1,zeroblob(32),?2)",
                    params![route.as_slice(), at],
                )
                .unwrap();
            store
                .connection
                .with_transaction(|| {
                    let conn = store.lock()?;
                    crate::account_recovery::delete_inventory_tx(
                        &conn,
                        "event_id=zeroblob(32)",
                        &[],
                    )?;
                    Ok::<_, StorageError>(())
                })
                .unwrap();
            let sample = observe(&store, 3_600_001)
                .expect("unrelated eviction must not suppress valid blocked-engine evidence");
            assert_eq!(sample.evidence.fruitless_completions, 2);
            assert_eq!(store.recovery_retry_state().unwrap().attempt_serial, 1);
        }
    }

    #[test]
    fn qualified_stall_rejects_new_loss_route_and_inventory_changes() {
        for invalidation in 0..3 {
            let store = fixture();
            qualify(&store);
            assert!(observe(&store, 1).is_some());
            match invalidation {
                0 => store
                    .record_account_delivery_loss("alice", 77, 1, 1)
                    .unwrap(),
                1 => {
                    store.observe_recovery_route_snapshot([7; 32]).unwrap();
                }
                _ => {
                    store.lock().unwrap().execute("INSERT INTO transport_reconciliation_items VALUES(1,?1,zeroblob(32),50)", [[3_u8; 32].as_slice()]).unwrap();
                    store
                        .connection
                        .with_transaction(|| {
                            let conn = store.lock()?;
                            crate::account_recovery::delete_inventory_tx(
                                &conn,
                                "event_id=zeroblob(32)",
                                &[],
                            )?;
                            Ok::<_, StorageError>(())
                        })
                        .unwrap();
                }
            }
            assert!(observe(&store, 3_600_001).is_none());
            assert!(!store.automatic_recovery_failed(&gid(1)).unwrap());
        }
    }

    #[test]
    fn qualified_stall_transaction_failure_and_clock_rebase_never_forge_samples() {
        let store = fixture();
        qualify(&store);
        assert!(observe(&store, 5_000_000).is_some());
        assert!(observe(&store, 1_000).is_none());
        assert!(observe(&store, 3_600_999).is_none());
        assert_eq!(
            observe(&store, 3_601_000)
                .unwrap()
                .evidence
                .fruitless_completions,
            2
        );
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_sample BEFORE INSERT ON app_group_recovery_failures BEGIN SELECT RAISE(FAIL, 'sample failure'); END;").unwrap();
        let revision = store.next_recovery_engine_observation().unwrap();
        assert!(
            store
                .sample_qualified_recovery_stall(
                    gid(1).as_slice(),
                    1,
                    revision,
                    7_201_000,
                    3_600_000,
                    3
                )
                .is_err()
        );
        assert_eq!(
            store.epoch_stall_evidence().unwrap()[0].fruitless_completions,
            2
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_sample")
            .unwrap();
        assert!(
            store
                .sample_qualified_recovery_stall(
                    gid(1).as_slice(),
                    1,
                    revision,
                    7_201_000,
                    3_600_000,
                    3
                )
                .unwrap()
                .unwrap()
                .escalated
        );
        assert!(
            store
                .sample_qualified_recovery_stall(
                    gid(1).as_slice(),
                    1,
                    revision,
                    10_801_000,
                    3_600_000,
                    3
                )
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn qualified_stall_certificate_and_interval_survive_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("qualified-stall.sqlite");
        let key = crate::SqlCipherKey::new("qualified stall reopen test").unwrap();
        let observation = {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            seed(&store);
            qualify(&store);
            let observation = store.next_recovery_engine_observation().unwrap();
            assert!(
                store
                    .sample_qualified_recovery_stall(
                        gid(1).as_slice(),
                        1,
                        observation,
                        1,
                        3_600_000,
                        3
                    )
                    .unwrap()
                    .is_some()
            );
            store.close().unwrap();
            observation
        };
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(
            reopened
                .sample_qualified_recovery_stall(
                    gid(1).as_slice(),
                    1,
                    observation,
                    3_600_001,
                    3_600_000,
                    3
                )
                .unwrap()
                .is_none()
        );
        assert!(observe(&reopened, 3_600_000).is_none());
        assert_eq!(
            observe(&reopened, 3_600_001)
                .unwrap()
                .evidence
                .fruitless_completions,
            2
        );
        assert_eq!(reopened.recovery_retry_state().unwrap().attempt_serial, 1);
    }
}
