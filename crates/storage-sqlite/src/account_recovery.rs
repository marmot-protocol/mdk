//! Account-private recovery demand. The worker owns demand and completion;
//! the narrow loss writer may only append monotonically increasing evidence.
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, i64_to_u64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, params};

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    let key = format!("epoch:{}", hex::encode(group));
    conn.execute_cached(
        "INSERT INTO account_recovery_obligations
         (demand_key, cause, group_id, stalled_epoch, created_at_ms, updated_at_ms)
         VALUES (?1, 1, ?2, ?3, ?4, ?4)
         ON CONFLICT(demand_key) DO UPDATE SET
             stalled_epoch = MAX(stalled_epoch, excluded.stalled_epoch),
             revision = revision + 1, state = 0, eligibility = 0,
             updated_at_ms = excluded.updated_at_ms",
        params![key, group, epoch, milliseconds(now)?],
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

pub(crate) fn arm_overflow_tx(
    conn: &Connection,
    label: &str,
    token: i64,
    dropped: i64,
    now: i64,
) -> StorageResult<()> {
    let key = format!("overflow:{label}");
    conn.execute_cached(
        "INSERT INTO account_recovery_obligations
         (demand_key, cause, account_label, marker_token, pending_since, dropped_count, created_at_ms, updated_at_ms)
         VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(demand_key) DO UPDATE SET
             revision = revision + CASE WHEN marker_token != excluded.marker_token
                 OR dropped_count < excluded.dropped_count OR state != 0 THEN 1 ELSE 0 END,
             eligibility = CASE WHEN marker_token != excluded.marker_token
                 OR dropped_count < excluded.dropped_count OR state != 0 THEN 0 ELSE eligibility END,
             pending_since = CASE WHEN marker_token = excluded.marker_token THEN pending_since ELSE excluded.pending_since END,
             dropped_count = CASE WHEN marker_token = excluded.marker_token THEN MAX(dropped_count, excluded.dropped_count) ELSE excluded.dropped_count END,
             marker_token = excluded.marker_token, state = 0, updated_at_ms = excluded.updated_at_ms",
        params![key, label, token, now, dropped, milliseconds(now)?],
    ).storage()?;
    conn.execute_cached(
        "INSERT OR IGNORE INTO account_recovery_scopes(obligation_id, scope_id)
         SELECT id, 0 FROM account_recovery_obligations WHERE demand_key = ?1",
        [key],
    )
    .storage()?;
    Ok(())
}

impl SqliteAccountStorage {
    pub fn recovery_retry_state(&self) -> StorageResult<RecoveryRetryState> {
        {
            let conn = self.lock()?;
            retry_state(&conn)
        }
    }

    pub fn recovery_revision_fence(&self) -> StorageResult<RecoveryRevisionFence> {
        {
            let conn = self.lock()?;
            revision_fence(&conn)
        }
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
            let unknown_format: bool = conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_recovery_scopes s
                 JOIN account_recovery_obligations o ON o.id = s.obligation_id
                 WHERE o.state = 0 AND s.scope_format != 1)",
                [], |row| row.get(0),
            ).storage()?;
            if unknown_format {
                return Err(StorageError::Serialization("unsupported recovery scope format".into()));
            }
            let eligible: bool = conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_recovery_obligations
                 WHERE state = 0 AND (eligibility IN (0, 1) OR ?1))",
                [explicit_override], |row| row.get(0),
            ).storage()?;
            if unimported || !eligible || revision_fence(&conn)? != *expected
                || (!explicit_override && now_ms < state.not_before_ms)
            {
                return Ok(None);
            }
            conn.execute_cached(
                "UPDATE account_recovery_state SET next_attempt = next_attempt + 1,
                 retry_ordinal = retry_ordinal + 1, retry_recorded_at_ms = ?1,
                 retry_delay_ms = ?2, retry_not_before_ms = ?3 WHERE singleton = 1",
                params![now, delay, due],
            ).storage()?;
            Ok(Some(retry_state(&conn)?))
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
            let rows = conn.prepare_cached(
                "SELECT marker_token, pending_since, dropped_count
                 FROM account_delivery_loss_evidence
                 WHERE account_label = ?1 AND cause = 0 AND (imported_count IS NULL OR dropped_count > imported_count)
                 ORDER BY pending_since, marker_token",
            ).storage()?.query_map([label], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)))
                .storage()?.collect::<Result<Vec<_>, _>>().storage()?;
            for (token, observed_at, dropped) in rows {
                arm_overflow_tx(&conn, label, token, dropped, observed_at)?;
                conn.execute_cached(
                    "UPDATE account_delivery_loss_evidence SET imported_count = ?3
                     WHERE account_label = ?1 AND cause = 0 AND marker_token = ?2",
                    params![label, token, dropped],
                ).storage()?;
                conn.execute_cached(
                    "UPDATE account_recovery_state SET loss_revision = loss_revision + 1 WHERE singleton = 1",
                    [],
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
        let integer = |value| {
            i64::try_from(value).map_err(|_| {
                StorageError::Serialization("recovery evidence outside supported range".into())
            })
        };
        self.lock()?
            .execute_cached(
                "INSERT INTO account_delivery_loss_evidence
             (account_label, cause, marker_token, pending_since, dropped_count)
             VALUES (?1, 0, ?2, ?3, ?4)
             ON CONFLICT(account_label, cause, marker_token) DO UPDATE SET
                 dropped_count = MAX(dropped_count, excluded.dropped_count)",
                params![
                    label,
                    integer(marker_token)?,
                    integer(observed_at_seconds)?,
                    integer(dropped_count)?
                ],
            )
            .storage()?;
        Ok(())
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
                "INSERT INTO cgka_released_transport_receipts VALUES (x'02', x'01', 7);
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
