//! A durable visit budget for the runner, separate from a sweep's progress.
//! Coverage is the intra-visit cursor; finishing a sweep never resolves MLS debt.

use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

use super::account_recovery::RecoveryDemandTicket;
use crate::base::connection::CachedSql;
use crate::{
    CopyFloorReason, SqliteAppStorage, SqliteResultExt, TransportReconciliationRoute, i64_to_u64,
};

/// The current missing epoch's return-visit state. No identities for logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryEpochGapRetry {
    /// Visits begun, including an unfinished visit resumed after restart.
    pub visits: u64,
    /// Its uncovered ledger ranges are still being swept/admitted.
    pub in_progress: bool,
    /// No more automatic visits at this epoch without explicit repair.
    pub exhausted: bool,
    /// The next visit's durable earliest start; zero during a visit.
    pub next_retry_at_seconds: u64,
}

fn integer(value: u64) -> StorageResult<i64> {
    i64::try_from(value)
        .map_err(|_| StorageError::Serialization("epoch-gap retry value outside range".into()))
}

impl SqliteAppStorage {
    /// Read only this ticket's state; an older revision grants no authority.
    pub fn recovery_epoch_gap_retry(
        &self,
        ticket: RecoveryDemandTicket,
    ) -> StorageResult<Option<RecoveryEpochGapRetry>> {
        let row = self
            .lock()?
            .query_row_cached(
                "SELECT r.visits,r.in_progress,r.next_retry_at_seconds,r.exhausted
             FROM account_recovery_epoch_gap_retries r JOIN account_recovery_obligations o
                 ON o.id=r.obligation_id AND o.stalled_epoch=r.stalled_epoch
             WHERE o.id=?1 AND o.revision=?2 AND o.cause=1 AND o.state=0",
                params![ticket.id.as_slice(), integer(ticket.revision)?],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()
            .storage()?;
        row.map(|(visits, in_progress, next, exhausted)| {
            Ok(RecoveryEpochGapRetry {
                visits: i64_to_u64(visits)?,
                in_progress,
                exhausted,
                next_retry_at_seconds: i64_to_u64(next)?,
            })
        })
        .transpose()
    }

    /// Begin one due visit and un-cover its retained goals atomically. A
    /// duplicate begin, stale ticket, parked demand or early retry does nothing.
    /// The owner supplies authoritative group routes and retention-bounded floors.
    /// The un-cover is clamped ([`CopyFloorReason::Clamp`]): a rejoined group's
    /// gap is in its new copy's epochs, so no visit reopens what lay before the
    /// copy (mdk#2660 row 11).
    pub fn begin_recovery_epoch_gap_retry(
        &self,
        ticket: RecoveryDemandTicket,
        floors: &[(TransportReconciliationRoute, u64)],
        now_seconds: u64,
    ) -> StorageResult<bool> {
        if floors.is_empty()
            || floors
                .iter()
                .any(|(route, _)| matches!(route, TransportReconciliationRoute::Inbox))
        {
            return Err(StorageError::Serialization(
                "epoch-gap retry requires group routes".into(),
            ));
        }
        self.connection.with_transaction(|| {
            let epoch = {
                let conn = self.lock()?;
                let current: Option<i64> = conn
                    .query_row_cached(
                        "SELECT stalled_epoch FROM account_recovery_obligations
                     WHERE id=?1 AND revision=?2 AND cause=1 AND state=0 AND eligibility!=4",
                        params![ticket.id.as_slice(), integer(ticket.revision)?],
                        |row| row.get(0),
                    )
                    .optional().storage()?;
                let Some(epoch) = current else { return Ok(false); };
                epoch
            };
            let prior = self.recovery_epoch_gap_retry(ticket)?;
            if prior.is_some_and(|state| state.exhausted) {
                // A newly released receipt can revise the same-epoch ticket.
                // It cannot mint another full automatic visit budget.
                self.lock()?.execute_cached(
                    "UPDATE account_recovery_obligations SET eligibility=4,parked_at_ms=COALESCE(parked_at_ms,?3)
                     WHERE id=?1 AND revision=?2 AND state=0",
                    params![ticket.id.as_slice(),integer(ticket.revision)?,integer(now_seconds.saturating_mul(1000))?],
                ).storage()?;
                return Ok(false);
            }
            if prior
                .is_some_and(|state| state.in_progress || state.next_retry_at_seconds > now_seconds)
            {
                return Ok(false);
            }
            let visits = prior.map_or(1, |state| state.visits.saturating_add(1));
            self.lock()?
                .execute_cached(
                    "INSERT INTO account_recovery_epoch_gap_retries
                 (obligation_id,stalled_epoch,visits,in_progress,exhausted,next_retry_at_seconds)
                 VALUES (?1,?2,?3,1,0,0) ON CONFLICT(obligation_id) DO UPDATE SET
                 stalled_epoch=excluded.stalled_epoch,visits=excluded.visits,
                 in_progress=1,exhausted=0,next_retry_at_seconds=0",
                    params![
                        ticket.id.as_slice(),
                        epoch,
                        integer(visits)?
                    ],
                )
                .storage()?;
            for (route, since) in floors {
                self.uncover_recovery_coverage(
                    std::slice::from_ref(route),
                    *since,
                    CopyFloorReason::Clamp,
                )?;
            }
            Ok(true)
        })
    }

    /// A complete visit left the epoch unresolved. Persist its next due time,
    /// or park the obligation visibly. A stale/duplicate settlement does nothing.
    /// This records neither history coverage nor successful epoch recovery.
    pub fn finish_recovery_epoch_gap_retry(
        &self,
        ticket: RecoveryDemandTicket,
        visits: u64,
        now_seconds: u64,
        delay_seconds: u64,
        exhausted: bool,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let changed = conn.execute_cached(
                "UPDATE account_recovery_epoch_gap_retries SET in_progress=0,next_retry_at_seconds=?4,exhausted=?5
                 WHERE obligation_id=?1 AND visits=?3 AND in_progress=1
                 AND EXISTS(SELECT 1 FROM account_recovery_obligations
                     WHERE id=?1 AND revision=?2 AND cause=1 AND state=0 AND eligibility!=4
                         AND stalled_epoch=account_recovery_epoch_gap_retries.stalled_epoch)",
                params![ticket.id.as_slice(),integer(ticket.revision)?,integer(visits)?,
                    integer(now_seconds.saturating_add(delay_seconds))?, exhausted],
            ).storage()?;
            if changed == 0 { return Ok(false); }
            if exhausted {
                conn.execute_cached(
                    "UPDATE account_recovery_obligations SET eligibility=4,parked_at_ms=?3
                     WHERE id=?1 AND revision=?2 AND cause=1 AND state=0",
                    params![ticket.id.as_slice(),integer(ticket.revision)?,integer(now_seconds.saturating_mul(1000))?],
                ).storage()?;
            }
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests;
