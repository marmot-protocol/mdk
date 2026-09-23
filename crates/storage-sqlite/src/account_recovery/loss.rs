//! Completion handoff between the account worker and the evidence-only writer.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum RecoveryLossCause {
    Queue = 0,
    NotificationConsumer = 1,
}

/// Capture before execution; never log account labels or marker identities.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryLossWatermark {
    pub marker_token: u64,
    pub observed_count: u64,
}

fn watermarks(
    conn: &Connection,
    label: &str,
    cause: RecoveryLossCause,
) -> StorageResult<Vec<RecoveryLossWatermark>> {
    let rows = conn
        .prepare_cached(
            "SELECT marker_token, dropped_count FROM account_delivery_loss_evidence
         WHERE account_label=?1 AND cause=?2 ORDER BY marker_token",
        )
        .storage()?
        .query_map(params![label, cause as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    rows.into_iter()
        .map(|(token, count)| {
            Ok(RecoveryLossWatermark {
                marker_token: i64_to_u64(token)?,
                observed_count: i64_to_u64(count)?,
            })
        })
        .collect()
}

impl SqliteAccountStorage {
    /// Typed evidence only. A notification count is an observation count, never
    /// a claim about how many encrypted events the receiver missed.
    pub fn record_account_recovery_loss(
        &self,
        label: &str,
        cause: RecoveryLossCause,
        marker_token: u64,
        observed_count: u64,
        observed_at_seconds: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO account_delivery_loss_evidence
             (account_label,cause,marker_token,pending_since,dropped_count)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(account_label,cause,marker_token) DO UPDATE SET
                 dropped_count=MAX(dropped_count,excluded.dropped_count)",
                params![
                    label,
                    cause as i64,
                    sqlite_integer(marker_token)?,
                    sqlite_integer(observed_at_seconds)?,
                    sqlite_integer(observed_count)?
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn recovery_loss_watermarks(
        &self,
        label: &str,
        cause: RecoveryLossCause,
    ) -> StorageResult<Vec<RecoveryLossWatermark>> {
        let conn = self.lock()?;
        watermarks(&conn, label, cause)
    }

    /// Run once when constructing the owner, before selecting work. A satisfied
    /// row with unreclaimed evidence means the prior process could have stopped
    /// before plane acknowledgment. Rearm conservatively without changing pacing.
    /// An absent row is a supported low-level retirement, not an interrupted
    /// owner completion; retaining its watermark does not recreate that demand.
    pub fn restore_unacknowledged_recovery_loss(&self) -> StorageResult<usize> {
        self.lock()?
            .execute_cached(
                "UPDATE account_recovery_obligations AS o SET state=0, eligibility=1, revision=revision+1
             WHERE state=1 AND cause IN (0,6) AND EXISTS(
                 SELECT 1 FROM account_delivery_loss_evidence AS e
                 WHERE e.account_label=o.account_label
                 AND e.cause=CASE o.cause WHEN 0 THEN 0 ELSE 1 END)",
                [],
            )
            .storage()
    }

    /// Call only after the matching plane generation/count is acknowledged and
    /// every writer for captured tokens has finished. SQL cannot prove that
    /// external prerequisite. Reclaim the exact captured set after checking the
    /// satisfied obligation and all invalidation fences; new evidence refuses
    /// reclamation. Do not publish completion if this returns false or errors.
    pub fn acknowledge_recovery_loss(
        &self,
        expected: &RecoveryRevisionFence,
        obligation_id: [u8; 16],
        captured: &[RecoveryLossWatermark],
    ) -> StorageResult<bool> {
        let Some((_, revision)) = expected
            .obligations
            .iter()
            .find(|(id, _)| *id == obligation_id)
        else {
            return Ok(false);
        };
        if captured.is_empty()
            || captured
                .windows(2)
                .any(|pair| pair[0].marker_token >= pair[1].marker_token)
        {
            return Ok(false);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let current = revision_fence(&conn)?;
            if current.loss_revision != expected.loss_revision
                || current.route_revision != expected.route_revision
                || !plan::no_unimported_loss(&conn)?
            {
                return Ok(false);
            }
            use rusqlite::OptionalExtension;
            let row: Option<(String, i64)> = conn
                .query_row_cached(
                    "SELECT account_label,cause FROM account_recovery_obligations
                 WHERE id=?1 AND revision=?2 AND state=1 AND cause IN (0,6)",
                    params![obligation_id.as_slice(), sqlite_integer(*revision)?],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .storage()?;
            let Some((label, cause)) = row else {
                return Ok(false);
            };
            let cause = if cause == 0 {
                RecoveryLossCause::Queue
            } else {
                RecoveryLossCause::NotificationConsumer
            };
            if !plan::scopes_qualify(&conn, expected, None, obligation_id, 0)? {
                return Ok(false);
            }
            if watermarks(&conn, &label, cause)? != captured {
                return Ok(false);
            }
            conn.execute_cached(
                "DELETE FROM account_delivery_loss_evidence WHERE account_label=?1 AND cause=?2",
                params![label, cause as i64],
            )
            .storage()?;
            Ok(true)
        })
    }
}
