//! When the account worker's attachment pass next has work, so the pass can
//! sleep until then instead of running on every maintenance tick (mdk#2923
//! step B).
use super::partial::{PARTIAL_TTL_SECONDS, STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS};
use super::*;
use crate::SqliteAppStorage;

/// What the attachment pass owes, and when.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttachmentWorkSchedule {
    /// The earliest second a timed row becomes due: an acquisition's `due`
    /// (a retry, a deferral, a lease end or a readmission backoff) among the
    /// candidates the pass would take, an acquisition's expiry, or a
    /// partial's prune time. `None` when no row is timed.
    pub next_at: Option<u64>,
    /// Work no time column announces, which the pass has to look for: a
    /// staged upload (recovery, promotion and pruning advance it on each
    /// pass), or a row parked for free disk space, which nothing signals.
    pub polling: bool,
    /// Event-created work waiting now: an admission demand.
    pub pending_now: bool,
}

impl SqliteAppStorage {
    /// When the attachment pass next has work. `automatic` is the account's
    /// automatic-download policy: without it only explicit requests are
    /// candidates, as in [`Self::attachment_transfer_candidates`]. Reads only.
    pub fn attachment_work_schedule(
        &self,
        automatic: bool,
    ) -> StorageResult<AttachmentWorkSchedule> {
        let explicit_filter = if automatic {
            ""
        } else {
            " AND explicit_request=1"
        };
        let candidates = format!(
            "SELECT MIN(due) FROM attachment_acquisition AS q
             WHERE due IS NOT NULL AND cancelled=0{explicit_filter} AND {}",
            super::outgoing::STAGED_UPLOAD_MATCH
        );
        let conn = self.lock()?;
        let min = |sql: &str, offset: Option<i64>| -> StorageResult<Option<u64>> {
            let value: Option<i64> = match offset {
                Some(offset) => conn.query_row_cached(sql, [offset], |row| row.get(0)),
                None => conn.query_row_cached(sql, [], |row| row.get(0)),
            }
            .storage()?;
            Ok(value.map(|value| u64::try_from(value).unwrap_or(0)))
        };
        // A storage-parked partial is exempt from pruning until it is
        // `STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS` old, which is this much
        // past its idle expiry (see `prune_attachment_partials`).
        let parked_extension = i64::try_from(
            STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS.saturating_sub(PARTIAL_TTL_SECONDS),
        )
        .unwrap_or(i64::MAX);
        let next_at = [
            min(&candidates, None)?,
            min(
                "SELECT MIN(expires_at) FROM attachment_acquisition WHERE expires_at IS NOT NULL",
                None,
            )?,
            min(
                "SELECT MIN(CASE WHEN EXISTS(SELECT 1 FROM attachment_acquisition q
                     WHERE q.token=p.token AND q.state=4 AND q.cancelled=0
                     AND q.storage_blocked_headroom IS NOT NULL)
                 THEN p.expires_at + ?1 ELSE p.expires_at END) FROM attachment_partial p",
                Some(parked_extension),
            )?,
        ]
        .into_iter()
        .flatten()
        .min();
        let (polling, pending_now): (bool, bool) = conn
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM outgoing_attachment_uploads)
                     OR EXISTS(SELECT 1 FROM attachment_acquisition
                         WHERE state=4 AND storage_blocked_headroom IS NOT NULL AND cancelled=0),
                     EXISTS(SELECT 1 FROM attachment_worker_demand)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .storage()?;
        Ok(AttachmentWorkSchedule {
            next_at,
            polling,
            pending_now,
        })
    }
}
