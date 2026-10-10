//! Account-private outbox for gift-wrapped moderation reports to the deployment's moderation team.
//!
//! The account database is the isolation boundary: a row belongs to the one account-device
//! identity whose database holds it. Rows never carry the reported key or the reporter's
//! explanation in the clear; both exist only inside the signed NIP-59 wrap, which is dropped once
//! a relay accepts it. Published rows stay as bare metadata until the app prunes them, so the
//! idempotency window and the local rate limit survive a restart.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, Row, params};

/// Last known delivery state of one queued report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModerationReportOutboxOutcome {
    /// At least one configured relay accepted the wrap.
    Published,
    /// Every attempted relay definitely refused or was unreachable; the wrap is retained.
    AcceptedPending,
    /// An attempt may have reached a relay without an acknowledgement; the wrap is retained.
    CompletionUnknown,
}

impl ModerationReportOutboxOutcome {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::AcceptedPending => "accepted_pending",
            Self::CompletionUnknown => "completion_unknown",
        }
    }

    fn from_sql(value: &str) -> StorageResult<Self> {
        Ok(match value {
            "published" => Self::Published,
            "accepted_pending" => Self::AcceptedPending,
            "completion_unknown" => Self::CompletionUnknown,
            _ => {
                return Err(StorageError::Backend(
                    "unknown moderation report outcome".into(),
                ));
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModerationReportOutboxEntry {
    /// Opaque local id, 32 lowercase hex characters.
    pub report_id: String,
    /// One-way key of the report's target, reason and origin (64 hex characters).
    pub dedupe_key: String,
    pub recipient_pubkey_hex: String,
    pub outcome: ModerationReportOutboxOutcome,
    /// The signed wrap while it awaits acceptance; `None` once published.
    pub event_json: Option<String>,
    pub created_at_ms: u64,
    pub attempts: u32,
}

const COLUMNS: &str =
    "report_id, dedupe_key, recipient_pubkey_hex, outcome, event_json, created_at_ms, attempts";

fn entry_from_row(row: &Row<'_>) -> rusqlite::Result<(ModerationReportOutboxEntryRaw, String)> {
    Ok((
        ModerationReportOutboxEntryRaw {
            report_id: row.get(0)?,
            dedupe_key: row.get(1)?,
            recipient_pubkey_hex: row.get(2)?,
            event_json: row.get(4)?,
            created_at_ms: row.get(5)?,
            attempts: row.get(6)?,
        },
        row.get(3)?,
    ))
}

struct ModerationReportOutboxEntryRaw {
    report_id: String,
    dedupe_key: String,
    recipient_pubkey_hex: String,
    event_json: Option<String>,
    created_at_ms: i64,
    attempts: i64,
}

fn entry_from_raw(
    (raw, outcome): (ModerationReportOutboxEntryRaw, String),
) -> StorageResult<ModerationReportOutboxEntry> {
    Ok(ModerationReportOutboxEntry {
        report_id: raw.report_id,
        dedupe_key: raw.dedupe_key,
        recipient_pubkey_hex: raw.recipient_pubkey_hex,
        outcome: ModerationReportOutboxOutcome::from_sql(&outcome)?,
        event_json: raw.event_json,
        created_at_ms: crate::i64_to_u64(raw.created_at_ms)?,
        attempts: u32::try_from(raw.attempts).unwrap_or(u32::MAX),
    })
}

impl SqliteAccountStorage {
    /// The newest report with `dedupe_key` created at or after `not_before_ms`.
    pub fn moderation_report_by_dedupe_key(
        &self,
        dedupe_key: &str,
        not_before_ms: u64,
    ) -> StorageResult<Option<ModerationReportOutboxEntry>> {
        self.lock()?
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM moderation_report_outbox
                     WHERE dedupe_key = ?1 AND created_at_ms >= ?2
                     ORDER BY created_at_ms DESC, report_id DESC LIMIT 1"
                ),
                params![dedupe_key, crate::u64_to_i64(not_before_ms)?],
                entry_from_row,
            )
            .optional()
            .storage()?
            .map(entry_from_raw)
            .transpose()
    }

    /// How many reports were created at or after `since_ms`, published or not.
    pub fn moderation_reports_created_since(&self, since_ms: u64) -> StorageResult<u64> {
        let count: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*) FROM moderation_report_outbox WHERE created_at_ms >= ?1",
                params![crate::u64_to_i64(since_ms)?],
                |row| row.get(0),
            )
            .storage()?;
        crate::i64_to_u64(count)
    }

    /// Record a signed report before any relay sees it.
    pub fn stage_moderation_report(
        &self,
        entry: &ModerationReportOutboxEntry,
    ) -> StorageResult<()> {
        if entry.event_json.is_none() != (entry.outcome == ModerationReportOutboxOutcome::Published)
        {
            return Err(StorageError::Backend(
                "staged moderation report must keep its wrap until published".into(),
            ));
        }
        self.lock()?
            .execute(
                "INSERT INTO moderation_report_outbox
                    (report_id, dedupe_key, recipient_pubkey_hex, outcome, event_json,
                     created_at_ms, attempts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    entry.report_id,
                    entry.dedupe_key,
                    entry.recipient_pubkey_hex,
                    entry.outcome.as_sql(),
                    entry.event_json,
                    crate::u64_to_i64(entry.created_at_ms)?,
                    i64::from(entry.attempts),
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Record one publish attempt. A published report drops its wrap. Returns
    /// whether the row still existed (a purge may have removed it meanwhile).
    pub fn record_moderation_report_attempt(
        &self,
        report_id: &str,
        outcome: ModerationReportOutboxOutcome,
        attempted_at_ms: u64,
    ) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute(
                "UPDATE moderation_report_outbox
                 SET outcome = ?2,
                     event_json = CASE WHEN ?2 = 'published' THEN NULL ELSE event_json END,
                     last_attempt_at_ms = ?3,
                     attempts = attempts + 1
                 WHERE report_id = ?1 AND event_json IS NOT NULL",
                params![
                    report_id,
                    outcome.as_sql(),
                    crate::u64_to_i64(attempted_at_ms)?
                ],
            )
            .storage()?;
        Ok(changed > 0)
    }

    /// Reports still awaiting acceptance, oldest first.
    pub fn pending_moderation_reports(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<ModerationReportOutboxEntry>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM moderation_report_outbox
                 WHERE event_json IS NOT NULL
                 ORDER BY created_at_ms, report_id LIMIT ?1"
            ))
            .storage()?;
        let rows = stmt
            .query_map(
                params![i64::try_from(limit).unwrap_or(i64::MAX)],
                entry_from_row,
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(entry_from_raw).collect()
    }

    pub fn has_pending_moderation_reports(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM moderation_report_outbox WHERE event_json IS NOT NULL)",
                [],
                |row| row.get(0),
            )
            .storage()
    }

    /// Drop one report, published or not.
    pub fn delete_moderation_report(&self, report_id: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM moderation_report_outbox WHERE report_id = ?1",
                params![report_id],
            )
            .storage()?;
        Ok(())
    }

    /// Forget published metadata created before `published_before_ms` and give
    /// up on unpublished reports created before `pending_before_ms`. Returns
    /// how many unpublished reports were abandoned.
    pub fn prune_moderation_reports(
        &self,
        published_before_ms: u64,
        pending_before_ms: u64,
    ) -> StorageResult<u64> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM moderation_report_outbox
             WHERE event_json IS NULL AND created_at_ms < ?1",
            params![crate::u64_to_i64(published_before_ms)?],
        )
        .storage()?;
        let abandoned = conn
            .execute(
                "DELETE FROM moderation_report_outbox
                 WHERE event_json IS NOT NULL AND created_at_ms < ?1",
                params![crate::u64_to_i64(pending_before_ms)?],
            )
            .storage()?;
        Ok(abandoned as u64)
    }

    /// Remove every report this account queued or published (sign-out, wipe).
    pub fn purge_moderation_reports(&self) -> StorageResult<u64> {
        let removed = self
            .lock()?
            .execute("DELETE FROM moderation_report_outbox", [])
            .storage()?;
        Ok(removed as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: char, key: char, created_at_ms: u64) -> ModerationReportOutboxEntry {
        ModerationReportOutboxEntry {
            report_id: id.to_string().repeat(32),
            dedupe_key: key.to_string().repeat(64),
            recipient_pubkey_hex: "c".repeat(64),
            outcome: ModerationReportOutboxOutcome::AcceptedPending,
            event_json: Some("{\"kind\":1059}".into()),
            created_at_ms,
            attempts: 0,
        }
    }

    #[test]
    fn staged_report_publishes_once_and_drops_its_wrap() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .stage_moderation_report(&entry('a', 'd', 1_000))
            .unwrap();
        assert!(store.has_pending_moderation_reports().unwrap());
        assert_eq!(store.pending_moderation_reports(10).unwrap().len(), 1);

        assert!(
            store
                .record_moderation_report_attempt(
                    &"a".repeat(32),
                    ModerationReportOutboxOutcome::CompletionUnknown,
                    2_000
                )
                .unwrap()
        );
        let pending = store.pending_moderation_reports(10).unwrap();
        assert_eq!(pending[0].attempts, 1);
        assert_eq!(
            pending[0].outcome,
            ModerationReportOutboxOutcome::CompletionUnknown
        );

        assert!(
            store
                .record_moderation_report_attempt(
                    &"a".repeat(32),
                    ModerationReportOutboxOutcome::Published,
                    3_000
                )
                .unwrap()
        );
        assert!(!store.has_pending_moderation_reports().unwrap());
        let published = store
            .moderation_report_by_dedupe_key(&"d".repeat(64), 0)
            .unwrap()
            .unwrap();
        assert_eq!(published.outcome, ModerationReportOutboxOutcome::Published);
        assert_eq!(published.event_json, None);
        // A published row accepts no further attempts.
        assert!(
            !store
                .record_moderation_report_attempt(
                    &"a".repeat(32),
                    ModerationReportOutboxOutcome::AcceptedPending,
                    4_000
                )
                .unwrap()
        );
    }

    #[test]
    fn dedupe_lookup_and_rate_count_respect_their_windows() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .stage_moderation_report(&entry('a', 'd', 1_000))
            .unwrap();
        store
            .stage_moderation_report(&entry('b', 'd', 5_000))
            .unwrap();
        store
            .stage_moderation_report(&entry('e', 'f', 9_000))
            .unwrap();

        let newest = store
            .moderation_report_by_dedupe_key(&"d".repeat(64), 0)
            .unwrap()
            .unwrap();
        assert_eq!(newest.report_id, "b".repeat(32));
        assert!(
            store
                .moderation_report_by_dedupe_key(&"d".repeat(64), 6_000)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.moderation_reports_created_since(0).unwrap(), 3);
        assert_eq!(store.moderation_reports_created_since(5_000).unwrap(), 2);
    }

    #[test]
    fn prune_and_purge_remove_the_right_rows() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .stage_moderation_report(&entry('a', 'd', 1_000))
            .unwrap();
        store
            .stage_moderation_report(&entry('b', 'e', 2_000))
            .unwrap();
        store
            .stage_moderation_report(&entry('f', 'f', 9_000))
            .unwrap();
        store
            .record_moderation_report_attempt(
                &"b".repeat(32),
                ModerationReportOutboxOutcome::Published,
                2_500,
            )
            .unwrap();

        // Published metadata before 3s goes; pending before 1.5s is abandoned.
        assert_eq!(store.prune_moderation_reports(3_000, 1_500).unwrap(), 1);
        assert_eq!(store.moderation_reports_created_since(0).unwrap(), 1);

        assert_eq!(store.purge_moderation_reports().unwrap(), 1);
        assert!(!store.has_pending_moderation_reports().unwrap());
    }

    #[test]
    fn a_published_row_cannot_be_staged_with_a_wrap() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut published = entry('a', 'd', 1_000);
        published.outcome = ModerationReportOutboxOutcome::Published;
        assert!(store.stage_moderation_report(&published).is_err());
    }
}
