//! Reads that tell the account worker whether its device-pairing, push and
//! history jobs have work, and when, so they run on their own deadlines
//! instead of on every maintenance tick (mdk#2923 step B). Each reads only.
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;

impl SqliteAppStorage {
    /// Whether stored device-pairing state still has work for pairing's
    /// timers: a device group being created or waiting for its Welcome, a
    /// join or a move not yet finished, or a link not yet decided or whose failed
    /// Welcome is not yet withdrawn. A settled device group and its decided
    /// links have none (mdk#3265), so a linked account no longer drives
    /// pairing every 15 s. A failed link still listed in the roster is the
    /// app's to find, from the roster.
    pub fn device_pairing_state_exists(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM device_groups
                                WHERE trust IN ('creating', 'awaiting_welcome'))
                     OR EXISTS(SELECT 1 FROM device_group_joins)
                     OR EXISTS(SELECT 1 FROM device_group_moves WHERE phase != 3)
                     OR EXISTS(SELECT 1 FROM device_links
                                WHERE outcome = 'pending'
                                   OR (outcome = 'failed' AND welcome_withdrawn = 0))",
                [],
                |row| row.get(0),
            )
            .storage()
    }

    /// Whether device-group work is stored that maintenance must retry with
    /// no time of its own (mdk#3265): small state, an invitation decision or
    /// a broadcast request a send left unsent, a history to send inline,
    /// a sibling Welcome to join that no chat holds back, or a private
    /// KeyPackage need not yet asked for. A removal's slot withdrawal is
    /// not counted: one no relay took fails its pass, which retries, and the
    /// rest wait for the device group to settle or never apply (`not_me`).
    pub fn device_group_work_owed(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM small_state_items WHERE unsent = 1)
                     OR EXISTS(SELECT 1 FROM invitation_decisions WHERE unsent = 1)
                     OR EXISTS(SELECT 1 FROM small_state_sync WHERE request_owed = 1)
                     OR EXISTS(SELECT 1 FROM history_deliveries_owed
                                WHERE sent_at IS NULL AND blossom_due_at IS NULL)
                     OR EXISTS(SELECT 1 FROM sibling_welcomes_received
                                WHERE held_group_id_hex IS NULL)
                     OR EXISTS(SELECT 1 FROM private_key_package_requests
                                WHERE requested_at IS NULL)",
                [],
                |row| row.get(0),
            )
            .storage()
    }

    /// The earliest second an unmet private KeyPackage need was last asked
    /// for, which paces when it may be asked for again (mdk#3265).
    pub fn private_key_package_earliest_request(&self) -> StorageResult<Option<u64>> {
        let next: Option<i64> = self
            .lock()?
            .query_row_cached(
                "SELECT MIN(requested_at) FROM private_key_package_requests
                 WHERE requested_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .storage()?;
        Ok(next.map(|at| u64::try_from(at).unwrap_or(0)))
    }

    /// Whether a push join window is open or an announce is owed. Both wait
    /// on fetch time, which only sampling counts, so the worker samples it
    /// every 15 s while either holds. Both use their partial indexes.
    pub fn push_gossip_timing_pending(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM group_push_gossip_state WHERE joining_since_ms IS NOT NULL)
                     OR EXISTS(SELECT 1 FROM group_push_gossip_state WHERE announce_owed_at_ms IS NOT NULL)",
                [],
                |row| row.get(0),
            )
            .storage()
    }

    /// The earliest second history dispatch has work: an owed history
    /// upload's or a parked fetch's retry, and with `backups` the next backup
    /// pass (at once when none was scheduled) or, while no backup pass is in
    /// failure backoff (`failed_passes = 0`), a condemned backup blob's next
    /// delete. Without a recovery key no backup pass or delete runs, so
    /// those deadlines count only when backups are configured. The delivery
    /// columns have no index; their tables hold one row per group and sibling
    /// at most. An index may be needed once device groups ship.
    pub fn history_dispatch_next_at(&self, backups: bool) -> StorageResult<Option<u64>> {
        let next: Option<i64> = self
            .lock()?
            .query_row_cached(
                "SELECT min(
                     coalesce((SELECT min(blossom_due_at) FROM history_deliveries_owed
                               WHERE sent_at IS NULL AND blossom_due_at IS NOT NULL), 9223372036854775807),
                     coalesce((SELECT min(fetch_due_at) FROM history_deliveries_parked
                               WHERE fetch_due_at IS NOT NULL), 9223372036854775807),
                     CASE WHEN ?1 THEN coalesce((SELECT next_pass_at FROM backup_schedule WHERE id = 1), 0)
                          ELSE 9223372036854775807 END,
                     CASE WHEN ?1 AND coalesce((SELECT failed_passes FROM backup_schedule WHERE id = 1), 0) = 0
                          THEN coalesce((SELECT min(next_try_at) FROM backup_condemned_blobs),
                                        9223372036854775807)
                          ELSE 9223372036854775807 END)",
                [backups],
                |row| row.get(0),
            )
            .storage()?;
        Ok(next
            .filter(|next| *next != i64::MAX)
            .map(|next| u64::try_from(next).unwrap_or(0)))
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;

    /// A fresh account has no pairing state and no push timing owed. With
    /// backups configured its first backup pass is due at once; without,
    /// history dispatch owes nothing (mdk#2923).
    #[test]
    fn a_fresh_account_owes_no_pairing_or_push_timing() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        assert!(!app.device_pairing_state_exists().unwrap());
        assert!(!app.push_gossip_timing_pending().unwrap());
        assert_eq!(app.history_dispatch_next_at(true).unwrap(), Some(0));
        assert_eq!(app.history_dispatch_next_at(false).unwrap(), None);
    }

    #[test]
    fn history_dispatch_next_at_honors_failed_backup_pass_backoff_over_due_deletes() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        let hash = format!("{:064x}", 1_u8);
        app.condemn_backup_blobs(
            b"recovery-key",
            &[0xaa; 16],
            &[(hash, "https://blossom.example".to_owned())],
            50,
            100,
        )
        .unwrap();

        // Normal schedule (failed_passes == 0): due deletes still wake early.
        app.schedule_backup_pass(crate::BackupSchedule {
            next_pass_at: 2_000,
            failed_passes: 0,
        })
        .unwrap();
        assert_eq!(app.history_dispatch_next_at(true).unwrap(), Some(100));

        // Backoff after a failed pass: due deletes must not bypass next_pass_at.
        app.schedule_backup_pass(crate::BackupSchedule {
            next_pass_at: 2_000,
            failed_passes: 1,
        })
        .unwrap();
        assert_eq!(app.history_dispatch_next_at(true).unwrap(), Some(2_000));
    }
}
