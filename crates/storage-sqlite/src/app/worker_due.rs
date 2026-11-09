//! Reads that tell the account worker whether its device-pairing, push and
//! history jobs have work, and when, so they run on their own deadlines
//! instead of on every maintenance tick (mdk#2923 step B). Each reads only.
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;

impl SqliteAppStorage {
    /// Whether any device-pairing state is stored: a device group, a join,
    /// a move or a link. While one is, the worker drives pairing every 15 s.
    pub fn device_pairing_state_exists(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM device_groups)
                     OR EXISTS(SELECT 1 FROM device_group_joins)
                     OR EXISTS(SELECT 1 FROM device_group_moves)
                     OR EXISTS(SELECT 1 FROM device_links)",
                [],
                |row| row.get(0),
            )
            .storage()
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
    /// upload's or a parked fetch's retry, the next backup pass (at once
    /// when none was scheduled), or a condemned backup blob's next delete.
    /// The delivery columns have no index; their tables hold one row per
    /// group and sibling at most. An index may be needed once device groups
    /// ship.
    pub fn history_dispatch_next_at(&self) -> StorageResult<Option<u64>> {
        let next: Option<i64> = self
            .lock()?
            .query_row_cached(
                "SELECT min(
                     coalesce((SELECT min(blossom_due_at) FROM history_deliveries_owed
                               WHERE sent_at IS NULL AND blossom_due_at IS NOT NULL), 9223372036854775807),
                     coalesce((SELECT min(fetch_due_at) FROM history_deliveries_parked
                               WHERE fetch_due_at IS NOT NULL), 9223372036854775807),
                     coalesce((SELECT next_pass_at FROM backup_schedule WHERE id = 1), 0),
                     coalesce((SELECT min(next_try_at) FROM backup_condemned_blobs), 9223372036854775807))",
                [],
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

    /// A fresh account has no pairing state and no push timing owed, and
    /// its first backup pass is due at once (mdk#2923).
    #[test]
    fn a_fresh_account_owes_no_pairing_or_push_timing() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        assert!(!app.device_pairing_state_exists().unwrap());
        assert!(!app.push_gossip_timing_pending().unwrap());
        assert_eq!(app.history_dispatch_next_at().unwrap(), Some(0));
    }
}
