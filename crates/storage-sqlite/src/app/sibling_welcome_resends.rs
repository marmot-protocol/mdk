//! One scheduling row per original engine-owned sibling Welcome. The exact
//! Welcome/ref/expiry/origin are never copied here.
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

impl SqliteAppStorage {
    /// Before a new carrier is sent, retain its association with the original
    /// Welcome. Preparing a carrier does not invent a successful generation or
    /// erase the preceding generation's armed deadline.
    pub(crate) fn prepare_sibling_welcome_resend(
        &self,
        welcome_id: &[u8],
        chat_id: &[u8],
        device_group_id: &[u8],
        target_slot: &[u8; 32],
        carrier: &[u8],
        created_at: u64,
    ) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "INSERT INTO sibling_welcome_resends
                (welcome_id, chat_id, device_group_id, target_slot, carrier,
                 prepared_carrier, last_carrier_created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?5, ?6)
             ON CONFLICT(welcome_id) DO UPDATE SET
                 prepared_carrier = excluded.prepared_carrier,
                 last_carrier_created_at = excluded.last_carrier_created_at
             WHERE chat_id = excluded.chat_id AND device_group_id = excluded.device_group_id
                 AND target_slot = excluded.target_slot
                 AND (last_carrier_created_at < excluded.last_carrier_created_at
                    OR (last_carrier_created_at = excluded.last_carrier_created_at
                        AND prepared_carrier = excluded.prepared_carrier
                        AND (publication_order IS NULL OR carrier != excluded.prepared_carrier)))",
                params![
                    welcome_id,
                    chat_id,
                    device_group_id,
                    target_slot,
                    carrier,
                    u64_to_i64(created_at)?
                ],
            )
            .storage()?;
        Ok(changed != 0)
    }

    /// Recover an exact prepared carrier not yet confirmed as published.
    /// Its actual original timestamp can be reused after restart or a definite
    /// unexposed failure, even when the wall clock has moved backwards.
    pub fn sibling_welcome_carrier_reservation(
        &self,
        welcome_id: &[u8],
    ) -> StorageResult<Option<(Vec<u8>, u64)>> {
        self.lock()?
            .query_row_cached(
                "SELECT prepared_carrier, last_carrier_created_at FROM sibling_welcome_resends
             WHERE welcome_id = ?1 AND (publication_order IS NULL OR carrier != prepared_carrier)",
                params![welcome_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .storage()?
            .map(|(carrier, at)| Ok((carrier, i64_to_u64(at)?)))
            .transpose()
    }

    /// Indexed due work, as original Welcome and current carrier identities.
    /// The engine rechecks selected origin, expiry and participation before
    /// rearming; transport must settle the previous carrier first.
    pub fn due_sibling_welcome_resends(
        &self,
        now_ms: u64,
    ) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT welcome_id, carrier FROM sibling_welcome_resends
             WHERE due_at_ms <= ?1 ORDER BY due_at_ms, welcome_id",
            )
            .storage()?;
        stmt.query_map(params![u64_to_i64(now_ms)?], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .storage()?
        .collect::<Result<_, _>>()
        .storage()
    }

    /// Retire completed, expired or terminal repair work. A held origin keeps
    /// its original fixed deadline.
    pub fn delete_sibling_welcome_resend(&self, welcome_id: &[u8]) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM sibling_welcome_resends WHERE welcome_id = ?1",
                params![welcome_id],
            )
            .storage()?;
        Ok(())
    }
}
