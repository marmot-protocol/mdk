//! One scheduling row per original engine-owned sibling Welcome. The exact
//! Welcome/ref/expiry/origin are never copied here.
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

impl SqliteAppStorage {
    /// Before a new carrier is sent, retain its association with the original
    /// Welcome. Preparing a carrier does not invent a successful generation or
    /// erase the preceding generation's accepted-publication time.
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
                        AND (published_at_ms IS NULL OR carrier != excluded.prepared_carrier)))",
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
             WHERE welcome_id = ?1 AND (published_at_ms IS NULL OR carrier != prepared_carrier)",
                params![welcome_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .storage()?
            .map(|(carrier, at)| Ok((carrier, i64_to_u64(at)?)))
            .transpose()
    }

    /// Bounded keyset walk of the existing per-Welcome owner, including rows
    /// whose publication time is unknown. No expiry or origin is mirrored here.
    pub fn sibling_welcome_resend_batch(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT welcome_id, carrier FROM sibling_welcome_resends WHERE welcome_id > ?1 ORDER BY welcome_id LIMIT ?2"
        ).storage()?;
        stmt.query_map(
            params![
                after.unwrap_or_default(),
                i64::try_from(limit).map_err(|_| cgka_traits::StorageError::Backend(
                    "resend batch limit overflow".into()
                ))?
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .storage()?
        .collect::<Result<_, _>>()
        .storage()
    }

    /// A heartbeat for the CURRENT roster incarnation must be at least ten
    /// minutes after this Welcome's latest actual accepted carrier. The caller
    /// supplies the current entry's linked_at; neither first sighting nor
    /// activity retained for an older incarnation qualifies. Unknown carrier
    /// timing stays unknown. Dividing milliseconds first avoids SQL overflow.
    pub fn sibling_welcome_resend_is_due(
        &self,
        welcome_id: &[u8],
        linked_at: u64,
    ) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(
                 SELECT 1 FROM sibling_welcome_resends AS r
                 JOIN device_activity AS a ON a.slot_id_hex = lower(hex(r.target_slot))
                 WHERE r.welcome_id = ?1 AND a.linked_at = ?2
                   AND r.published_at_ms IS NOT NULL
                   AND a.last_active_at >= r.published_at_ms / 1000 + 600
                       + CASE WHEN r.published_at_ms % 1000 = 0 THEN 0 ELSE 1 END
             )",
                params![welcome_id, u64_to_i64(linked_at)?],
                |row| row.get(0),
            )
            .storage()
    }

    /// Retire completed, expired or terminal repair work. A held origin keeps
    /// its retained publication time and engine-owned delivery expiry.
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
