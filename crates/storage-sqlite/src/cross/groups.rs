//! App state the engine's group lifecycle changes.

use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::StorageResult;
use cgka_traits::types::GroupId;
use rusqlite::params;

/// Lifts the media-secret retirement barrier of a forgotten group that is
/// joining again. The old app-only deletion path forbids rehydrating erased
/// media keys from retained MLS state. A rejoin has new MLS state, so that
/// barrier must not carry into the new membership (including a lower fork
/// epoch).
pub(crate) fn clear_media_barrier_on_rejoin(
    conn: &rusqlite::Connection,
    id: &GroupId,
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM encrypted_media_epoch_secret_retirement_watermarks
             WHERE group_id_hex = ?1 AND EXISTS (
                 SELECT 1 FROM locally_forgotten_groups
                 WHERE group_id = ?2 AND awaiting_welcome = 1)",
        params![hex::encode(id.as_slice()), id.as_slice()],
    )
    .storage()?;
    Ok(())
}
