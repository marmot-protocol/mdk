//! The app writing the engine's authority outbox.

use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::StorageResult;
use rusqlite::params;

/// Queues an authority request for a message the app projected before
/// authority requests existed, if the engine still holds the message. The
/// engine reads `pending_application_authority` on its next pass.
pub(crate) fn request_authority_backfill(
    conn: &rusqlite::Connection,
    message_id: &[u8],
    group_id: &[u8],
    record: &[u8],
) -> StorageResult<()> {
    conn.execute_cached(
        "INSERT OR IGNORE INTO pending_application_authority SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM cgka_messages WHERE id=?1 AND group_id=?2)",
        params![message_id, group_id, record],
    )
    .storage()?;
    Ok(())
}
