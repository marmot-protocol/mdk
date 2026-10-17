//! The app projection checkpoint's reads and writes of engine tables, inside
//! the checkpoint's own transaction.

use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::StorageResult;
use cgka_traits::types::MessageId;
use rusqlite::params;

/// Whether a group is locally forgotten and waiting for a fresh Welcome.
pub(crate) fn group_awaits_welcome(
    conn: &rusqlite::Connection,
    group_id: &[u8],
) -> StorageResult<bool> {
    conn.query_row_cached(
        "SELECT EXISTS(SELECT 1 FROM locally_forgotten_groups WHERE group_id = ?1 AND awaiting_welcome = 1)",
        params![group_id],
        |row| row.get::<_, bool>(0),
    )
    .storage()
}

/// Acknowledges an engine outbox row the checkpoint has projected, so the
/// engine does not hand it over again. The checkpoint and the acknowledgement
/// commit together.
pub(crate) fn acknowledge_outbox(
    conn: &rusqlite::Connection,
    message_id: &MessageId,
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM pending_application_events WHERE message_id = ?1",
        params![message_id.as_slice()],
    )
    .storage()?;
    Ok(())
}
