//! The app's side of message release for replay: whether an app owns the
//! released messages, the seen ring and the recovery inventory it keeps.

use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::StorageResult;
use cgka_traits::types::MessageId;
use rusqlite::params;

/// Whether an app owns this database's released messages. App ownership is
/// durable before engine hydration, so this does not depend on individual
/// receipts. A standalone engine has no app consumer.
pub(crate) fn app_owns_released_messages(conn: &rusqlite::Connection) -> StorageResult<bool> {
    conn.query_row_cached("SELECT EXISTS(SELECT 1 FROM account_state)", [], |row| {
        row.get::<_, bool>(0)
    })
    .storage()
}

/// Forgets a released message's transport receipts: its seen-ring entry and
/// its recovery inventory rows. Returns the inventory rows deleted.
pub(crate) fn retire_transport_receipts(
    conn: &rusqlite::Connection,
    id: &MessageId,
) -> StorageResult<usize> {
    conn.execute_cached(
        "DELETE FROM seen_events WHERE event_id = ?1",
        params![hex::encode(id.as_slice())],
    )
    .storage()?;
    crate::app::account_recovery::delete_inventory_tx(conn, "event_id = ?1", params![id.as_slice()])
}

/// Arms the recovery ledger for a group's released epoch.
pub(crate) fn arm_released_epoch(
    conn: &rusqlite::Connection,
    group: &[u8],
    epoch: i64,
    now: i64,
) -> StorageResult<()> {
    crate::app::account_recovery::arm_released_epoch_tx(conn, group, epoch, now)
}

/// Marks the recovery inventory incomplete when a release cannot bound it.
pub(crate) fn invalidate_recovery_inventory(conn: &rusqlite::Connection) -> StorageResult<()> {
    crate::app::account_recovery::invalidate_inventory_tx(conn)
}
