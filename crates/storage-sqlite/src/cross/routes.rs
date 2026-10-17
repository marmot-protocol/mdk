//! App state keyed by a Nostr route, which the engine clears when it deletes
//! routes or a whole group.

use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::StorageResult;

/// Deletes the recovery inventory and the NIP-77 reconciliation state of the
/// group routes `route_id {routes}` selects, in the caller's transaction.
/// `routes` is an SQL predicate on `route_id`, such as `= ?1` or
/// `IN (SELECT ...)`, and `parameters` bind it.
pub(crate) fn delete_route_app_state(
    conn: &rusqlite::Connection,
    routes: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> StorageResult<()> {
    crate::app::account_recovery::delete_inventory_tx(
        conn,
        &format!("route_kind = 1 AND route_id {routes}"),
        parameters,
    )?;
    conn.execute_cached(
        &format!(
            "DELETE FROM transport_reconciliation_route_state
             WHERE route_kind = 1 AND route_id {routes}"
        ),
        parameters,
    )
    .storage()?;
    conn.execute_cached(
        &format!(
            "DELETE FROM transport_reconciliation_scheduler
             WHERE singleton = 1 AND route_kind = 1 AND route_id {routes}"
        ),
        parameters,
    )
    .storage()?;
    Ok(())
}
