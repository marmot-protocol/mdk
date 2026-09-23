//! Persist current route-policy identity independently of historical goals.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_state ADD COLUMN route_snapshot BLOB
         CHECK(route_snapshot IS NULL OR (typeof(route_snapshot)='blob' AND length(route_snapshot)=32));
         ALTER TABLE cgka_released_transport_receipts ADD COLUMN inventory_invalidated INTEGER NOT NULL DEFAULT 0 CHECK(inventory_invalidated IN (0,1));
         CREATE UNIQUE INDEX account_recovery_single_explicit ON account_recovery_obligations(cause) WHERE cause=3;",
    ).storage()
}
