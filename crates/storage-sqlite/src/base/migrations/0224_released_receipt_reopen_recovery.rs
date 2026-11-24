//! Record whether a released transport receipt should reopen recovery
//! (inventory, coverage, and epoch-gap arming) when consumed, and mark
//! reconciliation inventory rows whose deferred-peel budget expired so
//! ordinary recovery sweeps do not restage them while explicit redelivery
//! remains possible. Receipts journaled before this upgrade keep their
//! existing behavior (`reopen_recovery = 1`).
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE cgka_released_transport_receipts ADD COLUMN reopen_recovery
         INTEGER NOT NULL DEFAULT 1 CHECK (reopen_recovery IN (0,1));
         ALTER TABLE transport_reconciliation_items ADD COLUMN expired_deferred
         INTEGER NOT NULL DEFAULT 0 CHECK (expired_deferred IN (0,1));",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn upgrade_keeps_an_unconsumed_release_reopening_recovery() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 223).unwrap();
        conn.execute_batch(
            "INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',7,x'00');
             INSERT INTO cgka_released_transport_receipts (id,group_id,epoch)
             VALUES (x'bb',x'0a',7);
             INSERT INTO transport_reconciliation_items (route_kind,route_id,event_id,created_at)
             VALUES (0,x'',zeroblob(32),120);",
        )
        .unwrap();
        run_through(&mut conn, 224).unwrap();
        let reopen: i64 = conn
            .query_row(
                "SELECT reopen_recovery FROM cgka_released_transport_receipts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let expired: i64 = conn
            .query_row(
                "SELECT expired_deferred FROM transport_reconciliation_items",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reopen, 1);
        assert_eq!(expired, 0);
    }
}
