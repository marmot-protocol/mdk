//! Record whether a released transport receipt should reopen recovery
//! (inventory, coverage, and epoch-gap arming) when consumed. Budget-expired
//! deferred-peel evictions only retire `seen_events` so explicit redelivery
//! remains possible without bouncing evicted rows back through the recovery
//! runner. Receipts journaled before this upgrade keep their existing behavior
//! (`1`).
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE cgka_released_transport_receipts ADD COLUMN reopen_recovery
         INTEGER NOT NULL DEFAULT 1 CHECK (reopen_recovery IN (0,1));",
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
             VALUES (x'bb',x'0a',7);",
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
        assert_eq!(reopen, 1);
    }
}
