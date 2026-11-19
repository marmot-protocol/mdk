//! Record whether each released transport receipt is stall evidence (mdk#3536).
//! A release the engine judged not to be (traffic that may predate this copy's
//! Welcome) still retires its receipts and stays eligible for redelivery, but
//! consuming it arms no epoch gap. Receipts journaled before this upgrade keep
//! the behavior they were written under: they count.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE cgka_released_transport_receipts ADD COLUMN stall_evidence
         INTEGER NOT NULL DEFAULT 1 CHECK (stall_evidence IN (0,1));",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn upgrade_keeps_an_unconsumed_release_as_stall_evidence() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 214).unwrap();
        conn.execute_batch(
            "INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',7,x'00');
             INSERT INTO cgka_released_transport_receipts (id,group_id,epoch)
             VALUES (x'bb',x'0a',7);",
        )
        .unwrap();
        run_through(&mut conn, 215).unwrap();
        let evidence: i64 = conn
            .query_row(
                "SELECT stall_evidence FROM cgka_released_transport_receipts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence, 1);
    }
}
