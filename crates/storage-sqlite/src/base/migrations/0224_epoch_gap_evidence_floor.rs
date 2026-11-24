//! Record the earliest deferred-row arrival epoch that still counts as
//! stall evidence for an active `EpochGap` obligation, so multi-step partial
//! epoch advances preserve a real gap across handoffs and restarts without
//! letting older dead rows re-arm a parked gap. Pre-upgrade obligations fall
//! back to their `stalled_epoch` when `evidence_floor_epoch` is `NULL`.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_obligations ADD COLUMN evidence_floor_epoch
         INTEGER CHECK (
             evidence_floor_epoch IS NULL
             OR (typeof(evidence_floor_epoch) = 'integer' AND evidence_floor_epoch >= 0)
         );",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn upgrade_leaves_existing_epoch_gap_floor_nullable() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 223).unwrap();
        conn.execute_batch(
            "INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',7,x'00');
             INSERT INTO account_recovery_obligations
                 (demand_key,cause,group_id,stalled_epoch,created_at_ms,updated_at_ms)
             VALUES ('epoch:0a',1,x'0a',7,1000,1000);",
        )
        .unwrap();
        run_through(&mut conn, 224).unwrap();
        let floor: Option<i64> = conn
            .query_row(
                "SELECT evidence_floor_epoch FROM account_recovery_obligations WHERE demand_key='epoch:0a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(floor, None);
    }
}
