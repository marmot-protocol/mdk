//! Give visits already in flight one finite endpoint at upgrade. Their coverage
//! and visit budget survive. Later visits record their own start atomically.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_epoch_gap_retries ADD COLUMN visit_until_seconds
         INTEGER NOT NULL DEFAULT 0 CHECK (visit_until_seconds >= 0);
         UPDATE account_recovery_epoch_gap_retries SET visit_until_seconds = unixepoch()
         WHERE in_progress = 1;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn upgrade_bounds_an_unfinished_epoch_gap_without_spending_its_budget() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 212).unwrap();
        conn.execute_batch(
            "INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');
             INSERT INTO account_recovery_obligations
                 (demand_key,cause,group_id,stalled_epoch,created_at_ms,updated_at_ms)
             VALUES ('gap',1,x'0a',1,0,0);
             INSERT INTO account_recovery_epoch_gap_retries
                 (obligation_id,stalled_epoch,visits,in_progress,exhausted,next_retry_at_seconds)
             SELECT id,1,3,1,0,0 FROM account_recovery_obligations WHERE demand_key='gap';",
        )
        .unwrap();
        let before: i64 = conn
            .query_row("SELECT unixepoch()", [], |r| r.get(0))
            .unwrap();
        run_through(&mut conn, 213).unwrap();
        let (until, now, visits, active): (i64,i64,u32,bool) = conn.query_row(
            "SELECT visit_until_seconds,unixepoch(),visits,in_progress FROM account_recovery_epoch_gap_retries",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).unwrap();
        assert!((before..=now).contains(&until));
        assert_eq!((visits, active), (3, true));
    }
}
