//! Earliest wire `created_at` among the deliveries charged to a loss
//! generation, so recovery can bound what a comparison must cover.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // `bound_state` 1: `bound_seconds` is the running minimum over every
    // charge. 2: some charge had no known `created_at`, which includes every
    // row written before this migration. Only state 1 bounds a goal.
    tx.execute_batch(
        "ALTER TABLE account_delivery_loss_evidence ADD COLUMN bound_state INTEGER NOT NULL
             DEFAULT 2 CHECK(bound_state IN (1, 2));
         ALTER TABLE account_delivery_loss_evidence ADD COLUMN bound_seconds INTEGER
             CHECK(bound_seconds IS NULL OR (typeof(bound_seconds)='integer' AND bound_seconds>=0));",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    /// Loss recorded before this migration has no known `created_at`, so it
    /// bounds no goal.
    #[test]
    fn earlier_loss_bounds_no_goal() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run_through(&mut conn, 96).unwrap();
        conn.execute_batch(
            "INSERT INTO account_state(label,updated_at) VALUES ('alice',100);
            INSERT INTO account_delivery_loss_evidence
                (account_label,cause,marker_token,pending_since,dropped_count,imported_count)
                VALUES ('alice',0,42,124,9,9);",
        )
        .unwrap();
        run_through(&mut conn, 97).unwrap();
        let bound: (i64, Option<i64>) = conn
            .query_row(
                "SELECT bound_state, bound_seconds FROM account_delivery_loss_evidence",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(bound, (2, None));
    }
}
