//! Migration 0128: the routes each loss generation touched (mdk#2660 phase 4).
//!
//! `account_delivery_loss_evidence_routes` holds, per loss generation, each
//! route one of its charges lost a delivery or notification on, with the
//! earliest `created_at` it could have lost there. `route_state` on the
//! evidence row is 1 while every charge named its route and time, and 0 for
//! good once one did not, or once the generation touched more routes than a
//! row may list. Rows from before this migration are 0.
//!
//! Un-covering is owed per write, not per count: a restored generation
//! restarts its process-local count under the same marker, so a write can
//! bring new loss without raising `dropped_count`. Each write marks what it
//! brought as owed (`owed` on its route rows, `uncover_owed` on the evidence
//! row), and the next import un-covers it: only the owed routes, each from its
//! own bound, while `route_state` is 1, and every route from the generation's
//! floor otherwise. A row whose count is not fully imported owes an un-cover
//! whatever its flag says, so earlier rows need no backfill.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_delivery_loss_evidence
            ADD COLUMN route_state INTEGER NOT NULL DEFAULT 0 CHECK (route_state IN (0, 1));
        ALTER TABLE account_delivery_loss_evidence
            ADD COLUMN uncover_owed INTEGER NOT NULL DEFAULT 0 CHECK (uncover_owed IN (0, 1));
        CREATE TABLE account_delivery_loss_evidence_routes (
            account_label TEXT NOT NULL,
            cause INTEGER NOT NULL,
            marker_token INTEGER NOT NULL,
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            bound_seconds INTEGER NOT NULL CHECK (bound_seconds >= 0),
            owed INTEGER NOT NULL DEFAULT 1 CHECK (owed IN (0, 1)),
            PRIMARY KEY (account_label, cause, marker_token, route_kind, route_id),
            FOREIGN KEY (account_label, cause, marker_token)
                REFERENCES account_delivery_loss_evidence (account_label, cause, marker_token)
                ON DELETE CASCADE
        ) WITHOUT ROWID;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// Earlier evidence imports account-wide and owes nothing by flag, and a
    /// generation's route rows go with it.
    #[test]
    fn earlier_evidence_is_unrouted_and_route_rows_cascade() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        let before = MIGRATIONS.iter().position(|m| m.version == 128).unwrap();
        run(&mut conn, &MIGRATIONS[..before]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_state (label, updated_at) VALUES ('alice', 0);
             INSERT INTO account_delivery_loss_evidence
                (account_label, cause, marker_token, pending_since, dropped_count, imported_count)
             VALUES ('alice', 0, 7, 10, 2, NULL), ('alice', 0, 8, 10, 2, 2);",
        )
        .unwrap();
        run(&mut conn, &MIGRATIONS[..=before]).unwrap();
        let states: Vec<(i64, i64)> = conn
            .prepare(
                "SELECT route_state, uncover_owed FROM account_delivery_loss_evidence
                 ORDER BY marker_token",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(states, vec![(0, 0), (0, 0)]);
        conn.execute(
            "INSERT INTO account_delivery_loss_evidence_routes VALUES ('alice', 0, 7, 0, x'', 5, 1)",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM account_delivery_loss_evidence", [])
            .unwrap();
        let routes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM account_delivery_loss_evidence_routes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(routes, 0);
    }
}
