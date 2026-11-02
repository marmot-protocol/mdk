//! Migration 0134: a recovery unit's re-check pass keeps a revision (mdk#2660
//! phase 4).
//!
//! Every request that makes the pass due (an epoch gap, explicit repair, a
//! long relay cooldown) bumps `recheck_revision`, and a quantum records the
//! pass's progress only under the revision it began on. A request can leave
//! the pass's position and completion as they were, so without the revision a
//! quantum running when it arrived would record its pass complete and the
//! requested re-check would wait for the next interval. Existing passes start
//! at revision 0.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_units ADD COLUMN recheck_revision INTEGER NOT NULL
            DEFAULT 0 CHECK (recheck_revision >= 0);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// A unit row from the schema before keeps its pass at revision 0.
    #[test]
    fn an_existing_pass_starts_at_revision_zero() {
        let mut conn = Connection::open_in_memory().unwrap();
        let end = MIGRATIONS.iter().position(|m| m.version == 134).unwrap();
        run(&mut conn, &MIGRATIONS[..end]).unwrap();
        conn.execute(
            "INSERT INTO account_recovery_units
             (route_kind, route_id, relay, recheck_position_seconds)
             VALUES (0, x'', 'wss://a', 40)",
            [],
        )
        .unwrap();
        run(&mut conn, &MIGRATIONS[..end + 1]).unwrap();
        let (position, revision): (Option<i64>, i64) = conn
            .query_row(
                "SELECT recheck_position_seconds, recheck_revision FROM account_recovery_units",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((position, revision), (Some(40), 0));
        assert!(
            conn.execute(
                "UPDATE account_recovery_units SET recheck_revision = -1",
                []
            )
            .is_err()
        );
    }
}
