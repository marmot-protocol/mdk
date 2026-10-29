//! Migration 0132: the loss revision each loss generation's latest import
//! left (mdk#2660 phase 4).
//!
//! `import_revision` on `account_delivery_loss_evidence` is the account's
//! `loss_revision` just after the generation's join in the import that last
//! charged it, and NULL while no import has charged it. A checkpoint captured
//! at a lower loss revision has not seen that charge. Generations imported
//! before this migration take the current revision: a checkpoint captured at
//! it saw them, and one captured earlier may not have.
//!
//! Acknowledgment deletes the generations it reclaims, so
//! `account_recovery_state.acknowledged_import_revision` keeps the highest
//! `import_revision` any acknowledgment deleted: below it, where loss
//! reached is no longer known. Acknowledgments before this migration left no
//! stamp, so it starts at the current loss revision.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_delivery_loss_evidence
            ADD COLUMN import_revision INTEGER CHECK (import_revision >= 0);
        UPDATE account_delivery_loss_evidence
            SET import_revision = (SELECT loss_revision FROM account_recovery_state
                                   WHERE singleton = 1)
            WHERE imported_count IS NOT NULL;
        ALTER TABLE account_recovery_state
            ADD COLUMN acknowledged_import_revision INTEGER NOT NULL DEFAULT 0
            CHECK (typeof(acknowledged_import_revision) = 'integer'
                   AND acknowledged_import_revision >= 0);
        UPDATE account_recovery_state SET acknowledged_import_revision = loss_revision;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// Imported generations take the current loss revision; generations no
    /// import has charged stay NULL. Earlier acknowledgments left no stamp, so
    /// everything up to the current revision counts as acknowledged.
    #[test]
    fn imported_generations_take_the_current_loss_revision() {
        let mut conn = Connection::open_in_memory().unwrap();
        let before = MIGRATIONS.iter().position(|m| m.version == 132).unwrap();
        run(&mut conn, &MIGRATIONS[..before]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_state (label, updated_at) VALUES ('alice', 0);
             UPDATE account_recovery_state SET loss_revision = 5 WHERE singleton = 1;
             INSERT INTO account_delivery_loss_evidence
                (account_label, cause, marker_token, pending_since, dropped_count, imported_count)
             VALUES ('alice', 0, 7, 10, 2, NULL), ('alice', 0, 8, 10, 2, 2);",
        )
        .unwrap();
        run(&mut conn, &MIGRATIONS[..=before]).unwrap();
        let revisions: Vec<Option<i64>> = conn
            .prepare(
                "SELECT import_revision FROM account_delivery_loss_evidence ORDER BY marker_token",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(revisions, vec![None, Some(5)]);
        let acknowledged: i64 = conn
            .query_row(
                "SELECT acknowledged_import_revision FROM account_recovery_state",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(acknowledged, 5);
    }
}
