//! Each recovery obligation's own streak of completed passes without progress.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // `quiet_passes` counts the obligation's completed comparison passes in a
    // row that certified nothing and admitted nothing, at `quiet_revision`. A
    // new revision is new evidence and starts the streak over. Rows written
    // before this migration start without a streak.
    tx.execute_batch(
        "ALTER TABLE account_recovery_obligations ADD COLUMN quiet_passes INTEGER NOT NULL DEFAULT 0
             CHECK(typeof(quiet_passes)='integer' AND quiet_passes>=0);
         ALTER TABLE account_recovery_obligations ADD COLUMN quiet_revision INTEGER
             CHECK(quiet_revision IS NULL OR (typeof(quiet_revision)='integer' AND quiet_revision>0));",
    )
    .storage()
}
