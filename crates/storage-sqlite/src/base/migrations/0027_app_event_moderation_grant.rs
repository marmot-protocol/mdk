use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // No backfill, by deliberate decision: existing rows default to 0 (no
    // grant), which is exactly the pre-migration behavior. Every historical
    // delete was honored only as a self-retraction (author == target), never
    // as admin moderation, so `false` is the correct historical verdict and
    // reprojecting old deletes keeps their original outcome. Backfilling `true`
    // for old cross-sender deletes would retroactively honor deletes that no
    // client ever applied.
    tx.execute_batch(
        r#"
ALTER TABLE app_events ADD COLUMN moderation_grant INTEGER NOT NULL DEFAULT 0;
"#,
    )
    .storage()
}
