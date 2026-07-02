use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Link a synthesized timeline row to the commit that produced it, without
/// breaking the multi-row-per-commit case.
///
/// Kind-1210 group system rows are synthesized locally from authenticated
/// `GroupStateChanged` events; one commit can produce several rows (e.g. a
/// commit that adds two members). They therefore carry a **null**
/// `source_message_id_hex` (decided in #276), because `source_message_id_hex`
/// is governed by a *partial unique* index and N rows sharing one commit id
/// would collide.
///
/// `origin_commit_id` is a separate, **non-unique** column: it records the
/// transport `MessageId` of the originating commit so that, when fork recovery
/// rolls that commit back, all rows it synthesized can be invalidated together
/// (`invalidate_app_events_by_origin_commit`, a legitimate 1:N update). The
/// supporting index is a plain (non-unique) index so it does not constrain the
/// number of rows per commit.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE app_events ADD COLUMN origin_commit_id TEXT;
CREATE INDEX idx_app_events_origin_commit
    ON app_events (origin_commit_id)
    WHERE origin_commit_id IS NOT NULL;
"#,
    )
    .storage()
}
