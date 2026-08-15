use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Covering partial index for the invite-policy pending-confirmation
/// predicate (mdk#1380). The agent connector's invite-policy worker asks
/// "which groups are pending confirmation and not archived" on every
/// reconciliation pass; without an index matching that predicate the query
/// scans every retained group row. The partial index holds only the matching
/// rows (typically zero), so an idle enumeration examines O(pending invites)
/// index entries — and both selected columns are covered, so SQLite answers
/// from the index alone with no table-row lookups, while the leading column
/// satisfies the query's `ORDER BY group_id_hex` without a sort.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE INDEX IF NOT EXISTS idx_account_groups_pending_invites
    ON account_groups (group_id_hex, welcomer_account_id_hex)
    WHERE pending_confirmation = 1 AND archived = 0;
"#,
    )
    .storage()
}
