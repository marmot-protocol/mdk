use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Index state-filtered message lookups. The engine's outbound send gate and
/// deferred-peel sweep ask "does this group hold any row in state X at or
/// after epoch Y" on every send; without a state-leading index those probes
/// scan and decode the group's whole retained history.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE INDEX IF NOT EXISTS idx_cgka_messages_group_state_epoch
    ON cgka_messages (group_id, state, epoch);
"#,
    )
    .storage()
}
