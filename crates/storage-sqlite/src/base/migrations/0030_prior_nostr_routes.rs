use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE account_groups
ADD COLUMN nostr_routing_last_epoch INTEGER NOT NULL DEFAULT 0;

ALTER TABLE account_groups
ADD COLUMN prior_nostr_routes_json TEXT NOT NULL DEFAULT '[]';
"#,
    )
    .storage()
}
