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
