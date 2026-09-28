//! Parked recovery shown as "history may be incomplete", and its explicit,
//! user-authorized retirement.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // `parked_at_ms` is the wall-clock time an obligation last moved to
    // `eligibility = 4` (needs deep repair). It is read only while the row is
    // still pending and parked; rows parked before this migration keep NULL.
    //
    // `retired_count` is a loss generation's watermark when the user retired
    // its obligation. Retired evidence carries no debt and is never coverage;
    // the watermark only stops a delayed duplicate observation from rearming
    // it. A later count above it is new loss.
    tx.execute_batch(
        "ALTER TABLE account_recovery_obligations ADD COLUMN parked_at_ms INTEGER
             CHECK(parked_at_ms IS NULL OR (typeof(parked_at_ms)='integer' AND parked_at_ms>=0));
         ALTER TABLE account_delivery_loss_evidence ADD COLUMN retired_count INTEGER
             CHECK(retired_count IS NULL OR (typeof(retired_count)='integer' AND retired_count>=0
                 AND retired_count<=imported_count));",
    )
    .storage()
}
