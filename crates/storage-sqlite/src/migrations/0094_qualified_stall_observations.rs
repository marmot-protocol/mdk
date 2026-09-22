//! Deduplicate qualified local stagnation observations without rewriting legacy evidence.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_state ADD COLUMN next_engine_observation INTEGER NOT NULL DEFAULT 0 CHECK(typeof(next_engine_observation)='integer' AND next_engine_observation >= 0);
         ALTER TABLE account_recovery_state ADD COLUMN next_stall_sample INTEGER NOT NULL DEFAULT 0 CHECK(typeof(next_stall_sample)='integer' AND next_stall_sample >= 0);
         ALTER TABLE app_epoch_stall_evidence ADD COLUMN qualified_certificate BLOB;
         ALTER TABLE app_epoch_stall_evidence ADD COLUMN last_engine_observation INTEGER NOT NULL DEFAULT 0 CHECK(typeof(last_engine_observation)='integer' AND last_engine_observation >= 0);
         ALTER TABLE app_epoch_stall_evidence ADD COLUMN last_sample_sequence INTEGER NOT NULL DEFAULT 0 CHECK(typeof(last_sample_sequence)='integer' AND last_sample_sequence >= 0);
         ALTER TABLE app_epoch_stall_evidence ADD COLUMN last_sample_at_ms INTEGER;",
    ).storage()
}
