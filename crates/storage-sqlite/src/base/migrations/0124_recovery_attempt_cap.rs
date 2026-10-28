//! Migration 0124: count each recovery obligation's attempts (mdk#2660).
//!
//! `recovery_attempts` counts the reserved attempts that selected a pending
//! obligation since it last made progress. Freezing an attempt adds one;
//! progress on any of its scopes resets it, and so does leaving the pending
//! state (satisfied or retired), through the trigger below. A native goal's
//! re-arm for a new wire generation keeps it pending, so the count survives
//! reconnects and process opens.
//!
//! A re-arm also makes a native goal prove its sources' admission again, so
//! re-proving one is not progress. `recovery_admitted_high` is the most
//! sources the goal has had admitted at once; only admitting more than that
//! resets the count, which bounds the resets by the number of sources. It
//! starts over with the count when the obligation leaves the pending state.
//! Existing rows start at zero.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE account_recovery_obligations ADD COLUMN recovery_attempts INTEGER NOT NULL
            DEFAULT 0 CHECK(typeof(recovery_attempts) = 'integer' AND recovery_attempts >= 0);
        ALTER TABLE account_recovery_obligations ADD COLUMN recovery_admitted_high INTEGER NOT NULL
            DEFAULT 0 CHECK(typeof(recovery_admitted_high) = 'integer' AND recovery_admitted_high >= 0);
        CREATE TRIGGER account_recovery_attempts_reset
            AFTER UPDATE OF state ON account_recovery_obligations
            WHEN NEW.state != 0 AND (NEW.recovery_attempts != 0 OR NEW.recovery_admitted_high != 0)
        BEGIN
            UPDATE account_recovery_obligations SET recovery_attempts = 0, recovery_admitted_high = 0
            WHERE id = NEW.id;
        END;",
    )
    .storage()
}
