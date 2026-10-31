//! Migration 0163: what this device keeps about the account's backup
//! recovery key (mdk#2628 item 4.4a).
//!
//! `backup_recovery_key` holds at most one row, in one of three states:
//! - `kept`: `public_key` is the public half of the recovery key words
//!   confirmed while this device had no device group derive; the roster it
//!   founds carries it.
//! - `confirmed`: `public_key` is the public half of the recovery key the
//!   words last confirmed on this device derive. `replaces` is the key the
//!   roster held when they replaced it, and the change is carried again while
//!   the roster holds that and branch selection could still withdraw or
//!   restore it, so a commit that never went out or that a fork dropped is
//!   not lost. It is absent when the words turned backups on, or were kept
//!   before this device trusted a device group; such a change is never
//!   carried again, since a roster that holds no key looks the same before
//!   backups are turned on and after they are turned off.
//! - `turning_off`: the user turned backups off on this device while the
//!   roster held `replaces`; the change is carried again as new words are.
//!
//! The row stays until the user makes another change, or dismisses words
//! that are not in use. Whether words are in use is read from the roster
//! each time, never stored. The words and the private half are never stored.
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE backup_recovery_key (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            state TEXT NOT NULL,
            public_key BLOB CHECK (public_key IS NULL OR length(public_key) BETWEEN 1 AND 255),
            replaces BLOB CHECK (replaces IS NULL OR length(replaces) BETWEEN 1 AND 255),
            CHECK (
                (state = 'kept' AND public_key IS NOT NULL AND replaces IS NULL)
                OR (state = 'confirmed' AND public_key IS NOT NULL)
                OR (state = 'turning_off' AND public_key IS NULL AND replaces IS NOT NULL)
            )
        );",
    )
    .storage()
}
