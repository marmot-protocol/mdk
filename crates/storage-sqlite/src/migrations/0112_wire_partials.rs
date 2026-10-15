//! Migration 0112: download checkpoints move from SQLCipher chunk rows to
//! append-only `.wire` files in the media store (mdk#2314 step 2b). A
//! checkpoint row now records only the identity, the received length and the
//! id of its wire file, plus `progress_floor`: the length of the checkpoint it
//! replaced, which new bytes must pass to count as forward progress.
//!
//! Wire checkpoints are not retained bytes: the triggers that charged a
//! checkpoint's whole `total` to `attachment_partial_usage.reserved_bytes`
//! are dropped and the counter is zeroed, so an in-flight download no longer
//! refuses outgoing staging or promotion. Free disk is their only limit.
//!
//! Existing database checkpoints are dropped: their downloads restart from
//! the first byte, as the mdk#2314 migration plan allows for in-flight
//! partials. Nothing writes `attachment_partial_chunk` afterwards.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "DELETE FROM attachment_partial;
        DELETE FROM attachment_partial_chunk;
        ALTER TABLE attachment_partial ADD COLUMN wire_file_id BLOB
            CHECK(wire_file_id IS NULL OR length(wire_file_id)=16);
        CREATE UNIQUE INDEX attachment_partial_wire_file
            ON attachment_partial(wire_file_id) WHERE wire_file_id IS NOT NULL;
        ALTER TABLE attachment_partial ADD COLUMN progress_floor INTEGER NOT NULL DEFAULT 0
            CHECK(progress_floor>=0);
        DROP TRIGGER attachment_partial_reserved_added;
        DROP TRIGGER attachment_partial_reserved_removed;
        UPDATE attachment_partial_usage SET reserved_bytes=0;",
    )
    .storage()
}
