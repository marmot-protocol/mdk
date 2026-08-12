//! Migration 0036: durable QUIC preview publisher sequence reservations.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE agent_stream_publisher_sequences (
    context_id BLOB PRIMARY KEY NOT NULL CHECK(length(context_id) = 32),
    next_seq INTEGER NOT NULL CHECK(next_seq >= 1),
    transcript_hash BLOB NOT NULL CHECK(length(transcript_hash) = 32),
    chunk_count INTEGER NOT NULL CHECK(chunk_count >= 0),
    reservation_token BLOB CHECK(reservation_token IS NULL OR length(reservation_token) = 16),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0, 1)),
    updated_at_ms INTEGER NOT NULL
);
"#,
    )
    .storage()
}
