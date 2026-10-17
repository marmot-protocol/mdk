//! Add a chat-list projection-version marker so the warm-up completeness check
//! can skip the O(groups × unread-per-group) per-group mention recompute once the
//! stored `unread_mention_count`s are known current (#750).
//!
//! Migration 0019 added `unread_mention_count` defaulted to 0, so
//! `chat_list_projection_complete_tx` re-derives the mention count of every
//! unread message of every group on warm-up to correct those defaulted rows —
//! materializing every unread plaintext each time. This marker records that the
//! counts have been reconciled to the current projection version; once set, the
//! per-group recompute is skipped (incremental refresh keeps the counts current
//! from then on). Seeded at version 0 (not reconciled) so the first warm-up still
//! runs the correction, then advances the marker.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE chat_list_projection_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    mention_counts_version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO chat_list_projection_meta (id, mention_counts_version) VALUES (1, 0);
"#,
    )
    .storage()?;
    Ok(())
}
