use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Peer-keyed index for existing-direct-conversation reuse (mdk#1463).
///
/// This migration creates the table and covering member index only. It cannot
/// obtain live MLS rosters. New Direct groups write both member hexes from
/// the account projection; existing Direct groups are filled once on the
/// account-worker hydration path and gated by an import marker. The covering
/// index on `member_id_hex` is the driving relation for reuse lookup.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS direct_conversation_members (
    group_id_hex TEXT NOT NULL,
    member_id_hex TEXT NOT NULL,
    PRIMARY KEY (group_id_hex, member_id_hex),
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_direct_conversation_members_member
    ON direct_conversation_members (member_id_hex, group_id_hex);
"#,
    )
    .storage()
}
