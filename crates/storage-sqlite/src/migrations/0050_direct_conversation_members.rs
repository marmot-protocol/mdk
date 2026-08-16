use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Peer-keyed index for existing-direct-conversation reuse (mdk#1463).
///
/// Hosts look up "the reusable DM with this peer" without paging every
/// unnamed two-member chat. The covering index on `member_id_hex` lets that
/// read examine only groups that already contain the peer; other-peer DMs
/// never enter the candidate set. Rows are written from the account
/// projection whenever a group is classified Direct (empty name, roster
/// size 2) and dropped when it is not.
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
