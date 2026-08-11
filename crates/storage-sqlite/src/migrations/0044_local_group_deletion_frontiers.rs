use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Per-group local-delete frontier. The projection row is intentionally absent
/// while the MLS group remains live; reconciliation uses this durable marker to
/// distinguish that state from a torn projection write. The frontier is the
/// local durable ingress order, not any remote sender's wall clock.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE local_group_deletion_frontiers (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    message_insert_order INTEGER NOT NULL CHECK(message_insert_order >= 0),
    prior_nostr_routes_json TEXT NOT NULL DEFAULT '[]'
);

-- Authenticated application deliveries remain pending until the app projection
-- commits. `record` is inside the account's SQLCipher database and is wiped
-- by local group deletion; the source message's durable ingress order provides
-- deterministic replay after a crash.
CREATE TABLE pending_application_events (
    message_id BLOB PRIMARY KEY NOT NULL,
    group_id BLOB NOT NULL,
    message_insert_order INTEGER NOT NULL CHECK(message_insert_order >= 0),
    record BLOB NOT NULL
);
CREATE INDEX idx_pending_application_events_group
    ON pending_application_events(group_id, message_insert_order);

-- Conservatively preserve already-absent live groups during upgrade. Before
-- this table existed, a deliberate local delete and a torn app projection were
-- indistinguishable; privacy wins until a causally newer chat message arrives.
INSERT INTO local_group_deletion_frontiers (group_id_hex, message_insert_order)
SELECT lower(hex(groups.id)), COALESCE(MAX(messages.insert_order), 0)
FROM cgka_groups AS groups
LEFT JOIN cgka_messages AS messages ON messages.group_id = groups.id
WHERE NOT EXISTS (
    SELECT 1 FROM account_groups AS projected
    WHERE projected.group_id_hex = lower(hex(groups.id))
)
AND NOT EXISTS (
    SELECT 1 FROM cgka_disband_tombstones AS terminal
    WHERE terminal.group_id = groups.id
)
GROUP BY groups.id;
"#,
    )
    .storage()
}
