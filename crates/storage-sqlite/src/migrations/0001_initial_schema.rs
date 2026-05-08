use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS cgka_groups (
    id BLOB PRIMARY KEY,
    epoch INTEGER NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS cgka_messages (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    group_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    state INTEGER NOT NULL,
    record BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cgka_messages_group_epoch
    ON cgka_messages (group_id, epoch, insert_order);

CREATE TABLE IF NOT EXISTS cgka_queued_outbound (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    group_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    record BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cgka_queued_outbound_group
    ON cgka_queued_outbound (group_id, insert_order);

CREATE TABLE IF NOT EXISTS cgka_welcomes (
    message_id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS cgka_features (
    feature TEXT PRIMARY KEY,
    requirement BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS cgka_member_capabilities (
    group_id BLOB NOT NULL,
    member_id BLOB NOT NULL,
    capabilities BLOB NOT NULL,
    PRIMARY KEY (group_id, member_id)
);

CREATE TABLE IF NOT EXISTS cgka_convergence_policies (
    group_id BLOB PRIMARY KEY,
    policy BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS cgka_group_snapshots (
    group_id BLOB NOT NULL,
    name TEXT NOT NULL,
    snapshot BLOB NOT NULL,
    PRIMARY KEY (group_id, name)
);

CREATE TABLE IF NOT EXISTS openmls_values (
    provider_version INTEGER NOT NULL,
    label BLOB NOT NULL,
    storage_key BLOB NOT NULL,
    group_key BLOB,
    value BLOB NOT NULL,
    PRIMARY KEY (provider_version, storage_key)
);
CREATE INDEX IF NOT EXISTS idx_openmls_values_group
    ON openmls_values (provider_version, group_key);
"#,
    )
    .storage()
}
