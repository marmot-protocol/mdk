use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_messages_new (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    state INTEGER NOT NULL,
    record BLOB NOT NULL
);
INSERT INTO cgka_messages_new (insert_order, id, group_id, epoch, state, record)
    SELECT insert_order, id, group_id, epoch, state, record FROM cgka_messages;
DROP TABLE cgka_messages;
ALTER TABLE cgka_messages_new RENAME TO cgka_messages;
CREATE INDEX idx_cgka_messages_group_epoch
    ON cgka_messages (group_id, epoch, insert_order);

CREATE TABLE cgka_queued_outbound_new (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    created_at_ms INTEGER NOT NULL,
    record BLOB NOT NULL
);
INSERT INTO cgka_queued_outbound_new (insert_order, id, group_id, created_at_ms, record)
    SELECT insert_order, id, group_id, created_at_ms, record FROM cgka_queued_outbound;
DROP TABLE cgka_queued_outbound;
ALTER TABLE cgka_queued_outbound_new RENAME TO cgka_queued_outbound;
CREATE INDEX idx_cgka_queued_outbound_group
    ON cgka_queued_outbound (group_id, insert_order);

CREATE TABLE cgka_member_capabilities_new (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    member_id BLOB NOT NULL,
    capabilities BLOB NOT NULL,
    PRIMARY KEY (group_id, member_id)
);
INSERT INTO cgka_member_capabilities_new (group_id, member_id, capabilities)
    SELECT group_id, member_id, capabilities FROM cgka_member_capabilities;
DROP TABLE cgka_member_capabilities;
ALTER TABLE cgka_member_capabilities_new RENAME TO cgka_member_capabilities;

CREATE TABLE cgka_convergence_policies_new (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    policy BLOB NOT NULL
);
INSERT INTO cgka_convergence_policies_new (group_id, policy)
    SELECT group_id, policy FROM cgka_convergence_policies;
DROP TABLE cgka_convergence_policies;
ALTER TABLE cgka_convergence_policies_new RENAME TO cgka_convergence_policies;

CREATE TABLE cgka_group_snapshots_new (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    snapshot BLOB NOT NULL,
    PRIMARY KEY (group_id, name)
);
INSERT INTO cgka_group_snapshots_new (group_id, name, snapshot)
    SELECT group_id, name, snapshot FROM cgka_group_snapshots;
DROP TABLE cgka_group_snapshots;
ALTER TABLE cgka_group_snapshots_new RENAME TO cgka_group_snapshots;
"#,
    )
    .storage()
}
