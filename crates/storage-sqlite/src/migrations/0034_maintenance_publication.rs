//! Migration 0034: durable KeyPackage and group-maintenance publication state.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_key_package_lifecycle (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    record BLOB NOT NULL
);

CREATE TABLE cgka_group_maintenance (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);

CREATE TABLE cgka_maintenance_obligations (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE INDEX cgka_maintenance_obligations_group_idx
    ON cgka_maintenance_obligations (group_id, insert_order);

CREATE TABLE cgka_group_evolutions (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE INDEX cgka_group_evolutions_group_idx
    ON cgka_group_evolutions (group_id, insert_order);

CREATE TABLE cgka_transport_fanout (
    id BLOB PRIMARY KEY,
    group_id BLOB REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE INDEX cgka_transport_fanout_group_idx
    ON cgka_transport_fanout (group_id, insert_order);

CREATE TABLE cgka_maintenance_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    periodic_policy INTEGER NOT NULL
);
INSERT INTO cgka_maintenance_settings (singleton, periodic_policy) VALUES (1, 1);
"#,
    )
    .storage()
}
