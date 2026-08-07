use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Durable transport-route index (mdk#1161): opaque transport routing-id
/// bytes -> MLS group id, so session open can seed inbound routing without
/// loading each group's MLS state. Many-to-one per group: a routing rotation
/// keeps the prior route for its overlap window (mdk#740). Deliberately not
/// captured by group snapshots — routes are a regenerable projection of MLS
/// state, and a rollback must not delete a still-valid route. Groups stored
/// before this migration have no rows; the engine backfills their routes on
/// first full hydration.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_transport_group_routes (
    transport_group_id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    FOREIGN KEY (group_id) REFERENCES cgka_groups(id) ON DELETE CASCADE
);

CREATE INDEX idx_cgka_transport_group_routes_group
    ON cgka_transport_group_routes(group_id);
"#,
    )
    .storage()
}
