use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE transport_reconciliation_items (
    route_kind  INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
    route_id    BLOB NOT NULL CHECK (
                    (route_kind = 0 AND length(route_id) = 0) OR
                    (route_kind = 1 AND length(route_id) = 32)
                ),
    event_id    BLOB NOT NULL CHECK (length(event_id) = 32),
    created_at  INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (route_kind, route_id, event_id)
) WITHOUT ROWID;

CREATE INDEX transport_reconciliation_items_route_order
    ON transport_reconciliation_items (route_kind, route_id, created_at, event_id);

CREATE TABLE transport_reconciliation_route_state (
    route_kind      INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
    route_id        BLOB NOT NULL CHECK (
                        (route_kind = 0 AND length(route_id) = 0) OR
                        (route_kind = 1 AND length(route_id) = 32)
                    ),
    inventory_since INTEGER NOT NULL CHECK (inventory_since >= 0),
    PRIMARY KEY (route_kind, route_id)
) WITHOUT ROWID;

CREATE TABLE transport_reconciliation_scheduler (
    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
    route_kind      INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
    route_id        BLOB NOT NULL CHECK (
                        (route_kind = 0 AND length(route_id) = 0) OR
                        (route_kind = 1 AND length(route_id) = 32)
                    )
);
"#,
    )
    .storage()
}
