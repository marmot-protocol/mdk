//! Migration 0092: durable per-route subscription replay obligations.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE subscription_replay_obligations (
    route_kind             INTEGER NOT NULL CHECK(route_kind IN (0, 1)),
    route_role             INTEGER NOT NULL CHECK(route_role IN (0, 1, 2)),
    group_id               BLOB NOT NULL,
    transport_group_id     BLOB NOT NULL,
    endpoint_scope_digest  BLOB NOT NULL CHECK(
        typeof(endpoint_scope_digest) = 'blob' AND length(endpoint_scope_digest) = 32
    ),
    generation             BLOB NOT NULL UNIQUE DEFAULT(randomblob(16)) CHECK(
        typeof(generation) = 'blob' AND length(generation) = 16
    ),
    replay_floor           INTEGER CHECK(replay_floor IS NULL OR replay_floor >= 0),
    admitted_scope_settled INTEGER NOT NULL DEFAULT 0 CHECK(admitted_scope_settled IN (0, 1)),
    PRIMARY KEY (
        route_kind,
        route_role,
        group_id,
        transport_group_id,
        endpoint_scope_digest
    ),
    CHECK(
        (route_kind = 0 AND route_role = 0
            AND length(group_id) = 0 AND length(transport_group_id) = 0)
        OR
        (route_kind = 1 AND route_role IN (1, 2)
            AND length(group_id) > 0 AND length(transport_group_id) = 32)
    )
) WITHOUT ROWID;

CREATE TABLE subscription_replay_endpoints (
    generation  BLOB NOT NULL REFERENCES subscription_replay_obligations(generation)
        ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL CHECK(ordinal >= 0),
    endpoint    TEXT NOT NULL CHECK(length(CAST(endpoint AS BLOB)) BETWEEN 1 AND 4096),
    PRIMARY KEY (generation, ordinal),
    UNIQUE (generation, endpoint)
) WITHOUT ROWID;

CREATE TABLE subscription_replay_admitted_endpoints (
    generation  BLOB NOT NULL REFERENCES subscription_replay_obligations(generation)
        ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL CHECK(ordinal >= 0),
    endpoint    TEXT NOT NULL CHECK(length(CAST(endpoint AS BLOB)) BETWEEN 1 AND 4096),
    PRIMARY KEY (generation, ordinal),
    UNIQUE (generation, endpoint)
) WITHOUT ROWID;
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    #[test]
    fn subscription_replay_migration_is_empty_and_rolls_back_atomically() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        run(&mut connection, &MIGRATIONS[..91]).unwrap();

        let transaction = connection.transaction().unwrap();
        apply(&transaction).unwrap();
        for table in [
            "subscription_replay_obligations",
            "subscription_replay_endpoints",
            "subscription_replay_admitted_endpoints",
        ] {
            assert!(
                transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master
                         WHERE type = 'table' AND name = ?1)",
                        [table],
                        |row| row.get::<_, bool>(0),
                    )
                    .unwrap()
            );
        }
        transaction.rollback().unwrap();

        for table in [
            "subscription_replay_obligations",
            "subscription_replay_endpoints",
            "subscription_replay_admitted_endpoints",
        ] {
            assert!(
                !connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master
                         WHERE type = 'table' AND name = ?1)",
                        [table],
                        |row| row.get::<_, bool>(0),
                    )
                    .unwrap()
            );
        }

        run(&mut connection, MIGRATIONS).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM subscription_replay_obligations",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        run(&mut connection, MIGRATIONS).unwrap();
    }
}
