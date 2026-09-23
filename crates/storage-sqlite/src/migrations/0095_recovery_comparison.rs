//! One operational comparison slot; coverage and retry remain in the existing ledger.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_comparison (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision)='integer' AND revision>=0),
            settled_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(settled_revision)='integer' AND settled_revision>=0 AND settled_revision<=revision),
            request_key BLOB CHECK(request_key IS NULL OR (typeof(request_key)='blob' AND length(request_key)=16)),
            requested_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(requested_at_ms)='integer' AND requested_at_ms>=0),
            requested_until_seconds INTEGER NOT NULL DEFAULT 0 CHECK(typeof(requested_until_seconds)='integer' AND requested_until_seconds>=0),
            blocked_route_revision INTEGER CHECK(blocked_route_revision IS NULL OR (typeof(blocked_route_revision)='integer' AND blocked_route_revision>=0)),
            blocked_capability_key BLOB,
            attempt_serial INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempt_serial)='integer' AND attempt_serial>=0),
            frozen_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(frozen_revision)='integer' AND frozen_revision>=0),
            plan_format INTEGER NOT NULL DEFAULT 1,
            plan_payload BLOB,
            last_outcome INTEGER CHECK(last_outcome BETWEEN 0 AND 3),
            CHECK((blocked_route_revision IS NULL)=(blocked_capability_key IS NULL))
        );
        INSERT INTO account_recovery_comparison(singleton) VALUES(1);",
    ).storage()
}
