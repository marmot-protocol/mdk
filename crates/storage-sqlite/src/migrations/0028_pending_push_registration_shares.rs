//! Durable per-group retry intent for local push-registration gossip.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE pending_push_registration_shares (
    group_id_hex TEXT PRIMARY KEY
        REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    token_fingerprint TEXT NOT NULL,
    registration_updated_at_ms INTEGER NOT NULL,
    queued_at_ms INTEGER NOT NULL,
    last_attempted_at_ms INTEGER
);
CREATE INDEX pending_push_registration_shares_token_idx
    ON pending_push_registration_shares (
        token_fingerprint, registration_updated_at_ms
    );

INSERT INTO pending_push_registration_shares (
    group_id_hex, token_fingerprint, registration_updated_at_ms,
    queued_at_ms, last_attempted_at_ms
)
SELECT account_groups.group_id_hex, push_registration.token_fingerprint,
       push_registration.updated_at_ms, push_registration.updated_at_ms, NULL
FROM account_groups
CROSS JOIN push_registration
WHERE account_groups.self_membership = 'member';

UPDATE push_registration
SET last_shared_at_ms = NULL
WHERE EXISTS (SELECT 1 FROM pending_push_registration_shares);
"#,
    )
    .storage()
}
