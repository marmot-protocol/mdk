//! Migration 0033: durable per-group outbox for push-registration updates and removals.

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

CREATE TABLE pending_push_registration_removals (
    -- Removal intent must outlive app-local projection deletion. Unlike update
    -- shares, these rows deliberately do not reference account_groups.
    group_id_hex TEXT NOT NULL,
    account_label TEXT NOT NULL,
    account_id_hex TEXT NOT NULL,
    platform INTEGER NOT NULL,
    token_fingerprint TEXT NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    relay_hint TEXT,
    registration_created_at_ms INTEGER NOT NULL,
    registration_updated_at_ms INTEGER NOT NULL,
    queued_at_ms INTEGER NOT NULL,
    last_attempted_at_ms INTEGER,
    PRIMARY KEY (
        group_id_hex, platform, server_pubkey_hex,
        token_fingerprint, registration_updated_at_ms
    )
);
CREATE INDEX pending_push_registration_removals_revision_idx
    ON pending_push_registration_removals (
        token_fingerprint, registration_updated_at_ms
    );

INSERT INTO pending_push_registration_shares (
    group_id_hex, token_fingerprint, registration_updated_at_ms,
    queued_at_ms, last_attempted_at_ms
)
SELECT account_groups.group_id_hex, current_registration.token_fingerprint,
       current_registration.updated_at_ms, current_registration.updated_at_ms, NULL
FROM account_groups
CROSS JOIN (
    -- Account-device databases normally contain one registration. If a legacy
    -- database contains more than one account label, choose one deterministically
    -- instead of cross-joining duplicate group keys and aborting the migration.
    SELECT token_fingerprint, updated_at_ms
    FROM push_registration
    ORDER BY updated_at_ms DESC, account_label DESC
    LIMIT 1
) AS current_registration
WHERE account_groups.self_membership = 'member';

-- The legacy last_shared_at_ms value was account-wide and was set after any
-- successful group publish, so it cannot identify which groups missed gossip.
-- Requeue every joined group once on upgrade to heal partial legacy fanout.
UPDATE push_registration
SET last_shared_at_ms = NULL
WHERE EXISTS (SELECT 1 FROM pending_push_registration_shares);
"#,
    )
    .storage()
}
