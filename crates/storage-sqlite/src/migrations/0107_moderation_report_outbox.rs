//! Migration 0107: durable outbox for private moderation reports to the deployment's moderation team.
//!
//! Rows hold only what retry, idempotency and the local rate limit need: an opaque local id, a
//! one-way key of the report's (target, reason, origin), the recipient key, and the already-signed
//! NIP-59 gift wrap while it awaits relay acceptance. The reported key and free-text explanation
//! exist only inside that ciphertext, and the ciphertext is cleared once a relay accepts it.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE moderation_report_outbox (
    report_id TEXT PRIMARY KEY NOT NULL CHECK(length(report_id) = 32),
    dedupe_key TEXT NOT NULL CHECK(length(dedupe_key) = 64),
    recipient_pubkey_hex TEXT NOT NULL CHECK(length(recipient_pubkey_hex) = 64),
    outcome TEXT NOT NULL
        CHECK(outcome IN ('published', 'accepted_pending', 'completion_unknown')),
    -- Signed kind-1059 wrap awaiting acceptance; NULL once a relay accepted it.
    event_json TEXT,
    created_at_ms INTEGER NOT NULL,
    last_attempt_at_ms INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    CHECK((outcome = 'published') = (event_json IS NULL))
);
CREATE INDEX moderation_report_outbox_dedupe_idx
    ON moderation_report_outbox (dedupe_key, created_at_ms);
CREATE INDEX moderation_report_outbox_created_idx
    ON moderation_report_outbox (created_at_ms);
"#,
    )
    .storage()
}
