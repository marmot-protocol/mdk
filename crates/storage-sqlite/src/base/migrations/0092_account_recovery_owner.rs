//! Replace narrow history-demand markers with one account-private authority.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE account_recovery_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    next_attempt INTEGER NOT NULL DEFAULT 0 CHECK(typeof(next_attempt) = 'integer' AND next_attempt >= 0),
    loss_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(loss_revision) = 'integer' AND loss_revision >= 0),
    route_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(route_revision) = 'integer' AND route_revision >= 0),
    inventory_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(inventory_revision) = 'integer' AND inventory_revision >= 0),
    retry_ordinal INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_ordinal) = 'integer' AND retry_ordinal >= 0),
    retry_recorded_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_recorded_at_ms) = 'integer' AND retry_recorded_at_ms >= 0),
    retry_delay_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_delay_ms) = 'integer' AND retry_delay_ms >= 0),
    retry_not_before_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_not_before_ms) = 'integer' AND retry_not_before_ms >= 0)
);
INSERT INTO account_recovery_state(singleton) VALUES (1);

CREATE TABLE account_recovery_obligations (
    id BLOB PRIMARY KEY NOT NULL DEFAULT(randomblob(16)) CHECK(typeof(id) = 'blob' AND length(id) = 16),
    demand_key TEXT NOT NULL UNIQUE,
    cause INTEGER NOT NULL CHECK(cause BETWEEN 0 AND 6),
    group_id BLOB REFERENCES cgka_groups(id) ON DELETE CASCADE,
    account_label TEXT REFERENCES account_state(label) ON DELETE CASCADE,
    stalled_epoch INTEGER CHECK(stalled_epoch IS NULL OR (typeof(stalled_epoch) = 'integer' AND stalled_epoch >= 0)),
    marker_token INTEGER CHECK(marker_token IS NULL OR (typeof(marker_token) = 'integer' AND marker_token >= 0)),
    pending_since INTEGER CHECK(pending_since IS NULL OR (typeof(pending_since) = 'integer' AND pending_since >= 0)),
    dropped_count INTEGER CHECK(dropped_count IS NULL OR (typeof(dropped_count) = 'integer' AND dropped_count >= 0)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(revision) = 'integer' AND revision > 0),
    predicate INTEGER NOT NULL DEFAULT 0 CHECK(predicate BETWEEN 0 AND 2),
    urgency INTEGER NOT NULL DEFAULT 0 CHECK(urgency BETWEEN 0 AND 2),
    created_at_ms INTEGER NOT NULL CHECK(typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(typeof(updated_at_ms) = 'integer' AND updated_at_ms >= 0),
    state INTEGER NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 2),
    eligibility INTEGER NOT NULL DEFAULT 0 CHECK(eligibility BETWEEN 0 AND 4),
    incomplete_reason INTEGER CHECK(incomplete_reason BETWEEN 0 AND 7),
    caller_origin INTEGER NOT NULL DEFAULT 0 CHECK(caller_origin IN (0, 1)),
    CHECK((cause NOT IN (0, 6)) OR (account_label IS NOT NULL AND marker_token IS NOT NULL
          AND pending_since IS NOT NULL AND dropped_count IS NOT NULL)),
    CHECK((cause != 1) OR (group_id IS NOT NULL AND stalled_epoch IS NOT NULL))
);
CREATE INDEX account_recovery_pending ON account_recovery_obligations(state, eligibility);
CREATE INDEX account_recovery_group ON account_recovery_obligations(cause, group_id, stalled_epoch);
CREATE INDEX account_recovery_account ON account_recovery_obligations(cause, account_label, marker_token);
CREATE INDEX account_recovery_epoch_order ON account_recovery_obligations(updated_at_ms, group_id) WHERE cause = 1 AND state = 0;

CREATE TABLE account_recovery_scopes (
    obligation_id BLOB NOT NULL REFERENCES account_recovery_obligations(id) ON DELETE CASCADE,
    scope_id INTEGER NOT NULL CHECK(typeof(scope_id) = 'integer' AND scope_id >= 0),
    route_kind INTEGER CHECK(route_kind BETWEEN 0 AND 2),
    route_role INTEGER CHECK(route_role BETWEEN 0 AND 2),
    group_id BLOB,
    transport_group_id BLOB CHECK(transport_group_id IS NULL OR (typeof(transport_group_id) = 'blob' AND length(transport_group_id) = 32)),
    route_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(route_revision) = 'integer' AND route_revision >= 0),
    since_seconds INTEGER CHECK(since_seconds IS NULL OR (typeof(since_seconds) = 'integer' AND since_seconds >= 0)),
    until_seconds INTEGER CHECK(until_seconds IS NULL OR (typeof(until_seconds) = 'integer' AND until_seconds >= 0)),
    known_event_id BLOB CHECK(known_event_id IS NULL OR (typeof(known_event_id) = 'blob' AND length(known_event_id) = 32)),
    scope_revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(scope_revision) = 'integer' AND scope_revision > 0),
    snapshot_state INTEGER NOT NULL DEFAULT 0 CHECK(snapshot_state IN (0, 1)),
    inventory_floor INTEGER CHECK(inventory_floor IS NULL OR (typeof(inventory_floor) = 'integer' AND inventory_floor >= 0)),
    progress_after BLOB CHECK(progress_after IS NULL OR (typeof(progress_after) = 'blob' AND length(progress_after) = 32)),
    scope_format INTEGER NOT NULL DEFAULT 1 CHECK(scope_format > 0),
    scope_payload BLOB,
    CHECK(snapshot_state = 0 OR (until_seconds IS NOT NULL AND scope_payload IS NOT NULL)),
    CHECK(since_seconds IS NULL OR until_seconds IS NULL OR since_seconds <= until_seconds),
    PRIMARY KEY(obligation_id, scope_id)
);

CREATE TABLE account_delivery_loss_evidence (
    account_label TEXT NOT NULL REFERENCES account_state(label) ON DELETE CASCADE,
    cause INTEGER NOT NULL CHECK(cause IN (0, 1)),
    marker_token INTEGER NOT NULL CHECK(typeof(marker_token) = 'integer' AND marker_token >= 0),
    pending_since INTEGER NOT NULL CHECK(typeof(pending_since) = 'integer' AND pending_since >= 0),
    dropped_count INTEGER NOT NULL CHECK(typeof(dropped_count) = 'integer' AND dropped_count >= 0),
    imported_count INTEGER CHECK(imported_count IS NULL OR (imported_count >= 0 AND imported_count <= dropped_count)),
    legacy_retired_count INTEGER CHECK(legacy_retired_count IS NULL OR
        (typeof(legacy_retired_count) = 'integer' AND legacy_retired_count >= 0 AND legacy_retired_count <= imported_count)),
    PRIMARY KEY(account_label, cause, marker_token)
);

INSERT INTO account_recovery_obligations
    (demand_key, cause, account_label, marker_token, pending_since, dropped_count, created_at_ms, updated_at_ms)
SELECT 'overflow:' || account_label, 0, account_label, marker_token, pending_since, dropped_count,
       pending_since * 1000, pending_since * 1000 FROM account_delivery_recovery;
INSERT INTO account_delivery_loss_evidence
    (account_label, cause, marker_token, pending_since, dropped_count, imported_count)
SELECT account_label, 0, marker_token, pending_since, dropped_count, dropped_count
FROM account_delivery_recovery;
INSERT INTO account_recovery_obligations
    (demand_key, cause, group_id, stalled_epoch, created_at_ms, updated_at_ms)
SELECT 'epoch:' || lower(hex(group_id)), 1, group_id, stalled_epoch, updated_at * 1000, updated_at * 1000
FROM app_epoch_backfill_intents;
INSERT INTO account_recovery_scopes(obligation_id, scope_id, group_id)
SELECT id, 0, group_id FROM account_recovery_obligations;
DROP TABLE account_delivery_recovery;
DROP TABLE app_epoch_backfill_intents;
"#,
    )
    .storage()
}
