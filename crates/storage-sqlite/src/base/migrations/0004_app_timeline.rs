use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_events (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    source_message_id_hex TEXT,
    direction TEXT NOT NULL,
    sender TEXT NOT NULL,
    plaintext TEXT NOT NULL,
    kind INTEGER NOT NULL,
    tags_json TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    invalidated INTEGER NOT NULL DEFAULT 0,
    invalidation_reason TEXT,
    UNIQUE (group_id_hex, message_id_hex)
);
CREATE UNIQUE INDEX idx_app_events_source_message
    ON app_events (source_message_id_hex)
    WHERE source_message_id_hex IS NOT NULL;
CREATE INDEX idx_app_events_group_order
    ON app_events (group_id_hex, recorded_at, message_id_hex);

CREATE TABLE message_timeline (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    source_message_id_hex TEXT,
    direction TEXT NOT NULL,
    sender TEXT NOT NULL,
    plaintext TEXT NOT NULL,
    kind INTEGER NOT NULL,
    tags_json TEXT NOT NULL,
    timeline_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    reply_to_message_id_hex TEXT,
    media_json TEXT,
    agent_stream_json TEXT,
    reactions_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    deleted_by_message_id_hex TEXT,
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE INDEX idx_message_timeline_order
    ON message_timeline (group_id_hex, timeline_at, message_id_hex);
CREATE INDEX idx_message_timeline_search
    ON message_timeline (group_id_hex, plaintext COLLATE NOCASE);

CREATE TABLE agent_stream_starts (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    source_message_id_hex TEXT,
    sender TEXT NOT NULL,
    stream_id_hex TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE INDEX idx_agent_stream_starts_group_stream
    ON agent_stream_starts (group_id_hex, stream_id_hex, started_at, message_id_hex);
"#,
    )
    .storage()
}
