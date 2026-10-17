use crate::{SqliteResultExt, tags_from_json};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
};
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE message_modifier_edges (
    group_id_hex TEXT NOT NULL,
    modifier_message_id_hex TEXT NOT NULL,
    target_message_id_hex TEXT NOT NULL,
    kind INTEGER NOT NULL,
    sender TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, modifier_message_id_hex, target_message_id_hex),
    FOREIGN KEY (group_id_hex, modifier_message_id_hex)
        REFERENCES app_events (group_id_hex, message_id_hex) ON DELETE CASCADE
);
CREATE INDEX idx_modifier_edges_target
    ON message_modifier_edges (group_id_hex, target_message_id_hex, kind, recorded_at, modifier_message_id_hex);
"#,
    )
    .storage()?;

    backfill_edges(tx)
}

/// Seed `message_modifier_edges` from existing REACTION/DELETE rows so a
/// database upgraded into this migration immediately serves modifier lookups
/// from the indexed edge table instead of the legacy JSON `LIKE` scan. One edge
/// row is emitted per `EVENT_REF_TAG` ("e") value on each modifier event,
/// matching the relationship the lookup helpers used to recompute in Rust.
fn backfill_edges(tx: &Transaction<'_>) -> StorageResult<()> {
    let mut stmt = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, kind, sender, recorded_at, tags_json
             FROM app_events
             WHERE kind IN (?1, ?2)",
        )
        .storage()?;
    let modifiers = stmt
        .query_map(
            params![
                i64::try_from(MARMOT_APP_EVENT_KIND_REACTION).unwrap_or_default(),
                i64::try_from(MARMOT_APP_EVENT_KIND_DELETE).unwrap_or_default(),
            ],
            |row| {
                let tags = tags_from_json(row.get::<_, String>(5)?).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?;
                Ok(BackfillModifier {
                    group_id_hex: row.get(0)?,
                    message_id_hex: row.get(1)?,
                    kind: row.get(2)?,
                    sender: row.get(3)?,
                    recorded_at: row.get(4)?,
                    tags,
                })
            },
        )
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    drop(stmt);

    for modifier in modifiers {
        for target in modifier
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|name| name == EVENT_REF_TAG))
            .filter_map(|tag| tag.get(1))
        {
            tx.execute(
                "INSERT OR IGNORE INTO message_modifier_edges (
                    group_id_hex, modifier_message_id_hex, target_message_id_hex,
                    kind, sender, recorded_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    modifier.group_id_hex,
                    modifier.message_id_hex,
                    target,
                    modifier.kind,
                    modifier.sender,
                    modifier.recorded_at,
                ],
            )
            .storage()?;
        }
    }
    Ok(())
}

struct BackfillModifier {
    group_id_hex: String,
    message_id_hex: String,
    kind: i64,
    sender: String,
    recorded_at: i64,
    tags: Vec<Vec<String>>,
}
