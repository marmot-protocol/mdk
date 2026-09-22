use crate::{SqliteResultExt, tags_from_json};
use cgka_traits::storage::StorageResult;
use cgka_traits::{EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_POLL_RESPONSE};
use rusqlite::{Transaction, params};

/// Backfill normalized target edges for poll responses that older versions
/// retained as unknown custom events, and remove their obsolete derived
/// timeline bubbles. New responses are indexed and hidden on ingest.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    let mut stmt = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, sender, recorded_at, tags_json
             FROM app_events WHERE kind = ?1",
        )
        .storage()?;
    let responses = stmt
        .query_map(
            params![i64::try_from(MARMOT_APP_EVENT_KIND_POLL_RESPONSE).unwrap_or_default()],
            |row| {
                let tags = tags_from_json(row.get::<_, String>(4)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    tags,
                ))
            },
        )
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    drop(stmt);

    for (group, message, sender, recorded_at, tags) in responses {
        for target in tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|name| name == EVENT_REF_TAG))
            .filter_map(|tag| tag.get(1))
        {
            tx.execute(
                "INSERT OR IGNORE INTO message_modifier_edges (
                    group_id_hex, modifier_message_id_hex, target_message_id_hex,
                    kind, sender, recorded_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    group,
                    message,
                    target,
                    i64::try_from(MARMOT_APP_EVENT_KIND_POLL_RESPONSE).unwrap_or_default(),
                    sender,
                    recorded_at,
                ],
            )
            .storage()?;
        }
    }
    // Before kind 1018 became a hidden poll modifier, older builds projected it
    // as an unknown custom-event bubble. Keep the source event, but remove that
    // obsolete derived row so upgraded timelines agree with fresh projection.
    tx.execute(
        "DELETE FROM message_timeline WHERE kind = ?1",
        params![i64::try_from(MARMOT_APP_EVENT_KIND_POLL_RESPONSE).unwrap_or_default()],
    )
    .storage()?;
    Ok(())
}
