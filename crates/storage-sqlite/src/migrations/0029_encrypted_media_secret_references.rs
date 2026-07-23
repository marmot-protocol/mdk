use crate::{
    SqliteResultExt, encrypted_media_secrets::encrypted_media_component_ids, tags_from_json,
};
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE encrypted_media_epoch_secrets
    ADD COLUMN retention_managed INTEGER NOT NULL DEFAULT 0;

CREATE TABLE encrypted_media_epoch_secret_references (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    component_id INTEGER NOT NULL,
    source_epoch INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex, component_id, source_epoch),
    FOREIGN KEY (group_id_hex, message_id_hex)
        REFERENCES app_events (group_id_hex, message_id_hex) ON DELETE CASCADE
);
CREATE INDEX idx_media_secret_references_secret
    ON encrypted_media_epoch_secret_references (
        group_id_hex, source_epoch, component_id, message_id_hex
    );

-- A bounded retirement watermark prevents eager current-epoch caching from
-- rehydrating key bytes after the final retained source-message reference was
-- deleted. Rows are metadata only; they contain no key material.
CREATE TABLE encrypted_media_epoch_secret_retirement_watermarks (
    group_id_hex TEXT PRIMARY KEY,
    retired_through_epoch INTEGER NOT NULL CHECK(retired_through_epoch >= 0),
    retired_at_unix_seconds INTEGER NOT NULL CHECK(retired_at_unix_seconds >= 0)
) WITHOUT ROWID;
"#,
    )
    .storage()?;

    backfill_references(tx)?;
    tx.execute(
        "UPDATE encrypted_media_epoch_secrets AS secrets
         SET retention_managed = 1
         WHERE EXISTS (
             SELECT 1
             FROM encrypted_media_epoch_secret_references AS refs
             WHERE refs.group_id_hex = secrets.group_id_hex
               AND refs.source_epoch = secrets.source_epoch
         )",
        [],
    )
    .storage()?;
    Ok(())
}

/// Backfill only references that can be proved from retained app-event rows.
/// Existing secrets without a recoverable retained reference deliberately keep
/// `retention_managed = 0`: a migration cannot distinguish stale material from a
/// secret cached in advance for delayed source-epoch delivery, so later message
/// sweeps must not guess destructively.
fn backfill_references(tx: &Transaction<'_>) -> StorageResult<()> {
    let mut statement = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, source_epoch, tags_json
             FROM app_events
             WHERE source_epoch IS NOT NULL",
        )
        .storage()?;
    let events = statement
        .query_map([], |row| {
            let tags = tags_from_json(row.get::<_, String>(3)?).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                tags,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    drop(statement);

    for (group_id_hex, message_id_hex, source_epoch, tags) in events {
        for component_id in encrypted_media_component_ids(&tags) {
            tx.execute(
                "INSERT OR IGNORE INTO encrypted_media_epoch_secret_references (
                     group_id_hex, message_id_hex, component_id, source_epoch
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    group_id_hex,
                    message_id_hex,
                    i64::from(component_id),
                    source_epoch,
                ],
            )
            .storage()?;
        }
    }
    Ok(())
}
