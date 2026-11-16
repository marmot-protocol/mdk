//! Frozen schema-211 encrypted-media references for retained NIP-34 issues.
//!
//! Before 211, a kind-1621 issue's attachments recorded no source-epoch
//! reference, so pruning its epoch's chat messages retired the secret it still
//! needs (mdk#3410). A backfilled reference makes a retired epoch servable and
//! storable again; a secret already erased must be exported anew.
use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params, types::ValueRef};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    let mut issues = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, source_epoch, tags_json
             FROM app_events
             WHERE kind = 1621 AND source_epoch >= 0",
        )
        .storage()?;
    let mut rows = issues.query([]).storage()?;
    while let Some(row) = rows.next().storage()? {
        // Damaged tags decode as empty in the runtime and own no media.
        let tags: Option<Vec<Vec<String>>> = match row.get_ref(3).storage()? {
            ValueRef::Text(bytes) => serde_json::from_slice(bytes).ok(),
            _ => None,
        };
        let Some(tags) = tags else {
            continue;
        };
        let group: String = row.get(0).storage()?;
        let message: String = row.get(1).storage()?;
        let epoch: i64 = row.get(2).storage()?;
        backfill_media_references(tx, &group, &message, epoch, &tags)?;
    }
    Ok(())
}

fn backfill_media_references(
    tx: &Transaction<'_>,
    group: &str,
    message: &str,
    epoch: i64,
    tags: &[Vec<String>],
) -> StorageResult<()> {
    // Version strings and component ids are part of schema 211, not the
    // evolving live parser. An imeta with several version fields is invalid.
    let mut components = [false; 2];
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "imeta"))
    {
        let mut versions = tag
            .iter()
            .skip(1)
            .filter_map(|field| field.strip_prefix("v "));
        let (Some(version), None) = (versions.next(), versions.next()) else {
            continue;
        };
        match version {
            "encrypted-media-v1" => components[0] = true,
            "encrypted-media-v2" => components[1] = true,
            _ => {}
        }
    }
    if !components.contains(&true) {
        return Ok(());
    }

    for (present, component) in components.into_iter().zip([0x8008, 0x800b]) {
        if present {
            tx.execute_cached(
                "INSERT OR IGNORE INTO encrypted_media_epoch_secret_references
                     (group_id_hex, message_id_hex, component_id, source_epoch)
                 VALUES (?1, ?2, ?3, ?4)",
                params![group, message, component, epoch],
            )
            .storage()?;
        }
    }
    // Both formats share the exporter: every cached component for the epoch
    // becomes retention-managed, as on a new app-event write.
    tx.execute_cached(
        "UPDATE encrypted_media_epoch_secrets SET retention_managed = 1
         WHERE group_id_hex = ?1 AND source_epoch = ?2 AND retention_managed = 0",
        params![group, epoch],
    )
    .storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn issue_media_references_backfill() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 210).unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('11', 'fixture', 0);
            INSERT INTO app_events(group_id_hex, message_id_hex, direction, sender, plaintext, kind, tags_json, source_epoch, recorded_at, received_at)
            VALUES ('11','v1','received','alice','issue',1621,'[["imeta","v encrypted-media-v1"]]',7,1,1),
                   ('11','v2','received','alice','issue',1621,'[["imeta","v encrypted-media-v2"],["imeta","v encrypted-media-v2"]]',8,1,1),
                   ('11','mixed','received','alice','issue',1621,'[["imeta","v encrypted-media-v1","v encrypted-media-v2"]]',9,1,1),
                   ('11','plain','received','alice','issue',1621,'[["imeta","url plain"]]',9,1,1),
                   ('11','no-epoch','received','alice','issue',1621,'[["imeta","v encrypted-media-v1"]]',NULL,1,1),
                   ('11','damaged','received','alice','issue',1621,x'ff',9,1,1),
                   ('11','custom','received','alice','custom',9000,'[["imeta","v encrypted-media-v1"]]',9,1,1);
            INSERT INTO encrypted_media_epoch_secrets(group_id_hex, component_id, source_epoch, secret, created_at_unix_seconds, retention_managed)
            VALUES ('11', 32776, 7, x'01', 0, 0),
                   ('11', 32779, 7, x'02', 0, 0),
                   ('11', 32776, 9, x'03', 0, 0);
            "#,
        )
        .unwrap();

        run_through(&mut conn, 211).unwrap();

        let mut statement = conn
            .prepare(
                "SELECT message_id_hex, component_id, source_epoch
                 FROM encrypted_media_epoch_secret_references ORDER BY message_id_hex",
            )
            .unwrap();
        let references: Vec<(String, i64, i64)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            references,
            vec![("v1".into(), 0x8008, 7), ("v2".into(), 0x800b, 8)]
        );
        let managed: Vec<(i64, i64, bool)> = conn
            .prepare(
                "SELECT component_id, source_epoch, retention_managed
                 FROM encrypted_media_epoch_secrets ORDER BY source_epoch, component_id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            managed,
            vec![(0x8008, 7, true), (0x800b, 7, true), (0x8008, 9, false)]
        );
    }
}
