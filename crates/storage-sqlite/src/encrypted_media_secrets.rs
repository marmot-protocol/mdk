use std::collections::BTreeSet;

use crate::{
    SqliteAccountStorage, SqliteResultExt, StoredAppEvent, u64_to_i64, unix_now_seconds_i64,
};
use cgka_traits::app_components::{
    ENCRYPTED_MEDIA_FORMAT_V1, ENCRYPTED_MEDIA_FORMAT_V2, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};

impl SqliteAccountStorage {
    pub fn remember_encrypted_media_epoch_secret(
        &self,
        group_id_hex: &str,
        component_id: u16,
        source_epoch: u64,
        secret: &[u8],
    ) -> StorageResult<()> {
        if group_id_hex.trim().is_empty() {
            return Err(StorageError::Backend(
                "encrypted media secret group id must not be empty".to_owned(),
            ));
        }
        if secret.is_empty() {
            return Err(StorageError::Backend(
                "encrypted media secret must not be empty".to_owned(),
            ));
        }
        self.lock()?
            .execute(
                r#"
INSERT INTO encrypted_media_epoch_secrets (
    group_id_hex,
    component_id,
    source_epoch,
    secret,
    created_at_unix_seconds,
    retention_managed
)
SELECT
    ?1, ?2, ?3, ?4, ?5,
    EXISTS (
        SELECT 1
        FROM encrypted_media_epoch_secret_references
        WHERE group_id_hex = ?1
          AND source_epoch = ?3
    )
WHERE NOT EXISTS (
    SELECT 1
    FROM encrypted_media_epoch_secret_retirement_watermarks
    WHERE group_id_hex = ?1
      AND retired_through_epoch >= ?3
) OR EXISTS (
    SELECT 1
    FROM encrypted_media_epoch_secret_references
    WHERE group_id_hex = ?1
      AND source_epoch = ?3
)
ON CONFLICT(group_id_hex, component_id, source_epoch) DO UPDATE SET
    secret = excluded.secret,
    created_at_unix_seconds = excluded.created_at_unix_seconds,
    retention_managed = CASE
        WHEN excluded.retention_managed = 1 THEN 1
        ELSE encrypted_media_epoch_secrets.retention_managed
    END
WHERE excluded.retention_managed = 1
   OR NOT EXISTS (
       SELECT 1
       FROM encrypted_media_epoch_secret_retirement_watermarks
       WHERE group_id_hex = excluded.group_id_hex
         AND retired_through_epoch >= excluded.source_epoch
   )
"#,
                params![
                    group_id_hex,
                    i64::from(component_id),
                    u64_to_i64(source_epoch)?,
                    secret,
                    unix_now_seconds_i64(),
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn encrypted_media_epoch_secret(
        &self,
        group_id_hex: &str,
        component_id: u16,
        source_epoch: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        self.lock()?
            .query_row(
                r#"
SELECT secret
FROM encrypted_media_epoch_secrets
WHERE group_id_hex = ?1
  AND component_id = ?2
  AND source_epoch = ?3
  AND (
      EXISTS (
          SELECT 1
          FROM encrypted_media_epoch_secret_references AS refs
          WHERE refs.group_id_hex = encrypted_media_epoch_secrets.group_id_hex
            AND refs.source_epoch = encrypted_media_epoch_secrets.source_epoch
      )
      OR NOT EXISTS (
          SELECT 1
          FROM encrypted_media_epoch_secret_retirement_watermarks AS watermarks
          WHERE watermarks.group_id_hex = encrypted_media_epoch_secrets.group_id_hex
            AND watermarks.retired_through_epoch >= encrypted_media_epoch_secrets.source_epoch
      )
  )
"#,
                params![
                    group_id_hex,
                    i64::from(component_id),
                    u64_to_i64(source_epoch)?
                ],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }

    /// Whether the epoch secret may be returned to a media caller. Epochs that
    /// have never been retired remain usable for freshly uploaded, not-yet-sent
    /// media. Once the final retained reference retires an epoch, only a new
    /// durable reference can make that epoch usable again.
    pub fn encrypted_media_epoch_secret_may_be_served(
        &self,
        group_id_hex: &str,
        source_epoch: u64,
    ) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT
                     EXISTS (
                         SELECT 1
                         FROM encrypted_media_epoch_secret_references
                         WHERE group_id_hex = ?1
                           AND source_epoch = ?2
                     )
                     OR NOT EXISTS (
                         SELECT 1
                         FROM encrypted_media_epoch_secret_retirement_watermarks
                         WHERE group_id_hex = ?1
                           AND retired_through_epoch >= ?2
                     )",
                params![group_id_hex, u64_to_i64(source_epoch)?],
                |row| row.get::<_, i64>(0),
            )
            .storage()?
            != 0)
    }
}

pub(crate) fn encrypted_media_component_ids(tags: &[Vec<String>]) -> BTreeSet<u16> {
    let mut component_ids = BTreeSet::new();
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "imeta"))
    {
        for field in tag.iter().skip(1) {
            match field.strip_prefix("v ") {
                Some(ENCRYPTED_MEDIA_FORMAT_V1) => {
                    component_ids.insert(GROUP_ENCRYPTED_MEDIA_COMPONENT_ID);
                }
                Some(ENCRYPTED_MEDIA_FORMAT_V2) => {
                    component_ids.insert(GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID);
                }
                _ => {}
            }
        }
    }
    component_ids
}

/// Replace one retained message's versioned media-secret references. This runs
/// inside the same transaction as the owning `app_events` upsert, so a restart
/// observes either the old event/reference set or the new one, never a torn mix.
pub(crate) fn replace_encrypted_media_secret_references_tx(
    tx: &Connection,
    event: &StoredAppEvent,
) -> StorageResult<()> {
    let retiring_epochs = encrypted_media_secret_reference_epochs_for_message_tx(
        tx,
        &event.group_id_hex,
        &event.message_id_hex,
    )?;
    tx.execute(
        "DELETE FROM encrypted_media_epoch_secret_references
         WHERE group_id_hex = ?1 AND message_id_hex = ?2",
        params![&event.group_id_hex, &event.message_id_hex],
    )
    .storage()?;

    if let Some(source_epoch) = event.source_epoch {
        let source_epoch = u64_to_i64(source_epoch)?;
        for component_id in encrypted_media_component_ids(&event.tags) {
            tx.execute(
                "INSERT INTO encrypted_media_epoch_secret_references (
                     group_id_hex, message_id_hex, component_id, source_epoch
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    &event.group_id_hex,
                    &event.message_id_hex,
                    i64::from(component_id),
                    source_epoch,
                ],
            )
            .storage()?;
            tx.execute(
                "UPDATE encrypted_media_epoch_secrets
                 SET retention_managed = 1
                 WHERE group_id_hex = ?1
                   AND source_epoch = ?2",
                params![&event.group_id_hex, source_epoch],
            )
            .storage()?;
        }
    }

    retire_unreferenced_encrypted_media_secret_epochs_tx(
        tx,
        &event.group_id_hex,
        &retiring_epochs,
    )?;
    Ok(())
}

fn encrypted_media_secret_reference_epochs_for_message_tx(
    tx: &Connection,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<BTreeSet<i64>> {
    let mut statement = tx
        .prepare(
            "SELECT DISTINCT source_epoch
             FROM encrypted_media_epoch_secret_references
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
        )
        .storage()?;
    statement
        .query_map(params![group_id_hex, message_id_hex], |row| row.get(0))
        .storage()?
        .collect::<Result<BTreeSet<_>, _>>()
        .storage()
}

/// Retire candidate exporter epochs that no retained V1 or V2 message still
/// references. The retirement watermark is independent of key-row existence,
/// so a later cache hydration cannot resurrect an epoch pruned before its key
/// was ever persisted. V1 and V2 share the same MLS exporter value; their
/// references therefore protect every cached component row for the epoch.
pub(crate) fn retire_unreferenced_encrypted_media_secret_epochs_tx(
    tx: &Connection,
    group_id_hex: &str,
    candidate_epochs: &BTreeSet<i64>,
) -> StorageResult<usize> {
    let mut deleted = 0usize;
    for source_epoch in candidate_epochs {
        let referenced = tx
            .query_row(
                "SELECT EXISTS (
                     SELECT 1
                     FROM encrypted_media_epoch_secret_references
                     WHERE group_id_hex = ?1 AND source_epoch = ?2
                 )",
                params![group_id_hex, source_epoch],
                |row| row.get::<_, i64>(0),
            )
            .storage()?
            != 0;
        if referenced {
            continue;
        }

        tx.execute(
            "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks (
                 group_id_hex, retired_through_epoch, retired_at_unix_seconds
             ) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                 retired_through_epoch = max(
                     encrypted_media_epoch_secret_retirement_watermarks.retired_through_epoch,
                     excluded.retired_through_epoch
                 ),
                 retired_at_unix_seconds = excluded.retired_at_unix_seconds",
            params![group_id_hex, source_epoch, unix_now_seconds_i64()],
        )
        .storage()?;
        tx.execute(
            "UPDATE encrypted_media_epoch_secrets
             SET secret = zeroblob(length(secret))
             WHERE retention_managed = 1
               AND group_id_hex = ?1
               AND source_epoch = ?2",
            params![group_id_hex, source_epoch],
        )
        .storage()?;
        deleted = deleted.saturating_add(
            tx.execute(
                "DELETE FROM encrypted_media_epoch_secrets
                 WHERE retention_managed = 1
                   AND group_id_hex = ?1
                   AND source_epoch = ?2",
                params![group_id_hex, source_epoch],
            )
            .storage()?,
        );
    }
    Ok(deleted)
}

/// Securely wipe every cached exporter value for a locally deleted group and
/// leave a group-wide barrier. MLS state intentionally survives local app-data
/// deletion, so the barrier prevents that retained state from immediately
/// rehydrating wiped epochs; a newly retained media reference still authorizes
/// its exact source epoch.
pub(crate) fn retire_all_encrypted_media_secrets_for_group_tx(
    tx: &Connection,
    group_id_hex: &str,
) -> StorageResult<usize> {
    let has_group_data = tx
        .query_row(
            "SELECT
                 EXISTS (SELECT 1 FROM account_groups WHERE group_id_hex = ?1)
                 OR EXISTS (SELECT 1 FROM app_events WHERE group_id_hex = ?1)
                 OR EXISTS (
                     SELECT 1 FROM encrypted_media_epoch_secrets WHERE group_id_hex = ?1
                 )
                 OR EXISTS (
                     SELECT 1 FROM encrypted_media_epoch_secret_references
                     WHERE group_id_hex = ?1
                 )",
            params![group_id_hex],
            |row| row.get::<_, i64>(0),
        )
        .storage()?
        != 0;
    if !has_group_data {
        return Ok(0);
    }

    tx.execute(
        "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks (
             group_id_hex, retired_through_epoch, retired_at_unix_seconds
         ) VALUES (?1, ?2, ?3)
         ON CONFLICT(group_id_hex) DO UPDATE SET
             retired_through_epoch = excluded.retired_through_epoch,
             retired_at_unix_seconds = excluded.retired_at_unix_seconds",
        params![group_id_hex, i64::MAX, unix_now_seconds_i64()],
    )
    .storage()?;
    tx.execute(
        "UPDATE encrypted_media_epoch_secrets
         SET secret = zeroblob(length(secret))
         WHERE group_id_hex = ?1",
        params![group_id_hex],
    )
    .storage()?;
    tx.execute(
        "DELETE FROM encrypted_media_epoch_secrets WHERE group_id_hex = ?1",
        params![group_id_hex],
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StoredAppEvent;
    use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;

    fn media_event(id: &str, recorded_at: u64, source_epoch: u64) -> StoredAppEvent {
        media_event_with_versions(id, recorded_at, source_epoch, &[ENCRYPTED_MEDIA_FORMAT_V1])
    }

    fn media_event_with_versions(
        id: &str,
        recorded_at: u64,
        source_epoch: u64,
        versions: &[&str],
    ) -> StoredAppEvent {
        StoredAppEvent {
            group_id_hex: "aa".to_owned(),
            message_id_hex: id.to_owned(),
            source_message_id_hex: Some(format!("source-{id}")),
            source_epoch: Some(source_epoch),
            direction: "received".to_owned(),
            sender: "sender".to_owned(),
            plaintext: String::new(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: versions
                .iter()
                .map(|version| {
                    vec![
                        "imeta".to_owned(),
                        format!("v {version}"),
                        format!("ciphertext_sha256 {}", "ab".repeat(32)),
                    ]
                })
                .collect(),
            recorded_at,
            received_at: recorded_at,
            origin_commit_id: None,
            moderation_grant: false,
        }
    }

    fn secret_is_referenced(
        store: &SqliteAccountStorage,
        group_id_hex: &str,
        component_id: u16,
        source_epoch: u64,
    ) -> bool {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS (
                     SELECT 1
                     FROM encrypted_media_epoch_secret_references
                     WHERE group_id_hex = ?1
                       AND component_id = ?2
                       AND source_epoch = ?3
                 )",
                params![
                    group_id_hex,
                    i64::from(component_id),
                    u64_to_i64(source_epoch).unwrap()
                ],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            != 0
    }

    #[test]
    fn encrypted_media_epoch_secret_round_trips_and_replaces() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group_id_hex = "aa";
        store
            .record_app_event(&media_event("retained", 10, 7))
            .unwrap();
        assert_eq!(
            store
                .encrypted_media_epoch_secret(group_id_hex, 0x8008, 7)
                .unwrap(),
            None
        );

        store
            .remember_encrypted_media_epoch_secret(group_id_hex, 0x8008, 7, &[1, 2, 3])
            .unwrap();
        assert_eq!(
            store
                .encrypted_media_epoch_secret(group_id_hex, 0x8008, 7)
                .unwrap(),
            Some(vec![1, 2, 3])
        );

        store
            .remember_encrypted_media_epoch_secret(group_id_hex, 0x8008, 7, &[4, 5, 6])
            .unwrap();
        assert_eq!(
            store
                .encrypted_media_epoch_secret(group_id_hex, 0x8008, 7)
                .unwrap(),
            Some(vec![4, 5, 6])
        );
    }

    #[test]
    fn unreferenced_non_retired_cached_secret_can_be_served() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();

        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            Some(vec![1, 2, 3])
        );
        let durable_rows: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM encrypted_media_epoch_secrets",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            durable_rows, 1,
            "pre-cached secrets remain for delayed messages"
        );
    }

    #[test]
    fn final_retained_media_message_prune_deletes_its_epoch_secret() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        store.record_app_event(&media_event("old", 10, 7)).unwrap();

        let outcome = store.secure_prune_app_events_before("aa", 11).unwrap();
        assert_eq!(outcome.pruned_messages, 1);
        assert_eq!(outcome.pruned_media_epoch_secrets, 1);
        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            None
        );
    }

    #[test]
    fn duplicate_attachments_create_one_epoch_secret_reference() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        let duplicate = media_event_with_versions(
            "duplicate",
            10,
            7,
            &[ENCRYPTED_MEDIA_FORMAT_V1, ENCRYPTED_MEDIA_FORMAT_V1],
        );

        store.record_app_event(&duplicate).unwrap();

        let references: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM encrypted_media_epoch_secret_references
                 WHERE group_id_hex = 'aa' AND message_id_hex = 'duplicate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(references, 1);
    }

    #[test]
    fn shared_epoch_secret_survives_partial_sweep_until_final_reference() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        store.record_app_event(&media_event("old", 10, 7)).unwrap();
        store.record_app_event(&media_event("new", 20, 7)).unwrap();

        let partial = store.secure_prune_app_events_before("aa", 15).unwrap();
        assert_eq!(partial.pruned_messages, 1);
        assert_eq!(partial.pruned_media_epoch_secrets, 0);
        assert!(secret_is_referenced(&store, "aa", 0x8008, 7));
        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            Some(vec![1, 2, 3])
        );

        let final_sweep = store.secure_prune_app_events_before("aa", 21).unwrap();
        assert_eq!(final_sweep.pruned_messages, 1);
        assert_eq!(final_sweep.pruned_media_epoch_secrets, 1);
        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            None
        );
    }

    #[test]
    fn media_v2_reference_is_tracked_under_its_distinct_component_id() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret(
                "aa",
                GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
                7,
                &[4, 5, 6],
            )
            .unwrap();
        store
            .record_app_event(&media_event_with_versions(
                "v2",
                10,
                7,
                &[ENCRYPTED_MEDIA_FORMAT_V2],
            ))
            .unwrap();

        assert!(secret_is_referenced(
            &store,
            "aa",
            GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
            7,
        ));
        assert!(!secret_is_referenced(
            &store,
            "aa",
            GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
            7,
        ));
        let outcome = store.secure_prune_app_events_before("aa", 11).unwrap();
        assert_eq!(outcome.pruned_media_epoch_secrets, 1);
        assert_eq!(
            store
                .encrypted_media_epoch_secret("aa", GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID, 7,)
                .unwrap(),
            None
        );
    }

    #[test]
    fn retired_secret_cannot_be_rehydrated_without_a_new_retained_reference() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        store.record_app_event(&media_event("old", 10, 7)).unwrap();
        store.secure_prune_app_events_before("aa", 11).unwrap();

        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[9, 9, 9])
            .unwrap();
        assert!(
            !store
                .encrypted_media_epoch_secret_may_be_served("aa", 7)
                .unwrap()
        );
        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            None,
            "eager current-epoch caching must not resurrect a retired secret"
        );

        store.record_app_event(&media_event("late", 20, 7)).unwrap();
        assert!(
            store
                .encrypted_media_epoch_secret_may_be_served("aa", 7)
                .unwrap()
        );
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[9, 9, 9])
            .unwrap();
        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            Some(vec![9, 9, 9]),
            "a newly retained sibling makes the source epoch usable again"
        );
    }

    #[test]
    fn retirement_watermark_is_bounded_and_advances_monotonically() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        store
            .record_app_event(&media_event("seven", 10, 7))
            .unwrap();
        store.secure_prune_app_events_before("aa", 11).unwrap();

        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 6, &[6])
            .unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 8, &[8])
            .unwrap();
        let durable_epochs = |store: &SqliteAccountStorage| {
            let conn = store.lock().unwrap();
            let mut statement = conn
                .prepare(
                    "SELECT source_epoch FROM encrypted_media_epoch_secrets
                     ORDER BY source_epoch",
                )
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(durable_epochs(&store), vec![8]);

        store
            .record_app_event(&media_event("eight", 20, 8))
            .unwrap();
        store.secure_prune_app_events_before("aa", 21).unwrap();
        let watermark: (i64, i64) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*), max(retired_through_epoch)
                 FROM encrypted_media_epoch_secret_retirement_watermarks",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(watermark, (1, 8));
    }

    #[test]
    fn retired_secret_stays_unavailable_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("media-retirement.sqlite");
        let store = SqliteAccountStorage::from_connection_with_options(
            rusqlite::Connection::open(&path).unwrap(),
            crate::SqliteStorageOptions::default(),
        )
        .unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        store.record_app_event(&media_event("old", 10, 7)).unwrap();
        store.secure_prune_app_events_before("aa", 11).unwrap();
        drop(store);

        let reopened = SqliteAccountStorage::from_connection_with_options(
            rusqlite::Connection::open(&path).unwrap(),
            crate::SqliteStorageOptions::default(),
        )
        .unwrap();
        reopened
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[9, 9, 9])
            .unwrap();
        assert_eq!(
            reopened
                .encrypted_media_epoch_secret("aa", 0x8008, 7)
                .unwrap(),
            None
        );
    }

    #[test]
    fn reference_without_cached_secret_still_retires_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("media-reference-only-retirement.sqlite");
        let store = SqliteAccountStorage::from_connection_with_options(
            rusqlite::Connection::open(&path).unwrap(),
            crate::SqliteStorageOptions::default(),
        )
        .unwrap();
        store
            .record_app_event(&media_event("reference-only", 10, 7))
            .unwrap();
        store.secure_prune_app_events_before("aa", 11).unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            None,
            "retirement must not depend on a key row existing at prune time"
        );
        drop(store);

        let reopened = SqliteAccountStorage::from_connection_with_options(
            rusqlite::Connection::open(&path).unwrap(),
            crate::SqliteStorageOptions::default(),
        )
        .unwrap();
        reopened
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[4, 5, 6])
            .unwrap();
        assert_eq!(
            reopened
                .encrypted_media_epoch_secret("aa", 0x8008, 7)
                .unwrap(),
            None
        );
    }

    #[test]
    fn v1_and_v2_references_share_one_exporter_secret_lifetime() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret(
                "aa",
                GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
                7,
                &[1, 2, 3],
            )
            .unwrap();
        store
            .record_app_event(&media_event_with_versions(
                "v1-old",
                10,
                7,
                &[ENCRYPTED_MEDIA_FORMAT_V1],
            ))
            .unwrap();
        store
            .record_app_event(&media_event_with_versions(
                "v2-new",
                20,
                7,
                &[ENCRYPTED_MEDIA_FORMAT_V2],
            ))
            .unwrap();

        let partial = store.secure_prune_app_events_before("aa", 15).unwrap();
        assert_eq!(partial.pruned_messages, 1);
        assert_eq!(partial.pruned_media_epoch_secrets, 0);
        assert_eq!(
            store
                .encrypted_media_epoch_secret("aa", GROUP_ENCRYPTED_MEDIA_COMPONENT_ID, 7)
                .unwrap(),
            Some(vec![1, 2, 3]),
            "a retained V2 sibling needs the same source-epoch exporter secret"
        );

        let final_sweep = store.secure_prune_app_events_before("aa", 21).unwrap();
        assert_eq!(final_sweep.pruned_messages, 1);
        assert_eq!(final_sweep.pruned_media_epoch_secrets, 1);
        assert_eq!(
            store
                .encrypted_media_epoch_secret("aa", GROUP_ENCRYPTED_MEDIA_COMPONENT_ID, 7)
                .unwrap(),
            None
        );
    }

    #[test]
    fn prune_failure_rolls_back_message_reference_secret_and_retirement() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .remember_encrypted_media_epoch_secret("aa", 0x8008, 7, &[1, 2, 3])
            .unwrap();
        store.record_app_event(&media_event("old", 10, 7)).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER abort_media_secret_delete
                 BEFORE DELETE ON encrypted_media_epoch_secrets
                 BEGIN
                    SELECT RAISE(ABORT, 'abort media secret delete');
                 END;",
            )
            .unwrap();

        let error = store
            .secure_prune_app_events_before("aa", 11)
            .expect_err("secret-delete failure must abort the whole prune");
        assert!(format!("{error}").contains("abort media secret delete"));
        assert_eq!(store.app_message_count().unwrap(), 1);
        assert!(secret_is_referenced(&store, "aa", 0x8008, 7));
        assert_eq!(
            store.encrypted_media_epoch_secret("aa", 0x8008, 7).unwrap(),
            Some(vec![1, 2, 3])
        );
        let retirement_watermarks: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM encrypted_media_epoch_secret_retirement_watermarks",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retirement_watermarks, 0);
    }
}
