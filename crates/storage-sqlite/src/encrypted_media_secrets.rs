use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64, unix_now_seconds_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

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
    created_at_unix_seconds
) VALUES (?1, ?2, ?3, ?4, ?5)
ON CONFLICT(group_id_hex, component_id, source_epoch) DO UPDATE SET
    secret = excluded.secret,
    created_at_unix_seconds = excluded.created_at_unix_seconds
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_media_epoch_secret_round_trips_and_replaces() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group_id_hex = "ab".repeat(32);
        assert_eq!(
            store
                .encrypted_media_epoch_secret(&group_id_hex, 0x8008, 7)
                .unwrap(),
            None
        );

        store
            .remember_encrypted_media_epoch_secret(&group_id_hex, 0x8008, 7, &[1, 2, 3])
            .unwrap();
        assert_eq!(
            store
                .encrypted_media_epoch_secret(&group_id_hex, 0x8008, 7)
                .unwrap(),
            Some(vec![1, 2, 3])
        );

        store
            .remember_encrypted_media_epoch_secret(&group_id_hex, 0x8008, 7, &[4, 5, 6])
            .unwrap();
        assert_eq!(
            store
                .encrypted_media_epoch_secret(&group_id_hex, 0x8008, 7)
                .unwrap(),
            Some(vec![4, 5, 6])
        );
    }
}
