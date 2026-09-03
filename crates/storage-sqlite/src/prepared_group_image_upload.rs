use crate::connection::CachedSql;
use std::fmt;

use crate::{SqliteAccountStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

pub const MAX_ACTIVE_PREPARED_GROUP_IMAGE_UPLOADS: usize = 16;
pub const MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS: usize = 128;
pub const ACTIVE_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const CONSUMED_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedGroupImageUploadState {
    Staged,
    Uploaded,
    Failed,
    Consumed,
}

impl PreparedGroupImageUploadState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Uploaded => "uploaded",
            Self::Failed => "failed",
            Self::Consumed => "consumed",
        }
    }

    fn from_storage(value: &str) -> StorageResult<Self> {
        match value {
            "staged" => Ok(Self::Staged),
            "uploaded" => Ok(Self::Uploaded),
            "failed" => Ok(Self::Failed),
            "consumed" => Ok(Self::Consumed),
            _ => Err(StorageError::Serialization(format!(
                "invalid prepared group image upload state: {value}"
            ))),
        }
    }
}

/// SQLCipher-protected staged founding-image upload.
///
/// `component_data` contains the MLS-protected image component fields and
/// `upload_secret` is Blossom authorization key material. Keep both redacted
/// from diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedGroupImageUploadRecord {
    pub upload_id: String,
    pub state: PreparedGroupImageUploadState,
    pub component_data: Vec<u8>,
    pub encrypted_blob: Option<Vec<u8>>,
    pub upload_secret: Option<Vec<u8>>,
    pub group_id_hex: Option<String>,
    pub attempt_count: u32,
    pub last_error_kind: Option<String>,
    pub recorded_at: u64,
    pub updated_at: u64,
}

impl fmt::Debug for PreparedGroupImageUploadRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedGroupImageUploadRecord")
            .field("upload_id", &self.upload_id)
            .field("state", &self.state)
            .field("component_data_len", &self.component_data.len())
            .field(
                "encrypted_blob_len",
                &self.encrypted_blob.as_ref().map(Vec::len),
            )
            .field("has_upload_secret", &self.upload_secret.is_some())
            .field("has_group_id", &self.group_id_hex.is_some())
            .field("attempt_count", &self.attempt_count)
            .field("last_error_kind", &self.last_error_kind)
            .field("recorded_at", &self.recorded_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl SqliteAccountStorage {
    pub fn stage_prepared_group_image_upload(
        &self,
        record: &PreparedGroupImageUploadRecord,
    ) -> StorageResult<()> {
        if record.state != PreparedGroupImageUploadState::Staged
            || record.upload_id.is_empty()
            || record.component_data.is_empty()
            || record.group_id_hex.is_some()
            || !matches!(&record.encrypted_blob, Some(blob) if !blob.is_empty())
            || !matches!(&record.upload_secret, Some(secret) if secret.len() == 32)
            || record.attempt_count != 0
            || record.last_error_kind.is_some()
        {
            return Err(StorageError::Serialization(
                "new prepared group image upload must be an unbound staged record".into(),
            ));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let active_cutoff = record
            .updated_at
            .saturating_sub(ACTIVE_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS);
        let consumed_cutoff = record
            .updated_at
            .saturating_sub(CONSUMED_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS);
        tx.execute_cached(
            "DELETE FROM app_prepared_group_image_upload
             WHERE (state != 'consumed' AND updated_at < ?1)
                OR (state = 'consumed' AND updated_at < ?2)",
            params![u64_to_i64(active_cutoff)?, u64_to_i64(consumed_cutoff)?],
        )
        .storage()?;
        tx.execute_cached(
            "DELETE FROM app_prepared_group_image_upload
             WHERE upload_id IN (
                 SELECT upload_id FROM app_prepared_group_image_upload
                 WHERE state = 'consumed'
                 ORDER BY updated_at DESC, upload_id DESC
                 LIMIT -1 OFFSET ?1
             )",
            params![
                i64::try_from(MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS).map_err(|_| {
                    StorageError::Serialization("prepared image bound is invalid".into())
                })?
            ],
        )
        .storage()?;
        let active_count: i64 = tx
            .query_row_cached(
                "SELECT COUNT(*) FROM app_prepared_group_image_upload WHERE state != 'consumed'",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if usize::try_from(active_count).unwrap_or(usize::MAX)
            >= MAX_ACTIVE_PREPARED_GROUP_IMAGE_UPLOADS
        {
            return Err(StorageError::Backend(format!(
                "prepared group image upload capacity reached ({MAX_ACTIVE_PREPARED_GROUP_IMAGE_UPLOADS})"
            )));
        }
        tx.execute_cached(
            "INSERT INTO app_prepared_group_image_upload (
                    upload_id, state, component_data, encrypted_blob, upload_secret,
                    group_id_hex, attempt_count, last_error_kind, recorded_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0, NULL, ?6, ?7)",
            params![
                record.upload_id,
                record.state.as_str(),
                record.component_data,
                record.encrypted_blob,
                record.upload_secret,
                u64_to_i64(record.recorded_at)?,
                u64_to_i64(record.updated_at)?,
            ],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(())
    }

    pub fn prepared_group_image_upload(
        &self,
        upload_id: &str,
    ) -> StorageResult<Option<PreparedGroupImageUploadRecord>> {
        let conn = self.lock()?;
        conn.query_row_cached(
            "SELECT upload_id, state, component_data, encrypted_blob, upload_secret,
                    group_id_hex, attempt_count, last_error_kind, recorded_at, updated_at
             FROM app_prepared_group_image_upload
             WHERE upload_id = ?1",
            params![upload_id],
            prepared_group_image_upload_from_row,
        )
        .optional()
        .storage()?
        .map(try_from_raw_record)
        .transpose()
    }

    pub fn list_prepared_group_image_uploads(
        &self,
    ) -> StorageResult<Vec<PreparedGroupImageUploadRecord>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare_cached(
                "SELECT upload_id, state, component_data, encrypted_blob, upload_secret,
                        group_id_hex, attempt_count, last_error_kind, recorded_at, updated_at
                 FROM app_prepared_group_image_upload
                 ORDER BY recorded_at, upload_id",
            )
            .storage()?;
        let rows = statement
            .query_map([], prepared_group_image_upload_from_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(try_from_raw_record).collect()
    }

    pub fn mark_prepared_group_image_upload_uploaded(
        &self,
        upload_id: &str,
        updated_at: u64,
    ) -> StorageResult<()> {
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE app_prepared_group_image_upload
                 SET state = 'uploaded', attempt_count = attempt_count + 1,
                     last_error_kind = NULL, updated_at = ?2
                 WHERE upload_id = ?1 AND state IN ('staged', 'failed')",
                params![upload_id, u64_to_i64(updated_at)?],
            )
            .storage()?;
        if changed == 0 && self.prepared_group_image_upload(upload_id)?.is_none() {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn mark_prepared_group_image_upload_failed(
        &self,
        upload_id: &str,
        error_kind: &str,
        updated_at: u64,
    ) -> StorageResult<()> {
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE app_prepared_group_image_upload
                 SET state = 'failed', attempt_count = attempt_count + 1,
                     last_error_kind = ?2, updated_at = ?3
                 WHERE upload_id = ?1 AND state IN ('staged', 'failed')",
                params![upload_id, error_kind, u64_to_i64(updated_at)?],
            )
            .storage()?;
        if changed == 0 && self.prepared_group_image_upload(upload_id)?.is_none() {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn consume_prepared_group_image_upload(
        &self,
        upload_id: &str,
        group_id_hex: &str,
        updated_at: u64,
    ) -> StorageResult<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let changed = tx
            .execute_cached(
                "UPDATE app_prepared_group_image_upload
                 SET state = 'consumed', group_id_hex = ?2,
                     component_data = X'', encrypted_blob = NULL,
                     upload_secret = NULL, updated_at = ?3
                 WHERE upload_id = ?1 AND state = 'uploaded'",
                params![upload_id, group_id_hex, u64_to_i64(updated_at)?],
            )
            .storage()?;
        if changed == 0 {
            let raw = tx
                .query_row_cached(
                    "SELECT upload_id, state, component_data, encrypted_blob, upload_secret,
                            group_id_hex, attempt_count, last_error_kind, recorded_at, updated_at
                     FROM app_prepared_group_image_upload WHERE upload_id = ?1",
                    params![upload_id],
                    prepared_group_image_upload_from_row,
                )
                .optional()
                .storage()?
                .ok_or(StorageError::NotFound)?;
            let record = try_from_raw_record(raw)?;
            if record.state != PreparedGroupImageUploadState::Consumed
                || record.group_id_hex.as_deref() != Some(group_id_hex)
            {
                return Err(StorageError::Backend(
                    "prepared group image upload is not ready for consumption".into(),
                ));
            }
        }
        tx.execute_cached(
            "DELETE FROM app_prepared_group_image_upload
             WHERE upload_id IN (
                 SELECT upload_id FROM app_prepared_group_image_upload
                 WHERE state = 'consumed'
                 ORDER BY updated_at DESC, upload_id DESC
                 LIMIT -1 OFFSET ?1
             )",
            params![
                i64::try_from(MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS).map_err(|_| {
                    StorageError::Serialization("prepared image bound is invalid".into())
                })?
            ],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(())
    }
}

type RawPreparedGroupImageUpload = (
    String,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    i64,
    Option<String>,
    i64,
    i64,
);

fn prepared_group_image_upload_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RawPreparedGroupImageUpload> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn try_from_raw_record(
    raw: RawPreparedGroupImageUpload,
) -> StorageResult<PreparedGroupImageUploadRecord> {
    Ok(PreparedGroupImageUploadRecord {
        upload_id: raw.0,
        state: PreparedGroupImageUploadState::from_storage(&raw.1)?,
        component_data: raw.2,
        encrypted_blob: raw.3,
        upload_secret: raw.4,
        group_id_hex: raw.5,
        attempt_count: u32::try_from(raw.6).map_err(|_| {
            StorageError::Serialization("invalid group image upload attempt count".into())
        })?,
        last_error_kind: raw.7,
        recorded_at: i64_to_u64(raw.8)?,
        updated_at: i64_to_u64(raw.9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged_record() -> PreparedGroupImageUploadRecord {
        PreparedGroupImageUploadRecord {
            upload_id: "upload-1".into(),
            state: PreparedGroupImageUploadState::Staged,
            component_data: vec![1, 2, 3],
            encrypted_blob: Some(vec![4, 5, 6]),
            upload_secret: Some(vec![7; 32]),
            group_id_hex: None,
            attempt_count: 0,
            last_error_kind: None,
            recorded_at: 10,
            updated_at: 10,
        }
    }

    fn staged_record_with(upload_id: String, now: u64) -> PreparedGroupImageUploadRecord {
        PreparedGroupImageUploadRecord {
            upload_id,
            recorded_at: now,
            updated_at: now,
            ..staged_record()
        }
    }

    #[test]
    fn staged_upload_survives_reopen_state_transitions_and_consumption() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .stage_prepared_group_image_upload(&staged_record())
            .unwrap();
        assert_eq!(
            store
                .prepared_group_image_upload("upload-1")
                .unwrap()
                .unwrap(),
            staged_record()
        );

        store
            .mark_prepared_group_image_upload_failed("upload-1", "blob_store", 11)
            .unwrap();
        let failed = store
            .prepared_group_image_upload("upload-1")
            .unwrap()
            .unwrap();
        assert_eq!(failed.state, PreparedGroupImageUploadState::Failed);
        assert_eq!(failed.attempt_count, 1);

        store
            .mark_prepared_group_image_upload_uploaded("upload-1", 12)
            .unwrap();
        store
            .consume_prepared_group_image_upload("upload-1", "abcd", 13)
            .unwrap();
        let consumed = store
            .prepared_group_image_upload("upload-1")
            .unwrap()
            .unwrap();
        assert_eq!(consumed.state, PreparedGroupImageUploadState::Consumed);
        assert_eq!(consumed.group_id_hex.as_deref(), Some("abcd"));
        assert!(consumed.component_data.is_empty());
        assert!(consumed.encrypted_blob.is_none());
        assert!(consumed.upload_secret.is_none());
        assert_eq!(consumed.attempt_count, 2);
    }

    #[test]
    fn uploaded_and_consumed_transitions_are_idempotent() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .stage_prepared_group_image_upload(&staged_record())
            .unwrap();
        store
            .mark_prepared_group_image_upload_uploaded("upload-1", 11)
            .unwrap();
        store
            .mark_prepared_group_image_upload_uploaded("upload-1", 12)
            .unwrap();
        assert_eq!(
            store
                .prepared_group_image_upload("upload-1")
                .unwrap()
                .unwrap()
                .attempt_count,
            1
        );
        store
            .consume_prepared_group_image_upload("upload-1", "abcd", 13)
            .unwrap();
        store
            .consume_prepared_group_image_upload("upload-1", "abcd", 14)
            .unwrap();
    }

    #[test]
    fn debug_redacts_component_blob_and_secret() {
        let debug = format!("{:?}", staged_record());
        assert!(!debug.contains("1, 2, 3"));
        assert!(!debug.contains("4, 5, 6"));
        assert!(!debug.contains("7, 7, 7"));
    }

    #[test]
    fn staged_upload_survives_database_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.sqlite3");
        let key = crate::SqlCipherKey::new("prepared-image-restart-key").unwrap();
        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store
                .stage_prepared_group_image_upload(&staged_record())
                .unwrap();
            store.close().unwrap();
        }
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            reopened
                .prepared_group_image_upload("upload-1")
                .unwrap()
                .unwrap(),
            staged_record()
        );
    }

    #[test]
    fn active_uploads_are_capped_and_expired_rows_reclaim_capacity() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let now = ACTIVE_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS + 100;
        for index in 0..MAX_ACTIVE_PREPARED_GROUP_IMAGE_UPLOADS {
            store
                .stage_prepared_group_image_upload(&staged_record_with(
                    format!("upload-{index}"),
                    now,
                ))
                .unwrap();
        }
        assert!(
            store
                .stage_prepared_group_image_upload(&staged_record_with("over-cap".into(), now,))
                .is_err()
        );

        let after_ttl = now + ACTIVE_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS + 1;
        store
            .stage_prepared_group_image_upload(&staged_record_with(
                "after-expiry".into(),
                after_ttl,
            ))
            .unwrap();
        assert_eq!(store.list_prepared_group_image_uploads().unwrap().len(), 1);
    }

    #[test]
    fn consumed_idempotency_markers_evict_oldest_at_bound() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let now = CONSUMED_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS + 100;
        for index in 0..=MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS {
            let upload_id = format!("upload-{index:04}");
            store
                .stage_prepared_group_image_upload(&staged_record_with(
                    upload_id.clone(),
                    now + index as u64,
                ))
                .unwrap();
            store
                .mark_prepared_group_image_upload_uploaded(&upload_id, now + index as u64)
                .unwrap();
            store
                .consume_prepared_group_image_upload(
                    &upload_id,
                    &format!("group-{index}"),
                    now + index as u64,
                )
                .unwrap();
        }
        let rows = store.list_prepared_group_image_uploads().unwrap();
        assert_eq!(rows.len(), MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS);
        assert!(rows.iter().all(|row| row.upload_id != "upload-0000"));
    }
}
