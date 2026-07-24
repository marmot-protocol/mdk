mod labels;
mod provider;
mod value_store;

use crate::connection::SharedConnection;
use cgka_traits::storage::{StorageError, StorageResult, StoredKeyPackageBundle};
use cgka_traits::types::GroupId as MarmotGroupId;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct SqliteOpenMlsStorage {
    pub(crate) connection: SharedConnection,
}

impl SqliteOpenMlsStorage {
    pub(crate) fn new(connection: SharedConnection) -> Self {
        Self { connection }
    }

    pub(crate) fn group_key<GroupId: Serialize>(
        group_id: &GroupId,
    ) -> Result<Vec<u8>, SqliteOpenMlsStorageError> {
        Ok(serde_json::to_vec(group_id)?)
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, SqliteOpenMlsStorageError> {
        self.connection
            .lock()
            .map_err(|e| SqliteOpenMlsStorageError::Lock(e.to_string()))
    }

    pub(crate) fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>> {
        use openmls_traits::storage::CURRENT_VERSION;
        use rusqlite::params;

        let connection = self.connection.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT storage_key, value
                 FROM openmls_values
                 WHERE provider_version = ?1 AND label = ?2
                 ORDER BY storage_key",
            )
            .map_err(crate::codec::map_sqlite_error)?;
        let rows = statement
            .query_map(params![CURRENT_VERSION, labels::KEY_PACKAGE_LABEL], |row| {
                Ok(StoredKeyPackageBundle {
                    storage_key: row.get(0)?,
                    value: row.get(1)?,
                })
            })
            .map_err(crate::codec::map_sqlite_error)?;
        rows.collect::<Result<Vec<StoredKeyPackageBundle>, _>>()
            .map_err(crate::codec::map_sqlite_error)
    }

    pub(crate) fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()> {
        use openmls_traits::storage::CURRENT_VERSION;
        use rusqlite::params;

        let connection = self.connection.lock()?;
        connection
            .execute(
                "DELETE FROM openmls_values
                 WHERE provider_version = ?1 AND label = ?2 AND storage_key = ?3",
                params![CURRENT_VERSION, labels::KEY_PACKAGE_LABEL, storage_key],
            )
            .map_err(crate::codec::map_sqlite_error)?;
        Ok(())
    }
}

pub(crate) fn mls_group_key(group_id: &MarmotGroupId) -> StorageResult<Vec<u8>> {
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    SqliteOpenMlsStorage::group_key(&mls_group_id)
        .map_err(|e| StorageError::Serialization(e.to_string()))
}

#[derive(thiserror::Error, Debug)]
pub enum SqliteOpenMlsStorageError {
    #[error("storage failure: {0}")]
    Storage(#[from] StorageError),
    #[error("sqlite failure: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization failure: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("queued proposal reference was present without a queued proposal")]
    MissingQueuedProposal,
    #[error("connection lock poisoned: {0}")]
    Lock(String),
}

impl crate::connection::TransientError for SqliteOpenMlsStorageError {
    fn is_busy(&self) -> bool {
        match self {
            SqliteOpenMlsStorageError::Sqlite(error) => crate::codec::is_busy_error(error),
            _ => false,
        }
    }
}
