mod labels;
mod provider;
mod value_store;

use crate::connection::SharedConnection;
use cgka_traits::storage::{StorageError, StorageResult};
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
}

pub(crate) fn mls_group_key(group_id: &MarmotGroupId) -> StorageResult<Vec<u8>> {
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    SqliteOpenMlsStorage::group_key(&mls_group_id)
        .map_err(|e| StorageError::Serialization(e.to_string()))
}

#[derive(thiserror::Error, Debug)]
pub enum SqliteOpenMlsStorageError {
    #[error("sqlite failure: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization failure: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("queued proposal reference was present without a queued proposal")]
    MissingQueuedProposal,
    #[error("connection lock poisoned: {0}")]
    Lock(String),
}
