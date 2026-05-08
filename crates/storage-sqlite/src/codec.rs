use cgka_traits::message::MessageState;
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::EpochId;
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn serialize<T: Serialize>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub(crate) fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
    serde_json::from_slice(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub(crate) trait SqliteResultExt<T> {
    fn storage(self) -> StorageResult<T>;
}

impl<T> SqliteResultExt<T> for rusqlite::Result<T> {
    fn storage(self) -> StorageResult<T> {
        self.map_err(|e| StorageError::Backend(e.to_string()))
    }
}

pub(crate) fn message_state_to_i64(state: MessageState) -> i64 {
    match state {
        MessageState::Sent => 0,
        MessageState::Created => 1,
        MessageState::Processed => 2,
        MessageState::Failed => 3,
        MessageState::Retryable => 4,
        MessageState::EpochInvalidated => 5,
    }
}

pub(crate) fn epoch_to_i64(epoch: EpochId) -> StorageResult<i64> {
    i64::try_from(epoch.0)
        .map_err(|_| StorageError::Serialization(format!("epoch too large: {}", epoch.0)))
}

pub(crate) fn created_at_to_i64(created_at_ms: u64) -> StorageResult<i64> {
    i64::try_from(created_at_ms).map_err(|_| {
        StorageError::Serialization(format!("created_at_ms too large: {created_at_ms}"))
    })
}
