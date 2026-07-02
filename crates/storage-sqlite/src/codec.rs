use std::time::{SystemTime, UNIX_EPOCH};

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
        self.map_err(map_sqlite_error)
    }
}

/// Map a `rusqlite::Error` to a [`StorageError`], classifying transient lock
/// contention (`SQLITE_BUSY` / `SQLITE_LOCKED`, including their extended result
/// codes) as [`StorageError::Busy`] rather than the catch-all
/// [`StorageError::Backend`]. This is the single place where the SQLite error
/// vocabulary is translated, so the transient/fatal distinction (issue #484)
/// stays in one spot and never has to be re-derived by string-parsing
/// "database is locked".
pub(crate) fn map_sqlite_error(error: rusqlite::Error) -> StorageError {
    if is_busy_error(&error) {
        StorageError::Busy(error.to_string())
    } else {
        StorageError::Backend(error.to_string())
    }
}

/// Whether a `rusqlite::Error` is transient SQLite lock contention worth
/// retrying: `SQLITE_BUSY` (the writer could not acquire the database lock
/// before the busy timeout) or `SQLITE_LOCKED` (a table in the same connection
/// is locked). Extended result codes such as `SQLITE_BUSY_RECOVERY` and
/// `SQLITE_LOCKED_SHAREDCACHE` collapse to these primary codes via
/// `sqlite_error_code`, so matching the primary codes covers them too.
pub(crate) fn is_busy_error(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

pub(crate) fn message_state_to_i64(state: MessageState) -> i64 {
    match state {
        MessageState::Sent => 0,
        MessageState::Created => 1,
        MessageState::Processed => 2,
        MessageState::Failed => 3,
        MessageState::Retryable => 4,
        MessageState::EpochInvalidated => 5,
        MessageState::PeelDeferred => 6,
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

/// Encode a `bool` as the SQLite integer convention (`1`/`0`).
pub(crate) fn bool_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

/// Convert a `u64` to SQLite's signed `INTEGER`, erroring if it overflows `i64`.
pub(crate) fn u64_to_i64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

/// Convert an optional `u64` to SQLite's signed `INTEGER`, preserving `None`.
pub(crate) fn optional_u64_to_i64(value: Option<u64>) -> StorageResult<Option<i64>> {
    value.map(u64_to_i64).transpose()
}

/// Convert a `usize` to SQLite's signed `INTEGER`, erroring if it overflows `i64`.
pub(crate) fn usize_to_i64(value: usize) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

/// Decode a JSON tag array as stored in projection rows.
pub(crate) fn tags_from_json(json: String) -> Result<Vec<Vec<String>>, serde_json::Error> {
    serde_json::from_str(&json)
}

/// Current wall-clock milliseconds since the Unix epoch, saturating at `i64::MAX`.
pub(crate) fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

/// Current wall-clock seconds since the Unix epoch.
pub(crate) fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current wall-clock seconds since the Unix epoch, saturating at `i64::MAX`.
pub(crate) fn unix_now_seconds_i64() -> i64 {
    i64::try_from(unix_now_seconds()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_failure(primary: std::os::raw::c_int) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(primary),
            Some("database is locked".to_string()),
        )
    }

    #[test]
    fn busy_and_locked_are_classified_transient() {
        assert!(is_busy_error(&sqlite_failure(rusqlite::ffi::SQLITE_BUSY)));
        assert!(is_busy_error(&sqlite_failure(rusqlite::ffi::SQLITE_LOCKED)));
        // Extended result codes collapse to the primary code via
        // `sqlite_error_code`, so they classify as transient too.
        assert!(is_busy_error(&sqlite_failure(
            rusqlite::ffi::SQLITE_BUSY_RECOVERY
        )));
        assert!(is_busy_error(&sqlite_failure(
            rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE
        )));
    }

    #[test]
    fn other_sqlite_errors_are_not_transient() {
        assert!(!is_busy_error(&sqlite_failure(
            rusqlite::ffi::SQLITE_CORRUPT
        )));
        assert!(!is_busy_error(&sqlite_failure(rusqlite::ffi::SQLITE_FULL)));
        assert!(!is_busy_error(&rusqlite::Error::QueryReturnedNoRows));
    }

    #[test]
    fn map_sqlite_error_routes_busy_to_busy_variant() {
        let mapped = map_sqlite_error(sqlite_failure(rusqlite::ffi::SQLITE_BUSY));
        assert!(
            matches!(mapped, StorageError::Busy(_)),
            "SQLITE_BUSY must map to StorageError::Busy, got {mapped:?}"
        );
        assert!(mapped.is_transient());
    }

    #[test]
    fn map_sqlite_error_routes_other_errors_to_backend() {
        let mapped = map_sqlite_error(sqlite_failure(rusqlite::ffi::SQLITE_CORRUPT));
        assert!(
            matches!(mapped, StorageError::Backend(_)),
            "non-busy errors must map to StorageError::Backend, got {mapped:?}"
        );
        assert!(!mapped.is_transient());
    }
}
