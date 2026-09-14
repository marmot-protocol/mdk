//! Privacy-safe SQLite diagnostics for every shared-store operation.
use cgka_traits::storage::{StorageError, StorageResult};

/// Shared queries use this instead of the crate-wide unredacted conversion.
pub(super) trait SharedSqliteResultExt<T> {
    fn storage(self) -> StorageResult<T>;
}

impl<T> SharedSqliteResultExt<T> for rusqlite::Result<T> {
    fn storage(self) -> StorageResult<T> {
        self.map_err(sqlite_error)
    }
}

/// Preserve SQLite codes/transience and useful conversion categories, but never
/// display database-controlled messages, column names, stored values or causes.
pub(super) fn sqlite_error(error: rusqlite::Error) -> StorageError {
    use rusqlite::Error;
    let detail = match error {
        Error::SqliteFailure(code, _) => {
            return crate::codec::map_sqlite_error(Error::SqliteFailure(code, None));
        }
        Error::InvalidColumnType(index, _, kind) => {
            format!("shared store invalid column type at index {index}: {kind:?}")
        }
        Error::FromSqlConversionFailure(index, kind, _) => {
            format!("shared store conversion failed at column index {index}: {kind:?}")
        }
        Error::IntegralValueOutOfRange(index, _) => {
            format!("shared store integer out of range at column index {index}")
        }
        Error::QueryReturnedNoRows => "shared store query returned no rows".into(),
        Error::QueryReturnedMoreThanOneRow => "shared store query returned multiple rows".into(),
        Error::InvalidColumnIndex(index) => format!("shared store invalid column index {index}"),
        _ => "shared store SQLite operation failed".into(),
    };
    StorageError::Backend(detail)
}
