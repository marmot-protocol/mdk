//! Error types for the SQLite storage implementation.

/// Error type for SQLite storage operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// SQLite database error
    #[error("Database error: {0}")]
    Database(String),
    /// Error from rusqlite
    #[error("SQLite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    /// Error during database migration
    #[error("Migration error: {0}")]
    Refinery(#[from] refinery::Error),
    /// Error from OpenMLS
    #[error("OpenMLS error: {0}")]
    OpenMls(String),
    /// Input validation error
    #[error("{field_name} exceeds maximum length of {max_size} bytes (got {actual_size} bytes)")]
    Validation {
        /// Name of the field that failed validation
        field_name: String,
        /// Maximum allowed size/length in bytes
        max_size: usize,
        /// Actual size/length in bytes
        actual_size: usize,
    },
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Database(format!("IO error: {}", e))
    }
}

impl From<Error> for rusqlite::Error {
    fn from(err: Error) -> Self {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            )),
        )
    }
}
