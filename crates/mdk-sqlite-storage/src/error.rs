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

    // Encryption-related errors

    /// Database encryption key has invalid length (expected 32 bytes)
    #[error("Invalid encryption key length: expected 32 bytes, got {0} bytes")]
    InvalidKeyLength(usize),

    /// Wrong encryption key provided for existing database
    #[error("Wrong encryption key: database cannot be decrypted with the provided key")]
    WrongEncryptionKey,

    /// Attempted to open an encrypted database without providing a key
    #[error("Encrypted database requires an encryption key")]
    EncryptedDatabaseRequiresKey,

    /// Attempted to open an unencrypted database with encryption enabled
    #[error("Cannot open unencrypted database with encryption: database was created without encryption")]
    UnencryptedDatabaseWithEncryption,

    /// Failed to generate random key
    #[error("Failed to generate encryption key: {0}")]
    KeyGeneration(String),

    /// File permission error
    #[error("File permission error: {0}")]
    FilePermission(String),

    // Keyring-related errors

    /// Keyring operation failed
    #[error("Keyring error: {0}")]
    Keyring(String),

    /// Keyring store not initialized
    ///
    /// The host application must initialize a platform-specific keyring store
    /// before using encrypted storage. See the MDK documentation for platform-specific
    /// setup instructions.
    #[error("Keyring store not initialized. The host application must call keyring_core::set_default_store() with a platform-specific store before using encrypted storage. Details: {0}")]
    KeyringNotInitialized(String),
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
