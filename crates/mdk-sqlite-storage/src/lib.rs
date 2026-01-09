//! SQLite-based storage implementation for Nostr MLS.
//!
//! This module provides a SQLite-based storage implementation for the Nostr MLS (Messaging Layer Security)
//! crate. It implements the [`MdkStorageProvider`] trait, allowing it to be used within the Nostr MLS context.
//!
//! SQLite-based storage is persistent and will be saved to a file. It's useful for production applications
//! where data persistence is required.
//!
//! # Encryption
//!
//! This crate uses SQLCipher for transparent encryption of MLS state at rest with keys stored securely
//! in the platform's native keyring (Keychain, Keystore, etc.).
//!
//! ## Setup (Required First)
//!
//! Before using MDK, the host application must initialize a platform-specific keyring store:
//!
//! ```ignore
//! // macOS/iOS
//! use apple_native_keyring_store::AppleStore;
//! keyring_core::set_default_store(AppleStore::new());
//!
//! // Windows
//! use windows_native_keyring_store::WindowsStore;
//! keyring_core::set_default_store(WindowsStore::new());
//!
//! // Linux
//! use linux_keyutils_keyring_store::KeyutilsStore;
//! keyring_core::set_default_store(KeyutilsStore::new());
//! ```
//!
//! ## Creating Encrypted Storage (Recommended)
//!
//! ```ignore
//! use mdk_sqlite_storage::MdkSqliteStorage;
//!
//! // MDK handles key generation and storage automatically
//! let storage = MdkSqliteStorage::new(
//!     "/path/to/db.sqlite",
//!     "com.example.myapp",      // Service identifier
//!     "mdk.db.key.default"      // Key identifier
//! )?;
//! ```
//!
//! ## Direct Key Management (Advanced)
//!
//! If you need to manage encryption keys yourself:
//!
//! ```no_run
//! use mdk_sqlite_storage::{EncryptionConfig, MdkSqliteStorage};
//!
//! let key = [0u8; 32]; // Your securely stored key
//! let config = EncryptionConfig::new(key);
//! let storage = MdkSqliteStorage::new_with_key("/path/to/db.sqlite", config)?;
//! # Ok::<(), mdk_sqlite_storage::error::Error>(())
//! ```
//!
//! # Security Recommendations
//!
//! - **Use [`MdkSqliteStorage::new`]**: It handles key generation and secure storage automatically
//! - **Never log encryption keys**: The [`EncryptionConfig`] debug output redacts the key
//! - **Use unique keys per database**: Don't reuse keys across different databases

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use mdk_storage_traits::{Backend, MdkStorageProvider};
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use rusqlite::Connection;
use serde::Serialize;
use serde::de::DeserializeOwned;

mod db;
pub mod encryption;
pub mod error;
mod groups;
pub mod keyring;
mod messages;
mod migrations;
mod permissions;
#[cfg(test)]
mod test_utils;
mod validation;
mod welcomes;

pub use self::encryption::EncryptionConfig;
use self::error::Error;
pub use self::permissions::verify_permissions;
use self::permissions::{
    FileCreationOutcome, precreate_secure_database_file, set_secure_file_permissions,
};

// Define a type alias for the specific SqliteStorageProvider we're using
type MlsStorage = SqliteStorageProvider<JsonCodec, Connection>;

// TODO: make this private?
/// A codec for JSON serialization and deserialization.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    #[inline]
    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    #[inline]
    fn from_slice<T>(slice: &[u8]) -> Result<T, Self::Error>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(slice)
    }
}

/// A SQLite-based storage implementation for Nostr MLS.
///
/// This struct implements the MdkStorageProvider trait for SQLite databases.
/// It directly interfaces with a SQLite database for storing MLS data.
///
/// # Encryption
///
/// All databases are encrypted by default using SQLCipher. Keys are stored securely
/// in the platform's native keyring (Keychain, Keystore, etc.).
///
/// # Example
///
/// ```ignore
/// use mdk_sqlite_storage::MdkSqliteStorage;
///
/// // Create encrypted storage (production - recommended)
/// let storage = MdkSqliteStorage::new(
///     "/path/to/db.sqlite",
///     "com.example.myapp",
///     "mdk.db.key.default"
/// )?;
/// ```
pub struct MdkSqliteStorage {
    /// The OpenMLS storage implementation
    openmls_storage: MlsStorage,
    /// The SQLite connection
    db_connection: Arc<Mutex<Connection>>,
}

impl MdkSqliteStorage {
    /// Creates a new encrypted [`MdkSqliteStorage`] with automatic key management.
    ///
    /// This is the recommended constructor for production use. The database encryption key
    /// is automatically retrieved from (or generated and stored in) the platform's native
    /// keyring (Keychain on macOS/iOS, Keystore on Android, etc.).
    ///
    /// # Prerequisites
    ///
    /// The host application must initialize a platform-specific keyring store before calling
    /// this method. See the module documentation for setup instructions.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the SQLite database file.
    /// * `service_id` - A stable, host-defined application identifier (e.g., reverse-DNS like
    ///   `"com.example.myapp"`). This should be unique per application.
    /// * `db_key_id` - A stable identifier for this database's key (e.g., `"mdk.db.key.default"`
    ///   or `"mdk.db.key.<profile_id>"` for multi-profile apps).
    ///
    /// # Key Management
    ///
    /// - If no key exists for the given identifiers, a new 32-byte key is generated using
    ///   cryptographically secure randomness and stored in the keyring.
    /// - On subsequent calls with the same identifiers, the existing key is retrieved.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No keyring store has been initialized
    /// - The keyring is unavailable or inaccessible
    /// - An existing database cannot be decrypted with the stored key
    /// - The database file cannot be created or opened
    ///
    /// # Example
    ///
    /// ```ignore
    /// use mdk_sqlite_storage::MdkSqliteStorage;
    ///
    /// // First, initialize the platform keyring (do this once at app startup)
    /// // keyring_core::set_default_store(platform_specific_store);
    ///
    /// // Then create storage with automatic key management
    /// let storage = MdkSqliteStorage::new(
    ///     "/path/to/db.sqlite",
    ///     "com.example.myapp",
    ///     "mdk.db.key.default"
    /// )?;
    /// ```
    pub fn new<P>(file_path: P, service_id: &str, db_key_id: &str) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let file_path = file_path.as_ref();

        // Atomically create the database file first, BEFORE making key decisions.
        // This prevents TOCTOU races where another process could create the file
        // between our existence check and key generation.
        let creation_outcome = precreate_secure_database_file(file_path)?;

        let config = match creation_outcome {
            FileCreationOutcome::Created | FileCreationOutcome::Skipped => {
                // We created the file (or it's a special path like :memory:).
                // Safe to generate a new key since we own this database.
                keyring::get_or_create_db_key(service_id, db_key_id)?
            }
            FileCreationOutcome::AlreadyExisted => {
                // File already existed - another thread/process may have created it.
                // We must retrieve the existing key, not generate a new one.
                //
                // IMPORTANT: Check the keyring FIRST, before checking if the file is encrypted.
                // This handles the race condition where another thread has created the file
                // and stored the key in the keyring, but hasn't yet written the encrypted
                // header to the database file. If we checked the file first, we'd see an
                // empty file and incorrectly return UnencryptedDatabaseWithEncryption.
                match keyring::get_db_key(service_id, db_key_id)? {
                    Some(config) => {
                        // Key exists in keyring - another thread/process is initializing
                        // (or has initialized) this database with encryption. Use that key.
                        config
                    }
                    None => {
                        // No key in keyring. Check if the database file appears unencrypted.
                        // This catches the case where someone tries to use new() on a
                        // database that was created with new_unencrypted().
                        if !encryption::is_database_encrypted(file_path)? {
                            return Err(Error::UnencryptedDatabaseWithEncryption);
                        }

                        // Database appears encrypted but no key in keyring - unrecoverable.
                        return Err(Error::KeyringEntryMissingForExistingDatabase {
                            db_path: file_path.display().to_string(),
                            service_id: service_id.to_string(),
                            db_key_id: db_key_id.to_string(),
                        });
                    }
                }
            }
        };

        Self::new_internal_skip_precreate(file_path, Some(config))
    }

    /// Creates a new encrypted [`MdkSqliteStorage`] with a directly provided encryption key.
    ///
    /// Use this method when you want to manage encryption keys yourself rather than using
    /// the platform keyring. For most applications, prefer [`Self::new`] which handles
    /// key management automatically.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the SQLite database file.
    /// * `config` - Encryption configuration containing the 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The encryption key is invalid
    /// - An existing database cannot be decrypted with the provided key
    /// - An existing database was created without encryption
    /// - The database file cannot be created or opened
    /// - File permissions cannot be set
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mdk_sqlite_storage::{EncryptionConfig, MdkSqliteStorage};
    ///
    /// let key = [0u8; 32]; // Your securely stored key
    /// let config = EncryptionConfig::new(key);
    /// let storage = MdkSqliteStorage::new_with_key("/path/to/db.sqlite", config)?;
    /// # Ok::<(), mdk_sqlite_storage::error::Error>(())
    /// ```
    pub fn new_with_key<P>(file_path: P, config: EncryptionConfig) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let file_path = file_path.as_ref();

        // If the database exists, verify it's encrypted before trying to use the key.
        // This provides a clearer error than letting apply_encryption fail.
        if file_path.exists() && !encryption::is_database_encrypted(file_path)? {
            return Err(Error::UnencryptedDatabaseWithEncryption);
        }

        Self::new_internal(file_path, Some(config))
    }

    /// Creates a new unencrypted [`MdkSqliteStorage`] with the provided file path.
    ///
    /// ⚠️ **WARNING**: This creates an unencrypted database. Sensitive MLS state including
    /// exporter secrets will be stored in plaintext. Only use this for development or testing.
    ///
    /// For production use, use [`Self::new`] or [`Self::new_with_key`] instead.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the SQLite database file.
    ///
    /// # Returns
    ///
    /// A Result containing a new instance of [`MdkSqliteStorage`] or an error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mdk_sqlite_storage::MdkSqliteStorage;
    ///
    /// // ⚠️ Unencrypted - for development only
    /// let storage = MdkSqliteStorage::new_unencrypted("/path/to/db.sqlite")?;
    /// # Ok::<(), mdk_sqlite_storage::error::Error>(())
    /// ```
    pub fn new_unencrypted<P>(file_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        tracing::warn!(
            "Creating unencrypted database. Sensitive MLS state will be stored in plaintext. \
             For production use, use new() or new_with_key() instead."
        );
        Self::new_internal(file_path, None)
    }

    /// Internal constructor that handles both encrypted and unencrypted database creation.
    ///
    /// This is used by constructors that haven't already pre-created the file.
    fn new_internal<P>(
        file_path: P,
        encryption_config: Option<EncryptionConfig>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let file_path = file_path.as_ref();

        // Pre-create database file with secure permissions to avoid permission race
        precreate_secure_database_file(file_path)?;

        Self::new_internal_skip_precreate(file_path, encryption_config)
    }

    /// Internal constructor that skips file pre-creation.
    ///
    /// Used when the caller has already atomically pre-created the file
    /// (e.g., in `new()` which uses atomic creation for TOCTOU prevention).
    fn new_internal_skip_precreate(
        file_path: &Path,
        encryption_config: Option<EncryptionConfig>,
    ) -> Result<Self, Error> {
        // Create or open the SQLite database for OpenMLS
        let mls_connection = Self::open_connection(file_path, encryption_config.as_ref())?;

        // Create OpenMLS storage
        let mut openmls_storage: MlsStorage = SqliteStorageProvider::new(mls_connection);

        // Initialize the OpenMLS storage
        openmls_storage.run_migrations()?;

        // Create a second connection for MDK tables
        let mut mdk_connection = Self::open_connection(file_path, encryption_config.as_ref())?;

        // Apply MDK migrations
        migrations::run_migrations(&mut mdk_connection)?;

        // Ensure secure permissions on the database file and any sidecar files
        Self::apply_secure_permissions(file_path)?;

        Ok(Self {
            openmls_storage,
            db_connection: Arc::new(Mutex::new(mdk_connection)),
        })
    }

    /// Opens a SQLite connection with optional encryption.
    fn open_connection(
        file_path: &Path,
        encryption_config: Option<&EncryptionConfig>,
    ) -> Result<Connection, Error> {
        let conn = Connection::open(file_path)?;

        // Apply encryption if configured (must be done before any other operations)
        if let Some(config) = encryption_config {
            encryption::apply_encryption(&conn, config)?;
        }

        // Enable foreign keys (after encryption is set up)
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        Ok(conn)
    }

    /// Applies secure file permissions to the database and related files.
    ///
    /// # Defense in Depth for Sidecar Files
    ///
    /// SQLite creates sidecar files (`-wal`, `-shm`, `-journal`) dynamically during
    /// database operations. We apply permissions to these files if they exist at
    /// initialization time, but files created afterward may have default permissions
    /// until the next `MdkSqliteStorage` instance is created.
    ///
    /// This is acceptable because of our layered security approach:
    ///
    /// 1. **Directory permissions**: The parent directory is created with 0700 permissions
    ///    (owner-only access). Even if sidecar files have more permissive default permissions,
    ///    other users cannot traverse into the directory to access them.
    ///
    /// 2. **SQLCipher encryption**: All data written to sidecar files is encrypted.
    ///    The `-wal` and `-journal` files contain encrypted page data, making them
    ///    unreadable without the encryption key regardless of file permissions.
    ///
    /// 3. **Mobile sandboxing**: On iOS and Android, the application sandbox provides
    ///    the primary security boundary, making file permissions defense-in-depth.
    ///
    /// Alternative approaches (e.g., `PRAGMA journal_mode = MEMORY`) were considered
    /// but rejected because they sacrifice crash durability, which is unacceptable
    /// for MLS cryptographic state.
    fn apply_secure_permissions(db_path: &Path) -> Result<(), Error> {
        // Skip special SQLite paths (in-memory databases, etc.)
        let path_str = db_path.to_string_lossy();
        if path_str.is_empty() || path_str == ":memory:" || path_str.starts_with(':') {
            return Ok(());
        }

        // Apply to main database file
        set_secure_file_permissions(db_path)?;

        // Apply to common SQLite sidecar files if they exist.
        // Note: Files created after this point will have default permissions, but are
        // still protected by directory permissions and SQLCipher encryption (see above).
        let parent = db_path.parent();
        let stem = db_path.file_name().and_then(|n| n.to_str());

        if let (Some(parent), Some(stem)) = (parent, stem) {
            for suffix in &["-wal", "-shm", "-journal"] {
                let sidecar = parent.join(format!("{}{}", stem, suffix));
                if sidecar.exists() {
                    set_secure_file_permissions(&sidecar)?;
                }
            }
        }

        Ok(())
    }

    /// Creates a new in-memory [`MdkSqliteStorage`] for testing purposes.
    ///
    /// In-memory databases are not encrypted and do not persist data.
    ///
    /// # Returns
    ///
    /// A Result containing a new in-memory instance of [`MdkSqliteStorage`] or an error.
    #[cfg(test)]
    pub fn new_in_memory() -> Result<Self, Error> {
        // Create an in-memory SQLite database
        let mls_connection = Connection::open_in_memory()?;

        // Enable foreign keys
        mls_connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Create OpenMLS storage
        let mut openmls_storage: MlsStorage = SqliteStorageProvider::new(mls_connection);

        // Initialize the OpenMLS storage
        openmls_storage.run_migrations()?;

        // For in-memory databases, we need to share the connection
        // to keep the database alive, so we will clone the connection
        // and let OpenMLS use a new handle
        let mut mdk_connection: Connection = Connection::open_in_memory()?;

        // Enable foreign keys
        mdk_connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Setup the schema in this connection as well
        migrations::run_migrations(&mut mdk_connection)?;

        Ok(Self {
            openmls_storage,
            db_connection: Arc::new(Mutex::new(mdk_connection)),
        })
    }
}

/// Implementation of [`MdkStorageProvider`] for SQLite-based storage.
impl MdkStorageProvider for MdkSqliteStorage {
    type OpenMlsStorageProvider = MlsStorage;

    /// Returns the backend type.
    ///
    /// # Returns
    ///
    /// [`Backend::SQLite`] indicating this is a SQLite-based storage implementation.
    fn backend(&self) -> Backend {
        Backend::SQLite
    }

    /// Get a reference to the openmls storage provider.
    ///
    /// This method provides access to the underlying OpenMLS storage provider.
    /// This is primarily useful for internal operations and testing.
    ///
    /// # Returns
    ///
    /// A reference to the openmls storage implementation.
    fn openmls_storage(&self) -> &Self::OpenMlsStorageProvider {
        &self.openmls_storage
    }

    /// Get a mutable reference to the openmls storage provider.
    ///
    /// This method provides mutable access to the underlying OpenMLS storage provider.
    /// This is primarily useful for internal operations and testing.
    ///
    /// # Returns
    ///
    /// A mutable reference to the openmls storage implementation.
    fn openmls_storage_mut(&mut self) -> &mut Self::OpenMlsStorageProvider {
        &mut self.openmls_storage
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mdk_storage_traits::GroupId;
    use mdk_storage_traits::Secret;
    use mdk_storage_traits::groups::GroupStorage;
    use mdk_storage_traits::groups::types::{Group, GroupExporterSecret, GroupState};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_new_in_memory() {
        let storage = MdkSqliteStorage::new_in_memory();
        assert!(storage.is_ok());
        let storage = storage.unwrap();
        assert_eq!(storage.backend(), Backend::SQLite);
    }

    #[test]
    fn test_backend_type() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        assert_eq!(storage.backend(), Backend::SQLite);
        assert!(storage.backend().is_persistent());
    }

    #[test]
    fn test_file_based_storage() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db.sqlite");

        // Create a new storage
        let storage = MdkSqliteStorage::new_unencrypted(&db_path);
        assert!(storage.is_ok());

        // Verify file exists
        assert!(db_path.exists());

        // Create a second instance that connects to the same file
        let storage2 = MdkSqliteStorage::new_unencrypted(&db_path);
        assert!(storage2.is_ok());

        // Clean up
        drop(storage);
        drop(storage2);
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_openmls_storage_access() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // Test that we can get a reference to the openmls storage
        let _openmls_storage = storage.openmls_storage();

        // Test mutable accessor
        let mut mutable_storage = MdkSqliteStorage::new_in_memory().unwrap();
        let _mutable_ref = mutable_storage.openmls_storage_mut();
    }

    #[test]
    fn test_database_tables() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("migration_test.sqlite");

        // Create a new SQLite database
        let storage = MdkSqliteStorage::new_unencrypted(&db_path).unwrap();

        // Verify the database has been properly initialized with migrations
        {
            let conn_guard = storage.db_connection.lock().unwrap();

            // Check if the tables exist
            let mut stmt = conn_guard
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")
                .unwrap();
            let table_names: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();

            // Check for essential tables
            assert!(table_names.contains(&"groups".to_string()));
            assert!(table_names.contains(&"messages".to_string()));
            assert!(table_names.contains(&"welcomes".to_string()));
            assert!(table_names.contains(&"processed_messages".to_string()));
            assert!(table_names.contains(&"processed_welcomes".to_string()));
            assert!(table_names.contains(&"group_relays".to_string()));
            assert!(table_names.contains(&"group_exporter_secrets".to_string()));
        } // conn_guard is dropped here when it goes out of scope

        // Drop explicitly to release all resources
        drop(storage);
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_group_exporter_secrets() {
        // Create an in-memory SQLite database
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // Create a test group
        let mls_group_id = GroupId::from_slice(vec![1, 2, 3, 4].as_slice());
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id: [0u8; 32],
            name: "Test Group".to_string(),
            description: "A test group for exporter secrets".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };

        // Save the group
        storage.save_group(group.clone()).unwrap();

        // Create test group exporter secrets for different epochs
        let secret_epoch_0 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 0,
            secret: Secret::new([0u8; 32]),
        };

        let secret_epoch_1 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 1,
            secret: Secret::new([0u8; 32]),
        };

        // Save the exporter secrets
        storage
            .save_group_exporter_secret(secret_epoch_0.clone())
            .unwrap();
        storage
            .save_group_exporter_secret(secret_epoch_1.clone())
            .unwrap();

        // Test retrieving exporter secrets
        let retrieved_secret_0 = storage.get_group_exporter_secret(&mls_group_id, 0).unwrap();
        assert!(retrieved_secret_0.is_some());
        let retrieved_secret_0 = retrieved_secret_0.unwrap();
        assert_eq!(retrieved_secret_0, secret_epoch_0);

        let retrieved_secret_1 = storage.get_group_exporter_secret(&mls_group_id, 1).unwrap();
        assert!(retrieved_secret_1.is_some());
        let retrieved_secret_1 = retrieved_secret_1.unwrap();
        assert_eq!(retrieved_secret_1, secret_epoch_1);

        // Test non-existent epoch
        let non_existent_epoch = storage
            .get_group_exporter_secret(&mls_group_id, 999)
            .unwrap();
        assert!(non_existent_epoch.is_none());

        // Test non-existent group
        let non_existent_group_id = GroupId::from_slice(&[9, 9, 9, 9]);
        let result = storage.get_group_exporter_secret(&non_existent_group_id, 0);
        assert!(result.is_err());

        // Test overwriting an existing secret
        let updated_secret_0 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 0,
            secret: Secret::new([0u8; 32]),
        };
        storage
            .save_group_exporter_secret(updated_secret_0.clone())
            .unwrap();

        let retrieved_updated_secret = storage
            .get_group_exporter_secret(&mls_group_id, 0)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_updated_secret, updated_secret_0);

        // Test trying to save a secret for a non-existent group
        let invalid_secret = GroupExporterSecret {
            mls_group_id: non_existent_group_id.clone(),
            epoch: 0,
            secret: Secret::new([0u8; 32]),
        };
        let result = storage.save_group_exporter_secret(invalid_secret);
        assert!(result.is_err());
    }

    // ========================================
    // Encryption tests
    // ========================================

    mod encryption_tests {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        use std::thread;

        use mdk_storage_traits::Secret;
        use mdk_storage_traits::groups::GroupStorage;
        use mdk_storage_traits::groups::types::{Group, GroupExporterSecret, GroupState};
        use mdk_storage_traits::messages::MessageStorage;
        use mdk_storage_traits::test_utils::cross_storage::{
            create_test_group, create_test_message, create_test_welcome,
        };
        use mdk_storage_traits::welcomes::WelcomeStorage;
        use nostr::EventId;

        use super::*;
        use crate::test_utils::ensure_mock_store;

        #[test]
        fn test_encrypted_storage_creation() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("encrypted.db");

            let config = EncryptionConfig::generate().unwrap();
            let storage = MdkSqliteStorage::new_with_key(&db_path, config);
            assert!(storage.is_ok());

            // Verify file exists
            assert!(db_path.exists());

            // Verify the database is encrypted (file header is not plain SQLite)
            assert!(
                encryption::is_database_encrypted(&db_path).unwrap(),
                "Database should be encrypted"
            );
        }

        #[test]
        fn test_encrypted_storage_reopen_with_correct_key() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("encrypted_reopen.db");

            // Create with a key
            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();
                // Do some operations to ensure the database is properly initialized
                let _ = storage.backend();
            }

            // Reopen with the same key
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2);
            assert!(
                storage2.is_ok(),
                "Should be able to reopen with correct key"
            );
        }

        #[test]
        fn test_encrypted_storage_wrong_key_fails() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("encrypted_wrong_key.db");

            // Create with key1
            let config1 = EncryptionConfig::generate().unwrap();
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config1).unwrap();
                drop(storage);
            }

            // Try to open with a different key
            let config2 = EncryptionConfig::generate().unwrap();
            let result = MdkSqliteStorage::new_with_key(&db_path, config2);

            assert!(result.is_err(), "Opening with wrong key should fail");

            // Verify it's the correct error type
            match result {
                Err(error::Error::WrongEncryptionKey) => {}
                Err(e) => panic!("Expected WrongEncryptionKey error, got: {:?}", e),
                Ok(_) => panic!("Expected error but got success"),
            }
        }

        #[test]
        fn test_unencrypted_cannot_read_encrypted() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("encrypted_only.db");

            // Create encrypted database
            let config = EncryptionConfig::generate().unwrap();
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();
                drop(storage);
            }

            // Try to open without encryption
            let result = MdkSqliteStorage::new_unencrypted(&db_path);

            // This should fail because the database is encrypted
            assert!(
                result.is_err(),
                "Opening encrypted database without key should fail"
            );
        }

        #[test]
        fn test_encrypted_storage_data_persistence() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("encrypted_persist.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            // Create storage and save a group
            let mls_group_id = GroupId::from_slice(&[1, 2, 3, 4]);
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let group = Group {
                    mls_group_id: mls_group_id.clone(),
                    nostr_group_id: [0u8; 32],
                    name: "Encrypted Group".to_string(),
                    description: "Testing encrypted persistence".to_string(),
                    admin_pubkeys: BTreeSet::new(),
                    last_message_id: None,
                    last_message_at: None,
                    epoch: 0,
                    state: GroupState::Active,
                    image_hash: None,
                    image_key: None,
                    image_nonce: None,
                };

                storage.save_group(group).unwrap();
            }

            // Reopen and verify the data is still there
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            let found_group = storage2.find_group_by_mls_group_id(&mls_group_id).unwrap();
            assert!(found_group.is_some());
            assert_eq!(found_group.unwrap().name, "Encrypted Group");
        }

        #[test]
        fn test_file_permissions_are_secure() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("secure_perms.db");

            let config = EncryptionConfig::generate().unwrap();
            let _storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

            // On Unix, verify permissions are restrictive
            #[cfg(unix)]
            {
                let metadata = std::fs::metadata(&db_path).unwrap();
                let mode = metadata.permissions().mode();

                // Check that group and world permissions are not set
                assert_eq!(
                    mode & 0o077,
                    0,
                    "Database file should have owner-only permissions, got {:o}",
                    mode & 0o777
                );
            }
        }

        #[test]
        fn test_encrypted_storage_multiple_groups() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("multi_groups.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            // Create storage and save multiple groups
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                for i in 0..5 {
                    let mls_group_id = GroupId::from_slice(&[i; 8]);
                    let mut group = create_test_group(mls_group_id);
                    group.name = format!("Group {}", i);
                    group.description = format!("Description {}", i);
                    storage.save_group(group).unwrap();
                }
            }

            // Reopen and verify all groups
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            let groups = storage2.all_groups().unwrap();
            assert_eq!(groups.len(), 5);

            for i in 0..5u8 {
                let mls_group_id = GroupId::from_slice(&[i; 8]);
                let group = storage2
                    .find_group_by_mls_group_id(&mls_group_id)
                    .unwrap()
                    .unwrap();
                assert_eq!(group.name, format!("Group {}", i));
            }
        }

        #[test]
        fn test_encrypted_storage_messages() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("messages.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            let mls_group_id = GroupId::from_slice(&[1, 2, 3, 4]);

            // Create storage, group, and messages
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let group = create_test_group(mls_group_id.clone());
                storage.save_group(group).unwrap();

                // Save a message
                let event_id = EventId::all_zeros();
                let mut message = create_test_message(mls_group_id.clone(), event_id);
                message.content = "Test message content".to_string();
                storage.save_message(message).unwrap();
            }

            // Reopen and verify messages
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            let messages = storage2.messages(&mls_group_id, None).unwrap();
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].content, "Test message content");
        }

        #[test]
        fn test_encrypted_storage_welcomes() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("welcomes.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            let mls_group_id = GroupId::from_slice(&[5, 6, 7, 8]);

            // Create storage, group, and welcome
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let group = create_test_group(mls_group_id.clone());
                storage.save_group(group).unwrap();

                let event_id = EventId::all_zeros();
                let welcome = create_test_welcome(mls_group_id.clone(), event_id);
                storage.save_welcome(welcome).unwrap();
            }

            // Reopen and verify
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            let welcomes = storage2.pending_welcomes(None).unwrap();
            assert_eq!(welcomes.len(), 1);
        }

        #[test]
        fn test_encrypted_storage_exporter_secrets() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("exporter_secrets.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            let mls_group_id = GroupId::from_slice(&[10, 20, 30, 40]);

            // Create storage, group, and exporter secrets for multiple epochs
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let group = Group {
                    mls_group_id: mls_group_id.clone(),
                    nostr_group_id: [0u8; 32],
                    name: "Exporter Secret Test".to_string(),
                    description: "Testing exporter secrets".to_string(),
                    admin_pubkeys: BTreeSet::new(),
                    last_message_id: None,
                    last_message_at: None,
                    epoch: 5,
                    state: GroupState::Active,
                    image_hash: None,
                    image_key: None,
                    image_nonce: None,
                };
                storage.save_group(group).unwrap();

                // Save secrets for epochs 0-5
                for epoch in 0..=5u64 {
                    let secret = GroupExporterSecret {
                        mls_group_id: mls_group_id.clone(),
                        epoch,
                        secret: Secret::new([epoch as u8; 32]),
                    };
                    storage.save_group_exporter_secret(secret).unwrap();
                }
            }

            // Reopen and verify all secrets
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            for epoch in 0..=5u64 {
                let secret = storage2
                    .get_group_exporter_secret(&mls_group_id, epoch)
                    .unwrap()
                    .unwrap();
                assert_eq!(secret.epoch, epoch);
                assert_eq!(secret.secret[0], epoch as u8);
            }

            // Non-existent epoch should return None
            let missing = storage2
                .get_group_exporter_secret(&mls_group_id, 999)
                .unwrap();
            assert!(missing.is_none());
        }

        #[test]
        fn test_encrypted_storage_with_nested_directory() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir
                .path()
                .join("deep")
                .join("nested")
                .join("path")
                .join("db.sqlite");

            let config = EncryptionConfig::generate().unwrap();
            let storage = MdkSqliteStorage::new_with_key(&db_path, config);
            assert!(storage.is_ok());

            // Verify the nested directories were created
            assert!(db_path.parent().unwrap().exists());
            assert!(db_path.exists());

            // Verify the database is encrypted
            assert!(encryption::is_database_encrypted(&db_path).unwrap());
        }

        #[test]
        fn test_encrypted_unencrypted_incompatibility() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("compat_test.db");

            // First create an unencrypted database
            {
                let _storage = MdkSqliteStorage::new_unencrypted(&db_path).unwrap();
            }

            // The database should NOT be encrypted
            assert!(!encryption::is_database_encrypted(&db_path).unwrap());

            // Now create an encrypted database at a different path
            let encrypted_path = temp_dir.path().join("compat_encrypted.db");
            {
                let config = EncryptionConfig::generate().unwrap();
                let _storage = MdkSqliteStorage::new_with_key(&encrypted_path, config).unwrap();
            }

            // The encrypted database SHOULD be encrypted
            assert!(encryption::is_database_encrypted(&encrypted_path).unwrap());
        }

        #[test]
        fn test_new_on_unencrypted_database_returns_correct_error() {
            // This test verifies that when MdkSqliteStorage::new() is called on an
            // existing unencrypted database (created with new_unencrypted()), the code
            // returns UnencryptedDatabaseWithEncryption rather than the misleading
            // KeyringEntryMissingForExistingDatabase error.

            // Initialize the mock keyring store for this test
            ensure_mock_store();

            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("unencrypted_then_new.db");

            // Create an unencrypted database first
            {
                let _storage = MdkSqliteStorage::new_unencrypted(&db_path).unwrap();
            }

            // Verify the database is unencrypted
            assert!(!encryption::is_database_encrypted(&db_path).unwrap());

            // Now try to open it with new() - should fail with UnencryptedDatabaseWithEncryption
            let result = MdkSqliteStorage::new(&db_path, "com.test.app", "test.key.id");

            assert!(result.is_err());
            match result {
                Err(Error::UnencryptedDatabaseWithEncryption) => {
                    // This is the expected error - the database was created unencrypted
                    // and we're trying to open it with the encrypted constructor
                }
                Err(Error::KeyringEntryMissingForExistingDatabase { .. }) => {
                    panic!(
                        "Got KeyringEntryMissingForExistingDatabase but should have gotten \
                         UnencryptedDatabaseWithEncryption. The database is unencrypted, not \
                         encrypted with a missing key."
                    );
                }
                Err(other) => {
                    panic!("Unexpected error: {:?}", other);
                }
                Ok(_) => {
                    panic!("Expected an error but got Ok");
                }
            }
        }

        #[test]
        fn test_new_with_key_on_unencrypted_database_returns_correct_error() {
            // This test verifies that when MdkSqliteStorage::new_with_key() is called on an
            // existing unencrypted database, the code returns UnencryptedDatabaseWithEncryption
            // rather than WrongEncryptionKey (which would be misleading).

            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("unencrypted_then_new_with_key.db");

            // Create an unencrypted database first
            {
                let _storage = MdkSqliteStorage::new_unencrypted(&db_path).unwrap();
            }

            // Verify the database is unencrypted
            assert!(!encryption::is_database_encrypted(&db_path).unwrap());

            // Now try to open it with new_with_key() - should fail with
            // UnencryptedDatabaseWithEncryption
            let config = EncryptionConfig::generate().unwrap();
            let result = MdkSqliteStorage::new_with_key(&db_path, config);

            assert!(result.is_err());
            match result {
                Err(Error::UnencryptedDatabaseWithEncryption) => {
                    // This is the expected error - the database was created unencrypted
                    // and we're trying to open it with an encryption key
                }
                Err(Error::WrongEncryptionKey) => {
                    panic!(
                        "Got WrongEncryptionKey but should have gotten \
                         UnencryptedDatabaseWithEncryption. The database is unencrypted, not \
                         encrypted with a different key."
                    );
                }
                Err(other) => {
                    panic!("Unexpected error: {:?}", other);
                }
                Ok(_) => {
                    panic!("Expected an error but got Ok");
                }
            }
        }

        #[test]
        fn test_encrypted_storage_large_data() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("large_data.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            let mls_group_id = GroupId::from_slice(&[99; 8]);

            // Create storage with a large message
            let large_content = "x".repeat(10_000);
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let mut group = create_test_group(mls_group_id.clone());
                group.name = "Large Data Test".to_string();
                group.description = "Testing large data".to_string();
                storage.save_group(group).unwrap();

                let event_id = EventId::all_zeros();
                let mut message = create_test_message(mls_group_id.clone(), event_id);
                message.content = large_content.clone();
                storage.save_message(message).unwrap();
            }

            // Reopen and verify
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            let messages = storage2.messages(&mls_group_id, None).unwrap();
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].content, large_content);
        }

        #[test]
        fn test_encrypted_storage_concurrent_reads() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("concurrent.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            let mls_group_id = GroupId::from_slice(&[77; 8]);

            // Create and populate the database
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let mut group = create_test_group(mls_group_id.clone());
                group.name = "Concurrent Test".to_string();
                group.description = "Testing concurrent access".to_string();
                storage.save_group(group).unwrap();
            }

            // Open two connections simultaneously
            let config1 = EncryptionConfig::new(key);
            let config2 = EncryptionConfig::new(key);

            let storage1 = MdkSqliteStorage::new_with_key(&db_path, config1).unwrap();
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            // Both should be able to read
            let group1 = storage1
                .find_group_by_mls_group_id(&mls_group_id)
                .unwrap()
                .unwrap();
            let group2 = storage2
                .find_group_by_mls_group_id(&mls_group_id)
                .unwrap()
                .unwrap();

            assert_eq!(group1.name, group2.name);
        }

        #[cfg(unix)]
        #[test]
        fn test_encrypted_storage_sidecar_file_permissions() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("sidecar_test.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            // Create and use the database to trigger WAL file creation
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                // Create multiple groups to generate some WAL activity
                for i in 0..10 {
                    let mls_group_id = GroupId::from_slice(&[i; 8]);
                    let mut group = create_test_group(mls_group_id);
                    group.name = format!("Group {}", i);
                    group.description = format!("Description {}", i);
                    storage.save_group(group).unwrap();
                }
            }

            // Reopen to ensure any sidecar files exist
            let config2 = EncryptionConfig::new(key);
            let _storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            // Check main database file permissions
            let db_metadata = std::fs::metadata(&db_path).unwrap();
            let db_mode = db_metadata.permissions().mode();
            assert_eq!(
                db_mode & 0o077,
                0,
                "Database file should have owner-only permissions, got {:o}",
                db_mode & 0o777
            );

            // Check sidecar file permissions if they exist
            let sidecar_suffixes = ["-wal", "-shm", "-journal"];
            for suffix in &sidecar_suffixes {
                let sidecar_path = temp_dir.path().join(format!("sidecar_test.db{}", suffix));
                if sidecar_path.exists() {
                    let metadata = std::fs::metadata(&sidecar_path).unwrap();
                    let mode = metadata.permissions().mode();
                    assert_eq!(
                        mode & 0o077,
                        0,
                        "Sidecar file {} should have owner-only permissions, got {:o}",
                        suffix,
                        mode & 0o777
                    );
                }
            }
        }

        #[test]
        fn test_encryption_config_key_is_accessible() {
            let key = [0xDE; 32];
            let config = EncryptionConfig::new(key);

            // Verify we can access the key
            assert_eq!(config.key().len(), 32);
            assert_eq!(config.key()[0], 0xDE);
            assert_eq!(config.key()[31], 0xDE);
        }

        #[test]
        fn test_encrypted_storage_empty_group_name() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("empty_name.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            let mls_group_id = GroupId::from_slice(&[0xAB; 8]);

            // Create storage with empty name
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let mut group = create_test_group(mls_group_id.clone());
                group.name = String::new();
                group.description = String::new();
                storage.save_group(group).unwrap();
            }

            // Reopen and verify
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            let group = storage2
                .find_group_by_mls_group_id(&mls_group_id)
                .unwrap()
                .unwrap();
            assert!(group.name.is_empty());
            assert!(group.description.is_empty());
        }

        #[test]
        fn test_encrypted_storage_unicode_content() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("unicode.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            let mls_group_id = GroupId::from_slice(&[0xCD; 8]);
            let unicode_content = "Hello 世界! 🎉 Ñoño مرحبا Привет 日本語 한국어 ελληνικά";

            // Create storage with unicode content
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();

                let mut group = create_test_group(mls_group_id.clone());
                group.name = "Тест группа 测试组".to_string();
                group.description = "描述 описание".to_string();
                storage.save_group(group).unwrap();

                let event_id = EventId::all_zeros();
                let mut message = create_test_message(mls_group_id.clone(), event_id);
                message.content = unicode_content.to_string();
                storage.save_message(message).unwrap();
            }

            // Reopen and verify
            let config2 = EncryptionConfig::new(key);
            let storage2 = MdkSqliteStorage::new_with_key(&db_path, config2).unwrap();

            let group = storage2
                .find_group_by_mls_group_id(&mls_group_id)
                .unwrap()
                .unwrap();
            assert_eq!(group.name, "Тест группа 测试组");
            assert_eq!(group.description, "描述 описание");

            let messages = storage2.messages(&mls_group_id, None).unwrap();
            assert_eq!(messages[0].content, unicode_content);
        }

        /// Test that opening an existing database fails when keyring entry is missing.
        ///
        /// This verifies the fix for the issue where a missing keyring entry would
        /// cause a new key to be generated instead of failing immediately.
        #[test]
        fn test_existing_db_with_missing_keyring_entry_fails() {
            ensure_mock_store();

            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("missing_key_test.db");

            let service_id = "test.mdk.storage.missingkey";
            let db_key_id = "test.key.missingkeytest";

            // Clean up any existing key
            let _ = keyring::delete_db_key(service_id, db_key_id);

            // First, create an encrypted database using automatic key management
            {
                let storage = MdkSqliteStorage::new(&db_path, service_id, db_key_id);
                assert!(storage.is_ok(), "Should create database successfully");
            }

            // Verify database exists
            assert!(db_path.exists(), "Database file should exist");

            // Delete the keyring entry to simulate key loss
            keyring::delete_db_key(service_id, db_key_id).unwrap();

            // Verify keyring entry is gone
            let key_check = keyring::get_db_key(service_id, db_key_id).unwrap();
            assert!(key_check.is_none(), "Key should be deleted");

            // Now try to open the existing database - this should fail with a clear error
            // instead of generating a new key
            let result = MdkSqliteStorage::new(&db_path, service_id, db_key_id);

            assert!(result.is_err(), "Should fail when keyring entry is missing");

            match result {
                Err(error::Error::KeyringEntryMissingForExistingDatabase {
                    db_path: err_path,
                    service_id: err_service,
                    db_key_id: err_key,
                }) => {
                    assert!(
                        err_path.contains("missing_key_test.db"),
                        "Error should contain database path"
                    );
                    assert_eq!(err_service, service_id);
                    assert_eq!(err_key, db_key_id);
                }
                Err(e) => panic!(
                    "Expected KeyringEntryMissingForExistingDatabase error, got: {:?}",
                    e
                ),
                Ok(_) => panic!("Expected error but got success"),
            }

            // Verify that no new key was stored in the keyring
            let key_after = keyring::get_db_key(service_id, db_key_id).unwrap();
            assert!(
                key_after.is_none(),
                "No new key should have been stored in keyring"
            );
        }

        /// Test that creating a new database with automatic key management works.
        #[test]
        fn test_new_db_with_keyring_creates_key() {
            ensure_mock_store();

            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("new_db_keyring.db");

            let service_id = "test.mdk.storage.newdb";
            let db_key_id = "test.key.newdbtest";

            // Clean up any existing key
            let _ = keyring::delete_db_key(service_id, db_key_id);

            // Verify database doesn't exist
            assert!(!db_path.exists(), "Database should not exist yet");

            // Create a new database - should succeed and create a key
            let storage = MdkSqliteStorage::new(&db_path, service_id, db_key_id);
            assert!(storage.is_ok(), "Should create database successfully");

            // Verify database exists
            assert!(db_path.exists(), "Database file should exist");

            // Verify key was stored
            let key = keyring::get_db_key(service_id, db_key_id).unwrap();
            assert!(key.is_some(), "Key should be stored in keyring");

            // Verify database is encrypted
            assert!(
                encryption::is_database_encrypted(&db_path).unwrap(),
                "Database should be encrypted"
            );

            // Clean up
            drop(storage);
            keyring::delete_db_key(service_id, db_key_id).unwrap();
        }

        /// Test that reopening a database with keyring works when the key is present.
        #[test]
        fn test_reopen_db_with_keyring_succeeds() {
            ensure_mock_store();

            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("reopen_keyring.db");

            let service_id = "test.mdk.storage.reopen";
            let db_key_id = "test.key.reopentest";

            // Clean up any existing key
            let _ = keyring::delete_db_key(service_id, db_key_id);

            let mls_group_id = GroupId::from_slice(&[0xAA; 8]);

            // Create database and save a group
            {
                let storage = MdkSqliteStorage::new(&db_path, service_id, db_key_id).unwrap();

                let mut group = create_test_group(mls_group_id.clone());
                group.name = "Keyring Reopen Test".to_string();
                storage.save_group(group).unwrap();
            }

            // Reopen with the same keyring entry - should succeed
            let storage2 = MdkSqliteStorage::new(&db_path, service_id, db_key_id);
            assert!(storage2.is_ok(), "Should reopen database successfully");

            // Verify data persisted
            let storage2 = storage2.unwrap();
            let group = storage2
                .find_group_by_mls_group_id(&mls_group_id)
                .unwrap()
                .unwrap();
            assert_eq!(group.name, "Keyring Reopen Test");

            // Clean up
            drop(storage2);
            keyring::delete_db_key(service_id, db_key_id).unwrap();
        }

        /// Test concurrent access to encrypted database with same key.
        #[test]
        fn test_concurrent_encrypted_access_same_key() {
            let temp_dir = tempdir().unwrap();
            let db_path = temp_dir.path().join("concurrent_encrypted.db");

            let config = EncryptionConfig::generate().unwrap();
            let key = *config.key();

            // Create database with initial data
            {
                let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();
                let group = create_test_group(GroupId::from_slice(&[1, 2, 3, 4]));
                storage.save_group(group).unwrap();
            }

            // Spawn multiple threads that all read from the database
            let num_threads = 5;
            let handles: Vec<_> = (0..num_threads)
                .map(|_| {
                    let db_path = db_path.clone();
                    thread::spawn(move || {
                        let config = EncryptionConfig::new(key);
                        let storage = MdkSqliteStorage::new_with_key(&db_path, config).unwrap();
                        let groups = storage.all_groups().unwrap();
                        assert_eq!(groups.len(), 1);
                        groups
                    })
                })
                .collect();

            // All threads should succeed
            for handle in handles {
                let groups = handle.join().unwrap();
                assert_eq!(groups.len(), 1);
            }
        }

        /// Test multiple databases with different keys in same directory.
        #[test]
        fn test_multiple_encrypted_databases_different_keys() {
            let temp_dir = tempdir().unwrap();

            // Create multiple databases with different keys
            let db1_path = temp_dir.path().join("db1.db");
            let db2_path = temp_dir.path().join("db2.db");
            let db3_path = temp_dir.path().join("db3.db");

            let config1 = EncryptionConfig::generate().unwrap();
            let config2 = EncryptionConfig::generate().unwrap();
            let config3 = EncryptionConfig::generate().unwrap();

            let key1 = *config1.key();
            let key2 = *config2.key();
            let key3 = *config3.key();

            // Create and populate each database
            {
                let storage1 = MdkSqliteStorage::new_with_key(&db1_path, config1).unwrap();
                let mut group1 = create_test_group(GroupId::from_slice(&[1]));
                group1.name = "Database 1".to_string();
                storage1.save_group(group1).unwrap();

                let storage2 = MdkSqliteStorage::new_with_key(&db2_path, config2).unwrap();
                let mut group2 = create_test_group(GroupId::from_slice(&[2]));
                group2.name = "Database 2".to_string();
                storage2.save_group(group2).unwrap();

                let storage3 = MdkSqliteStorage::new_with_key(&db3_path, config3).unwrap();
                let mut group3 = create_test_group(GroupId::from_slice(&[3]));
                group3.name = "Database 3".to_string();
                storage3.save_group(group3).unwrap();
            }

            // Reopen each with correct key
            let config1_reopen = EncryptionConfig::new(key1);
            let config2_reopen = EncryptionConfig::new(key2);
            let config3_reopen = EncryptionConfig::new(key3);

            let storage1 = MdkSqliteStorage::new_with_key(&db1_path, config1_reopen).unwrap();
            let storage2 = MdkSqliteStorage::new_with_key(&db2_path, config2_reopen).unwrap();
            let storage3 = MdkSqliteStorage::new_with_key(&db3_path, config3_reopen).unwrap();

            // Verify each database has correct data
            let group1 = storage1
                .find_group_by_mls_group_id(&GroupId::from_slice(&[1]))
                .unwrap()
                .unwrap();
            assert_eq!(group1.name, "Database 1");

            let group2 = storage2
                .find_group_by_mls_group_id(&GroupId::from_slice(&[2]))
                .unwrap()
                .unwrap();
            assert_eq!(group2.name, "Database 2");

            let group3 = storage3
                .find_group_by_mls_group_id(&GroupId::from_slice(&[3]))
                .unwrap()
                .unwrap();
            assert_eq!(group3.name, "Database 3");

            // Verify wrong keys don't work
            let wrong_config = EncryptionConfig::new(key1);
            let result = MdkSqliteStorage::new_with_key(&db2_path, wrong_config);
            assert!(result.is_err());
        }
    }
}
