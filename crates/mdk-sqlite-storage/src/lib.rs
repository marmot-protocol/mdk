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
//! use mdk_sqlite_storage::{MdkSqliteStorage, EncryptionConfig};
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

use std::path::{Path, PathBuf};
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
mod validation;
mod welcomes;

pub use self::encryption::EncryptionConfig;
use self::error::Error;
use self::permissions::{precreate_secure_database_file, set_secure_file_permissions};

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
    /// Path to the database file (None for in-memory databases)
    #[allow(dead_code)]
    db_path: Option<PathBuf>,
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
        let config = keyring::get_or_create_db_key(service_id, db_key_id)?;
        Self::new_internal(file_path, Some(config))
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
    /// - The database file cannot be created or opened
    /// - File permissions cannot be set
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mdk_sqlite_storage::{MdkSqliteStorage, EncryptionConfig};
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
    fn new_internal<P>(file_path: P, encryption_config: Option<EncryptionConfig>) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let file_path = file_path.as_ref();
        let db_path = file_path.to_path_buf();

        // Pre-create database file with secure permissions to avoid permission race
        precreate_secure_database_file(file_path)?;

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
            db_path: Some(db_path),
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
    fn apply_secure_permissions(db_path: &Path) -> Result<(), Error> {
        // Skip special SQLite paths (in-memory databases, etc.)
        let path_str = db_path.to_string_lossy();
        if path_str.is_empty() || path_str == ":memory:" || path_str.starts_with(':') {
            return Ok(());
        }

        // Apply to main database file
        set_secure_file_permissions(db_path)?;

        // Apply to common SQLite sidecar files if they exist
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
            db_path: None,
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
        use mdk_storage_traits::groups::GroupStorage;
        use mdk_storage_traits::groups::types::{Group, GroupExporterSecret, GroupState};

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
            secret: [0u8; 32],
        };

        let secret_epoch_1 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 1,
            secret: [0u8; 32],
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
            secret: [0u8; 32],
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
            secret: [0u8; 32],
        };
        let result = storage.save_group_exporter_secret(invalid_secret);
        assert!(result.is_err());
    }

    // ========================================
    // Encryption tests
    // ========================================

    mod encryption_tests {
        use super::*;

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
            assert!(storage2.is_ok(), "Should be able to reopen with correct key");
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

            assert!(
                result.is_err(),
                "Opening with wrong key should fail"
            );

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
            use mdk_storage_traits::groups::GroupStorage;
            use mdk_storage_traits::groups::types::{Group, GroupState};

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

            let found_group = storage2
                .find_group_by_mls_group_id(&mls_group_id)
                .unwrap();
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
                use std::os::unix::fs::PermissionsExt;
                let metadata = std::fs::metadata(&db_path).unwrap();
                let mode = metadata.permissions().mode();

                // Check that group and world permissions are not set
                assert_eq!(
                    mode & 0o077, 0,
                    "Database file should have owner-only permissions, got {:o}",
                    mode & 0o777
                );
            }
        }
    }
}
