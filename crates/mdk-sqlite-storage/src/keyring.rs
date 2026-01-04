//! Keyring integration for secure encryption key storage.
//!
//! This module provides integration with the `keyring-core` ecosystem for
//! securely storing database encryption keys in platform-native credential stores.
//!
//! # Platform Setup
//!
//! Before using MDK's encrypted storage, the host application must initialize
//! a platform-specific keyring store. MDK uses the `keyring-core` API directly.
//!
//! ## macOS / iOS
//!
//! ```ignore
//! use apple_native_keyring_store::AppleStore;
//! keyring_core::set_default_store(AppleStore::new());
//! ```
//!
//! ## Windows
//!
//! ```ignore
//! use windows_native_keyring_store::WindowsStore;
//! keyring_core::set_default_store(WindowsStore::new());
//! ```
//!
//! ## Linux
//!
//! ```ignore
//! use linux_keyutils_keyring_store::KeyutilsStore;
//! keyring_core::set_default_store(KeyutilsStore::new());
//! ```
//!
//! ## Android (requires initialization from Kotlin)
//!
//! See the MDK documentation for Android-specific setup instructions.

use std::sync::{Mutex, OnceLock};

use keyring_core::{Entry, Error as KeyringError};

use crate::encryption::EncryptionConfig;
use crate::error::Error;

/// Lock to coordinate key generation within a single process.
///
/// This ensures that if multiple threads try to get-or-create the same key
/// simultaneously, only one will generate and store it.
static KEY_GENERATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Gets an existing database encryption key or generates and stores a new one.
///
/// This function uses the `keyring-core` API to securely store encryption keys
/// in the platform's native credential store (Keychain, Keystore, etc.).
///
/// # Arguments
///
/// * `service_id` - A stable, host-defined application identifier (e.g., reverse-DNS
///   like `"com.example.myapp"`). This should be unique per application to avoid
///   collisions with other apps.
/// * `db_key_id` - A stable identifier for this database's key (e.g., `"mdk.db.key.default"`
///   or `"mdk.db.key.<profile_id>"`).
///
/// # Key Generation
///
/// If no key exists for the given identifiers, a new 32-byte key is generated
/// using `getrandom` and stored securely.
///
/// # Errors
///
/// Returns an error if:
/// - No keyring store has been initialized (call platform-specific store setup first)
/// - The keyring store is unavailable or inaccessible
/// - Key generation fails
///
/// # Thread Safety
///
/// This function uses an in-process mutex to coordinate key generation. If multiple
/// threads call this function simultaneously for the same key, only one will generate
/// and store the key.
///
/// **Note:** Cross-process coordination is not provided. If your application can
/// start multiple processes that access the same database concurrently, you should
/// provide higher-level coordination.
pub fn get_or_create_db_key(service_id: &str, db_key_id: &str) -> Result<EncryptionConfig, Error> {
    // Acquire lock to prevent race conditions during key generation
    let lock = KEY_GENERATION_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|e| Error::Keyring(format!("Failed to acquire key generation lock: {}", e)))?;

    let entry = Entry::new(service_id, db_key_id).map_err(|e| {
        Error::Keyring(format!(
            "Failed to create keyring entry for service='{}', key='{}': {}",
            service_id, db_key_id, e
        ))
    })?;

    // Try to get existing key
    match entry.get_secret() {
        Ok(secret) => {
            // Key exists, validate and return it
            EncryptionConfig::from_slice(&secret).map_err(|e| {
                Error::Keyring(format!(
                    "Stored key has invalid length (expected 32 bytes): {}",
                    e
                ))
            })
        }
        Err(KeyringError::NoEntry) => {
            // Key doesn't exist, generate a new one
            tracing::info!(
                service_id = service_id,
                db_key_id = db_key_id,
                "Generating new database encryption key"
            );

            let config = EncryptionConfig::generate()?;

            // Store the new key
            entry.set_secret(config.key()).map_err(|e| {
                Error::Keyring(format!("Failed to store encryption key in keyring: {}", e))
            })?;

            Ok(config)
        }
        Err(KeyringError::NoStorageAccess(err)) => {
            Err(Error::KeyringNotInitialized(err.to_string()))
        }
        Err(e) => Err(Error::Keyring(format!(
            "Failed to retrieve encryption key from keyring: {}",
            e
        ))),
    }
}

/// Deletes a database encryption key from the keyring.
///
/// This is useful when you want to completely remove a database and its key,
/// or when re-keying a database.
///
/// # Arguments
///
/// * `service_id` - The service identifier used when creating the key
/// * `db_key_id` - The key identifier used when creating the key
///
/// # Errors
///
/// Returns an error if:
/// - The keyring is unavailable
/// - The key cannot be deleted (permissions, etc.)
///
/// Note: This function succeeds silently if the key doesn't exist.
pub fn delete_db_key(service_id: &str, db_key_id: &str) -> Result<(), Error> {
    let entry = Entry::new(service_id, db_key_id).map_err(|e| {
        Error::Keyring(format!(
            "Failed to create keyring entry for deletion: {}",
            e
        ))
    })?;

    match entry.delete_credential() {
        Ok(()) => {
            tracing::info!(
                service_id = service_id,
                db_key_id = db_key_id,
                "Deleted database encryption key from keyring"
            );
            Ok(())
        }
        Err(KeyringError::NoEntry) => {
            // Key doesn't exist, nothing to delete
            Ok(())
        }
        Err(e) => Err(Error::Keyring(format!(
            "Failed to delete encryption key from keyring: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests require a keyring store to be initialized.
    // In CI/testing environments, use keyring-core's mock store:
    //
    // use keyring_core::mock::MockCredentialStore;
    // keyring_core::set_default_store(MockCredentialStore::new());
    //
    // For now, we skip these tests if no store is available.

    use super::*;

    /// Helper to check if a keyring store is available
    fn keyring_available() -> bool {
        // Try to create an entry - this will fail if no store is set
        Entry::new("test.mdk.keyring", "test.availability").is_ok()
    }

    #[test]
    fn test_get_or_create_generates_key_if_missing() {
        if !keyring_available() {
            eprintln!("Skipping test: no keyring store available");
            return;
        }

        let service_id = "test.mdk.storage";
        let db_key_id = "test.key.generate";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Get or create should generate a new key
        let config1 = get_or_create_db_key(service_id, db_key_id).unwrap();
        assert_eq!(config1.key().len(), 32);

        // Calling again should return the same key
        let config2 = get_or_create_db_key(service_id, db_key_id).unwrap();
        assert_eq!(config1.key(), config2.key());

        // Clean up
        delete_db_key(service_id, db_key_id).unwrap();
    }

    #[test]
    fn test_delete_nonexistent_key_succeeds() {
        if !keyring_available() {
            eprintln!("Skipping test: no keyring store available");
            return;
        }

        // Deleting a key that doesn't exist should succeed
        let result = delete_db_key("test.mdk.storage", "test.nonexistent.key");
        assert!(result.is_ok());
    }
}
