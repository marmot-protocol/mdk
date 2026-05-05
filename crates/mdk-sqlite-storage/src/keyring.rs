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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use keyring_core::{Entry, Error as KeyringError};

use crate::encryption::EncryptionConfig;
use crate::error::Error;

/// Lock to coordinate key generation within a single process.
///
/// This ensures that if multiple threads try to get-or-create the same key
/// simultaneously, only one will generate and store it.
static KEY_GENERATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

// v1 stores the raw 32-byte SQLCipher key as RFC 4648 base64.
const DB_KEY_KEYRING_PREFIX: &str = "mdk-sqlite-key-v1:";

enum DecodedDbKey {
    Current(EncryptionConfig),
    LegacyRaw(EncryptionConfig),
}

fn encode_db_key_for_keyring(config: &EncryptionConfig) -> Vec<u8> {
    format!("{DB_KEY_KEYRING_PREFIX}{}", BASE64.encode(config.key())).into_bytes()
}

/// Decode current prefixed payloads first; non-UTF-8 payloads and UTF-8 payloads
/// without the prefix are both handled by the legacy raw-key path.
fn decode_db_key_from_keyring(secret: &[u8]) -> Result<DecodedDbKey, Error> {
    match std::str::from_utf8(secret) {
        Ok(secret_text) => match secret_text.strip_prefix(DB_KEY_KEYRING_PREFIX) {
            Some(encoded_key) => decode_current_db_key(encoded_key),
            None => decode_legacy_db_key(secret),
        },
        Err(_) => decode_legacy_db_key(secret),
    }
}

fn decode_current_db_key(encoded_key: &str) -> Result<DecodedDbKey, Error> {
    let key = BASE64.decode(encoded_key).map_err(|_| {
        Error::Keyring("Stored key has invalid encoded keyring payload".to_string())
    })?;
    let config = EncryptionConfig::from_slice(&key).map_err(|e| {
        Error::Keyring(format!(
            "Stored key has invalid length after decoding encoded keyring payload: {}",
            e
        ))
    })?;
    Ok(DecodedDbKey::Current(config))
}

fn decode_legacy_db_key(secret: &[u8]) -> Result<DecodedDbKey, Error> {
    match secret.len() {
        32 => {
            let config = EncryptionConfig::from_slice(secret)
                .map_err(|e| Error::Keyring(format!("Stored key has invalid length: {}", e)))?;
            Ok(DecodedDbKey::LegacyRaw(config))
        }
        len => Err(Error::Keyring(format!(
            "Stored key has invalid length (expected encoded keyring payload or 32-byte legacy key, got {} bytes)",
            len
        ))),
    }
}

fn save_db_key(entry: &Entry, config: &EncryptionConfig) -> Result<(), Error> {
    let payload = encode_db_key_for_keyring(config);
    entry.set_secret(&payload).map_err(|e| match e {
        KeyringError::NoStorageAccess(err) => Error::KeyringNotInitialized(err.to_string()),
        other => Error::Keyring(format!(
            "Failed to store encryption key in keyring: {}",
            other
        )),
    })
}

/// Gets an existing database encryption key or generates and stores a new one.
///
/// This function uses the `keyring-core` API to securely store encryption keys
/// in the platform's native credential store (Keychain, Keystore, etc.).
/// New keys are stored as UTF-8-safe, version-prefixed base64 payloads. Existing
/// raw 32-byte keyring payloads are still accepted and migrated after a successful
/// read. If that legacy rewrite fails, the existing key is returned and the
/// migration failure is logged so callers are not locked out of readable databases.
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
    // Fast path: check if key exists before acquiring lock.
    // This avoids lock contention in the common case where the key already exists.
    if let Some(config) = get_db_key(service_id, db_key_id)? {
        return Ok(config);
    }

    // Key doesn't exist, acquire lock to prevent race conditions during generation
    let lock = KEY_GENERATION_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|e| Error::Keyring(format!("Failed to acquire key generation lock: {}", e)))?;

    // Double-check after acquiring lock (another thread may have created it)
    if let Some(config) = get_db_key(service_id, db_key_id)? {
        return Ok(config);
    }

    // Key doesn't exist, generate a new one
    tracing::info!(
        service_id = service_id,
        db_key_id = db_key_id,
        "Generating new database encryption key"
    );

    let config = EncryptionConfig::generate()?;

    // Store the new key
    let entry = Entry::new(service_id, db_key_id).map_err(|e| {
        Error::Keyring(format!(
            "Failed to create keyring entry for service='{}', key='{}': {}",
            service_id, db_key_id, e
        ))
    })?;

    save_db_key(&entry, &config)?;

    Ok(config)
}

/// Creates a fresh database encryption key, replacing any existing keyring entry.
///
/// This is used only after the caller has created a new database file and is
/// starting a new database lifecycle. If this function returns an error, callers
/// should remove any precreated empty database file before returning so a retry
/// can attempt fresh creation again rather than treating the orphan file as an
/// existing database.
///
/// # Thread Safety
///
/// This function uses the same in-process mutex as [`get_or_create_db_key`] to
/// coordinate key creation with other threads in this process. Cross-process
/// coordination is not provided, and keyring replacement is delete-then-save
/// rather than an atomic keyring operation. A process crash between those
/// operations can leave no key in the keyring.
pub(crate) fn create_fresh_db_key(
    service_id: &str,
    db_key_id: &str,
) -> Result<EncryptionConfig, Error> {
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

    match entry.delete_credential() {
        Ok(()) => {
            tracing::info!(
                service_id = service_id,
                db_key_id = db_key_id,
                "Deleted stale database encryption key from keyring before fresh database creation"
            );
        }
        Err(KeyringError::NoEntry) => {}
        Err(KeyringError::NoStorageAccess(err)) => {
            return Err(Error::KeyringNotInitialized(err.to_string()));
        }
        Err(e) => {
            return Err(Error::Keyring(format!(
                "Failed to delete stale encryption key from keyring: {}",
                e
            )));
        }
    }

    tracing::info!(
        service_id = service_id,
        db_key_id = db_key_id,
        "Generating new database encryption key"
    );

    let config = EncryptionConfig::generate()?;
    save_db_key(&entry, &config)?;

    Ok(config)
}

/// Gets an existing database encryption key from the keyring.
///
/// Unlike [`get_or_create_db_key`], this function does NOT generate a new key if one
/// doesn't exist. It returns `Ok(None)` if no key is found.
///
/// # Arguments
///
/// * `service_id` - The service identifier used when creating the key
/// * `db_key_id` - The key identifier used when creating the key
///
/// # Returns
///
/// - `Ok(Some(config))` if the key exists
/// - `Ok(None)` if no key exists for the given identifiers
/// - `Err(...)` if the keyring is unavailable or the stored key is invalid
pub fn get_db_key(service_id: &str, db_key_id: &str) -> Result<Option<EncryptionConfig>, Error> {
    let entry = Entry::new(service_id, db_key_id).map_err(|e| {
        Error::Keyring(format!(
            "Failed to create keyring entry for service='{}', key='{}': {}",
            service_id, db_key_id, e
        ))
    })?;

    match entry.get_secret() {
        Ok(secret) => {
            // Key exists, validate and return it
            let config = match decode_db_key_from_keyring(&secret)? {
                DecodedDbKey::Current(config) => config,
                DecodedDbKey::LegacyRaw(config) => {
                    if let Err(e) = save_db_key(&entry, &config) {
                        tracing::warn!(
                            error = %e,
                            "Failed to migrate legacy database encryption key to encoded keyring payload"
                        );
                    }
                    config
                }
            };
            Ok(Some(config))
        }
        Err(KeyringError::NoEntry) => Ok(None),
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
        Err(KeyringError::NoStorageAccess(err)) => {
            Err(Error::KeyringNotInitialized(err.to_string()))
        }
        Err(e) => Err(Error::Keyring(format!(
            "Failed to delete encryption key from keyring: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::{str, thread};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    use super::*;
    use crate::test_utils::ensure_mock_store;

    fn encoded_payload_for_key(key: &[u8; 32]) -> Vec<u8> {
        format!("{DB_KEY_KEYRING_PREFIX}{}", BASE64.encode(key)).into_bytes()
    }

    #[test]
    fn test_get_or_create_generates_key_if_missing() {
        ensure_mock_store();

        let service_id = "test.mdk.storage";
        let db_key_id = "test.key.generate";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Get or create should generate a new key
        let config1 = get_or_create_db_key(service_id, db_key_id).unwrap();
        assert_eq!(config1.key().len(), 32);

        let stored_payload = Entry::new(service_id, db_key_id)
            .unwrap()
            .get_secret()
            .unwrap();
        let stored_payload_text = str::from_utf8(&stored_payload).unwrap();
        assert_ne!(stored_payload.as_slice(), config1.key());
        assert_ne!(stored_payload.len(), 32);
        assert!(stored_payload_text.starts_with(DB_KEY_KEYRING_PREFIX));

        // Calling again should return the same key
        let config2 = get_or_create_db_key(service_id, db_key_id).unwrap();
        assert_eq!(config1.key(), config2.key());

        // Clean up
        delete_db_key(service_id, db_key_id).unwrap();
    }

    #[test]
    fn test_get_db_key_reads_encoded_keyring_payload() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.encoded";
        let db_key_id = "test.key.encoded";
        let config = EncryptionConfig::new([0x42u8; 32]);

        let _ = delete_db_key(service_id, db_key_id);

        let entry = Entry::new(service_id, db_key_id).unwrap();
        entry
            .set_secret(&encoded_payload_for_key(config.key()))
            .unwrap();

        let retrieved = get_db_key(service_id, db_key_id).unwrap().unwrap();
        assert_eq!(retrieved.key(), config.key());

        delete_db_key(service_id, db_key_id).unwrap();
    }

    #[test]
    fn test_get_db_key_migrates_legacy_raw_keyring_payload() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.legacy";
        let db_key_id = "test.key.legacy";
        let legacy_key = [0x7bu8; 32];

        let _ = delete_db_key(service_id, db_key_id);

        let entry = Entry::new(service_id, db_key_id).unwrap();
        entry.set_secret(&legacy_key).unwrap();

        let retrieved = get_db_key(service_id, db_key_id).unwrap().unwrap();
        assert_eq!(retrieved.key(), &legacy_key);

        let stored_payload = entry.get_secret().unwrap();
        let stored_payload_text = str::from_utf8(&stored_payload).unwrap();
        assert_ne!(stored_payload.as_slice(), &legacy_key);
        assert!(stored_payload_text.starts_with(DB_KEY_KEYRING_PREFIX));

        let migrated = get_db_key(service_id, db_key_id).unwrap().unwrap();
        assert_eq!(migrated.key(), &legacy_key);
        assert_eq!(entry.get_secret().unwrap(), stored_payload);

        delete_db_key(service_id, db_key_id).unwrap();
    }

    #[test]
    fn test_get_or_create_with_invalid_encoded_payload_returns_error_without_replacement() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.invalidencoded";
        let db_key_id = "test.key.invalidencoded";
        let invalid_payload = b"mdk-sqlite-key-v1:not-valid-base64!!!";

        let _ = delete_db_key(service_id, db_key_id);

        let entry = Entry::new(service_id, db_key_id).unwrap();
        entry.set_secret(invalid_payload).unwrap();

        let result = get_or_create_db_key(service_id, db_key_id);
        assert!(
            result.is_err(),
            "Should fail when keyring contains invalid encoded key"
        );
        assert!(result.unwrap_err().to_string().contains("encoded"));
        assert_eq!(entry.get_secret().unwrap(), invalid_payload);

        let _ = delete_db_key(service_id, db_key_id);
    }

    #[test]
    fn test_get_db_key_with_invalid_encoded_key_length_returns_error() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.invalidencodedlength";
        let db_key_id = "test.key.invalidencodedlength";
        let invalid_payload = format!("{DB_KEY_KEYRING_PREFIX}{}", BASE64.encode([0x9au8; 31]));

        let _ = delete_db_key(service_id, db_key_id);

        let entry = Entry::new(service_id, db_key_id).unwrap();
        entry.set_secret(invalid_payload.as_bytes()).unwrap();

        let result = get_db_key(service_id, db_key_id);
        assert!(
            result.is_err(),
            "Should fail when encoded keyring payload decodes to wrong length"
        );
        assert!(result.unwrap_err().to_string().contains("invalid length"));

        let _ = delete_db_key(service_id, db_key_id);
    }

    #[test]
    fn test_delete_nonexistent_key_succeeds() {
        ensure_mock_store();

        // Deleting a key that doesn't exist should succeed
        let result = delete_db_key("test.mdk.storage", "test.nonexistent.key");
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_or_create_returns_same_key_on_repeated_calls() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.repeated";
        let db_key_id = "test.key.repeated.calls";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Multiple calls should return the same key
        let configs: Vec<_> = (0..5)
            .map(|_| get_or_create_db_key(service_id, db_key_id).unwrap())
            .collect();

        let first_key = configs[0].key();
        for config in &configs[1..] {
            assert_eq!(config.key(), first_key, "All keys should be identical");
        }

        // Clean up
        delete_db_key(service_id, db_key_id).unwrap();
    }

    #[test]
    fn test_delete_and_recreate_generates_new_key() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.recreate";
        let db_key_id = "test.key.recreate";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Generate first key
        let config1 = get_or_create_db_key(service_id, db_key_id).unwrap();
        let key1 = *config1.key();

        // Delete it
        delete_db_key(service_id, db_key_id).unwrap();

        // Generate new key
        let config2 = get_or_create_db_key(service_id, db_key_id).unwrap();
        let key2 = *config2.key();

        // Keys should be different (with overwhelming probability)
        assert_ne!(
            key1, key2,
            "Regenerated key should be different from original"
        );

        // Clean up
        delete_db_key(service_id, db_key_id).unwrap();
    }

    #[test]
    fn test_different_service_ids_have_different_keys() {
        ensure_mock_store();

        let service_id_1 = "test.mdk.storage.service1";
        let service_id_2 = "test.mdk.storage.service2";
        let db_key_id = "test.key.shared";

        // Clean up any existing keys
        let _ = delete_db_key(service_id_1, db_key_id);
        let _ = delete_db_key(service_id_2, db_key_id);

        // Generate keys for different services
        let config1 = get_or_create_db_key(service_id_1, db_key_id).unwrap();
        let config2 = get_or_create_db_key(service_id_2, db_key_id).unwrap();

        // Keys should be different
        assert_ne!(
            config1.key(),
            config2.key(),
            "Different services should have different keys"
        );

        // Clean up
        delete_db_key(service_id_1, db_key_id).unwrap();
        delete_db_key(service_id_2, db_key_id).unwrap();
    }

    #[test]
    fn test_different_key_ids_have_different_keys() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.keyids";
        let db_key_id_1 = "test.key.id1";
        let db_key_id_2 = "test.key.id2";

        // Clean up any existing keys
        let _ = delete_db_key(service_id, db_key_id_1);
        let _ = delete_db_key(service_id, db_key_id_2);

        // Generate keys for different key IDs
        let config1 = get_or_create_db_key(service_id, db_key_id_1).unwrap();
        let config2 = get_or_create_db_key(service_id, db_key_id_2).unwrap();

        // Keys should be different
        assert_ne!(
            config1.key(),
            config2.key(),
            "Different key IDs should have different keys"
        );

        // Clean up
        delete_db_key(service_id, db_key_id_1).unwrap();
        delete_db_key(service_id, db_key_id_2).unwrap();
    }

    #[test]
    fn test_get_db_key_returns_none_when_missing() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.getkey";
        let db_key_id = "test.key.nonexistent";

        // Ensure key doesn't exist
        let _ = delete_db_key(service_id, db_key_id);

        // get_db_key should return None
        let result = get_db_key(service_id, db_key_id).unwrap();
        assert!(result.is_none(), "Should return None for missing key");
    }

    #[test]
    fn test_get_db_key_returns_existing_key() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.getexisting";
        let db_key_id = "test.key.existing";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Create a key first
        let created_config = get_or_create_db_key(service_id, db_key_id).unwrap();

        // get_db_key should return the same key
        let retrieved = get_db_key(service_id, db_key_id).unwrap();
        assert!(retrieved.is_some(), "Should return Some for existing key");
        assert_eq!(
            retrieved.unwrap().key(),
            created_config.key(),
            "Retrieved key should match created key"
        );

        // Clean up
        delete_db_key(service_id, db_key_id).unwrap();
    }

    #[test]
    fn test_get_or_create_with_invalid_key_in_keyring_returns_error() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.invalidkey";
        let db_key_id = "test.key.invalid";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Manually store an invalid legacy payload with no prefix and the wrong length.
        let entry = Entry::new(service_id, db_key_id).unwrap();
        entry.set_secret(b"short_key").unwrap(); // Only 9 bytes, not 32

        // get_or_create should fail because the stored key is invalid
        let result = get_or_create_db_key(service_id, db_key_id);
        assert!(
            result.is_err(),
            "Should fail when keyring contains invalid key"
        );
        assert!(result.unwrap_err().to_string().contains("invalid length"));

        // Clean up
        let _ = delete_db_key(service_id, db_key_id);
    }

    #[test]
    fn test_get_db_key_with_invalid_legacy_key_length_returns_error() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.invalidget";
        let db_key_id = "test.key.invalidget";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Manually store an invalid legacy payload with no prefix and the wrong length.
        let entry = Entry::new(service_id, db_key_id).unwrap();
        entry.set_secret(&[0x42u8; 33]).unwrap();

        // get_db_key should fail because the stored key is invalid
        let result = get_db_key(service_id, db_key_id);
        assert!(
            result.is_err(),
            "Should fail when keyring contains invalid key"
        );
        assert!(result.unwrap_err().to_string().contains("invalid length"));

        // Clean up
        let _ = delete_db_key(service_id, db_key_id);
    }

    #[test]
    fn test_concurrent_get_or_create_same_key() {
        ensure_mock_store();

        let service_id = "test.mdk.storage.concurrent";
        let db_key_id = "test.key.concurrent";

        // Clean up any existing key
        let _ = delete_db_key(service_id, db_key_id);

        // Spawn multiple threads that all try to get_or_create the same key
        let num_threads = 10;
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let service_id = service_id.to_string();
                let db_key_id = db_key_id.to_string();
                thread::spawn(move || get_or_create_db_key(&service_id, &db_key_id).unwrap())
            })
            .collect();

        // Collect all results
        let configs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All keys should be identical (only one should have been generated)
        let first_key = configs[0].key();
        for config in &configs[1..] {
            assert_eq!(
                config.key(),
                first_key,
                "All concurrent calls should return the same key"
            );
        }

        // Clean up
        delete_db_key(service_id, db_key_id).unwrap();
    }
}
