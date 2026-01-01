# Encrypted SQLite Storage Implementation Plan

This document outlines the plan for implementing encrypted SQLite storage using SQLCipher, addressing the security audit finding regarding unencrypted MLS state storage.

## Background

### Audit Finding (Issue F)

The MLS state is stored in an unencrypted SQLite database with default file permissions, exposing sensitive data including:
- Messages and message content
- Group metadata
- Exporter secrets (enables retrospective traffic decryption)

### Document Structure

This document is split into two parts:

1. **Part A (MDK-generic)**: The design and implementation plan intended to be useful for any MDK user, regardless of platform.
2. **Part B (whitenoise-rs-specific)**: Non-normative integration notes and examples for `whitenoise-rs` and Flutter/FRB.

---

## Part A: MDK-generic design

### Goals

1. **Encrypt MLS state at rest** in `mdk-sqlite-storage` using SQLCipher.
2. **Keep MDK platform-agnostic**: core Rust + callback-based secure storage integration for all mobile platforms.
3. **Minimize footguns**: explicit keying procedure, clear failure modes, and safe defaults for file placement/permissions.

### Non-goals (for this workstream)

1. **Backups / restore / portability** are not supported yet. (Future work could add explicit export/import tooling, but that changes the threat model and must be opt-in.)
2. **In-memory zeroization / secure buffers** are out of scope here and will be addressed separately.
3. **Defense against a compromised runtime** (root/jailbreak/malware that can read process memory or intercept callbacks) is out of scope. This plan primarily targets offline/exfiltration threats.

### Threat Model

**Assets to protect**

- MLS state stored by `mdk-sqlite-storage`, especially **exporter secrets** (which enable retrospective traffic decryption).
- Group metadata and message content stored in the DB.
- The SQLCipher database encryption key (and any other secrets stored via secure storage).

**Primary attacker we are designing for**

- An attacker who can obtain **a copy of the SQLite database files** (e.g., via device theft, filesystem exfiltration, misconfigured file permissions, developer backups), but who does **not** have access to platform secure storage (Keychain/Keystore/etc.) and does not control the running process.

**Out of scope / explicitly not defended**

- A compromised host application (malicious integration).
- A compromised device / OS (root/jailbreak) or malware that can call secure storage APIs or read process memory.
- Side-channel attacks, hardware attacks, and “evil maid” runtime tampering.

**Trust boundaries**

- MDK **trusts the host-provided secure storage callbacks** to keep secrets confidential and to avoid logging/exfiltrating key material. This is a major security boundary; see “FFI / callback boundary risks” below.

### Solution Overview (MDK-generic)

1. **Database Encryption**: Use SQLCipher via `rusqlite` `bundled-sqlcipher`.
2. **Secure Storage Abstraction**: Create `mdk-secure-storage` crate:
   - `SecureStorageProvider` trait for secret storage
   - Desktop provider implementation (optional) using `keyring`
   - Callback-based provider for iOS/Android and any other platforms (host provides implementation)
3. **File Permissions**: Restrict database directories/files on Unix-like platforms (0600/0700), and apply best-effort ACL hardening guidance for Windows.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               Host Application                               │
│     (Swift/Kotlin/Flutter/React Native/Desktop/etc.)                         │
│                                   │                                          │
│                                   ▼ (FFI/UniFFI callbacks)                   │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                               MDK (Rust)                               │  │
│  │                                                                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                        mdk-secure-storage                        │  │  │
│  │  │  - SecureStorageProvider trait                                   │  │  │
│  │  │  - CallbackProvider (required for iOS/Android + generic)         │  │  │
│  │  │  - KeyringProvider (optional, desktop convenience)               │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                   │                                    │  │
│  │                                   ▼                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                       mdk-sqlite-storage                         │  │  │
│  │  │  - SQLCipher-encrypted SQLite                                    │  │  │
│  │  │  - Uses SecureStorageProvider to obtain DB key                   │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Technical Design

### 1. SQLCipher Integration

#### Crypto Backends by Platform

| Platform | Crypto Backend | Notes |
|----------|---------------|-------|
| iOS | CommonCrypto (Security.framework) | Native, no OpenSSL |
| macOS | CommonCrypto (Security.framework) | Native, no OpenSSL |
| Android | libcrypto (NDK) | Provided by NDK |
| Linux | libcrypto (OpenSSL) | System dependency |
| Windows | OpenSSL | Requires configuration |

#### Cargo.toml Changes

```toml
# Workspace Cargo.toml
[workspace.dependencies]
rusqlite = { version = "0.32", default-features = false }
mdk-secure-storage = { version = "0.1.0", path = "./crates/mdk-secure-storage" }

# mdk-sqlite-storage/Cargo.toml
[features]
default = []
encryption = []

[dependencies]
rusqlite = { workspace = true, features = ["bundled-sqlcipher"] }
```

#### Keying Procedure (precise `PRAGMA key` format)

MDK will use a **random 32-byte (256-bit) key** generated once and stored in secure storage (see `mdk-secure-storage`). When opening a database connection:

1. **Call `PRAGMA key` as the first operation** on the database connection.
2. Use **raw key data** (not a passphrase) so we do not depend on passphrase KDF settings:
   - SQLCipher expects a **64 character hex string** inside a blob literal, which it converts to 32 bytes of key data:

```sql
PRAGMA key = "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'";
```

3. **Validate the key immediately**: SQLCipher will not always error on `PRAGMA key` alone if the key is wrong. A simple schema read is the recommended check:

```sql
SELECT count(*) FROM sqlite_master;
```

**Alternative:** SQLCipher also exposes `sqlite3_key()` / `sqlite3_key_v2()` as programmatic equivalents to `PRAGMA key`. (The `PRAGMA` interface calls these internally.)

#### Cipher Parameters (defaults, but pinned intentionally)

SQLCipher’s **major versions have different default settings**, and existing databases can require migration when defaults change. This plan will:

- **Stick to SQLCipher defaults** for the selected compatibility baseline.
- Use `PRAGMA cipher_compatibility` to force defaults consistent with a specific major version for the current connection (e.g., 3 or 4), so that future SQLCipher upgrades do not silently change defaults.
- If we ever need to open databases created under older defaults, use SQLCipher’s supported migration mechanisms (e.g., `PRAGMA cipher_migrate` or `sqlcipher_export`) rather than guessing parameters.

#### SQLite Sidecar Files and Temporary Files

SQLCipher encrypts more than just the `*.db` file, but there are important nuances:

- **Rollback journals (`*-journal`)**: data pages are encrypted with the same key as the main database. The rollback journal includes an **unencrypted header**, but it does not contain data.
- **WAL (`*-wal`)**: page data stored in the WAL file is encrypted using the database key.
- **Statement journals**: encrypted; when file-based temp is disabled, these remain in memory.
- **Master journal**: does not contain data (it contains pathnames for rollback journals).
- **Other transient files are not encrypted**: SQLite can write temporary files for sorts, indexes, etc. To avoid plaintext transient spill to disk, we must disable file-based temporary storage (compile-time) and/or enforce in-memory temp storage (runtime).

Operational guidance:

- Treat `*.db`, `*-wal`, `*-shm`, and `*-journal` as sensitive and ensure they live in a private directory with restrictive permissions.
- Prefer in-memory temp store (`PRAGMA temp_store = MEMORY;`) and ensure the bundled SQLCipher build is configured to avoid file-based temp stores.

### 2. The `mdk-secure-storage` Crate

This new crate provides a unified interface for secure secret storage across all platforms.

#### Crate Structure

```
crates/mdk-secure-storage/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Trait definition + re-exports
│   ├── error.rs            # SecureStorageError enum
│   ├── keyring.rs          # KeyringProvider (optional desktop convenience: macOS/Linux/Windows)
│   └── callback.rs         # CallbackProvider (host-provided; recommended for iOS/Android and generic use)
```

#### Cargo.toml

```toml
[package]
name = "mdk-secure-storage"
version = "0.1.0"
edition = "2024"
description = "Secure storage abstraction for MDK - supports keychain, keyring, and callbacks"

[features]
default = []
keyring-provider = ["keyring"]
callback-provider = []  # No deps, but still explicitly enabled

[dependencies]
thiserror.workspace = true
getrandom = "0.2"  # For secure random key generation

# Optional providers
keyring = { version = "3", optional = true }
```

**Provider Selection by Platform:**

| Platform | Provider | Backend |
|----------|----------|---------|
| iOS (native) | `CallbackProvider` | Keychain Services (host implemented) |
| macOS | `KeyringProvider` | Keychain Services |
| Linux | `KeyringProvider` | Secret Service (libsecret) |
| Windows | `KeyringProvider` | Credential Manager |
| Android (native) | `CallbackProvider` | Keystore-backed secure storage (host implemented) |

**Note:** MDK recommends **callback-based secure storage on all mobile platforms** (iOS and Android) for maximum portability and to avoid relying on Rust-side platform bindings.

#### The Trait

```rust
// src/lib.rs

use crate::error::SecureStorageError;

/// A provider for secure secret storage.
///
/// Implementations store secrets in platform-native secure storage:
/// - iOS/macOS: Keychain
/// - Android: EncryptedSharedPreferences (via callback)
/// - Linux: Secret Service (libsecret)
/// - Windows: Credential Manager
pub trait SecureStorageProvider: Send + Sync {
    /// Retrieve a secret by key.
    ///
    /// Returns `Ok(None)` if the key doesn't exist.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecureStorageError>;

    /// Store a secret with the given key.
    ///
    /// Overwrites any existing value for this key.
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecureStorageError>;

    /// Delete a secret by key.
    ///
    /// Returns `Ok(())` even if the key didn't exist.
    fn delete(&self, key: &str) -> Result<(), SecureStorageError>;

    /// Check if a key exists.
    fn contains(&self, key: &str) -> Result<bool, SecureStorageError> {
        Ok(self.get(key)?.is_some())
    }
}

/// Extension trait for common key generation patterns
pub trait SecureStorageProviderExt: SecureStorageProvider {
    /// Get an existing key or generate and store a new one.
    ///
    /// Uses platform-secure random number generation.
    ///
    /// **Concurrency:** This operation must be atomic (at least within the current process).
    /// Otherwise, concurrent callers can generate *different* keys and overwrite each other,
    /// which can permanently brick encrypted data.
    fn get_or_create_key(&self, key: &str, length: usize) -> Result<Vec<u8>, SecureStorageError> {
        use std::sync::{Mutex, OnceLock};

        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        if let Some(existing) = self.get(key)? {
            return Ok(existing);
        }

        let new_key = generate_random_bytes(length)?;
        self.set(key, &new_key)?;
        Ok(new_key)
    }
}

impl<T: SecureStorageProvider> SecureStorageProviderExt for T {}

fn generate_random_bytes(length: usize) -> Result<Vec<u8>, SecureStorageError> {
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| SecureStorageError::KeyGeneration(e.to_string()))?;
    Ok(bytes)
}
```

#### Keyring Provider (optional desktop convenience: macOS, Linux, Windows)

```rust
// src/keyring.rs

use crate::{SecureStorageError, SecureStorageProvider};

/// Secure storage provider using the system keyring/keychain.
///
/// Works on:
/// - macOS: Keychain Services
/// - Linux: Secret Service (libsecret/GNOME Keyring)
/// - Windows: Credential Manager
///
/// Note: Mobile platforms should use CallbackProvider (host implemented) instead of relying on `keyring`.
pub struct KeyringProvider {
    service_name: String,
}

impl KeyringProvider {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

impl SecureStorageProvider for KeyringProvider {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecureStorageError> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| SecureStorageError::Backend(e.to_string()))?;

        match entry.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecureStorageError::Retrieval(e.to_string())),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecureStorageError> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| SecureStorageError::Backend(e.to_string()))?;

        entry
            .set_secret(value)
            .map_err(|e| SecureStorageError::Storage(e.to_string()))
    }

    fn delete(&self, key: &str) -> Result<(), SecureStorageError> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| SecureStorageError::Backend(e.to_string()))?;

        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(SecureStorageError::Deletion(e.to_string())),
        }
    }
}
```

#### Callback Provider (host-provided; iOS/Android + generic)

```rust
// src/callback.rs

use crate::{SecureStorageError, SecureStorageProvider};

/// Callback interface that host applications implement.
///
/// This is the recommended integration for:
/// - **iOS**: implement using Keychain Services
/// - **Android**: implement using Keystore-backed secure storage (e.g. EncryptedSharedPreferences)
/// - Any other host environment where MDK should not directly depend on platform-specific bindings
pub trait SecureStorageCallbacks: Send + Sync {
    fn get(&self, key: String) -> Result<Option<Vec<u8>>, String>;
    fn set(&self, key: String, value: Vec<u8>) -> Result<(), String>;
    fn delete(&self, key: String) -> Result<(), String>;
}

/// Secure storage provider that delegates to host-provided callbacks.
///
/// Use this when the host application is responsible for integrating with platform secure storage.
pub struct CallbackProvider {
    callbacks: Box<dyn SecureStorageCallbacks>,
}

impl CallbackProvider {
    pub fn new(callbacks: Box<dyn SecureStorageCallbacks>) -> Self {
        Self { callbacks }
    }
}

impl SecureStorageProvider for CallbackProvider {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecureStorageError> {
        self.callbacks
            .get(key.to_string())
            .map_err(SecureStorageError::Callback)
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecureStorageError> {
        self.callbacks
            .set(key.to_string(), value.to_vec())
            .map_err(SecureStorageError::Callback)
    }

    fn delete(&self, key: &str) -> Result<(), SecureStorageError> {
        self.callbacks
            .delete(key.to_string())
            .map_err(SecureStorageError::Callback)
    }
}
```

### 3. Project-Specific Integration Packages (see Part B)

MDK remains Rust-first and platform-agnostic. Companion packages (e.g., Flutter/Dart helpers) are
documented in **Part B** as non-normative examples and are not required for MDK itself.

### 4. Integration with MDK

#### How MDK Uses the Storage Provider

**Key identifiers (important):**

- The database encryption key must be stored under a **stable, host-defined key identifier** (e.g., `mdk.db.key.default` or `mdk.db.key.<profile_id>`).
- **Do not derive the key identifier from an absolute `db_path`** (hashing paths is fragile across reinstalls, sandbox path changes, migrations, and renames).
- The key identifier is **not secret**; it is an index into secure storage. Treat changes to it as a breaking migration (the DB becomes unreadable without the old key).

```rust
// mdk-sqlite-storage/src/lib.rs

use mdk_secure_storage::{SecureStorageProvider, SecureStorageProviderExt};

impl MdkSqliteStorage {
    /// Creates encrypted storage using a secure storage provider.
    ///
    /// The provider is used to get or create the database encryption key.
    pub fn new_with_provider<P>(
        file_path: P,
        db_key_id: &str,
        storage_provider: &dyn SecureStorageProvider,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // Get or create the 32-byte encryption key
        let key = storage_provider.get_or_create_key(db_key_id, 32)?;
        let key_array: [u8; 32] = key.try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        let config = EncryptionConfig { key: key_array };
        Self::new(file_path, Some(config))
    }
}
```

#### UniFFI Bindings

```rust
// mdk-uniffi/src/lib.rs

/// Callback interface for secure storage.
///
/// Implement this in your host application (Kotlin, Swift, etc.)
#[uniffi::export(callback_interface)]
pub trait SecureStorageCallbacks: Send + Sync {
    fn get(&self, key: String) -> Result<Option<Vec<u8>>, String>;
    fn set(&self, key: String, value: Vec<u8>) -> Result<(), String>;
    fn delete(&self, key: String) -> Result<(), String>;
}

/// Create MDK with encrypted storage using host-provided secure storage.
#[uniffi::export]
pub fn new_mdk_with_secure_storage(
    db_path: String,
    db_key_id: String,
    storage_callbacks: Box<dyn SecureStorageCallbacks>,
) -> Result<Mdk, MdkUniffiError> {
    let provider = CallbackProvider::new(storage_callbacks);
    let storage = MdkSqliteStorage::new_with_provider(
        PathBuf::from(db_path),
        &db_key_id,
        &provider,
    )?;

    let mdk = MDK::new(storage);
    Ok(Mdk { mdk: Mutex::new(mdk) })
}
```

### 5. Project-Specific Usage Examples (see Part B)

Downstream integrations (including `whitenoise-rs`) are documented in **Part B** as non-normative examples.

### 6. Platform Integration Examples (Native Apps)

The following are reference implementations for host applications implementing secure storage (e.g., to back `SecureStorageCallbacks`).

#### iOS (Swift)

```swift
import Security

class MdkKeyManager {
    private let serviceName = "dev.mdk.database"

    func getOrCreateKey(dbKeyId: String) throws -> Data {
        let keyIdentifier = dbKeyId

        // Try to retrieve existing key
        if let existingKey = try? retrieveKey(identifier: keyIdentifier) {
            return existingKey
        }

        // Generate new key
        var key = Data(count: 32)
        let result = key.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw KeychainError.randomGenerationFailed
        }

        // Store in keychain
        try storeKey(key, identifier: keyIdentifier)
        return key
    }

    private func storeKey(_ key: Data, identifier: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: identifier,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unableToStore
        }
    }

    private func retrieveKey(identifier: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: identifier,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess {
            return result as? Data
        } else if status == errSecItemNotFound {
            return nil
        } else {
            throw KeychainError.unableToRetrieve
        }
    }
}
```

#### Android (Kotlin) - Using EncryptedSharedPreferences

**Note**: Android Keystore doesn't allow direct export of raw key bytes for keys it generates.
For SQLCipher, we need the raw key bytes, so we use EncryptedSharedPreferences which is
backed by Android Keystore but allows storing arbitrary secrets.

```kotlin
import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import android.util.Base64

class MdkKeyManager(private val context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val securePrefs = EncryptedSharedPreferences.create(
        context,
        "mdk_secure_keys",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun getOrCreateKey(dbKeyId: String): ByteArray {
        val keyAlias = dbKeyId

        // Try to retrieve existing key
        val existingKeyBase64 = securePrefs.getString(keyAlias, null)
        if (existingKeyBase64 != null) {
            return Base64.decode(existingKeyBase64, Base64.NO_WRAP)
        }

        // Generate new 256-bit key
        val random = SecureRandom()
        val key = ByteArray(32)
        random.nextBytes(key)

        // Store in encrypted preferences
        securePrefs.edit()
            .putString(keyAlias, Base64.encodeToString(key, Base64.NO_WRAP))
            .apply()

        return key
    }

    fun deleteKey(dbKeyId: String) {
        val keyAlias = dbKeyId
        securePrefs.edit().remove(keyAlias).apply()
    }
}

// Usage with UniFFI bindings:
// Implement `SecureStorageCallbacks` in the host (backed by this EncryptedSharedPreferences logic),
// then call `newMdkWithSecureStorage(dbPath, dbKeyId, callbacks)` (name varies by language binding).
```

**Gradle Dependencies** (add to app's build.gradle):
```groovy
dependencies {
    implementation "androidx.security:security-crypto:1.1.0-alpha06"
}
```

#### Flutter / FRB Integration (see Part B)

Flutter-specific examples and helper packages are documented in **Part B** as non-normative integration notes.

### 7. File Permission Hardening

**Goal:** prevent other local users/processes from reading the encrypted database files.

- **Unix-like (macOS/Linux/etc.)**: create the database directory with `0700` and database files with `0600`.
- **iOS/Android**: rely on the application sandbox, but still store databases in app-private directories.
- **Windows (not currently a supported target)**: there is no portable chmod-equivalent; the right long-term approach is to store under per-user app data directories and apply best-effort ACL restrictions to the current user.

```rust
// mdk-sqlite-storage/src/lib.rs

#[cfg(unix)]
fn create_secure_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(path)?;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn set_secure_file_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if path.exists() {
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_secure_directory(path: &Path) -> std::io::Result<()> {
    // On iOS/Android, the app sandbox generally restricts filesystem access.
    //
    // On Windows, Unix permissions don't apply. We should prefer per-user app data locations and
    // (in the future) apply best-effort ACL hardening to restrict access to the current user.
    std::fs::create_dir_all(path)
}

#[cfg(not(unix))]
fn set_secure_file_permissions(_path: &Path) -> std::io::Result<()> {
    // On non-Unix platforms there is no portable chmod-equivalent.
    // We currently rely on sandboxing (mobile) and per-user locations (Windows).
    // A future Windows implementation can apply best-effort ACL restrictions.
    Ok(())
}
```

---

## Implementation Tasks

### Phase 1: Create `mdk-secure-storage` Crate

- [ ] Create new crate `crates/mdk-secure-storage`
- [ ] Define `SecureStorageProvider` trait
- [ ] Define `SecureStorageProviderExt` trait with `get_or_create_key()`
- [ ] Define `SecureStorageError` enum
- [ ] Ensure **no provider is enabled by default** (providers behind explicit crate features)
- [ ] Implement `KeyringProvider` using `keyring` crate (optional desktop convenience: macOS, Linux, Windows)
- [ ] Implement `CallbackProvider` for host-provided callbacks (recommended for iOS/Android and generic use)
- [ ] Add `SecureStorageCallbacks` trait for FFI callbacks
- [ ] Add unit tests for all providers
- [ ] Smoke test `KeyringProvider` on at least one desktop platform

### Phase 2: SQLCipher Integration in `mdk-sqlite-storage`

- [ ] Update `Cargo.toml` to use `bundled-sqlcipher` feature
- [ ] Add dependency on `mdk-secure-storage`
- [ ] Add `EncryptionConfig` struct
- [ ] Modify `MdkSqliteStorage::new()` to accept optional encryption config
- [ ] Add `MdkSqliteStorage::new_with_provider()` that uses `SecureStorageProvider`
- [ ] Apply `PRAGMA key` **as the first operation** on a new connection (use raw key data blob literal)
- [ ] Validate the key with a read (e.g., `SELECT count(*) FROM sqlite_master;`) to distinguish “wrong key” from other failures
- [ ] Ensure in-memory temporary storage (e.g., `PRAGMA temp_store = MEMORY;`) and avoid file-based temp spill
- [ ] Consider `PRAGMA cipher_compatibility` to pin defaults for forward compatibility
- [ ] Add file permission hardening for Unix platforms
- [ ] Add unit tests for encrypted storage
- [ ] Test cross-platform compilation (iOS, Android, macOS, Linux)

### Phase 3: UniFFI Binding Updates

- [ ] Export `SecureStorageCallbacks` as callback interface
- [ ] Add `new_mdk_with_secure_storage(db_path, db_key_id, callbacks)` function
- [ ] Update generated bindings for Swift, Kotlin, Python, Ruby
- [ ] Keep unencrypted `new_mdk()` for backward compatibility (mark as deprecated)
- [ ] Add documentation for storage provider responsibilities

### Phase 4: Project-Specific Integrations (see Part B)

- [ ] Downstream work (e.g., `whitenoise-rs`, Flutter/FRB helper packages) is tracked in **Part B**

### Phase 7: Migration Support

- [ ] Add utility to migrate unencrypted database to encrypted
- [ ] Add utility to re-key encrypted database
- [ ] Handle edge case: app upgrade from unencrypted to encrypted storage
- [ ] Document supported migration paths and failure modes (e.g., missing key vs wrong key vs corrupt DB)

---

## Security Considerations

### Key Storage Best Practices

1. **Never log or expose the encryption key**
2. **Use platform-specific secure storage** - Don't store keys in SharedPreferences, UserDefaults, or files
3. **Use device-bound keys where possible** - Prefer `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` on iOS
4. **Consider biometric protection** - For high-security use cases, require biometric auth to access the key

### Android-Specific Security Notes

1. **Use EncryptedSharedPreferences** - This is backed by Android Keystore but allows storing arbitrary secrets
2. **Avoid plain SharedPreferences** - Even with obfuscation, this is not secure
3. **MasterKey.KeyScheme.AES256_GCM** - Use the strongest available key scheme
4. **Android Keystore limitations** - Keys generated in Keystore cannot be exported as raw bytes, which is why we use EncryptedSharedPreferences for SQLCipher keys
5. **Minimum API level** - EncryptedSharedPreferences requires API 23+ (Android 6.0+)

### Database Security

1. **SQLCipher security design** - SQLCipher encrypts pages with 256-bit AES-CBC and authenticates page writes with HMAC-SHA512 (see SQLCipher design docs).
2. **Keying is explicit** - Use `PRAGMA key = "x'...'"` (raw 32-byte key data) and validate with a read (e.g., `SELECT count(*) FROM sqlite_master;`).
3. **Defaults, but pinned** - Use `PRAGMA cipher_compatibility` to avoid unexpected default changes across SQLCipher major versions.
4. **Sidecar + temp files** - WAL/journal page data is encrypted, but other transient files are not; ensure in-memory temp store and strict directory permissions.
5. **Optional hardening** - Consider `PRAGMA cipher_memory_security = ON` if the performance impact is acceptable.

### Backup / Restore (Not Supported Yet)

MDK does not currently provide backup/restore/export tooling. Hosts should assume that copying the database file(s) alone is insufficient without a compatible key management strategy.

### FFI / Callback Boundary Risks (Critical)

Using host callbacks for secure storage is what keeps MDK platform-agnostic, but it is also the most important trust boundary in this design:

1. **Key material crosses language/runtime boundaries** (often multiple times). Many hosts will need to serialize as base64 or byte arrays, which increases the risk of accidental logging, caching, or analytics ingestion.
2. **A compromised or misconfigured host can exfiltrate secrets**. MDK cannot enforce correct handling once the host receives key bytes.
3. **“Key identifier” input is untrusted**: callbacks must treat the key name/identifier as potentially attacker-controlled input and must not allow arbitrary reads/writes outside the app’s intended namespace.

Minimum required host behaviors:

- Never log secrets or include them in crash reports/telemetry.
- Store secrets only in platform secure storage, not in plaintext files or preferences.
- Keep callback implementations small, deterministic, and well-tested (failure modes should be explicit and actionable).

---

## Testing Strategy

### Unit Tests

```rust
#[test]
fn test_encrypted_storage_creation() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("encrypted.db");
    let key = [0u8; 32]; // Test key

    let config = EncryptionConfig { key };
    let storage = MdkSqliteStorage::new(&db_path, Some(config));
    assert!(storage.is_ok());
}

#[test]
fn test_encrypted_storage_wrong_key_fails() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("encrypted.db");

    // Create with key1
    let key1 = [1u8; 32];
    let config1 = EncryptionConfig { key: key1 };
    let storage1 = MdkSqliteStorage::new(&db_path, Some(config1)).unwrap();
    drop(storage1);

    // Try to open with key2
    let key2 = [2u8; 32];
    let config2 = EncryptionConfig { key: key2 };
    let result = MdkSqliteStorage::new(&db_path, Some(config2));
    assert!(result.is_err());
}

#[test]
fn test_unencrypted_cannot_read_encrypted() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("encrypted.db");

    // Create encrypted database
    let key = [0u8; 32];
    let config = EncryptionConfig { key };
    let storage = MdkSqliteStorage::new(&db_path, Some(config)).unwrap();
    drop(storage);

    // Try to open without encryption
    let result = MdkSqliteStorage::new(&db_path, None);
    assert!(result.is_err());
}
```

### Integration Tests

- [ ] Test on iOS Simulator
- [ ] Test on Android Emulator
- [ ] Test host callback integration on both platforms (native iOS + native Android)
- [ ] Performance benchmarks (encryption overhead)

---

## References

- [SQLCipher Design](https://www.zetetic.net/sqlcipher/design/)
- [SQLCipher Documentation](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
- [rusqlite SQLCipher feature](https://github.com/rusqlite/rusqlite#optional-features)
- [iOS Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [Android Keystore](https://developer.android.com/training/articles/keystore)
- [Android EncryptedSharedPreferences](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
- [AndroidX Security Crypto Library](https://developer.android.com/jetpack/androidx/releases/security)
- [UniFFI Callback Interfaces](https://mozilla.github.io/uniffi-rs/latest/udl/callback_interfaces.html)

---

## Part B: `whitenoise-rs` / Flutter Integration Notes (Non-normative)

This section captures downstream work that is useful for `whitenoise-rs`, but is intentionally separated from the MDK-generic design.

### Background: Current whitenoise-rs Key Storage Problem

`whitenoise-rs` (which depends on MDK) currently handles Nostr key storage using:

- `keyring` crate for most platforms
- Android: file-based obfuscation (not secure)

This plan enables `whitenoise-rs` to reuse the same `mdk-secure-storage` abstraction for:

- The SQLCipher DB encryption key (MDK storage)
- Nostr secret keys (whitenoise-rs)

### Strategy (Downstream)

- **Mobile (iOS + Android)**: use `CallbackProvider` via FFI (host implements secure storage callbacks).
- **Desktop**: optionally use `KeyringProvider` (enabled explicitly) for convenience.

### Companion Flutter/Dart Package (Optional)

Downstream Flutter apps can implement the callback interface using [`flutter_secure_storage`](https://pub.dev/packages/flutter_secure_storage). The Dart layer must treat secrets as **bytes** and encode them for storage (base64 is common).

Example sketch (non-normative):

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class FlutterSecureStorageCallbacks {
  final FlutterSecureStorage _storage;

  FlutterSecureStorageCallbacks({
    FlutterSecureStorage? storage,
  }) : _storage = storage ?? const FlutterSecureStorage(
          aOptions: AndroidOptions(encryptedSharedPreferences: true),
          iOptions: IOSOptions(
            accessibility: KeychainAccessibility.first_unlock_this_device,
            synchronizable: false,
          ),
        );

  Future<Uint8List?> get(String key) async {
    final encoded = await _storage.read(key: key);
    if (encoded == null) return null;
    return base64Decode(encoded);
  }

  Future<void> set(String key, Uint8List value) async {
    await _storage.write(key: key, value: base64Encode(value));
  }

  Future<void> delete(String key) async {
    await _storage.delete(key: key);
  }
}
```

### `whitenoise-rs` Usage (Sketch)

Use a stable `db_key_id` (not derived from a file path), and reuse the same provider for other secrets (e.g., Nostr keys):

```rust
// In whitenoise-rs (sketch)

use mdk_secure_storage::{SecureStorageProvider, SecureStorageProviderExt};

fn open_mdk(db_path: &Path, storage: &dyn SecureStorageProvider) -> Result<MDK<MdkSqliteStorage>, Error> {
    let db_key_id = "mdk.db.key.whitenoise.default";
    let mdk_storage = MdkSqliteStorage::new_with_provider(db_path, db_key_id, storage)?;
    Ok(MDK::new(mdk_storage))
}

fn get_or_create_nostr_key(storage: &dyn SecureStorageProvider) -> Result<Vec<u8>, Error> {
    Ok(storage.get_or_create_key("nostr.secret_key.default", 32)?)
}
```

### Downstream Tasks (whitenoise / Flutter)

- [ ] Implement `SecureStorageCallbacks` in the host layer for iOS and Android
- [ ] Provide a Dart/Flutter callback implementation using `flutter_secure_storage` (if needed)
- [ ] Replace any Android file-obfuscation key storage with secure storage callbacks
- [ ] Update `whitenoise-rs` to pass a stable `db_key_id` to MDK
