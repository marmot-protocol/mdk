use crate::openmls_storage::SqliteOpenMlsStorage;
use crate::{SqliteResultExt, migrations};
use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use cgka_traits::types::Backend;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) type SharedConnection = Arc<Mutex<rusqlite::Connection>>;

pub struct SqlCipherKey(Zeroizing<String>);

impl SqlCipherKey {
    pub fn new(key: impl Into<String>) -> StorageResult<Self> {
        let key = Zeroizing::new(key.into());
        if key.is_empty() {
            return Err(StorageError::Backend(
                "SQLCipher key must not be empty".to_string(),
            ));
        }
        Ok(Self(key))
    }

    pub fn as_secret_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SqlCipherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SqlCipherKey").field(&"<redacted>").finish()
    }
}

#[derive(Clone)]
pub struct SqliteAccountStorage {
    pub(crate) connection: SharedConnection,
    pub(crate) openmls: SqliteOpenMlsStorage,
}

#[deprecated(
    note = "renamed to SqliteAccountStorage; SqliteStorage will be removed once downstream crates have migrated"
)]
pub type SqliteStorage = SqliteAccountStorage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqliteStorageOptions {
    pub busy_timeout_ms: u64,
    pub journal_mode: SqliteJournalMode,
    pub synchronous: SqliteSynchronous,
    pub secure_delete: bool,
    pub temp_store_memory: bool,
    pub trusted_schema: bool,
    pub cipher_memory_security: bool,
    pub cipher_compatibility: u8,
}

impl Default for SqliteStorageOptions {
    fn default() -> Self {
        Self {
            busy_timeout_ms: 5_000,
            journal_mode: SqliteJournalMode::Wal,
            synchronous: SqliteSynchronous::Full,
            secure_delete: true,
            temp_store_memory: true,
            trusted_schema: false,
            cipher_memory_security: true,
            cipher_compatibility: 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqliteJournalMode {
    Wal,
    Delete,
}

impl SqliteJournalMode {
    fn as_pragma(self) -> &'static str {
        match self {
            Self::Wal => "WAL",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqliteSynchronous {
    Full,
    Normal,
}

impl SqliteSynchronous {
    fn as_pragma(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Normal => "NORMAL",
        }
    }
}

impl SqliteAccountStorage {
    pub fn in_memory() -> StorageResult<Self> {
        Self::in_memory_with_options(SqliteStorageOptions::default())
    }

    pub fn in_memory_with_options(options: SqliteStorageOptions) -> StorageResult<Self> {
        let connection = rusqlite::Connection::open_in_memory().storage()?;
        apply_cipher_pragmas(&connection, &options)?;
        Self::from_connection_with_options(connection, options)
    }

    pub fn open_encrypted(path: impl AsRef<Path>, key: &SqlCipherKey) -> StorageResult<Self> {
        Self::open_encrypted_with_options(path, key, SqliteStorageOptions::default())
    }

    pub fn open_encrypted_with_options(
        path: impl AsRef<Path>,
        key: &SqlCipherKey,
        options: SqliteStorageOptions,
    ) -> StorageResult<Self> {
        let connection = rusqlite::Connection::open(path).storage()?;
        Self::from_unkeyed_encrypted_connection_with_options(connection, key, options)
    }

    fn from_unkeyed_encrypted_connection_with_options(
        connection: rusqlite::Connection,
        key: &SqlCipherKey,
        options: SqliteStorageOptions,
    ) -> StorageResult<Self> {
        apply_cipher_pragmas(&connection, &options)?;
        apply_sqlcipher_key(&connection, key)?;
        Self::from_connection_with_options(connection, options)
    }

    pub(crate) fn from_connection_with_options(
        mut connection: rusqlite::Connection,
        options: SqliteStorageOptions,
    ) -> StorageResult<Self> {
        apply_operational_pragmas(&connection, &options)?;
        migrations::run_all(&mut connection)?;
        let connection = Arc::new(Mutex::new(connection));
        let openmls = SqliteOpenMlsStorage::new(connection.clone());
        Ok(Self {
            connection,
            openmls,
        })
    }

    pub(crate) fn lock(&self) -> StorageResult<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        Ok(self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()))
    }
}

fn apply_sqlcipher_key(connection: &rusqlite::Connection, key: &SqlCipherKey) -> StorageResult<()> {
    connection
        .pragma_update(None, "key", key.as_secret_str())
        .storage()?;
    let _: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .storage()?;
    Ok(())
}

fn apply_cipher_pragmas(
    connection: &rusqlite::Connection,
    options: &SqliteStorageOptions,
) -> StorageResult<()> {
    connection
        .pragma_update(
            None,
            "cipher_compatibility",
            i64::from(options.cipher_compatibility),
        )
        .storage()?;
    if options.cipher_memory_security {
        connection
            .execute_batch("PRAGMA cipher_memory_security = ON;")
            .storage()?;
    }
    Ok(())
}

fn apply_operational_pragmas(
    connection: &rusqlite::Connection,
    options: &SqliteStorageOptions,
) -> StorageResult<()> {
    connection
        .busy_timeout(Duration::from_millis(options.busy_timeout_ms))
        .storage()?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .storage()?;
    connection
        .pragma_update(None, "secure_delete", options.secure_delete)
        .storage()?;
    connection
        .pragma_update(None, "trusted_schema", options.trusted_schema)
        .storage()?;
    if options.temp_store_memory {
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .storage()?;
    }
    connection
        .pragma_update(None, "synchronous", options.synchronous.as_pragma())
        .storage()?;
    let journal_mode = format!("PRAGMA journal_mode = {}", options.journal_mode.as_pragma());
    let _: String = connection
        .query_row(&journal_mode, [], |row| row.get(0))
        .storage()?;
    Ok(())
}

/// SQLCipher hardening for connections opened *outside* the account-storage
/// aggregate (the app's directory cache, legacy account-projection import, and
/// key-rotation paths). It mirrors the hardening [`SqliteAccountStorage`]
/// applies so every SQLCipher database the workspace opens pins
/// `cipher_compatibility`, enables `cipher_memory_security` *before* keying,
/// and optionally scrubs deleted rows and keeps temp state in memory.
///
/// The cipher fields default to the same values as [`SqliteStorageOptions`] so
/// the two hardening paths cannot silently drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlCipherHardening {
    /// Pin `cipher_compatibility` so a future SQLCipher default-compat bump
    /// cannot silently change the on-disk format these databases require.
    pub cipher_compatibility: u8,
    /// Enable `cipher_memory_security` so key/page material is wiped from the
    /// SQLCipher heap.
    pub cipher_memory_security: bool,
    /// Scrub deleted rows on this connection (`secure_delete`).
    pub secure_delete: bool,
    /// Keep temporary tables/indexes in memory (`temp_store = MEMORY`).
    pub temp_store_memory: bool,
}

impl SqlCipherHardening {
    /// Cipher hardening only: pin `cipher_compatibility` and enable
    /// `cipher_memory_security`, without row scrubbing or temp-store changes.
    /// Suitable for short-lived migration/rekey opens.
    pub fn cipher_only() -> Self {
        let defaults = SqliteStorageOptions::default();
        Self {
            cipher_compatibility: defaults.cipher_compatibility,
            cipher_memory_security: defaults.cipher_memory_security,
            secure_delete: false,
            temp_store_memory: false,
        }
    }

    /// Full hardening for a long-lived encrypted cache: cipher hardening plus
    /// `secure_delete` and `temp_store = MEMORY`.
    pub fn live_cache() -> Self {
        Self {
            secure_delete: true,
            temp_store_memory: true,
            ..Self::cipher_only()
        }
    }
}

impl Default for SqlCipherHardening {
    fn default() -> Self {
        Self::cipher_only()
    }
}

/// Apply SQLCipher hardening to `connection` and key it, in the order the
/// PRAGMAs require to take effect: `cipher_compatibility` and
/// `cipher_memory_security` are set **before** `PRAGMA key`, then the privacy
/// PRAGMAs (`secure_delete`, `temp_store`) are applied after keying.
///
/// This is the shared entry point for SQLCipher databases opened outside
/// [`SqliteAccountStorage`]. The cipher-pragma ordering invariant is exercised
/// by `public_hardened_open_pins_cipher_pragmas_before_keying`.
pub fn open_hardened_sqlcipher(
    connection: &rusqlite::Connection,
    key: &SqlCipherKey,
    hardening: SqlCipherHardening,
) -> StorageResult<()> {
    // Reuse the account-storage cipher-pragma path so the "cipher pragmas
    // before keying" ordering lives in exactly one place.
    let cipher_options = SqliteStorageOptions {
        cipher_compatibility: hardening.cipher_compatibility,
        cipher_memory_security: hardening.cipher_memory_security,
        ..SqliteStorageOptions::default()
    };
    apply_cipher_pragmas(connection, &cipher_options)?;
    apply_sqlcipher_key(connection, key)?;
    if hardening.secure_delete {
        connection
            .pragma_update(None, "secure_delete", true)
            .storage()?;
    }
    if hardening.temp_store_memory {
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .storage()?;
    }
    Ok(())
}

impl StorageProvider for SqliteAccountStorage {
    type Mls = SqliteOpenMlsStorage;

    fn mls_storage(&self) -> &Self::Mls {
        &self.openmls
    }

    fn backend(&self) -> Backend {
        Backend::Sqlite
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TRACE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static TRACED_SQLCIPHER_SETUP: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    fn trace_sqlcipher_setup(sql: &str) {
        let sql = sql.to_ascii_lowercase();
        let setup_step = if sql.contains("cipher_compatibility") {
            Some("cipher_compatibility")
        } else if sql.contains("cipher_memory_security") {
            Some("cipher_memory_security")
        } else if sql.contains("pragma key") || sql.contains("pragma \"key\"") {
            Some("key")
        } else if sql.contains("sqlite_master") {
            Some("key_probe")
        } else {
            None
        };

        if let Some(setup_step) = setup_step {
            TRACED_SQLCIPHER_SETUP.lock().unwrap().push(setup_step);
        }
    }

    #[test]
    fn reports_sqlite_backend() {
        assert_eq!(
            SqliteAccountStorage::in_memory().unwrap().backend(),
            Backend::Sqlite
        );
    }

    #[test]
    fn sqlcipher_key_debug_redacts_secret_material() {
        let key = SqlCipherKey::new("debug-visible secret").unwrap();

        let rendered = format!("{key:?}");

        assert!(!rendered.contains("debug-visible secret"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn connection_lock_recovers_from_poisoned_guard() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.connection.lock().unwrap();
            panic!("poison sqlite connection lock");
        }));

        let conn = store.lock().unwrap();

        assert_eq!(pragma_i64(&conn, "foreign_keys"), 1);
    }

    #[test]
    fn encrypted_connection_applies_operational_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("operational defaults key").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let conn = store.lock().unwrap();

        assert_eq!(pragma_i64(&conn, "busy_timeout"), 5_000);
        assert_eq!(pragma_i64(&conn, "foreign_keys"), 1);
        assert_eq!(pragma_i64(&conn, "secure_delete"), 1);
        assert_eq!(pragma_i64(&conn, "temp_store"), 2);
        assert_eq!(pragma_i64(&conn, "trusted_schema"), 0);
        assert_eq!(pragma_i64(&conn, "synchronous"), 2);
        assert_eq!(pragma_string(&conn, "journal_mode"), "wal");
    }

    #[test]
    fn encrypted_connection_pins_cipher_pragmas_before_keying() {
        let _guard = TRACE_TEST_LOCK.lock().unwrap();
        TRACED_SQLCIPHER_SETUP.lock().unwrap().clear();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("trace setup key").unwrap();
        let mut connection = rusqlite::Connection::open(path).unwrap();
        connection.trace(Some(trace_sqlcipher_setup));

        let _store = SqliteAccountStorage::from_unkeyed_encrypted_connection_with_options(
            connection,
            &key,
            SqliteStorageOptions::default(),
        )
        .unwrap();

        let statements = TRACED_SQLCIPHER_SETUP.lock().unwrap().clone();
        let cipher_compatibility = statements
            .iter()
            .position(|statement| *statement == "cipher_compatibility")
            .expect("cipher_compatibility pragma was traced");
        let cipher_memory_security = statements
            .iter()
            .position(|statement| *statement == "cipher_memory_security")
            .expect("cipher_memory_security pragma was traced");
        let key = statements
            .iter()
            .position(|statement| *statement == "key")
            .expect("key pragma was traced");
        let key_probe = statements
            .iter()
            .position(|statement| *statement == "key_probe")
            .expect("keying probe was traced");

        assert!(
            cipher_compatibility < key,
            "cipher_compatibility must be pinned before SQLCipher keying",
        );
        assert!(
            cipher_compatibility < key_probe,
            "cipher_compatibility must be pinned before the keying probe",
        );
        assert!(
            cipher_memory_security < key,
            "cipher_memory_security must be enabled before SQLCipher keying",
        );
        assert!(
            cipher_memory_security < key_probe,
            "cipher_memory_security must be enabled before the keying probe",
        );
    }

    #[test]
    fn public_hardened_open_pins_cipher_pragmas_before_keying() {
        let _guard = TRACE_TEST_LOCK.lock().unwrap();
        TRACED_SQLCIPHER_SETUP.lock().unwrap().clear();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hardened.sqlite");
        let key = SqlCipherKey::new("public hardened key").unwrap();
        let mut connection = rusqlite::Connection::open(path).unwrap();
        connection.trace(Some(trace_sqlcipher_setup));

        open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();

        let statements = TRACED_SQLCIPHER_SETUP.lock().unwrap().clone();
        let cipher_compatibility = statements
            .iter()
            .position(|statement| *statement == "cipher_compatibility")
            .expect("cipher_compatibility pragma was traced");
        let cipher_memory_security = statements
            .iter()
            .position(|statement| *statement == "cipher_memory_security")
            .expect("cipher_memory_security pragma was traced");
        let key = statements
            .iter()
            .position(|statement| *statement == "key")
            .expect("key pragma was traced");
        let key_probe = statements
            .iter()
            .position(|statement| *statement == "key_probe")
            .expect("keying probe was traced");

        assert!(
            cipher_compatibility < key,
            "cipher_compatibility must be pinned before SQLCipher keying",
        );
        assert!(
            cipher_compatibility < key_probe,
            "cipher_compatibility must be pinned before the keying probe",
        );
        assert!(
            cipher_memory_security < key,
            "cipher_memory_security must be enabled before SQLCipher keying",
        );
        assert!(
            cipher_memory_security < key_probe,
            "cipher_memory_security must be enabled before the keying probe",
        );
    }

    #[test]
    fn public_hardened_open_applies_requested_privacy_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hardened.sqlite");
        let key = SqlCipherKey::new("hardened privacy key").unwrap();

        let connection = rusqlite::Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
        assert_eq!(pragma_i64(&connection, "secure_delete"), 1);
        assert_eq!(pragma_i64(&connection, "temp_store"), 2);
        drop(connection);

        // cipher_only() must not switch temp_store to MEMORY. (secure_delete is
        // left at the SQLCipher compile-time default, which is ON, so it is not
        // asserted here — only the live-cache path opts into it explicitly.)
        let path = dir.path().join("cipher-only.sqlite");
        let connection = rusqlite::Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::cipher_only()).unwrap();
        assert_ne!(pragma_i64(&connection, "temp_store"), 2);
    }

    #[test]
    fn hardened_file_roundtrip_requires_the_correct_sqlcipher_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hardened-roundtrip.sqlite");
        let key = SqlCipherKey::new("hardened correct key").unwrap();
        let wrong_key = SqlCipherKey::new("hardened wrong key").unwrap();

        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE marker (value TEXT NOT NULL);
                     INSERT INTO marker (value) VALUES ('kept');",
                )
                .unwrap();
        }

        let file_bytes = std::fs::read(&path).unwrap();
        assert!(!file_bytes.starts_with(b"SQLite format 3\0"));

        // Wrong key cannot read the data.
        let connection = rusqlite::Connection::open(&path).unwrap();
        assert!(
            open_hardened_sqlcipher(&connection, &wrong_key, SqlCipherHardening::live_cache())
                .is_err()
        );
        drop(connection);

        // Correct key reopens and reads.
        let connection = rusqlite::Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
        let value: String = connection
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "kept");
    }

    #[test]
    fn custom_options_can_relax_operational_defaults_for_tests() {
        let store = SqliteAccountStorage::in_memory_with_options(SqliteStorageOptions {
            busy_timeout_ms: 250,
            journal_mode: SqliteJournalMode::Delete,
            synchronous: SqliteSynchronous::Normal,
            secure_delete: false,
            temp_store_memory: false,
            trusted_schema: true,
            cipher_memory_security: false,
            cipher_compatibility: 4,
        })
        .unwrap();
        let conn = store.lock().unwrap();

        assert_eq!(pragma_i64(&conn, "busy_timeout"), 250);
        assert_eq!(pragma_i64(&conn, "secure_delete"), 0);
        assert_eq!(pragma_i64(&conn, "trusted_schema"), 1);
        assert_eq!(pragma_i64(&conn, "synchronous"), 1);
    }

    #[test]
    fn encrypted_file_roundtrip_requires_the_correct_sqlcipher_key() {
        use crate::storage::test_support::{gid, sample_group};
        use cgka_traits::storage::GroupStorage;
        use cgka_traits::types::EpochId;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("correct horse battery staple").unwrap();
        let wrong_key = SqlCipherKey::new("wrong key").unwrap();

        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.put_group(&sample_group(gid(1), 3, 1)).unwrap();
        }

        let file_bytes = std::fs::read(&path).unwrap();
        assert!(!file_bytes.starts_with(b"SQLite format 3\0"));

        assert!(SqliteAccountStorage::open_encrypted(&path, &wrong_key).is_err());

        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(reopened.get_group(&gid(1)).unwrap().epoch, EpochId(3));
    }

    fn pragma_i64(connection: &rusqlite::Connection, name: &str) -> i64 {
        connection
            .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
            .unwrap()
    }

    fn pragma_string(connection: &rusqlite::Connection, name: &str) -> String {
        connection
            .query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, String>(0))
            .unwrap()
            .to_ascii_lowercase()
    }
}
