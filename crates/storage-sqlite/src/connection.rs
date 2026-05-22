use crate::openmls_storage::SqliteOpenMlsStorage;
use crate::{SqliteResultExt, migrations};
use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use cgka_traits::types::Backend;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) type SharedConnection = Arc<Mutex<rusqlite::Connection>>;

#[derive(Clone)]
pub struct SqlCipherKey(String);

impl SqlCipherKey {
    pub fn new(key: impl Into<String>) -> StorageResult<Self> {
        let key = key.into();
        if key.is_empty() {
            return Err(StorageError::Backend(
                "SQLCipher key must not be empty".to_string(),
            ));
        }
        Ok(Self(key))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub struct SqliteStorage {
    pub(crate) connection: SharedConnection,
    pub(crate) openmls: SqliteOpenMlsStorage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqliteStorageOptions {
    pub busy_timeout_ms: u64,
    pub journal_mode: SqliteJournalMode,
    pub synchronous: SqliteSynchronous,
    pub secure_delete: bool,
    pub temp_store_memory: bool,
    pub trusted_schema: bool,
    pub cipher_memory_security: bool,
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

impl SqliteStorage {
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
        self.connection
            .lock()
            .map_err(|e| StorageError::Backend(format!("sqlite connection lock poisoned: {e}")))
    }
}

fn apply_sqlcipher_key(connection: &rusqlite::Connection, key: &SqlCipherKey) -> StorageResult<()> {
    connection
        .pragma_update(None, "key", key.as_str())
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

impl StorageProvider for SqliteStorage {
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
        let setup_step = if sql.contains("cipher_memory_security") {
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
            SqliteStorage::in_memory().unwrap().backend(),
            Backend::Sqlite
        );
    }

    #[test]
    fn encrypted_connection_applies_operational_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("operational defaults key").unwrap();
        let store = SqliteStorage::open_encrypted(&path, &key).unwrap();
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
    fn encrypted_connection_enables_cipher_memory_security_before_keying() {
        let _guard = TRACE_TEST_LOCK.lock().unwrap();
        TRACED_SQLCIPHER_SETUP.lock().unwrap().clear();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("trace setup key").unwrap();
        let mut connection = rusqlite::Connection::open(path).unwrap();
        connection.trace(Some(trace_sqlcipher_setup));

        let _store = SqliteStorage::from_unkeyed_encrypted_connection_with_options(
            connection,
            &key,
            SqliteStorageOptions::default(),
        )
        .unwrap();

        let statements = TRACED_SQLCIPHER_SETUP.lock().unwrap().clone();
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
            cipher_memory_security < key,
            "cipher_memory_security must be enabled before SQLCipher keying",
        );
        assert!(
            cipher_memory_security < key_probe,
            "cipher_memory_security must be enabled before the keying probe",
        );
    }

    #[test]
    fn custom_options_can_relax_operational_defaults_for_tests() {
        let store = SqliteStorage::in_memory_with_options(SqliteStorageOptions {
            busy_timeout_ms: 250,
            journal_mode: SqliteJournalMode::Delete,
            synchronous: SqliteSynchronous::Normal,
            secure_delete: false,
            temp_store_memory: false,
            trusted_schema: true,
            cipher_memory_security: false,
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
            let store = SqliteStorage::open_encrypted(&path, &key).unwrap();
            store.put_group(&sample_group(gid(1), 3, 1)).unwrap();
        }

        let file_bytes = std::fs::read(&path).unwrap();
        assert!(!file_bytes.starts_with(b"SQLite format 3\0"));

        assert!(SqliteStorage::open_encrypted(&path, &wrong_key).is_err());

        let reopened = SqliteStorage::open_encrypted(&path, &key).unwrap();
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
