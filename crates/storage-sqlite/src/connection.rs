use crate::openmls_storage::SqliteOpenMlsStorage;
use crate::{SqliteResultExt, migrations};
use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use cgka_traits::types::Backend;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::ThreadId;
use std::time::Duration;
use zeroize::Zeroizing;

/// Maximum number of attempts a write operation makes before giving up and
/// surfacing the transient `Busy` error. The connection already sets
/// `PRAGMA busy_timeout`, so each attempt blocks for that long inside SQLite
/// before returning `SQLITE_BUSY`; this retry loop adds a second, coarser layer
/// so brief contention from a concurrent writer (a background sync, projection
/// rebuild, retention prune, or a WAL checkpoint racing the send path)
/// self-resolves instead of bubbling to the user as "Send failed". See issue
/// #484.
const BUSY_MAX_ATTEMPTS: u32 = 6;

/// Base backoff between busy retries. Backoff grows exponentially per attempt
/// (capped at [`BUSY_BACKOFF_CAP`]) with no jitter — the in-process write mutex
/// already serialises this connection's writers, so contention here is with a
/// *separate* connection/process and a deterministic backoff is sufficient.
const BUSY_BACKOFF_BASE: Duration = Duration::from_millis(20);

/// Upper bound on a single busy-retry backoff sleep.
const BUSY_BACKOFF_CAP: Duration = Duration::from_millis(250);

/// An error that may represent transient SQLite lock contention worth retrying.
/// Implemented for the two storage error types so [`retry_on_busy`] can drive a
/// retry loop without knowing which one a call site uses.
pub(crate) trait TransientError {
    /// Whether this error is transient lock contention (`SQLITE_BUSY` /
    /// `SQLITE_LOCKED`) rather than a durable failure.
    fn is_busy(&self) -> bool;
}

impl TransientError for StorageError {
    fn is_busy(&self) -> bool {
        matches!(self, StorageError::Busy(_))
    }
}

/// Run a whole storage operation, retrying with capped exponential backoff while
/// it fails with transient lock contention. `op` MUST be a complete, idempotent
/// unit of work (a single autocommit statement or an entire `BEGIN..COMMIT`
/// transaction) — never a single statement inside a larger transaction, since a
/// retry re-runs the closure from the top. On `SQLITE_BUSY`/`SQLITE_LOCKED`
/// SQLite has already rolled back the failed transaction, so re-running is safe.
/// After [`BUSY_MAX_ATTEMPTS`] the last transient error is returned unchanged so
/// callers still see a `Busy` (transient) classification.
pub(crate) fn retry_on_busy<T, E, F>(mut op: F) -> Result<T, E>
where
    E: TransientError,
    F: FnMut() -> Result<T, E>,
{
    let mut attempt: u32 = 0;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if err.is_busy() && attempt + 1 < BUSY_MAX_ATTEMPTS => {
                let backoff = busy_backoff(attempt);
                attempt += 1;
                std::thread::sleep(backoff);
            }
            Err(err) => return Err(err),
        }
    }
}

/// Exponential backoff for busy retry `attempt` (0-indexed), capped at
/// [`BUSY_BACKOFF_CAP`].
fn busy_backoff(attempt: u32) -> Duration {
    let scaled = BUSY_BACKOFF_BASE
        .checked_mul(1u32 << attempt.min(8))
        .unwrap_or(BUSY_BACKOFF_CAP);
    scaled.min(BUSY_BACKOFF_CAP)
}

#[derive(Clone)]
pub(crate) struct SharedConnection {
    inner: Arc<SharedConnectionInner>,
}

struct SharedConnectionInner {
    connection: Mutex<rusqlite::Connection>,
    transaction_owner: Mutex<Option<ThreadId>>,
    transaction_unusable: Mutex<Option<String>>,
    transaction_released: Condvar,
}

impl fmt::Debug for SharedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedConnection").finish_non_exhaustive()
    }
}

impl SharedConnection {
    fn new(connection: rusqlite::Connection) -> Self {
        Self {
            inner: Arc::new(SharedConnectionInner {
                connection: Mutex::new(connection),
                transaction_owner: Mutex::new(None),
                transaction_unusable: Mutex::new(None),
                transaction_released: Condvar::new(),
            }),
        }
    }

    pub(crate) fn lock(&self) -> StorageResult<MutexGuard<'_, rusqlite::Connection>> {
        let current = std::thread::current().id();
        loop {
            self.wait_for_transaction_slot(current)?;
            let connection = self
                .inner
                .connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let owner = self
                .inner
                .transaction_owner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(err) = self.transaction_unusable_error() {
                return Err(err);
            }
            if !owner.as_ref().is_some_and(|owner| owner != &current) {
                drop(owner);
                return Ok(connection);
            }
            drop(owner);
            drop(connection);
        }
    }

    pub(crate) fn is_current_thread_transaction_owner(&self) -> bool {
        let current = std::thread::current().id();
        let owner = self
            .inner
            .transaction_owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        owner.as_ref().is_some_and(|owner| owner == &current)
    }

    pub(crate) fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce() -> Result<T, E>,
    {
        let current = std::thread::current().id();
        let mut owner = self
            .inner
            .transaction_owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while owner.as_ref().is_some_and(|owner| owner != &current) {
            if let Some(err) = self.transaction_unusable_error() {
                return Err(E::from(err));
            }
            owner = self
                .inner
                .transaction_released
                .wait(owner)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if let Some(err) = self.transaction_unusable_error() {
            return Err(E::from(err));
        }

        // Nested transaction on the same thread: the outer SQL transaction is
        // already active and owns rollback/commit.
        if owner.as_ref().is_some_and(|owner| owner == &current) {
            drop(owner);
            return f();
        }

        *owner = Some(current);
        drop(owner);

        if let Err(err) = self.begin_immediate_with_retry() {
            self.clear_transaction_owner();
            return Err(E::from(err));
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        match result {
            Ok(Ok(value)) => match self.execute_transaction_boundary("COMMIT") {
                Ok(()) => {
                    self.clear_transaction_owner();
                    Ok(value)
                }
                Err(commit_err) => match self.execute_transaction_boundary("ROLLBACK") {
                    Ok(()) => {
                        self.clear_transaction_owner();
                        Err(E::from(commit_err))
                    }
                    Err(rollback_err) => Err(E::from(self.mark_transaction_unusable(format!(
                        "sqlite transaction COMMIT failed ({commit_err}); ROLLBACK after failed COMMIT also failed ({rollback_err}); connection marked unusable",
                    )))),
                },
            },
            Ok(Err(err)) => match self.execute_transaction_boundary("ROLLBACK") {
                Ok(()) => {
                    self.clear_transaction_owner();
                    Err(err)
                }
                Err(rollback_err) => Err(E::from(self.mark_transaction_unusable(format!(
                    "sqlite transaction ROLLBACK failed after callback error ({rollback_err}); connection marked unusable",
                )))),
            },
            Err(payload) => match self.execute_transaction_boundary("ROLLBACK") {
                Ok(()) => {
                    self.clear_transaction_owner();
                    std::panic::resume_unwind(payload);
                }
                Err(rollback_err) => {
                    let _ = self.mark_transaction_unusable(format!(
                        "sqlite transaction ROLLBACK failed during panic cleanup ({rollback_err}); connection marked unusable",
                    ));
                    std::panic::resume_unwind(payload);
                }
            },
        }
    }

    fn wait_for_transaction_slot(&self, current: ThreadId) -> StorageResult<()> {
        let mut owner = self
            .inner
            .transaction_owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(err) = self.transaction_unusable_error() {
                return Err(err);
            }
            if !owner.as_ref().is_some_and(|owner| owner != &current) {
                return Ok(());
            }
            owner = self
                .inner
                .transaction_released
                .wait(owner)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn execute_transaction_boundary(&self, sql: &str) -> StorageResult<()> {
        let conn = self
            .inner
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        conn.execute_batch(sql)
            .map_err(|e| StorageError::Backend(format!("sqlite transaction {sql}: {e}")))
    }

    /// Run `BEGIN IMMEDIATE`, retrying with capped exponential backoff on
    /// transient lock contention. `BEGIN IMMEDIATE` eagerly acquires the SQLite
    /// write lock, so it is the dominant `SQLITE_BUSY` surface when a separate
    /// connection/process is mid-write (background sync, projection rebuild,
    /// retention prune, or WAL checkpoint). No transaction work has run yet at
    /// this point, so retrying the BEGIN has no side effects. A busy failure
    /// that survives all attempts is surfaced as the transient
    /// [`StorageError::Busy`] so callers can tell it apart from a fatal backend
    /// fault (issue #484).
    fn begin_immediate_with_retry(&self) -> StorageResult<()> {
        retry_on_busy(|| {
            let conn = self
                .inner
                .connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(crate::codec::map_sqlite_error)
        })
    }

    fn transaction_unusable_error(&self) -> Option<StorageError> {
        let unusable = self
            .inner
            .transaction_unusable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unusable
            .as_ref()
            .map(|reason| StorageError::Backend(reason.clone()))
    }

    fn clear_transaction_owner(&self) {
        let mut owner = self
            .inner
            .transaction_owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *owner = None;
        self.inner.transaction_released.notify_all();
    }

    fn mark_transaction_unusable(&self, reason: String) -> StorageError {
        let mut owner = self
            .inner
            .transaction_owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut unusable = self
            .inner
            .transaction_unusable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if unusable.is_none() {
            *unusable = Some(reason.clone());
        }
        *owner = None;
        drop(unusable);
        drop(owner);
        self.inner.transaction_released.notify_all();
        StorageError::Backend(reason)
    }
}

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
        let connection = SharedConnection::new(connection);
        let openmls = SqliteOpenMlsStorage::new(connection.clone());
        Ok(Self {
            connection,
            openmls,
        })
    }

    pub(crate) fn lock(&self) -> StorageResult<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        self.connection.lock()
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

    fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection.with_transaction(|| f(self))
    }

    fn backend(&self) -> Backend {
        Backend::Sqlite
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, mpsc};

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
    fn transaction_rolls_back_openmls_writes_on_error() {
        use crate::storage::test_support::TestGroupState;
        use cgka_traits::storage::StorageError;
        use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;

        let store = SqliteAccountStorage::in_memory().unwrap();
        let group_id = openmls::group::GroupId::from_slice(b"transaction-rollback");

        let result: Result<(), StorageError> = store.with_transaction(|storage| {
            storage
                .mls_storage()
                .write_group_state(&group_id, &TestGroupState(b"partial".to_vec()))
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            Err(StorageError::Backend("force rollback".to_string()))
        });

        assert!(result.is_err());
        let persisted: Option<TestGroupState> = store.mls_storage().group_state(&group_id).unwrap();
        assert_eq!(persisted, None);
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct TestLeafNode(Vec<u8>);

    impl openmls_traits::storage::Entity<{ openmls_traits::storage::CURRENT_VERSION }>
        for TestLeafNode
    {
    }
    impl openmls_traits::storage::traits::LeafNode<{ openmls_traits::storage::CURRENT_VERSION }>
        for TestLeafNode
    {
    }

    #[test]
    fn transaction_allows_openmls_list_mutations_inside_outer_transaction() {
        use cgka_traits::storage::StorageError;
        use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;

        let store = SqliteAccountStorage::in_memory().unwrap();
        let group_id = openmls::group::GroupId::from_slice(b"transaction-list-mutation");

        store
            .with_transaction(|storage| {
                storage
                    .mls_storage()
                    .append_own_leaf_node(&group_id, &TestLeafNode(b"leaf".to_vec()))
                    .map_err(|e| StorageError::Backend(e.to_string()))
            })
            .unwrap();

        let leaves: Vec<TestLeafNode> = store.mls_storage().own_leaf_nodes(&group_id).unwrap();
        assert_eq!(leaves, vec![TestLeafNode(b"leaf".to_vec())]);
    }

    #[test]
    fn connection_lock_rechecks_transaction_owner_after_acquiring_connection() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let shared = store.connection.clone();
        let connection_guard = shared
            .inner
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (lock_returned_tx, lock_returned_rx) = mpsc::channel();
        let worker_connection = shared.clone();
        let worker = std::thread::spawn(move || {
            let _guard = worker_connection.lock().unwrap();
            lock_returned_tx.send(()).unwrap();
        });

        std::thread::sleep(Duration::from_millis(100));
        {
            let mut owner = shared
                .inner
                .transaction_owner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *owner = Some(std::thread::current().id());
        }
        drop(connection_guard);

        assert!(
            lock_returned_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "non-owner connection lock entered another thread's transaction",
        );

        shared.clear_transaction_owner();
        lock_returned_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("connection lock should proceed after the transaction owner clears");
        worker.join().unwrap();
    }

    #[test]
    fn transaction_rolls_back_after_failed_commit_before_releasing_owner() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute_batch(
                "CREATE TABLE deferred_parent (id INTEGER PRIMARY KEY);
                 CREATE TABLE deferred_child (
                     parent_id INTEGER NOT NULL REFERENCES deferred_parent(id) DEFERRABLE INITIALLY DEFERRED
                 );",
            )
            .storage()
            .unwrap();
        }

        let result: StorageResult<()> = store.with_transaction(|storage| {
            let conn = storage.lock()?;
            conn.execute("INSERT INTO deferred_child (parent_id) VALUES (7)", [])
                .storage()?;
            Ok(())
        });

        assert!(result.is_err());
        let conn = store.lock().unwrap();
        assert!(
            conn.is_autocommit(),
            "failed COMMIT must not leave the connection inside a transaction",
        );
        let child_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM deferred_child", [], |row| row.get(0))
            .storage()
            .unwrap();
        assert_eq!(child_count, 0);
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

    #[test]
    fn busy_backoff_grows_and_is_capped() {
        assert_eq!(busy_backoff(0), BUSY_BACKOFF_BASE);
        assert_eq!(busy_backoff(1), BUSY_BACKOFF_BASE * 2);
        assert_eq!(busy_backoff(2), BUSY_BACKOFF_BASE * 4);
        // Large attempt counts saturate at the cap rather than overflowing.
        assert_eq!(busy_backoff(20), BUSY_BACKOFF_CAP);
        assert!(busy_backoff(3) <= BUSY_BACKOFF_CAP);
    }

    #[test]
    fn retry_on_busy_retries_transient_then_succeeds() {
        let mut calls = 0u32;
        let result: Result<u32, StorageError> = retry_on_busy(|| {
            calls += 1;
            if calls < 3 {
                Err(StorageError::Busy("locked".into()))
            } else {
                Ok(calls)
            }
        });
        assert_eq!(result.unwrap(), 3, "should succeed once the busy clears");
    }

    #[test]
    fn retry_on_busy_does_not_retry_fatal_errors() {
        let mut calls = 0u32;
        let result: Result<(), StorageError> = retry_on_busy(|| {
            calls += 1;
            Err(StorageError::Backend("fatal".into()))
        });
        assert!(matches!(result, Err(StorageError::Backend(_))));
        assert_eq!(calls, 1, "fatal errors must not be retried");
    }

    #[test]
    fn retry_on_busy_surfaces_busy_after_exhausting_attempts() {
        let mut calls = 0u32;
        let result: Result<(), StorageError> = retry_on_busy(|| {
            calls += 1;
            Err(StorageError::Busy("still locked".into()))
        });
        assert!(
            matches!(result, Err(StorageError::Busy(_))),
            "persistent busy must surface as a transient Busy error, not Backend"
        );
        assert_eq!(calls, BUSY_MAX_ATTEMPTS, "must use the full attempt budget");
    }

    // Regression for issue #484: a concurrent writer on a SECOND connection to
    // the same database file briefly holds the SQLite write lock. With a busy
    // timeout shorter than the hold, the first attempt sees SQLITE_BUSY; the
    // storage layer's retry-with-backoff must wait it out so the send-path
    // write succeeds instead of bubbling "database is locked" to the user.
    #[test]
    fn concurrent_writer_contention_is_retried_not_surfaced() {
        use crate::storage::test_support::{gid, mid, sample_group, sample_message};
        use cgka_traits::storage::{GroupStorage, MessageStorage};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contention.sqlite");
        let key = SqlCipherKey::new("contention test key").unwrap();
        // Short busy timeout so the *first* attempt fails fast and the win comes
        // from the retry loop, not from SQLite's own busy_timeout wait.
        let options = SqliteStorageOptions {
            busy_timeout_ms: 50,
            ..SqliteStorageOptions::default()
        };

        let writer =
            SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone())
                .unwrap();
        writer.put_group(&sample_group(gid(1), 0, 0)).unwrap();

        // A separate connection/handle to the same file holds an exclusive write
        // transaction for longer than one busy-timeout window, then releases.
        let hold = std::time::Duration::from_millis(200);
        let blocker_options = options.clone();
        let blocker_key = SqlCipherKey::new("contention test key").unwrap();
        let blocker_path = path.clone();
        let blocker = std::thread::spawn(move || {
            let blocker = SqliteAccountStorage::open_encrypted_with_options(
                &blocker_path,
                &blocker_key,
                blocker_options,
            )
            .unwrap();
            let conn = blocker.lock().unwrap();
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            conn.execute(
                "INSERT INTO cgka_groups (id, record) VALUES (?1, ?2)",
                rusqlite::params![gid(2).as_slice(), b"blocker".as_slice()],
            )
            .ok();
            std::thread::sleep(hold);
            conn.execute_batch("COMMIT").unwrap();
        });

        // Give the blocker time to take the write lock before we try to write.
        std::thread::sleep(std::time::Duration::from_millis(40));

        // This write contends with the blocker. Without retry it would return
        // a "database is locked" error after the 50ms busy timeout; with retry
        // it waits out the 200ms hold and succeeds.
        writer
            .put_message(&sample_message(mid(1), gid(1), 0))
            .expect("contended write must succeed via busy retry, not surface as failure");

        blocker.join().unwrap();
        assert_eq!(
            writer.get_message(&mid(1)).unwrap().id,
            mid(1),
            "the message persisted after contention cleared"
        );
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
