use crate::openmls_storage::SqliteOpenMlsStorage;
use crate::{SqliteResultExt, migrations};
use cgka_traits::storage::{
    KeyPackageBundleStorage, StorageError, StorageProvider, StorageResult, StoredKeyPackageBundle,
};
use cgka_traits::types::Backend;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Retry an operation with capped exponential backoff while it fails with
/// transient lock contention. `op` MUST be safe to invoke again. Most callers
/// pass a complete, idempotent storage operation (a single autocommit statement
/// or an entire transaction), never one statement from the middle of a larger
/// transaction. Transaction-boundary callers are the deliberate exception:
/// they retry only `COMMIT` or `ROLLBACK` in place while retaining transaction
/// ownership, without re-running the transaction closure. After
/// [`BUSY_MAX_ATTEMPTS`] the last transient error is returned unchanged so
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

/// Message carried by every [`StorageError::Closed`] this module raises.
const CLOSED_DETAIL: &str = "sqlite account storage is closed";

/// Coarse, privacy-safe label for a `rusqlite::Error`, for `tracing` fields.
/// The full error text can carry SQL, so only the classification is logged.
fn sqlite_error_kind(error: &rusqlite::Error) -> &'static str {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy) => "busy",
        Some(rusqlite::ErrorCode::DatabaseLocked) => "locked",
        Some(_) => "sqlite",
        None => "rusqlite",
    }
}

/// Borrowed access to the live `rusqlite::Connection` behind a
/// [`CloseableConnection`].
///
/// The connection lives in an `Option` so a close can take it out and close it
/// for real while other handles are still alive. Every path that hands out a
/// guard has already checked, *while holding the same mutex the guard holds*,
/// that the slot is occupied, so the deref is infallible for the guard's
/// lifetime.
pub struct ConnectionGuard<'a> {
    guard: MutexGuard<'a, Option<rusqlite::Connection>>,
}

impl Deref for ConnectionGuard<'_> {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        self.guard
            .as_ref()
            .expect("connection guard outlived its checked slot")
    }
}

impl DerefMut for ConnectionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard
            .as_mut()
            .expect("connection guard outlived its checked slot")
    }
}

/// A `rusqlite::Connection` that can be closed on demand, even while other
/// handles to it survive.
///
/// Dropping handles is not a usable close for a shared connection: it lives
/// behind an `Arc` reachable from the engine, the OpenMLS adapter, and app
/// projections at once, so a host has no way to observe or await the last clone
/// going away. And in WAL mode an open connection holds a persistent lock on
/// its `-shm` sidecar for its whole lifetime — on iOS a process suspended while
/// holding a lock in a shared App Group container is killed with `0xdead10cc`.
/// Hosts therefore need an operation that ends the connection at a known
/// instant and can be awaited.
///
/// This type is that operation. It is the shared building block for every
/// closeable SQLite handle in the workspace, including databases opened outside
/// the [`SqliteAccountStorage`] aggregate (the app's shared cache and directory
/// caches), so the checkpoint-then-close ordering and the closed-state contract
/// live in one place.
#[derive(Debug)]
pub struct CloseableConnection {
    slot: Mutex<Option<rusqlite::Connection>>,
    /// Published before [`Self::close`] waits for the connection mutex. New
    /// operations must stop being admitted as soon as closing begins; otherwise
    /// racing callers could repeatedly acquire `slot` ahead of the closer and
    /// extend the host's suspension-critical teardown indefinitely.
    closed: AtomicBool,
    /// Detail carried by the [`StorageError::Closed`] this connection raises,
    /// naming which database is closed.
    closed_detail: &'static str,
}

impl CloseableConnection {
    /// Take ownership of `connection`. `closed_detail` names this database in
    /// the [`StorageError::Closed`] raised after a close.
    #[must_use]
    pub fn new(connection: rusqlite::Connection, closed_detail: &'static str) -> Self {
        Self {
            slot: Mutex::new(Some(connection)),
            closed: AtomicBool::new(false),
            closed_detail,
        }
    }

    /// Borrow the connection, or fail with [`StorageError::Closed`] if it has
    /// been closed or is currently closing.
    pub fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        if self.is_closed() {
            return Err(StorageError::Closed(self.closed_detail.to_string()));
        }
        let guard = self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // `close` may have published after the optimistic check but before this
        // mutex acquisition. Recheck under the mutex so a caller that queued
        // behind the closer cannot start fresh work during teardown.
        if self.is_closed() || guard.is_none() {
            return Err(StorageError::Closed(self.closed_detail.to_string()));
        }
        Ok(ConnectionGuard { guard })
    }

    /// Whether [`Self::close`] has started. Nonblocking.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Checkpoint the WAL and close the connection, releasing every file lock
    /// it holds on the database and its `-wal`/`-shm` sidecars.
    ///
    /// Idempotent: a second call finds an empty slot and returns `Ok(())`.
    /// Blocking only for as long as the statement currently executing on
    /// another thread; SQLite rolls back any transaction still open on that
    /// connection as part of closing, so a half-applied transaction is not a
    /// reachable outcome.
    ///
    /// A failed checkpoint is logged and does not block the close: leaving a
    /// larger `-wal` behind costs the next open a replay, whereas leaving the
    /// connection open costs the host its process.
    pub fn close(&self) -> StorageResult<()> {
        // Close admission before waiting for the currently executing operation.
        // Do not return early when this was already set: concurrent close
        // callers still have to serialize on `slot` so every return truthfully
        // means the connection has been taken and closed.
        self.closed.store(true, Ordering::Release);
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(connection) = slot.take() else {
            return Ok(());
        };

        // TRUNCATE folds the WAL back into the main database and resets the
        // file to zero length, so the next open starts from a clean sidecar
        // rather than replaying this session's log. It is a no-op error on
        // rollback-journal databases, which is why the failure is not fatal.
        if let Err(error) = connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
            tracing::debug!(
                target: "storage_sqlite::connection",
                method = "close",
                error_kind = sqlite_error_kind(&error),
                "wal checkpoint before close failed; closing anyway",
            );
        }

        match connection.close() {
            Ok(()) => Ok(()),
            Err((connection, error)) => {
                // `close` handing the connection back means SQLite still had
                // work attached to it. Drop it regardless: rusqlite's `Drop`
                // uses `sqlite3_close_v2`, which detaches the handle and frees
                // it once that work finishes, so the file locks still go away.
                drop(connection);
                Err(StorageError::Backend(format!(
                    "closing sqlite connection: {error}"
                )))
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct SharedConnection {
    inner: Arc<SharedConnectionInner>,
}

struct SharedConnectionInner {
    connection: CloseableConnection,
    /// Set before the connection is taken so threads parked on
    /// [`SharedConnectionInner::transaction_released`] wake up and bail out
    /// rather than waiting for a transaction owner that will never run again.
    closed: AtomicBool,
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
                connection: CloseableConnection::new(connection, CLOSED_DETAIL),
                closed: AtomicBool::new(false),
                transaction_owner: Mutex::new(None),
                transaction_unusable: Mutex::new(None),
                transaction_released: Condvar::new(),
            }),
        }
    }

    pub(crate) fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        let current = std::thread::current().id();
        loop {
            self.wait_for_transaction_slot(current)?;
            let connection = self.inner.connection.lock()?;
            let owner = self
                .inner
                .transaction_owner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(err) = self.unusable_error() {
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

    /// Whether [`Self::close`] has run (or is running) on this connection.
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// Checkpoint the WAL and close the underlying `rusqlite::Connection`,
    /// releasing every database file lock it holds.
    ///
    /// This is the only way to guarantee the `-wal`/`-shm` sidecars are
    /// unlocked: in WAL mode an open connection holds a persistent shared lock
    /// on `-shm` for its entire lifetime, and dropping one `SharedConnection`
    /// clone does nothing while other clones survive somewhere in the process.
    /// Hosts that must be lock-free at a known instant — notably iOS apps
    /// facing the `0xdead10cc` suspension kill for holding a lock in a shared
    /// App Group container — call this and await it.
    ///
    /// Behavior:
    /// - Idempotent. The second and later calls see an empty slot and return
    ///   `Ok(())`.
    /// - Terminal. Surviving clones (including the OpenMLS adapter's) fail with
    ///   [`StorageError::Closed`]; nothing reopens. Callers construct a fresh
    ///   [`SqliteAccountStorage`] to use the database again.
    /// - Safe under concurrent work. Acquiring the connection mutex waits out
    ///   whatever statement is executing; an open transaction owned by another
    ///   thread is rolled back by SQLite as part of closing, and that thread's
    ///   next call fails with [`StorageError::Closed`]. Partial application is
    ///   therefore impossible — a transaction either committed before the close
    ///   or was discarded whole.
    ///
    /// A failed checkpoint is logged and does not prevent the close: leaving a
    /// larger `-wal` behind costs the next open a replay, whereas leaving the
    /// connection open costs the host its process.
    pub(crate) fn close(&self) -> StorageResult<()> {
        // Publish "closed" before taking the connection so anyone parked in
        // `wait_for_transaction_slot` wakes to an error rather than a deadlock.
        self.inner.closed.store(true, Ordering::Release);
        self.wake_transaction_waiters();
        self.inner.connection.close()
    }

    fn wake_transaction_waiters(&self) {
        let _owner = self
            .inner
            .transaction_owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.inner.transaction_released.notify_all();
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
            if let Some(err) = self.unusable_error() {
                return Err(E::from(err));
            }
            owner = self
                .inner
                .transaction_released
                .wait(owner)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if let Some(err) = self.unusable_error() {
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
            Ok(Ok(value)) => match self.execute_transaction_boundary_with_retry("COMMIT") {
                Ok(()) => {
                    self.clear_transaction_owner();
                    Ok(value)
                }
                Err(commit_err) => match self.execute_transaction_boundary_with_retry("ROLLBACK") {
                    Ok(()) => {
                        self.clear_transaction_owner();
                        Err(E::from(commit_err))
                    }
                    Err(rollback_err) => Err(E::from(self.mark_transaction_unusable(format!(
                        "sqlite transaction COMMIT failed ({commit_err}); ROLLBACK after failed COMMIT also failed ({rollback_err}); connection marked unusable",
                    )))),
                },
            },
            Ok(Err(err)) => match self.execute_transaction_boundary_with_retry("ROLLBACK") {
                Ok(()) => {
                    self.clear_transaction_owner();
                    Err(err)
                }
                Err(rollback_err) => Err(E::from(self.mark_transaction_unusable(format!(
                    "sqlite transaction ROLLBACK failed after callback error ({rollback_err}); connection marked unusable",
                )))),
            },
            Err(payload) => match self.execute_transaction_boundary_with_retry("ROLLBACK") {
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
            if let Some(err) = self.unusable_error() {
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

    /// Finish the active transaction without releasing its in-process owner.
    ///
    /// SQLite leaves a transaction active when `COMMIT` returns
    /// `SQLITE_BUSY`, so retrying that boundary in place is safe and avoids
    /// re-running the arbitrary transaction closure. `ROLLBACK` uses the same
    /// bounded policy so a transient boundary failure cannot strand a usable
    /// connection. Ownership is cleared only by the caller after a boundary
    /// succeeds; an exhausted rollback instead marks the connection unusable.
    ///
    /// A boundary that lands after [`Self::close`] took the connection is not
    /// a fault: closing rolls the open transaction back inside SQLite. So a
    /// `ROLLBACK` against a closed connection reports success — the rollback it
    /// asked for has already happened — while a `COMMIT` reports
    /// [`StorageError::Closed`], because that work was discarded. Reporting the
    /// rollback as a failure instead would latch the connection "unusable" and
    /// turn an orderly host suspension into a corruption-shaped error.
    fn execute_transaction_boundary_with_retry(&self, sql: &str) -> StorageResult<()> {
        retry_transaction_boundary(sql, || {
            let Ok(conn) = self.inner.connection.lock() else {
                return Err(BoundaryOutcome::Closed);
            };
            conn.execute_batch(sql).map_err(BoundaryOutcome::Sqlite)
        })
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
            self.inner
                .connection
                .lock()?
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(crate::codec::map_sqlite_error)
        })
    }

    /// The reason this connection can no longer serve work, if any. Closing
    /// takes precedence over a latched transaction fault: once the host has
    /// closed the store, "closed" is the accurate and more actionable answer.
    fn unusable_error(&self) -> Option<StorageError> {
        if self.is_closed() {
            return Some(StorageError::Closed(CLOSED_DETAIL.to_string()));
        }
        self.transaction_unusable_error()
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

/// Why a transaction-boundary statement did not execute.
enum BoundaryOutcome {
    /// SQLite ran the statement and rejected it.
    Sqlite(rusqlite::Error),
    /// The connection was closed before the statement could run.
    Closed,
}

fn retry_transaction_boundary<F>(sql: &str, mut execute: F) -> StorageResult<()>
where
    F: FnMut() -> Result<(), BoundaryOutcome>,
{
    retry_on_busy(|| {
        execute().map_err(|outcome| match outcome {
            // Closing the connection rolled the transaction back inside
            // SQLite, so the rollback this boundary wanted is already done.
            // A commit, by contrast, genuinely did not happen.
            BoundaryOutcome::Closed if sql == "ROLLBACK" => {
                BoundaryClosedOrError::RolledBackByClose
            }
            BoundaryOutcome::Closed => BoundaryClosedOrError::Error(StorageError::Closed(format!(
                "sqlite transaction {sql}: {CLOSED_DETAIL}"
            ))),
            BoundaryOutcome::Sqlite(error) => {
                BoundaryClosedOrError::Error(match crate::codec::map_sqlite_error(error) {
                    StorageError::Busy(detail) => {
                        StorageError::Busy(format!("sqlite transaction {sql}: {detail}"))
                    }
                    StorageError::Backend(detail) => {
                        StorageError::Backend(format!("sqlite transaction {sql}: {detail}"))
                    }
                    other => StorageError::Backend(format!("sqlite transaction {sql}: {other}")),
                })
            }
        })
    })
    .or_else(|outcome| match outcome {
        BoundaryClosedOrError::RolledBackByClose => Ok(()),
        BoundaryClosedOrError::Error(error) => Err(error),
    })
}

/// [`retry_transaction_boundary`]'s internal error, distinguishing the
/// "already rolled back by close" success-in-disguise from a real failure.
enum BoundaryClosedOrError {
    RolledBackByClose,
    Error(StorageError),
}

impl TransientError for BoundaryClosedOrError {
    fn is_busy(&self) -> bool {
        matches!(self, Self::Error(error) if error.is_busy())
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
    /// Export one group's convergence/OpenMLS state, including any durable
    /// convergence pass, for a sensitive test-only replay capsule.
    #[cfg(feature = "test-conformance-replay")]
    pub fn export_conformance_replay_snapshot(
        &self,
        group_id: &cgka_traits::types::GroupId,
    ) -> StorageResult<Vec<u8>> {
        crate::storage::snapshots::export_replay(self, group_id)
    }

    /// Restore a sensitive test-only conformance replay snapshot into this
    /// account-device database.
    #[cfg(feature = "test-conformance-replay")]
    pub fn import_conformance_replay_snapshot(
        &self,
        group_id: &cgka_traits::types::GroupId,
        snapshot: &[u8],
    ) -> StorageResult<()> {
        crate::storage::snapshots::import_replay(self, group_id, snapshot)
    }

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
        let path = path.as_ref();
        ensure_private_db_files(path)?;
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

    pub(crate) fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        self.connection.lock()
    }

    /// Checkpoint the WAL and close this account database, releasing every
    /// file lock it holds on the main database and its `-wal`/`-shm` sidecars.
    ///
    /// **Closing is terminal.** Every clone of this handle — including the
    /// OpenMLS adapter reached through
    /// [`StorageProvider::mls_storage`][cgka_traits::storage::StorageProvider::mls_storage]
    /// and any clone held elsewhere in the process — fails with
    /// [`StorageError::Closed`] from here on. Nothing reopens implicitly; to
    /// use the database again, construct a new [`SqliteAccountStorage`].
    ///
    /// Callers should quiesce their own work first. Closing is nonetheless
    /// safe under concurrent use: it waits out the statement currently
    /// executing, and SQLite rolls back any transaction still open on another
    /// thread as part of closing, so a partially applied transaction is not a
    /// reachable outcome. Idempotent — later calls return `Ok(())`.
    ///
    /// This exists because dropping handles is not a usable close: the
    /// connection lives behind an `Arc` shared by the engine, the OpenMLS
    /// adapter, and app projections, so a host has no way to observe or await
    /// the last clone going away. Hosts that must be provably lock-free at a
    /// known instant need this — on iOS, a WAL connection left open across app
    /// suspension holds a lock in the shared App Group container and the
    /// process is killed with `0xdead10cc`.
    pub fn close(&self) -> StorageResult<()> {
        self.connection.close()
    }

    /// Whether [`Self::close`] has run on this database.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }
}

/// Make a database file owner-only before SQLite can create it at the process
/// umask; see `fs_private::ensure_private_db_files` for the sidecar rules.
pub(crate) fn ensure_private_db_files(path: &Path) -> StorageResult<()> {
    fs_private::ensure_private_db_files(path).map_err(|err| StorageError::Backend(err.to_string()))
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

    fn maintenance_storage(&self) -> Option<&dyn cgka_traits::storage::MaintenanceStorage> {
        Some(self)
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

impl KeyPackageBundleStorage for SqliteAccountStorage {
    fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>> {
        self.openmls.stored_key_package_bundles()
    }

    fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()> {
        self.openmls.delete_stored_key_package_bundle(storage_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::trace::{TraceEvent, TraceEventCodes};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
        mpsc,
    };

    static TRACE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static TRACED_SQLCIPHER_SETUP: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    fn delete_journal_options() -> SqliteStorageOptions {
        SqliteStorageOptions {
            busy_timeout_ms: 0,
            journal_mode: SqliteJournalMode::Delete,
            ..SqliteStorageOptions::default()
        }
    }

    fn open_delete_journal_store(path: &Path) -> SqliteAccountStorage {
        SqliteAccountStorage::open_encrypted_with_options(
            path,
            &SqlCipherKey::new("delete journal transaction boundary key").unwrap(),
            delete_journal_options(),
        )
        .unwrap()
    }

    fn sqlite_failure(primary: std::os::raw::c_int) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(primary),
            Some("database is locked".to_string()),
        )
    }

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

    fn trace_sqlcipher_setup_event(event: TraceEvent<'_>) {
        if let TraceEvent::Stmt(_, sql) = event {
            trace_sqlcipher_setup(sql);
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
    fn bundled_sqlcipher_contains_the_wal_reset_corruption_fix() {
        fn version_tuple(value: &str) -> (u64, u64, u64) {
            let numeric = value.split_ascii_whitespace().next().unwrap_or(value);
            let mut components = numeric.split('.').map(|part| {
                part.parse::<u64>()
                    .unwrap_or_else(|_| panic!("invalid runtime version {value:?}"))
            });
            (
                components.next().unwrap_or(0),
                components.next().unwrap_or(0),
                components.next().unwrap_or(0),
            )
        }

        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let sqlite_version: String = connection
            .query_row("SELECT sqlite_version()", [], |row| row.get(0))
            .unwrap();
        let sqlcipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .unwrap();

        assert!(
            version_tuple(&sqlite_version) >= (3, 51, 3),
            "SQLite {sqlite_version} predates the WAL-reset corruption fix"
        );
        assert!(
            version_tuple(&sqlcipher_version) >= (4, 14, 0),
            "SQLCipher {sqlcipher_version} does not contain fixed SQLite 3.51.3"
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
        let connection_guard = shared.inner.connection.lock().unwrap();
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
    fn delete_journal_transient_commit_contention_retries_boundary_not_closure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transient-commit.sqlite");
        let writer = open_delete_journal_store(&path);
        {
            let conn = writer.lock().unwrap();
            conn.execute_batch("CREATE TABLE boundary_probe (value INTEGER NOT NULL)")
                .unwrap();
        }
        let reader = open_delete_journal_store(&path);
        let reader_conn = reader.lock().unwrap();
        reader_conn.execute_batch("BEGIN").unwrap();
        let _: i64 = reader_conn
            .query_row("SELECT COUNT(*) FROM boundary_probe", [], |row| row.get(0))
            .unwrap();

        let closure_calls = Arc::new(AtomicU32::new(0));
        let worker_calls = closure_calls.clone();
        let worker_store = writer.clone();
        let (closure_done_tx, closure_done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_store.with_transaction(|storage| {
                worker_calls.fetch_add(1, Ordering::SeqCst);
                storage
                    .lock()?
                    .execute("INSERT INTO boundary_probe (value) VALUES (1)", [])
                    .storage()?;
                closure_done_tx.send(()).unwrap();
                Ok::<_, StorageError>(())
            })
        });

        closure_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer closure should reach the contended COMMIT");

        let waiting_store = writer.clone();
        let (lock_acquired_tx, lock_acquired_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _guard = waiting_store.lock().unwrap();
            lock_acquired_tx.send(()).unwrap();
        });
        assert!(
            lock_acquired_rx
                .recv_timeout(Duration::from_millis(60))
                .is_err(),
            "transaction ownership must remain held while COMMIT is retrying",
        );

        reader_conn.execute_batch("COMMIT").unwrap();
        drop(reader_conn);
        worker
            .join()
            .unwrap()
            .expect("COMMIT should succeed after reader contention clears");
        lock_acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("connection waiter should proceed after COMMIT finishes");
        waiter.join().unwrap();

        assert_eq!(
            closure_calls.load(Ordering::SeqCst),
            1,
            "busy COMMIT retries must not rerun the transaction closure",
        );
        let persisted: i64 = writer
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM boundary_probe", [], |row| row.get(0))
            .unwrap();
        assert_eq!(persisted, 1);
    }

    #[test]
    fn delete_journal_persistent_commit_contention_returns_busy_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("persistent-commit.sqlite");
        let writer = open_delete_journal_store(&path);
        {
            let conn = writer.lock().unwrap();
            conn.execute_batch("CREATE TABLE boundary_probe (value INTEGER NOT NULL)")
                .unwrap();
        }
        let reader = open_delete_journal_store(&path);
        let reader_conn = reader.lock().unwrap();
        reader_conn.execute_batch("BEGIN").unwrap();
        let _: i64 = reader_conn
            .query_row("SELECT COUNT(*) FROM boundary_probe", [], |row| row.get(0))
            .unwrap();

        let mut closure_calls = 0;
        let result: StorageResult<()> = writer.with_transaction(|storage| {
            closure_calls += 1;
            storage
                .lock()?
                .execute("INSERT INTO boundary_probe (value) VALUES (1)", [])
                .storage()?;
            Ok(())
        });

        assert!(
            matches!(result, Err(StorageError::Busy(_))),
            "exhausted COMMIT contention must remain retryable Busy, got {result:?}",
        );
        assert!(
            result
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("sqlite transaction COMMIT"),
            "busy classification should retain transaction-boundary context",
        );
        assert_eq!(
            closure_calls, 1,
            "persistent COMMIT contention must not rerun the closure",
        );
        assert!(
            writer.lock().unwrap().is_autocommit(),
            "failed COMMIT must be rolled back before ownership is released",
        );

        reader_conn.execute_batch("COMMIT").unwrap();
        drop(reader_conn);
        writer
            .with_transaction(|storage| {
                storage
                    .lock()?
                    .execute("INSERT INTO boundary_probe (value) VALUES (2)", [])
                    .storage()?;
                Ok::<_, StorageError>(())
            })
            .expect("connection must remain usable after contended COMMIT rollback");
        let values: i64 = writer
            .lock()
            .unwrap()
            .query_row("SELECT SUM(value) FROM boundary_probe", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(values, 2, "the rolled-back value must not persist");
    }

    #[test]
    fn delete_journal_fatal_commit_failure_rolls_back_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fatal-commit.sqlite");
        let store = open_delete_journal_store(&path);
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

        let mut closure_calls = 0;
        let result: StorageResult<()> = store.with_transaction(|storage| {
            closure_calls += 1;
            let conn = storage.lock()?;
            conn.execute("INSERT INTO deferred_child (parent_id) VALUES (7)", [])
                .storage()?;
            Ok(())
        });

        assert!(
            matches!(result, Err(StorageError::Backend(_))),
            "deferred constraint failure must remain fatal Backend, got {result:?}",
        );
        assert_eq!(closure_calls, 1, "fatal COMMIT must not rerun the closure");
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
        drop(conn);
        store
            .with_transaction(|storage| {
                storage
                    .lock()?
                    .execute("INSERT INTO deferred_parent (id) VALUES (7)", [])
                    .storage()?;
                Ok::<_, StorageError>(())
            })
            .expect("connection must remain usable after fatal COMMIT rollback");
    }

    #[test]
    fn delete_journal_rollback_boundary_retries_busy_and_locked_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback-classification.sqlite");
        let store = open_delete_journal_store(&path);
        assert_eq!(
            pragma_string(&store.lock().unwrap(), "journal_mode"),
            "delete"
        );

        let mut calls = 0;
        retry_transaction_boundary("ROLLBACK", || {
            calls += 1;
            match calls {
                1 => Err(BoundaryOutcome::Sqlite(sqlite_failure(
                    rusqlite::ffi::SQLITE_BUSY,
                ))),
                2 => Err(BoundaryOutcome::Sqlite(sqlite_failure(
                    rusqlite::ffi::SQLITE_LOCKED,
                ))),
                _ => Ok(()),
            }
        })
        .expect("transient rollback boundary failures should be retried");
        assert_eq!(calls, 3);

        let mut persistent_calls = 0;
        let result = retry_transaction_boundary("ROLLBACK", || {
            persistent_calls += 1;
            Err(BoundaryOutcome::Sqlite(sqlite_failure(
                rusqlite::ffi::SQLITE_LOCKED,
            )))
        });
        assert!(
            matches!(result, Err(StorageError::Busy(_))),
            "exhausted ROLLBACK lock contention must remain Busy, got {result:?}",
        );
        assert!(
            result
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("sqlite transaction ROLLBACK"),
            "busy classification should retain transaction-boundary context",
        );
        assert_eq!(persistent_calls, BUSY_MAX_ATTEMPTS);
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
    #[cfg(unix)]
    fn account_db_and_sidecars_are_owner_only_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("on-disk mode key").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        // Force a WAL write so the -wal/-shm sidecars exist.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TABLE mode_probe (id INTEGER); INSERT INTO mode_probe VALUES (1);",
            )
            .unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        for suffix in ["-wal", "-shm"] {
            let sidecar = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            assert!(sidecar.exists(), "expected {suffix} sidecar to exist");
            assert_eq!(mode(&sidecar), 0o600, "sidecar {suffix} should be 0600");
        }
    }

    /// The load-bearing assertion for the iOS `0xdead10cc` fix: after `close`,
    /// the WAL sidecars are gone and a *fresh* connection can take an exclusive
    /// lock on the database. SQLite only unlinks `-wal`/`-shm` when the last
    /// connection to a database closes, and `locking_mode = EXCLUSIVE` only
    /// takes hold if nothing else holds a lock — together these are the same
    /// property iOS checks when it decides whether to kill a suspended process.
    #[test]
    fn close_releases_wal_locks_and_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("close releases locks key").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TABLE close_probe (id INTEGER); INSERT INTO close_probe VALUES (1);",
            )
            .unwrap();

        let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
        let shm = std::path::PathBuf::from(format!("{}-shm", path.display()));
        assert!(
            wal.exists() && shm.exists(),
            "WAL sidecars should exist while open"
        );

        // A clone the host cannot reach — exactly the situation that makes
        // dropping handles useless — must not keep the database locked.
        let surviving_clone = store.clone();
        store.close().expect("close should succeed");

        assert!(
            !wal.exists(),
            "-wal must be gone once the last connection closes"
        );
        assert!(
            !shm.exists(),
            "-shm must be gone once the last connection closes"
        );

        let reopened = rusqlite::Connection::open(&path).unwrap();
        apply_sqlcipher_key(&reopened, &key).unwrap();
        reopened
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .unwrap();
        reopened
            .execute_batch("INSERT INTO close_probe VALUES (2);")
            .expect("an exclusive writer must be able to take the database");
        let rows: i64 = reopened
            .query_row("SELECT count(*) FROM close_probe", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            rows, 2,
            "the pre-close write must have been durably committed"
        );

        // The surviving clone is inert, not dangerous.
        assert!(surviving_clone.is_closed());
        assert!(matches!(
            surviving_clone.lock().err(),
            Some(StorageError::Closed(_))
        ));
    }

    #[test]
    fn close_is_idempotent_and_leaves_every_handle_reporting_closed() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        assert!(!store.is_closed());

        store.close().expect("first close should succeed");
        store.close().expect("second close should be a no-op");
        assert!(store.is_closed());

        assert!(matches!(store.lock().err(), Some(StorageError::Closed(_))));
        // The OpenMLS adapter shares the same connection and must report the
        // same terminal state rather than panicking on a missing connection.
        assert!(matches!(
            store.openmls.stored_key_package_bundles().err(),
            Some(StorageError::Closed(_))
        ));
        // And a real storage operation, not just the raw lock.
        assert!(matches!(
            cgka_traits::storage::GroupStorage::list_groups(&store).err(),
            Some(StorageError::Closed(_))
        ));
    }

    /// Once closing starts, later callers must fail without queueing for the
    /// connection mutex. Otherwise a stream of racing operations can repeatedly
    /// get ahead of the closer and defeat the host's suspension deadline.
    #[test]
    fn close_rejects_new_admissions_while_waiting_for_the_active_operation() {
        let connection = Arc::new(CloseableConnection::new(
            rusqlite::Connection::open_in_memory().unwrap(),
            "admission test connection is closed",
        ));
        let active_operation = connection.lock().unwrap();

        let closing_connection = Arc::clone(&connection);
        let (closed_tx, closed_rx) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            let result = closing_connection.close();
            closed_tx.send(()).unwrap();
            result
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !connection.is_closed() && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(
            connection.is_closed(),
            "the closer must publish terminal admission before waiting for slot",
        );

        let waiting_connection = Arc::clone(&connection);
        let (admission_tx, admission_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            admission_tx
                .send(waiting_connection.lock().map(|_| ()))
                .unwrap();
        });
        assert!(matches!(
            admission_rx
                .recv_timeout(Duration::from_millis(250))
                .expect("new admission must be rejected without waiting for slot"),
            Err(StorageError::Closed(_)),
        ));
        assert!(
            closed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "close must still wait for the operation that was active before it began",
        );

        drop(active_operation);
        closer.join().unwrap().unwrap();
        waiter.join().unwrap();
    }

    /// A transaction that is open when the store closes must report the close,
    /// not latch the connection "unusable" with a rollback-failed message. The
    /// rollback it wanted did happen — SQLite performs it as part of closing.
    #[test]
    fn transaction_open_at_close_reports_closed_without_latching_unusable() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let closed_during_callback = store.connection.clone();

        let result: Result<(), StorageError> = store.connection.with_transaction(|| {
            closed_during_callback.close().unwrap();
            Ok(())
        });

        assert!(
            matches!(result, Err(StorageError::Closed(_))),
            "COMMIT against a closed connection must report Closed, got {result:?}",
        );
        assert!(
            store.connection.transaction_unusable_error().is_none(),
            "closing must not latch the transaction-unusable flag",
        );

        // An error path through the same window rolls back and still reports
        // the close rather than a doubled rollback failure.
        let store = SqliteAccountStorage::in_memory().unwrap();
        let closed_during_callback = store.connection.clone();
        let result: Result<(), StorageError> = store.connection.with_transaction(|| {
            closed_during_callback.close().unwrap();
            Err(StorageError::Backend("callback failed".into()))
        });
        assert!(
            matches!(result, Err(StorageError::Backend(detail)) if detail == "callback failed"),
            "the callback's own error must survive the closed rollback",
        );
        assert!(store.connection.transaction_unusable_error().is_none());
    }

    /// Closing while another thread is parked waiting for the transaction slot
    /// must wake it with an error rather than leave it blocked forever.
    #[test]
    fn close_wakes_threads_waiting_for_the_transaction_slot() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let shared = store.connection.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let holder_connection = shared.clone();
        let holder = std::thread::spawn(move || {
            holder_connection.with_transaction(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, StorageError>(())
            })
        });
        entered_rx.recv().unwrap();

        let waiter_connection = shared.clone();
        let waiter = std::thread::spawn(move || waiter_connection.lock().map(|_| ()));

        // Give the waiter time to park on the condvar, then close under it.
        std::thread::sleep(Duration::from_millis(100));
        shared.close().unwrap();
        release_tx.send(()).unwrap();

        assert!(
            matches!(waiter.join().unwrap(), Err(StorageError::Closed(_))),
            "a parked waiter must be woken with Closed",
        );
        let _ = holder.join().unwrap();
    }

    /// Closing under a live writer is the case that matters most: a host
    /// suspending in a hurry will not always have quiesced cleanly. The close
    /// must be prompt, and every transaction must be all-or-nothing across the
    /// cut — a half-applied multi-table write would be worse than the crash
    /// this whole change exists to avoid.
    #[test]
    fn close_under_a_live_writer_is_prompt_and_leaves_no_torn_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("torn write probe key").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TABLE torn_left (id INTEGER); CREATE TABLE torn_right (id INTEGER);",
            )
            .unwrap();

        let writer_store = store.clone();
        let writer = std::thread::spawn(move || {
            for id in 0..10_000i64 {
                // Both inserts land, or neither does. Nothing else is allowed.
                let result: Result<(), StorageError> =
                    writer_store.connection.with_transaction(|| {
                        let conn = writer_store.lock()?;
                        conn.execute("INSERT INTO torn_left VALUES (?1)", [id])
                            .storage()?;
                        conn.execute("INSERT INTO torn_right VALUES (?1)", [id])
                            .storage()?;
                        Ok(())
                    });
                if let Err(error) = result {
                    // The only acceptable way to stop is the close itself.
                    assert!(
                        error.is_closed(),
                        "writer should only ever fail with Closed, got {error:?}",
                    );
                    return;
                }
            }
        });

        // Let the writer get going, then close out from under it.
        std::thread::sleep(Duration::from_millis(50));
        let started_at = std::time::Instant::now();
        store.close().unwrap();
        let close_elapsed = started_at.elapsed();
        writer.join().unwrap();

        assert!(
            close_elapsed < Duration::from_secs(1),
            "close should wait only for the executing statement, took {close_elapsed:?}",
        );

        let reopened = rusqlite::Connection::open(&path).unwrap();
        apply_sqlcipher_key(&reopened, &key).unwrap();
        let left: i64 = reopened
            .query_row("SELECT count(*) FROM torn_left", [], |row| row.get(0))
            .unwrap();
        let right: i64 = reopened
            .query_row("SELECT count(*) FROM torn_right", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            left, right,
            "a transaction interrupted by close must be rolled back whole",
        );
        assert!(left > 0, "the writer should have committed something first");
    }

    #[test]
    #[cfg(unix)]
    fn pre_existing_db_and_sidecar_modes_are_tightened_on_open() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("tighten mode key").unwrap();
        drop(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
        let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
        // Simulate files left behind by builds that created them at the umask.
        for p in [&path, &wal] {
            if !p.exists() {
                std::fs::write(p, b"").unwrap();
            }
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        // Assert while the store is open: the -wal sidecar is checkpointed
        // away on clean close.
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&wal), 0o600);
        drop(store);
    }

    #[test]
    fn encrypted_connection_pins_cipher_pragmas_before_keying() {
        let _guard = TRACE_TEST_LOCK.lock().unwrap();
        TRACED_SQLCIPHER_SETUP.lock().unwrap().clear();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("trace setup key").unwrap();
        let connection = rusqlite::Connection::open(path).unwrap();
        connection.trace_v2(
            TraceEventCodes::SQLITE_TRACE_STMT,
            Some(trace_sqlcipher_setup_event),
        );

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
        let connection = rusqlite::Connection::open(path).unwrap();
        connection.trace_v2(
            TraceEventCodes::SQLITE_TRACE_STMT,
            Some(trace_sqlcipher_setup_event),
        );

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
