//! `SqliteAccountStorage`: the engine's handle on the account database.

#[cfg(feature = "test-migrated-template")]
use crate::base::connection::open_account_in_memory_from_migrated_template;
use crate::base::connection::{
    ConnectionGuard, DatabaseCloser, OpenedAccount, SharedConnection, SqlCipherKey,
    SqliteStorageOptions, SqliteTimingObserver, open_account_encrypted, open_account_in_memory,
};
#[cfg(test)]
use crate::base::connection::{finish_account_open, open_account_unkeyed};
use crate::protocol::openmls_storage::SqliteOpenMlsStorage;
use cgka_traits::storage::StorageResult;
use std::path::Path;
use std::time::Duration;

/// The engine's handle on an account database: the protocol traits, open and
/// close. The app side's handle over the same connection comes from
/// [`SqliteAccountStorage::app_storage`].
#[derive(Clone)]
pub struct SqliteAccountStorage {
    pub(crate) draft_commit_observer: crate::cross::outbound::DraftObserverSlot,
    migrations_applied: usize,
    migration_duration: Duration,
    pub(crate) connection: SharedConnection,
    pub(crate) openmls: SqliteOpenMlsStorage,
}

#[deprecated(
    note = "renamed to SqliteAccountStorage; SqliteStorage will be removed once downstream crates have migrated"
)]
pub type SqliteStorage = SqliteAccountStorage;

impl SqliteAccountStorage {
    fn from_opened(opened: OpenedAccount) -> Self {
        let openmls = SqliteOpenMlsStorage::new(opened.connection.clone());
        Self {
            connection: opened.connection,
            openmls,
            draft_commit_observer: Default::default(),
            migrations_applied: opened.migrations_applied,
            migration_duration: opened.migration_duration,
        }
    }

    /// Neutral open-time result. Existing ledger entries are not new migrations.
    pub fn migration_summary(&self) -> (usize, Duration) {
        (self.migrations_applied, self.migration_duration)
    }

    /// Export one group's convergence/OpenMLS state, including any durable
    /// convergence pass, for a sensitive test-only replay capsule.
    #[cfg(feature = "test-conformance-replay")]
    pub fn export_conformance_replay_snapshot(
        &self,
        group_id: &cgka_traits::types::GroupId,
    ) -> StorageResult<Vec<u8>> {
        crate::protocol::storage::snapshots::export_replay(self, group_id)
    }

    /// Restore a sensitive test-only conformance replay snapshot into this
    /// account-device database.
    #[cfg(feature = "test-conformance-replay")]
    pub fn import_conformance_replay_snapshot(
        &self,
        group_id: &cgka_traits::types::GroupId,
        snapshot: &[u8],
    ) -> StorageResult<()> {
        crate::protocol::storage::snapshots::import_replay(self, group_id, snapshot)
    }

    pub fn in_memory() -> StorageResult<Self> {
        Self::in_memory_with_options(SqliteStorageOptions::default())
    }

    pub fn in_memory_with_options(options: SqliteStorageOptions) -> StorageResult<Self> {
        open_account_in_memory(options).map(Self::from_opened)
    }

    /// Test-only in-memory storage copied from one migrated template per
    /// process. Harnesses that open thousands of short-lived databases would
    /// otherwise replay every migration for each. Opening the copy still runs
    /// the migration ledger check, which finds nothing to apply.
    #[cfg(feature = "test-migrated-template")]
    pub fn in_memory_from_migrated_template(options: SqliteStorageOptions) -> StorageResult<Self> {
        open_account_in_memory_from_migrated_template(options).map(Self::from_opened)
    }

    /// Open a private encrypted account store with the standard privacy and durability defaults.
    pub fn open_encrypted(path: impl AsRef<Path>, key: &SqlCipherKey) -> StorageResult<Self> {
        Self::open_encrypted_with_options(path, key, SqliteStorageOptions::default())
    }

    /// Apply the caller's cipher/operational options and pending migrations before publishing the store.
    pub fn open_encrypted_with_options(
        path: impl AsRef<Path>,
        key: &SqlCipherKey,
        options: SqliteStorageOptions,
    ) -> StorageResult<Self> {
        open_account_encrypted(path.as_ref(), key, options, None).map(Self::from_opened)
    }

    /// Observe fixed phases and migration numbers without exposing database paths, SQL or keys.
    /// Callback faults are isolated; ordinary callers keep the same defaults and no callback.
    pub fn open_encrypted_observed(
        path: impl AsRef<Path>,
        key: &SqlCipherKey,
        observer: &dyn Fn(crate::StorageOpenProgress),
    ) -> StorageResult<Self> {
        open_account_encrypted(
            path.as_ref(),
            key,
            SqliteStorageOptions::default(),
            Some(observer),
        )
        .map(Self::from_opened)
    }

    /// Exercise raw unkeyed connections with production keying defaults and no diagnostic callback.
    #[cfg(test)]
    pub(crate) fn from_unkeyed_encrypted_connection_with_options(
        connection: rusqlite::Connection,
        key: &SqlCipherKey,
        options: SqliteStorageOptions,
    ) -> StorageResult<Self> {
        open_account_unkeyed(connection, key, options, None).map(Self::from_opened)
    }

    /// Finish an existing connection without recording progress; options and migrations remain identical.
    #[cfg(test)]
    pub(crate) fn from_connection_with_options(
        connection: rusqlite::Connection,
        options: SqliteStorageOptions,
    ) -> StorageResult<Self> {
        finish_account_open(connection, options, None).map(Self::from_opened)
    }

    /// Set an aggregate-only observer shared by all clones. No identities or SQL
    /// are passed. Install once per runtime; `None` disables observation.
    pub fn set_timing_observer(&self, observer: Option<SqliteTimingObserver>) {
        self.connection.set_timing_observer(observer);
    }

    pub(crate) fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        self.connection.lock()
    }

    /// Whether `other` is a clone of this same opened database handle, not
    /// merely another connection to the same file.
    pub fn shares_connection_with(&self, other: &SqliteAccountStorage) -> bool {
        self.connection.same_as(&other.connection)
    }

    /// Checkpoint the WAL and close this account database, releasing every
    /// file lock it holds on the main database and its `-wal`/`-shm` sidecars.
    ///
    /// **Closing is terminal.** Every clone of this handle — including the
    /// OpenMLS adapter reached through
    /// [`StorageProvider::mls_storage`][cgka_traits::storage::StorageProvider::mls_storage]
    /// and any clone held elsewhere in the process — fails with
    /// [`StorageError::Closed`][cgka_traits::storage::StorageError::Closed] from here on. Nothing reopens implicitly; to
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

    /// A [`DatabaseCloser`] for this connection, shared by every clone.
    #[must_use]
    pub fn closer(&self) -> DatabaseCloser {
        self.connection.closer()
    }
}
