//! The engine's `StorageProvider` and `KeyPackageBundleStorage` impls for the account database.

use crate::base::connection::CachedSql;
use crate::protocol::openmls_storage::SqliteOpenMlsStorage;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{
    KeyPackageBundleStorage, StorageError, StorageProvider, StorageResult, StoredKeyPackageBundle,
};
use cgka_traits::types::Backend;

impl StorageProvider for SqliteAccountStorage {
    type Mls = SqliteOpenMlsStorage;

    fn mls_storage(&self) -> &Self::Mls {
        &self.openmls
    }

    fn pending_ref_high_water(&self) -> StorageResult<u64> {
        let connection = self.lock()?;
        read_pending_high_water(&connection)
    }

    fn mls_write_generation(&self) -> Option<u64> {
        if self.connection.is_closed() {
            return None;
        }
        // `PRAGMA data_version` changes whenever another connection or process
        // commits to this database, which the in-process write counter cannot
        // see. Pack both so either kind of write invalidates a cached group.
        // Each half wraps at 2^32; a wrap between two reads of the same cache
        // entry is not a realistic event.
        let data_version: i64 = self
            .connection
            .lock()
            .ok()?
            .query_row_cached("PRAGMA data_version", [], |row| row.get(0))
            .ok()?;
        let own = self.connection.openmls_write_generation() & 0xffff_ffff;
        Some(((data_version as u64) << 32) | own)
    }

    fn with_read_snapshot<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection
            .with_transaction_mode(true, || self.connection.with_query_only(|| f(self)))
    }

    fn maintenance_storage(&self) -> Option<&dyn cgka_traits::storage::MaintenanceStorage> {
        Some(self)
    }

    fn private_key_package_storage(
        &self,
    ) -> Option<&dyn cgka_traits::storage::PrivateKeyPackageStorage> {
        Some(self)
    }

    fn roster_tag_key_storage(&self) -> Option<&dyn cgka_traits::storage::RosterTagKeyStorage> {
        Some(self)
    }

    fn sibling_add_storage(&self) -> Option<&dyn cgka_traits::storage::SiblingAddStorage> {
        Some(self)
    }

    fn group_replay_state_fingerprint(
        &self,
        group_id: &cgka_traits::types::GroupId,
    ) -> StorageResult<Option<[u8; 32]>> {
        crate::protocol::storage::snapshots::replay_fingerprint(self, group_id).map(Some)
    }

    fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection.with_transaction(|| f(self))
    }

    fn after_commit(&self, callback: Box<dyn FnOnce() + Send + 'static>) {
        self.connection.after_commit(callback);
    }

    fn with_group_savepoint<T, E, F>(
        &self,
        _group_id: &cgka_traits::types::GroupId,
        _fallback_snapshot: &str,
        f: F,
    ) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection.with_savepoint(|| f(self))
    }

    fn rollback_group_state_keeping_live_records(
        &self,
        group_id: &cgka_traits::types::GroupId,
        name: &str,
    ) -> StorageResult<()> {
        // Restores canonical state only, even from a full snapshot.
        cgka_traits::storage::MessageStorage::rollback_group_state_to_snapshot(self, group_id, name)
    }

    fn list_snapshots_with_prefixes(
        &self,
        prefixes: &[&str],
    ) -> StorageResult<Vec<(cgka_traits::types::GroupId, String)>> {
        crate::protocol::storage::snapshots::list_with_prefixes(self, prefixes)
    }

    fn backend(&self) -> Backend {
        Backend::Sqlite
    }
}

fn read_pending_high_water(connection: &rusqlite::Connection) -> StorageResult<u64> {
    use rusqlite::{OptionalExtension, types::ValueRef};

    let value = connection
        .query_row_cached(
            "SELECT high_water FROM cgka_pending_ref_watermark WHERE singleton = 1",
            [],
            |row| {
                Ok(match row.get_ref(0)? {
                    ValueRef::Blob(bytes) => bytes.try_into().ok().map(u64::from_be_bytes),
                    _ => None,
                })
            },
        )
        .optional()
        .storage()?;
    value.flatten().ok_or_else(|| {
        StorageError::Backend("pending reference high-water metadata is missing or corrupt".into())
    })
}

/// The caller owns a transaction/savepoint containing the artifact write.
pub(super) fn raise_pending_ref(
    connection: &rusqlite::Connection,
    pending: u64,
) -> StorageResult<()> {
    if pending > read_pending_high_water(connection)? {
        connection
            .execute_cached(
                "UPDATE cgka_pending_ref_watermark SET high_water = ?1 WHERE singleton = 1",
                rusqlite::params![pending.to_be_bytes().as_slice()],
            )
            .storage()?;
    }
    Ok(())
}

impl KeyPackageBundleStorage for SqliteAccountStorage {
    fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>> {
        self.openmls.stored_key_package_bundles()
    }

    fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()> {
        self.openmls.delete_stored_key_package_bundle(storage_key)
    }
}
