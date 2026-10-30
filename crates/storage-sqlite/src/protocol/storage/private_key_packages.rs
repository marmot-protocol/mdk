//! The private KeyPackages this device issued to its siblings (mdk#2628 item
//! 3.4b). See migration 0140. The engine keeps each row in step with its
//! OpenMLS private bundle.

use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize, u64_to_i64};
use cgka_traits::storage::{IssuedPrivateKeyPackage, PrivateKeyPackageStorage, StorageResult};
use rusqlite::{OptionalExtension, params};

impl PrivateKeyPackageStorage for SqliteAccountStorage {
    fn put_issued_private_key_package(
        &self,
        record: &IssuedPrivateKeyPackage,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO cgka_private_key_packages
                     (key_package_ref, issued_at, record)
                 VALUES (?1, ?2, ?3)",
                params![
                    record.key_package_ref,
                    u64_to_i64(record.issued_at)?,
                    serialize(record)?
                ],
            )
            .storage()?;
        Ok(())
    }

    fn issued_private_key_package(
        &self,
        key_package_ref: &[u8],
    ) -> StorageResult<Option<IssuedPrivateKeyPackage>> {
        let record: Option<Vec<u8>> = self
            .lock()?
            .query_row_cached(
                "SELECT record FROM cgka_private_key_packages WHERE key_package_ref = ?1",
                params![key_package_ref],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        record.as_deref().map(deserialize).transpose()
    }

    fn list_issued_private_key_packages(&self) -> StorageResult<Vec<IssuedPrivateKeyPackage>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT record FROM cgka_private_key_packages
                 ORDER BY issued_at, key_package_ref",
            )
            .storage()?;
        let records = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records.iter().map(|record| deserialize(record)).collect()
    }

    fn delete_issued_private_key_package(&self, key_package_ref: &[u8]) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM cgka_private_key_packages WHERE key_package_ref = ?1",
                params![key_package_ref],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlCipherKey;

    fn issued(reference: u8, issued_at: u64) -> IssuedPrivateKeyPackage {
        IssuedPrivateKeyPackage {
            key_package_ref: vec![reference; 32],
            recipient_slot: [7; 32],
            not_before: 10,
            not_after: 20,
            key_package: vec![1, 2, 3],
            issued_at,
            hand_off_queued: false,
            counted: true,
            request_id: None,
        }
    }

    #[test]
    fn issued_private_key_packages_survive_reopen_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("local identity key").unwrap();
        let mut answered = issued(2, 5);
        answered.request_id = Some(cgka_traits::MessageId::new(vec![9; 32]));
        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.put_issued_private_key_package(&issued(1, 6)).unwrap();
            store.put_issued_private_key_package(&answered).unwrap();
            let mut queued = issued(1, 6);
            queued.hand_off_queued = true;
            store.put_issued_private_key_package(&queued).unwrap();
        }
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let listed = store.list_issued_private_key_packages().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], answered);
        assert!(listed[1].hand_off_queued);
        assert_eq!(
            store.issued_private_key_package(&[2; 32]).unwrap(),
            Some(answered)
        );
        store.delete_issued_private_key_package(&[2; 32]).unwrap();
        assert_eq!(store.issued_private_key_package(&[2; 32]).unwrap(), None);
        assert_eq!(store.list_issued_private_key_packages().unwrap().len(), 1);
    }
}
