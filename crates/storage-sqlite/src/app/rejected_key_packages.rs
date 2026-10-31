//! KeyPackages this device rejected itself (mdk#2628 item 3.7b). See
//! migration 0165 for the columns.
//!
//! The app decides what to reject, when a rejection lapses, and whether the
//! device group's roster still lacks it; this module keeps each one until
//! it lapses.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::params;

/// A KeyPackage this device rejected, as the roster records one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptKeyPackageRejection {
    /// Lowercase hex `KeyPackageRef`.
    pub key_package_ref_hex: String,
    /// The slot the KeyPackage appeared in, as lowercase hex.
    pub slot_id_hex: String,
    /// The KeyPackage's LeafNode signature key.
    pub leaf_signature_key: Vec<u8>,
    /// When this device recorded the rejection, by its own clock.
    pub rejected_at: u64,
}

impl SqliteAppStorage {
    /// Keep `rejection`. One this device already keeps stays as it is.
    /// Returns whether it is new.
    pub fn keep_rejected_key_package(
        &self,
        rejection: &KeptKeyPackageRejection,
    ) -> StorageResult<bool> {
        let inserted = self
            .lock()?
            .execute_cached(
                "INSERT INTO account_rejected_key_packages
                     (key_package_ref_hex, slot_id_hex, leaf_signature_key, rejected_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(key_package_ref_hex) DO NOTHING",
                params![
                    rejection.key_package_ref_hex,
                    rejection.slot_id_hex,
                    rejection.leaf_signature_key,
                    u64_to_i64(rejection.rejected_at)?,
                ],
            )
            .storage()?;
        Ok(inserted != 0)
    }

    /// Every rejection this device keeps, the oldest first.
    pub fn kept_rejected_key_packages(&self) -> StorageResult<Vec<KeptKeyPackageRejection>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT key_package_ref_hex, slot_id_hex, leaf_signature_key, rejected_at
                 FROM account_rejected_key_packages
                 ORDER BY rejected_at ASC, key_package_ref_hex ASC",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(
                |(key_package_ref_hex, slot_id_hex, leaf_signature_key, rejected_at)| {
                    Ok(KeptKeyPackageRejection {
                        key_package_ref_hex,
                        slot_id_hex,
                        leaf_signature_key,
                        rejected_at: i64_to_u64(rejected_at)?,
                    })
                },
            )
            .collect()
    }

    /// Stop keeping each rejection in `key_package_refs_hex`: it lapsed.
    /// Returns how many it dropped.
    pub fn forget_rejected_key_packages(
        &self,
        key_package_refs_hex: &[String],
    ) -> StorageResult<usize> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let mut dropped = 0;
        for key_package_ref_hex in key_package_refs_hex {
            dropped += tx
                .execute_cached(
                    "DELETE FROM account_rejected_key_packages WHERE key_package_ref_hex = ?1",
                    params![key_package_ref_hex],
                )
                .storage()?;
        }
        tx.commit().storage()?;
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    fn rejection(byte: u8, rejected_at: u64) -> KeptKeyPackageRejection {
        KeptKeyPackageRejection {
            key_package_ref_hex: hex::encode([byte; 32]),
            slot_id_hex: hex::encode([0x11; 32]),
            leaf_signature_key: vec![byte; 32],
            rejected_at,
        }
    }

    /// A kept rejection stays until it is forgotten. Keeping one again
    /// changes nothing.
    #[test]
    fn a_kept_rejection_stays_until_it_lapses() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(store.keep_rejected_key_package(&rejection(2, 20)).unwrap());
        assert!(store.keep_rejected_key_package(&rejection(1, 10)).unwrap());
        assert!(
            !store
                .keep_rejected_key_package(&KeptKeyPackageRejection {
                    rejected_at: 99,
                    ..rejection(1, 10)
                })
                .unwrap()
        );
        assert_eq!(
            store.kept_rejected_key_packages().unwrap(),
            vec![rejection(1, 10), rejection(2, 20)]
        );
        assert_eq!(
            store
                .forget_rejected_key_packages(&[
                    rejection(1, 10).key_package_ref_hex,
                    hex::encode([9; 32]),
                ])
                .unwrap(),
            1
        );
        assert_eq!(
            store.kept_rejected_key_packages().unwrap(),
            vec![rejection(2, 20)]
        );
    }
}
