//! The private KeyPackages this device's siblings handed it, and what it still
//! needs from each (mdk#2628 item 3.4b). See migration 0140.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageResult, private_key_package_halfway};
use rusqlite::{OptionalExtension, params};

/// A single-use KeyPackage a sibling handed this device, for adding that
/// sibling to a chat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedPrivateKeyPackage {
    pub key_package_ref_hex: String,
    /// The issuing sibling's KeyPackage slot, 64 lowercase hex characters.
    pub issuer_slot_hex: String,
    pub not_before: u64,
    pub not_after: u64,
    /// The KeyPackage as an `mls_key_package` MLSMessage.
    pub key_package: Vec<u8>,
    pub received_at: u64,
}

impl ReceivedPrivateKeyPackage {
    /// Whether it still counts as usable stock at `now`: before halfway.
    pub fn usable_at(&self, now: u64) -> bool {
        now < private_key_package_halfway(self.not_before, self.not_after)
    }
}

/// How many usable KeyPackages this device needs from one sibling, and when
/// it last asked for them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyPackageNeed {
    pub issuer_slot_hex: String,
    /// 1 to 100.
    pub need: u32,
    /// `None` until a request is sent for this need.
    pub requested_at: Option<u64>,
}

impl SqliteAppStorage {
    /// Keep handed-over KeyPackages, skipping any already held and any this
    /// device has used (mdk#2628 D42). Returns how many were new.
    pub fn insert_received_private_key_packages(
        &self,
        records: &[ReceivedPrivateKeyPackage],
    ) -> StorageResult<usize> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let mut inserted = 0;
        for record in records {
            inserted += tx
                .execute_cached(
                    "INSERT OR IGNORE INTO private_key_packages_received
                         (key_package_ref_hex, issuer_slot_hex, not_before, not_after,
                          key_package, received_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        record.key_package_ref_hex,
                        record.issuer_slot_hex,
                        u64_to_i64(record.not_before)?,
                        u64_to_i64(record.not_after)?,
                        record.key_package,
                        u64_to_i64(record.received_at)?
                    ],
                )
                .storage()?;
        }
        tx.commit().storage()?;
        Ok(inserted)
    }

    /// Every handed-over KeyPackage this device has not used, by issuer, then
    /// expiry.
    pub fn received_private_key_packages(&self) -> StorageResult<Vec<ReceivedPrivateKeyPackage>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(&format!(
                "SELECT {RECEIVED_COLUMNS} FROM private_key_packages_received
                 WHERE taken_at IS NULL
                 ORDER BY issuer_slot_hex, not_after, key_package_ref_hex"
            ))
            .storage()?;
        let rows = stmt
            .query_map([], received_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(received_record).collect()
    }

    /// Unused, unexpired received stock from one issuer, in expiry/ref order.
    /// Capability and admission checks belong to the caller, after this read
    /// has released the SQLite lock.
    pub fn received_private_key_packages_from(
        &self,
        issuer_slot_hex: &str,
        now: u64,
    ) -> StorageResult<Vec<ReceivedPrivateKeyPackage>> {
        let conn = self.lock()?;
        received_from(&conn, issuer_slot_hex, now)
    }

    /// Claim exactly the received record the caller validated, if it is still
    /// held, unchanged and unexpired at `now`. Never substitute another row
    /// when ranking changes or the selected record is no longer eligible.
    /// The single atomic update erases its bytes and keeps the used ref until
    /// the record expires, so a repeated hand-off cannot make it usable again.
    pub fn take_received_private_key_package_exact(
        &self,
        candidate: &ReceivedPrivateKeyPackage,
        now: u64,
    ) -> StorageResult<bool> {
        let taken = self
            .lock()?
            .execute_cached(
                "UPDATE private_key_packages_received SET taken_at = ?7, key_package = X''
             WHERE key_package_ref_hex = ?1 AND issuer_slot_hex = ?2
               AND not_before = ?3 AND not_after = ?4 AND key_package = ?5
               AND received_at = ?6 AND taken_at IS NULL AND not_after > ?7",
                params![
                    candidate.key_package_ref_hex,
                    candidate.issuer_slot_hex,
                    u64_to_i64(candidate.not_before)?,
                    u64_to_i64(candidate.not_after)?,
                    candidate.key_package,
                    u64_to_i64(candidate.received_at)?,
                    u64_to_i64(now)?,
                ],
            )
            .storage()?;
        Ok(taken == 1)
    }

    /// Discard every handed-over KeyPackage that expired by `now`. Returns
    /// how many went.
    pub fn delete_expired_received_private_key_packages(&self, now: u64) -> StorageResult<usize> {
        self.lock()?
            .execute_cached(
                "DELETE FROM private_key_packages_received WHERE not_after <= ?1",
                params![u64_to_i64(now)?],
            )
            .storage()
    }

    /// Discard everything `issuer_slot_hex` handed over, and this device's
    /// need from it. Returns how many KeyPackages went.
    pub fn delete_received_private_key_packages_from(
        &self,
        issuer_slot_hex: &str,
    ) -> StorageResult<usize> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let deleted = tx
            .execute_cached(
                "DELETE FROM private_key_packages_received WHERE issuer_slot_hex = ?1",
                params![issuer_slot_hex],
            )
            .storage()?;
        tx.execute_cached(
            "DELETE FROM private_key_package_requests WHERE issuer_slot_hex = ?1",
            params![issuer_slot_hex],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(deleted)
    }

    pub fn private_key_package_need(
        &self,
        issuer_slot_hex: &str,
    ) -> StorageResult<Option<PrivateKeyPackageNeed>> {
        self.lock()?
            .query_row_cached(
                "SELECT issuer_slot_hex, need, requested_at FROM private_key_package_requests
                 WHERE issuer_slot_hex = ?1",
                params![issuer_slot_hex],
                need_row,
            )
            .optional()
            .storage()?
            .map(need_record)
            .transpose()
    }

    pub fn put_private_key_package_need(&self, need: &PrivateKeyPackageNeed) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO private_key_package_requests
                     (issuer_slot_hex, need, requested_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    need.issuer_slot_hex,
                    need.need,
                    need.requested_at.map(u64_to_i64).transpose()?
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn delete_private_key_package_need(&self, issuer_slot_hex: &str) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM private_key_package_requests WHERE issuer_slot_hex = ?1",
                params![issuer_slot_hex],
            )
            .storage()?;
        Ok(())
    }
}

fn received_from(
    conn: &rusqlite::Connection,
    issuer_slot_hex: &str,
    now: u64,
) -> StorageResult<Vec<ReceivedPrivateKeyPackage>> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "SELECT {RECEIVED_COLUMNS} FROM private_key_packages_received
         WHERE issuer_slot_hex = ?1 AND not_after > ?2 AND taken_at IS NULL
         ORDER BY not_after, key_package_ref_hex"
        ))
        .storage()?;
    stmt.query_map(params![issuer_slot_hex, u64_to_i64(now)?], received_row)
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?
        .into_iter()
        .map(received_record)
        .collect()
}

const RECEIVED_COLUMNS: &str =
    "key_package_ref_hex, issuer_slot_hex, not_before, not_after, key_package, received_at";

type ReceivedRow = (String, String, i64, i64, Vec<u8>, i64);

fn received_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReceivedRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn received_record(
    (key_package_ref_hex, issuer_slot_hex, not_before, not_after, key_package, received_at): ReceivedRow,
) -> StorageResult<ReceivedPrivateKeyPackage> {
    Ok(ReceivedPrivateKeyPackage {
        key_package_ref_hex,
        issuer_slot_hex,
        not_before: i64_to_u64(not_before)?,
        not_after: i64_to_u64(not_after)?,
        key_package,
        received_at: i64_to_u64(received_at)?,
    })
}

type NeedRow = (String, u32, Option<i64>);

fn need_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NeedRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}

fn need_record(
    (issuer_slot_hex, need, requested_at): NeedRow,
) -> StorageResult<PrivateKeyPackageNeed> {
    Ok(PrivateKeyPackageNeed {
        issuer_slot_hex,
        need,
        requested_at: requested_at.map(i64_to_u64).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqlCipherKey, SqliteAccountStorage};

    fn received(reference: &str, issuer: &str, not_before: u64) -> ReceivedPrivateKeyPackage {
        ReceivedPrivateKeyPackage {
            key_package_ref_hex: reference.into(),
            issuer_slot_hex: issuer.into(),
            not_before,
            not_after: not_before + 100,
            key_package: vec![1, 2, 3],
            received_at: not_before,
        }
    }

    #[test]
    fn handed_over_key_packages_survive_reopen_and_are_kept_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::raw([7; 32]);
        let batch = [received("a1", "aa", 0), received("a2", "aa", 10)];
        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key)
                .unwrap()
                .app_storage();
            assert_eq!(
                store.insert_received_private_key_packages(&batch).unwrap(),
                2
            );
            assert_eq!(
                store.insert_received_private_key_packages(&batch).unwrap(),
                0
            );
            store
                .put_private_key_package_need(&PrivateKeyPackageNeed {
                    issuer_slot_hex: "aa".into(),
                    need: 40,
                    requested_at: Some(7),
                })
                .unwrap();
        }
        let store = SqliteAccountStorage::open_encrypted(&path, &key)
            .unwrap()
            .app_storage();
        assert_eq!(store.received_private_key_packages().unwrap(), batch);
        assert_eq!(
            store.private_key_package_need("aa").unwrap(),
            Some(PrivateKeyPackageNeed {
                issuer_slot_hex: "aa".into(),
                need: 40,
                requested_at: Some(7),
            })
        );
    }

    /// Selection may cross halfway while its candidate is checked. Claiming
    /// that candidate must not spend the newly preferred allocation instead.
    #[test]
    fn exact_claim_does_not_rerank_across_halfway() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let a = received("a", "aa", 0);
        let b = received("b", "aa", 10);
        store
            .insert_received_private_key_packages(&[a.clone(), b.clone()])
            .unwrap();
        let candidate = store
            .received_private_key_packages_from("aa", 49)
            .unwrap()
            .remove(0);
        assert_eq!(candidate, a);
        assert!(
            store
                .take_received_private_key_package_exact(&candidate, 50)
                .unwrap()
        );
        assert!(
            !store
                .take_received_private_key_package_exact(&candidate, 50)
                .unwrap()
        );
        assert_eq!(store.received_private_key_packages().unwrap(), vec![b]);
    }

    /// An exact claim is fenced on the complete received record, expiry and
    /// unused state. A failed or repeated claim never consumes other stock.
    #[test]
    fn exact_claim_refuses_stale_records_without_spending_other_stock() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let a = received("a", "aa", 0);
        let b = received("b", "aa", 10);
        let held = vec![a.clone(), b.clone()];
        store.insert_received_private_key_packages(&held).unwrap();
        let mut mismatches = vec![a.clone(); 6];
        mismatches[0].key_package_ref_hex = "b".into();
        mismatches[1].issuer_slot_hex = "bb".into();
        mismatches[2].not_before = 1;
        mismatches[3].not_after = 101;
        mismatches[4].key_package.push(4);
        mismatches[5].received_at = 1;
        for candidate in mismatches {
            assert!(
                !store
                    .take_received_private_key_package_exact(&candidate, 20)
                    .unwrap()
            );
            assert_eq!(store.received_private_key_packages().unwrap(), held);
        }
        assert!(
            !store
                .take_received_private_key_package_exact(&a, 100)
                .unwrap()
        );
        assert_eq!(store.received_private_key_packages().unwrap(), held);
        // A failed write is atomic too: the candidate and every other row
        // remain available, rather than falling back after the failure.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_exact_take AFTER UPDATE ON private_key_packages_received
             BEGIN SELECT RAISE(ABORT, 'exact claim refused'); END;",
            )
            .unwrap();
        let error = store
            .take_received_private_key_package_exact(&b, 100)
            .unwrap_err();
        assert!(
            matches!(error, cgka_traits::storage::StorageError::Backend(ref message)
            if message.contains("exact claim refused")),
            "{error}"
        );
        assert_eq!(store.received_private_key_packages().unwrap(), held);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER refuse_exact_take")
            .unwrap();
        assert!(
            store
                .take_received_private_key_package_exact(&b, 100)
                .unwrap()
        );
        assert!(
            !store
                .take_received_private_key_package_exact(&b, 100)
                .unwrap()
        );
        assert_eq!(store.received_private_key_packages().unwrap(), vec![a]);
        assert_eq!(store.insert_received_private_key_packages(&[b]).unwrap(), 0);
        let remaining_bytes: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT length(key_package) FROM private_key_packages_received
             WHERE key_package_ref_hex = 'b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_bytes, 0);
    }

    /// An issuer-local batch excludes expired/used rows and never decodes
    /// another issuer's record, even if that unrelated row is corrupt.
    #[test]
    fn issuer_batch_reads_only_its_own_unexpired_unused_records() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let used = received("used", "aa", 0);
        let expired = received("expired", "aa", 0);
        let held = received("held", "aa", 10);
        store
            .insert_received_private_key_packages(&[
                used.clone(),
                expired,
                held.clone(),
                received("other", "bb", 0),
            ])
            .unwrap();
        assert!(
            store
                .take_received_private_key_package_exact(&used, 1)
                .unwrap()
        );
        // SQLite's scalar affinity permits this corrupt record; a whole-table
        // decode would fail before an app could filter by issuer in Rust.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE private_key_packages_received SET not_before = 'unreadable',
             not_after = 'unreadable' WHERE issuer_slot_hex = 'bb'",
            )
            .unwrap();
        assert_eq!(
            store.received_private_key_packages_from("aa", 100).unwrap(),
            vec![held]
        );
        assert!(
            store
                .received_private_key_packages_from("missing", 100)
                .unwrap()
                .is_empty()
        );
    }

    /// A KeyPackage this device used is not kept again when it is handed over
    /// again, and its ref goes when it expires (mdk#2628 D42).
    #[test]
    fn a_used_key_package_is_not_kept_again() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let batch = [received("a1", "aa", 0)];
        store.insert_received_private_key_packages(&batch).unwrap();
        assert!(
            store
                .take_received_private_key_package_exact(&batch[0], 10)
                .unwrap()
        );
        // The taken private bytes are gone, not only hidden.
        let kept: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT length(key_package) FROM private_key_packages_received
                 WHERE key_package_ref_hex = 'a1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(kept, 0);
        assert_eq!(
            store.insert_received_private_key_packages(&batch).unwrap(),
            0
        );
        assert!(store.received_private_key_packages().unwrap().is_empty());
        assert!(
            !store
                .take_received_private_key_package_exact(&batch[0], 10)
                .unwrap()
        );
        assert_eq!(
            store
                .delete_expired_received_private_key_packages(100)
                .unwrap(),
            1
        );
        assert_eq!(
            store.insert_received_private_key_packages(&batch).unwrap(),
            1
        );
    }

    #[test]
    fn discarding_a_sibling_drops_its_key_packages_and_need() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .insert_received_private_key_packages(&[
                received("a1", "aa", 0),
                received("b1", "bb", 0),
            ])
            .unwrap();
        store
            .put_private_key_package_need(&PrivateKeyPackageNeed {
                issuer_slot_hex: "aa".into(),
                need: 1,
                requested_at: None,
            })
            .unwrap();
        assert_eq!(
            store
                .delete_received_private_key_packages_from("aa")
                .unwrap(),
            1
        );
        assert_eq!(store.private_key_package_need("aa").unwrap(), None);
        let left = store.received_private_key_packages().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].issuer_slot_hex, "bb");
    }
}
