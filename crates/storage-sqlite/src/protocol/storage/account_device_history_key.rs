use crate::SqliteAccountStorage;
use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::{
    AccountDeviceHistoryKey, AccountDeviceHistoryKeyStorage, StorageError, StorageResult,
};
use cgka_traits::types::MemberId;
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

impl AccountDeviceHistoryKeyStorage for SqliteAccountStorage {
    fn put_account_device_history_key_if_absent(
        &self,
        key: &AccountDeviceHistoryKey,
    ) -> StorageResult<AccountDeviceHistoryKey> {
        let connection = self.lock()?;
        connection
            .execute_cached(
                "INSERT OR IGNORE INTO cgka_account_device_history_keys
                     (marmot_identity, ciphersuite, public_key, private_key)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    key.marmot_identity.as_slice(),
                    key.ciphersuite,
                    key.public_key,
                    key.private_key.as_slice(),
                ],
            )
            .storage()?;
        read(&connection, &key.marmot_identity)?.ok_or(StorageError::NotFound)
    }

    fn account_device_history_key(
        &self,
        marmot_identity: &MemberId,
    ) -> StorageResult<Option<AccountDeviceHistoryKey>> {
        read(&*self.lock()?, marmot_identity)
    }
}

fn read(
    connection: &Connection,
    marmot_identity: &MemberId,
) -> StorageResult<Option<AccountDeviceHistoryKey>> {
    connection
        .query_row_cached(
            "SELECT ciphersuite, public_key, private_key
             FROM cgka_account_device_history_keys WHERE marmot_identity = ?1",
            params![marmot_identity.as_slice()],
            |row| {
                Ok(AccountDeviceHistoryKey {
                    marmot_identity: marmot_identity.clone(),
                    ciphersuite: row.get(0)?,
                    public_key: row.get(1)?,
                    private_key: Zeroizing::new(row.get(2)?),
                })
            },
        )
        .optional()
        .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    fn history_key(identity: u8, public: u8) -> AccountDeviceHistoryKey {
        AccountDeviceHistoryKey {
            marmot_identity: MemberId::new(vec![identity; 32]),
            ciphersuite: 1,
            public_key: vec![public; 32],
            private_key: Zeroizing::new(vec![public ^ 0xff; 32]),
        }
    }

    #[test]
    fn the_first_history_key_is_kept_over_a_later_one() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let first = history_key(1, 0x11);
        assert_eq!(
            store
                .put_account_device_history_key_if_absent(&first)
                .unwrap(),
            first
        );
        // A second key for the same identity never replaces the first.
        assert_eq!(
            store
                .put_account_device_history_key_if_absent(&history_key(1, 0x22))
                .unwrap(),
            first
        );
        assert_eq!(
            store
                .account_device_history_key(&first.marmot_identity)
                .unwrap(),
            Some(first)
        );
        assert_eq!(
            store
                .account_device_history_key(&MemberId::new(vec![9; 32]))
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_history_key_debug_hides_the_private_half() {
        let rendered = format!("{:?}", history_key(1, 0x11));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&format!("{}", 0x11 ^ 0xff)));
    }
}
