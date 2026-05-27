use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage, StorageResult};
use cgka_traits::types::MemberId;
use rusqlite::{OptionalExtension, params};

impl AccountDeviceSignerStorage for SqliteAccountStorage {
    fn put_account_device_signer(&self, binding: &AccountDeviceSignerBinding) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_account_device_signers (marmot_identity, record)
                 VALUES (?1, ?2)",
                params![binding.marmot_identity.as_slice(), serialize(binding)?],
            )
            .storage()?;
        Ok(())
    }

    fn account_device_signer(
        &self,
        marmot_identity: &MemberId,
    ) -> StorageResult<Option<AccountDeviceSignerBinding>> {
        let record: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT record FROM cgka_account_device_signers WHERE marmot_identity = ?1",
                params![marmot_identity.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        record.as_deref().map(deserialize).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqlCipherKey, SqliteAccountStorage};

    fn member_id(n: u8) -> MemberId {
        MemberId::new(vec![n; 4])
    }

    #[test]
    fn account_device_signer_binding_roundtrips() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let binding = AccountDeviceSignerBinding {
            marmot_identity: member_id(1),
            mls_signature_public_key: vec![1, 2, 3],
        };

        store.put_account_device_signer(&binding).unwrap();

        assert_eq!(
            store.account_device_signer(&member_id(1)).unwrap(),
            Some(binding)
        );
        assert_eq!(store.account_device_signer(&member_id(9)).unwrap(), None);
    }

    #[test]
    fn account_device_signer_binding_survives_encrypted_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("local identity key").unwrap();
        let binding = AccountDeviceSignerBinding {
            marmot_identity: member_id(1),
            mls_signature_public_key: vec![9, 8, 7],
        };

        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.put_account_device_signer(&binding).unwrap();
        }

        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            reopened.account_device_signer(&member_id(1)).unwrap(),
            Some(binding)
        );
    }
}
