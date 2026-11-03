//! Authenticated native admission joined to the finite local move owner.
use crate::base::connection::CachedSql;
use crate::{DeviceGroupMovePhase, SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{
    DeviceGroupWelcomeExpectation, DeviceGroupWelcomeStorage, StorageError, StorageResult,
};
use cgka_traits::{StorageProvider as _, Timestamp};
use rusqlite::params;

pub(crate) fn accept_welcome(
    store: &SqliteAccountStorage,
    expected: &DeviceGroupWelcomeExpectation,
    joined_at: Timestamp,
) -> StorageResult<bool> {
    store.with_transaction(|store| {
        if store.device_group_welcome_expectation(&expected.group_id)?.as_ref() != Some(expected) {
            return Ok(false);
        }
        let app = store.app_storage();
        if let Some(movement) = app.device_group_move(&expected.group_id)?.filter(|record| record.phase == DeviceGroupMovePhase::Waiting) {
            if movement.expectation != *expected {
                return Err(StorageError::Backend("move does not match authenticated Welcome expectation".into()));
            }
            let original = app.device_group(&hex::encode(movement.original_id.as_slice()))?;
            if !original.is_some_and(|row| row.trust == movement.original_trust && row.key_package_ref_hex.as_deref() == Some(movement.original_key_package_ref_hex.as_str()) && row.recorded_at == movement.original_recorded_at) {
                return Err(StorageError::Backend("move original provenance changed before join".into()));
            }
            let conn = store.lock()?;
            conn.execute_cached("UPDATE device_group_moves SET phase = 1 WHERE move_id = ?1 AND phase = 0", params![movement.move_id]).storage()?;
            conn.execute_cached("INSERT INTO device_group_joins(group_id_hex,joined_at) VALUES(?1,?2) ON CONFLICT(group_id_hex) DO NOTHING", params![hex::encode(expected.group_id.as_slice()),crate::u64_to_i64(joined_at.0)?]).storage()?;
        }
        store.delete_device_group_welcome_expectation(&expected.group_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceGroupRecord, DeviceGroupTrust, FirstTrustedRoster};
    use cgka_traits::GroupId;

    /// Storage bookkeeping only: consuming the expectation and local Joined
    /// progress roll back together, without a trust cut. Native validation is
    /// owned by the engine's real encrypted Welcome test.
    #[test]
    fn move_join_bookkeeping_is_atomic_without_changing_trust() {
        let store = SqliteAccountStorage::in_memory_for_test().unwrap();
        let app = store.app_storage();
        let original = GroupId::new(vec![1; 16]);
        let original_hex = hex::encode(original.as_slice());
        assert!(
            app.insert_device_group(&DeviceGroupRecord {
                group_id_hex: original_hex.clone(),
                trust: DeviceGroupTrust::Creating,
                key_package_ref_hex: Some("01".into()),
                recorded_at: 1,
            })
            .unwrap()
        );
        app.trust_device_group(
            &original_hex,
            DeviceGroupTrust::Creating,
            DeviceGroupTrust::Created,
            None,
            1,
            &FirstTrustedRoster {
                own: &[],
                roster: &[],
                now: 1,
            },
        )
        .unwrap()
        .unwrap();
        let expected = DeviceGroupWelcomeExpectation {
            group_id: GroupId::new(vec![2; 16]),
            sender_signature_key: vec![3; 32],
            key_package_ref: vec![4; 32],
            expires_at: 600,
        };
        assert!(
            app.prepare_device_group_move(&expected, &[5; 32], 2)
                .unwrap()
        );
        store
            .put_device_group_welcome_expectation(&expected)
            .unwrap();
        store.lock().unwrap().execute_batch(
            "CREATE TRIGGER fail_move_expectation_consume BEFORE DELETE ON cgka_device_group_welcome_expectations
            BEGIN SELECT RAISE(FAIL, 'move expectation consume failed'); END;"
        ).unwrap();
        let error = store
            .accept_device_group_welcome(&expected, Timestamp(3))
            .unwrap_err();
        assert!(
            matches!(error, StorageError::Backend(ref message) if message.contains("move expectation consume failed")),
            "{error:?}"
        );
        assert_eq!(
            app.device_group_move(&expected.group_id)
                .unwrap()
                .unwrap()
                .phase,
            DeviceGroupMovePhase::Waiting
        );
        assert!(app.device_group_joins().unwrap().is_empty());
        assert_eq!(
            store
                .device_group_welcome_expectation(&expected.group_id)
                .unwrap(),
            Some(expected.clone())
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_move_expectation_consume")
            .unwrap();
        assert!(
            store
                .accept_device_group_welcome(&expected, Timestamp(3))
                .unwrap()
        );
        assert_eq!(
            app.device_group_move(&expected.group_id)
                .unwrap()
                .unwrap()
                .phase,
            DeviceGroupMovePhase::Joined
        );
        assert_eq!(
            app.device_group_joins().unwrap(),
            vec![(hex::encode(expected.group_id.as_slice()), 3)]
        );
        assert!(
            store
                .device_group_welcome_expectation(&expected.group_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            app.device_group(&original_hex).unwrap().unwrap().trust,
            DeviceGroupTrust::Created
        );
        assert_eq!(
            app.device_group(&hex::encode(expected.group_id.as_slice()))
                .unwrap()
                .unwrap()
                .trust,
            DeviceGroupTrust::AwaitingWelcome
        );
    }
}
