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

impl SqliteAccountStorage {
    /// Commit the local Made cut after the session has proved the current
    /// selected first-own destination Commit. Source identity, captured facts,
    /// one-way App debt retirement and full small-state bootstrap are atomic.
    /// No admitted native intent or frozen carrier bytes are deleted here.
    pub fn commit_device_group_move_made(
        &self,
        movement: &crate::DeviceGroupMoveRecord,
        original_roster: &cgka_traits::app_components::DeviceRosterV1,
        destination_roster: &cgka_traits::app_components::DeviceRosterV1,
        now: u64,
    ) -> StorageResult<bool> {
        use crate::app::backup_recovery_key::forget_kept_recovery_key;
        use crate::app::compromise_warning::{
            FirstTrustedRoster, ObservedWarningItem, record_first_trusted_roster,
        };
        use crate::{CompromiseWarningReason, MoveRejectedSlot, MoveSibling, SignInAnswer};
        use cgka_traits::app_components::RejectedSlotReasonV1;
        self.with_transaction(|store| {
            let app = store.app_storage();
            if app.device_group_move(&movement.destination_id)?.as_ref() != Some(movement)
                || movement.phase != DeviceGroupMovePhase::Joined { return Ok(false); }
            let old = hex::encode(movement.original_id.as_slice());
            let destination = hex::encode(movement.destination_id.as_slice());
            let rejected = original_roster.rejected_slots.iter().map(|(slot, entry)| MoveRejectedSlot {
                slot: *slot, removed: entry.reason == RejectedSlotReasonV1::Removed,
                rejected_at: entry.rejected_at, tag_signature_key: entry.tag_signature_key.clone(), outcome: None,
            }).collect::<Vec<_>>();
            let siblings = original_roster.devices.iter().filter(|(slot, _)| **slot != movement.own_slot)
                .map(|(slot, entry)| MoveSibling { slot: *slot, label: entry.label.clone(), ended: false }).collect::<Vec<_>>();
            let own = app.sign_ins()?.into_iter().filter(|row| row.answer == SignInAnswer::Rejected
                && !destination_roster.devices.keys().any(|slot| hex::encode(slot) == row.slot_id_hex))
                .map(|row| ObservedWarningItem { reason: CompromiseWarningReason::RejectedSignIn,
                    subject: row.slot_id_hex.clone(), slot_id_hex: row.slot_id_hex,
                    occurred_at: row.answered_at.unwrap_or(now) }).collect::<Vec<_>>();
            let roster = destination_roster.rejected_slots.iter().filter(|(_, entry)| entry.reason == RejectedSlotReasonV1::NotMe)
                .map(|(slot, entry)| ObservedWarningItem { reason: CompromiseWarningReason::RejectedSignIn,
                    subject: hex::encode(slot), slot_id_hex: hex::encode(slot), occurred_at: entry.rejected_at }).collect::<Vec<_>>();
            {
                let conn = store.lock()?;
                if conn.execute_cached("UPDATE device_groups SET trust = 'untrusted', key_package_ref_hex = NULL WHERE group_id_hex = ?1 AND trust = ?2 AND key_package_ref_hex = ?3 AND recorded_at = ?4", params![old, if movement.original_trust == crate::DeviceGroupTrust::Created { "created" } else { "linked" }, movement.original_key_package_ref_hex, crate::u64_to_i64(movement.original_recorded_at)?]).storage()? != 1 {
                    return Err(StorageError::Backend("move original provenance changed before Made".into()));
                }
                if conn.execute_cached("UPDATE device_groups SET trust = 'linked', recorded_at = ?2 WHERE group_id_hex = ?1 AND trust = 'awaiting_welcome' AND key_package_ref_hex = ?3", params![destination, crate::u64_to_i64(now)?, hex::encode(&movement.expectation.key_package_ref)]).storage()? != 1 {
                    return Err(StorageError::Backend("move destination provenance changed before Made".into()));
                }
                record_first_trusted_roster(&conn, &destination, &FirstTrustedRoster { own: &own, roster: &roster, now })?;
                forget_kept_recovery_key(&conn)?;
                conn.execute_cached("UPDATE device_group_moves SET phase = 2, rejected_slots = ?2, siblings = ?3 WHERE move_id = ?1 AND phase = 1", params![movement.move_id, crate::serialize(&rejected)?, crate::serialize(&siblings)?]).storage()?;
                // These owners are account-device local and only the old
                // namespace can have produced their debt before this cut.
                conn.execute_batch("DELETE FROM device_renames;
                    DELETE FROM private_key_packages_received WHERE taken_at IS NULL;
                    DELETE FROM private_key_package_requests;
                    DELETE FROM sibling_welcomes_received;
                    DELETE FROM cgka_sibling_adds;
                    DELETE FROM history_deliveries_owed;
                    DELETE FROM history_deliveries_parked;
                    DELETE FROM history_delivery_sends;
                    DELETE FROM sibling_welcome_resends;
                    DELETE FROM device_group_joins;") .storage()?;
            }
            app.start_small_state()?;
            app.owe_all_small_state_items()?;
            app.owe_small_state_broadcast_request()?;
            app.owe_small_state_broadcast_answer()?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceGroupRecord, DeviceGroupTrust, FirstTrustedRoster};
    use cgka_traits::GroupId;

    /// Storage bookkeeping only: Joined leaves trust unchanged; Made cuts it
    /// with capture/bootstrap/retirement, and each transaction rolls back on
    /// a late fault. Native proof is owned by real encrypted Welcome/App tests.
    #[test]
    fn move_join_and_made_bookkeeping_are_atomic() {
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
        // The caller's selected-proof boundary is owned by the native/app
        // move owner. Here a late bootstrap failure must roll back the trust
        // cut, capture and old debt retirement together.
        use cgka_traits::app_components::{
            DeviceEntryV1, DeviceRosterV1, RejectedSlotReasonV1, RejectedSlotV1,
        };
        let source = DeviceRosterV1 {
            devices: [
                ([5; 32], DeviceEntryV1::default()),
                (
                    [6; 32],
                    DeviceEntryV1 {
                        label: "Old sibling".into(),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
            rejected_slots: [(
                [7; 32],
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::NotMe,
                    rejected_at: 4,
                    tag_signature_key: None,
                },
            )]
            .into(),
            ..Default::default()
        };
        let target = DeviceRosterV1::default();
        app.start_small_state().unwrap();
        app.small_state_broadcast_request_sent().unwrap();
        let need = crate::PrivateKeyPackageNeed {
            issuer_slot_hex: hex::encode([6; 32]),
            need: 3,
            requested_at: Some(4),
        };
        app.put_private_key_package_need(&need).unwrap();
        app.owe_history_delivery("ab", &need.issuer_slot_hex, 4)
            .unwrap();
        let owed = app.unsent_history_deliveries().unwrap();
        let movement = app.device_group_move(&expected.group_id).unwrap().unwrap();
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_move_bootstrap BEFORE UPDATE OF request_owed ON small_state_sync WHEN NEW.request_owed = 1 BEGIN SELECT RAISE(ABORT, 'move bootstrap failed'); END;").unwrap();
        let error = store
            .commit_device_group_move_made(&movement, &source, &target, 5)
            .unwrap_err();
        assert!(
            matches!(error, StorageError::Backend(ref message) if message.contains("move bootstrap failed")),
            "{error:?}"
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
        assert_eq!(
            app.private_key_package_need(&need.issuer_slot_hex).unwrap(),
            Some(need.clone())
        );
        assert_eq!(app.unsent_history_deliveries().unwrap(), owed);
        assert_eq!(
            app.device_group_move(&expected.group_id).unwrap(),
            Some(movement.clone())
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_move_bootstrap")
            .unwrap();
        assert!(
            store
                .commit_device_group_move_made(&movement, &source, &target, 5)
                .unwrap()
        );
        assert_eq!(
            app.device_group(&original_hex).unwrap().unwrap().trust,
            DeviceGroupTrust::Untrusted
        );
        assert_eq!(
            app.device_group(&hex::encode(expected.group_id.as_slice()))
                .unwrap()
                .unwrap()
                .trust,
            DeviceGroupTrust::Linked
        );
        assert!(
            app.private_key_package_need(&need.issuer_slot_hex)
                .unwrap()
                .is_none()
        );
        assert!(app.unsent_history_deliveries().unwrap().is_empty());
        assert!(app.small_state_schedule().unwrap().unwrap().request_owed);
        let made = app.device_group_move(&expected.group_id).unwrap().unwrap();
        assert_eq!(made.phase, DeviceGroupMovePhase::Made);
        assert_eq!(
            made.siblings
                .iter()
                .map(|sibling| (sibling.slot, sibling.label.as_str()))
                .collect::<Vec<_>>(),
            vec![([6; 32], "Old sibling")]
        );
        let captured = made.rejected_slots.unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            (
                captured[0].slot,
                captured[0].rejected_at,
                captured[0].removed
            ),
            ([7; 32], 4, false)
        );
        assert!(
            !store
                .commit_device_group_move_made(&movement, &source, &target, 5)
                .unwrap(),
            "stale Made cannot cut another current trust"
        );
    }
}
