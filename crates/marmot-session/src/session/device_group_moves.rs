//! Selected native proof and the same-connection Made cut. Only the outer
//! pairing drive calls Made; generic projection/recovery never cuts trust.
use super::*;
use cgka_traits::EpochState;
use cgka_traits::app_components::{DEVICE_ROSTER_COMPONENT_ID, decode_device_roster_v1};
use cgka_traits::storage::{DeviceGroupWelcomeStorage as _, StorageProvider};
use storage_sqlite::DeviceGroupMovePhase;

impl AccountDeviceSession {
    /// Pin exact original trust and destination expectation before Confirm.
    pub fn prepare_device_group_move(
        &mut self,
        expectation: &DeviceGroupWelcomeExpectation,
        own_slot: [u8; 32],
        now: u64,
    ) -> SessionResult<bool> {
        let rows = self
            .storage
            .app_storage()
            .device_groups()?
            .into_iter()
            .filter(|row| row.trust.is_trusted())
            .collect::<Vec<_>>();
        let [original] = rows.as_slice() else {
            return Err(
                EngineError::Other("move requires one authenticated original".into()).into(),
            );
        };
        let original_id = GroupId::new(
            hex::decode(&original.group_id_hex)
                .map_err(|_| EngineError::Other("invalid original device group id".into()))?,
        );
        if !self.ensure_group_hydrated(&original_id)? {
            return Ok(false);
        }
        self.storage
            .with_transaction(|store| -> SessionResult<bool> {
                let roster = self
                    .engine
                    .app_component(&original_id, DEVICE_ROSTER_COMPONENT_ID)?
                    .and_then(|bytes| decode_device_roster_v1(&bytes).ok())
                    .ok_or_else(|| EngineError::Other("move original roster unavailable".into()))?;
                if !roster.devices.get(&own_slot).is_some_and(|entry| {
                    entry.tag_signature_key.as_ref() == Some(&self.engine.own_signature_key())
                }) {
                    return Err(EngineError::Other(
                        "move original does not authenticate this device".into(),
                    )
                    .into());
                }
                if !store
                    .app_storage()
                    .prepare_device_group_move(expectation, &own_slot, now)?
                {
                    return Ok(false);
                }
                store.put_device_group_welcome_expectation(expectation)?;
                Ok(true)
            })
    }

    /// Require present D40 Made proof, capture selected old facts, and cut
    /// trust with debt retirement on this session's connection. Join alone
    /// never calls this. Exposed native group-pinned work remains unchanged.
    pub fn record_device_group_move_made(
        &mut self,
        destination: &GroupId,
        now: u64,
    ) -> SessionResult<bool> {
        let Some(movement) = self
            .storage
            .app_storage()
            .device_group_move(destination)?
            .filter(|row| row.phase == DeviceGroupMovePhase::Joined)
        else {
            return Ok(false);
        };
        if !self.ensure_group_hydrated(destination)?
            || !self.ensure_group_hydrated(&movement.original_id)?
        {
            return Ok(false);
        }
        self.storage
            .with_transaction(|store| -> SessionResult<bool> {
                if store.app_storage().device_group_move(destination)?.as_ref() != Some(&movement) {
                    return Ok(false);
                }
                if !matches!(
                    self.engine.epoch_state(destination),
                    Some(EpochState::Stable { .. })
                ) || self.engine.has_pending_convergence_inputs(destination)?
                {
                    return Ok(false);
                }
                let record = self.engine.group_record(destination)?;
                if record.is_terminal() || record.unrecoverable {
                    return Ok(false);
                }
                let roster = self
                    .engine
                    .app_component(destination, DEVICE_ROSTER_COMPONENT_ID)?
                    .and_then(|bytes| decode_device_roster_v1(&bytes).ok())
                    .ok_or_else(|| {
                        EngineError::Other("move destination roster unavailable".into())
                    })?;
                if !roster.devices.get(&movement.own_slot).is_some_and(|entry| {
                    entry.tag_signature_key.as_ref() == Some(&self.engine.own_signature_key())
                }) || !self.engine.own_device_tag_commit_landed(
                    destination,
                    &roster,
                    &movement.own_slot,
                )? {
                    return Ok(false);
                }
                let original = self
                    .engine
                    .app_component(&movement.original_id, DEVICE_ROSTER_COMPONENT_ID)?
                    .and_then(|bytes| decode_device_roster_v1(&bytes).ok())
                    .ok_or_else(|| EngineError::Other("move original roster unavailable".into()))?;
                // All pre-cut private stock belongs to the original namespace.
                // Per-recipient discard removes real keys, unlike discard(None).
                let recipients = self
                    .engine
                    .issued_private_key_packages()?
                    .into_iter()
                    .map(|record| record.recipient_slot)
                    .collect::<std::collections::BTreeSet<_>>();
                for recipient in recipients {
                    self.engine
                        .discard_private_key_packages(now, Some(&recipient))?;
                }
                self.engine.retire_sibling_welcome_deliveries()?;
                Ok(store.commit_device_group_move_made(&movement, &original, &roster, now)?)
            })
    }
}
