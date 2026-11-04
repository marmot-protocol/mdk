//! Finite move progress in the existing outer pairing drive. Generic
//! projection/sync observers never call Made, so awaited ordinary App edits
//! finish on their captured old group before this one-way cut can run.
use super::AppClient;
use super::device_pairing::{DeviceGroupMoveSibling, DeviceGroupMoveState, DeviceGroupMoveView};
use crate::AppError;
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceStatusV1, decode_device_roster_v1,
};
use cgka_traits::storage::GroupStorage as _;
use cgka_traits::{EpochState, SendIntent};
use storage_sqlite::{DeviceGroupMovePhase, DeviceGroupMoveRecord};

const TRACE_TARGET: &str = "marmot_app::client::device_group_moves";

#[cfg_attr(not(feature = "unreleased-device-pairing"), allow(dead_code))]
impl AppClient {
    pub(super) fn device_group_move_views(&self) -> Result<Vec<DeviceGroupMoveView>, AppError> {
        let current = self.trusted_device_group()?;
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_group_moves()?
            .into_iter()
            .map(|movement| {
                let made = movement.rejected_slots.is_some();
                let state = match movement.phase {
                    DeviceGroupMovePhase::Waiting => DeviceGroupMoveState::WaitingForWelcome,
                    DeviceGroupMovePhase::Joined => DeviceGroupMoveState::Joining,
                    DeviceGroupMovePhase::Made => DeviceGroupMoveState::Made,
                    DeviceGroupMovePhase::Finished if made => DeviceGroupMoveState::Made,
                    DeviceGroupMovePhase::Finished => DeviceGroupMoveState::Failed,
                };
                let suppress = made && current.as_ref() == Some(&movement.destination_id);
                DeviceGroupMoveView {
                    move_id: movement.move_id.to_string(),
                    state,
                    old_siblings: movement
                        .siblings
                        .into_iter()
                        .map(|sibling| DeviceGroupMoveSibling {
                            slot_id_hex: hex::encode(sibling.slot),
                            label: sibling.label,
                            question_suppressed: suppress && !sibling.ended,
                        })
                        .collect(),
                    overridden_rejection_slots: movement
                        .rejected_slots
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|fact| {
                            fact.outcome == Some(storage_sqlite::MoveCarryOutcome::DeviceCollision)
                        })
                        .map(|fact| hex::encode(fact.slot))
                        .collect(),
                }
            })
            .collect())
    }

    pub(super) fn dismiss_move_sibling(
        &mut self,
        move_id: &str,
        slot_hex: &str,
    ) -> Result<(), AppError> {
        let move_id = move_id
            .parse::<i64>()
            .map_err(|_| AppError::DeviceGroupRefused("unknown_move"))?;
        let slot = super::device_group::device_slot(slot_hex)?;
        if !self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .end_device_group_move_sibling_guidance(move_id, &slot)?
        {
            return Err(AppError::DeviceGroupRefused("unknown_move_sibling"));
        }
        self.device_link_changed = true;
        self.unrecognized_sign_ins_changed = true;
        Ok(())
    }

    pub(super) fn old_move_sibling_exceptions(
        &self,
    ) -> Result<std::collections::BTreeSet<String>, AppError> {
        Ok(self
            .device_group_move_views()?
            .into_iter()
            .flat_map(|movement| movement.old_siblings)
            .filter(|sibling| sibling.question_suppressed)
            .map(|sibling| sibling.slot_id_hex)
            .collect())
    }

    /// A carried local rejection keeps the selected source fact's age and
    /// destination precedence; ordinary folding must not replace it anew.
    pub(super) fn moving_rejection_is_carried(
        &self,
        record: &storage_sqlite::SignInRecord,
    ) -> Result<bool, AppError> {
        let current = self.trusted_device_group()?;
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_group_moves()?
            .into_iter()
            .filter(|movement| current.as_ref() == Some(&movement.destination_id))
            .filter_map(|movement| movement.rejected_slots)
            .flatten()
            .any(|fact| {
                !fact.removed
                    && hex::encode(fact.slot) == record.slot_id_hex
                    && Some(fact.rejected_at) == record.answered_at
            }))
    }

    pub(crate) async fn drive_device_group_moves(&mut self, now: u64) -> Result<(), AppError> {
        let records = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_group_moves()?;
        let mut first_error = None;
        for movement in records {
            if let Err(error) = self.advance_device_group_move(&movement, now).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn advance_device_group_move(
        &mut self,
        movement: &DeviceGroupMoveRecord,
        now: u64,
    ) -> Result<(), AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        match movement.phase {
            DeviceGroupMovePhase::Waiting => {
                use cgka_traits::storage::DeviceGroupWelcomeStorage as _;
                if account
                    .device_group_welcome_expectation(&movement.destination_id)?
                    .is_none()
                {
                    self.finish_move_before_made(movement).await?;
                }
            }
            DeviceGroupMovePhase::Joined => {
                if account.is_group_forgotten(&movement.destination_id)?
                    || self
                        .stored_group(&movement.destination_id)?
                        .is_some_and(|group| group.is_terminal())
                {
                    self.finish_move_before_made(movement).await?;
                    return Ok(());
                }
                let held = self.epoch_gap_held_groups()?;
                let effects = self
                    .runtime
                    .set_device_tag_key_in_group_holding(&movement.destination_id, &held)
                    .await?;
                self.observe_drained_session_events(&effects).await?;
                if self
                    .runtime
                    .record_device_group_move_made(&movement.destination_id, now)?
                {
                    self.sibling_chat_gaps = Default::default();
                    self.received_private_key_package_generation =
                        self.received_private_key_package_generation.wrapping_add(1);
                    self.sync_device_tag_group()?;
                    #[cfg(feature = "unreleased-device-pairing")]
                    self.note_move_link_made(&movement.destination_id);
                    self.note_device_roster_changed();
                    self.device_link_changed = true;
                }
            }
            DeviceGroupMovePhase::Made | DeviceGroupMovePhase::Finished
                if movement.rejected_slots.is_some() =>
            {
                // Destination bookkeeping must retry without blocking the
                // independent old-group status/settlement owner. Report the
                // first error only after each existing obligation got its turn.
                let mut first_error = self.end_joined_move_sibling_guidance(movement).err();
                if let Err(error) = self.carry_move_rejections(movement).await {
                    first_error.get_or_insert(error);
                }
                let cleanup = async {
                    if movement.phase == DeviceGroupMovePhase::Made {
                        if account.is_group_forgotten(&movement.original_id)? {
                            storage.complete_device_group_move(movement.move_id)?;
                        } else if self.finish_old_moved_status(movement).await?
                            && !self
                                .runtime
                                .has_pending_outbound_fanouts(&movement.original_id)?
                            && !self
                                .runtime
                                .has_queued_outbound_intents(&movement.original_id)?
                        {
                            self.forget_group_local(&movement.original_id).await?;
                            storage.complete_device_group_move(movement.move_id)?;
                            self.device_link_changed = true;
                        }
                    }
                    Ok::<(), AppError>(())
                }
                .await;
                if let Err(error) = cleanup {
                    first_error.get_or_insert(error);
                }
                if let Some(error) = first_error {
                    return Err(error);
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn finish_move_before_made(
        &mut self,
        movement: &DeviceGroupMoveRecord,
    ) -> Result<(), AppError> {
        self.runtime
            .withdraw_device_group_welcome(&movement.destination_id)?;
        if self.stored_group(&movement.destination_id)?.is_some() {
            self.forget_group_local(&movement.destination_id).await?;
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        storage.delete_device_group(
            &hex::encode(movement.destination_id.as_slice()),
            storage_sqlite::DeviceGroupTrust::AwaitingWelcome,
        )?;
        storage.end_device_group_move_before_made(movement.move_id)?;
        #[cfg(feature = "unreleased-device-pairing")]
        self.note_move_link_failed(&movement.destination_id);
        self.device_link_changed = true;
        Ok(())
    }

    fn end_joined_move_sibling_guidance(
        &mut self,
        movement: &DeviceGroupMoveRecord,
    ) -> Result<(), AppError> {
        if self.trusted_device_group()?.as_ref() != Some(&movement.destination_id) {
            return Ok(());
        }
        let Some((_, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let selected = self.runtime.group_record(&movement.destination_id)?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        for sibling in movement.siblings.iter().filter(|sibling| !sibling.ended) {
            // A selected departure retains an actual admitted entry even if
            // one accepted batch added then removed it before the App read.
            if roster.devices.contains_key(&sibling.slot)
                || selected
                    .device_roster_departures
                    .iter()
                    .any(|departure| departure.slot == sibling.slot)
            {
                storage.end_device_group_move_sibling_guidance(movement.move_id, &sibling.slot)?;
                self.device_link_changed = true;
                self.unrecognized_sign_ins_changed = true;
            }
        }
        Ok(())
    }

    async fn carry_move_rejections(
        &mut self,
        movement: &storage_sqlite::DeviceGroupMoveRecord,
    ) -> Result<(), AppError> {
        use cgka_traits::app_components::{
            DeviceRosterOperationV1, DeviceRosterUpdateV1, RejectedSlotReasonV1, RejectedSlotV1,
            encode_device_roster_update_v1,
        };
        use storage_sqlite::MoveCarryOutcome;
        if self.trusted_device_group()?.as_ref() != Some(&movement.destination_id) {
            return Ok(());
        }
        let Some(facts) = &movement.rejected_slots else {
            return Ok(());
        };
        let Some((group, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let mut operations = Vec::new();
        for fact in facts.iter().filter(|fact| fact.outcome.is_none()) {
            let original = RejectedSlotV1 {
                reason: if fact.removed {
                    RejectedSlotReasonV1::Removed
                } else {
                    RejectedSlotReasonV1::NotMe
                },
                rejected_at: fact.rejected_at,
                tag_signature_key: fact.tag_signature_key.clone(),
            };
            let outcome = if roster.devices.contains_key(&fact.slot) {
                Some(MoveCarryOutcome::DeviceCollision)
            } else if let Some(current) = roster.rejected_slots.get(&fact.slot) {
                Some(if current == &original {
                    MoveCarryOutcome::Imported
                } else {
                    MoveCarryOutcome::DestinationRejected
                })
            } else if fact.removed
                && crate::unix_now_seconds().saturating_sub(fact.rejected_at) >= 30 * 24 * 60 * 60
            {
                Some(MoveCarryOutcome::Expired)
            } else {
                None
            };
            if let Some(outcome) = outcome {
                storage.settle_device_group_move_carry(movement.move_id, &fact.slot, outcome)?;
                self.device_link_changed = true;
            } else {
                operations.push(DeviceRosterOperationV1::SetRejectedSlot(
                    fact.slot, original,
                ));
            }
        }
        if operations.is_empty() || !self.group_quiet(&group)? {
            return Ok(());
        }
        let update = DeviceRosterUpdateV1::new(operations)
            .and_then(|update| {
                encode_device_roster_update_v1(&update).map_err(|error| error.to_string())
            })
            .map_err(|_| AppError::DeviceGroupRefused("roster_invalid"))?;
        let effects = self
            .runtime
            .send(SendIntent::ImportDeviceGroupRejections {
                group_id: group,
                roster_update: update,
            })
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
            .await
    }

    async fn finish_old_moved_status(
        &mut self,
        movement: &storage_sqlite::DeviceGroupMoveRecord,
    ) -> Result<bool, AppError> {
        if !self.runtime.ensure_group_hydrated(&movement.original_id)? {
            return Ok(false);
        }
        if !matches!(
            self.runtime.epoch_state(&movement.original_id),
            Some(EpochState::Stable { .. })
        ) || self
            .runtime
            .has_pending_convergence_inputs(&movement.original_id)?
        {
            return Ok(false);
        }
        let group = self.runtime.group_record(&movement.original_id)?;
        if group.unrecoverable {
            return Ok(false);
        }
        if !self
            .runtime
            .canonical_group_membership(&movement.original_id)?
            .local_leaf_active
        {
            return Ok(group.removed);
        }
        if !self
            .runtime
            .device_group_takes_commit(&movement.original_id, &[])?
        {
            return Ok(false);
        }
        let Some(roster) = self
            .runtime
            .app_component(&movement.original_id, DEVICE_ROSTER_COMPONENT_ID)?
            .and_then(|bytes| decode_device_roster_v1(&bytes).ok())
        else {
            return Ok(false);
        };
        let Some(entry) = roster.devices.get(&movement.own_slot) else {
            return Ok(false);
        };
        if entry.status == DeviceStatusV1::Moved {
            return Ok(true);
        }
        let effects = self
            .runtime
            .send(SendIntent::MarkDeviceGroupMoved {
                group_id: movement.original_id.clone(),
                slot: movement.own_slot,
                expected: Box::new(entry.clone()),
            })
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
            .await?;
        tracing::debug!(target: TRACE_TARGET, method = "finish_old_moved_status", "old moved-status work advanced");
        Ok(false)
    }
}
