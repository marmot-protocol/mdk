//! Marking and removing inactive siblings (mdk#2628 item 3.6b-2, D67(6),
//! D94, D95).
//!
//! - **Caught up.** A device acts only on a maintenance pass that finds it
//!   caught up with the device group it trusts: the group is quiet and its
//!   copy recoverable, no epoch gap is open at its epoch, and the coverage
//!   ledger proves its history up to now on every relay that certifies it
//!   ([`AppClient::group_history_proved`]).
//! - **The clock.** Only caught-up passes count. When more than 24 hours pass
//!   between two of them, or the clock went back, every sibling's clock
//!   restarts at the second: this device was closed, offline or behind.
//!   Shorter gaps count as running time. Every clock also restarts when a
//!   parked remainder, history the retention floor overtook unproved, reaches
//!   past the last restart; older remainders cannot hold a heartbeat that
//!   would move any clock, and they last until a user dismisses them. A sibling's clock runs from the
//!   latest of when this device first found its entry, its last activity,
//!   when this device read the heartbeat that showed it (D95), when this
//!   device saw it clear its own mark, and the last restart. It never starts
//!   before the Devices screen's judgement (D35), so a mark never comes before
//!   this device would show the sibling inactive.
//! - **Mark.** At 30 days a caught-up device commits the sibling's entry with
//!   status `inactive`, every other field unchanged. A mark that loses branch
//!   selection is reissued by the engine only while the entry is unchanged:
//!   it is this pass's decision, and it decides no removal, which checks the
//!   clock again. A lost mark that is not reissued reads as a clear on the
//!   next pass and postpones that sibling's mark.
//! - **Remove.** At 90 days, while the roster still lists the sibling as
//!   `inactive` and its "keep while inactive" setting is off, a caught-up
//!   device removes it with the removal Commit a user's removal makes. Nothing
//!   is recorded first, and the engine never reissues it, so a removal that
//!   loses branch selection is decided afresh on a later pass (D94); a user's
//!   removal of the slot is left to its own record. An automatic removal does
//!   not delete the removed device's KeyPackage slot, which by then has
//!   expired unless the device kept running without reaching its group.
//! - **Clear.** A device that finds its own entry `inactive` sets it back to
//!   `active` once it is caught up and has sent a heartbeat since its clock
//!   last restarted. The heartbeat and inactivity passes of one maintenance
//!   pass share a second, so a device back after more than a day clears its
//!   mark on the pass that sends its first heartbeat. A sibling that sees
//!   the mark cleared restarts that
//!   device's clock, so one that applies the clear before it reads the
//!   heartbeat does not mark it again. A device sees a mark on a caught-up
//!   pass, or when it commits the mark itself; one that applies another
//!   device's mark and its clear between two passes, and reads the cleared
//!   device's heartbeat only after the clear, may mark it once more, and
//!   that device clears it again.
//! - **Stalled.** A device whose recovery gave up on an epoch gap in its
//!   device group, or whose copy is unrecoverable, can never catch up, see
//!   or clear its mark: its link snapshot shows `device_group_stalled`, which
//!   offers the explicit reset and fresh pairing (D112). The pairing drive
//!   raises `DeviceLinkChanged` when that changes, as for any change to the
//!   snapshot.
//!
//! One pass makes at most one Commit here. Nothing runs while device groups
//! are off, maintenance is paused or the account is signing out.

use cgka_traits::GroupId;
use cgka_traits::app_components::{DeviceSlotId, DeviceStatusV1};
use marmot_session::{DeviceRosterEdit, DeviceRosterEditBlocked};
use storage_sqlite::{DeviceActivityRecord, DeviceInactivityClock};

use super::AppClient;
use super::device_heartbeats::INACTIVE_AFTER_SECS;
use crate::AppError;

const TRACE_TARGET: &str = "marmot_app::client::device_inactivity";

/// A sibling is marked `inactive` once its clock has run this long.
pub(crate) const MARK_INACTIVE_AFTER_SECS: u64 = INACTIVE_AFTER_SECS;

/// A sibling still marked `inactive` is removed once its clock has run this
/// long.
pub(crate) const REMOVE_INACTIVE_AFTER_SECS: u64 = 90 * 24 * 60 * 60;

/// The longest gap between two caught-up passes that still counts as
/// running time.
pub(crate) const RUNNING_GAP_SECS: u64 = 24 * 60 * 60;

/// This device's clock after a caught-up pass at `now`: it restarts when the
/// last caught-up pass is more than [`RUNNING_GAP_SECS`] back, or later than
/// `now`.
fn advance_clock(clock: Option<DeviceInactivityClock>, now: u64) -> DeviceInactivityClock {
    match clock {
        Some(clock)
            if clock.caught_up_at <= now && now - clock.caught_up_at <= RUNNING_GAP_SECS =>
        {
            DeviceInactivityClock {
                caught_up_at: now,
                restarted_at: clock.restarted_at,
            }
        }
        _ => DeviceInactivityClock {
            caught_up_at: now,
            restarted_at: now,
        },
    }
}

/// How long `activity`'s sibling has gone without a restart of its clock at
/// `now`.
fn inactive_for(activity: &DeviceActivityRecord, clock: &DeviceInactivityClock, now: u64) -> u64 {
    let since = [
        activity.first_seen_at,
        activity.last_active_at.unwrap_or(0),
        activity.clock_from.unwrap_or(0),
        clock.restarted_at,
    ]
    .into_iter()
    .max()
    .unwrap_or(now);
    now.saturating_sub(since)
}

impl AppClient {
    /// One inactivity pass as of `now`, the second the heartbeat pass used;
    /// a failure waits for the next one.
    pub(crate) async fn device_inactivity_upkeep(&mut self, held: &[GroupId], now: u64) {
        if !self.app.device_groups_enabled()
            || self.runtime.maintenance_is_paused()
            || self.signing_out()
        {
            return;
        }
        if let Err(error) = self.try_device_inactivity_upkeep(held, now).await {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "device_inactivity_upkeep",
                error_kind = error.privacy_safe_kind(),
                "device inactivity upkeep failed"
            );
        }
    }

    /// Whether this device can no longer catch up with the device group it
    /// trusts: automatic recovery gave up on an epoch gap at its epoch, or its
    /// copy is unrecoverable. Only the explicit reset and fresh pairing bring
    /// it back (D112).
    #[cfg(feature = "unreleased-device-pairing")]
    pub(crate) fn device_group_stalled(&self) -> Result<bool, AppError> {
        let Some(group_id) = self.trusted_device_group()? else {
            return Ok(false);
        };
        let Ok(record) = self.runtime.group_record(&group_id) else {
            return Ok(false);
        };
        if record.is_terminal() {
            return Ok(false);
        }
        Ok(record.unrecoverable
            || self
                .app
                .account_storage(&self.state.label)?
                .app_storage()
                .epoch_gap_recovery_given_up(group_id.as_slice(), record.epoch.0)?)
    }

    /// Whether this device is caught up with its device group `group_id` at
    /// `now` (see the module docs).
    async fn device_group_caught_up(&self, group_id: &GroupId, now: u64) -> Result<bool, AppError> {
        if !self.group_quiet(group_id)? || self.group_unrecoverable(group_id.as_slice()) {
            return Ok(false);
        }
        let epoch = self.runtime.group_record(group_id)?.epoch;
        if self.epoch_gap_open_since(group_id, epoch)?.is_some() {
            return Ok(false);
        }
        self.group_history_proved(group_id.as_slice(), now).await
    }

    /// [`Self::device_inactivity_upkeep`]'s pass as of `now`.
    async fn try_device_inactivity_upkeep(
        &mut self,
        held: &[GroupId],
        now: u64,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        let group_id = exchange.group_id.clone();
        if held.contains(&group_id) || !self.device_group_caught_up(&group_id, now).await? {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let mut clock = advance_clock(storage.device_inactivity_clock()?, now);
        // History since the last restart that fell below the retention floor
        // unproved may hold a heartbeat this device never read.
        if self
            .group_parked_until(group_id.as_slice())?
            .is_some_and(|until| until >= clock.restarted_at)
        {
            clock.restarted_at = now;
        }
        storage.put_device_inactivity_clock(&clock)?;
        for (slot, entry) in &exchange.roster.devices {
            if exchange.is_sibling(slot) {
                storage.note_device_marked_inactive(
                    &hex::encode(slot),
                    entry.linked_at,
                    entry.status == DeviceStatusV1::Inactive,
                    now,
                )?;
            }
        }

        let group_id_hex = hex::encode(group_id.as_slice());
        if exchange
            .roster
            .devices
            .get(&exchange.own_slot)
            .is_some_and(|entry| entry.status == DeviceStatusV1::Inactive)
            && storage.device_heartbeat_sent()?.is_some_and(|sent| {
                sent.group_id_hex == group_id_hex && sent.sent_at >= clock.restarted_at
            })
        {
            self.set_inactivity_status(&group_id, &exchange.own_slot, held, DeviceStatusV1::Active)
                .await?;
            return Ok(());
        }

        let removing = storage
            .device_removals()?
            .into_iter()
            .filter(|removal| removal.group_id_hex == group_id_hex)
            .map(|removal| removal.slot_hex)
            .collect::<std::collections::HashSet<_>>();
        let activity = storage.device_activity()?;
        for (slot, entry) in &exchange.roster.devices {
            let slot_hex = hex::encode(slot);
            if !exchange.is_sibling(slot)
                || entry.tag_signature_key.is_none()
                || removing.contains(&slot_hex)
            {
                continue;
            }
            let Some(age) = activity
                .iter()
                .find(|row| row.slot_id_hex == slot_hex && row.linked_at == entry.linked_at)
                .map(|row| inactive_for(row, &clock, now))
            else {
                continue;
            };
            match entry.status {
                DeviceStatusV1::Active if age >= MARK_INACTIVE_AFTER_SECS => {
                    // This device saw its own mark, so it sees the clear
                    // even when it applies it before its next pass.
                    if self
                        .set_inactivity_status(&group_id, slot, held, DeviceStatusV1::Inactive)
                        .await?
                    {
                        storage.note_device_marked_inactive(
                            &slot_hex,
                            entry.linked_at,
                            true,
                            now,
                        )?;
                    }
                    return Ok(());
                }
                DeviceStatusV1::Inactive
                    if age >= REMOVE_INACTIVE_AFTER_SECS && !entry.settings.keep_while_inactive =>
                {
                    return self
                        .commit_device_removal(&group_id, &exchange.roster, slot, now)
                        .await;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Commit `slot`'s entry with `status`, every other field unchanged, and
    /// return whether the Commit went out. A device group that cannot take a
    /// commit now waits for a later pass.
    async fn set_inactivity_status(
        &mut self,
        group_id: &GroupId,
        slot: &DeviceSlotId,
        held: &[GroupId],
        status: DeviceStatusV1,
    ) -> Result<bool, AppError> {
        match self
            .runtime
            .edit_device_roster_entry(group_id, slot, held, |entry| entry.status = status)
            .await?
        {
            DeviceRosterEdit::Committed(effects) => {
                self.linked_devices_changed = true;
                self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                    .await?;
                Ok(true)
            }
            DeviceRosterEdit::Unchanged
            | DeviceRosterEdit::Blocked(
                DeviceRosterEditBlocked::Busy
                | DeviceRosterEditBlocked::NoEntry
                | DeviceRosterEditBlocked::Unreadable,
            ) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    fn clock(caught_up_at: u64, restarted_at: u64) -> DeviceInactivityClock {
        DeviceInactivityClock {
            caught_up_at,
            restarted_at,
        }
    }

    fn activity(
        first_seen_at: u64,
        last_active_at: Option<u64>,
        clock_from: Option<u64>,
    ) -> DeviceActivityRecord {
        DeviceActivityRecord {
            slot_id_hex: "aa".into(),
            linked_at: 1,
            first_seen_at,
            last_active_at,
            clock_from,
            marked_inactive: false,
        }
    }

    /// Gaps of 24 hours or less between caught-up passes count as running
    /// time; a longer one, a clock that went back, or no earlier pass
    /// restarts every clock.
    #[test]
    fn the_clock_restarts_after_a_gap_of_more_than_a_day() {
        let now = 100 * DAY;
        assert_eq!(advance_clock(None, now), clock(now, now));
        assert_eq!(
            advance_clock(Some(clock(now - RUNNING_GAP_SECS, 10 * DAY)), now),
            clock(now, 10 * DAY)
        );
        assert_eq!(
            advance_clock(Some(clock(now - RUNNING_GAP_SECS - 1, 10 * DAY)), now),
            clock(now, now)
        );
        assert_eq!(
            advance_clock(Some(clock(now + 1, 10 * DAY)), now),
            clock(now, now)
        );
    }

    /// A sibling's clock runs from the latest of when this device found it,
    /// its last activity, when that activity was read, and the last restart.
    #[test]
    fn a_siblings_clock_runs_from_its_latest_restart() {
        let now = 100 * DAY;
        let restarted = clock(now, 10 * DAY);
        assert_eq!(
            inactive_for(&activity(5 * DAY, None, None), &restarted, now),
            90 * DAY
        );
        assert_eq!(
            inactive_for(&activity(5 * DAY, Some(20 * DAY), None), &restarted, now),
            80 * DAY
        );
        assert_eq!(
            inactive_for(
                &activity(5 * DAY, Some(20 * DAY), Some(30 * DAY)),
                &restarted,
                now
            ),
            70 * DAY
        );
        assert_eq!(
            inactive_for(&activity(40 * DAY, None, None), &restarted, now),
            60 * DAY
        );
    }
}
