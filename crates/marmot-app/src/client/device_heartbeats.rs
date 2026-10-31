//! Heartbeats, last activity and inactive siblings (mdk#2628 item 3.6, D35).
//!
//! - Each maintenance pass, a device sends a heartbeat (kind 457, `{"v":1}`)
//!   in the device group it trusts when its last one there is at least an
//!   hour old, at open or later. It sends only once its own leaf carries a
//!   device tag that reads as its slot (3.1d), since siblings count nothing
//!   from an untagged leaf. When it sent its last one, and where, is kept on
//!   disk, recorded once the send went out, so one that reached no one or
//!   failed is sent again at the next pass. A heartbeat is a device-group
//!   message, so it never asks for a push notification.
//! - A heartbeat counts for a sibling only when the sending leaf, in the tree
//!   this device holds when it reads the heartbeat, carries a device tag that
//!   reads as another device in the roster. One from an earlier epoch counts
//!   for no device; that sibling's next one counts. The content is not read,
//!   so a later version can add to it without older devices judging its
//!   sender inactive, and no rate is enforced. A heartbeat is dated
//!   `min(created_at, the time it was read)`; a sibling's last activity is
//!   the newest such date.
//! - Each pass tracks the siblings the roster lists, from when this device
//!   first finds each one's entry there. An entry is named by its
//!   `linked_at`, so a slot removed and linked again between two passes, or
//!   heard from first, starts afresh rather than inheriting the earlier
//!   entry's activity. A sibling is inactive 30 days after the
//!   later of its last activity and that first sighting, judged here for the
//!   Devices screen only: nothing is written to the roster (3.6b writes its
//!   `inactive` status). A pass that judges differently from the last one
//!   owes hosts a `LinkedDevicesChanged`.

use std::collections::BTreeSet;

use cgka_traits::app_components::DeviceTagClaim;
use cgka_traits::{EpochId, GroupId};
use storage_sqlite::{DeviceActivityRecord, DeviceHeartbeatSent};

use super::AppClient;
use super::device_group::KIND_DEVICE_HEARTBEAT;
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::device_heartbeats";

/// What a heartbeat says. Receivers do not read it.
const HEARTBEAT_CONTENT: &str = r#"{"v":1}"#;

/// A device sends a heartbeat once its last one is this old.
pub(crate) const HEARTBEAT_INTERVAL_SECS: u64 = 60 * 60;

/// A sibling is inactive this long after the later of its last activity and
/// when this device first found it in the roster.
pub(crate) const INACTIVE_AFTER_SECS: u64 = 30 * 24 * 60 * 60;

/// Whether the sibling `activity` describes is inactive at `now`. One this
/// device does not track yet has just been found, so it is not.
pub(crate) fn sibling_inactive(activity: Option<&DeviceActivityRecord>, now: u64) -> bool {
    activity.is_some_and(|activity| {
        let since = activity
            .last_active_at
            .map_or(activity.first_seen_at, |at| at.max(activity.first_seen_at));
        now.saturating_sub(since) >= INACTIVE_AFTER_SECS
    })
}

/// When a heartbeat created at `created_at` and read at `now` shows its
/// sender running: a late delivery never dates activity later than it was,
/// and a sender's clock never dates it after it was read.
fn heartbeat_time(created_at: u64, now: u64) -> u64 {
    created_at.min(now)
}

/// Whether a heartbeat sent at `sent_at` is recent enough at `now` that
/// this device sends none. One dated after `now` means the clock went back;
/// then it sends.
fn heartbeat_is_recent(sent_at: u64, now: u64) -> bool {
    sent_at <= now && now - sent_at < HEARTBEAT_INTERVAL_SECS
}

impl AppClient {
    /// One heartbeat pass; a failure waits for the next one.
    pub(crate) async fn device_heartbeat_upkeep(&mut self, held: &[GroupId]) {
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return;
        }
        if let Err(error) = self.try_device_heartbeat_upkeep(held).await {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "device_heartbeat_upkeep",
                error_kind = error.privacy_safe_kind(),
                "device heartbeat upkeep failed"
            );
        }
    }

    async fn try_device_heartbeat_upkeep(&mut self, held: &[GroupId]) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        let now = unix_now_seconds();
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let siblings: Vec<(String, u64)> = exchange
            .roster
            .devices
            .iter()
            .filter(|(slot, _)| exchange.is_sibling(slot))
            .map(|(slot, entry)| (hex::encode(slot), entry.linked_at))
            .collect();
        storage.track_device_activity(&siblings, now)?;
        let inactive: BTreeSet<String> = storage
            .device_activity()?
            .into_iter()
            .filter(|activity| sibling_inactive(Some(activity), now))
            .map(|activity| activity.slot_id_hex)
            .collect();
        if self
            .inactive_siblings
            .replace(inactive.clone())
            .is_some_and(|before| before != inactive)
        {
            self.linked_devices_changed = true;
        }

        if held.contains(&exchange.group_id) || !exchange.tagged {
            return Ok(());
        }
        let group_id_hex = hex::encode(exchange.group_id.as_slice());
        let last = storage.device_heartbeat_sent()?;
        if last.as_ref().is_some_and(|last| {
            last.group_id_hex == group_id_hex && heartbeat_is_recent(last.sent_at, now)
        }) {
            return Ok(());
        }
        let sent = self
            .send_device_group_message(
                &exchange.group_id,
                KIND_DEVICE_HEARTBEAT,
                HEARTBEAT_CONTENT.to_owned(),
            )
            .await?;
        // Recorded only once it went out, so one that reached no one, failed
        // or was cut short by a restart is sent again at the next pass. A
        // restart after it went out and before this write sends it twice,
        // which costs nothing: receivers enforce no rate.
        if sent {
            storage.put_device_heartbeat_sent(Some(&DeviceHeartbeatSent {
                group_id_hex,
                sent_at: now,
            }))?;
        }
        Ok(())
    }

    /// Count a heartbeat for the sibling whose device tag the sending leaf
    /// carries in the tree this device holds now. One from an earlier epoch
    /// counts for no device.
    pub(super) fn receive_device_heartbeat(
        &mut self,
        group_id: &GroupId,
        (epoch, sender_leaf_index): (EpochId, Option<u32>),
        created_at: u64,
    ) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        // The tag reader reads a past epoch from its retained anchor; a
        // heartbeat counts only from the tree this device holds now.
        if &exchange.group_id != group_id || epoch != self.runtime.group_record(group_id)?.epoch {
            return Ok(());
        }
        let claim = match sender_leaf_index {
            Some(leaf) => {
                self.runtime
                    .member_device_tag_claim(group_id, epoch, leaf, &exchange.roster)?
            }
            None => None,
        };
        let (slot, linked_at) = match claim {
            // The index holds no leaf.
            None => return Ok(()),
            Some(DeviceTagClaim::Device(slot)) => match exchange.roster.devices.get(&slot) {
                Some(entry) if exchange.is_sibling(&slot) => (slot, entry.linked_at),
                _ => return Ok(()),
            },
            Some(DeviceTagClaim::RejectedSlot(_) | DeviceTagClaim::Unclaimed) => {
                return Err(AppError::DeviceGroupRefused("sender_not_tagged"));
            }
        };
        let now = unix_now_seconds();
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .note_device_active(
                &hex::encode(slot),
                linked_at,
                heartbeat_time(created_at, now),
                now,
            )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activity(first_seen_at: u64, last_active_at: Option<u64>) -> DeviceActivityRecord {
        DeviceActivityRecord {
            slot_id_hex: "aa".into(),
            linked_at: 1,
            first_seen_at,
            last_active_at,
        }
    }

    #[test]
    fn a_sibling_is_inactive_thirty_days_after_it_was_last_seen_active() {
        let day = 24 * 60 * 60;
        let now = 100 * day;
        assert!(!sibling_inactive(None, now));
        assert!(!sibling_inactive(
            Some(&activity(now - 29 * day, None)),
            now
        ));
        assert!(sibling_inactive(Some(&activity(now - 30 * day, None)), now));
        assert!(!sibling_inactive(
            Some(&activity(now - 60 * day, Some(now - 29 * day))),
            now
        ));
        assert!(sibling_inactive(
            Some(&activity(now - 60 * day, Some(now - 30 * day))),
            now
        ));
        // A device found in the roster after its last heartbeat gets thirty
        // days from then.
        assert!(!sibling_inactive(
            Some(&activity(now - 29 * day, Some(now - 90 * day))),
            now
        ));
    }

    #[test]
    fn a_heartbeat_is_dated_no_later_than_it_was_read() {
        assert_eq!(heartbeat_time(100, 200), 100);
        assert_eq!(heartbeat_time(300, 200), 200);
    }

    #[test]
    fn a_heartbeat_is_due_an_hour_after_the_last_or_when_the_clock_went_back() {
        assert!(heartbeat_is_recent(1_000, 1_000));
        assert!(heartbeat_is_recent(
            1_000,
            1_000 + HEARTBEAT_INTERVAL_SECS - 1
        ));
        assert!(!heartbeat_is_recent(1_000, 1_000 + HEARTBEAT_INTERVAL_SECS));
        assert!(!heartbeat_is_recent(1_000, 999));
    }
}
