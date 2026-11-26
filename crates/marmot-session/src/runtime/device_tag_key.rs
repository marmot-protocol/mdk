//! This device's tag signature key (mdk#2628 item 3.1d).
//!
//! A device's entry in its device group's roster carries its tag signature
//! key, its MLS signature key, from the Commit that added it (marmot#521;
//! device-tag-v1.md, "Producing tags"). The founder writes its own key into
//! the founding roster. A device that joined makes its first own Commit there
//! once it has joined: a roster update writing its history key (4.1), or a
//! self-update when the entry needs no change, whose UpdatePath the engine
//! tags. That Commit shows its link made, and the device tags its KeyPackages
//! and its leaves elsewhere only from then on. Maintenance and every host
//! KeyPackage publication make that Commit first, through the roster write
//! path ([`AccountDeviceRuntime::edit_device_roster_entry`]); the host names
//! the group. No Commit changes an entry's key ("Key binding"), so a device
//! whose entry carries no key or another key never tags from that roster.
//!
//! No KeyPackage is staged while that Commit is due: it would be built
//! untagged and published after the device started tagging.

use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::{GroupId, SendIntent, TransportAdapter};

use super::device_roster::{DeviceRosterEdit, DeviceRosterEditBlocked};
use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::AccountResult;
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

/// Where this device's roster entry stands for its tag signature key.
enum TagKey {
    /// The entry carries it and the device's leaf shows its link made, or no
    /// device group is named.
    Set,
    /// The entry of this device's slot lacks the key, or its leaf does not
    /// show its link made yet: its first own Commit is due.
    Due(DeviceSlotId),
    /// It cannot be set: the device group is unreadable, holds no entry for
    /// this device's slot, or that entry carries no key or another key,
    /// which no Commit can change. The engine tags only from this device's
    /// own entry, so a KeyPackage staged meanwhile is untagged.
    Blocked(&'static str),
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Tag this device's KeyPackages and leaves from `group_id`'s roster, or
    /// stop with `None`. The host names the device group it trusts and sets
    /// it again after every open. An error says the group is not live; it
    /// stays named. See [`cgka_engine::engine::Engine::set_device_tag_group`].
    pub fn set_device_tag_group(&mut self, group_id: Option<GroupId>) -> AccountResult<()> {
        self.device_tag_group = group_id.clone();
        Ok(self.session.set_device_tag_group(group_id)?)
    }

    /// The device group this device tags from, as the host last named it.
    pub fn device_tag_group(&self) -> Option<&GroupId> {
        self.device_tag_group.as_ref()
    }

    /// Whether a KeyPackage staged now is built as this device should
    /// build it: no device group is named, the slot is withdrawn, the merged
    /// roster carries this device's tag signature key in its own entry, or
    /// the device cannot tag from that roster at all. False while the key is
    /// due, whether or not an update setting it is on its way.
    pub(super) fn device_tag_key_settled(&mut self) -> AccountResult<bool> {
        let Some(group_id) = self.device_tag_group.clone() else {
            return Ok(true);
        };
        if self.key_package_slot_withdrawn {
            return Ok(true);
        }
        Ok(!matches!(self.device_tag_key(&group_id)?, TagKey::Due(_)))
    }

    /// Maintenance's step before it stages or announces a KeyPackage:
    /// [`Self::set_device_tag_key_holding`], except while maintenance is
    /// paused. A failure is logged and retried on the next pass.
    pub(super) async fn set_device_tag_key_for_maintenance(
        &mut self,
        held: &[GroupId],
    ) -> AccountDeviceEffects {
        if self.maintenance_paused {
            return AccountDeviceEffects::default();
        }
        self.set_device_tag_key_holding(held)
            .await
            .unwrap_or_else(|_| {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "set_device_tag_key",
                    error_kind = "roster_update",
                    "could not set this device's tag signature key; maintenance retries"
                );
                AccountDeviceEffects::default()
            })
    }

    /// Make this device's first own Commit in its device group when it is
    /// due. The returned
    /// effects carry the commit. The host calls this before it publishes a
    /// KeyPackage, which is refused until that Commit has made this device's
    /// link (`made_device_links` lists its slot).
    ///
    /// Does nothing when no device group is named, the slot is withdrawn, the
    /// link is already made, or neither the roster write path nor its
    /// self-update fallback sends anything:
    /// the device group cannot take a commit from this device now (it is in
    /// `held`, quarantined, or settling, or an earlier change of this
    /// device's there is still queued or unconfirmed), or the entry changed
    /// under the send. A later call retries.
    pub async fn set_device_tag_key_holding(
        &mut self,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        let Some(group_id) = self.device_tag_group.clone() else {
            return Ok(AccountDeviceEffects::default());
        };
        self.set_device_tag_key_in_group_holding(&group_id, held)
            .await
    }

    /// Set this device's own roster key in an explicit link destination,
    /// without naming it as the trusted tag group. A move uses this for its
    /// first own Commit before Made; ordinary tags still use the named group.
    /// All readiness, current-entry and withdrawn-slot checks are unchanged.
    pub async fn set_device_tag_key_in_group_holding(
        &mut self,
        group_id: &GroupId,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        if self.key_package_slot_withdrawn {
            return Ok(AccountDeviceEffects::default());
        }
        let slot = match self.device_tag_key(group_id)? {
            TagKey::Set => return Ok(AccountDeviceEffects::default()),
            TagKey::Due(slot) => slot,
            TagKey::Blocked(reason) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "set_device_tag_key",
                    reason,
                    "cannot set this device's tag signature key yet"
                );
                return Ok(AccountDeviceEffects::default());
            }
        };
        // The commit carries this device's history key (4.1), when it can be
        // read; the first Commit never waits for it.
        let history_key = self.own_history_key("set_device_tag_key");
        match self
            .edit_device_roster_entry(group_id, &slot, held, |entry| {
                if let Some(history_key) = history_key {
                    entry.history_key = Some(history_key);
                }
            })
            .await?
        {
            DeviceRosterEdit::Committed(effects) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "set_device_tag_key",
                    "set this device's tag signature key in its device group"
                );
                Ok(*effects)
            }
            // The entry already says everything this Commit would write, so
            // a self-update makes it: its UpdatePath carries the first tag.
            DeviceRosterEdit::Unchanged => {
                if !self.device_group_takes_commit(group_id, held)? {
                    return Ok(AccountDeviceEffects::default());
                }
                self.send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
            }
            DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Busy) => {
                Ok(AccountDeviceEffects::default())
            }
            DeviceRosterEdit::Blocked(blocked) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "set_device_tag_key",
                    reason = blocked.reason(),
                    "cannot set this device's tag signature key yet"
                );
                Ok(AccountDeviceEffects::default())
            }
        }
    }

    fn device_tag_key(&mut self, group_id: &GroupId) -> AccountResult<TagKey> {
        let Some(slot) = self.own_device_slot()? else {
            return Ok(TagKey::Blocked("slot_unavailable"));
        };
        let Some(roster) = self.merged_device_roster(group_id) else {
            return Ok(TagKey::Blocked("device_group_unreadable"));
        };
        let own_key = self.session.own_signature_key();
        let Some(entry) = roster.devices.get(&slot) else {
            return Ok(TagKey::Blocked("no_roster_entry"));
        };
        if entry.tag_signature_key.as_deref() != Some(own_key.as_slice()) {
            return Ok(TagKey::Blocked("entry_key_not_own"));
        }
        let Ok(made) = self.session.made_device_links(group_id, &roster) else {
            return Ok(TagKey::Blocked("device_group_unreadable"));
        };
        Ok(if made.contains(&slot) {
            TagKey::Set
        } else {
            TagKey::Due(slot)
        })
    }
}
