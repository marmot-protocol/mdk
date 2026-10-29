//! Slot announcements (mdk#2628 item 3.4).
//!
//! While this device trusts a device group, every KeyPackage it puts in its
//! publication slot is first named in its own roster entry there
//! (`announced_key_package`). A sibling that finds a new KeyPackage in a known
//! slot then tells a refresh, which the roster names, from a replacement by
//! someone else holding the account key, which it does not.
//!
//! The host names the device group; this runtime announces and publishes. The
//! gate reads the roster each time a KeyPackage would go out, never a copy, so
//! an announcement that convergence dropped holds publication back until it
//! is made again. With no device group, publication runs as before.

use cgka_traits::app_components::{
    AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1,
    DeviceRosterUpdateV1, DeviceSlotId, decode_device_roster_v1, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::{FanoutMlsState, GroupId, Timestamp, TransportAdapter};

use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::{AccountError, AccountResult};
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

/// Where this device's roster entry stands for one KeyPackage.
enum Announcement {
    /// The entry names it, or no device group is set.
    Announced,
    /// The entry names another KeyPackage, or none.
    Due {
        slot: DeviceSlotId,
        entry: DeviceEntryV1,
    },
    /// It cannot be announced now: the device group is unreadable, or holds
    /// no entry for this device's slot.
    Blocked(&'static str),
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Name the device group this device announces its KeyPackages in, or
    /// `None` when it trusts none. The host sets it whenever that changes.
    /// While one is set, no KeyPackage of this device reaches its slot until
    /// this device's roster entry there names it.
    pub fn set_key_package_announcement_group(&mut self, group_id: Option<GroupId>) {
        self.key_package_announcement_group = group_id;
    }

    /// The device group this device announces its KeyPackages in.
    pub fn key_package_announcement_group(&self) -> Option<&GroupId> {
        self.key_package_announcement_group.as_ref()
    }

    /// Note that this device's slot holds a publication it did not make, at
    /// `created_at`. The next KeyPackage it publishes there is newer, so it
    /// replaces that one, and maintenance publishes it as soon as it can.
    pub fn supersede_foreign_slot_publication(&mut self, created_at: Timestamp) {
        tracing::warn!(
            target: TRACE_TARGET,
            method = "supersede_foreign_slot_publication",
            "this device's key package slot holds a publication it did not make; replacing it"
        );
        self.foreign_slot_publication_at = Some(
            self.foreign_slot_publication_at
                .map_or(created_at, |earlier| earlier.max(created_at)),
        );
    }

    /// Whether a publication this device makes at `created_at` still leaves
    /// a foreign publication newer than its own in the slot.
    pub(super) fn foreign_slot_publication_outranks(&self, created_at: Timestamp) -> bool {
        self.foreign_slot_publication_at
            .is_some_and(|foreign| created_at <= foreign)
    }

    /// A publication at `created_at` reached a relay: once it is newer than
    /// the foreign one, that one no longer needs replacing.
    pub(super) fn note_slot_publication(&mut self, created_at: Timestamp) {
        if !self.foreign_slot_publication_outranks(created_at) {
            self.foreign_slot_publication_at = None;
        }
    }

    /// Whether `key_package_ref` may reach this device's slot: no device
    /// group is set, or this device's roster entry there names it.
    pub(super) fn key_package_announced(&mut self, key_package_ref: &[u8]) -> AccountResult<bool> {
        Ok(matches!(
            self.key_package_announcement(key_package_ref)?,
            Announcement::Announced
        ))
    }

    /// Refuse to publish `key_package_ref` until it is announced.
    pub(super) fn ensure_key_package_announced(
        &mut self,
        key_package_ref: &[u8],
    ) -> AccountResult<()> {
        if self.key_package_announced(key_package_ref)? {
            Ok(())
        } else {
            Err(AccountError::KeyPackageAnnouncementPending)
        }
    }

    /// Maintenance's first KeyPackage step while a device group is set: stage
    /// a due replacement, so there is a reference to announce, then announce
    /// it. The publication steps after this one find it announced once the
    /// roster commit is confirmed. Paused maintenance makes no new commit, so
    /// the announcement waits for resume; so does the publication.
    pub(super) async fn announce_key_package_for_maintenance(
        &mut self,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        if self.key_package_announcement_group.is_none()
            || self.key_package_slot_withdrawn
            || self.maintenance_paused
        {
            return Ok(AccountDeviceEffects::default());
        }
        if self.key_package_network_maintenance_due()? {
            let endpoints = self.routing.key_package_endpoints().to_vec();
            if let Err(error) = self.prepare_key_package_replacement(endpoints, false).await {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "announce_key_package",
                    error_kind = if matches!(error, AccountError::ClockSkewBlocked) {
                        "clock_skew_blocked"
                    } else {
                        "key_package_prepare"
                    },
                    "could not stage the key package to announce; maintenance retries"
                );
                return Ok(AccountDeviceEffects::default());
            }
        }
        match self.announce_key_package_holding(held).await {
            Ok(effects) => Ok(effects),
            Err(_) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "announce_key_package",
                    error_kind = "roster_update",
                    "could not announce this device's key package; maintenance retries"
                );
                Ok(AccountDeviceEffects::default())
            }
        }
    }

    /// Announce, in this device's roster entry, the KeyPackage this device is
    /// about to publish, or has published: its pending replacement, otherwise
    /// its current one. The returned effects carry the roster commit.
    ///
    /// Does nothing when no device group is set, the entry already names it,
    /// or the device group cannot take a commit from this device now: it is
    /// in `held`, quarantined, or settling, or an earlier change of this
    /// device's there is still queued or unconfirmed. A later call retries.
    pub async fn announce_key_package_holding(
        &mut self,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        let Some(group_id) = self.key_package_announcement_group.clone() else {
            return Ok(AccountDeviceEffects::default());
        };
        let Some(lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(AccountDeviceEffects::default());
        };
        let Some(key_package_ref) = lifecycle
            .pending_replacement
            .as_ref()
            .map(|pending| pending.key_package_ref.clone())
            .or(lifecycle.current_key_package_ref)
        else {
            return Ok(AccountDeviceEffects::default());
        };
        let (slot, mut entry) = match self.key_package_announcement(&key_package_ref)? {
            Announcement::Announced => return Ok(AccountDeviceEffects::default()),
            Announcement::Due { slot, entry } => (slot, entry),
            Announcement::Blocked(reason) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "announce_key_package",
                    reason,
                    "cannot announce this device's key package yet; its publication waits"
                );
                return Ok(AccountDeviceEffects::default());
            }
        };
        if held.contains(&group_id)
            || self
                .session
                .quarantined_groups()
                .iter()
                .any(|(quarantined, _)| quarantined == &group_id)
            || self.session.has_pending_convergence_inputs(&group_id)?
            || self.session.has_queued_outbound_intents(&group_id)?
            || self
                .session
                .outbound_fanouts_for_group(&group_id)?
                .iter()
                .any(|fanout| matches!(fanout.mls_state(), FanoutMlsState::Pending(_)))
        {
            return Ok(AccountDeviceEffects::default());
        }
        // The commit replaces the entry whole: every other field stays as
        // the roster holds it.
        entry.announced_key_package = Some(key_package_ref);
        let update =
            DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(slot, entry)])
                .and_then(|update| encode_device_roster_update_v1(&update))
                .map_err(|error| {
                    AccountError::Engine(cgka_traits::EngineError::Serialize(error))
                })?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "announce_key_package",
            "announcing this device's key package in its device group"
        );
        self.send(SendIntent::UpdateAppComponents {
            group_id,
            updates: vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        })
        .await
    }

    /// Whether [`Self::republish_key_package`] would publish a fresh
    /// KeyPackage rather than the current one, so the host announces that
    /// one instead ([`Self::announce_fresh_key_package_holding`]).
    pub fn key_package_republish_falls_back(&mut self) -> AccountResult<bool> {
        let Some(lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(true);
        };
        Ok(lifecycle.pending_replacement.is_none()
            && !lifecycle.stable_slot_id.is_empty()
            && (lifecycle.authored_signed_event.is_none()
                || lifecycle.current_key_package.is_none()
                || self
                    .current_key_package_republish_fallback(&lifecycle)
                    .is_some()))
    }

    /// [`Self::announce_key_package_holding`] for the KeyPackage the next
    /// [`Self::publish_fresh_key_package`] sends: stage it first, unless a
    /// usable replacement is already staged, so the announcement names it.
    pub async fn announce_fresh_key_package_holding(
        &mut self,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        if self.key_package_announcement_group.is_none() {
            return Ok(AccountDeviceEffects::default());
        }
        let endpoints = self.routing.key_package_endpoints().to_vec();
        self.prepare_key_package_replacement(endpoints, false)
            .await?;
        self.announce_key_package_holding(held).await
    }

    fn key_package_announcement(&mut self, key_package_ref: &[u8]) -> AccountResult<Announcement> {
        let Some(group_id) = self.key_package_announcement_group.clone() else {
            return Ok(Announcement::Announced);
        };
        let Some(slot) = self
            .session
            .key_package_lifecycle()?
            .and_then(|lifecycle| hex::decode(lifecycle.stable_slot_id).ok())
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
        else {
            return Ok(Announcement::Blocked("slot_unavailable"));
        };
        // Every failure to read the roster holds publication back.
        let roster = self
            .session
            .ensure_group_hydrated(&group_id)
            .ok()
            .and_then(|_| {
                self.session
                    .app_component(&group_id, DEVICE_ROSTER_COMPONENT_ID)
                    .ok()
            })
            .flatten()
            .and_then(|bytes| decode_device_roster_v1(&bytes).ok());
        let Some(mut roster) = roster else {
            return Ok(Announcement::Blocked("device_group_unreadable"));
        };
        Ok(match roster.devices.remove(&slot) {
            None => Announcement::Blocked("no_roster_entry"),
            Some(entry) if entry.announced_key_package.as_deref() == Some(key_package_ref) => {
                Announcement::Announced
            }
            Some(entry) => Announcement::Due { slot, entry },
        })
    }
}
