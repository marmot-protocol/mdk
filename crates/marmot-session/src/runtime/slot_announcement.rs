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

use cgka_traits::{GroupId, TransportAdapter};

use super::device_roster::{DeviceRosterEdit, DeviceRosterEditBlocked};
use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::{AccountError, AccountResult};
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

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

    /// Whether `key_package_ref` may reach this device's slot: no device
    /// group is set, or this device's roster entry there names it.
    pub(super) fn key_package_announced(&mut self, key_package_ref: &[u8]) -> AccountResult<bool> {
        let Some(group_id) = self.key_package_announcement_group.clone() else {
            return Ok(true);
        };
        let Some(slot) = self.own_device_slot()? else {
            return Ok(false);
        };
        // Every failure to read the roster holds publication back.
        Ok(self
            .merged_device_roster(&group_id)
            .and_then(|mut roster| roster.devices.remove(&slot))
            .is_some_and(|entry| entry.announced_key_package.as_deref() == Some(key_package_ref)))
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
    /// its current one, along with what this device says about itself
    /// ([`Self::set_device_self_report`]) and its history key (4.1). The
    /// returned effects carry the roster commit.
    ///
    /// Does nothing when no device group is set, the entry already reads so,
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
        let Some(slot) = self.own_device_slot()? else {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "announce_key_package",
                reason = "slot_unavailable",
                "cannot announce this device's key package yet; its publication waits"
            );
            return Ok(AccountDeviceEffects::default());
        };
        let report = self.device_self_report.clone();
        let history_key = self.own_history_key("announce_key_package");
        match self
            .edit_device_roster_entry(&group_id, &slot, held, |entry| {
                entry.announced_key_package = Some(key_package_ref);
                report.apply(entry);
                if let Some(history_key) = history_key {
                    entry.history_key = Some(history_key);
                }
            })
            .await?
        {
            DeviceRosterEdit::Committed(effects) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "announce_key_package",
                    "announced this device's key package and self-report in its device group"
                );
                Ok(*effects)
            }
            DeviceRosterEdit::Unchanged
            | DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Busy) => {
                Ok(AccountDeviceEffects::default())
            }
            DeviceRosterEdit::Blocked(blocked) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    method = "announce_key_package",
                    reason = blocked.reason(),
                    "cannot announce this device's key package yet; its publication waits"
                );
                Ok(AccountDeviceEffects::default())
            }
        }
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

    /// Whether this device's KeyPackage refresh is overdue because its
    /// announcement is held back, so the host can warn the user (D31 choice
    /// 6). That is: a device group is set and the slot isn't withdrawn, the
    /// KeyPackage this device would publish (the pending replacement, else the
    /// current one) is not announced, or none may be staged while this
    /// device's tag signature key is unsettled (mdk#2628 3.1d), and this
    /// device's newest publication in the slot is older than the weekly
    /// refresh bound, or there is none. A
    /// publication is then always owed, so retry backoff at the relays never
    /// hides it. A routine refresh announces and publishes in one maintenance
    /// pass, so it never shows. One that is announced but failing at the
    /// relays is not held back by the announcement, so it does not count.
    pub fn key_package_refresh_overdue(&mut self) -> AccountResult<bool> {
        if self.key_package_announcement_group.is_none() || self.key_package_slot_withdrawn {
            return Ok(false);
        }
        let Some(lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(false);
        };
        let Some(key_package_ref) = lifecycle
            .pending_replacement
            .as_ref()
            .map(|pending| pending.key_package_ref.clone())
            .or_else(|| lifecycle.current_key_package_ref.clone())
        else {
            return Ok(false);
        };
        if self.key_package_announced(&key_package_ref)? && self.device_tag_key_settled()? {
            return Ok(false);
        }
        let now = self.wall_clock.now();
        Ok(lifecycle.authored_event_created_at.is_none_or(|published| {
            published
                .0
                .saturating_add(super::KEY_PACKAGE_REFRESH_MAX_SECS)
                <= now.0
        }))
    }
}
