//! The own-slot check's runtime half (mdk#2628 item 3.4,
//! `foundation/key-packages.md`, "A publication the device did not make").
//!
//! Anyone holding the account key can publish into this device's slot. The
//! host reads the slot from every relay and hands over each current
//! publication there that this device did not make. Relays keep the newest
//! publication in a slot, so this device replaces such a publication with a
//! newer KeyPackage of its own, announced first like any other.
//!
//! - **One rule.** [`AccountDeviceRuntime::slot_publication_superseded`] is
//!   the only test of whether a publication of this device's own is still
//!   current in the slot: one at or before the slot's withdrawal, or at or
//!   before the newest foreign publication found (and the current
//!   publication at that time, which some relay no longer serves). Every
//!   step that stages, publishes, resends or republishes asks it.
//! - **Out of reach.** A foreign publication whose time is past what this
//!   device would sign cannot be outranked. It never feeds the rule, so it
//!   never holds back this device's refreshes. This device asks the relays
//!   to delete that event by id (D63). A relay that accepts is left with an
//!   empty slot, so the refresh that refills it is made due, durably, before
//!   the request goes out, and put back if no relay accepts.
//! - Otherwise the finding lives in memory only: the host reads the slot
//!   again at open, and finds any foreign publication still there.
//! - **Known gap.** A deletion a relay honored but never acknowledged, or
//!   one made while a replacement is already on its way, can leave that
//!   relay's slot empty until the weekly refresh: the rollback assumes no
//!   acknowledgement means nothing was deleted, and promoting the in-flight
//!   replacement reschedules the refresh. Reading the slot cannot show the
//!   gap, since an empty slot holds no foreign publication. The slot
//!   withdrawal's rollback has the same gap. A read that refills a relay
//!   that accepted this device's latest publication but serves nothing is
//!   mdk#2628's follow-up under 3.4.

use cgka_traits::{MessageId, Timestamp, TransportAdapter};

use super::{AccountDeviceRuntime, KEY_PACKAGE_MAX_FUTURE_SKEW_SECS, TRACE_TARGET};
use crate::error::AccountResult;
use crate::key_package::{KeyPackageEventDeletion, KeyPackagePublisher};
use crate::routing::TransportRoutingPolicy;
use cgka_traits::KeyPackageLifecycleState;

/// A current publication in this device's slot that this device did not
/// make, as the host's read of the slot found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignSlotPublication {
    pub event_id: MessageId,
    pub created_at: Timestamp,
}

/// What [`AccountDeviceRuntime::replace_foreign_slot_publications`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForeignSlotOutcome {
    /// This device's current publication is to be replaced by a newer one.
    pub replacing: bool,
    /// Publications too far in the future to outrank.
    pub beyond_skew: usize,
    /// Of those, the ones whose deletion some relay accepted.
    pub deleted: usize,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Replace `foreign`, publications in this device's slot it did not make,
    /// with a newer KeyPackage of its own, which maintenance publishes. One
    /// whose time is past what this device would sign is deleted by id
    /// instead. Nothing happens while the slot is withdrawn or maintenance
    /// is paused.
    pub async fn replace_foreign_slot_publications(
        &mut self,
        foreign: &[ForeignSlotPublication],
    ) -> AccountResult<ForeignSlotOutcome> {
        let mut outcome = ForeignSlotOutcome::default();
        if foreign.is_empty() || self.key_package_slot_withdrawn || self.maintenance_paused {
            return Ok(outcome);
        }
        let latest_signable = self
            .wall_clock
            .now()
            .0
            .saturating_add(KEY_PACKAGE_MAX_FUTURE_SKEW_SECS);
        let (outrankable, beyond): (Vec<_>, Vec<_>) = foreign
            .iter()
            .partition(|publication| publication.created_at.0 < latest_signable);
        if let Some(newest) = outrankable
            .iter()
            .map(|publication| publication.created_at)
            .max()
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "replace_foreign_slot_publications",
                count = outrankable.len(),
                "this device's key package slot serves a publication it did not make; replacing it"
            );
            outcome.replacing = self.supersede_slot_publications_through(newest)?;
        }
        outcome.beyond_skew = beyond.len();
        for publication in beyond {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "replace_foreign_slot_publications",
                "this device's key package slot serves a publication it did not make, dated too far ahead to replace; deleting it"
            );
            if self.delete_slot_publication(&publication.event_id).await? {
                outcome.deleted += 1;
                outcome.replacing = true;
            }
        }
        Ok(outcome)
    }

    /// Whether this device's publication at `created_at` no longer stands in
    /// its slot: the slot's withdrawal covers it, or a foreign publication
    /// at least as new was found there.
    pub(super) fn slot_publication_superseded(
        &self,
        lifecycle: &KeyPackageLifecycleState,
        created_at: Timestamp,
    ) -> bool {
        super::withdrawn_with_slot(lifecycle, created_at)
            || self
                .slot_superseded_through
                .is_some_and(|through| created_at <= through)
    }

    /// Whether this device's current publication no longer stands in its
    /// slot, so it is replaced rather than sent again: the slot was
    /// withdrawn, or [`Self::slot_publication_superseded`] covers it.
    pub(super) fn current_publication_superseded(
        &self,
        lifecycle: &KeyPackageLifecycleState,
    ) -> bool {
        lifecycle.slot_withdrawn_at.is_some()
            || lifecycle
                .authored_event_created_at
                .is_some_and(|created_at| self.slot_publication_superseded(lifecycle, created_at))
    }

    /// The time the next publication must be later than, for the foreign
    /// publications found. One this device can no longer outrank, because
    /// its clock went back, is dropped rather than blocking every refresh.
    pub(super) fn slot_superseded_through_signable(&mut self, now: Timestamp) -> Option<Timestamp> {
        let through = self.slot_superseded_through?;
        if through.0 < now.0.saturating_add(KEY_PACKAGE_MAX_FUTURE_SKEW_SECS) {
            return Some(through);
        }
        tracing::warn!(
            target: TRACE_TARGET,
            method = "slot_superseded_through_signable",
            "a foreign key package publication is now too far ahead to outrank; no longer replacing it"
        );
        self.slot_superseded_through = None;
        None
    }

    /// A publication of this device's own at `created_at` became current:
    /// once it is newer than every foreign one found, none needs replacing.
    pub(super) fn note_slot_publication(&mut self, created_at: Timestamp) {
        if self
            .slot_superseded_through
            .is_some_and(|through| through < created_at)
        {
            self.slot_superseded_through = None;
        }
    }

    /// Supersede every publication of this device's own up to `foreign`
    /// and its current one. Returns whether there was one to supersede.
    fn supersede_slot_publications_through(&mut self, foreign: Timestamp) -> AccountResult<bool> {
        let current = self
            .session
            .key_package_lifecycle()?
            .and_then(|lifecycle| lifecycle.authored_event_created_at);
        let through = current.map_or(foreign, |current| current.max(foreign));
        self.slot_superseded_through = Some(
            self.slot_superseded_through
                .map_or(through, |earlier| earlier.max(through)),
        );
        Ok(current.is_some())
    }

    /// Ask every KeyPackage relay to delete `event_id`. Returns whether one
    /// accepted, and with it that this device's KeyPackage is to be
    /// replaced: a relay that dropped this device's publication for the
    /// deleted one serves nothing in the slot now.
    async fn delete_slot_publication(&mut self, event_id: &MessageId) -> AccountResult<bool> {
        let mut endpoints = self.routing.key_package_endpoints().to_vec();
        if let Some(lifecycle) = self.session.key_package_lifecycle()? {
            for target in &lifecycle.publication_targets {
                if !endpoints.contains(&target.endpoint) {
                    endpoints.push(target.endpoint.clone());
                }
            }
        }
        if endpoints.is_empty() {
            return Ok(false);
        }
        let now = self.wall_clock.now();
        let Some(refresh_at) = self.make_refresh_due(now)? else {
            return Ok(false);
        };
        let deletion = KeyPackageEventDeletion {
            account_id: self.session.self_id().clone(),
            event_id: event_id.clone(),
            created_at: now,
            endpoints,
        };
        let accepted = match self.key_packages.delete_key_package_event(&deletion).await {
            Ok(receipt) => receipt.accepted.len(),
            Err(error) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "delete_slot_publication",
                    error_kind = "key_package_event_deletion",
                    externally_exposed = error.externally_exposed,
                    "could not ask the relays to delete a foreign key package publication"
                );
                0
            }
        };
        tracing::info!(
            target: TRACE_TARGET,
            method = "delete_slot_publication",
            endpoint_count = deletion.endpoints.len(),
            accepted_count = accepted,
            "asked the relays to delete a foreign key package publication"
        );
        if accepted == 0 {
            // The slot holds what it held: no refill is owed.
            self.restore_refresh(now, refresh_at)?;
        }
        Ok(accepted > 0)
    }

    /// Make this device's KeyPackage refresh due at `now`, durably, so a
    /// restart still refills the slot. Returns the refresh time it replaced,
    /// or `None` when this device has no KeyPackage lifecycle.
    fn make_refresh_due(&mut self, now: Timestamp) -> AccountResult<Option<Option<Timestamp>>> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(None);
        };
        let replaced = lifecycle.refresh_at.replace(now);
        self.session.put_key_package_lifecycle(&lifecycle)?;
        Ok(Some(replaced))
    }

    /// Put back the refresh time [`Self::make_refresh_due`] replaced, unless
    /// something rescheduled the refresh since.
    fn restore_refresh(
        &mut self,
        due_at: Timestamp,
        replaced: Option<Timestamp>,
    ) -> AccountResult<()> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(());
        };
        if lifecycle.refresh_at == Some(due_at) {
            lifecycle.refresh_at = replaced;
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }
        Ok(())
    }
}
