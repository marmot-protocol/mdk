//! Rejected KeyPackages (mdk#2628 item 3.7b, D52, D59).
//!
//! A rejected KeyPackage records a KeyPackage of this account that someone
//! holding the account key published where the account's devices did not,
//! with the slot it appeared in and its LeafNode's signature key. This device
//! rejects one itself in two places, each decided while it holds the
//! KeyPackage (`sign_ins.rs` finds both):
//!
//! - **Its own slot.** A publication there that this device did not make is
//!   replaced (3.4). When it holds a valid KeyPackage of the account, this
//!   device also rejects it.
//! - **A rejected sign-in's slot** (D59). A complete check rejects each valid
//!   KeyPackage it found as the current publication of a slot rejected as
//!   `not_me`, in the roster or here, unless the same check also found it as
//!   the current publication of a slot that is not. An incomplete check
//!   rejects nothing: it may have missed the slot a copy came from.
//!
//! Whatever the place:
//!
//! - **Never.** A KeyPackage this device made (it keeps their refs until
//!   they expire), one the roster already rejects, one any roster of the
//!   trusted device group announced for any device, or one whose LeafNode
//!   carries a device tag that reads as a device's. Whoever holds the account key can copy a real
//!   device's KeyPackage into any slot, this device's included, and with no
//!   device group nothing else marks this device's own as its.
//! - **Keeping.** A rejection is kept here, across restarts, until it lapses:
//!   30 days after this device recorded it, by its own clock, or once it is
//!   not among the eight newest for its slot of the roster's records and this
//!   device's together. One that a roster since announced is dropped too.
//!   While kept, it is committed whenever the trusted roster lacks it: each
//!   pass compares the kept ones with that roster and commits every one it
//!   lacks through the runtime's `reject_key_packages`. Nothing records that
//!   the roster took one, so one a branch drops is committed anew, whichever
//!   device recorded it, and a restart loses nothing.
//! - **No device group.** The rejection is kept here. The founding roster of
//!   a device group this device creates carries the eight newest for each
//!   slot; one it joins gets them once this device trusts it.
//! - **The warning.** Each kept rejection joins the compromise warning (3.7a).
//!
//! Everything here runs only while device groups are on.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DEVICE_ROSTER_REJECTED_KEY_PACKAGES_PER_SLOT, DeviceRosterV1,
    DeviceTagClaim, RejectedKeyPackageV1, newest_rejected_key_packages,
};
use marmot_session::REJECTED_KEY_PACKAGE_RETENTION_SECS;
use nostr_directory::CurrentKeyPackage;
use storage_sqlite::KeptKeyPackageRejection;

use super::AppClient;
use super::sign_ins::roster_slot;
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::key_package_rejections";

/// What a device reads to decide whether it may reject a KeyPackage: its
/// trusted device group's roster, if it has one, every `KeyPackageRef` a
/// roster of that group announced, for any device, and the `KeyPackageRef`
/// of each KeyPackage this device made that may still be valid.
#[derive(Default)]
pub(crate) struct RejectionGuard {
    pub(crate) roster: Option<DeviceRosterV1>,
    pub(crate) announced: BTreeSet<Vec<u8>>,
    pub(crate) own: BTreeSet<Vec<u8>>,
}

impl RejectionGuard {
    /// Whether this device may reject `found`: it did not make it, the
    /// roster does not already reject it, no roster announced it, and its
    /// LeafNode carries no device tag that reads as a device's. A tag that
    /// cannot be read is no proof either way, so a KeyPackage whose tag read
    /// fails is not rejected.
    fn may_reject(&self, key_package_ref: &[u8], found: &CurrentKeyPackage) -> bool {
        if self.own.contains(key_package_ref) || self.announced.contains(key_package_ref) {
            return false;
        }
        let Some(roster) = &self.roster else {
            return true;
        };
        if roster.rejected_key_packages.contains_key(key_package_ref)
            || roster
                .devices
                .values()
                .any(|device| device.announced_key_package.as_deref() == Some(key_package_ref))
        {
            return false;
        }
        matches!(
            marmot_session::key_package_device_tag_claim(&found.fetched.key_package, roster),
            Ok(DeviceTagClaim::Unclaimed | DeviceTagClaim::RejectedSlot(_))
        )
    }
}

impl AppClient {
    /// Reject `found`, a valid KeyPackage of this account that this device
    /// holds, in the slot that served it, unless `guard` forbids it. Keeps
    /// the rejection and raises the warning. Returns whether it is newly
    /// kept.
    pub(crate) fn reject_found_key_package(
        &mut self,
        found: &CurrentKeyPackage,
        guard: &RejectionGuard,
    ) -> Result<bool, AppError> {
        let Ok(key_package_ref) = hex::decode(&found.fetched.key_package_ref_hex) else {
            return Ok(false);
        };
        if !guard.may_reject(&key_package_ref, found) {
            return Ok(false);
        }
        let kept = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .keep_rejected_key_package(&KeptKeyPackageRejection {
                key_package_ref_hex: hex::encode(&key_package_ref),
                slot_id_hex: found.fetched.key_package_id.clone(),
                leaf_signature_key: found.leaf_signature_key.clone(),
                rejected_at: unix_now_seconds(),
            })?;
        if kept {
            tracing::info!(
                target: TRACE_TARGET,
                method = "reject_found_key_package",
                "rejected a key package of this account that no device published"
            );
            self.note_compromise_warning_due();
        }
        Ok(kept)
    }

    /// Drop every kept rejection that lapsed, then commit, in one roster
    /// update, every one the trusted device group's roster lacks, once that
    /// group can take a commit from this device. One whose slot the roster
    /// cannot name stays here only.
    pub(crate) async fn commit_key_package_rejections(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let kept = storage.kept_rejected_key_packages()?;
        if kept.is_empty() {
            return Ok(());
        }
        let trusted = self.trusted_device_roster()?;
        let announced: BTreeSet<Vec<u8>> = match &trusted {
            Some((group_id, _)) => self
                .announced_key_packages(group_id)?
                .into_iter()
                .map(|announced| announced.key_package_ref)
                .collect(),
            None => BTreeSet::new(),
        };
        let lapsed = lapsed_rejections(
            &kept,
            trusted.as_ref().map(|(_, roster)| roster),
            &announced,
            unix_now_seconds(),
        );
        if !lapsed.is_empty() {
            storage.forget_rejected_key_packages(&lapsed)?;
            self.note_compromise_warning_due();
        }
        let Some((group_id, roster)) = trusted else {
            return Ok(());
        };
        let rejections: Vec<_> = kept
            .iter()
            .filter(|kept| !lapsed.contains(&kept.key_package_ref_hex))
            .filter_map(roster_record)
            .filter(|(key_package_ref, _)| {
                !roster.rejected_key_packages.contains_key(key_package_ref)
            })
            .collect();
        if rejections.is_empty() {
            return Ok(());
        }
        let held = self.epoch_gap_held_groups()?;
        let context = Self::local_human_action_context(
            "reject_key_package",
            vec!["app_component"],
            vec![DEVICE_ROSTER_COMPONENT_ID],
            None,
        );
        let effects = self
            .runtime
            .reject_key_packages(&group_id, &held, rejections, context)
            .await?;
        self.observe_drained_session_events(&effects).await?;
        Ok(())
    }

    /// Rejections this device kept while it had no device group, for the
    /// founding roster of the one it creates: the eight newest for each
    /// slot of those that have not lapsed, other than any KeyPackage
    /// `roster` or `also_announced` announces. The commit that settles them
    /// reads that roster.
    pub(crate) fn founding_key_package_rejections(
        &self,
        roster: &mut DeviceRosterV1,
        also_announced: &[Vec<u8>],
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(());
        }
        let now = unix_now_seconds();
        let records: Vec<_> = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .kept_rejected_key_packages()?
            .iter()
            .filter(|kept| !expired(kept, now))
            .filter_map(roster_record)
            .filter(|(key_package_ref, _)| {
                !also_announced.contains(key_package_ref)
                    && !roster.devices.values().any(|device| {
                        device.announced_key_package.as_ref() == Some(key_package_ref)
                    })
            })
            .collect();
        let newest = newest_rejected_key_packages(
            records
                .iter()
                .map(|(key_package_ref, record)| (key_package_ref.as_slice(), record)),
        );
        for (key_package_ref, record) in records {
            if newest.contains(&key_package_ref) {
                roster.rejected_key_packages.insert(key_package_ref, record);
            }
        }
        Ok(())
    }
}

/// `kept` as the roster records it, or `None` when the roster cannot name
/// its KeyPackage or slot.
fn roster_record(kept: &KeptKeyPackageRejection) -> Option<(Vec<u8>, RejectedKeyPackageV1)> {
    let key_package_ref = hex::decode(&kept.key_package_ref_hex).ok()?;
    let record = RejectedKeyPackageV1 {
        slot: roster_slot(&kept.slot_id_hex)?,
        leaf_signature_key: kept.leaf_signature_key.clone(),
        rejected_at: kept.rejected_at,
    };
    (!key_package_ref.is_empty()).then_some((key_package_ref, record))
}

/// Whether 30 days have passed since this device recorded `kept`.
fn expired(kept: &KeptKeyPackageRejection, now: u64) -> bool {
    kept.rejected_at
        .checked_add(REJECTED_KEY_PACKAGE_RETENTION_SECS)
        .is_some_and(|expires_at| expires_at <= now)
}

/// The kept rejections that lapsed: 30 days old, announced by a roster
/// since, or not among the eight newest for their slot of `roster`'s and
/// the kept ones together, each counted once. One the roster cannot record,
/// as when its slot is not a roster slot, counts among the eight newest of
/// the kept ones with that same stored slot.
fn lapsed_rejections(
    kept: &[KeptKeyPackageRejection],
    roster: Option<&DeviceRosterV1>,
    announced: &BTreeSet<Vec<u8>>,
    now: u64,
) -> Vec<String> {
    let records: Vec<_> = kept
        .iter()
        .filter(|kept| !expired(kept, now))
        .filter_map(roster_record)
        .collect();
    let newest = newest_rejected_key_packages(
        roster
            .into_iter()
            .flat_map(|roster| roster.rejected_key_packages.iter())
            .map(|(key_package_ref, record)| (key_package_ref.as_slice(), record))
            .chain(
                records
                    .iter()
                    .map(|(key_package_ref, record)| (key_package_ref.as_slice(), record)),
            ),
    );
    let mut unrecorded = BTreeMap::<&str, Vec<(u64, &str)>>::new();
    for kept in kept
        .iter()
        .filter(|kept| !expired(kept, now) && roster_record(kept).is_none())
    {
        unrecorded
            .entry(kept.slot_id_hex.as_str())
            .or_default()
            .push((kept.rejected_at, kept.key_package_ref_hex.as_str()));
    }
    let newest_unrecorded: BTreeSet<&str> = unrecorded
        .into_values()
        .flat_map(|mut records| {
            records.sort_unstable_by(|a, b| b.cmp(a));
            records
                .into_iter()
                .take(DEVICE_ROSTER_REJECTED_KEY_PACKAGES_PER_SLOT)
                .map(|(_, key_package_ref_hex)| key_package_ref_hex)
        })
        .collect();
    kept.iter()
        .filter(|kept| {
            expired(kept, now)
                || match roster_record(kept) {
                    Some((key_package_ref, _)) => {
                        announced.contains(&key_package_ref) || !newest.contains(&key_package_ref)
                    }
                    None => !newest_unrecorded.contains(kept.key_package_ref_hex.as_str()),
                }
        })
        .map(|kept| kept.key_package_ref_hex.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(byte: u8, rejected_at: u64) -> KeptKeyPackageRejection {
        KeptKeyPackageRejection {
            key_package_ref_hex: hex::encode([byte; 32]),
            slot_id_hex: hex::encode([0x11; 32]),
            leaf_signature_key: vec![7; 32],
            rejected_at,
        }
    }

    /// A kept rejection lapses 30 days after it was recorded, once a roster
    /// announced it, or once eight newer ones for its slot are in the roster
    /// and here together.
    #[test]
    fn a_kept_rejection_lapses() {
        let now = 100 * 24 * 60 * 60;
        let old = kept(1, now - REJECTED_KEY_PACKAGE_RETENTION_SECS);
        let young = kept(2, now - 1);
        assert_eq!(
            lapsed_rejections(&[old.clone(), young.clone()], None, &BTreeSet::new(), now),
            vec![old.key_package_ref_hex.clone()]
        );
        assert_eq!(
            lapsed_rejections(
                std::slice::from_ref(&young),
                None,
                &[vec![2; 32]].into_iter().collect(),
                now
            ),
            vec![young.key_package_ref_hex.clone()]
        );

        let mut roster = DeviceRosterV1::default();
        for n in 10..18u8 {
            roster.rejected_key_packages.insert(
                vec![n; 32],
                RejectedKeyPackageV1 {
                    slot: [0x11; 32],
                    leaf_signature_key: vec![7; 32],
                    rejected_at: now,
                },
            );
        }
        assert_eq!(
            lapsed_rejections(
                std::slice::from_ref(&young),
                Some(&roster),
                &BTreeSet::new(),
                now
            ),
            vec![young.key_package_ref_hex.clone()]
        );
        // One the roster already holds counts once, so it stays.
        let held = kept(10, now);
        assert!(lapsed_rejections(&[held], Some(&roster), &BTreeSet::new(), now).is_empty());
    }

    /// Rejections in a slot the roster cannot name never reach the roster,
    /// so the eight newest of those kept for the same stored slot stay and
    /// the rest lapse.
    #[test]
    fn rejections_in_a_slot_the_roster_cannot_name_keep_the_eight_newest() {
        let now = 100 * 24 * 60 * 60;
        let in_slot = |byte: u8, slot: &str| KeptKeyPackageRejection {
            slot_id_hex: slot.to_owned(),
            ..kept(byte, now - u64::from(byte))
        };
        let mut kept: Vec<_> = (1..=9u8).map(|byte| in_slot(byte, "not-a-slot")).collect();
        kept.push(in_slot(20, "another-slot"));
        assert_eq!(
            lapsed_rejections(&kept, None, &BTreeSet::new(), now),
            vec![hex::encode([9; 32])]
        );
    }
}
