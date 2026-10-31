//! Recording rejected KeyPackages (mdk#2628 item 3.7b).
//!
//! A rejected KeyPackage names, by its `KeyPackageRef`, a KeyPackage of the
//! account that someone holding the account key published where the
//! account's devices did not, with the slot it appeared in and its LeafNode's
//! signature key (device-group.md, "Rejections"). The host decides what to
//! reject; this runtime writes it, behind the gate its other roster updates
//! wait behind.
//!
//! - A record the merged roster already holds stays as it is.
//! - The roster holds at most eight for one slot. An update that adds records
//!   keeps, of the merged roster's records and the ones it adds, the eight
//!   newest for each slot (`newest_rejected_key_packages`), removes the
//!   roster's others in the same update and adds none of the others. Each
//!   call works this out from the roster as it reads it then, so a retry
//!   after a Commit fails or a branch is dropped works it out from the new
//!   parent.
//! - Maintenance drops a record 30 days after its `rejected_at`, by this
//!   device's clock, in the same update as expired `removed` slots
//!   (`removed_slot_expiry.rs`).

use cgka_traits::app_components::{
    DeviceRosterOperationV1, DeviceRosterV1, RejectedKeyPackageV1, newest_rejected_key_packages,
};
use cgka_traits::{GroupId, TransportAdapter};
use marmot_forensics::AuditEventContext;

use super::{AccountDeviceEffects, AccountDeviceRuntime, TRACE_TARGET};
use crate::error::AccountResult;
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;

/// How long a rejected KeyPackage stays in the roster after its
/// `rejected_at`.
pub const REJECTED_KEY_PACKAGE_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Record each of `rejections`, keyed by `KeyPackageRef`, as a rejected
    /// KeyPackage in the roster of `group_id`, in one roster update carrying
    /// `context`. The returned effects carry the commit.
    ///
    /// Leaves out every one the merged roster already rejects, and every one
    /// that is not among the eight newest for its slot together with the
    /// roster's. Sends nothing when that leaves none, the roster cannot be
    /// read, or the group cannot take a commit from this device now: it is
    /// in `held`, quarantined, or settling, or an earlier change of this
    /// device's there is still queued or unconfirmed. A later call retries.
    pub async fn reject_key_packages(
        &mut self,
        group_id: &GroupId,
        held: &[GroupId],
        rejections: Vec<(Vec<u8>, RejectedKeyPackageV1)>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let Some(roster) = self.merged_device_roster(group_id) else {
            return Ok(AccountDeviceEffects::default());
        };
        let operations = rejection_operations(&roster, rejections);
        if operations.is_empty() || !self.device_group_takes_commit(group_id, held)? {
            return Ok(AccountDeviceEffects::default());
        }
        tracing::debug!(
            target: TRACE_TARGET,
            method = "reject_key_packages",
            operation_count = operations.len(),
            "recording rejected key packages in the device group"
        );
        self.send_device_roster_update(group_id.clone(), operations, Some(context))
            .await
    }
}

/// The operations that add `rejections` to `roster`: a set for each one the
/// roster lacks that is among the eight newest for its slot, and a removal
/// for each of the roster's records that no longer is. Empty when no record
/// would be set.
pub(super) fn rejection_operations(
    roster: &DeviceRosterV1,
    rejections: Vec<(Vec<u8>, RejectedKeyPackageV1)>,
) -> Vec<DeviceRosterOperationV1> {
    let added: Vec<_> = rejections
        .into_iter()
        .filter(|(key_package_ref, _)| !roster.rejected_key_packages.contains_key(key_package_ref))
        .collect();
    let kept = newest_rejected_key_packages(
        roster
            .rejected_key_packages
            .iter()
            .map(|(key_package_ref, record)| (key_package_ref.as_slice(), record))
            .chain(
                added
                    .iter()
                    .map(|(key_package_ref, record)| (key_package_ref.as_slice(), record)),
            ),
    );
    let set: Vec<_> = added
        .iter()
        .filter(|(key_package_ref, _)| kept.contains(key_package_ref))
        .map(|(key_package_ref, record)| {
            DeviceRosterOperationV1::SetRejectedKeyPackage(key_package_ref.clone(), record.clone())
        })
        .collect();
    if set.is_empty() {
        return Vec::new();
    }
    roster
        .rejected_key_packages
        .keys()
        .filter(|key_package_ref| !kept.contains(*key_package_ref))
        .map(|key_package_ref| {
            DeviceRosterOperationV1::RemoveRejectedKeyPackage(key_package_ref.clone())
        })
        .chain(set)
        .collect()
}

/// The removals that drop each of `roster`'s rejected KeyPackages whose
/// `rejected_at` is at least [`REJECTED_KEY_PACKAGE_RETENTION_SECS`] before
/// `now`.
pub(super) fn expired_rejected_key_packages(
    roster: &DeviceRosterV1,
    now: u64,
) -> impl Iterator<Item = DeviceRosterOperationV1> + '_ {
    roster
        .rejected_key_packages
        .iter()
        .filter(move |(_, rejected)| {
            rejected
                .rejected_at
                .checked_add(REJECTED_KEY_PACKAGE_RETENTION_SECS)
                .is_some_and(|expires_at| expires_at <= now)
        })
        .map(|(key_package_ref, _)| {
            DeviceRosterOperationV1::RemoveRejectedKeyPackage(key_package_ref.clone())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(slot: u8, rejected_at: u64) -> RejectedKeyPackageV1 {
        RejectedKeyPackageV1 {
            slot: [slot; 32],
            leaf_signature_key: vec![0x07; 32],
            rejected_at,
        }
    }

    fn roster(records: impl IntoIterator<Item = (u8, RejectedKeyPackageV1)>) -> DeviceRosterV1 {
        DeviceRosterV1 {
            rejected_key_packages: records
                .into_iter()
                .map(|(key_package_ref, record)| (vec![key_package_ref; 32], record))
                .collect(),
            ..DeviceRosterV1::default()
        }
    }

    /// A slot the roster holds eight for: a newer record replaces the oldest
    /// in the same update, an older one is left out, and one the roster
    /// already rejects is never set again.
    #[test]
    fn adding_keeps_the_eight_newest_for_each_slot() {
        let full = roster((1..=8u8).map(|n| (n, record(1, 10 * u64::from(n)))));

        let newer = rejection_operations(
            &full,
            vec![
                (vec![0x20; 32], record(1, 100)),
                (vec![0x30; 32], record(2, 0)),
            ],
        );
        assert_eq!(
            newer,
            vec![
                DeviceRosterOperationV1::RemoveRejectedKeyPackage(vec![1; 32]),
                DeviceRosterOperationV1::SetRejectedKeyPackage(vec![0x20; 32], record(1, 100)),
                DeviceRosterOperationV1::SetRejectedKeyPackage(vec![0x30; 32], record(2, 0)),
            ]
        );
        let next = full
            .apply(&cgka_traits::app_components::DeviceRosterUpdateV1::new(newer).unwrap())
            .unwrap();
        assert_eq!(next.rejected_key_packages.len(), 9);

        assert!(rejection_operations(&full, vec![(vec![0x20; 32], record(1, 0))]).is_empty());
        assert!(rejection_operations(&full, vec![(vec![3; 32], record(1, 999))]).is_empty());

        // Of two at the oldest time, the one with the higher ref stays.
        let tied =
            roster((1..=8u8).map(|n| (n, record(1, if n == 1 { 5 } else { 10 * u64::from(n) }))));
        assert_eq!(
            rejection_operations(&tied, vec![(vec![0x20; 32], record(1, 5))]),
            vec![
                DeviceRosterOperationV1::RemoveRejectedKeyPackage(vec![1; 32]),
                DeviceRosterOperationV1::SetRejectedKeyPackage(vec![0x20; 32], record(1, 5)),
            ]
        );
    }

    #[test]
    fn a_record_expires_30_days_after_it_was_rejected() {
        let now = 100 * 24 * 60 * 60;
        let held = roster([
            (1, record(1, now - REJECTED_KEY_PACKAGE_RETENTION_SECS)),
            (2, record(1, now - REJECTED_KEY_PACKAGE_RETENTION_SECS + 1)),
            (3, record(2, u64::MAX)),
        ]);
        assert_eq!(
            expired_rejected_key_packages(&held, now).collect::<Vec<_>>(),
            vec![DeviceRosterOperationV1::RemoveRejectedKeyPackage(vec![
                1;
                32
            ])]
        );
    }
}
