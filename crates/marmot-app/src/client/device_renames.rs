//! Renaming this account's devices (mdk#2628 item 3.6, D35, D37).
//!
//! Any device may rename any device, itself included: one roster commit in the
//! device group this device trusts, setting one entry's label and a fresh
//! rename id and keeping every other field as the roster holds it, through
//! the runtime's one roster write path. While that group cannot take a commit
//! from this device, a rename is refused and nothing is sent.
//!
//! A rename is kept on disk before its commit is sent: the ids it wrote, and
//! the ids the entry held where this device's renames of that device were
//! built ([`DeviceRenameRecord`]). Its commit can lose a fork. Each
//! maintenance pass, while the device group can take a commit from this
//! device (so each of its commits there has reached its outcome), reads the
//! rename id the winning roster holds for every device this device renamed:
//! - one this rename wrote: it applied, by its own commit or the engine's
//!   re-issue of it, which carries the same bytes;
//! - one the entry held where this device's renames were built: the rename
//!   lost and nothing renamed the device since, so it is made again with a
//!   fresh id;
//! - any other: another rename won and stands, and the record goes.
//!
//! Saving the label the roster already shows sends nothing. It keeps a rename
//! that applied, so a fork that rewinds it later still has it made again, and
//! forgets a lost one, which would now undo the user's choice.

use cgka_traits::GroupId;
use cgka_traits::app_components::{DEVICE_ROSTER_TEXT_MAX_LEN, DeviceRenameId, DeviceSlotId};
use marmot_session::{DeviceRosterEdit, DeviceRosterEditBlocked};
use rand::RngCore;
use rand::rngs::OsRng;
use storage_sqlite::DeviceRenameRecord;

use super::AppClient;
use super::device_group::device_slot;
use crate::AppError;

const TRACE_TARGET: &str = "marmot_app::client::device_renames";

/// Most rename ids kept for one renamed device. Past it the oldest replaced
/// ids go first: a roster holding a forgotten id reads as another rename.
const MAX_KEPT_RENAME_IDS: usize = 32;

/// Where a kept rename stands against the rename id the roster holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// The roster holds an id the rename wrote.
    Applied,
    /// The roster holds an id one of this device's renames replaced:
    /// nothing renamed the device since.
    Lost,
    /// Another rename won.
    Replaced,
}

fn standing(record: &DeviceRenameRecord, rename_id: Option<DeviceRenameId>) -> Standing {
    match rename_id {
        Some(id) if record.written.contains(&id) => Standing::Applied,
        id if record.replaced.contains(&id) => Standing::Lost,
        _ => Standing::Replaced,
    }
}

fn fresh_rename_id() -> DeviceRenameId {
    let mut id = DeviceRenameId::default();
    OsRng.fill_bytes(&mut id);
    id
}

/// Keep at most [`MAX_KEPT_RENAME_IDS`] ids, the oldest replaced ones going
/// first, and always the newest of each.
fn bound(record: &mut DeviceRenameRecord) {
    let excess = (record.written.len() + record.replaced.len()).saturating_sub(MAX_KEPT_RENAME_IDS);
    let from_replaced = excess.min(record.replaced.len().saturating_sub(1));
    record.replaced.drain(..from_replaced);
    let from_written = (excess - from_replaced).min(record.written.len().saturating_sub(1));
    record.written.drain(..from_written);
}

/// What one rename commit came to.
enum RenameCommit {
    Sent,
    /// The device group can't take a commit from this device now, or the
    /// entry changed since it was read.
    Busy,
}

impl AppClient {
    /// Rename one of this account's devices: set the label of `slot_id_hex`'s
    /// roster entry, with a fresh rename id. The label is at most 64 bytes of
    /// UTF-8; empty clears it.
    ///
    /// Refused with nothing sent when device groups are off, with no trusted
    /// device group, for a slot the roster doesn't list (`unknown_device`),
    /// and while the device group cannot take a commit from this device now
    /// (`device_group_busy`; retry later).
    pub(crate) async fn rename_linked_device(
        &mut self,
        slot_id_hex: &str,
        label: &str,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        if label.len() > DEVICE_ROSTER_TEXT_MAX_LEN {
            return Err(AppError::DeviceGroupRefused("label_too_long"));
        }
        let slot =
            device_slot(slot_id_hex).map_err(|_| AppError::DeviceGroupRefused("unknown_device"))?;
        self.sync_runtime_groups_for_send("rename_linked_device")
            .await?;
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Err(AppError::DeviceGroupRefused("no_device_group"));
        };
        let Some(entry) = roster.devices.get(&slot) else {
            return Err(AppError::DeviceGroupRefused("unknown_device"));
        };
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let slot_id_hex = hex::encode(slot);
        let kept = storage.device_rename(&slot_id_hex)?;
        let kept_standing = kept.as_ref().map(|kept| standing(kept, entry.rename_id));
        if entry.label == label {
            // The user chose the label the roster shows. A lost rename of
            // this device would undo that choice; one that applied stays.
            if kept_standing.is_some_and(|kept| kept != Standing::Applied) {
                storage.drop_device_rename(&slot_id_hex)?;
            }
            return Ok(());
        }
        // Where this device's earlier renames of the device still stand, a
        // roster holding any id they wrote or replaced means this one lost.
        let replaced = match kept {
            Some(kept) if kept_standing != Some(Standing::Replaced) => kept
                .replaced
                .into_iter()
                .chain(kept.written.into_iter().map(Some))
                .collect(),
            _ => vec![entry.rename_id],
        };
        let record = DeviceRenameRecord {
            slot_id_hex,
            label: label.to_owned(),
            written: vec![fresh_rename_id()],
            replaced,
        };
        let expected = entry.rename_id;
        match self
            .commit_device_rename(&group_id, slot, expected, record)
            .await?
        {
            RenameCommit::Sent => Ok(()),
            RenameCommit::Busy => Err(AppError::DeviceGroupRefused(
                DeviceRosterEditBlocked::Busy.reason(),
            )),
        }
    }

    /// Make each rename this device keeps that lost a fork again, and forget
    /// those another rename replaced. A failure waits for the next
    /// maintenance pass.
    pub(crate) async fn device_rename_upkeep(&mut self) {
        if let Err(error) = self.try_device_rename_upkeep().await {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "device_rename_upkeep",
                error_kind = error.privacy_safe_kind(),
                "could not settle device renames; retrying later"
            );
        }
    }

    pub(crate) async fn try_device_rename_upkeep(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        for rename in storage.device_renames()? {
            let Some((group_id, roster)) = self.trusted_device_roster()? else {
                return Ok(());
            };
            let held = self.epoch_gap_held_groups()?;
            if !self.runtime.device_group_takes_commit(&group_id, &held)? {
                return Ok(());
            }
            let slot = device_slot(&rename.slot_id_hex)?;
            let Some(entry) = roster.devices.get(&slot) else {
                storage.drop_device_rename(&rename.slot_id_hex)?;
                continue;
            };
            match standing(&rename, entry.rename_id) {
                Standing::Applied => {}
                Standing::Replaced => storage.drop_device_rename(&rename.slot_id_hex)?,
                // The roster shows this rename's label already.
                Standing::Lost if entry.label == rename.label => {}
                Standing::Lost => {
                    let expected = entry.rename_id;
                    let mut again = rename;
                    again.written.push(fresh_rename_id());
                    if let RenameCommit::Busy = self
                        .commit_device_rename(&group_id, slot, expected, again)
                        .await?
                    {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    /// Commit `record`'s rename of `slot` in `group_id`, through the
    /// runtime's roster write path, on the entry holding `expected`. The
    /// record is kept before the commit is sent, and put back as it was when
    /// nothing went out.
    async fn commit_device_rename(
        &mut self,
        group_id: &GroupId,
        slot: DeviceSlotId,
        expected: Option<DeviceRenameId>,
        mut record: DeviceRenameRecord,
    ) -> Result<RenameCommit, AppError> {
        bound(&mut record);
        let held = self.epoch_gap_held_groups()?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let previous = storage.device_rename(&record.slot_id_hex)?;
        storage.put_device_rename(&record)?;
        let rename_id = *record.written.last().expect("a rename writes an id");
        let label = record.label.clone();
        let edit = self
            .runtime
            .edit_device_roster_entry(group_id, &slot, &held, |entry| {
                // Only on the entry the record was built from: any other
                // reads as unchanged, and the rename waits.
                if entry.rename_id == expected {
                    entry.label = label;
                    entry.rename_id = Some(rename_id);
                }
            })
            .await;
        let outcome = match edit {
            Ok(DeviceRosterEdit::Committed(effects)) => {
                self.linked_devices_changed = true;
                self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                    .await
                    .map(|()| RenameCommit::Sent)
            }
            Ok(DeviceRosterEdit::Unchanged)
            | Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Busy)) => {
                Ok(RenameCommit::Busy)
            }
            Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::NoEntry)) => {
                Err(AppError::DeviceGroupRefused("unknown_device"))
            }
            Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Unreadable)) => {
                Err(AppError::DeviceGroupRefused("roster_unavailable"))
            }
            Err(error) => Err(error.into()),
        };
        if !matches!(outcome, Ok(RenameCommit::Sent)) {
            match &previous {
                Some(previous) => storage.put_device_rename(previous)?,
                None => storage.drop_device_rename(&record.slot_id_hex)?,
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(written: &[u8], replaced: &[Option<u8>]) -> DeviceRenameRecord {
        DeviceRenameRecord {
            slot_id_hex: "aa".into(),
            label: "Laptop".into(),
            written: written.iter().map(|id| [*id; 16]).collect(),
            replaced: replaced.iter().map(|id| id.map(|id| [id; 16])).collect(),
        }
    }

    #[test]
    fn a_rename_stands_by_the_id_the_roster_holds() {
        let kept = record(&[3, 4], &[None, Some(1)]);
        assert_eq!(standing(&kept, Some([4; 16])), Standing::Applied);
        assert_eq!(standing(&kept, Some([3; 16])), Standing::Applied);
        assert_eq!(standing(&kept, Some([1; 16])), Standing::Lost);
        assert_eq!(standing(&kept, None), Standing::Lost);
        assert_eq!(standing(&kept, Some([9; 16])), Standing::Replaced);
        assert_eq!(
            standing(&record(&[3], &[Some(1)]), None),
            Standing::Replaced
        );
    }

    #[test]
    fn a_kept_rename_forgets_its_oldest_replaced_ids_first() {
        let replaced: Vec<Option<u8>> = (0..40).map(Some).collect();
        let mut kept = record(&[100, 101], &replaced);
        bound(&mut kept);
        assert_eq!(
            kept.written.len() + kept.replaced.len(),
            MAX_KEPT_RENAME_IDS
        );
        assert_eq!(kept.written, vec![[100; 16], [101; 16]]);
        assert_eq!(kept.replaced.first(), Some(&Some([10; 16])));
        assert_eq!(kept.replaced.last(), Some(&Some([39; 16])));

        let written: Vec<u8> = (0..40).collect();
        let mut redone = record(&written, &[None]);
        bound(&mut redone);
        assert_eq!(redone.replaced, vec![None]);
        assert_eq!(redone.written.len(), MAX_KEPT_RENAME_IDS - 1);
        assert_eq!(redone.written.last(), Some(&[39; 16]));
    }
}
