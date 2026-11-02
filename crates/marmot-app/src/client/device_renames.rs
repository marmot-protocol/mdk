//! Human edits of this account's device labels and settings (D37/D86).
//!
//! Rename and settings commands resolve their supplied fields on the worker,
//! journal label + all three settings, then use the runtime's roster CAS.
//! Legacy records with no settings still replay only a label. The existing
//! maintenance owner recovers a lost edit by provenance: a written id means
//! applied, a replaced id means replay, any other id means another edit won.
//! A later human edit first tries that same recovery and re-reads. A no-op
//! cancels a lost edit only when it explicitly covers every pending difference.
//! Journal writes precede publication and are restored only when nothing went
//! out; uncertain publication remains recoverable. There is no new scheduler.

use cgka_traits::GroupId;
use cgka_traits::app_components::{
    DEVICE_ROSTER_TEXT_MAX_LEN, DeviceEntryV1, DeviceRenameId, DeviceSettingsV1, DeviceSlotId,
};
use marmot_session::{AccountResult, DeviceRosterEdit, DeviceRosterEditBlocked, PendingResolution};
use rand::RngCore;
use rand::rngs::OsRng;
use storage_sqlite::DeviceRenameRecord;

use super::AppClient;
use super::device_group::Exchange;
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

/// A fresh rename id. Every roster entry is created with one and every
/// rename writes one, so an id this device kept shows up in the roster again
/// only when a fork brings back an earlier state.
pub(crate) fn fresh_rename_id() -> DeviceRenameId {
    let mut id = DeviceRenameId::default();
    OsRng.fill_bytes(&mut id);
    id
}

/// Keep at most [`MAX_KEPT_RENAME_IDS`] ids, the oldest replaced ones going
/// first. The newest written id always stays, and so does `base`, the id the
/// entry held where the rename was built or made again, kept as the newest
/// replaced: while the rename is lost and nothing renamed the device since,
/// the roster holds it.
fn bound(record: &mut DeviceRenameRecord, base: Option<DeviceRenameId>) {
    record.replaced.retain(|id| *id != base);
    record.replaced.push(base);
    let excess = (record.written.len() + record.replaced.len()).saturating_sub(MAX_KEPT_RENAME_IDS);
    let from_replaced = excess.min(record.replaced.len().saturating_sub(1));
    record.replaced.drain(..from_replaced);
    let from_written = (excess - from_replaced).min(record.written.len().saturating_sub(1));
    record.written.drain(..from_written);
}

/// Whether a rename's edit sent nothing, so its record goes back as it was:
/// the edit was refused, or its commit rolled back. A commit neither
/// confirmed nor rolled back waits for the runtime's retry and may still land.
/// An error carries no resolution, so `None`: it may come before the commit
/// was staged or after it was published.
pub(super) fn nothing_went_out(edit: &AccountResult<DeviceRosterEdit>) -> Option<bool> {
    Some(match edit {
        Ok(DeviceRosterEdit::Committed(effects)) => {
            // Only this commit was in flight: the gate let nothing else of
            // this device's through.
            effects
                .pending
                .iter()
                .any(|resolution| matches!(resolution, PendingResolution::RolledBack { .. }))
                && !effects
                    .pending
                    .iter()
                    .any(|resolution| matches!(resolution, PendingResolution::Confirmed { .. }))
        }
        Ok(DeviceRosterEdit::Unchanged | DeviceRosterEdit::Blocked(_)) => true,
        Err(_) => return None,
    })
}

/// What one rename commit came to.
enum RenameCommit {
    Sent,
    /// The device group can't take a commit from this device now, or the
    /// entry changed since it was read.
    Busy,
}

/// A host request changes only its supplied fields. It is resolved on the worker
/// after any earlier lost local edit has been recovered, never on a host snapshot.
#[derive(Default)]
struct DeviceEdit<'a> {
    label: Option<&'a str>,
    add_to_all_chats: Option<bool>,
    bring_history: Option<bool>,
    keep_while_inactive: Option<bool>,
}

impl DeviceEdit<'_> {
    fn apply(&self, entry: &mut DeviceEntryV1) {
        if let Some(label) = self.label {
            entry.label = label.to_owned();
        }
        if let Some(value) = self.add_to_all_chats {
            entry.settings.add_to_all_chats = value;
        }
        if let Some(value) = self.bring_history {
            entry.settings.bring_history = value;
        }
        if let Some(value) = self.keep_while_inactive {
            entry.settings.keep_while_inactive = value;
        }
    }

    /// A no-op request may cancel only the pending differences it explicitly
    /// covers. Choosing the shown label must not drop an unrelated settings edit.
    fn cancels(&self, record: &DeviceRenameRecord, current: &DeviceEntryV1) -> bool {
        let mut desired = current.clone();
        desired.label.clone_from(&record.label);
        if let Some(settings) = record.settings {
            desired.settings = settings;
        }
        self.apply(&mut desired);
        desired.label == current.label && desired.settings == current.settings
    }
}

fn edit_matches(record: &DeviceRenameRecord, entry: &DeviceEntryV1) -> bool {
    record.label == entry.label
        && record
            .settings
            .is_none_or(|settings| settings == entry.settings)
}

impl AppClient {
    /// Before a new settings-dependent side effect, wait for a differing local
    /// intention to settle. This reads the existing journal, not another queue.
    /// Equal flags, legacy labels and applied edits do not hold unrelated work.
    pub(super) fn device_setting_ready(
        &mut self,
        exchange: &Exchange,
        slot: &DeviceSlotId,
        flag: fn(DeviceSettingsV1) -> bool,
    ) -> Result<bool, AppError> {
        let Some(entry) = exchange.roster.devices.get(slot) else {
            return Ok(true);
        };
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some(record) = storage.device_rename(&hex::encode(slot))? else {
            return Ok(true);
        };
        let Some(settings) = record.settings else {
            return Ok(true);
        };
        let state = standing(&record, entry.rename_id);
        if flag(settings) == flag(entry.settings) || state == Standing::Applied {
            return Ok(true);
        }
        // A different id retires this intention only after every own Commit
        // has reached its outcome, exactly as the D37 recovery owner requires.
        let held = self.epoch_gap_held_groups()?;
        if !self
            .runtime
            .device_group_takes_commit(&exchange.group_id, &held)?
        {
            return Ok(false);
        }
        Ok(state == Standing::Replaced)
    }

    /// Rename any linked device; empty clears its label and at most 64 UTF-8
    /// bytes are accepted. Earlier lost edits recover before a later edit.
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
        self.edit_linked_device(
            slot_id_hex,
            DeviceEdit {
                label: Some(label),
                ..DeviceEdit::default()
            },
        )
        .await
    }

    /// Patch the supplied settings of any linked device. Omitted values are
    /// read from the current roster, after recovering an earlier local edit.
    pub(crate) async fn update_linked_device_settings(
        &mut self,
        slot_id_hex: &str,
        add_to_all_chats: Option<bool>,
        bring_history: Option<bool>,
        keep_while_inactive: Option<bool>,
    ) -> Result<(), AppError> {
        self.edit_linked_device(
            slot_id_hex,
            DeviceEdit {
                label: None,
                add_to_all_chats,
                bring_history,
                keep_while_inactive,
            },
        )
        .await
    }

    async fn edit_linked_device(
        &mut self,
        slot_id_hex: &str,
        request: DeviceEdit<'_>,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let slot =
            device_slot(slot_id_hex).map_err(|_| AppError::DeviceGroupRefused("unknown_device"))?;
        self.sync_runtime_groups_for_send("edit_linked_device")
            .await?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let slot_id_hex = hex::encode(slot);
        // One attempt uses the existing recovery owner; a replay still in flight
        // is Busy. There is no new retry loop, scheduler or intention merging.
        for recover_first in [true, false] {
            let Some((group_id, roster)) = self.trusted_device_roster()? else {
                return Err(AppError::DeviceGroupRefused("no_device_group"));
            };
            let Some(entry) = roster.devices.get(&slot) else {
                return Err(AppError::DeviceGroupRefused("unknown_device"));
            };
            if request.label.is_none()
                && request.add_to_all_chats.is_none()
                && request.bring_history.is_none()
                && request.keep_while_inactive.is_none()
            {
                return Ok(());
            }
            let kept = storage.device_rename(&slot_id_hex)?;
            let kept_standing = kept.as_ref().map(|kept| standing(kept, entry.rename_id));
            let mut desired = entry.clone();
            request.apply(&mut desired);
            let unchanged = desired.label == entry.label && desired.settings == entry.settings;
            if unchanged {
                match kept_standing {
                    None | Some(Standing::Applied) => return Ok(()),
                    Some(Standing::Lost | Standing::Replaced) => {
                        // A record not visible on the roster can still land while
                        // its commit is unresolved. Never report a contrary no-op.
                        let held = self.epoch_gap_held_groups()?;
                        if !self.runtime.device_group_takes_commit(&group_id, &held)? {
                            return Err(AppError::DeviceGroupRefused("device_group_busy"));
                        }
                        if kept_standing == Some(Standing::Replaced)
                            || request.cancels(kept.as_ref().expect("kept edit"), entry)
                        {
                            storage.drop_device_rename(&slot_id_hex)?;
                            return Ok(());
                        }
                    }
                }
            }
            if let Some(kept) = kept
                .as_ref()
                .filter(|kept| kept_standing == Some(Standing::Lost) && !edit_matches(kept, entry))
            {
                if !recover_first {
                    return Err(AppError::DeviceGroupRefused("device_group_busy"));
                }
                self.settle_kept_device_edit(kept.clone()).await?;
                continue;
            }
            let replaced = match kept {
                Some(kept) if kept_standing != Some(Standing::Replaced) => kept
                    .replaced
                    .into_iter()
                    .chain(kept.written.into_iter().map(Some))
                    .collect(),
                _ => vec![entry.rename_id],
            };
            let record = DeviceRenameRecord {
                slot_id_hex: slot_id_hex.clone(),
                label: desired.label,
                settings: Some(desired.settings),
                written: vec![fresh_rename_id()],
                replaced,
            };
            return match self
                .commit_device_rename(&group_id, slot, entry.rename_id, record)
                .await?
            {
                RenameCommit::Sent => Ok(()),
                RenameCommit::Busy => Err(AppError::DeviceGroupRefused("device_group_busy")),
            };
        }
        unreachable!("the second pass returns")
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
        for record in storage.device_renames()? {
            if !self.settle_kept_device_edit(record).await? {
                break;
            }
        }
        Ok(())
    }

    /// The same D37 owner serves maintenance and a new human command. True
    /// permits maintenance to visit the next record; commands re-read afterwards.
    async fn settle_kept_device_edit(
        &mut self,
        mut record: DeviceRenameRecord,
    ) -> Result<bool, AppError> {
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(false);
        };
        let held = self.epoch_gap_held_groups()?;
        if !self.runtime.device_group_takes_commit(&group_id, &held)? {
            return Ok(false);
        }
        let slot = device_slot(&record.slot_id_hex)?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some(entry) = roster.devices.get(&slot) else {
            storage.drop_device_rename(&record.slot_id_hex)?;
            return Ok(true);
        };
        match standing(&record, entry.rename_id) {
            Standing::Applied => {}
            Standing::Replaced => storage.drop_device_rename(&record.slot_id_hex)?,
            Standing::Lost if edit_matches(&record, entry) => {}
            Standing::Lost => {
                record.written.push(fresh_rename_id());
                if let RenameCommit::Busy = self
                    .commit_device_rename(&group_id, slot, entry.rename_id, record)
                    .await?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Commit `record`'s rename of `slot` in `group_id`, through the
    /// runtime's roster write path, on the entry holding `expected`. The
    /// record is kept before the commit is sent, and put back as it was when
    /// nothing went out: the edit was refused, or the commit rolled back.
    async fn commit_device_rename(
        &mut self,
        group_id: &GroupId,
        slot: DeviceSlotId,
        expected: Option<DeviceRenameId>,
        mut record: DeviceRenameRecord,
    ) -> Result<RenameCommit, AppError> {
        bound(&mut record, expected);
        let held = self.epoch_gap_held_groups()?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let previous = storage.device_rename(&record.slot_id_hex)?;
        storage.put_device_rename(&record)?;
        let rename_id = *record.written.last().expect("a rename writes an id");
        let label = record.label.clone();
        let settings = record.settings;
        let edit = self
            .runtime
            .edit_device_roster_entry(group_id, &slot, &held, |entry| {
                // Only on the entry the record was built from: any other
                // reads as unchanged, and the rename waits.
                if entry.rename_id == expected {
                    entry.label = label;
                    if let Some(settings) = settings {
                        entry.settings = settings;
                    }
                    entry.rename_id = Some(rename_id);
                }
            })
            .await;
        let nothing_sent = match nothing_went_out(&edit) {
            Some(nothing_sent) => nothing_sent,
            None => self.rename_never_went_out(group_id, &slot, rename_id, &held),
        };
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
        if nothing_sent {
            match &previous {
                Some(previous) => storage.put_device_rename(previous)?,
                None => storage.drop_device_rename(&record.slot_id_hex)?,
            }
        }
        outcome
    }

    /// After an error, whether the rename writing `rename_id` at `slot` never
    /// went out, judged by what the device group holds now: the roster does
    /// not carry it, and nothing of this device's is in flight there. Anything
    /// unreadable or unsettled counts as possibly out, so the record stays.
    fn rename_never_went_out(
        &mut self,
        group_id: &GroupId,
        slot: &DeviceSlotId,
        rename_id: DeviceRenameId,
        held: &[GroupId],
    ) -> bool {
        let landed = match self.trusted_device_roster() {
            Ok(Some((trusted, roster))) if trusted == *group_id => roster
                .devices
                .get(slot)
                .is_some_and(|entry| entry.rename_id == Some(rename_id)),
            _ => return false,
        };
        !landed
            && self
                .runtime
                .device_group_takes_commit(group_id, held)
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(written: &[u8], replaced: &[Option<u8>]) -> DeviceRenameRecord {
        DeviceRenameRecord {
            slot_id_hex: "aa".into(),
            label: "Laptop".into(),
            settings: None,
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
    fn a_record_goes_back_only_when_nothing_went_out() {
        use cgka_traits::{EngineError, PendingStateRef};
        use marmot_session::{AccountDeviceEffects, AccountError};

        let committed = |pending: Vec<PendingResolution>| {
            Ok(DeviceRosterEdit::Committed(Box::new(
                AccountDeviceEffects {
                    pending,
                    ..AccountDeviceEffects::default()
                },
            )))
        };
        let pending = PendingStateRef::new(1);
        assert_eq!(
            nothing_went_out(&Ok(DeviceRosterEdit::Unchanged)),
            Some(true)
        );
        assert_eq!(
            nothing_went_out(&Ok(DeviceRosterEdit::Blocked(
                DeviceRosterEditBlocked::Busy
            ))),
            Some(true)
        );
        assert_eq!(
            nothing_went_out(&committed(vec![PendingResolution::RolledBack { pending }])),
            Some(true)
        );
        assert_eq!(
            nothing_went_out(&committed(vec![PendingResolution::Confirmed { pending }])),
            Some(false)
        );
        assert_eq!(
            nothing_went_out(&committed(Vec::new())),
            Some(false),
            "a commit kept for a retry may still land"
        );
        assert_eq!(
            nothing_went_out(&Err(AccountError::Engine(EngineError::Storage(
                cgka_traits::storage::StorageError::Backend("after the publish".into())
            )))),
            None,
            "an error is judged by what the device group holds"
        );
    }

    #[test]
    fn a_kept_rename_forgets_its_oldest_replaced_ids_first() {
        let replaced: Vec<Option<u8>> = (0..40).map(Some).collect();
        let mut kept = record(&[100, 101], &replaced);
        bound(&mut kept, Some([39; 16]));
        assert_eq!(
            kept.written.len() + kept.replaced.len(),
            MAX_KEPT_RENAME_IDS
        );
        assert_eq!(kept.written, vec![[100; 16], [101; 16]]);
        assert_eq!(kept.replaced.first(), Some(&Some([10; 16])));
        assert_eq!(kept.replaced.last(), Some(&Some([39; 16])));

        let written: Vec<u8> = (0..40).collect();
        let mut redone = record(&written, &[None]);
        bound(&mut redone, None);
        assert_eq!(redone.replaced, vec![None]);
        assert_eq!(redone.written.len(), MAX_KEPT_RENAME_IDS - 1);
        assert_eq!(redone.written.last(), Some(&[39; 16]));
    }

    /// A rename of a never-renamed device lost, and a later one carried its
    /// ids: the roster still holds none, the id the later one was built on,
    /// so bounding keeps that one however old it is.
    #[test]
    fn a_kept_rename_never_forgets_the_id_it_was_built_on() {
        let replaced: Vec<Option<u8>> = std::iter::once(None).chain((0..40).map(Some)).collect();
        let mut kept = record(&[100], &replaced);
        bound(&mut kept, None);
        assert_eq!(
            kept.written.len() + kept.replaced.len(),
            MAX_KEPT_RENAME_IDS
        );
        assert_eq!(kept.replaced.last(), Some(&None));
        assert_eq!(standing(&kept, None), Standing::Lost);
    }
}
