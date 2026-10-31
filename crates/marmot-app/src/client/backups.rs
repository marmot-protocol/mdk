//! Backups' recovery words (mdk#2628 item 4.4a, D34 item 2, D71).
//!
//! An account's backups are sealed to a recovery key that 12 BIP-39 English
//! words derive, separate from the nsec. MDK makes the words and the host
//! shows them once; the user types back the two at positions MDK picks. Only
//! then does this device keep anything: the key's public half. The words and
//! the private half live in memory for the flow alone and never reach disk.
//! A client that closes mid-flow starts over with new words.
//!
//! The account's recovery key is its device group's roster account entry;
//! backups are off while it holds none. A device that trusts no device group
//! keeps the key itself, and the roster it founds carries it, naming this
//! device as the backup writer. Once the device trusts a device group, one it
//! founded or one it joined, the key it kept counts as words that turned
//! backups on there, and founds nothing again. In a device group, confirming
//! words or turning backups off commits the account entry through the
//! runtime's one roster write path, as a compare-and-set, and only while the
//! group can take a commit from this device. Turning backups on makes this
//! device the writer; new words keep the writer the roster names; turning
//! them off clears the entry.
//!
//! The change is kept on disk, with the key the roster held when the user
//! made it, before its commit is sent ([`BackupRecoveryKeyRecord`]), put back
//! as it was when nothing went out, and kept until the user makes another.
//! The engine re-issues a commit a fork dropped, and the runtime retries one
//! the relays refused. Each maintenance pass, after those, and while the
//! device group can take a commit from this device (it cannot while a commit
//! of this device's is queued, unconfirmed or owed a re-issue), carries new
//! words or a turn-off again when the roster holds the key they replaced
//! ([`upkeep`]): no device writes that key again, so the commit was lost. It
//! does so only while the engine still keeps one of this device's
//! account-entry commits, so while branch selection could still withdraw or
//! restore the change; once none is kept, none is again. A change made over no
//! key is never carried again: the roster holds no key both before backups
//! are turned on and after a later turn-off, so carrying it could undo
//! another device's turn-off.
//!
//! Whether words confirmed here are in use is read each time, never stored
//! ([`words_status`]): in use while the roster holds their key; pending while
//! anything could still make it the roster's, a change of this device's in
//! flight or a branch that branch selection can still pick; and only then not
//! in use, which is final: nothing brings that key back.

use std::fmt;

use bip39::Mnemonic;
use cgka_traits::GroupId;
use cgka_traits::app_components::{AccountEntryV1, DeviceRosterV1, DeviceSlotId};
use marmot_session::{
    AccountResult, DeviceRosterEdit, DeviceRosterEditBlocked, RECOVERY_ENTROPY_LEN,
};
use rand::RngCore;
use rand::rngs::OsRng;
use rand::seq::index::sample;
use storage_sqlite::BackupRecoveryKeyRecord;
use zeroize::Zeroizing;

use super::AppClient;
use super::device_renames::nothing_went_out;
use crate::AppError;

const TRACE_TARGET: &str = "marmot_app::client::backups";

/// How many recovery words there are: 128 bits of entropy and a 4-bit
/// checksum.
const RECOVERY_WORD_COUNT: usize = 12;
/// How many of them the user types back to confirm.
const CONFIRM_WORD_COUNT: usize = 2;

/// New recovery words for the account's backups, for the user to write down.
/// Shown once: MDK keeps them in memory only until they are confirmed or
/// cancelled.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryWords {
    /// The 12 words, in order.
    pub words: Vec<String>,
    /// The 1-based positions, ascending, of the two words the user types back.
    pub confirm_positions: Vec<u32>,
}

impl fmt::Debug for RecoveryWords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryWords")
            .field("words", &format_args!("[{} redacted]", self.words.len()))
            .field("confirm_positions", &self.confirm_positions)
            .finish()
    }
}

/// Where the account's backups stand, as this device sees them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupSettings {
    /// Whether the account has a recovery key, so its backups are on.
    pub enabled: bool,
    /// Whether this device writes the account's backups.
    pub this_device_writes: bool,
    /// Whether the words last confirmed on this device are not in the
    /// device group's roster yet but may still be: their change is in
    /// flight or carried again, or a branch that branch selection can still
    /// pick holds them.
    pub words_pending: bool,
    /// Whether backups turned off on this device wait to be turned off in
    /// the device group's roster.
    pub off_pending: bool,
    /// Whether the words last confirmed on this device are not in use and
    /// never will be: another change won, their commit was lost, or this
    /// device joined a device group with words it kept, and no branch that
    /// branch selection can still pick holds them. Until the user dismisses
    /// it or confirms new words.
    pub words_unused: bool,
}

/// Recovery words shown and not yet confirmed.
pub(crate) struct PendingRecoveryWords {
    entropy: Zeroizing<[u8; RECOVERY_ENTROPY_LEN]>,
    /// The 0-based positions of the words the user types back, ascending.
    confirm: [usize; CONFIRM_WORD_COUNT],
}

impl PendingRecoveryWords {
    fn generate() -> Self {
        let mut entropy = Zeroizing::new([0; RECOVERY_ENTROPY_LEN]);
        OsRng.fill_bytes(entropy.as_mut_slice());
        let mut confirm = [0; CONFIRM_WORD_COUNT];
        for (slot, at) in
            confirm
                .iter_mut()
                .zip(sample(&mut OsRng, RECOVERY_WORD_COUNT, CONFIRM_WORD_COUNT))
        {
            *slot = at;
        }
        confirm.sort_unstable();
        Self { entropy, confirm }
    }

    fn words(&self) -> Zeroizing<Vec<String>> {
        Zeroizing::new(recovery_words(&self.entropy))
    }

    /// Whether `answers` are the words at the confirm positions, in order,
    /// ignoring case and surrounding whitespace.
    fn confirmed_by(&self, answers: &[String]) -> bool {
        let words = self.words();
        answers.len() == CONFIRM_WORD_COUNT
            && self
                .confirm
                .iter()
                .zip(answers)
                .all(|(&at, answer)| answer.trim().eq_ignore_ascii_case(&words[at]))
    }
}

/// The 12 BIP-39 English words `entropy` encodes, in order.
fn recovery_words(entropy: &[u8; RECOVERY_ENTROPY_LEN]) -> Vec<String> {
    Mnemonic::from_entropy(entropy)
        .expect("16 bytes of entropy encode 12 words")
        .words()
        .map(str::to_owned)
        .collect()
}

/// What a maintenance pass does about what this device keeps.
#[derive(Debug, PartialEq, Eq)]
enum Upkeep {
    Nothing,
    /// Commit the change again: the account entry's key to `key`, on the
    /// entry holding `replaces`.
    Carry {
        key: Option<Vec<u8>>,
        replaces: Vec<u8>,
    },
}

/// What a maintenance pass does about `record` while the roster holds
/// `holds`. A change is carried again only over the key it replaced, which
/// no device writes again, never over no key, which recurs; and only while
/// the engine still keeps one of this device's account-entry commits
/// (`retained`), so never once words could have shown as not in use.
fn upkeep(record: BackupRecoveryKeyRecord, holds: Option<Vec<u8>>, retained: bool) -> Upkeep {
    let (key, replaces) = match record {
        BackupRecoveryKeyRecord::Confirmed {
            public_key,
            replaces: Some(replaces),
        } => (Some(public_key), replaces),
        BackupRecoveryKeyRecord::TurningOff { replaces } => (None, replaces),
        BackupRecoveryKeyRecord::Empty
        | BackupRecoveryKeyRecord::Kept { .. }
        | BackupRecoveryKeyRecord::Confirmed { replaces: None, .. } => return Upkeep::Nothing,
    };
    if retained && holds.as_ref() == Some(&replaces) {
        Upkeep::Carry { key, replaces }
    } else {
        Upkeep::Nothing
    }
}

/// Where the words last confirmed on this device stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WordsStatus {
    InUse,
    Pending,
    Unused,
}

/// Where words stand while the roster `holds_them` or not, asking only then
/// whether anything may still make them its key. Not in use only on a
/// definite no: a read that fails counts as pending.
fn words_status<E>(
    holds_them: bool,
    may_be_in_use: impl FnOnce() -> Result<bool, E>,
) -> WordsStatus {
    if holds_them {
        return WordsStatus::InUse;
    }
    match may_be_in_use() {
        Ok(false) => WordsStatus::Unused,
        Ok(true) | Err(_) => WordsStatus::Pending,
    }
}

impl AppClient {
    /// Make new recovery words for the account's backups, in place of any
    /// not yet confirmed. Refused with `roster_unsupported` while device
    /// groups are off.
    pub(crate) fn begin_recovery_words(&mut self) -> Result<RecoveryWords, AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let pending = PendingRecoveryWords::generate();
        let shown = RecoveryWords {
            words: pending.words().to_vec(),
            confirm_positions: pending
                .confirm
                .iter()
                .map(|&at| u32::try_from(at + 1).expect("a word position fits"))
                .collect(),
        };
        self.pending_recovery_words = Some(pending);
        Ok(shown)
    }

    /// Forget the recovery words not yet confirmed, if any.
    pub(crate) fn cancel_recovery_words(&mut self) {
        self.pending_recovery_words = None;
    }

    /// Confirm the recovery words [`Self::begin_recovery_words`] made with
    /// the words the user typed at its confirm positions, in order, and make
    /// their key the account's recovery key. The words are then forgotten.
    ///
    /// Refused with nothing kept, and the words kept for another try:
    /// `roster_unsupported` while device groups are off,
    /// `recovery_words_not_started` without words to confirm,
    /// `recovery_words_mismatch` when the typed words differ,
    /// `device_group_busy` while the device group cannot take a commit from
    /// this device (retry later), and `roster_unavailable`.
    pub(crate) async fn confirm_recovery_words(
        &mut self,
        answers: &[String],
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let Some(pending) = &self.pending_recovery_words else {
            return Err(AppError::DeviceGroupRefused("recovery_words_not_started"));
        };
        if !pending.confirmed_by(answers) {
            return Err(AppError::DeviceGroupRefused("recovery_words_mismatch"));
        }
        let public_key = self.runtime.recovery_public_key(&pending.entropy)?;
        self.sync_runtime_groups_for_send("confirm_recovery_words")
            .await?;
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            // No device group: the key is this device's to keep, and the
            // roster it founds carries it.
            self.app
                .account_storage(&self.state.label)?
                .app_storage()
                .put_backup_recovery_key(&BackupRecoveryKeyRecord::Kept { public_key })?;
            self.pending_recovery_words = None;
            return Ok(());
        };
        // Build only on a roster where each of this device's commits has an
        // outcome: a key one still in flight sets is not on it yet.
        let held = self.epoch_gap_held_groups()?;
        if !self.runtime.device_group_takes_commit(&group_id, &held)? {
            return Err(AppError::DeviceGroupRefused(
                DeviceRosterEditBlocked::Busy.reason(),
            ));
        }
        let replaces = roster.account.recovery_public_key;
        let record = BackupRecoveryKeyRecord::Confirmed {
            public_key: public_key.clone(),
            replaces: replaces.clone(),
        };
        self.send_account_entry_change(&group_id, record, Some(public_key), replaces, &held)
            .await?;
        // The commit went out, so the words are confirmed.
        self.pending_recovery_words = None;
        Ok(())
    }

    /// Turn the account's backups off: clear the roster's account entry, its
    /// recovery key and backup writer, or, with no device group, forget the
    /// key this device keeps. Backups already written stay. Turning them on
    /// again takes new words. Off already is not an error.
    ///
    /// Refused with nothing changed: `roster_unsupported` while device groups
    /// are off, `device_group_busy` while the device group cannot take a
    /// commit from this device (retry later), and `roster_unavailable`.
    pub(crate) async fn turn_off_backups(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        self.sync_runtime_groups_for_send("turn_off_backups")
            .await?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            storage.put_backup_recovery_key(&BackupRecoveryKeyRecord::Empty)?;
            return Ok(());
        };
        // A key a commit of this device's still in flight sets is not on the
        // roster yet.
        let held = self.epoch_gap_held_groups()?;
        if !self.runtime.device_group_takes_commit(&group_id, &held)? {
            return Err(AppError::DeviceGroupRefused(
                DeviceRosterEditBlocked::Busy.reason(),
            ));
        }
        let Some(replaces) = roster.account.recovery_public_key else {
            // Off already: stop carrying any words confirmed here.
            storage.put_backup_recovery_key(&BackupRecoveryKeyRecord::Empty)?;
            return Ok(());
        };
        let record = BackupRecoveryKeyRecord::TurningOff {
            replaces: replaces.clone(),
        };
        self.send_account_entry_change(&group_id, record, None, Some(replaces), &held)
            .await
    }

    /// Keep `record`, then commit its change to the account entry of
    /// `group_id`'s roster: the key to `key`, on the entry holding
    /// `replaces`. When nothing went out, put back what was kept and refuse
    /// with `device_group_busy`, `roster_unavailable` or the error. Otherwise
    /// the change is kept for maintenance ([`upkeep`]).
    async fn send_account_entry_change(
        &mut self,
        group_id: &GroupId,
        record: BackupRecoveryKeyRecord,
        key: Option<Vec<u8>>,
        replaces: Option<Vec<u8>>,
        held: &[GroupId],
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let own_slot = self.own_slot()?;
        let previous = storage.backup_recovery_key()?;
        storage.put_backup_recovery_key(&record)?;
        let edit = self
            .commit_account_entry(group_id, key, replaces, own_slot, held)
            .await;
        let nothing_sent = match nothing_went_out(&edit) {
            Some(nothing_sent) => nothing_sent,
            None => self.account_entry_change_never_went_out(group_id),
        };
        if nothing_sent {
            storage.put_backup_recovery_key(&previous)?;
            return Err(match edit {
                Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Unreadable)) => {
                    AppError::DeviceGroupRefused("roster_unavailable")
                }
                Err(error) => error.into(),
                Ok(_) => AppError::DeviceGroupRefused(DeviceRosterEditBlocked::Busy.reason()),
            });
        }
        let published = match edit {
            Ok(DeviceRosterEdit::Committed(effects)) => {
                self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                    .await
            }
            Ok(_) => Ok(()),
            Err(error) => Err(error.into()),
        };
        if let Err(error) = published {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "send_account_entry_change",
                error_kind = error.privacy_safe_kind(),
                "backup settings change not confirmed; the runtime retries it"
            );
        }
        Ok(())
    }

    /// What this device keeps about the account's recovery key, with the
    /// trusted device group's roster if there is one. Once the device trusts
    /// a device group, a key it kept with none counts as words that turned
    /// backups on there, and founds nothing again.
    fn recovery_key_state(
        &mut self,
    ) -> Result<(BackupRecoveryKeyRecord, Option<(GroupId, DeviceRosterV1)>), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let mut record = storage.backup_recovery_key()?;
        let trusted = self.trusted_device_roster()?;
        if trusted.is_some()
            && let BackupRecoveryKeyRecord::Kept { public_key } = record
        {
            record = BackupRecoveryKeyRecord::Confirmed {
                public_key,
                replaces: None,
            };
            storage.put_backup_recovery_key(&record)?;
        }
        Ok((record, trusted))
    }

    /// Where the words last confirmed on this device stand in `group_id`,
    /// whose roster holds `holds`, if `record` keeps any ([`words_status`]).
    fn recovery_words_status(
        &mut self,
        group_id: &GroupId,
        record: &BackupRecoveryKeyRecord,
        holds: Option<&[u8]>,
        held: &[GroupId],
    ) -> Option<WordsStatus> {
        let BackupRecoveryKeyRecord::Confirmed { public_key, .. } = record else {
            return None;
        };
        Some(words_status(holds == Some(public_key.as_slice()), || {
            self.runtime
                .recovery_key_may_be_in_use(group_id, held, public_key)
                .map_err(AppError::from)
                .inspect_err(|error| {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "recovery_words_status",
                        error_kind = error.privacy_safe_kind(),
                        "could not read whether recovery words may be in use; showing them pending"
                    );
                })
        }))
    }

    /// Where the account's backups stand on this device. Refused with
    /// `roster_unsupported` while device groups are off, and with
    /// `roster_unavailable` when the trusted roster cannot be read.
    pub(crate) fn backup_settings(&mut self) -> Result<BackupSettings, AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let (record, trusted) = self.recovery_key_state()?;
        let Some((group_id, roster)) = trusted else {
            // Without a device group this device keeps the key and writes.
            let on = matches!(record, BackupRecoveryKeyRecord::Kept { .. });
            return Ok(BackupSettings {
                enabled: on,
                this_device_writes: on,
                ..BackupSettings::default()
            });
        };
        let key = roster.account.recovery_public_key;
        let held = self.epoch_gap_held_groups()?;
        let words = self.recovery_words_status(&group_id, &record, key.as_deref(), &held);
        // A turn-off waits while it is in flight or could still be carried
        // again; anything unreadable counts as waiting.
        let off_pending = match &record {
            BackupRecoveryKeyRecord::TurningOff { replaces } if key.as_ref() == Some(replaces) => {
                !matches!(
                    self.runtime.device_group_takes_commit(&group_id, &held),
                    Ok(true)
                ) || !matches!(
                    self.runtime.own_account_entry_change_retained(&group_id),
                    Ok(false)
                )
            }
            _ => false,
        };
        Ok(BackupSettings {
            enabled: key.is_some(),
            this_device_writes: key.is_some()
                && roster.account.backup_writer == Some(self.own_slot()?),
            words_pending: words == Some(WordsStatus::Pending),
            off_pending,
            words_unused: words == Some(WordsStatus::Unused),
        })
    }

    /// Forget words confirmed on this device that are not in use, so the
    /// notice ends. Words in use or pending stay.
    pub(crate) fn dismiss_unused_recovery_words(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let (record, trusted) = self.recovery_key_state()?;
        let Some((group_id, roster)) = trusted else {
            return Ok(());
        };
        let held = self.epoch_gap_held_groups()?;
        let key = roster.account.recovery_public_key;
        if self.recovery_words_status(&group_id, &record, key.as_deref(), &held)
            == Some(WordsStatus::Unused)
        {
            self.app
                .account_storage(&self.state.label)?
                .app_storage()
                .put_backup_recovery_key(&BackupRecoveryKeyRecord::Empty)?;
        }
        Ok(())
    }

    /// The account entry the roster this device founds starts with: the
    /// recovery key it keeps, if any, with this device writing.
    pub(crate) fn founding_account_entry(
        &self,
        own_slot: DeviceSlotId,
    ) -> Result<AccountEntryV1, AppError> {
        let record = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .backup_recovery_key()?;
        Ok(match record {
            BackupRecoveryKeyRecord::Kept { public_key } => AccountEntryV1 {
                backup_writer: Some(own_slot),
                recovery_public_key: Some(public_key),
            },
            _ => AccountEntryV1::default(),
        })
    }

    /// Carry a lost change again ([`upkeep`]). A failure waits for the next
    /// maintenance pass.
    pub(crate) async fn recovery_key_upkeep(&mut self) {
        if let Err(error) = self.try_recovery_key_upkeep().await {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "recovery_key_upkeep",
                error_kind = error.privacy_safe_kind(),
                "could not settle the recovery key; retrying later"
            );
        }
    }

    pub(crate) async fn try_recovery_key_upkeep(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(());
        }
        let (record, trusted) = self.recovery_key_state()?;
        if !matches!(
            record,
            BackupRecoveryKeyRecord::Confirmed {
                replaces: Some(_),
                ..
            } | BackupRecoveryKeyRecord::TurningOff { .. }
        ) {
            return Ok(());
        }
        let Some((group_id, roster)) = trusted else {
            return Ok(());
        };
        let held = self.epoch_gap_held_groups()?;
        if !self.runtime.device_group_takes_commit(&group_id, &held)? {
            return Ok(());
        }
        let retained = self.runtime.own_account_entry_change_retained(&group_id)?;
        if let Upkeep::Carry { key, replaces } =
            upkeep(record, roster.account.recovery_public_key, retained)
        {
            let own_slot = self.own_slot()?;
            // Busy or unchanged waits for the next pass.
            if let DeviceRosterEdit::Committed(effects) = self
                .commit_account_entry(&group_id, key, Some(replaces), own_slot, &held)
                .await?
            {
                self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                    .await?;
            }
        }
        Ok(())
    }

    /// Commit the account entry of `group_id`'s roster with its key set to
    /// `key`, through the runtime's roster write path, on the entry holding
    /// `replaces`.
    async fn commit_account_entry(
        &mut self,
        group_id: &GroupId,
        key: Option<Vec<u8>>,
        replaces: Option<Vec<u8>>,
        own_slot: DeviceSlotId,
        held: &[GroupId],
    ) -> AccountResult<DeviceRosterEdit> {
        self.runtime
            .edit_roster_account_entry(group_id, held, |entry| {
                // Only on the key the change was made over: any other reads
                // as unchanged, and the change waits.
                if entry.recovery_public_key != replaces {
                    return;
                }
                match key {
                    // Turning backups on makes this device the writer; new
                    // words keep the writer the roster names.
                    Some(key) => {
                        if entry.recovery_public_key.is_none() || entry.backup_writer.is_none() {
                            entry.backup_writer = Some(own_slot);
                        }
                        entry.recovery_public_key = Some(key);
                    }
                    // Turning them off clears the entry.
                    None => *entry = AccountEntryV1::default(),
                }
            })
            .await
    }

    /// After an error, whether the change's commit never went out: the
    /// engine keeps no commit of this device's that changes `group_id`'s
    /// account entry, queued, in flight or sent. Anything unreadable counts
    /// as possibly out, so the change stays.
    fn account_entry_change_never_went_out(&mut self, group_id: &GroupId) -> bool {
        matches!(
            self.runtime.own_account_entry_change_retained(group_id),
            Ok(false)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words of the spec's test vectors.
    #[test]
    fn the_published_vectors_encode_their_words() {
        let mut zero = vec!["abandon"; 11];
        zero.push("about");
        assert_eq!(recovery_words(&[0; RECOVERY_ENTROPY_LEN]), zero);
        assert_eq!(
            recovery_words(&[0x7f; RECOVERY_ENTROPY_LEN]).join(" "),
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
    }

    #[test]
    fn confirming_takes_the_words_at_the_confirm_positions_in_order() {
        let pending = PendingRecoveryWords {
            entropy: Zeroizing::new([0x7f; RECOVERY_ENTROPY_LEN]),
            confirm: [2, 9],
        };
        let words = recovery_words(&[0x7f; RECOVERY_ENTROPY_LEN]);
        let (third, tenth) = (words[2].clone(), words[9].clone());
        assert!(pending.confirmed_by(&[third.clone(), tenth.clone()]));
        assert!(pending.confirmed_by(&[format!(" {} ", third.to_uppercase()), tenth.clone()]));
        assert!(!pending.confirmed_by(&[tenth.clone(), third.clone()]));
        assert!(!pending.confirmed_by(std::slice::from_ref(&third)));
        assert!(!pending.confirmed_by(&[third.clone(), tenth.clone(), tenth]));
        assert!(!pending.confirmed_by(&[third, "zoo".into()]));
    }

    /// Each maintenance pass reads only the key the roster holds, and
    /// carries only while the engine keeps one of this device's
    /// account-entry commits.
    #[test]
    fn upkeep_reads_the_key_the_roster_holds() {
        use BackupRecoveryKeyRecord::{Confirmed, Empty, Kept, TurningOff};
        let key = |byte: u8| Some(vec![byte; 32]);
        let confirmed = |public_key: u8, replaces: Option<u8>| Confirmed {
            public_key: vec![public_key; 32],
            replaces: replaces.map(|byte| vec![byte; 32]),
        };
        let turning_off = TurningOff {
            replaces: vec![2; 32],
        };
        let carry = |key: Option<Vec<u8>>, replaces: u8| Upkeep::Carry {
            key,
            replaces: vec![replaces; 32],
        };
        let cases = [
            (Empty, key(1), true, Upkeep::Nothing),
            (
                Kept {
                    public_key: vec![2; 32],
                },
                None,
                true,
                Upkeep::Nothing,
            ),
            // Words confirmed over the key 1.
            (confirmed(2, Some(1)), key(2), true, Upkeep::Nothing),
            (confirmed(2, Some(1)), key(1), true, carry(key(2), 1)),
            (confirmed(2, Some(1)), key(1), false, Upkeep::Nothing),
            (confirmed(2, Some(1)), key(3), true, Upkeep::Nothing),
            (confirmed(2, Some(1)), None, true, Upkeep::Nothing),
            // Words that turned backups on, or were kept with no device
            // group, are never carried, even over no key.
            (confirmed(2, None), key(2), true, Upkeep::Nothing),
            (confirmed(2, None), None, true, Upkeep::Nothing),
            (confirmed(2, None), key(3), true, Upkeep::Nothing),
            // Turning off over the key 2.
            (turning_off.clone(), key(2), true, carry(None, 2)),
            (turning_off.clone(), key(2), false, Upkeep::Nothing),
            (turning_off.clone(), None, true, Upkeep::Nothing),
            (turning_off, key(3), true, Upkeep::Nothing),
        ];
        for (record, holds, retained, expected) in cases {
            let case = format!("{record:?} while the roster holds {holds:?}, retained {retained}");
            assert_eq!(upkeep(record, holds, retained), expected, "{case}");
        }
    }

    /// Words read as not in use only on a definite no; a failed read shows
    /// them pending, and words the roster holds are never asked about.
    #[test]
    fn words_are_unused_only_on_a_definite_no() {
        let never = || -> Result<bool, ()> { panic!("asked about words the roster holds") };
        assert_eq!(words_status(true, never), WordsStatus::InUse);
        assert_eq!(
            words_status(false, || Ok::<_, ()>(true)),
            WordsStatus::Pending
        );
        assert_eq!(words_status(false, || Err(())), WordsStatus::Pending);
        assert_eq!(
            words_status(false, || Ok::<_, ()>(false)),
            WordsStatus::Unused
        );
    }

    #[test]
    fn new_words_confirm_two_distinct_positions_and_never_print() {
        for _ in 0..64 {
            let pending = PendingRecoveryWords::generate();
            let [first, second] = pending.confirm;
            assert!(first < second && second < RECOVERY_WORD_COUNT);
        }
        let shown = RecoveryWords {
            words: recovery_words(&[0; RECOVERY_ENTROPY_LEN]),
            confirm_positions: vec![1, 12],
        };
        let printed = format!("{shown:?}");
        assert!(!printed.contains("abandon"), "{printed}");
    }
}
