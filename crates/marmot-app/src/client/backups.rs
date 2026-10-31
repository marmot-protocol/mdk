//! Backups' recovery words (mdk#2628 item 4.4a, D34 item 2, D75).
//!
//! An account's backups are sealed to a recovery key that 12 BIP-39 English
//! words derive, separate from the nsec. MDK makes the words and the host
//! shows them once; the user types back the two at positions MDK picks. Only
//! then does this device use anything: the key's public half. The words and
//! the private half live in memory for the flow alone and never reach disk.
//! A client that closes mid-flow starts over with new words.
//!
//! The account's recovery key is its device group's roster account entry;
//! backups are off while it holds none. A device that trusts no device group
//! keeps the key itself, and the roster it founds carries it, naming this
//! device as the backup writer; trusting any device group forgets it, so a
//! joined group's backups stay as they are. In a device group, confirming
//! words or turning backups off commits the account entry through the
//! runtime's one roster write path, as a compare-and-set over the entry this
//! device read, and only while the group can take a commit from this device.
//! Turning backups on makes this device the writer; new words keep the
//! writer the roster names; turning them off clears the entry.
//!
//! Nothing here sends a change again or stores what became of one (D75). The
//! engine re-issues a commit a fork dropped, while the entry it was made over
//! still stands, and the runtime retries one the relays refused; a change
//! whose re-issue is refused stays lost, and settings show the roster as it
//! is, so the user can make it again. An action reports only what it sent.

use std::fmt;

use bip39::Mnemonic;
use cgka_traits::GroupId;
use cgka_traits::app_components::{AccountEntryV1, DeviceSlotId};
use marmot_session::{
    AccountResult, DeviceRosterEdit, DeviceRosterEditBlocked, RECOVERY_ENTROPY_LEN,
};
use rand::RngCore;
use rand::rngs::OsRng;
use rand::seq::index::sample;
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

/// Where the account's backups stand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupSettings {
    /// Whether the account has a recovery key, so its backups are on.
    pub enabled: bool,
    /// Whether this device writes the account's backups.
    pub this_device_writes: bool,
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
    /// their key the account's recovery key. The words are forgotten once
    /// their commit went out, or the roster already holds their key.
    ///
    /// Refused with the words kept for another try: `roster_unsupported`
    /// while device groups are off, `recovery_words_not_started` without
    /// words to confirm, `recovery_words_mismatch` when the typed words
    /// differ, `device_group_busy` while the device group cannot take a
    /// commit from this device or its roster changed meanwhile (retry later),
    /// and `roster_unavailable`. Any other error keeps them too: the commit
    /// may have gone out, and trying again finds its key in the roster.
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
                .keep_recovery_key(&public_key)?;
            self.pending_recovery_words = None;
            return Ok(());
        };
        let held = self.wait_for_own_commits(&group_id)?;
        let read = roster.account.recovery_public_key;
        if read.as_ref() != Some(&public_key) {
            self.change_account_entry(&group_id, Some(public_key), read, &held)
                .await?;
        }
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
    /// commit from this device or its roster changed meanwhile (retry later),
    /// and `roster_unavailable`.
    pub(crate) async fn turn_off_backups(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        self.sync_runtime_groups_for_send("turn_off_backups")
            .await?;
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            self.app
                .account_storage(&self.state.label)?
                .app_storage()
                .forget_kept_recovery_key()?;
            return Ok(());
        };
        let held = self.wait_for_own_commits(&group_id)?;
        let Some(read) = roster.account.recovery_public_key else {
            return Ok(());
        };
        self.change_account_entry(&group_id, None, Some(read), &held)
            .await
    }

    /// The groups an epoch gap holds, once `group_id` can take a commit from
    /// this device; refused with `device_group_busy` until it can. The
    /// device group cannot while a commit of this device's there has no
    /// outcome, one owed a re-issue included, so neither action reports
    /// "nothing to send" while one of this device's changes may still land.
    fn wait_for_own_commits(&mut self, group_id: &GroupId) -> Result<Vec<GroupId>, AppError> {
        let held = self.epoch_gap_held_groups()?;
        if !self.runtime.device_group_takes_commit(group_id, &held)? {
            return Err(AppError::DeviceGroupRefused(
                DeviceRosterEditBlocked::Busy.reason(),
            ));
        }
        Ok(held)
    }

    /// Commit the account entry of `group_id`'s roster with its key set to
    /// `key`, on the entry holding `read`, the key this device read: turning
    /// backups on makes this device the writer, new words keep the writer
    /// the roster names, and no key clears the entry. Refused with
    /// `device_group_busy` while the device group cannot take a commit from
    /// this device, or when the roster no longer holds `read`, and with
    /// `roster_unavailable`; then nothing went out. A commit the relays
    /// refused is the runtime's to retry.
    async fn change_account_entry(
        &mut self,
        group_id: &GroupId,
        key: Option<Vec<u8>>,
        read: Option<Vec<u8>>,
        held: &[GroupId],
    ) -> Result<(), AppError> {
        let own_slot = self.own_slot()?;
        let edit = self
            .commit_account_entry(group_id, key, read, own_slot, held)
            .await;
        if nothing_went_out(&edit) == Some(true) {
            return Err(match edit {
                Ok(DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Unreadable)) => {
                    AppError::DeviceGroupRefused("roster_unavailable")
                }
                _ => AppError::DeviceGroupRefused(DeviceRosterEditBlocked::Busy.reason()),
            });
        }
        if let DeviceRosterEdit::Committed(effects) = edit?
            && let Err(error) = self
                .observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                .await
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "change_account_entry",
                error_kind = error.privacy_safe_kind(),
                "backup settings change not confirmed; the runtime retries it"
            );
        }
        Ok(())
    }

    /// Where the account's backups stand: as the trusted device group's
    /// roster holds them now, or, with none, as this device keeps them.
    /// Refused with `roster_unsupported` while device groups are off, and
    /// with `roster_unavailable` when the trusted roster cannot be read.
    pub(crate) fn backup_settings(&mut self) -> Result<BackupSettings, AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let Some((_, roster)) = self.trusted_device_roster()? else {
            // Without a device group this device keeps the key and writes.
            let on = self
                .app
                .account_storage(&self.state.label)?
                .app_storage()
                .kept_recovery_key()?
                .is_some();
            return Ok(BackupSettings {
                enabled: on,
                this_device_writes: on,
            });
        };
        let enabled = roster.account.recovery_public_key.is_some();
        Ok(BackupSettings {
            enabled,
            this_device_writes: enabled && roster.account.backup_writer == Some(self.own_slot()?),
        })
    }

    /// The account entry the roster this device founds starts with: the
    /// recovery key it keeps, if any, with this device writing.
    pub(crate) fn founding_account_entry(
        &self,
        own_slot: DeviceSlotId,
    ) -> Result<AccountEntryV1, AppError> {
        let kept = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .kept_recovery_key()?;
        Ok(AccountEntryV1 {
            backup_writer: kept.is_some().then_some(own_slot),
            recovery_public_key: kept,
        })
    }

    /// Commit the account entry of `group_id`'s roster with its key set to
    /// `key`, through the runtime's roster write path, on the entry holding
    /// `read`.
    async fn commit_account_entry(
        &mut self,
        group_id: &GroupId,
        key: Option<Vec<u8>>,
        read: Option<Vec<u8>>,
        own_slot: DeviceSlotId,
        held: &[GroupId],
    ) -> AccountResult<DeviceRosterEdit> {
        self.runtime
            .edit_roster_account_entry(group_id, held, |entry| {
                // Only on the key this device read: any other reads as
                // unchanged, and nothing is sent.
                if entry.recovery_public_key != read {
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

    /// The confirm positions are two distinct words, and a debug print
    /// never shows the words.
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
