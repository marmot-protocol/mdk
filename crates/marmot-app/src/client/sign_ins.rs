//! New sign-ins (mdk#2628 item 3.2, D29): a fresh, valid KeyPackage of this
//! account in a slot neither this device nor its device group's roster knows.
//!
//! - **Evidence.** A check reads every slot of the account with the inviter's
//!   read and keeps what an inviter would add: each slot's newest publication,
//!   not deleted, valid, current profile, fresh. Nothing else raises a prompt,
//!   and a `client` tag only labels one. A check that reached no relay proves
//!   nothing.
//! - **When.** At open, every six hours, on a live KeyPackage of this account
//!   from the directory subscription (a nudge only: the check's read is the
//!   evidence), and when the host asks.
//! - **Before or after this device.** This device's first check takes a
//!   baseline: every slot its read returns, whether or not the slot counts
//!   then, is a device that was here first ("do you still have it?"). Every
//!   other slot is a new sign-in ("Was this you?"). Publication times,
//!   freshness included, never decide which, since the key holder chooses
//!   them.
//! - **Answers.** Not now keeps it listed. Reject records the slot as
//!   rejected (`not_me`) in the trusted device group's roster, in one commit
//!   made once that group is quiet. A device with no device group keeps the
//!   rejection here; it goes into the founding roster when this device
//!   creates one, and is committed once this device trusts one it joined. A
//!   slot the roster cannot name (a `d` that is not 32 bytes of lowercase
//!   hex) is rejected here only. Linking is device pairing's (3.3b).
//! - **Keeping a rejection.** A device keeps its rejection until the roster
//!   holds the slot as a device, which means the user confirmed a link of
//!   it. Until then it commits the rejection again whenever the roster has
//!   no entry for the slot, and it never replaces an entry.
//! - **Slots.** A slot is its `d` exactly as published, compared as bytes the
//!   way relays compare it. A rejection names the slot alone, never its
//!   KeyPackage, and a rejected KeyPackage never makes another slot rejected:
//!   whoever holds the account key can copy any KeyPackage, a real device's
//!   included, into a slot the user rejects. Rejected KeyPackages are Scene
//!   8's (3.7).
//! - **Any one device's answer.** A prompt for a slot another device linked or
//!   rejected stays up, saying so, until dismissed. That answer holds only
//!   while the roster does: a sign-in dismissed here is listed again once the
//!   roster has no entry for its slot.
//! - **Gone.** A sign-in whose slot a complete read finds holding no valid
//!   KeyPackage, fresh or not, stays listed, marked as no longer signed in.
//!   A stale publication never signs a slot out, and only a complete read
//!   changes that mark.
//!
//! Everything here runs only while device groups are on.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceRosterV1, DeviceSlotId, RejectedSlotReasonV1, RejectedSlotV1,
};
use cgka_traits::storage::MaintenanceStorage as _;
use storage_sqlite::{ObservedSignIn, SignInAnswer, SignInCheck, SignInRecord, SqliteAppStorage};

use super::AppClient;
use super::device_group::device_slot;
use crate::{AppError, unix_now_seconds};

/// How often a running device reads its account's slots.
const SIGN_IN_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// How soon a check that failed runs again.
const SIGN_IN_CHECK_RETRY: Duration = Duration::from_secs(10 * 60);
/// The least time between two checks a live KeyPackage asked for.
const SIGN_IN_NUDGE_INTERVAL: Duration = Duration::from_secs(60);

/// A sign-in this device does not recognize, as the host lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnrecognizedSignIn {
    /// The sign-in's KeyPackage slot (the Nostr `d`) as published: 64
    /// lowercase hex characters for every well-formed slot. Answers name it by
    /// this.
    pub slot_id_hex: String,
    /// The client name the sign-in reports for itself; empty when it reports
    /// none. Display only.
    pub client: String,
    /// When it appeared, in Unix seconds: its earliest publication this device
    /// saw, never later than when this device first saw it.
    pub appeared_at: u64,
    /// When it last refreshed its KeyPackage, in Unix seconds. That is all a
    /// device outside the device group can know of it.
    pub last_seen_at: u64,
    /// This device's first check found it: a device that was signed in before
    /// this one. Its prompt asks whether the user still has it, not whether
    /// it was them.
    pub before_this_device: bool,
    /// Whether its slot still holds a fresh, valid KeyPackage. A complete
    /// read that finds none clears it; the sign-in stays listed.
    pub signed_in: bool,
    pub state: UnrecognizedSignInState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnrecognizedSignInState {
    /// Waiting for an answer.
    Prompt,
    /// Answered Not now: listed with no prompt.
    NotNow,
    /// Another device linked it, while its prompt here waited. Dismiss ends
    /// the prompt. `linked_by_slot_id_hex` is the linking device's slot.
    LinkedElsewhere {
        linked_by_slot_id_hex: Option<String>,
    },
    /// Another device rejected it, while its prompt here waited. Dismiss
    /// ends the prompt.
    RejectedElsewhere,
}

/// An answer to an unrecognized sign-in. Linking it is device pairing's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInResponse {
    /// Keep it listed, with no prompt.
    NotNow,
    /// It was not the user: record its slot as rejected.
    Reject,
    /// End a prompt another device already answered.
    Dismiss,
}

/// How a check classified one slot. Only [`SlotOutcome::Unrecognized`]
/// reaches the host; Scene 8's warning (3.7) reads the others.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SlotOutcome {
    /// This device's slot, holding a KeyPackage it made.
    OwnSlot,
    /// This device's slot, holding a KeyPackage it did not make.
    OwnSlotForeign,
    /// A roster device's slot. `announced` compares the KeyPackage with the
    /// one its roster entry announces now. A device announces each
    /// KeyPackage before publishing it (3.4), so a slot still serving the
    /// previous one differs until this device keeps the announcements it
    /// has seen (D31 item 7).
    KnownDevice {
        announced: Announcement,
    },
    /// A slot the roster or this device rejected, or a rejected KeyPackage
    /// in a roster device's slot.
    Rejected,
    Unrecognized,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Announcement {
    Matches,
    Differs,
    None,
}

/// What one check found: each slot's outcome, by slot.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SignInCheckReport {
    pub(crate) slots: BTreeMap<String, SlotOutcome>,
    pub(crate) complete: bool,
}

/// When an account's devices next check for sign-ins. Ephemeral: a new
/// client checks on its first maintenance pass.
#[derive(Debug, Default)]
pub(crate) struct SignInSchedule {
    due: Option<Instant>,
    pub(crate) last: Option<Instant>,
}

/// Live KeyPackages of local accounts, from the directory subscription, that
/// their clients have not checked yet. Only an account whose client has
/// checked is tracked, so other accounts' KeyPackages cost nothing.
#[derive(Debug, Default)]
pub(crate) struct SignInNudges(std::sync::Mutex<BTreeMap<String, bool>>);

impl SignInNudges {
    /// A KeyPackage `account_id_hex` published arrived live.
    pub(crate) fn nudge(&self, account_id_hex: &str) {
        if let Ok(mut accounts) = self.0.lock()
            && let Some(nudged) = accounts.get_mut(account_id_hex)
        {
            *nudged = true;
        }
    }

    /// Whether a KeyPackage of `account_id_hex` arrived since the last call.
    /// The first call starts tracking the account.
    fn take(&self, account_id_hex: &str) -> bool {
        self.0.lock().is_ok_and(|mut accounts| {
            std::mem::take(accounts.entry(account_id_hex.to_owned()).or_default())
        })
    }
}

/// This device's slot and every KeyPackage it made that may still be
/// published there.
#[derive(Debug, Default)]
struct OwnKeyPackages {
    slot: Option<String>,
    refs: BTreeSet<String>,
}

impl AppClient {
    /// Check for sign-ins when one is due: at the first maintenance pass, six
    /// hours after the last, and within a minute of a live KeyPackage of this
    /// account. Then commit any rejection the roster still lacks.
    pub(crate) async fn drive_sign_ins(&mut self) {
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return;
        }
        let now = Instant::now();
        let account_id_hex = hex::encode(self.runtime.self_id().as_slice());
        if self.app.sign_in_nudges.take(&account_id_hex) {
            let schedule = &mut self.sign_in_schedule;
            let earliest = schedule
                .last
                .map_or(now, |last| last + SIGN_IN_NUDGE_INTERVAL);
            schedule.due = Some(schedule.due.map_or(earliest, |due| due.min(earliest)));
        }
        if self.sign_in_schedule.due.is_none_or(|due| now >= due) {
            let next = match self.check_sign_ins().await {
                Ok(_) => SIGN_IN_CHECK_INTERVAL,
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::client::sign_ins",
                        method = "check_sign_ins",
                        error_kind = error.privacy_safe_kind(),
                        "could not check the account's key packages for new sign-ins; retrying later"
                    );
                    SIGN_IN_CHECK_RETRY
                }
            };
            self.sign_in_schedule.last = Some(now);
            self.sign_in_schedule.due = Some(now + next);
        }
        if let Err(error) = self.commit_sign_in_rejections().await {
            tracing::warn!(
                target: "marmot_app::client::sign_ins",
                method = "commit_sign_in_rejections",
                error_kind = error.privacy_safe_kind(),
                "could not record sign-in rejections in the device group; retrying later"
            );
        }
    }

    /// Read every slot of the account and record each unrecognized one. See
    /// the module docs for what counts.
    pub(crate) async fn check_sign_ins(&mut self) -> Result<SignInCheckReport, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(SignInCheckReport::default());
        }
        let read = self
            .app
            .read_account_key_package_slots(&self.state.label)
            .await?;
        if !read.reached {
            return Err(AppError::DeviceGroupRefused("key_packages_unreachable"));
        }
        let own = self.own_key_packages()?;
        let roster = self.trusted_device_roster()?.map(|(_, roster)| roster);
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let rejected_here = rejected_slots_here(&storage.sign_ins()?);

        let mut report = SignInCheckReport {
            slots: BTreeMap::new(),
            complete: read.complete,
        };
        let mut unrecognized = Vec::new();
        for slot_key_package in read.key_packages {
            let fetched = slot_key_package.fetched;
            let slot_hex = fetched.key_package_id;
            let outcome = classify(
                &slot_hex,
                &fetched.key_package_ref_hex,
                &own,
                roster.as_ref(),
                &rejected_here,
            );
            if outcome == SlotOutcome::Unrecognized {
                unrecognized.push(ObservedSignIn {
                    slot_id_hex: slot_hex.clone(),
                    client: slot_key_package.client.unwrap_or_default(),
                    published_at: fetched.created_at,
                    key_package_event_id_hex: fetched.key_package_event_id,
                    key_package_ref_hex: fetched.key_package_ref_hex,
                });
            }
            report.slots.insert(slot_hex, outcome);
        }
        if storage.record_sign_in_check(&SignInCheck {
            unrecognized: &unrecognized,
            present_slots: &read.current_slots,
            returned_slots: &read.returned_slots,
            complete: read.complete,
            now: unix_now_seconds(),
        })? {
            self.unrecognized_sign_ins_changed = true;
        }
        tracing::debug!(
            target: "marmot_app::client::sign_ins",
            method = "check_sign_ins",
            unrecognized = unrecognized.len(),
            complete = read.complete,
            "checked the account's key packages for new sign-ins"
        );
        Ok(report)
    }

    /// Check now, for the host, and restart the six-hour clock from this
    /// check. Returns the sign-ins listed after it. A read that reached no
    /// relay is `key_packages_unreachable` and leaves the schedule alone.
    pub(crate) async fn check_sign_ins_now(&mut self) -> Result<Vec<UnrecognizedSignIn>, AppError> {
        let now = Instant::now();
        self.check_sign_ins().await?;
        self.sign_in_schedule.last = Some(now);
        self.sign_in_schedule.due = Some(now + SIGN_IN_CHECK_INTERVAL);
        self.unrecognized_sign_ins()
    }

    /// The sign-ins this device does not recognize, the earliest to appear
    /// first. Empty while device groups are off.
    pub(crate) fn unrecognized_sign_ins(&mut self) -> Result<Vec<UnrecognizedSignIn>, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(Vec::new());
        }
        let own_slot = self.own_key_packages()?.slot;
        let roster = self.trusted_device_roster()?.map(|(_, roster)| roster);
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        Ok(storage
            .sign_ins()?
            .into_iter()
            .filter_map(|record| {
                let state = listed_state(&record, roster.as_ref(), own_slot.as_deref())?;
                Some(UnrecognizedSignIn {
                    slot_id_hex: record.slot_id_hex,
                    client: record.client,
                    appeared_at: record.appeared_at,
                    last_seen_at: record.last_published_at,
                    before_this_device: record.before_this_device,
                    signed_in: record.signed_in,
                    state,
                })
            })
            .collect())
    }

    /// Answer the unrecognized sign-in in `slot_id_hex`. A rejection is
    /// recorded here first, then committed to the device group's roster when
    /// one is trusted and quiet; maintenance retries what this call could not.
    pub(crate) async fn answer_sign_in(
        &mut self,
        slot_id_hex: &str,
        response: SignInResponse,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let listed = self
            .unrecognized_sign_ins()?
            .into_iter()
            .find(|sign_in| sign_in.slot_id_hex == slot_id_hex)
            .ok_or(AppError::DeviceGroupRefused("sign_in_unknown"))?;
        let answered_elsewhere = matches!(
            listed.state,
            UnrecognizedSignInState::LinkedElsewhere { .. }
                | UnrecognizedSignInState::RejectedElsewhere
        );
        let (from, to): (&[SignInAnswer], _) = match response {
            SignInResponse::Dismiss if answered_elsewhere => {
                (&[SignInAnswer::Unanswered], SignInAnswer::Dismissed)
            }
            SignInResponse::Dismiss => {
                return Err(AppError::DeviceGroupRefused("sign_in_unanswered"));
            }
            _ if answered_elsewhere => {
                return Err(AppError::DeviceGroupRefused("sign_in_answered_elsewhere"));
            }
            // A dismissed sign-in is listed again once the roster drops the
            // answer it saw.
            SignInResponse::NotNow => (
                &[SignInAnswer::Unanswered, SignInAnswer::Dismissed],
                SignInAnswer::NotNow,
            ),
            SignInResponse::Reject => (
                &[
                    SignInAnswer::Unanswered,
                    SignInAnswer::NotNow,
                    SignInAnswer::Dismissed,
                ],
                SignInAnswer::Rejected,
            ),
        };
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        if !storage.answer_sign_in(&listed.slot_id_hex, from, to, unix_now_seconds())? {
            return Err(AppError::DeviceGroupRefused("sign_in_answered"));
        }
        self.unrecognized_sign_ins_changed = true;
        if to == SignInAnswer::Rejected
            && let Err(error) = self.commit_sign_in_rejections().await
        {
            tracing::warn!(
                target: "marmot_app::client::sign_ins",
                method = "answer_sign_in",
                error_kind = error.privacy_safe_kind(),
                "recorded a sign-in rejection; the device group's roster gets it later"
            );
        }
        Ok(())
    }

    /// Commit every rejection this device made that the trusted device
    /// group's roster lacks, in one roster update through the runtime's
    /// rejected-slot write, once that group can take a commit from this
    /// device. A rejection the roster records is settled here, and one of a
    /// slot the roster holds as a device ends: the user confirmed a link of
    /// it. With no trusted device group, rejections stay here.
    pub(crate) async fn commit_sign_in_rejections(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let records = storage.sign_ins()?;
        let pending: Vec<_> = records
            .iter()
            .filter(|record| record.roster_pending)
            .collect();
        if pending.is_empty() {
            return Ok(());
        }
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let mut rejections = Vec::new();
        for record in pending {
            if linked(record, &roster) {
                end_rejection(&storage, record)?;
                continue;
            }
            match rejected_slot(record, &roster)? {
                Some(rejection) => rejections.push(rejection),
                None => {
                    storage.settle_sign_in_rejection(&record.slot_id_hex)?;
                }
            }
        }
        if rejections.is_empty() {
            return Ok(());
        }
        let held = self.epoch_gap_held_groups()?;
        let context = Self::local_human_action_context(
            "reject_sign_in",
            vec!["app_component"],
            vec![DEVICE_ROSTER_COMPONENT_ID],
            None,
        );
        let effects = self
            .runtime
            .reject_device_slots(&group_id, &held, rejections, context)
            .await?;
        self.observe_drained_session_events(&effects).await?;
        Ok(())
    }

    /// Whether the unrecognized sign-ins may have changed since the last
    /// call. Set at open, by a check or answer that changed them, and with
    /// every roster change ([`Self::note_device_roster_changed`]).
    pub(crate) fn take_unrecognized_sign_ins_changed(&mut self) -> bool {
        std::mem::take(&mut self.unrecognized_sign_ins_changed) && self.app.device_groups_enabled()
    }

    /// The device group changed, or convergence superseded a roster update
    /// this device made. A rejection of a slot the roster now holds as a
    /// device ends at once: the user confirmed that link, and if branch
    /// selection drops it before the next pass, the device asks again rather
    /// than restore the rejection. Every other rejection is checked against
    /// the roster again, so one the roster lost is committed anew. A rejection
    /// settled from another device's commit is lost if that commit later
    /// loses convergence, and that device may never come back to repair it.
    pub(crate) fn recheck_sign_in_rejections(&mut self) {
        let ended = self.trusted_device_roster().and_then(|roster| {
            let Some((_, roster)) = roster else {
                return Ok(());
            };
            let storage = self.app.account_storage(&self.state.label)?.app_storage();
            for record in storage.sign_ins()? {
                if record.answer == SignInAnswer::Rejected && linked(&record, &roster) {
                    end_rejection(&storage, &record)?;
                }
            }
            Ok(())
        });
        let rearmed = ended.and_then(|()| {
            Ok(self
                .app
                .account_storage(&self.state.label)?
                .app_storage()
                .rearm_sign_in_rejections()?)
        });
        if let Err(error) = rearmed {
            tracing::warn!(
                target: "marmot_app::client::sign_ins",
                method = "recheck_sign_in_rejections",
                error_kind = error.privacy_safe_kind(),
                "could not recheck sign-in rejections after a device group change"
            );
        }
    }

    /// Rejections this device made while it had no device group, for the
    /// founding roster of the one it creates: every one but the slot it is
    /// linking, which the user just confirmed. The commit that settles them
    /// reads that roster.
    pub(crate) fn founding_sign_in_rejections(
        &self,
        roster: &mut DeviceRosterV1,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        for record in storage.sign_ins()? {
            if !record.roster_pending {
                continue;
            }
            if let Some((slot, rejected)) = rejected_slot(&record, roster)? {
                roster.rejected_slots.insert(slot, rejected);
            }
        }
        Ok(())
    }

    fn own_key_packages(&self) -> Result<OwnKeyPackages, AppError> {
        let Some(lifecycle) = self
            .app
            .account_storage(&self.state.label)?
            .key_package_lifecycle()?
        else {
            return Ok(OwnKeyPackages::default());
        };
        let refs = lifecycle
            .current_key_package_ref
            .iter()
            .chain(
                lifecycle
                    .pending_replacement
                    .iter()
                    .map(|pending| &pending.key_package_ref),
            )
            .chain(
                lifecycle
                    .retained_private_material
                    .iter()
                    .map(|material| &material.key_package_ref),
            )
            .map(hex::encode)
            .collect();
        Ok(OwnKeyPackages {
            slot: Some(lifecycle.stable_slot_id),
            refs,
        })
    }
}

/// The slots this device rejected.
fn rejected_slots_here(records: &[SignInRecord]) -> BTreeSet<String> {
    records
        .iter()
        .filter(|record| record.answer == SignInAnswer::Rejected)
        .map(|record| record.slot_id_hex.clone())
        .collect()
}

fn classify(
    slot_hex: &str,
    key_package_ref_hex: &str,
    own: &OwnKeyPackages,
    roster: Option<&DeviceRosterV1>,
    rejected_slots: &BTreeSet<String>,
) -> SlotOutcome {
    if own.slot.as_deref() == Some(slot_hex) {
        return if own.refs.contains(key_package_ref_hex) {
            SlotOutcome::OwnSlot
        } else {
            SlotOutcome::OwnSlotForeign
        };
    }
    let slot = roster_slot(slot_hex);
    let key_package_ref = hex::decode(key_package_ref_hex).ok();
    if roster
        .is_some_and(|roster| slot.is_some_and(|slot| roster.rejected_slots.contains_key(&slot)))
    {
        return SlotOutcome::Rejected;
    }
    let device = roster
        .zip(slot)
        .and_then(|(roster, slot)| roster.devices.get(&slot).map(|device| (roster, device)));
    if let Some((roster, device)) = device {
        // A rejected KeyPackage in a device's slot is rejected, not the device.
        if key_package_ref.as_ref().is_some_and(|key_package_ref| {
            roster.rejected_key_packages.contains_key(key_package_ref)
        }) {
            return SlotOutcome::Rejected;
        }
        return SlotOutcome::KnownDevice {
            announced: match &device.announced_key_package {
                None => Announcement::None,
                Some(announced) if key_package_ref.as_ref() == Some(announced) => {
                    Announcement::Matches
                }
                Some(_) => Announcement::Differs,
            },
        };
    }
    // A rejected KeyPackage elsewhere rejects nothing here: it may be a real
    // device's, copied into the slot the user rejected.
    if rejected_slots.contains(slot_hex) {
        SlotOutcome::Rejected
    } else {
        SlotOutcome::Unrecognized
    }
}

/// The roster's name for `slot_hex`: only a `d` of 32 bytes in lowercase
/// hex, so no other spelling of a device's slot passes for it.
fn roster_slot(slot_hex: &str) -> Option<DeviceSlotId> {
    device_slot(slot_hex)
        .ok()
        .filter(|slot| hex::encode(slot) == slot_hex)
}

/// How `record` is listed, if it is. A sign-in this device rejected is not,
/// nor one it dismissed while the roster has an entry for its slot. One
/// another device answered keeps its prompt, saying so, only while that
/// prompt waited here for a new sign-in. A device that was
/// here before this one, or a sign-in this device put off or linked itself,
/// leaves the list once the roster answers it.
fn listed_state(
    record: &SignInRecord,
    roster: Option<&DeviceRosterV1>,
    own_slot: Option<&str>,
) -> Option<UnrecognizedSignInState> {
    let waiting = match record.answer {
        SignInAnswer::Unanswered => UnrecognizedSignInState::Prompt,
        SignInAnswer::NotNow => UnrecognizedSignInState::NotNow,
        SignInAnswer::Rejected => return None,
        // Another device's answer, or a link that ended this device's
        // rejection, holds only while the roster does: then ask again.
        SignInAnswer::Dismissed => {
            if roster
                .zip(roster_slot(&record.slot_id_hex))
                .is_some_and(|(roster, slot)| {
                    roster.devices.contains_key(&slot) || roster.rejected_slots.contains_key(&slot)
                })
            {
                return None;
            }
            UnrecognizedSignInState::Prompt
        }
    };
    let Some((roster, slot)) = roster.zip(roster_slot(&record.slot_id_hex)) else {
        return Some(waiting);
    };
    let keeps_prompt = waiting == UnrecognizedSignInState::Prompt && !record.before_this_device;
    if let Some(device) = roster.devices.get(&slot) {
        let linked_by = device.linked_by.map(hex::encode);
        return (keeps_prompt && linked_by.as_deref() != own_slot).then_some(
            UnrecognizedSignInState::LinkedElsewhere {
                linked_by_slot_id_hex: linked_by,
            },
        );
    }
    if roster.rejected_slots.contains_key(&slot) {
        return keeps_prompt.then_some(UnrecognizedSignInState::RejectedElsewhere);
    }
    Some(waiting)
}

/// Whether the roster holds `record`'s slot as a device: the user confirmed
/// a link of it, which ends a rejection of it.
fn linked(record: &SignInRecord, roster: &DeviceRosterV1) -> bool {
    roster_slot(&record.slot_id_hex).is_some_and(|slot| roster.devices.contains_key(&slot))
}

/// End `record`'s rejection: a link of its slot overrode it. The sign-in is
/// listed again if the roster later has no entry for the slot.
fn end_rejection(storage: &SqliteAppStorage, record: &SignInRecord) -> Result<(), AppError> {
    storage.answer_sign_in(
        &record.slot_id_hex,
        &[SignInAnswer::Rejected],
        SignInAnswer::Dismissed,
        unix_now_seconds(),
    )?;
    Ok(())
}

/// The rejected slot that records `record`'s rejection, if the roster has no
/// entry for its slot: a rejection never replaces a device or another
/// rejected slot, a `removed` one included. A slot the roster cannot name
/// stays rejected here only.
fn rejected_slot(
    record: &SignInRecord,
    roster: &DeviceRosterV1,
) -> Result<Option<(DeviceSlotId, RejectedSlotV1)>, AppError> {
    let Some(slot) = roster_slot(&record.slot_id_hex) else {
        return Ok(None);
    };
    if roster.devices.contains_key(&slot) || roster.rejected_slots.contains_key(&slot) {
        return Ok(None);
    }
    let rejected_at = record
        .answered_at
        .ok_or(AppError::DeviceGroupRefused("sign_in_unknown"))?;
    Ok(Some((
        slot,
        RejectedSlotV1 {
            reason: RejectedSlotReasonV1::NotMe,
            rejected_at,
            tag_signature_key: None,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::app_components::{DeviceEntryV1, RejectedKeyPackageV1};

    fn slot(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn key_package(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn record(byte: u8, answer: SignInAnswer, before_this_device: bool) -> SignInRecord {
        SignInRecord {
            slot_id_hex: slot(byte),
            before_this_device,
            client: String::new(),
            appeared_at: 1,
            last_published_at: 2,
            key_package_event_id_hex: String::new(),
            key_package_ref_hex: key_package(byte),
            signed_in: true,
            answer,
            answered_at: (answer != SignInAnswer::Unanswered).then_some(3),
            roster_pending: answer == SignInAnswer::Rejected,
        }
    }

    /// The roster: this device (slot 1) linked slot 2, announcing
    /// KeyPackage 2; slot 3 and KeyPackage 9 are rejected.
    fn roster() -> DeviceRosterV1 {
        let mut roster = DeviceRosterV1::default();
        roster.devices.insert([1; 32], DeviceEntryV1::default());
        roster.devices.insert(
            [2; 32],
            DeviceEntryV1 {
                linked_by: Some([1; 32]),
                announced_key_package: Some(vec![2; 32]),
                ..DeviceEntryV1::default()
            },
        );
        roster.devices.insert(
            [4; 32],
            DeviceEntryV1 {
                linked_by: Some([2; 32]),
                ..DeviceEntryV1::default()
            },
        );
        roster.rejected_slots.insert(
            [3; 32],
            RejectedSlotV1 {
                reason: RejectedSlotReasonV1::NotMe,
                rejected_at: 1,
                tag_signature_key: None,
            },
        );
        roster.rejected_key_packages.insert(
            vec![9; 32],
            RejectedKeyPackageV1 {
                slot: [2; 32],
                rejected_at: 1,
            },
        );
        roster
    }

    #[test]
    fn a_slot_is_classified_by_its_slot_and_key_package() {
        let own = OwnKeyPackages {
            slot: Some(slot(1)),
            refs: BTreeSet::from([key_package(1)]),
        };
        let roster = roster();
        let none = Default::default();
        let classify = |slot_byte, key_package_byte, roster| {
            classify(
                &slot(slot_byte),
                &key_package(key_package_byte),
                &own,
                roster,
                &none,
            )
        };
        assert_eq!(classify(1, 1, Some(&roster)), SlotOutcome::OwnSlot);
        assert_eq!(classify(1, 7, Some(&roster)), SlotOutcome::OwnSlotForeign);
        assert_eq!(
            classify(2, 2, Some(&roster)),
            SlotOutcome::KnownDevice {
                announced: Announcement::Matches
            }
        );
        assert_eq!(
            classify(2, 7, Some(&roster)),
            SlotOutcome::KnownDevice {
                announced: Announcement::Differs
            }
        );
        assert_eq!(
            classify(4, 7, Some(&roster)),
            SlotOutcome::KnownDevice {
                announced: Announcement::None
            }
        );
        // A rejected KeyPackage in a device's slot is rejected, not the
        // device.
        assert_eq!(classify(2, 9, Some(&roster)), SlotOutcome::Rejected);
        assert_eq!(classify(3, 3, Some(&roster)), SlotOutcome::Rejected);
        assert_eq!(classify(5, 5, Some(&roster)), SlotOutcome::Unrecognized);
        // A rejected KeyPackage in any other slot leaves that slot a sign-in.
        assert_eq!(classify(5, 9, Some(&roster)), SlotOutcome::Unrecognized);
        // Without a roster, every other slot is unrecognized unless rejected
        // here.
        assert_eq!(classify(2, 2, None), SlotOutcome::Unrecognized);
        // A slot is its `d` as published: another spelling of a device's slot
        // is not that device.
        let mut with_letters = roster.clone();
        with_letters
            .devices
            .insert([0xab; 32], DeviceEntryV1::default());
        for (spelling, outcome) in [
            (
                slot(0xab),
                SlotOutcome::KnownDevice {
                    announced: Announcement::None,
                },
            ),
            (slot(0xab).to_uppercase(), SlotOutcome::Unrecognized),
        ] {
            assert_eq!(
                super::classify(&spelling, &key_package(7), &own, Some(&with_letters), &none),
                outcome
            );
        }
        // A slot rejected here is rejected whatever it holds; its KeyPackage
        // in another slot leaves that slot a sign-in.
        let here = rejected_slots_here(&[record(5, SignInAnswer::Rejected, false)]);
        for (slot_byte, key_package_byte, outcome) in [
            (5, 6, SlotOutcome::Rejected),
            (6, 5, SlotOutcome::Unrecognized),
        ] {
            assert_eq!(
                super::classify(
                    &slot(slot_byte),
                    &key_package(key_package_byte),
                    &own,
                    None,
                    &here
                ),
                outcome
            );
        }
    }

    #[test]
    fn only_a_waiting_new_sign_in_keeps_its_prompt_once_another_device_answers() {
        let roster = roster();
        let own = slot(1);
        let listed = |byte, answer, before| {
            listed_state(&record(byte, answer, before), Some(&roster), Some(&own))
        };
        use SignInAnswer::*;
        use UnrecognizedSignInState as State;
        assert_eq!(
            listed(4, Unanswered, false),
            Some(State::LinkedElsewhere {
                linked_by_slot_id_hex: Some(slot(2))
            })
        );
        assert_eq!(listed(3, Unanswered, false), Some(State::RejectedElsewhere));
        // This device linked it.
        assert_eq!(listed(2, Unanswered, false), None);
        // A device that was here before this one, or one put off.
        assert_eq!(listed(4, Unanswered, true), None);
        assert_eq!(listed(3, Unanswered, true), None);
        assert_eq!(listed(4, NotNow, false), None);
        assert_eq!(listed(3, NotNow, false), None);
        // Answered here. A dismissal holds only while the roster has an entry
        // for the slot.
        assert_eq!(listed(5, Rejected, false), None);
        assert_eq!(listed(3, Dismissed, false), None);
        assert_eq!(listed(4, Dismissed, false), None);
        assert_eq!(listed(5, Dismissed, false), Some(State::Prompt));
        assert_eq!(
            listed_state(&record(3, Dismissed, false), None, Some(&own)),
            Some(State::Prompt)
        );
        // Unknown to the roster.
        assert_eq!(listed(5, Unanswered, true), Some(State::Prompt));
        assert_eq!(listed(5, NotNow, false), Some(State::NotNow));
        assert_eq!(
            listed_state(&record(4, Unanswered, false), None, Some(&own)),
            Some(State::Prompt)
        );
        // A slot the roster cannot name stays listed.
        let mut unnamed = record(4, Unanswered, false);
        unnamed.slot_id_hex = "not-a-slot".into();
        assert_eq!(
            listed_state(&unnamed, Some(&roster), Some(&own)),
            Some(State::Prompt)
        );
    }

    #[test]
    fn a_rejection_the_roster_lacks_becomes_its_slot() {
        let roster = roster();
        let rejected = rejected_slot(&record(5, SignInAnswer::Rejected, false), &roster).unwrap();
        assert_eq!(
            rejected,
            Some((
                [5; 32],
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::NotMe,
                    rejected_at: 3,
                    tag_signature_key: None,
                }
            ))
        );
        // Recorded already, linked by another device, or a slot the roster
        // cannot name: nothing to commit.
        for byte in [3, 4, 6] {
            let mut rejected = record(byte, SignInAnswer::Rejected, false);
            if byte == 6 {
                rejected.slot_id_hex = "not-a-slot".into();
            }
            assert_eq!(rejected_slot(&rejected, &roster).unwrap(), None);
        }
    }

    #[test]
    fn a_nudge_counts_only_for_an_account_that_checked() {
        let nudges = SignInNudges::default();
        nudges.nudge("aa");
        assert!(!nudges.take("aa"));
        nudges.nudge("aa");
        assert!(nudges.take("aa"));
        assert!(!nudges.take("aa"));
        nudges.nudge("bb");
        assert!(!nudges.take("bb"));
    }
}
