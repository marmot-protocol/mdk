//! Linking a new device of this account (mdk#2628 item 3.3b): the code
//! exchange through the account runtime, and joining the device group once
//! both users confirmed.
//!
//! - The new device names its published KeyPackage, shows the seven emoji
//!   once a device already signed in answers, and confirms only after that
//!   device's confirmation verified (D26). It then joins only through a
//!   Welcome into the device group that confirmation named, from the leaf it
//!   named, for a bounded time (D28).
//! - A device already signed in answers a request only after it found and
//!   validated the named KeyPackage, checked that it supports everything the
//!   device group requires, and checked the 20-device cap. Its user's Link
//!   device carries the new device's label and two settings. Once the new
//!   device's confirmation verifies, it creates the device group on a first
//!   link, or adds the device in one commit to the one it trusts (D21). That
//!   commit is the approval, and its Welcome goes out once it is confirmed.
//! - Holding the account key never authenticates a device: only the code
//!   compared on both screens does.
//!
//! Pairing is unreleased: without `unreleased-device-pairing` every call is
//! refused, and with it nothing runs unless `dev_device_groups` is on.

use super::AppClient;
use crate::AppError;

#[cfg(feature = "unreleased-device-pairing")]
mod live;
#[cfg(feature = "unreleased-device-pairing")]
pub(crate) use live::{DevicePairing, PairingInbox};

/// One emoji of the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkEmoji {
    pub emoji: String,
    /// Matrix's English description, for screen readers. Users compare the
    /// pictures, not the descriptions, which differ between languages.
    pub description: String,
}

/// The new device's side of a link, as its screen shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewDeviceLinkState {
    /// Waiting for a device already signed in to answer. Ask the user to
    /// open the app there.
    WaitingForAnswer,
    /// Both screens show `code`. Offer "They match" and cancel.
    Comparing {
        code: Vec<DeviceLinkEmoji>,
    },
    /// This user confirmed; the other device's user has not yet.
    WaitingForOtherDevice,
    /// Both users confirmed. Waiting for the other device to add this one.
    Joining,
    /// This device joined the account's device group. The device that added
    /// it shows the link made once this device's first change there reaches
    /// it.
    Linked,
    Ended {
        reason: DeviceLinkEndReason,
    },
}

/// Why a link ended without one device adding the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLinkEndReason {
    /// This device's user cancelled.
    Cancelled,
    /// The other device cancelled, or its user chose Not now.
    CancelledElsewhere,
    /// A user said the codes differ.
    CodesDiffer,
    /// The exchange failed a check, so the code can't be trusted.
    VerificationFailed,
    /// Time ran out.
    TimedOut,
    /// Another device of this account is linking the sign-in.
    AnsweredElsewhere,
    /// The sign-in's client can't join the device group.
    CannotLink,
    /// The sign-in was rejected on one of this account's devices.
    Rejected,
    /// Both users confirmed, but adding the device failed, or the new device
    /// made no change in the device group within an hour of being added, so
    /// the device that added it removed it again.
    LinkFailed,
}

/// A new sign-in this device can link, as its prompt shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkPrompt {
    /// Opaque local id for [`DeviceLinkOp::Link`] and
    /// [`DeviceLinkOp::Decline`]. Never a pairing session id.
    pub prompt_id: String,
    /// The sign-in's KeyPackage slot (the Nostr `d`, hex), once its
    /// KeyPackage was found. New sign-ins are keyed by it.
    pub slot_id_hex: Option<String>,
    /// When the request arrived, in Unix seconds.
    pub requested_at: u64,
    pub state: DeviceLinkPromptState,
}

/// Where a prompt stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceLinkPromptState {
    /// Checking the sign-in's KeyPackage, or waiting for the code.
    Preparing,
    /// Both screens show `code`. Offer Link device and Not now.
    Comparing {
        code: Vec<DeviceLinkEmoji>,
    },
    /// More than one sign-in asked to link at once, so Link is offered for
    /// none of them.
    CompetingRequests,
    /// This device answered too many link requests lately. It tries again at
    /// `retry_at`, in Unix seconds.
    RateLimited {
        retry_at: u64,
    },
    /// The sign-in's client can't join the device group. `missing` names
    /// what it lacks.
    CannotLink {
        missing: Vec<String>,
    },
    /// The account has 20 linked devices. Remove one first.
    TooManyDevices,
    /// This user chose Link device. Waiting for the new device's
    /// confirmation, then, for up to an hour, for it to join and make its
    /// first change in the device group.
    Linking,
    /// This device added it, and the new device's first change in the device
    /// group arrived.
    Linked,
    /// Another device added it: "<device_label> was added by
    /// <added_by_label>". A label the roster lacks is empty.
    AddedElsewhere {
        device_label: String,
        added_by_label: String,
    },
    Ended {
        reason: DeviceLinkEndReason,
    },
}

/// What Link device sets for the new device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkChoices {
    /// The name the user gave the device, at most 64 bytes.
    pub label: String,
    /// Add the device to the chats this account's devices are in.
    pub add_to_all_chats: bool,
    /// Bring those chats' history to it.
    pub bring_history: bool,
}

impl DeviceLinkChoices {
    /// `label`, with both settings on, their default.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            add_to_all_chats: true,
            bring_history: true,
        }
    }
}

/// Linking as this device shows it: its own new-device session, if any, and
/// the prompts for sign-ins it can link.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceLinkSnapshot {
    pub new_device: Option<NewDeviceLinkState>,
    pub prompts: Vec<DeviceLinkPrompt>,
}

impl DeviceLinkSnapshot {
    /// The prompt for the sign-in in `slot_id_hex`, if one is listed.
    pub fn prompt_for_slot(&self, slot_id_hex: &str) -> Option<&DeviceLinkPrompt> {
        self.prompts
            .iter()
            .rev()
            .find(|prompt| prompt.slot_id_hex.as_deref() == Some(slot_id_hex))
    }
}

/// What the user asked of linking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceLinkOp {
    /// On a new device: ask a device already signed in to link this one.
    Start,
    /// On the new device: "They match".
    ConfirmMatch,
    /// On the new device: cancel.
    Cancel,
    /// On a device already signed in: Link device.
    Link {
        prompt_id: String,
        choices: DeviceLinkChoices,
    },
    /// On a device already signed in: Not now. The sign-in stays listed
    /// with the unrecognized ones.
    Decline { prompt_id: String },
    /// Change nothing.
    Read,
}

impl AppClient {
    /// Apply `op` and return linking as this device now shows it.
    pub(crate) async fn device_link(
        &mut self,
        op: DeviceLinkOp,
    ) -> Result<DeviceLinkSnapshot, AppError> {
        #[cfg(feature = "unreleased-device-pairing")]
        {
            self.device_link_live(op).await
        }
        #[cfg(not(feature = "unreleased-device-pairing"))]
        {
            let _ = op;
            Err(AppError::DeviceGroupRefused("pairing_unsupported"))
        }
    }

    /// Move linking on: read the pairing messages the Welcome peeler split
    /// off, send what is owed, run the timers, retry KeyPackage checks,
    /// decide the links this device made, and nudge this device's first
    /// commit in a device group it joined. The worker calls it after each delivery and
    /// on its maintenance tick.
    pub(crate) async fn drive_device_pairing(&mut self) {
        #[cfg(feature = "unreleased-device-pairing")]
        self.drive_device_pairing_live().await;
    }

    /// Withdraw the Welcomes of failed and expired links before anything can
    /// publish them. Every open calls it, before it returns the client.
    pub(crate) fn withdraw_expired_link_welcomes(&mut self) {
        #[cfg(feature = "unreleased-device-pairing")]
        self.withdraw_expired_link_welcomes_at(crate::unix_now_seconds());
    }

    /// Whether to announce `DeviceLinkChanged`, clearing the flag. Never
    /// without pairing, or while device groups are off.
    pub(crate) fn take_device_link_changed(&mut self) -> bool {
        std::mem::take(&mut self.device_link_changed)
            && cfg!(feature = "unreleased-device-pairing")
            && self.app.device_groups_enabled()
    }
}
