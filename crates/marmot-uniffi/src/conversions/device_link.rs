//! Linking a new device of this account, as each device's screen shows it.

use marmot_app::{
    DeviceLinkEmoji, DeviceLinkEndReason, DeviceLinkPrompt, DeviceLinkPromptState,
    DeviceLinkSnapshot, NewDeviceLinkState,
};

/// One emoji of the code.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkEmojiFfi {
    pub emoji: String,
    /// The emoji's English description, for screen readers. Users compare
    /// the pictures, not the descriptions.
    pub description: String,
}

impl From<DeviceLinkEmoji> for DeviceLinkEmojiFfi {
    fn from(value: DeviceLinkEmoji) -> Self {
        Self {
            emoji: value.emoji,
            description: value.description,
        }
    }
}

/// Why a link ended without one device adding the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceLinkEndReasonFfi {
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
    /// Both users confirmed, but adding the device failed, or its Welcome
    /// did not reach the relays before the new device stopped waiting.
    LinkFailed,
}

impl From<DeviceLinkEndReason> for DeviceLinkEndReasonFfi {
    fn from(value: DeviceLinkEndReason) -> Self {
        match value {
            DeviceLinkEndReason::Cancelled => Self::Cancelled,
            DeviceLinkEndReason::CancelledElsewhere => Self::CancelledElsewhere,
            DeviceLinkEndReason::CodesDiffer => Self::CodesDiffer,
            DeviceLinkEndReason::VerificationFailed => Self::VerificationFailed,
            DeviceLinkEndReason::TimedOut => Self::TimedOut,
            DeviceLinkEndReason::AnsweredElsewhere => Self::AnsweredElsewhere,
            DeviceLinkEndReason::CannotLink => Self::CannotLink,
            DeviceLinkEndReason::Rejected => Self::Rejected,
            DeviceLinkEndReason::LinkFailed => Self::LinkFailed,
        }
    }
}

/// The new device's side of a link, as its screen shows it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NewDeviceLinkStateFfi {
    /// Waiting for a device already signed in to answer. Ask the user to
    /// open the app there.
    WaitingForAnswer,
    /// Both screens show `code`. Offer "They match" and cancel.
    Comparing {
        code: Vec<DeviceLinkEmojiFfi>,
    },
    /// This user confirmed; the other device's user has not yet.
    WaitingForOtherDevice,
    /// Both users confirmed. Waiting for the other device to add this one.
    Joining,
    /// This device joined the account's device group.
    Linked,
    Ended {
        reason: DeviceLinkEndReasonFfi,
    },
}

impl From<NewDeviceLinkState> for NewDeviceLinkStateFfi {
    fn from(value: NewDeviceLinkState) -> Self {
        match value {
            NewDeviceLinkState::WaitingForAnswer => Self::WaitingForAnswer,
            NewDeviceLinkState::Comparing { code } => Self::Comparing {
                code: code.into_iter().map(Into::into).collect(),
            },
            NewDeviceLinkState::WaitingForOtherDevice => Self::WaitingForOtherDevice,
            NewDeviceLinkState::Joining => Self::Joining,
            NewDeviceLinkState::Linked => Self::Linked,
            NewDeviceLinkState::Ended { reason } => Self::Ended {
                reason: reason.into(),
            },
        }
    }
}

/// Where a prompt on a device already signed in stands.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceLinkPromptStateFfi {
    /// Checking the sign-in's KeyPackage, or waiting for the code.
    Preparing,
    /// Both screens show `code`. Offer Link device and Not now.
    Comparing {
        code: Vec<DeviceLinkEmojiFfi>,
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
    /// confirmation, then for relays to confirm the change that adds it and
    /// take its Welcome.
    Linking,
    /// This device added it: relays confirmed the change and took its
    /// Welcome.
    Linked,
    /// Another device added it: "<device_label> was added by
    /// <added_by_label>". A label the roster lacks is empty.
    AddedElsewhere {
        device_label: String,
        added_by_label: String,
    },
    Ended {
        reason: DeviceLinkEndReasonFfi,
    },
}

impl From<DeviceLinkPromptState> for DeviceLinkPromptStateFfi {
    fn from(value: DeviceLinkPromptState) -> Self {
        match value {
            DeviceLinkPromptState::Preparing => Self::Preparing,
            DeviceLinkPromptState::Comparing { code } => Self::Comparing {
                code: code.into_iter().map(Into::into).collect(),
            },
            DeviceLinkPromptState::CompetingRequests => Self::CompetingRequests,
            DeviceLinkPromptState::RateLimited { retry_at } => Self::RateLimited { retry_at },
            DeviceLinkPromptState::CannotLink { missing } => Self::CannotLink { missing },
            DeviceLinkPromptState::TooManyDevices => Self::TooManyDevices,
            DeviceLinkPromptState::Linking => Self::Linking,
            DeviceLinkPromptState::Linked => Self::Linked,
            DeviceLinkPromptState::AddedElsewhere {
                device_label,
                added_by_label,
            } => Self::AddedElsewhere {
                device_label,
                added_by_label,
            },
            DeviceLinkPromptState::Ended { reason } => Self::Ended {
                reason: reason.into(),
            },
        }
    }
}

/// A new sign-in this device can link, as its prompt shows it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkPromptFfi {
    /// Opaque local id that `link_device` and `decline_device_link` take.
    pub prompt_id: String,
    /// The sign-in's KeyPackage slot, 64 lowercase hex characters, once its
    /// KeyPackage was found.
    pub slot_id_hex: Option<String>,
    /// When the request arrived, in Unix seconds.
    pub requested_at: u64,
    pub state: DeviceLinkPromptStateFfi,
}

impl From<DeviceLinkPrompt> for DeviceLinkPromptFfi {
    fn from(value: DeviceLinkPrompt) -> Self {
        Self {
            prompt_id: value.prompt_id,
            slot_id_hex: value.slot_id_hex,
            requested_at: value.requested_at,
            state: value.state.into(),
        }
    }
}

/// Linking as this device shows it: its own new-device link, if any, and
/// the prompts for sign-ins it can link.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkSnapshotFfi {
    pub new_device: Option<NewDeviceLinkStateFfi>,
    pub prompts: Vec<DeviceLinkPromptFfi>,
}

impl From<DeviceLinkSnapshot> for DeviceLinkSnapshotFfi {
    fn from(value: DeviceLinkSnapshot) -> Self {
        Self {
            new_device: value.new_device.map(Into::into),
            prompts: value.prompts.into_iter().map(Into::into).collect(),
        }
    }
}
