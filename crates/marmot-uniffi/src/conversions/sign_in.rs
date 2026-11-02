//! Sign-ins of this account that this device does not recognize.

use marmot_app::{SignInResponse, UnrecognizedSignIn, UnrecognizedSignInState};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UnrecognizedSignInStateFfi {
    /// Waiting for an answer.
    Prompt,
    /// Answered Not now: listed with no prompt.
    NotNow,
    /// Another device linked it while its prompt here waited. Dismiss ends
    /// the prompt.
    LinkedElsewhere,
    /// Another device rejected it while its prompt here waited. Dismiss ends
    /// the prompt.
    RejectedElsewhere,
}

/// A sign-in of this account that this device does not recognize: a fresh,
/// valid KeyPackage in a slot neither this device nor its device group's
/// roster knows.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnrecognizedSignInFfi {
    /// The sign-in's KeyPackage slot as published: 64 lowercase hex
    /// characters for every well-formed slot. Answers name it by this.
    pub slot_id_hex: String,
    /// The client name the sign-in reports for itself; empty when it reports
    /// none. Display only.
    pub client: String,
    /// When it appeared, in Unix seconds: its earliest publication this
    /// device saw, never later than when this device first saw it.
    pub appeared_at: u64,
    /// When it last refreshed its KeyPackage, in Unix seconds.
    pub last_seen_at: u64,
    /// It was signed in before this device was: ask whether the user still
    /// has it, not whether it was them.
    pub before_this_device: bool,
    /// Whether its slot still holds a fresh, valid KeyPackage. It stays
    /// listed after it signs out.
    pub signed_in: bool,
    pub state: UnrecognizedSignInStateFfi,
    /// The slot of the device that linked it, when `state` is
    /// `LinkedElsewhere` and the roster names one; `None` otherwise.
    pub linked_by_slot_id_hex: Option<String>,
}

impl From<UnrecognizedSignIn> for UnrecognizedSignInFfi {
    fn from(value: UnrecognizedSignIn) -> Self {
        let (state, linked_by_slot_id_hex) = match value.state {
            UnrecognizedSignInState::Prompt => (UnrecognizedSignInStateFfi::Prompt, None),
            UnrecognizedSignInState::NotNow => (UnrecognizedSignInStateFfi::NotNow, None),
            UnrecognizedSignInState::LinkedElsewhere {
                linked_by_slot_id_hex,
            } => (
                UnrecognizedSignInStateFfi::LinkedElsewhere,
                linked_by_slot_id_hex,
            ),
            UnrecognizedSignInState::RejectedElsewhere => {
                (UnrecognizedSignInStateFfi::RejectedElsewhere, None)
            }
        };
        Self {
            slot_id_hex: value.slot_id_hex,
            client: value.client,
            appeared_at: value.appeared_at,
            last_seen_at: value.last_seen_at,
            before_this_device: value.before_this_device,
            signed_in: value.signed_in,
            state,
            linked_by_slot_id_hex,
        }
    }
}

/// An answer to an unrecognized sign-in. Linking one is device pairing's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SignInResponseFfi {
    /// Keep it listed, with no prompt.
    NotNow,
    /// It was not the user: record it as rejected in the device group's
    /// roster.
    Reject,
    /// End a prompt another device already answered.
    Dismiss,
}

impl From<SignInResponseFfi> for SignInResponse {
    fn from(value: SignInResponseFfi) -> Self {
        match value {
            SignInResponseFfi::NotNow => Self::NotNow,
            SignInResponseFfi::Reject => Self::Reject,
            SignInResponseFfi::Dismiss => Self::Dismiss,
        }
    }
}
