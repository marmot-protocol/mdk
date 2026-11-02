//! Device pairing: how a new device and an existing device of one Marmot
//! account authenticate each other before the new device joins the
//! account's device group.
//!
//! The exchange is Matrix's reviewed SAS verification (`m.sas.v1`),
//! transcribed into Marmot encodings without Matrix's event protocol
//! (mdk#2628 D18):
//!
//! 1. The new device sends a [`PairingRequest`] naming its published
//!    KeyPackage and committing to a fresh X25519 key.
//! 2. An existing device sends a [`PairingAnswer`] with its own fresh key.
//! 3. The new device sends a [`PairingReveal`] with its key, which the
//!    existing device checks against the commitment.
//! 4. Both derive the same [`SasCode`] and show it as seven emoji, each
//!    with its text description for screen readers (D25). The users compare
//!    the two screens.
//! 5. Each side whose user confirmed sends a [`PairingConfirm`]: the new
//!    device's covers its exact `KeyPackageRef`, the existing device's the
//!    device group it will add the new device to and the MLS signature key
//!    of its own leaf there, the only sender whose Welcome the new device
//!    accepts.
//!
//! Either side may send a [`PairingCancel`]. Holding the account key never
//! authenticates a device here: only the code compared on both screens does.
//!
//! The crate is transport-neutral. A transport carries each message as one
//! app event of its kind with [`PairingMessage::to_content`] as content, sent
//! to the account itself. It holds no state beyond the session: nothing here
//! persists or logs a key, a code or an id.
//!
//! The wire format is unreleased until its spec lands. Nothing sends it in a
//! release build.

mod code;
mod emoji;
mod existing_device;
mod message;
mod new_device;
mod sas;
mod session;
mod types;

pub use code::{SAS_EMOJI_COUNT, SasCode};
pub use emoji::{SAS_EMOJI, SasEmoji};
pub use existing_device::{
    ExistingDeviceEvent, ExistingDevicePairing, LiveRequest, PublishedKeyPackage,
};
pub use message::{
    CancelReason, ConfirmSender, KIND_PAIRING_ANSWER, KIND_PAIRING_CANCEL, KIND_PAIRING_CONFIRM,
    KIND_PAIRING_REQUEST, KIND_PAIRING_REVEAL, MAX_CONTENT_LEN, PAIRING_KINDS, PairingAnswer,
    PairingCancel, PairingConfirm, PairingMessage, PairingMessageError, PairingRequest,
    PairingReveal,
};
pub use new_device::{NewDeviceConfirmation, NewDeviceEvent, NewDevicePairing};
pub use sas::{RequestBinding, commitment};
pub use session::{
    ANSWER_WINDOW_SECS, ConfirmedLink, EndReason, IgnoreReason, MAX_ANSWERS_PER_WINDOW,
    MAX_TRACKED_REQUESTS, PairingError, REQUEST_MAX_FUTURE_SECS, REQUEST_TTL_SECS,
    SESSION_TTL_SECS,
};
pub use types::{
    AccountKey, ExchangeKey, GROUP_ID_MAX_LEN, KEY_PACKAGE_REF_MAX_LEN, KeyPackageEventId,
    KeyPackageRef, SIGNATURE_KEY_MAX_LEN, SessionId, SignatureKey, SlotId,
};
