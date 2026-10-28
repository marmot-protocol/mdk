//! What both sides of a session share: limits, outcomes and the result.

use cgka_traits::GroupId;

use crate::message::CancelReason;
use crate::types::{KeyPackageEventId, KeyPackageRef, SessionId, SlotId};

/// A request with no answer expires this long after it was made, in seconds.
pub const REQUEST_TTL_SECS: u64 = 10 * 60;

/// A session expires this long after the answer, in seconds.
pub const SESSION_TTL_SECS: u64 = 10 * 60;

/// An answering device ignores a request dated further than this into its
/// future, in seconds, as Matrix's request rule does.
pub const REQUEST_MAX_FUTURE_SECS: u64 = 5 * 60;

/// Most sessions one device answers in [`ANSWER_WINDOW_SECS`] (D20).
pub const MAX_ANSWERS_PER_WINDOW: usize = 10;

/// The rate-limit window, in seconds. A device that answered
/// [`MAX_ANSWERS_PER_WINDOW`] sessions in the last window answers no more
/// until the oldest of them leaves it.
pub const ANSWER_WINDOW_SECS: u64 = 60 * 60;

/// Most requests an answering device tracks at once. Two live requests
/// already block every session, so further ones are dropped.
pub const MAX_TRACKED_REQUESTS: usize = 32;

/// A verified link: what both devices hold once both users confirmed and both
/// confirmations verified.
///
/// The existing device adds the KeyPackage with this exact `KeyPackageRef`,
/// and no other, to the device group. The new device accepts a Welcome only
/// for this device group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedLink {
    pub session_id: SessionId,
    /// The new device's published KeyPackage.
    pub key_package_event_id: KeyPackageEventId,
    /// That KeyPackage's `KeyPackageRef`, covered by the new device's
    /// confirmation.
    pub key_package_ref: KeyPackageRef,
    /// The device group, covered by the existing device's confirmation.
    pub device_group_id: GroupId,
    /// The existing device that took part.
    pub existing_device_slot: SlotId,
}

impl ConfirmedLink {
    /// Whether a Welcome into `group_id` is the one this link allows.
    pub fn allows_welcome_for(&self, group_id: &GroupId) -> bool {
        &self.device_group_id == group_id
    }
}

/// Why a session ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The other side, or another device of the account, sent a cancel.
    Cancelled(CancelReason),
    /// This device's user cancelled.
    UserCancelled,
    /// This device's user said the codes differ.
    MismatchedCode,
    /// The revealed key was not the one the request committed to.
    MismatchedCommitment,
    /// The other side's confirmation did not verify.
    MismatchedConfirm,
    /// The other side's key was a low-order point.
    InvalidKey,
    /// The request or the session expired.
    Timeout,
    /// The new device took another device's answer.
    AnsweredElsewhere,
}

impl EndReason {
    /// The cancel this device sends for the reason, if it sends one.
    pub(crate) fn outgoing_cancel(&self) -> Option<CancelReason> {
        match self {
            Self::Cancelled(_) | Self::AnsweredElsewhere => None,
            Self::UserCancelled => Some(CancelReason::User),
            Self::MismatchedCode => Some(CancelReason::MismatchedCode),
            Self::MismatchedCommitment => Some(CancelReason::MismatchedCommitment),
            Self::MismatchedConfirm => Some(CancelReason::MismatchedConfirm),
            Self::InvalidKey => Some(CancelReason::UnexpectedMessage),
            Self::Timeout => Some(CancelReason::Timeout),
        }
    }
}

/// Why a message changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoreReason {
    /// It names a session this side doesn't hold.
    OtherSession,
    /// This side sent it, or another device of its role did.
    OwnRole,
    /// The session already moved past the step it belongs to: a replay, or a
    /// second answer.
    WrongStep,
    /// The session already ended.
    Ended,
    /// A request this side has already seen.
    Duplicate,
    /// A request dated outside the accepted window.
    Stale,
    /// Too many requests are tracked already. The request still counts as
    /// live until it would have expired, so no session links meanwhile.
    Capacity,
}

/// Why a local call was refused. Carries no ids or key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    #[error("no such pairing session")]
    UnknownSession,
    #[error("the pairing session is not at this step")]
    WrongStep,
    #[error("the pairing session has expired")]
    Expired,
    #[error("more than one pairing request is live")]
    CompetingRequests,
    #[error("this device has answered too many pairing sessions recently")]
    RateLimited {
        /// When the next answer is allowed, in Unix seconds.
        retry_at: u64,
    },
    #[error("the published KeyPackage does not match the request")]
    KeyPackageMismatch,
    #[error("the device-group id is empty or too long")]
    InvalidGroupId,
}
