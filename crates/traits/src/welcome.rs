//! Pending-welcome persistence.
//!
//! Validated replacement invitations await explicit local confirmation.
//! Declining stores durable transport and content deduplication markers.

use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};

/// A welcome the engine has received but not yet processed (e.g. because the
/// client is offline or joining hasn't been confirmed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWelcome {
    pub message_id: MessageId,
    pub group_id: GroupId,
    pub welcome_bytes: Vec<u8>,
    /// Present only for a validated replacement awaiting explicit local consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejoin: Option<RejoinWelcome>,
}

/// Authenticated replacement identity plus a revision of the local branch the
/// user is choosing to discard. The opaque revision binds the local epoch authenticator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejoinWelcome {
    pub epoch: EpochId,
    pub content_id: MessageId,
    pub welcomer: MemberId,
    pub local_state_token: Vec<u8>,
}
