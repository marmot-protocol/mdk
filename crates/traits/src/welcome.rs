//! Pending-welcome persistence.
//!
//! Validated replacement invitations await explicit local confirmation.
//! Declining stores durable transport and content deduplication markers.

use crate::ingest::IngestOutcome;
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

/// What joining from a sibling Welcome came to (mdk#2628 3.5b).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiblingWelcomeJoin {
    /// Settled as an ingested Welcome settles: joined, or refused for a
    /// reason.
    Settled(IngestOutcome),
    /// Into `group_id`, a chat this device still holds an active copy of.
    /// Nothing was written and the KeyPackage is still held: the caller keeps
    /// the Welcome and joins it again once that copy reads removed or
    /// unrecoverable.
    Held { group_id: GroupId },
}
