//! Typed outcomes from [`crate::engine::CgkaEngine::ingest`] plus the
//! peeled-message intermediate form.
//!
//! `IngestOutcome` separates applied messages from classifiable stale cases.
//! Hard errors stay in `EngineError`; stale routing, dedupe, and epoch cases
//! remain ordinary outcomes.

use crate::transport::TransportMessage;
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestOutcome {
    /// Message was validated, applied to the group's MLS state, and any
    /// resulting `GroupEvent`s were enqueued for `drain_events`.
    Processed,
    /// Message was accepted into durable storage but not yet applied because
    /// the group is temporarily not ingestible, usually during a local
    /// publish-before-apply transition. The engine replays buffered messages
    /// when the group returns to `Stable`.
    Buffered { group_id: GroupId, epoch: EpochId },
    /// Message was not applied. The variant names why — callers log by
    /// category rather than pattern-matching error strings.
    Stale { reason: StaleReason },
}

/// Why an inbound message was not processed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaleReason {
    /// The engine has already seen this `MessageId`. Coordinator dedup.
    AlreadySeen,
    /// The engine is already at or past the message's epoch. Commonly hit
    /// when a commit arrives after a welcome that already advanced the
    /// recipient.
    AlreadyAtEpoch {
        current: EpochId,
        msg_epoch: EpochId,
    },
    /// A welcome addressed to a member other than ourselves.
    NotForThisClient,
    /// No local group matches this message's routing.
    UnknownGroup,
    /// The message is our own commit echoed back by the transport.
    OwnEcho,
    /// The peeler rejected the message. The stored message may be terminal or
    /// retryable depending on whether the engine has evidence that another
    /// epoch context could later peel it.
    PeelFailed,
}

/// Decrypted inbound message ready for engine processing.
///
/// Produced by [`crate::peeler::TransportPeeler::peel_group_message`] /
/// [`crate::peeler::TransportPeeler::peel_welcome`]. The `kind` field is the
/// structural discriminator — application messages, MLS commits, welcomes,
/// etc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeeledMessage {
    pub id: MessageId,
    pub group_id: Option<GroupId>,
    pub sender: Option<MemberId>,
    pub content: PeeledContent,
    pub origin: TransportMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeeledContent {
    /// Inner MLS message (commit, application, proposal, etc.) — engine
    /// decides how to apply.
    MlsMessage { bytes: Vec<u8> },
    /// Welcome payload (MLS welcome bytes).
    Welcome { bytes: Vec<u8> },
}
