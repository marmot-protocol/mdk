//! Stored message records and their state machine.
//!
//! The state machine matches `cgka-engine-design.md:48-54`: messages live in
//! a typed state that the engine + coordinator walk through as processing
//! progresses. Kept here (and not inside the engine) so the storage backend
//! can query "what's retryable?" without cracking engine internals.

use crate::engine::CommitOrderingPriority;
use crate::transport::TransportMessage;
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};

/// Convergence-relevant ordering metadata for a commit this device published
/// and confirmed, captured at confirm time (while the staged commit is still
/// attached) and persisted alongside the stored wire bytes.
///
/// MLS cannot process a device's own commit through `process_message`, so
/// after an engine restart the stored wire record is the ONLY source from
/// which stored convergence can rebuild the own commit's branch-selection
/// ordering key (priority + authenticated committer; the digest is recomputed
/// from the stored bytes) and its consumed proposal references.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnCommitConvergenceStamp {
    /// This device's member identity — the authenticated committer of the
    /// stored commit.
    pub committer: MemberId,
    /// Authorization-aware ordering priority derived from the staged commit's
    /// shape at confirm time.
    pub priority: CommitOrderingPriority,
    /// Hex-encoded proposal references the commit consumed, in sorted order.
    pub consumed_proposal_refs: Vec<String>,
}

/// Typed envelope for the opaque bytes stored in [`MessageRecord::payload`].
///
/// The database column remains a byte blob so backends do not need a schema
/// change every time the engine stores a new payload flavor. The bytes inside
/// the blob are this versioned JSON shape:
///
/// - `RawTransport`: original transport-wrapped message. Used when peeling is
///   deferred or the engine needs to retry with a different epoch context.
/// - `OpenMlsWire`: transport metadata plus payload replaced with peeled MLS
///   wire bytes. Only this variant and `OwnCommitWire` are eligible for
///   OpenMLS projection and convergence replay.
/// - `OwnCommitWire`: an `OpenMlsWire` commit this device published and
///   confirmed, enriched with its [`OwnCommitConvergenceStamp`] so stored
///   convergence can treat it as a pre-validated candidate branch after a
///   restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum StoredMessagePayload {
    RawTransport(TransportMessage),
    OpenMlsWire(TransportMessage),
    OwnCommitWire {
        message: TransportMessage,
        stamp: OwnCommitConvergenceStamp,
    },
}

impl StoredMessagePayload {
    pub fn raw_transport(message: TransportMessage) -> Self {
        Self::RawTransport(message)
    }

    pub fn openmls_wire(message: TransportMessage) -> Self {
        Self::OpenMlsWire(message)
    }

    pub fn own_commit_wire(message: TransportMessage, stamp: OwnCommitConvergenceStamp) -> Self {
        Self::OwnCommitWire { message, stamp }
    }

    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        match serde_json::from_slice(bytes) {
            Ok(payload) => Ok(payload),
            Err(envelope_error) => match serde_json::from_slice(bytes) {
                Ok(legacy) => Ok(Self::OpenMlsWire(legacy)),
                Err(_) => Err(envelope_error),
            },
        }
    }

    pub fn as_raw_transport(&self) -> Option<&TransportMessage> {
        match self {
            Self::RawTransport(message) => Some(message),
            Self::OpenMlsWire(_) | Self::OwnCommitWire { .. } => None,
        }
    }

    pub fn as_openmls_wire(&self) -> Option<&TransportMessage> {
        match self {
            Self::RawTransport(_) => None,
            Self::OpenMlsWire(message) | Self::OwnCommitWire { message, .. } => Some(message),
        }
    }

    /// The confirm-time convergence stamp, when this payload is an own
    /// published-and-confirmed commit.
    pub fn own_commit_stamp(&self) -> Option<&OwnCommitConvergenceStamp> {
        match self {
            Self::RawTransport(_) | Self::OpenMlsWire(_) => None,
            Self::OwnCommitWire { stamp, .. } => Some(stamp),
        }
    }

    pub fn into_message(self) -> TransportMessage {
        match self {
            Self::RawTransport(message)
            | Self::OpenMlsWire(message)
            | Self::OwnCommitWire { message, .. } => message,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: MessageId,
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub state: MessageState,
    pub payload: Vec<u8>,
}

/// Per-message state.
///
/// Transitions:
///   `Sent` → `Sent` (outbound message recorded for durable own-echo checks)
///   `Created` → `Processed` (happy path after successful ingest)
///   `Created` → `Failed` (terminal error — no retry)
///   `Created` → `Retryable` (transient error — can be re-tried later)
///   `Created` → `PeelDeferred` (transport bytes retained for later peel)
///   `Retryable` → `Processed` (retry succeeded)
///   `PeelDeferred` → `Created` (peel succeeded and MLS bytes are buffered)
///   any → `EpochInvalidated` (group forked past; message will never apply)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageState {
    /// Locally produced outbound message. If the transport echoes it back,
    /// the engine can classify it as `OwnEcho` even after restart.
    Sent,
    /// Stored but not yet processed.
    Created,
    /// Successfully applied to the group state.
    Processed,
    /// Terminal failure — do not retry.
    Failed,
    /// Transient failure — eligible for retry (e.g. awaiting out-of-order
    /// commit that hasn't arrived yet).
    Retryable,
    /// Transport-wrapped bytes are stored, but no available epoch context has
    /// peeled them yet. The engine may retry when it learns or retains more
    /// group epoch state.
    PeelDeferred,
    /// The epoch this message targets has been superseded by a fork recovery
    /// transition; the message will never apply. Kept for audit.
    EpochInvalidated,
}
