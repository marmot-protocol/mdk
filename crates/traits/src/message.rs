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
    /// SHA-256 of the confirmed parent GroupContext from which this commit was
    /// authored. Older unstamped-parent rows decode as `None` and are not
    /// eligible for the anchor-rollforward fast path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_group_context_sha256: Option<String>,
    /// SHA-256 of the confirmed GroupContext after this commit merged. The
    /// retained-anchor fast path validates the epoch-only snapshot against
    /// this value before treating it as this commit's post-merge state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_group_context_sha256: Option<String>,
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
/// - `OutboundWelcome`: a locally produced Welcome retained until its
///   independent transport acknowledgement policy is satisfied. Keeping this
///   distinct from historical `RawTransport` `Sent` rows lets cold-restart
///   recovery find only delivery obligations created by versions that track
///   their completion.
/// - `OpenMlsWire`: transport metadata plus payload replaced with peeled MLS
///   wire bytes. Only this variant and `OwnCommitWire` are eligible for
///   OpenMLS projection and convergence replay.
/// - `SignedOpenMlsWire`: the exact signed outer transport message alongside
///   the projection-friendly MLS wire message. This is the current outbound
///   representation and supports byte-identical retry after restart.
/// - `OwnCommitWire`: an `OpenMlsWire` commit this device published and
///   confirmed, enriched with its [`OwnCommitConvergenceStamp`] so stored
///   convergence can treat it as a pre-validated candidate branch after a
///   restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum StoredMessagePayload {
    RawTransport(TransportMessage),
    OutboundWelcome(TransportMessage),
    OpenMlsWire(TransportMessage),
    SignedOpenMlsWire {
        exact_message: TransportMessage,
        openmls_message: TransportMessage,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stamp: Option<OwnCommitConvergenceStamp>,
    },
    OwnCommitWire {
        message: TransportMessage,
        stamp: OwnCommitConvergenceStamp,
    },
}

impl StoredMessagePayload {
    pub fn raw_transport(message: TransportMessage) -> Self {
        Self::RawTransport(message)
    }

    pub fn outbound_welcome(message: TransportMessage) -> Self {
        Self::OutboundWelcome(message)
    }

    pub fn openmls_wire(message: TransportMessage) -> Self {
        Self::OpenMlsWire(message)
    }

    pub fn signed_openmls_wire(
        exact_message: TransportMessage,
        openmls_message: TransportMessage,
    ) -> Self {
        Self::SignedOpenMlsWire {
            exact_message,
            openmls_message,
            stamp: None,
        }
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
            Self::OutboundWelcome(_)
            | Self::OpenMlsWire(_)
            | Self::SignedOpenMlsWire { .. }
            | Self::OwnCommitWire { .. } => None,
        }
    }

    pub fn as_outbound_welcome(&self) -> Option<&TransportMessage> {
        match self {
            Self::OutboundWelcome(message) => Some(message),
            Self::RawTransport(_)
            | Self::OpenMlsWire(_)
            | Self::SignedOpenMlsWire { .. }
            | Self::OwnCommitWire { .. } => None,
        }
    }

    pub fn as_openmls_wire(&self) -> Option<&TransportMessage> {
        match self {
            Self::RawTransport(_) | Self::OutboundWelcome(_) => None,
            Self::OpenMlsWire(message) | Self::OwnCommitWire { message, .. } => Some(message),
            Self::SignedOpenMlsWire {
                openmls_message, ..
            } => Some(openmls_message),
        }
    }

    /// Exact signed outer event retained for restart-safe retransmission.
    pub fn as_exact_transport(&self) -> Option<&TransportMessage> {
        match self {
            Self::RawTransport(message) | Self::OutboundWelcome(message) => Some(message),
            Self::SignedOpenMlsWire { exact_message, .. } => Some(exact_message),
            Self::OpenMlsWire(_) | Self::OwnCommitWire { .. } => None,
        }
    }

    /// The confirm-time convergence stamp, when this payload is an own
    /// published-and-confirmed commit.
    pub fn own_commit_stamp(&self) -> Option<&OwnCommitConvergenceStamp> {
        match self {
            Self::RawTransport(_) | Self::OutboundWelcome(_) | Self::OpenMlsWire(_) => None,
            Self::SignedOpenMlsWire { stamp, .. } => stamp.as_ref(),
            Self::OwnCommitWire { stamp, .. } => Some(stamp),
        }
    }

    pub fn into_message(self) -> TransportMessage {
        match self {
            Self::RawTransport(message)
            | Self::OutboundWelcome(message)
            | Self::OpenMlsWire(message)
            | Self::OwnCommitWire { message, .. } => message,
            Self::SignedOpenMlsWire {
                openmls_message, ..
            } => openmls_message,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredPeelLifecycle {
    /// Wall-clock time when this account-device first retained the opaque
    /// transport object. This is local resource metadata, never wire data.
    pub first_observed_wall_ms: u64,
    /// Greatest wall-clock observation persisted for this row. A later
    /// backwards jump cannot erase already-observed residence.
    pub wall_high_water_ms: u64,
    /// Process-local convergence clock instance that owns
    /// `residence_deadline_monotonic_ms`.
    pub clock_instance_id: u64,
    /// Live-process deadline. It is rebased from the durable wall deadline
    /// after restart because monotonic clock values do not survive processes.
    pub residence_deadline_monotonic_ms: u64,
    /// Durable deadline used only to reconstruct the monotonic deadline after
    /// restart. Backwards wall movement must never make this deadline earlier.
    pub residence_deadline_wall_ms: u64,
    /// Number of distinct peel contexts actually consumed by this row.
    pub distinct_context_attempts: u32,
    /// Last `(epoch, retained snapshot set)` fingerprint attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_context_fingerprint: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: MessageId,
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub state: MessageState,
    pub payload: Vec<u8>,
    /// Durable local bookkeeping for raw transport objects in
    /// [`MessageState::PeelDeferred`]. Older rows deserialize without it and
    /// receive a fresh conservative residence window on first maintenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_peel: Option<DeferredPeelLifecycle>,
}

/// Per-message state.
///
/// Transitions:
///   `Sent` → `Sent` (outbound message recorded for durable own-echo checks)
///   `Sent` → `Processed` (a retained outbound Welcome met its delivery policy)
///   `Created` → `Processed` (happy path after successful ingest)
///   `Created` → `Failed` (terminal error — no retry)
///   `Created` → `Retryable` (transient error — can be re-tried later)
///   `Created` → `ConvergenceDeferred` (retained for a later convergence pass)
///   `Created` → `PeelDeferred` (transport bytes retained for later peel)
///   `Retryable` → `Processed` (retry succeeded)
///   `ConvergenceDeferred` → `Processed` (later evidence selects the input)
///   `PeelDeferred` → `Created` (peel succeeded and MLS bytes are buffered)
///   `PeelDeferred` → deleted (local retry budget exhausted; redelivery remains eligible)
///   any → `EpochInvalidated` (group forked past; message will never apply)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageState {
    /// Locally produced outbound message. If the transport echoes it back,
    /// the engine can classify it as `OwnEcho` even after restart.
    Sent,
    /// Stored but not yet processed.
    Created,
    /// Successfully applied to the group state, or a retained outbound
    /// Welcome whose independent delivery obligation completed.
    Processed,
    /// Terminal failure — do not retry.
    Failed,
    /// Transient failure — eligible for retry (e.g. awaiting out-of-order
    /// commit that hasn't arrived yet).
    Retryable,
    /// The convergence engine evaluated this input but cannot give it a
    /// terminal disposition in the completed pass. It remains graph input for
    /// a later pass, but does not by itself reopen convergence or gate sends.
    ConvergenceDeferred,
    /// Transport-wrapped bytes are stored, but no available epoch context has
    /// peeled them yet. The engine may retry when it learns or retains more
    /// group epoch state.
    PeelDeferred,
    /// The epoch this message targets has been superseded by a fork recovery
    /// transition; the message will never apply. Kept for audit.
    EpochInvalidated,
}
