//! Typed errors returned by the engine and the peeler.
//!
//! Typed variants cover cases the engine can classify. `Backend(String)` is
//! the fallback for backend failures that do not yet have a narrower variant.

use crate::capabilities::GroupCapabilities;
use crate::types::{EpochId, GroupId, MemberId};

/// Errors returned by every [`crate::engine::CgkaEngine`] method.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("unknown group")]
    UnknownGroup(GroupId),

    #[error("unknown pending send reference")]
    UnknownPending,

    #[error("local identity is not a member of the group")]
    NotAMember { group_id: GroupId },

    #[error("local identity is not an admin of the group")]
    NotGroupAdmin { group_id: GroupId },

    #[error("member is not in the group")]
    UnknownMember { group_id: GroupId, member: MemberId },

    /// A credential identity is not a valid Marmot account identity. Per
    /// `spec/foundation/identity.md`, a Marmot member-leaf credential identity
    /// MUST be exactly 32 bytes encoding a valid x-only secp256k1 (BIP-340)
    /// public key. Returned at every member/credential ingress (create,
    /// invite, join/welcome, inbound processing) and at local identity
    /// creation.
    #[error("invalid credential identity: {0}")]
    InvalidCredentialIdentity(String),

    /// Admins must leave the admin set before using SelfRemove.
    #[error("admin cannot self-remove: leave the admin set first")]
    AdminCannotSelfRemove { group_id: GroupId },

    /// MIP-03 §150 — a commit that would result in zero admins is rejected
    /// before construction. Used when an inbound SelfRemove from the only
    /// admin would deplete admins on commit.
    #[error("commit would deplete group admins")]
    AdminDepletion { group_id: GroupId },

    /// Invitee KeyPackage is missing a capability required by the group.
    /// `required` and `had` are populated so callers can render the diff.
    #[error("missing required capabilities: required={required:?} had={had:?}")]
    MissingRequiredCapabilities {
        required: Box<GroupCapabilities>,
        had: Box<GroupCapabilities>,
    },

    /// The configured MLS ciphersuite is not the Marmot mandatory-to-implement
    /// ciphersuite. Per `spec/foundation/mls-protocol.md`, Marmot requires
    /// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (id `0x0001`); building an
    /// engine or creating a group with any other ciphersuite is rejected.
    #[error("unsupported MLS ciphersuite {got:#06x}: Marmot requires {required:#06x}")]
    UnsupportedCiphersuite { got: u16, required: u16 },

    /// MLS application-message plaintext is not a Marmot app event:
    /// unsigned Nostr-shaped JSON with a canonical NIP-01 `id` and no `sig`.
    #[error("invalid Marmot app message payload: {0}")]
    InvalidAppMessagePayload(String),

    /// A member leaf or KeyPackage does not carry a valid account-key proof
    /// binding the Marmot credential identity to the MLS leaf signature key.
    #[error("invalid account identity proof: {0}")]
    InvalidAccountIdentityProof(String),

    /// Epoch fork detected that the current recovery manager could not
    /// resolve, usually because no pre-commit snapshot was available.
    /// Recoverable same-epoch commit races roll back and replay internally.
    #[error("forked epoch: last stable {last_stable}, conflicting {conflicting_epoch}")]
    ForkedEpoch {
        group_id: GroupId,
        last_stable: EpochId,
        conflicting_epoch: EpochId,
    },

    /// Illegal state-machine transition (from
    /// [`crate::engine_state::InvalidTransition`]). Indicates an engine bug.
    #[error(transparent)]
    InvalidTransition(#[from] crate::engine_state::InvalidTransition),

    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),

    #[error(transparent)]
    Peeler(#[from] PeelerError),

    #[error("serialization failure: {0}")]
    Serialize(String),

    /// Last-resort bucket. Prefer adding a typed variant.
    #[error("backend failure: {0}")]
    Backend(String),

    /// Truly unclassified. Should be empty in practice.
    #[error("other: {0}")]
    Other(String),
}

impl EngineError {
    /// Whether this error reflects transient backend contention (a
    /// [`crate::storage::StorageError::Busy`] that survived the backend's own
    /// retries) rather than a durable failure. Callers driving the
    /// publish-before-apply lifecycle use this to retry `confirm_published`
    /// instead of surfacing a lock blip as a fatal failure — the confirm path
    /// is structured to be retry-safe (the in-memory state-machine transition
    /// only runs after the durable storage transaction commits).
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, EngineError::Storage(e) if e.is_transient())
    }
}

/// Errors returned by the peeler. The split mirrors the four-method peeler
/// surface (group/welcome × peel/wrap).
#[derive(Debug, thiserror::Error)]
pub enum PeelerError {
    #[error("malformed transport payload: {0}")]
    Malformed(String),

    #[error("decrypt failed (likely stale or wrong-epoch exporter secret)")]
    DecryptFailed,

    #[error("message epoch {message_epoch} is older than available context epoch {context_epoch}")]
    StaleEpoch {
        message_epoch: EpochId,
        context_epoch: EpochId,
    },

    #[error("required context secret missing: {label}")]
    MissingContext { label: String },

    /// Wrap-side failure, e.g. rumor signing failed.
    #[error("wrap failed: {0}")]
    WrapFailed(String),

    /// Last-resort bucket.
    #[error("peeler backend failure: {0}")]
    Backend(String),
}
