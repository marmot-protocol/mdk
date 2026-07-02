//! Storage traits and the `StorageProvider` aggregate.
//!
//! Marmot-level traits compose with `openmls_traits::storage::StorageProvider`
//! (at `CURRENT_VERSION`) to form the single `S: StorageProvider` type
//! carried by the engine. The engine uses static storage dispatch.
//!
//! **Invariant:** storage trait methods are **sync**. OpenMLS's storage
//! surface is sync; async concerns live above storage (on the engine). If a
//! future backend needs async I/O (e.g. a remote KV), it can wrap sync
//! methods in `tokio::task::spawn_blocking`.

use crate::capabilities::{CapabilityRequirement, GroupCapabilities};
use crate::engine::SendIntent;
use crate::group::{Group, Member};
use crate::message::{MessageRecord, MessageState};
use crate::types::{Backend, EpochId, GroupId, MemberId, MessageId};
use crate::welcome::PendingWelcome;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider as OpenMlsStorageProvider};
use serde::{Deserialize, Serialize};

/// Marmot-level storage error. Every trait method returns
/// `Result<_, StorageError>` so the engine can pattern-match rather than
/// string-parse.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("record not found")]
    NotFound,
    #[error("record already exists")]
    AlreadyExists,
    #[error("snapshot not found: {0}")]
    SnapshotMissing(String),
    /// Transient lock contention: the backend could not acquire the database
    /// lock in time (for SQLite this is `SQLITE_BUSY` / `SQLITE_LOCKED`). It is
    /// distinct from [`StorageError::Backend`] so callers can recognise a
    /// retryable condition instead of string-parsing "database is locked" and
    /// surfacing it to the user as a fatal failure. The storage backend already
    /// retries with backoff; this variant is what escapes only after those
    /// retries are exhausted, so callers may retry the whole operation or report
    /// it as a transient (not fatal) error.
    #[error("backend busy: {0}")]
    Busy(String),
    #[error("backend failure: {0}")]
    Backend(String),
    #[error("serialization failure: {0}")]
    Serialization(String),
}

impl StorageError {
    /// Whether this error reflects transient contention worth retrying rather
    /// than a durable failure. Currently only [`StorageError::Busy`] is
    /// transient; everything else (not-found, serialization, backend faults) is
    /// terminal for the attempt.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, StorageError::Busy(_))
    }
}

pub type StorageResult<T> = Result<T, StorageError>;

// ── GroupStorage ────────────────────────────────────────────────────────────

/// CRUD for group metadata (no Nostr types; see `group.rs` invariants).
pub trait GroupStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()>;
    fn get_group(&self, id: &GroupId) -> StorageResult<Group>;
    fn delete_group(&self, id: &GroupId) -> StorageResult<()>;
    fn list_groups(&self) -> StorageResult<Vec<GroupId>>;
}

// ── MessageStorage ──────────────────────────────────────────────────────────

/// Messages + epoch-scoped snapshot/rollback hooks.
///
/// Snapshots are name-keyed per-group: the engine's `EpochManager` creates
/// one before entering a risky transition and either commits (`release_*`)
/// or rewinds (`rollback_*`). Invariant: snapshots capture every piece of
/// backend state needed to reload the group at the snapshot epoch, including
/// OpenMLS group state. `list_messages` must return a deterministic replay
/// order for a given backend; insertion order is preferred when the backend
/// can retain it.
pub trait MessageStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()>;
    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord>;
    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()>;
    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>>;

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;
    fn list_group_snapshots(&self, group_id: &GroupId) -> StorageResult<Vec<String>>;
    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;
    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;
}

// ── OutboundIntentStorage ──────────────────────────────────────────────────

/// Durable queue for local outbound work that cannot be safely published
/// until convergence reaches `Settled`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedOutboundIntent {
    pub id: MessageId,
    pub group_id: GroupId,
    pub intent: SendIntent,
    pub created_at_ms: u64,
}

pub trait OutboundIntentStorage {
    fn put_queued_outbound_intent(&self, record: &QueuedOutboundIntent) -> StorageResult<()>;
    fn list_queued_outbound_intents(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<QueuedOutboundIntent>>;
    fn delete_queued_outbound_intent(&self, id: &MessageId) -> StorageResult<()>;
}

// ── LeaveRequestStorage ────────────────────────────────────────────────────

/// Durable user intent to leave a group.
///
/// MLS SelfRemove proposals are epoch-bound, but the product intent is not:
/// once a user asks to leave, the engine keeps trying until a commit actually
/// removes the local member or a future explicit cancel/recovery flow clears
/// the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaveRequest {
    pub group_id: GroupId,
    pub requested_at_ms: u64,
    pub last_proposed_epoch: Option<EpochId>,
}

pub trait LeaveRequestStorage {
    fn put_leave_request(&self, request: &LeaveRequest) -> StorageResult<()>;
    fn leave_request(&self, group_id: &GroupId) -> StorageResult<Option<LeaveRequest>>;
    fn clear_leave_request(&self, group_id: &GroupId) -> StorageResult<()>;
}

// ── WelcomeStorage ──────────────────────────────────────────────────────────

pub trait WelcomeStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()>;
    fn take_welcome(&self, id: &MessageId) -> StorageResult<PendingWelcome>;
    fn list_welcomes(&self) -> StorageResult<Vec<PendingWelcome>>;
}

// ── CapabilityStorage ───────────────────────────────────────────────────────

/// Feature registry + per-member capability cache.
///
/// Per-member capabilities can be read live from OpenMLS, but the cache avoids
/// repeated tree walks, retains capabilities for members who later leave, and
/// keeps `feature_status` a cheap local lookup.
pub trait CapabilityStorage {
    fn register_feature(
        &self,
        feature: crate::capabilities::Feature,
        req: CapabilityRequirement,
    ) -> StorageResult<()>;

    fn feature_requirement(
        &self,
        feature: &crate::capabilities::Feature,
    ) -> StorageResult<Option<CapabilityRequirement>>;

    fn save_member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
        capabilities: GroupCapabilities,
    ) -> StorageResult<()>;

    fn member_capabilities(
        &self,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> StorageResult<Option<GroupCapabilities>>;
}

// ── ConvergencePolicyStorage ────────────────────────────────────────────────

/// Durable per-group convergence policy.
///
/// The storage layer keeps opaque bytes so `cgka_traits` does not need to own
/// the engine's policy schema. Engines are responsible for versioned
/// serialization and validation.
pub trait ConvergencePolicyStorage {
    fn put_convergence_policy(&self, group_id: &GroupId, policy: &[u8]) -> StorageResult<()>;
    fn convergence_policy(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>>;
}

// ── MemberValidationCacheStorage ────────────────────────────────────────────

/// Durable per-group marker certifying that a specific ratchet-tree state
/// already passed member-credential + account-identity-proof validation.
///
/// The engine keys the marker on the exact exported ratchet-tree bytes, so any
/// change to membership, a leaf node, or an account-identity proof yields a
/// different marker and forces full re-validation. Storage keeps opaque bytes;
/// the engine owns marker derivation and versioning. The marker lives in the
/// same encrypted, account-device-scoped database as the group state it
/// certifies, so it never widens the trust boundary: an attacker who could
/// forge a marker row could already tamper the group state it guards.
pub trait MemberValidationCacheStorage {
    fn put_validated_tree_marker(&self, group_id: &GroupId, marker: &[u8]) -> StorageResult<()>;
    fn validated_tree_marker(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>>;
}

// ── AccountDeviceSignerStorage ─────────────────────────────────────────────

/// Account-device-local binding from Marmot identity to MLS signer lookup key.
///
/// OpenMLS stores signature keypairs keyed by their MLS signing public key.
/// Marmot sessions are opened from stable identity bytes instead. For the
/// Nostr-backed profile, those identity bytes are the Nostr public key. This
/// binding lets a session recover which MLS signing keypair belongs to that
/// Marmot account-device identity. Key material itself remains in OpenMLS
/// storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDeviceSignerBinding {
    pub marmot_identity: MemberId,
    pub mls_signature_public_key: Vec<u8>,
}

pub trait AccountDeviceSignerStorage {
    fn put_account_device_signer(&self, binding: &AccountDeviceSignerBinding) -> StorageResult<()>;
    fn account_device_signer(
        &self,
        marmot_identity: &MemberId,
    ) -> StorageResult<Option<AccountDeviceSignerBinding>>;
}

// ── StorageProvider aggregate ───────────────────────────────────────────────

/// The single storage type parameter carried by the engine.
///
/// Marmot storage concerns live on this trait. OpenMLS storage is exposed
/// through `mls_storage()` so the engine can build an `OpenMlsProvider`
/// bundle without hand-forwarding every OpenMLS storage method.
pub trait StorageProvider:
    GroupStorage
    + MessageStorage
    + OutboundIntentStorage
    + LeaveRequestStorage
    + WelcomeStorage
    + CapabilityStorage
    + ConvergencePolicyStorage
    + MemberValidationCacheStorage
    + AccountDeviceSignerStorage
    + Send
    + Sync
{
    /// Concrete OpenMLS storage type this provider owns.
    type Mls: OpenMlsStorageProvider<CURRENT_VERSION> + Send + Sync;

    /// Reference to the OpenMLS storage side. Used by the engine to construct
    /// `OpenMlsProvider`-shaped objects for MLS operations.
    fn mls_storage(&self) -> &Self::Mls;

    /// Run a storage operation inside one backend transaction when the backend
    /// supports it. Backends without transactional support use the closure
    /// directly; SQLite overrides this so multi-write OpenMLS transitions are
    /// committed or rolled back as one unit.
    fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        Self: Sized,
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        f(self)
    }

    fn backend(&self) -> Backend;
}
