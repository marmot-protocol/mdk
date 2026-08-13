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
use crate::convergence_pass::DurableConvergencePass;
use crate::engine::{GroupEvent, SendIntent};
use crate::group::{Group, Member};
use crate::maintenance::{
    DurableGroupEvolution, DurableTransportFanout, GroupMaintenanceState, KeyPackageLifecycleState,
    MaintenanceObligation, PeriodicMaintenancePolicy,
};
use crate::message::{MessageRecord, MessageState};
use crate::transport_adapter::OutboundFanout;
use crate::types::{Backend, EpochId, GroupId, MemberId, MessageId};
use crate::welcome::PendingWelcome;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider as OpenMlsStorageProvider};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

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
    /// A canonical timeline cursor row was removed by retention. Callers should
    /// refresh from the timeline head instead of retrying the stale cursor.
    #[error("timeline cursor no longer exists; refresh the timeline")]
    TimelineCursorExpired,
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
    /// The backend has been closed and will not serve further operations.
    ///
    /// Distinct from [`StorageError::Backend`] because it is an *expected*
    /// terminal state, not a fault: a host that closes its store to release
    /// database file locks before process suspension (see
    /// `docs/marmot-architecture/overview/local-artifact-safety.md`) will race
    /// a small amount of in-flight work, and that work must be reportable as
    /// "we shut down" rather than as storage corruption. Never retryable —
    /// a closed backend is terminal for the handle, and callers reopen a fresh
    /// one instead.
    #[error("backend closed: {0}")]
    Closed(String),
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

    /// Whether this error means the backend has been deliberately closed.
    ///
    /// Callers use this to classify a failure as orderly shutdown rather than
    /// a storage fault — for example to downgrade log severity or to suppress
    /// a user-visible error while an app is being suspended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self, StorageError::Closed(_))
    }
}

pub type StorageResult<T> = Result<T, StorageError>;

/// Immutable, branch-addressed canonical group-state checkpoint.
///
/// The checkpoint id is derived from an authenticated MLS commit, while the
/// resulting epoch is retained only for bounded garbage collection.  Backends
/// must reject an attempt to replace an existing id with different contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStateCheckpointRef {
    pub id: String,
    pub resulting_epoch: EpochId,
}

// ── GroupStorage ────────────────────────────────────────────────────────────

/// CRUD for group metadata (no Nostr types; see `group.rs` invariants).
pub trait GroupStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()>;
    fn get_group(&self, id: &GroupId) -> StorageResult<Group>;
    fn delete_group(&self, id: &GroupId) -> StorageResult<()>;
    fn list_groups(&self) -> StorageResult<Vec<GroupId>>;

    /// Every stored group record in one pass. The engine's session-open seed
    /// walks all records (mdk#1161); backends should override the default
    /// `list_groups` + `get_group` loop with a single query.
    fn list_group_records(&self) -> StorageResult<Vec<Group>> {
        self.list_groups()?
            .iter()
            .map(|id| self.get_group(id))
            .collect()
    }

    /// Durable transport-route index: opaque transport routing-id bytes to
    /// MLS group id, many-to-one (a routing rotation retains the prior route
    /// for its overlap window, mdk#740). Each row carries the group epoch of
    /// the last write that observed the route as current, so the session-open
    /// seed can detect a stale route set (a crash between a commit apply and
    /// the route refresh) and the engine can retire prior routes once no
    /// epoch using them remains inside the retained-history window
    /// (routing-v1 overlap rule). Routes are a regenerable projection of MLS
    /// state — the engine rebuilds a missing route from the loaded group on
    /// demand — so the default implementations store nothing and return
    /// nothing. Backends without an override are correct but pay a per-group
    /// MLS load to re-derive routes on the first inbound lookup after
    /// reopen. No transport *types* here: routes are bytes only (`group.rs`
    /// invariants).
    fn put_transport_group_route(
        &self,
        transport_group_id: &[u8],
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> StorageResult<()> {
        let _ = (transport_group_id, group_id, source_epoch);
        Ok(())
    }

    fn list_transport_group_routes(&self) -> StorageResult<Vec<TransportGroupRoute>> {
        Ok(Vec::new())
    }

    /// Retire one route (routing-v1: a prior address stops being accepted
    /// once no epoch using it remains in either retained-history window).
    fn delete_transport_group_route(&self, transport_group_id: &[u8]) -> StorageResult<()> {
        let _ = transport_group_id;
        Ok(())
    }

    /// Retire every route of `group_id` whose `source_epoch` is below
    /// `cutoff` — the bulk form the engine uses when a route refresh advances
    /// the retention horizon.
    fn delete_transport_group_routes_below_epoch(
        &self,
        group_id: &GroupId,
        cutoff: EpochId,
    ) -> StorageResult<()> {
        let _ = (group_id, cutoff);
        Ok(())
    }

    fn delete_transport_group_routes_for_group(&self, group_id: &GroupId) -> StorageResult<()> {
        let _ = group_id;
        Ok(())
    }
}

/// One durable transport-route row; see
/// [`GroupStorage::put_transport_group_route`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportGroupRoute {
    /// Opaque transport routing-id bytes (no transport types).
    pub transport_group_id: Vec<u8>,
    pub group_id: GroupId,
    /// Group epoch of the last write that observed this route as current.
    pub source_epoch: EpochId,
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
    fn delete_message(&self, id: &MessageId) -> StorageResult<()>;
    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()>;
    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>>;

    /// Whether any retained row for `group_id` at or after `at_or_after_epoch`
    /// is in one of `states`. Hot-path gates (outbound send checks, sweep
    /// short-circuits) call this before deciding whether a full
    /// [`Self::list_messages`] scan is worth paying, so backends should answer
    /// it with an indexed existence probe instead of materializing and
    /// decoding rows. An empty `states` slice answers `false`.
    fn has_messages_in_states(
        &self,
        group_id: &GroupId,
        states: &[MessageState],
        at_or_after_epoch: EpochId,
    ) -> StorageResult<bool> {
        Ok(self
            .list_messages(group_id, at_or_after_epoch)?
            .iter()
            .any(|record| states.contains(&record.state)))
    }

    /// [`Self::list_messages`] restricted to rows whose state is in `states`,
    /// in the same deterministic replay order. Backends should push the state
    /// filter into the query so callers interested in a rare state (for
    /// example `PeelDeferred`) do not pay to materialize and decode every
    /// retained row. An empty `states` slice returns no rows.
    fn list_messages_in_states(
        &self,
        group_id: &GroupId,
        states: &[MessageState],
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        Ok(self
            .list_messages(group_id, at_or_after_epoch)?
            .into_iter()
            .filter(|record| states.contains(&record.state))
            .collect())
    }

    /// Persist authenticated app-visible output until its app projection has
    /// committed. Implementations accept `MessageReceived` and `GroupJoined`,
    /// keyed by their source message or Welcome id, and reject other events.
    /// The engine calls this on the same transaction rail that marks the source
    /// input processed, closing the crash gap between protocol ingest and app
    /// projection.
    fn put_pending_application_event(&self, event: &GroupEvent) -> StorageResult<()>;

    /// Return pending app-visible outputs in deterministic ingress order.
    fn list_pending_application_events(&self) -> StorageResult<Vec<GroupEvent>>;

    /// Acknowledge app-visible outputs only after their app projection has
    /// committed. Unknown ids are harmless so replay remains idempotent.
    fn delete_pending_application_events(&self, ids: &[MessageId]) -> StorageResult<()>;

    /// Persist a terminal duplicate-detection marker for inbound protocol
    /// material that cannot yet be associated with a group (notably malformed
    /// or rejected welcomes). Markers are account-device scoped and may be
    /// keyed by either the transport id or a content-derived id.
    fn put_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<()>;
    fn has_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<bool>;

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;

    /// [`Self::create_group_snapshot`] scoped to canonical group state: the
    /// group record, member capabilities, convergence policy, validation
    /// marker, and group-scoped OpenMLS values — the message ledger and
    /// outbound queue are not captured, and rolling back to such a snapshot
    /// leaves those tables untouched. Use this for snapshots taken on every
    /// canonical advance (retained anchors), where capturing the whole
    /// retained message history would make each applied commit O(stored
    /// bytes).
    ///
    /// Callers must not depend on the narrower scope for correctness: the
    /// default implementation captures a full snapshot, whose rollback also
    /// restores messages and queued outbound work (a superset image is always
    /// an acceptable substitute).
    fn create_group_state_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.create_group_snapshot(group_id, name)
    }

    fn list_group_snapshots(&self, group_id: &GroupId) -> StorageResult<Vec<String>>;
    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;
    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;

    /// Capture only canonical group state: the Marmot group projection,
    /// member-capability projection, validation marker, and every group-scoped
    /// OpenMLS provider value. Messages, outbound queues, and convergence-pass
    /// bookkeeping are deliberately excluded.
    fn create_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint: &GroupStateCheckpointRef,
    ) -> StorageResult<()>;

    fn restore_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()>;

    fn list_group_state_checkpoints(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<GroupStateCheckpointRef>>;

    fn release_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()>;
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

// ── OutboundFanoutStorage ──────────────────────────────────────────────────

/// Durable frozen transport fanouts, keyed by the signed message id.
pub trait OutboundFanoutStorage {
    fn put_outbound_fanout(&self, fanout: &OutboundFanout) -> StorageResult<()>;

    fn outbound_fanout(&self, message_id: &MessageId) -> StorageResult<Option<OutboundFanout>>;

    fn list_outbound_fanouts(&self) -> StorageResult<Vec<OutboundFanout>>;

    /// Read fanouts for one MLS group in original staging order.
    ///
    /// Hydration uses this indexed lookup instead of scanning every account
    /// fanout once per group.
    fn list_outbound_fanouts_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<OutboundFanout>>;

    /// Remove a terminal fanout after its outcome has been surfaced.
    fn delete_outbound_fanout(&self, message_id: &MessageId) -> StorageResult<()>;
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

// ── DisbandRequestStorage ──────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisbandFailureReason {
    NoLongerAdmin,
    NoLongerMember,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisbandRequestStatus {
    #[default]
    Pending,
    Failed(DisbandFailureReason),
}

/// Durable irreversible product intent to terminate a group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisbandRequest {
    pub group_id: GroupId,
    pub requested_at_ms: u64,
    #[serde(default)]
    pub status: DisbandRequestStatus,
    /// Last epoch for which this client prepared a disband Commit. The product
    /// intent is not epoch-bound; a losing branch clears this and retries.
    pub last_prepared_epoch: Option<EpochId>,
}

pub trait DisbandRequestStorage {
    fn put_disband_request(&self, request: &DisbandRequest) -> StorageResult<()>;
    fn disband_request(&self, group_id: &GroupId) -> StorageResult<Option<DisbandRequest>>;
    fn clear_disband_request(&self, group_id: &GroupId) -> StorageResult<()>;
}

/// Authenticated terminal Commit evidence retained while the Commit competes
/// in the mandatory bounded convergence pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisbandCandidate {
    pub group_id: GroupId,
    pub source_epoch: EpochId,
    /// Identifier used by the durable convergence record. Locally authored
    /// commits use the exact signed transport id; inbound commits are already
    /// rebound to their content-derived id by ingest.
    pub commit_id: MessageId,
    /// SHA-256 of the MLS commit bytes, matching convergence's canonical
    /// cross-transport identifier.
    pub content_commit_id: MessageId,
    pub commit_digest: [u8; 32],
    pub actor: crate::types::MemberId,
    pub local_was_committer_leaf: bool,
    /// Deduplicated account roster from the candidate parent.
    pub former_members: Vec<crate::group::Member>,
}

pub trait DisbandCandidateStorage {
    fn put_disband_candidate(&self, candidate: &DisbandCandidate) -> StorageResult<()>;
    fn disband_candidate(
        &self,
        group_id: &GroupId,
        commit_id: &MessageId,
    ) -> StorageResult<Option<DisbandCandidate>>;
    fn list_disband_candidates(&self, group_id: &GroupId) -> StorageResult<Vec<DisbandCandidate>>;
    fn clear_disband_candidates(&self, group_id: &GroupId) -> StorageResult<()>;
}

/// Minimal authenticated terminal guard. Unlike the presentation `Group`
/// record this row deliberately has no foreign key, so deleting local history
/// cannot make a disbanded MLS group id joinable again.
pub trait DisbandTombstoneStorage {
    fn put_disband_tombstone(
        &self,
        group_id: &GroupId,
        tombstone: &crate::group::DisbandTombstone,
    ) -> StorageResult<()>;
    fn disband_tombstone(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<crate::group::DisbandTombstone>>;

    /// Enumerate terminal guards independently from live group records. This is
    /// required after a user deletes local history and only the anti-
    /// resurrection tombstone remains.
    fn list_disband_tombstones(
        &self,
    ) -> StorageResult<Vec<(GroupId, crate::group::DisbandTombstone)>>;
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

// ── KeyPackageBundleStorage ────────────────────────────────────────────────

/// Account-device-local enumeration of persisted OpenMLS KeyPackage bundles.
///
/// OpenMLS exposes point lookup and deletion by KeyPackage reference, but no
/// enumeration API. A strict protocol-profile cutover must nevertheless find
/// and retire every legacy bundle, including unpublished bundles for which the
/// application has no public-event cache entry. Storage therefore exposes the
/// serialized OpenMLS entities as opaque bytes; the engine owns their schema,
/// profile classification, and deletion.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredKeyPackageBundle {
    pub storage_key: Vec<u8>,
    /// Serialized `KeyPackageBundle`, including its private init and leaf keys.
    pub value: Zeroizing<Vec<u8>>,
}

struct RedactedValue;

impl fmt::Debug for RedactedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Debug for StoredKeyPackageBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredKeyPackageBundle")
            .field("storage_key", &self.storage_key)
            .field("value", &RedactedValue)
            .finish()
    }
}

pub trait KeyPackageBundleStorage {
    fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>>;
    fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()>;
}

// ── MaintenanceStorage ─────────────────────────────────────────────────────

/// Account-device-local maintenance and immutable publication recovery.
///
/// Implementations must keep these records in the same encrypted database as
/// the MLS state.  Multi-record transitions use `StorageProvider::with_transaction`.
pub trait MaintenanceStorage {
    fn key_package_lifecycle(&self) -> StorageResult<Option<KeyPackageLifecycleState>>;
    fn put_key_package_lifecycle(&self, state: &KeyPackageLifecycleState) -> StorageResult<()>;

    fn group_maintenance(&self, group_id: &GroupId)
    -> StorageResult<Option<GroupMaintenanceState>>;
    fn put_group_maintenance(&self, state: &GroupMaintenanceState) -> StorageResult<()>;
    fn delete_group_maintenance(&self, group_id: &GroupId) -> StorageResult<()>;

    fn put_maintenance_obligation(&self, record: &MaintenanceObligation) -> StorageResult<()>;
    fn maintenance_obligation(
        &self,
        id: &MessageId,
    ) -> StorageResult<Option<MaintenanceObligation>>;
    fn list_maintenance_obligations(&self) -> StorageResult<Vec<MaintenanceObligation>>;
    fn list_maintenance_obligations_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<MaintenanceObligation>>;
    fn delete_maintenance_obligation(&self, id: &MessageId) -> StorageResult<()>;

    fn put_group_evolution(&self, record: &DurableGroupEvolution) -> StorageResult<()>;
    fn group_evolution(&self, id: &MessageId) -> StorageResult<Option<DurableGroupEvolution>>;
    fn list_group_evolutions(&self) -> StorageResult<Vec<DurableGroupEvolution>>;
    fn list_group_evolutions_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<DurableGroupEvolution>>;
    fn delete_group_evolution(&self, id: &MessageId) -> StorageResult<()>;

    fn put_transport_fanout(&self, record: &DurableTransportFanout) -> StorageResult<()>;
    fn transport_fanout(&self, id: &MessageId) -> StorageResult<Option<DurableTransportFanout>>;
    fn list_transport_fanouts(&self) -> StorageResult<Vec<DurableTransportFanout>>;
    fn delete_transport_fanout(&self, id: &MessageId) -> StorageResult<()>;

    fn periodic_maintenance_policy(&self) -> StorageResult<PeriodicMaintenancePolicy>;
    fn put_periodic_maintenance_policy(
        &self,
        policy: PeriodicMaintenancePolicy,
    ) -> StorageResult<()>;
}

// ── ConvergencePassStorage ─────────────────────────────────────────────────

/// Account-device-local frozen convergence-pass state.
///
/// This is a required part of the engine store because resolving a mutable
/// re-enumeration after restart would violate the convergence cutoff.
pub trait ConvergencePassStorage {
    fn convergence_pass(&self, group_id: &GroupId)
    -> StorageResult<Option<DurableConvergencePass>>;
    fn put_convergence_pass(&self, pass: &DurableConvergencePass) -> StorageResult<()>;
    fn list_convergence_passes(&self) -> StorageResult<Vec<DurableConvergencePass>>;
    fn delete_convergence_pass(&self, group_id: &GroupId) -> StorageResult<()>;
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
    + OutboundFanoutStorage
    + LeaveRequestStorage
    + DisbandRequestStorage
    + DisbandCandidateStorage
    + DisbandTombstoneStorage
    + WelcomeStorage
    + CapabilityStorage
    + ConvergencePolicyStorage
    + ConvergencePassStorage
    + MemberValidationCacheStorage
    + AccountDeviceSignerStorage
    + KeyPackageBundleStorage
    + Send
    + Sync
{
    /// Concrete OpenMLS storage type this provider owns.
    type Mls: OpenMlsStorageProvider<CURRENT_VERSION> + Send + Sync;

    /// Reference to the OpenMLS storage side. Used by the engine to construct
    /// `OpenMlsProvider`-shaped objects for MLS operations.
    fn mls_storage(&self) -> &Self::Mls;

    /// Optional account-device maintenance store.
    ///
    /// This is accessor composition for the same reason as `mls_storage()`:
    /// fault-injection and alternate engine stores that predate maintenance
    /// remain valid `StorageProvider`s, while production SQLCipher storage
    /// exposes the durable maintenance capability.
    fn maintenance_storage(&self) -> Option<&dyn MaintenanceStorage> {
        None
    }

    /// Run a storage operation inside one backend transaction when the backend
    /// supports it. Backends without transactional support use the closure
    /// directly; SQLite overrides this so multi-write OpenMLS transitions are
    /// committed or rolled back as one unit.
    ///
    /// The closure receives this same provider, and every write issued on it
    /// for the closure's duration joins the one unit — whether through the
    /// passed handle or through another reference to the same value. Engine
    /// helpers that write through their own `&S` field rely on this, so an
    /// implementation must not hand the closure a different connection or a
    /// distinct `Self`: that would silently split a unit whose atomicity
    /// callers depend on.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_key_package_debug_redacts_serialized_private_key_material() {
        let bundle = StoredKeyPackageBundle {
            storage_key: b"public-storage-key".to_vec(),
            value: Zeroizing::new(vec![222, 173, 190, 239]),
        };
        let debug = format!("{bundle:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("222, 173, 190, 239"));
    }
}
