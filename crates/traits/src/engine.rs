//! The `CgkaEngine` trait — application's sole contact with the engine.
//!
//! Application code never calls OpenMLS directly, never instantiates a
//! concrete engine type, never touches transport bytes beyond passing them
//! into [`CgkaEngine::ingest`]. This trait is the boundary.
//!
//! ### Signature note
//!
//! `drain_events` + `drain_auto_publish` supersede the design doc's
//! `events() -> BoxStream<'_, GroupEvent>` per spike-findings §1.7. Drains
//! are simpler to reason about in a single-threaded coordinator loop and
//! don't force the engine to hold a broadcast channel.
//!
//! ### `#[async_trait]` vs. native AFIT
//!
//! Stable Rust's async-fn-in-traits + dyn-safety story is still unsettled.
//! `#[async_trait]` is the pragmatic choice for 0.1.0 — it gives us
//! `Box<dyn CgkaEngine + Send + Sync>` today and can be dropped later without
//! breaking the contract.

use crate::capabilities::{Feature, FeatureStatus, GroupCapabilities};
use crate::engine_state::PendingStateRef;
use crate::error::EngineError;
use crate::group::Member;
use crate::group_context::GroupContext;
use crate::ingest::IngestOutcome;
use crate::transport::{Timestamp, TransportMessage};
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

// ── Value types on the trait surface ────────────────────────────────────────

/// Opaque KeyPackage bytes. The engine validates and parses internally; the
/// application layer just shuttles these between KeyPackage-publish events
/// and [`SendIntent::Invite`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyPackage(pub Vec<u8>);

/// Application's intent when calling [`CgkaEngine::send`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendIntent {
    /// Encrypt + send an application-layer payload to the group.
    AppMessage { group_id: GroupId, payload: Vec<u8> },
    /// Invite new members via their KeyPackages.
    Invite {
        group_id: GroupId,
        key_packages: Vec<KeyPackage>,
    },
    /// Leave the group via MIP-03 SelfRemove.
    Leave { group_id: GroupId },
    /// Update the group's `BasicGroupData` extension fields.
    UpdateGroupData {
        group_id: GroupId,
        name: Option<String>,
        description: Option<String>,
    },
}

/// The engine's response to [`CgkaEngine::send`].
///
/// `GroupEvolution` carries both the commit and any welcomes produced by
/// member additions — the spike discovered the original single-`msg` shape
/// was structurally insufficient (spike-findings §1.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendResult {
    /// Pure application message — publish once, no state advance.
    ApplicationMessage { msg: TransportMessage },
    /// A proposal that does not itself advance the epoch — application
    /// publishes it and moves on. The epoch advance happens later via an
    /// auto-committer (per MIP-03 SelfRemove) or an explicit
    /// `SendIntent::Commit*` from some member. No `confirm_published`
    /// required, no `PendingStateRef` issued.
    Proposal { msg: TransportMessage },
    /// Commit (+ optional welcomes) that EXISTING group members need to
    /// process. Used for invite / remove / update to an existing group.
    /// Application must publish ALL outputs and then call
    /// [`CgkaEngine::confirm_published`] with `pending` so the engine can
    /// advance its epoch.
    GroupEvolution {
        msg: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
    },
    /// Initial group creation. Only `welcomes` need publishing — there's no
    /// pre-existing member to consume a commit, so the founding client
    /// doesn't emit one. The application calls
    /// [`CgkaEngine::confirm_published`] once every welcome is handed off
    /// to the transport.
    GroupCreated {
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
    },
}

/// Deterministic transport ordering key used to resolve same-epoch commit
/// races. Lower keys win: first by transport timestamp, then by message id
/// bytes as the stable tie-breaker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitOrderingKey {
    pub timestamp: Timestamp,
    pub message_id: MessageId,
}

impl CommitOrderingKey {
    pub fn from_transport_message(msg: &TransportMessage) -> Self {
        Self {
            timestamp: msg.timestamp,
            message_id: msg.id.clone(),
        }
    }
}

impl Ord for CommitOrderingKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.message_id.as_slice().cmp(other.message_id.as_slice()))
    }
}

impl PartialOrd for CommitOrderingKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Ordered, decrypted output the application should render / act on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupEvent {
    GroupCreated {
        group_id: GroupId,
    },
    GroupJoined {
        group_id: GroupId,
        via_welcome: MessageId,
    },
    MessageReceived {
        group_id: GroupId,
        sender: MemberId,
        payload: Vec<u8>,
    },
    MemberAdded {
        group_id: GroupId,
        member: Member,
    },
    MemberRemoved {
        group_id: GroupId,
        member: MemberId,
    },
    EpochChanged {
        group_id: GroupId,
        from: EpochId,
        to: EpochId,
    },
    ForkRecovered {
        group_id: GroupId,
        source_epoch: EpochId,
        recovered_epoch: EpochId,
        winner: CommitOrderingKey,
        invalidated: CommitOrderingKey,
    },
}

/// Request shape for [`CgkaEngine::create_group`]. Carries the intended
/// transports so the engine can populate the right extensions (per
/// `docs/marmot-architecture/further-context/cgka-engine-design.md:431-440`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: String,
    pub members: Vec<KeyPackage>,
    pub required_features: Vec<Feature>,
    /// Initial admin set (per MIP-01 `marmot_group_data.admin_pubkeys`).
    /// The **creator is always implicitly added** to this set — pass
    /// additional `MemberId`s here to bootstrap a multi-admin group.
    /// Default (empty) → creator is sole admin.
    ///
    /// Per MIP-03 §149/§150, admins cannot self-remove if doing so would
    /// deplete the admin set. Bootstrapping with co-admins is the only
    /// way (in 0.1.0) for an admin to subsequently leave the group, since
    /// engine-level admin promotion lands in a follow-on plan.
    pub initial_admins: Vec<MemberId>,
}

// ── The trait ───────────────────────────────────────────────────────────────

/// The entire application-facing contract of the engine.
///
/// See the module doc for the high-level factoring; every method's
/// invariants, legal state transitions, and error classes are documented
/// inline below (Task 3.7 of the production refactor plan).
#[async_trait]
pub trait CgkaEngine: Send + Sync {
    // ── Inbound ─────────────────────────────────────────────────────────────

    /// Ingest a raw transport message.
    ///
    /// **Invariants.** May be called in any order — the engine's coordinator
    /// stores and sequences internally. Calls while the group is in
    /// [`crate::engine_state::EpochState::PendingPublish`] or
    /// [`crate::engine_state::EpochState::Merging`] return
    /// [`IngestOutcome::Buffered`] and replay once the state returns to
    /// `Stable`.
    ///
    /// **Errors.** `UnknownGroup`, `Peeler`, `ForkedEpoch`, `Backend`. Stale
    /// / duplicate / not-for-us messages return
    /// `Ok(IngestOutcome::Stale { .. })`, **not** `Err`.
    async fn ingest(&mut self, msg: TransportMessage) -> Result<IngestOutcome, EngineError>;

    /// Drain ordered `GroupEvent`s produced since the last drain. Application
    /// typically calls this right after every `ingest` batch.
    fn drain_events(&mut self) -> Vec<GroupEvent>;

    /// Drain transport messages the engine produced as a side-effect of
    /// `ingest` (e.g. auto-committing a received SelfRemove proposal per the
    /// lowest-index rule). These are NOT tied to a `SendIntent` — the
    /// application should publish them but does not need to call
    /// `confirm_published` on any of them.
    fn drain_auto_publish(&mut self) -> Vec<TransportMessage>;

    // ── Outbound ────────────────────────────────────────────────────────────

    /// Encrypt + prepare an outbound message or group operation.
    ///
    /// **State.** Valid only when the group is in `Stable`. Returns
    /// `InvalidTransition` if called during `PendingPublish` / `Merging`.
    async fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError>;

    /// Confirm that a [`SendResult::GroupEvolution`] (or
    /// [`SendResult::GroupCreated`]) was successfully published to the
    /// transport. The engine applies the staged commit to local MLS state,
    /// updates Marmot bookkeeping + capability cache, and emits
    /// `GroupEvent::EpochChanged` (or `GroupCreated`).
    ///
    /// **Publish-before-apply contract** (Task 4.13). The engine must NOT
    /// have applied the commit before this call: if the application calls
    /// `epoch()` between `send` and `confirm_published`, the visible
    /// `EpochState` is `PendingPublish`. Other clients can only observe the
    /// new epoch once `confirm_published` returns, ensuring the engine's
    /// reported epoch is always one the network has had a chance to see.
    ///
    /// **Errors.** `UnknownPending` if the ref has already been confirmed,
    /// rolled back, or was never issued.
    async fn confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError>;

    /// Report that a [`SendResult::GroupEvolution`] (or
    /// [`SendResult::GroupCreated`]) failed to publish. The engine
    /// discards the staged commit (`MlsGroup::clear_pending_commit`),
    /// rewinds Marmot/cache state to its pre-stage shape, and transitions
    /// back to `Stable` at the prior epoch. The group is immediately
    /// usable for a fresh `send`.
    ///
    /// **Errors.** `UnknownPending` if the ref has already been confirmed,
    /// rolled back, or was never issued.
    async fn publish_failed(&mut self, pending: PendingStateRef) -> Result<(), EngineError>;

    // ── Lifecycle ───────────────────────────────────────────────────────────

    /// Create a new group with the named members (via their KeyPackages) and
    /// the requested required features. Returns the new `GroupId` and a
    /// `SendResult::GroupEvolution` carrying the initial welcomes.
    ///
    /// **Validation.** Every invitee's KeyPackage must advertise the union of
    /// capabilities required by `required_features`. On mismatch, returns
    /// `MissingRequiredCapabilities`.
    async fn create_group(
        &mut self,
        req: CreateGroupRequest,
    ) -> Result<(GroupId, SendResult), EngineError>;

    /// Accept a welcome addressed to the local identity.
    ///
    /// **Errors.** Returns `Peeler(...)` if the welcome was not addressed to
    /// us; `UnknownGroup` if the welcome references an already-joined group.
    async fn join_welcome(&mut self, welcome_msg: TransportMessage)
    -> Result<GroupId, EngineError>;

    // ── Capabilities ────────────────────────────────────────────────────────

    /// Current status of a feature in a group.
    fn feature_status(
        &self,
        group_id: &GroupId,
        feature: &Feature,
    ) -> Result<FeatureStatus, EngineError>;

    /// Capabilities that would result from constructing a group with the
    /// given members (intersection of every invitee's advertised caps).
    fn constructable_capabilities(
        &self,
        key_packages: &[KeyPackage],
    ) -> Result<GroupCapabilities, EngineError>;

    /// Capabilities the group's current members could support but that are
    /// not yet in `RequiredCapabilities`. Applying
    /// [`Self::upgrade_group_capabilities`] adds all of these atomically.
    fn upgradeable_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupCapabilities, EngineError>;

    /// Upgrade the group to require every currently-upgradeable capability.
    /// Produces a `SendResult::GroupEvolution` whose commit updates
    /// `RequiredCapabilities`.
    async fn upgrade_group_capabilities(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendResult, EngineError>;

    // ── Inspection ──────────────────────────────────────────────────────────

    /// Current engine-internal view of the group (exporter secrets, epoch,
    /// transport group id). Read-only. Returns `Box<dyn>` because the
    /// underlying type varies with the storage parameter.
    fn group_context(&self, group_id: &GroupId) -> Result<Box<dyn GroupContext + '_>, EngineError>;

    fn members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError>;

    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError>;

    /// Stable identity of the local client across every group.
    fn self_id(&self) -> MemberId;

    /// Produce a fresh KeyPackage suitable for publishing to a KeyPackage
    /// directory. Expiry / refresh scheduling is deferred (Task 7 in the
    /// production refactor plan).
    async fn fresh_key_package(&mut self) -> Result<KeyPackage, EngineError>;
}
