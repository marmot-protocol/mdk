//! The `CgkaEngine` trait — application's sole contact with the engine.
//!
//! Application code never calls OpenMLS directly, never instantiates a
//! concrete engine type, never touches transport bytes beyond passing them
//! into [`CgkaEngine::ingest`]. This trait is the boundary.
//!
//! ### Signature note
//!
//! `drain_events` and `drain_auto_publish` are explicit drains. They are
//! simple to reason about in a single-threaded coordinator loop and do not
//! force the engine to hold a broadcast channel.
//!
//! ### `#[async_trait]` vs. native AFIT
//!
//! Stable Rust's async-fn-in-traits + dyn-safety story is still unsettled.
//! `#[async_trait]` is the pragmatic choice for 0.1.0 — it gives us
//! `Box<dyn CgkaEngine + Send + Sync>` today and can be dropped later without
//! breaking the contract.

use crate::app_components::{AppComponentData, AppComponentId};
use crate::capabilities::{Feature, FeatureStatus, GroupCapabilities};
use crate::engine_state::PendingStateRef;
use crate::error::EngineError;
use crate::group::Member;
use crate::group_context::{GroupContext, SecretBytes};
use crate::ingest::IngestOutcome;
use crate::transport::TransportMessage;
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// Remove existing members from the group.
    RemoveMembers {
        group_id: GroupId,
        members: Vec<MemberId>,
    },
    /// Leave the group via MIP-03 SelfRemove.
    Leave { group_id: GroupId },
    /// Update one or more MLS app-component dictionary entries.
    ///
    /// This is the generic path for group settings such as profile,
    /// admin policy, routing, image metadata, retention, and stream policy.
    /// Component-specific validation and admin authorization live in the
    /// engine and are checked on outbound send and inbound commit ingest.
    UpdateAppComponents {
        group_id: GroupId,
        updates: Vec<AppComponentData>,
    },
    /// Update the group's `marmot.group.profile.v1` app component fields.
    UpdateGroupData {
        group_id: GroupId,
        name: Option<String>,
        description: Option<String>,
    },
}

/// The engine's response to [`CgkaEngine::send`].
///
/// `GroupEvolution` carries both the commit and any welcomes produced by
/// member additions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendResult {
    /// Pure application message — publish once, no state advance.
    ApplicationMessage { msg: TransportMessage },
    /// The engine accepted the local intent but did not publish anything
    /// yet because the group has unresolved convergence input. The intent
    /// will be regenerated from the canonical state when the group becomes
    /// stable.
    Queued {
        group_id: GroupId,
        intent_id: MessageId,
    },
    /// A proposal that does not itself advance the epoch — application
    /// publishes it and moves on. The epoch advance happens later via an
    /// auto-committer (per MIP-03 SelfRemove) or another member's commit.
    /// No `confirm_published` required, no `PendingStateRef` issued.
    Proposal { msg: TransportMessage },
    /// Commit (+ optional welcomes) that EXISTING group members need to
    /// process. Used for invite / remove / update to an existing group.
    /// Application must publish `msg` and call
    /// [`CgkaEngine::confirm_published`] with `pending` once the commit meets
    /// the transport's required acknowledgements. Welcome delivery is
    /// independent: a failed welcome must not roll back a live commit.
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

/// Group evolution produced as a side effect of inbound processing.
///
/// Auto-publish work follows the same publish-before-apply contract as
/// [`SendResult::GroupEvolution`]: the application publishes `msg`, then calls
/// [`CgkaEngine::confirm_published`] or [`CgkaEngine::publish_failed`] with
/// `pending`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoPublish {
    pub msg: TransportMessage,
    pub pending: PendingStateRef,
}

/// Why an application message did not become canonical group output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppMessageInvalidationReason {
    LosingBranch,
    BeyondAnchor,
    BeyondAppRetention,
    UndecryptableInCanonicalState,
}

/// Deterministic, content-derived ordering key used to resolve same-epoch
/// commit races. Two replicas processing the same commit derive the same key
/// from the same MLS wire bytes, independent of transport metadata. Lower keys
/// win: first by `source_epoch`, then by `commit_digest` bytes.
///
/// `commit_digest` is `SHA-256(mls_bytes)` — the hash of the serialized MLS
/// message as it appears on the wire. This works for both `PublicMessage` and
/// `PrivateMessage` framings because we hash the wire form, not the inner
/// content; no decryption is required to compute it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitOrderingKey {
    pub source_epoch: EpochId,
    pub commit_digest: [u8; 32],
}

impl CommitOrderingKey {
    /// Build an ordering key from a commit's serialized MLS wire bytes.
    pub fn from_commit_bytes(source_epoch: EpochId, mls_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(mls_bytes);
        Self {
            source_epoch,
            commit_digest: hasher.finalize().into(),
        }
    }
}

impl Ord for CommitOrderingKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.source_epoch
            .cmp(&other.source_epoch)
            .then_with(|| self.commit_digest.cmp(&other.commit_digest))
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
    AppMessageInvalidated {
        group_id: GroupId,
        message_id: MessageId,
        epoch: EpochId,
        reason: AppMessageInvalidationReason,
        decrypted_payload_ref: Option<String>,
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
    /// The group entered the `Unrecoverable` state: convergence reported a
    /// `MissingRetainedAnchor` inside the rollback horizon, so the client
    /// stopped applying group-state changes and now needs a verified repair
    /// path. See `spec/protocol-core/group-state.md:54-66`.
    GroupUnrecoverable {
        group_id: GroupId,
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
    /// Initial app-component state that must be present in the new group.
    /// The engine requires every founding member to advertise these component
    /// ids and writes the bytes into the group's `app_data_dictionary`.
    pub app_components: Vec<AppComponentData>,
    /// Initial admin set, projected to `marmot.group.admin-policy.v1`.
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

/// The application-facing contract of the engine.
///
/// Method docs describe legal state transitions and error classes.
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

    /// Drain group evolution the engine produced as a side effect of `ingest`
    /// (e.g. auto-committing a received SelfRemove proposal per the
    /// lowest-index rule). These are not tied to a `SendIntent`, but they are
    /// still publish-before-apply obligations: the application must publish
    /// each message and then call [`Self::confirm_published`] or
    /// [`Self::publish_failed`] with its pending reference.
    fn drain_auto_publish(&mut self) -> Vec<AutoPublish>;

    // ── Outbound ────────────────────────────────────────────────────────────

    /// Encrypt + prepare an outbound message or group operation.
    ///
    /// **State.** Valid when the group is in `Stable`. If convergence input
    /// is still unresolved, the engine stores the intent and returns
    /// [`SendResult::Queued`]. Returns `InvalidTransition` if called during
    /// `PendingPublish` / `Merging`.
    async fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError>;

    /// Advance convergence for a group and release any queued outbound work
    /// that is now safe to regenerate from the selected canonical state.
    /// Accepted inbound application messages from the canonical branch are
    /// appended to [`Self::drain_events`] as [`GroupEvent::MessageReceived`].
    /// Invalidated application messages are appended as
    /// [`GroupEvent::AppMessageInvalidated`] so applications can decide
    /// whether to hide, annotate, or surface them separately.
    ///
    /// Applications should call this after relay sync batches, reconnect
    /// catch-up, or a convergence timer tick. The engine uses its local
    /// monotonic lifecycle clock to decide whether the quiescence window has
    /// elapsed.
    ///
    /// Returns publishable [`SendResult`] values. If a queued group evolution
    /// is regenerated, the engine stops after that result because the group
    /// enters `PendingPublish` until the application reports
    /// [`Self::confirm_published`] or [`Self::publish_failed`]. Calls made
    /// while the group is already in `PendingPublish` / `Merging` return no
    /// publishable work.
    async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Vec<SendResult>, EngineError>;

    /// Confirm that a [`SendResult::GroupEvolution`] (or
    /// [`SendResult::GroupCreated`]) was successfully published to the
    /// transport. The engine applies the staged commit to local MLS state,
    /// updates Marmot bookkeeping + capability cache, and emits
    /// `GroupEvent::EpochChanged` (or `GroupCreated`).
    ///
    /// **Publish-before-apply contract.** The engine must NOT have applied
    /// the commit before this call: if the application calls
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

    /// Derive and consume a forward-secure MLS app-component export secret.
    ///
    /// This is OpenMLS's SafeExportSecret(ComponentID) path. It mutates the
    /// MLS application export tree so the same component secret cannot be
    /// derived twice in the same epoch. Returned bytes are key material and
    /// must not be logged, persisted in plaintext, or surfaced in diagnostics.
    fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<SecretBytes, EngineError>;

    /// Signed app-component bytes from the group's current
    /// `app_data_dictionary`.
    fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<Option<Vec<u8>>, EngineError>;

    fn members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError>;

    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError>;

    /// Stable identity of the local client across every group.
    fn self_id(&self) -> MemberId;

    /// Produce a fresh KeyPackage suitable for publishing to a KeyPackage
    /// directory. Expiry and refresh scheduling live above the engine.
    async fn fresh_key_package(&mut self) -> Result<KeyPackage, EngineError>;
}
