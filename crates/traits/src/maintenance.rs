//! Durable maintenance and publication-recovery value types.
//!
//! These records deliberately describe semantic work separately from a
//! transport fanout.  A group evolution becomes canonical after the first
//! accepted transport acknowledgement, while the immutable signed event can
//! still have outstanding per-endpoint delivery work.

use crate::engine::KeyPackage;
use crate::engine_state::PendingStateRef;
use crate::transport::{Timestamp, TransportMessage};
use crate::transport_adapter::{TransportEndpoint, TransportPublishTarget};
use crate::types::{EpochId, GroupId, MessageId};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const POST_JOIN_CONTENTION_JITTER_MAX_MS: u64 = 30_000;

/// Injectable wall clock for persisted maintenance deadlines.
pub trait WallClock: Send + Sync {
    fn now(&self) -> Timestamp;

    /// Milliseconds since the Unix epoch.
    ///
    /// Persisted sub-second deadlines must use this value directly. Implementors
    /// must not derive it from [`Self::now`], whose protocol timestamp has
    /// second precision.
    fn now_ms(&self) -> u64;
}

/// Injectable monotonic clock for process-local quiet windows and timeouts.
pub trait MonotonicClock: Send + Sync {
    fn elapsed(&self) -> Duration;
}

/// Injectable entropy source. Every sampled delay is persisted before use.
pub trait MaintenanceRandom: Send + Sync {
    fn next_u64(&self) -> u64;

    fn sample_inclusive(&self, minimum: u64, maximum: u64) -> u64 {
        if minimum >= maximum {
            return minimum;
        }
        let span = maximum.saturating_sub(minimum).saturating_add(1);
        minimum.saturating_add(self.next_u64() % span)
    }
}

/// Why an own-leaf rotation is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceTrigger {
    PostJoin,
    Periodic,
    Manual,
}

/// Persisted lifecycle of a semantic maintenance obligation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenancePhase {
    CatchUp,
    EoseTimeout,
    Grace,
    Quiet,
    Jitter,
    Overdue,
    Paused,
    ClockSkewBlocked,
    PendingPublication,
    Fanout,
    Retry,
    SupersededByConvergence,
    #[default]
    Complete,
    Failed,
}

impl MaintenancePhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CatchUp => "catch_up",
            Self::EoseTimeout => "eose_timeout",
            Self::Grace => "grace",
            Self::Quiet => "quiet",
            Self::Jitter => "jitter",
            Self::Overdue => "overdue",
            Self::Paused => "paused",
            Self::ClockSkewBlocked => "clock_skew_blocked",
            Self::PendingPublication => "pending_publication",
            Self::Fanout => "fanout",
            Self::Retry => "retry",
            Self::SupersededByConvergence => "superseded_by_convergence",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }
}

/// Durable per-group enrollment and own-leaf rotation history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMaintenanceState {
    pub group_id: GroupId,
    /// Successful group creation/join time.  Old rows without this field are
    /// deliberately not eligible for automatic periodic maintenance.
    pub enrolled_at: Option<Timestamp>,
    pub periodic_enrolled: bool,
    pub last_own_leaf_rotation_at: Option<Timestamp>,
    pub next_periodic_rotation_at: Option<Timestamp>,
    /// When to replace an own leaf that advertises fewer app components than
    /// this device supports. Sampled once per stale period so a release does
    /// not make every member of a group commit at once; cleared once the leaf
    /// is current. Independent of periodic enrollment.
    #[serde(default)]
    pub leaf_refresh_due_at: Option<Timestamp>,
    /// The temporary history fetch of a copy installed from a Welcome. A
    /// replacement Welcome rewrites this whole state, so it starts a new fetch.
    /// `None` for a created group and for copies joined before fetches were
    /// recorded.
    #[serde(default)]
    pub post_join_history: Option<PostJoinHistoryFetch>,
}

/// A joined copy's fetch of the group messages its delivery endpoints hold from
/// its Welcome on. Once a relay reaches end-of-stored-events it lasts until this
/// device has processed what the fetch delivered; until then it lasts until its
/// deadline. Commits end neither: the post-join self-update, whose obligation
/// commits move to its quiet window, is separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostJoinHistoryFetch {
    /// The post-join obligation created with this copy. Identifies the fetch,
    /// so work for an earlier copy of the group cannot complete it.
    pub obligation_id: MessageId,
    /// When the fetch's current subscription stops waiting for its first
    /// end-of-stored-events. Set at each installation: a restart or a lost
    /// subscription resumes the fetch with a fresh one.
    pub deadline_at: Option<Timestamp>,
    /// `None` while the fetch is owed.
    pub completion: Option<PostJoinHistoryFetchCompletion>,
}

impl PostJoinHistoryFetch {
    pub fn new(obligation_id: MessageId) -> Self {
        Self {
            obligation_id,
            deadline_at: None,
            completion: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostJoinHistoryFetchCompletion {
    pub outcome: PostJoinHistoryFetchOutcome,
    /// Milliseconds since the Unix epoch.
    pub completed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostJoinHistoryFetchOutcome {
    /// This device has fetched and processed the group messages its delivery
    /// endpoints hold from its join epoch on.
    Fetched,
    /// No relay reached end-of-stored-events before the deadline. Messages may
    /// be missing.
    DeadlineExpired,
}

/// Restart-safe semantic intent.  Wall-clock deadlines and sampled jitter are
/// persisted; in-process quiet-window measurement may additionally use a
/// monotonic clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceObligation {
    pub id: MessageId,
    pub group_id: GroupId,
    pub trigger: MaintenanceTrigger,
    pub phase: MaintenancePhase,
    pub created_at: Timestamp,
    pub operational_target_at: Option<Timestamp>,
    #[serde(default)]
    pub overdue: bool,
    pub eose_deadline_at: Option<Timestamp>,
    pub grace_until: Option<Timestamp>,
    pub quiet_since: Option<Timestamp>,
    /// Hash of the local LeafNode when the obligation was created or last
    /// re-armed. A confirmed intervening commit satisfies the obligation only
    /// when the canonical local leaf differs from this baseline.
    #[serde(default)]
    pub own_leaf_baseline_hash: Option<Vec<u8>>,
    pub sampled_jitter_ms: u64,
    pub not_before: Option<Timestamp>,
    pub attempt_count: u32,
    pub semantic_rearm_count: u32,
    pub last_failure_code: Option<String>,
}

/// Durable group-evolution state, independent from relay fanout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupEvolutionPhase {
    Preparing,
    Prepared,
    Attempting,
    Confirmed,
    SupersededByConvergence,
}

/// Semantic reason for a persisted group evolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum GroupEvolutionSemantic {
    SelfUpdate {
        trigger: MaintenanceTrigger,
        obligation_id: Option<MessageId>,
    },
    Invite,
    RemoveMembers,
    /// Exact source-bound grants replaced together by one remove-and-add commit.
    RecoverMembers {
        request_ids: Vec<[u8; 32]>,
        source_authenticator_hash: [u8; 32],
    },
    UpdateAppComponents,
    LegacyRecovery,
}

/// Restart-safe description of a staged MLS evolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableGroupEvolution {
    pub id: MessageId,
    pub group_id: GroupId,
    pub source_epoch: EpochId,
    pub target_epoch: EpochId,
    pub phase: GroupEvolutionPhase,
    pub semantic: GroupEvolutionSemantic,
    /// Hash of the local LeafNode before staging.  Comparing this to the
    /// selected branch proves whether an intervening commit rotated our leaf.
    pub own_leaf_before_hash: Option<Vec<u8>>,
    /// Descriptor-backed removals can be resumed without reconstructing the
    /// target set from projected membership.
    pub removal_members: Vec<Vec<u8>>,
    pub signed_message_id: Option<MessageId>,
    #[serde(default)]
    pub pending_ref: Option<PendingStateRef>,
}

/// Per-endpoint state for an immutable signed event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFanoutAttemptState {
    Unattempted,
    Accepted,
    AttemptedFailed,
    PolicyProhibited,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportFanoutTarget {
    pub endpoint: TransportEndpoint,
    pub state: TransportFanoutAttemptState,
    pub attempt_count: u32,
    pub last_attempt_at: Option<Timestamp>,
    pub failure_code: Option<String>,
}

/// Exact signed transport event plus its snapshotted delivery set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableTransportFanout {
    pub id: MessageId,
    pub group_id: Option<GroupId>,
    pub evolution_id: Option<MessageId>,
    pub exact_message: TransportMessage,
    pub target: TransportPublishTarget,
    pub targets: Vec<TransportFanoutTarget>,
    pub required_acks: usize,
    pub evolution_confirmed: bool,
    /// A transport error occurred after the exact event crossed the adapter
    /// boundary, so exposure cannot be disproved after restart.
    #[serde(default)]
    pub possible_exposure: bool,
    pub created_at: Timestamp,
    pub bounded_until: Option<Timestamp>,
}

/// Transport-neutral exact signed artifact used for account-scoped
/// replaceable events such as a KeyPackage publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPublicationArtifact {
    pub id: MessageId,
    pub created_at: Timestamp,
    pub bytes: Vec<u8>,
}

/// Durable generator policy revision, independent of app/workspace versions.
/// Revision 1 omits RFC 9420 section 7.2 default capability advertisements.
/// Bump only when existing published packages must be regenerated.
pub const KEY_PACKAGE_GENERATION_REVISION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingKeyPackageReplacement {
    /// Generator policy that produced this exact bundle. Missing on pre-migration records.
    #[serde(default)]
    pub generation_revision: u32,
    pub key_package: KeyPackage,
    pub key_package_ref: Vec<u8>,
    /// Transport authoring time selected before signing. The private bundle
    /// and this enclosing lifecycle intent are persisted atomically; signing
    /// may therefore resume safely after a crash.
    pub authored_created_at: Timestamp,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
    pub refresh_at: Timestamp,
    pub signed_event: Option<SignedPublicationArtifact>,
    pub targets: Vec<TransportFanoutTarget>,
    pub attempt_count: u32,
    pub last_failure_code: Option<String>,
    /// When a successfully processed Welcome consumed this package before its
    /// publication was acknowledged. It may already have reached a relay.
    #[serde(default)]
    pub consumed_at: Option<Timestamp>,
}

/// The replacement grace period: how long a superseded KeyPackage's private
/// material outlives confirmed publication of its replacement, consumed or
/// not. An inviter that fetched the old publication just before the
/// replacement reached it can still be joined (mdk#2344,
/// `foundation/key-packages.md`, "Refreshing a slot").
pub const KEY_PACKAGE_REPLACEMENT_GRACE_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "StoredRetainedKeyPackagePrivateMaterial")]
pub struct RetainedKeyPackagePrivateMaterial {
    pub key_package: KeyPackage,
    pub key_package_ref: Vec<u8>,
    pub not_after: Timestamp,
    /// When the package was replaced, which starts the grace period: when
    /// publication of the replacement was confirmed, or for a pending
    /// replacement superseded before that, when the next one was staged.
    /// While [`Self::awaiting_confirmed_replacement`] holds, confirmation
    /// moves it.
    pub replaced_at: Timestamp,
    /// A successfully processed Welcome consumed this package, so it is
    /// deleted [`KEY_PACKAGE_REPLACEMENT_GRACE_SECS`] after `replaced_at`
    /// without waiting for a confirmed replacement (mdk#2352).
    #[serde(default)]
    pub consumed: bool,
    /// The id of the signed publication that carried this package. Missing on
    /// packages retained before ids were recorded here, and on a replacement
    /// superseded before it was signed.
    #[serde(default)]
    pub authored_event_id: Option<MessageId>,
    /// A pending replacement superseded this unconsumed package before any
    /// replacement was confirmed, so the grace period has not started.
    /// Promotion of the next confirmed replacement starts it, and a Welcome
    /// consuming the package ends the wait.
    ///
    /// Records written before this flag keep the bound they had then: an
    /// unconsumed package decodes as awaiting, so `not_after` bounds it until
    /// a replacement is confirmed, and a consumed one already counts its grace
    /// period from `replaced_at`.
    pub awaiting_confirmed_replacement: bool,
}

/// The stored form of [`RetainedKeyPackagePrivateMaterial`], which tells a
/// record written before `awaiting_confirmed_replacement` from one that says
/// `false`.
#[derive(Deserialize)]
struct StoredRetainedKeyPackagePrivateMaterial {
    key_package: KeyPackage,
    key_package_ref: Vec<u8>,
    not_after: Timestamp,
    replaced_at: Timestamp,
    #[serde(default)]
    consumed: bool,
    #[serde(default)]
    authored_event_id: Option<MessageId>,
    #[serde(default)]
    awaiting_confirmed_replacement: Option<bool>,
}

impl From<StoredRetainedKeyPackagePrivateMaterial> for RetainedKeyPackagePrivateMaterial {
    fn from(stored: StoredRetainedKeyPackagePrivateMaterial) -> Self {
        Self {
            key_package: stored.key_package,
            key_package_ref: stored.key_package_ref,
            not_after: stored.not_after,
            replaced_at: stored.replaced_at,
            consumed: stored.consumed,
            authored_event_id: stored.authored_event_id,
            awaiting_confirmed_replacement: stored
                .awaiting_confirmed_replacement
                .unwrap_or(!stored.consumed),
        }
    }
}

impl RetainedKeyPackagePrivateMaterial {
    /// When the private material must be deleted: at the end of the grace
    /// period, [`KEY_PACKAGE_REPLACEMENT_GRACE_SECS`] after `replaced_at`, or
    /// at `not_after` if that is earlier. Until a replacement is confirmed,
    /// only `not_after` bounds an unconsumed package.
    pub fn delete_at(&self) -> Timestamp {
        if self.awaiting_confirmed_replacement && !self.consumed {
            return self.not_after;
        }
        Timestamp(
            self.not_after.0.min(
                self.replaced_at
                    .0
                    .saturating_add(KEY_PACKAGE_REPLACEMENT_GRACE_SECS),
            ),
        )
    }
}

/// The one stable replaceable-event slot for an account-device's last-resort
/// KeyPackage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageLifecycleState {
    pub stable_slot_id: String,
    #[serde(default)]
    pub phase: MaintenancePhase,
    pub current_key_package: Option<KeyPackage>,
    pub current_key_package_ref: Option<Vec<u8>>,
    pub current_not_before: Option<Timestamp>,
    pub current_not_after: Option<Timestamp>,
    pub authored_event_id: Option<MessageId>,
    pub authored_event_created_at: Option<Timestamp>,
    /// Exact current replaceable event retained until its snapshotted fanout
    /// finishes. Local lifecycle promotion still occurs on the first accepted
    /// acknowledgement.
    #[serde(default)]
    pub authored_signed_event: Option<SignedPublicationArtifact>,
    #[serde(default)]
    pub publication_targets: Vec<TransportFanoutTarget>,
    pub refresh_at: Option<Timestamp>,
    pub upgrade_rotation_recorded: bool,
    /// Generator policy of the acknowledged current package, promoted atomically
    /// with that package. Zero denotes records written before revision tracking.
    #[serde(default)]
    pub generation_revision: u32,
    /// The reference proven to have been consumed by a successfully processed
    /// MLS Welcome. This comes from the Welcome's encrypted-group-secrets
    /// entries matched against local bundles, never from a transport tag.
    ///
    /// It names only the current package, whose consumption makes a
    /// replacement due. A pending or retained package records its own
    /// consumption, so a delayed Welcome for one cannot overwrite this marker;
    /// see [`Self::record_consumed_key_package`].
    #[serde(default)]
    pub last_consumed_key_package_ref: Option<Vec<u8>>,
    #[serde(default)]
    pub last_consumed_at: Option<Timestamp>,
    /// Prior packages remain decryptable after their replacement so an invite
    /// already in flight can still be processed, for
    /// [`KEY_PACKAGE_REPLACEMENT_GRACE_SECS`] after the replacement is
    /// confirmed. See [`RetainedKeyPackagePrivateMaterial::delete_at`].
    #[serde(default)]
    pub retained_private_material: Vec<RetainedKeyPackagePrivateMaterial>,
    pub pending_replacement: Option<PendingKeyPackageReplacement>,
    /// The build that last replaced a KeyPackage because the publisher
    /// refused its signed bytes as unusable (mdk#2628, D8). Each build does so
    /// at most once, so a publisher that refuses what this build signs cannot
    /// make it generate a KeyPackage per attempt, while a later build can
    /// still replace one an earlier build signed.
    #[serde(default)]
    pub unusable_artifact_replaced_by: Option<String>,
    /// When this device asked its relays to delete its slot at sign-out
    /// (`foundation/key-packages.md`, "Stopping publication"). Relays drop
    /// every publication in the slot up to this time, so the next one must be
    /// newer and is due as soon as the device runs again. Confirmed
    /// publication of that newer one clears it.
    #[serde(default)]
    pub slot_withdrawn_at: Option<Timestamp>,
}

impl KeyPackageLifecycleState {
    /// Create lifecycle authority before a current package has been promoted.
    /// An empty slot is a fail-closed migration sentinel and must never be
    /// published.
    pub fn slot_only(stable_slot_id: String) -> Self {
        Self {
            stable_slot_id,
            phase: MaintenancePhase::Complete,
            current_key_package: None,
            current_key_package_ref: None,
            current_not_before: None,
            current_not_after: None,
            authored_event_id: None,
            authored_event_created_at: None,
            authored_signed_event: None,
            publication_targets: Vec::new(),
            refresh_at: None,
            upgrade_rotation_recorded: false,
            generation_revision: 0,
            last_consumed_key_package_ref: None,
            last_consumed_at: None,
            retained_private_material: Vec::new(),
            pending_replacement: None,
            unusable_artifact_replaced_by: None,
            slot_withdrawn_at: None,
        }
    }

    /// Every publication whose private material this device still holds, as
    /// `(event id, KeyPackageRef)`: the current package, a signed pending
    /// replacement, and each retained package whose id was recorded. A Welcome
    /// delivery is addressed to this device only when it names one of these
    /// ids (`protocol-core/joining.md`, "Receiving flow" step 2).
    pub fn held_publications(&self) -> impl Iterator<Item = (&MessageId, &[u8])> {
        let current = self
            .authored_event_id
            .as_ref()
            .zip(self.current_key_package_ref.as_deref());
        let pending = self.pending_replacement.as_ref().and_then(|pending| {
            pending
                .signed_event
                .as_ref()
                .map(|event| (&event.id, pending.key_package_ref.as_slice()))
        });
        let retained = self
            .retained_private_material
            .iter()
            .filter_map(|material| {
                material
                    .authored_event_id
                    .as_ref()
                    .map(|id| (id, material.key_package_ref.as_slice()))
            });
        current.into_iter().chain(pending).chain(retained)
    }

    /// Record that a successfully processed Welcome consumed `key_package_ref`.
    pub fn record_consumed_key_package(&mut self, key_package_ref: &[u8], consumed_at: Timestamp) {
        // An older record may keep a replaced or pending package's consumption
        // only in the marker this can overwrite.
        self.migrate_legacy_consumption_marker();
        if !self.mark_replaced_or_pending_consumed(key_package_ref, consumed_at)
            && self.current_key_package_ref.as_deref() == Some(key_package_ref)
        {
            self.last_consumed_key_package_ref = Some(key_package_ref.to_vec());
            self.last_consumed_at = Some(consumed_at);
        }
    }

    /// Move a consumption marker written before pending and retained packages
    /// recorded their own onto the package it names. Returns whether the
    /// lifecycle changed.
    pub fn migrate_legacy_consumption_marker(&mut self) -> bool {
        let Some(consumed) = self.last_consumed_key_package_ref.clone() else {
            return false;
        };
        let consumed_at = self.last_consumed_at.unwrap_or(Timestamp(0));
        if !self.mark_replaced_or_pending_consumed(&consumed, consumed_at) {
            return false;
        }
        self.last_consumed_key_package_ref = None;
        self.last_consumed_at = None;
        true
    }

    fn mark_replaced_or_pending_consumed(
        &mut self,
        key_package_ref: &[u8],
        consumed_at: Timestamp,
    ) -> bool {
        if let Some(material) = self
            .retained_private_material
            .iter_mut()
            .find(|material| material.key_package_ref == key_package_ref)
        {
            material.consumed = true;
            material.awaiting_confirmed_replacement = false;
            return true;
        }
        if let Some(pending) = self
            .pending_replacement
            .as_mut()
            .filter(|pending| pending.key_package_ref == key_package_ref)
        {
            pending.consumed_at.get_or_insert(consumed_at);
            return true;
        }
        false
    }
}

/// Runtime-level policy is persisted; pause/resume remains intentionally
/// process-local.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeriodicMaintenancePolicy {
    #[default]
    EnabledForNewGroups,
    Disabled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendMaintenanceDisposition {
    #[default]
    Ready,
    PostJoinRotationPendingRetryable,
}

/// Result of actively advancing maintenance work.
///
/// This is deliberately separate from `SendMaintenanceDisposition`: a user
/// send reports whether background maintenance remains pending, while a
/// maintenance run reports what maintenance itself published or deferred.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceRunSummary {
    pub published: u32,
    pub message_ids: Vec<MessageId>,
    pub deferred: u32,
    pub ambiguous_exposure: u32,
    pub failures: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMaintenanceStatus {
    pub group_id: GroupId,
    pub state: Option<GroupMaintenanceState>,
    pub obligations: Vec<MaintenanceObligation>,
    pub evolutions: Vec<DurableGroupEvolution>,
    pub fanouts: Vec<DurableTransportFanout>,
    pub paused: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        KEY_PACKAGE_REPLACEMENT_GRACE_SECS, KeyPackageLifecycleState, MaintenancePhase,
        PendingKeyPackageReplacement, RetainedKeyPackagePrivateMaterial,
    };
    use crate::engine::KeyPackage;
    use crate::transport::Timestamp;
    use crate::types::MessageId;

    fn retained(not_after: u64, consumed: bool) -> RetainedKeyPackagePrivateMaterial {
        RetainedKeyPackagePrivateMaterial {
            key_package: KeyPackage::new(vec![1]),
            key_package_ref: vec![2],
            not_after: Timestamp(not_after),
            replaced_at: Timestamp(1_000),
            consumed,
            authored_event_id: None,
            awaiting_confirmed_replacement: false,
        }
    }

    #[test]
    fn retained_key_package_is_deleted_when_the_grace_period_or_lifetime_ends() {
        let grace_end = 1_000 + KEY_PACKAGE_REPLACEMENT_GRACE_SECS;
        for consumed in [false, true] {
            assert_eq!(
                retained(grace_end + 10, consumed).delete_at(),
                Timestamp(grace_end),
                "consumed: {consumed}"
            );
            assert_eq!(
                retained(grace_end - 10, consumed).delete_at(),
                Timestamp(grace_end - 10),
                "the KeyPackage lifetime still bounds it; consumed: {consumed}"
            );
        }
        // Until a replacement is confirmed the grace period has not started.
        let mut awaiting = retained(grace_end + 10, false);
        awaiting.awaiting_confirmed_replacement = true;
        assert_eq!(awaiting.delete_at(), Timestamp(grace_end + 10));
    }

    #[test]
    fn a_consumed_key_package_does_not_wait_for_a_confirmed_replacement() {
        let grace_end = 1_000 + KEY_PACKAGE_REPLACEMENT_GRACE_SECS;
        let mut lifecycle = KeyPackageLifecycleState::slot_only("slot".into());
        let mut awaiting = retained(grace_end + 10, false);
        awaiting.awaiting_confirmed_replacement = true;
        lifecycle.retained_private_material = vec![awaiting];
        assert_eq!(
            lifecycle.retained_private_material[0].delete_at(),
            Timestamp(grace_end + 10)
        );
        // A Welcome consuming it keeps the grace period from `replaced_at`.
        lifecycle.record_consumed_key_package(&[2], Timestamp(2_000));
        let consumed = &lifecycle.retained_private_material[0];
        assert!(consumed.consumed && !consumed.awaiting_confirmed_replacement);
        assert_eq!(consumed.delete_at(), Timestamp(grace_end));
    }

    fn pending(key_package_ref: Vec<u8>) -> PendingKeyPackageReplacement {
        PendingKeyPackageReplacement {
            generation_revision: 1,
            key_package: KeyPackage::new(vec![3]),
            key_package_ref,
            authored_created_at: Timestamp(1),
            not_before: Timestamp(1),
            not_after: Timestamp(5_000),
            refresh_at: Timestamp(4_000),
            signed_event: None,
            targets: Vec::new(),
            attempt_count: 0,
            last_failure_code: None,
            consumed_at: None,
        }
    }

    /// Current `[1]`, retained `[2]` (unconsumed), pending `[3]`.
    fn lifecycle() -> KeyPackageLifecycleState {
        let mut lifecycle = KeyPackageLifecycleState::slot_only("slot".into());
        lifecycle.current_key_package_ref = Some(vec![1]);
        lifecycle.retained_private_material = vec![retained(5_000, false)];
        lifecycle.pending_replacement = Some(pending(vec![3]));
        lifecycle
    }

    #[test]
    fn delayed_welcome_for_a_replaced_package_keeps_the_current_marker() {
        let mut lifecycle = lifecycle();
        lifecycle.record_consumed_key_package(&[1], Timestamp(10));
        lifecycle.record_consumed_key_package(&[2], Timestamp(11));
        lifecycle.record_consumed_key_package(&[3], Timestamp(12));

        assert_eq!(lifecycle.last_consumed_key_package_ref, Some(vec![1]));
        assert_eq!(lifecycle.last_consumed_at, Some(Timestamp(10)));
        assert!(lifecycle.retained_private_material[0].consumed);
        assert_eq!(
            lifecycle.pending_replacement.unwrap().consumed_at,
            Some(Timestamp(12))
        );
    }

    #[test]
    fn current_consumption_migrates_a_legacy_marker_before_replacing_it() {
        let mut replaced = lifecycle();
        replaced.last_consumed_key_package_ref = Some(vec![2]);
        replaced.last_consumed_at = Some(Timestamp(10));
        replaced.record_consumed_key_package(&[1], Timestamp(20));
        assert!(replaced.retained_private_material[0].consumed);
        assert_eq!(replaced.last_consumed_key_package_ref, Some(vec![1]));
        assert_eq!(replaced.last_consumed_at, Some(Timestamp(20)));

        let mut pending = lifecycle();
        pending.last_consumed_key_package_ref = Some(vec![3]);
        pending.last_consumed_at = Some(Timestamp(10));
        pending.record_consumed_key_package(&[1], Timestamp(20));
        assert_eq!(
            pending.pending_replacement.as_ref().unwrap().consumed_at,
            Some(Timestamp(10))
        );
        assert_eq!(pending.last_consumed_key_package_ref, Some(vec![1]));
    }

    #[test]
    fn untracked_consumption_leaves_the_current_marker() {
        let mut lifecycle = lifecycle();
        lifecycle.record_consumed_key_package(&[1], Timestamp(10));
        lifecycle.record_consumed_key_package(&[9], Timestamp(11));
        assert_eq!(lifecycle.last_consumed_key_package_ref, Some(vec![1]));
        assert_eq!(lifecycle.last_consumed_at, Some(Timestamp(10)));
    }

    #[test]
    fn legacy_consumption_marker_moves_onto_the_package_it_names() {
        let mut current = lifecycle();
        current.last_consumed_key_package_ref = Some(vec![1]);
        assert!(!current.migrate_legacy_consumption_marker());
        assert_eq!(current.last_consumed_key_package_ref, Some(vec![1]));

        let mut replaced = lifecycle();
        replaced.last_consumed_key_package_ref = Some(vec![2]);
        replaced.last_consumed_at = Some(Timestamp(10));
        assert!(replaced.migrate_legacy_consumption_marker());
        assert!(replaced.retained_private_material[0].consumed);
        assert!(replaced.last_consumed_key_package_ref.is_none());
        assert!(replaced.last_consumed_at.is_none());

        let mut pending = lifecycle();
        pending.last_consumed_key_package_ref = Some(vec![3]);
        pending.last_consumed_at = Some(Timestamp(10));
        assert!(pending.migrate_legacy_consumption_marker());
        assert_eq!(
            pending.pending_replacement.unwrap().consumed_at,
            Some(Timestamp(10))
        );
    }

    #[test]
    fn retained_key_package_records_without_consumption_decode_as_unconsumed() {
        let mut value = serde_json::to_value(retained(5_000, true)).unwrap();
        value.as_object_mut().unwrap().remove("consumed");
        let decoded: RetainedKeyPackagePrivateMaterial = serde_json::from_value(value).unwrap();
        assert!(!decoded.consumed);
    }

    #[test]
    fn retained_key_package_records_written_before_the_confirmation_flag_keep_their_bound() {
        let legacy = |consumed| {
            let mut value = serde_json::to_value(retained(1_000_000, consumed)).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .remove("awaiting_confirmed_replacement");
            serde_json::from_value::<RetainedKeyPackagePrivateMaterial>(value).unwrap()
        };
        // An unconsumed package was kept until it expired, and its replacement
        // may not be confirmed yet.
        let unconsumed = legacy(false);
        assert!(unconsumed.awaiting_confirmed_replacement);
        assert_eq!(unconsumed.delete_at(), Timestamp(1_000_000));
        // A consumed one was already deleted a day after `replaced_at`.
        let consumed = legacy(true);
        assert!(!consumed.awaiting_confirmed_replacement);
        assert_eq!(
            consumed.delete_at(),
            Timestamp(1_000 + KEY_PACKAGE_REPLACEMENT_GRACE_SECS)
        );
        // A record that says `false` is not legacy.
        let written = retained(1_000_000, false);
        let decoded: RetainedKeyPackagePrivateMaterial =
            serde_json::from_value(serde_json::to_value(&written).unwrap()).unwrap();
        assert_eq!(decoded, written);
    }

    #[test]
    fn held_publications_name_every_package_with_private_material_and_a_recorded_id() {
        let id = |byte| MessageId::new(vec![byte; 32]);
        let mut lifecycle = lifecycle();
        lifecycle.authored_event_id = Some(id(0x11));
        lifecycle.retained_private_material[0].authored_event_id = Some(id(0x22));
        let mut legacy = retained(5_000, false);
        legacy.key_package_ref = vec![4];
        lifecycle.retained_private_material.push(legacy);
        // An unsigned replacement has no publication yet.
        assert_eq!(
            lifecycle.held_publications().collect::<Vec<_>>(),
            vec![(&id(0x11), [1].as_slice()), (&id(0x22), [2].as_slice())]
        );

        lifecycle.pending_replacement.as_mut().unwrap().signed_event =
            Some(super::SignedPublicationArtifact {
                id: id(0x33),
                created_at: Timestamp(1),
                bytes: Vec::new(),
            });
        // The current package's private material is gone once it expires,
        // even though the record still names its publication.
        lifecycle.current_key_package_ref = None;
        assert_eq!(
            lifecycle.held_publications().collect::<Vec<_>>(),
            vec![(&id(0x33), [3].as_slice()), (&id(0x22), [2].as_slice())]
        );
    }

    #[test]
    fn retained_key_package_records_without_a_publication_id_decode_without_one() {
        let mut material = retained(5_000, false);
        material.authored_event_id = Some(MessageId::new(vec![0x22; 32]));
        let mut value = serde_json::to_value(material).unwrap();
        value.as_object_mut().unwrap().remove("authored_event_id");
        let decoded: RetainedKeyPackagePrivateMaterial = serde_json::from_value(value).unwrap();
        assert!(decoded.authored_event_id.is_none());
    }

    #[test]
    fn maintenance_phase_names_are_stable_snake_case() {
        assert_eq!(
            MaintenancePhase::PendingPublication.as_str(),
            "pending_publication"
        );
        assert_eq!(
            MaintenancePhase::SupersededByConvergence.as_str(),
            "superseded_by_convergence"
        );
        assert_eq!(
            MaintenancePhase::ClockSkewBlocked.as_str(),
            "clock_skew_blocked"
        );
    }
}
