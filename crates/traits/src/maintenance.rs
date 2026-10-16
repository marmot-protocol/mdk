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

/// How long a consumed KeyPackage's private material outlives confirmed
/// publication of its replacement. An inviter that fetched the old publication
/// before the replacement reached it can still be joined (mdk#2344).
pub const CONSUMED_KEY_PACKAGE_RETENTION_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedKeyPackagePrivateMaterial {
    pub key_package: KeyPackage,
    pub key_package_ref: Vec<u8>,
    pub not_after: Timestamp,
    pub replaced_at: Timestamp,
    /// A successfully processed Welcome consumed this package, so its private
    /// material is deleted [`CONSUMED_KEY_PACKAGE_RETENTION_SECS`] after
    /// `replaced_at`, or at `not_after` if that is earlier.
    #[serde(default)]
    pub consumed: bool,
}

impl RetainedKeyPackagePrivateMaterial {
    /// When the private material must be deleted.
    pub fn delete_at(&self) -> Timestamp {
        if self.consumed {
            Timestamp(
                self.not_after.0.min(
                    self.replaced_at
                        .0
                        .saturating_add(CONSUMED_KEY_PACKAGE_RETENTION_SECS),
                ),
            )
        } else {
            self.not_after
        }
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
    /// already in flight can still be processed: unconsumed ones until their
    /// MLS lifetime expires, consumed ones for
    /// [`CONSUMED_KEY_PACKAGE_RETENTION_SECS`]. See
    /// [`RetainedKeyPackagePrivateMaterial::delete_at`].
    #[serde(default)]
    pub retained_private_material: Vec<RetainedKeyPackagePrivateMaterial>,
    pub pending_replacement: Option<PendingKeyPackageReplacement>,
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
        }
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
        CONSUMED_KEY_PACKAGE_RETENTION_SECS, KeyPackageLifecycleState, MaintenancePhase,
        PendingKeyPackageReplacement, RetainedKeyPackagePrivateMaterial,
    };
    use crate::engine::KeyPackage;
    use crate::transport::Timestamp;

    fn retained(not_after: u64, consumed: bool) -> RetainedKeyPackagePrivateMaterial {
        RetainedKeyPackagePrivateMaterial {
            key_package: KeyPackage::new(vec![1]),
            key_package_ref: vec![2],
            not_after: Timestamp(not_after),
            replaced_at: Timestamp(1_000),
            consumed,
        }
    }

    #[test]
    fn retained_key_package_deletion_bound_depends_on_consumption() {
        let retention_end = 1_000 + CONSUMED_KEY_PACKAGE_RETENTION_SECS;
        assert_eq!(
            retained(retention_end + 10, false).delete_at(),
            Timestamp(retention_end + 10)
        );
        assert_eq!(
            retained(retention_end + 10, true).delete_at(),
            Timestamp(retention_end)
        );
        assert_eq!(
            retained(retention_end - 10, true).delete_at(),
            Timestamp(retention_end - 10),
            "the KeyPackage lifetime still bounds consumed material"
        );
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
