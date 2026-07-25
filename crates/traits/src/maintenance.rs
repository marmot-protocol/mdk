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
    /// Snapshot used for convergence reconciliation before any retry.
    pub recovery_snapshot: Option<String>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingKeyPackageReplacement {
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedKeyPackagePrivateMaterial {
    pub key_package: KeyPackage,
    pub key_package_ref: Vec<u8>,
    pub not_after: Timestamp,
    pub replaced_at: Timestamp,
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
    /// The reference proven to have been consumed by a successfully processed
    /// MLS Welcome. This comes from the Welcome's encrypted-group-secrets
    /// entries matched against local bundles, never from a transport tag.
    #[serde(default)]
    pub last_consumed_key_package_ref: Option<Vec<u8>>,
    #[serde(default)]
    pub last_consumed_at: Option<Timestamp>,
    /// Prior, unconsumed packages remain decryptable until their MLS lifetime
    /// expires so an invite already in flight can still be processed.
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
            last_consumed_key_package_ref: None,
            last_consumed_at: None,
            retained_private_material: Vec::new(),
            pending_replacement: None,
        }
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
    use super::MaintenancePhase;

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
