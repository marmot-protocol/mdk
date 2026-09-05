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

/// Maximum durable exact `(signed event id, relay endpoint)` liabilities held
/// by one account-device KeyPackage lifecycle.
pub const MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES: usize = 256;
/// Additional exact endpoint liabilities reserved exclusively for atomically
/// deleting one explicitly selected KeyPackage revision. An event id that is
/// not projected as current/pending is still treated as potentially live for
/// this purpose because the deletion API carries no stable-slot proof. The
/// app's relay safety boundary caps one publication route at sixteen
/// endpoints. Keeping the reserve separate means a full ordinary journal
/// cannot force partial same-slot deletion, while discovery and new
/// publication remain bound by
/// [`MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES`].
pub const MAX_KEY_PACKAGE_LIVE_DELETION_OVERFLOW_LIABILITIES: usize = 16;
/// Absolute lifecycle bound while a live-revision deletion is in flight.
pub const MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES_WITH_LIVE_DELETION_OVERFLOW: usize =
    MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
        + MAX_KEY_PACKAGE_LIVE_DELETION_OVERFLOW_LIABILITIES;
/// Maximum distinct consumed KeyPackage references awaiting account cleanup.
/// The journal never evicts live evidence; a transaction that would exceed
/// this cap fails closed before committing the Welcome.
pub const MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP: usize = 256;

/// The durable consumed-KeyPackage cleanup journal has no free slot.
///
/// Welcome processing must fail closed instead of evicting an older, still
/// unswept consumption record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("consumed KeyPackage cleanup journal is full")]
pub struct ConsumedKeyPackageRefJournalFull;
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

/// One exact signed revision of an account-scoped replaceable event such as a
/// KeyPackage publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPublicationArtifact {
    pub id: MessageId,
    pub created_at: Timestamp,
    pub bytes: Vec<u8>,
}

/// A superseded signed KeyPackage revision that still has relay-side deletion
/// work outstanding.
///
/// Reauthoring keeps the same replaceable-event coordinate, but a relay that
/// accepted (or may ambiguously have accepted) the older event can retain that
/// exact event id. Each endpoint remains listed until it explicitly
/// acknowledges a deletion for `event_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredKeyPackagePublication {
    pub event_id: MessageId,
    pub authored_created_at: Timestamp,
    /// Reference of the semantic MLS KeyPackage carried by this signed
    /// revision. This lets consumption make every older transport revision of
    /// the same single-use package immediately eligible for deletion.
    #[serde(default)]
    pub key_package_ref: Option<Vec<u8>>,
    /// MLS lifetime boundary for the semantic KeyPackage carried by this
    /// revision. Once reached, the old event may be deleted even when no newer
    /// revision reached that endpoint.
    #[serde(default)]
    pub package_not_after: Option<Timestamp>,
    /// The underlying single-use KeyPackage is no longer usable locally (for
    /// example because a Welcome consumed it), so successor acknowledgement is
    /// not required before deleting this revision.
    #[serde(default)]
    pub delete_without_successor: bool,
    #[serde(default)]
    pub deletion_targets: Vec<TransportFanoutTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingKeyPackageReplacement {
    pub key_package: KeyPackage,
    pub key_package_ref: Vec<u8>,
    /// Transport authoring time of the current pending signed revision. The
    /// private bundle and this enclosing lifecycle intent are persisted
    /// atomically; signing may therefore resume safely after a crash. A
    /// bounded-age transport updates this field and `signed_event` together
    /// before exposing a newer revision.
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
    /// Durable fail-closed gate for upgrade cutover discovery. While set, the
    /// account may prepare local KeyPackage material and retry exact deletion
    /// obligations, but it must not publish, republish, or fan out a kind
    /// 30443 revision. The app clears this only after every authoritative
    /// relay completed its scan and every discovered exact endpoint liability
    /// was admitted durably.
    #[serde(default)]
    pub cutover_publication_blocked: bool,
    pub current_key_package: Option<KeyPackage>,
    pub current_key_package_ref: Option<Vec<u8>>,
    pub current_not_before: Option<Timestamp>,
    pub current_not_after: Option<Timestamp>,
    pub authored_event_id: Option<MessageId>,
    /// Highest transport authoring time durably selected for this stable
    /// replaceable-event slot. This normally describes the current artifact,
    /// but remains above it when a newer pending artifact was consumed before
    /// acknowledgement so the required fresh replacement sorts after both.
    pub authored_event_created_at: Option<Timestamp>,
    /// Current signed revision retained for restart-safe exact retries within
    /// that revision. A bounded-age transport may atomically replace it with a
    /// strictly newer revision at the same coordinate and reset every live
    /// target before fanout continues. Local lifecycle promotion still occurs
    /// on the first accepted acknowledgement.
    #[serde(default)]
    pub authored_signed_event: Option<SignedPublicationArtifact>,
    /// Current or pending signed revision ids selected for relay deletion.
    /// An artifact remains forbidden from exact republication while its id is
    /// present; the marker follows that exact revision rather than leaking
    /// onto a newly generated KeyPackage after expiry or promotion.
    #[serde(default)]
    pub deleted_live_revision_event_ids: Vec<MessageId>,
    /// Exact deletion currently entitled to use the bounded liabilities above
    /// [`MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES`]. The owner remains
    /// durable until every one of that event's deletion targets has a terminal
    /// receipt, preventing two atomic exact-deletion sets from sharing the
    /// overflow reserve across retries or process restarts.
    #[serde(default)]
    pub deletion_overflow_owner_event_id: Option<MessageId>,
    /// Superseded signed revisions whose possible relay copies still require
    /// explicit deletion acknowledgement. This is independent of MLS private
    /// material retention and therefore survives package expiry and restart.
    #[serde(default)]
    pub retired_publications_pending_deletion: Vec<RetiredKeyPackagePublication>,
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
    /// Durable, deduplicated references of locally owned KeyPackages proven
    /// consumed by successfully processed Welcomes. Only the account sweep
    /// may remove evidence after it has handled the matching private material;
    /// unmatched upgrade-era evidence is retained fail-closed.
    #[serde(default)]
    pub consumed_key_package_refs: Vec<Vec<u8>>,
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
            cutover_publication_blocked: false,
            current_key_package: None,
            current_key_package_ref: None,
            current_not_before: None,
            current_not_after: None,
            authored_event_id: None,
            authored_event_created_at: None,
            authored_signed_event: None,
            deleted_live_revision_event_ids: Vec::new(),
            deletion_overflow_owner_event_id: None,
            retired_publications_pending_deletion: Vec::new(),
            publication_targets: Vec::new(),
            refresh_at: None,
            upgrade_rotation_recorded: false,
            last_consumed_key_package_ref: None,
            last_consumed_at: None,
            consumed_key_package_refs: Vec::new(),
            retained_private_material: Vec::new(),
            pending_replacement: None,
        }
    }

    /// Record a locally matched Welcome consumption without overwriting an
    /// earlier still-live reference. The legacy `last_consumed_*` fields remain
    /// the latest-consumption status projection.
    pub fn record_consumed_key_package_ref(
        &mut self,
        key_package_ref: Vec<u8>,
        consumed_at: Timestamp,
    ) -> Result<(), ConsumedKeyPackageRefJournalFull> {
        if !self.consumed_key_package_refs.contains(&key_package_ref) {
            if self.consumed_key_package_refs.len() >= MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP
            {
                return Err(ConsumedKeyPackageRefJournalFull);
            }
            self.consumed_key_package_refs.push(key_package_ref.clone());
        }
        self.last_consumed_key_package_ref = Some(key_package_ref);
        self.last_consumed_at = Some(consumed_at);
        Ok(())
    }

    /// Import the legacy last-consumed marker and deduplicate without pruning.
    /// Only the account sweep that actually handles matching private/lifecycle
    /// material may clear consumption evidence; an upgrade row may not yet
    /// project its still-owned OpenMLS bundle into these lifecycle fields.
    pub fn reconcile_consumed_key_package_refs(&mut self) {
        if let Some(last) = self.last_consumed_key_package_ref.as_ref()
            && !self
                .consumed_key_package_refs
                .iter()
                .any(|candidate| candidate == last)
            && self.consumed_key_package_refs.len() < MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP
        {
            self.consumed_key_package_refs.push(last.clone());
        }
        let mut reconciled = Vec::with_capacity(self.consumed_key_package_refs.len());
        for consumed in self.consumed_key_package_refs.drain(..) {
            if !reconciled.iter().any(|candidate| candidate == &consumed) {
                reconciled.push(consumed);
            }
        }
        self.consumed_key_package_refs = reconciled;
    }

    /// Whether a still-live/private lifecycle reference has durable Welcome
    /// consumption evidence. The legacy field is accepted for upgrade safety.
    pub fn key_package_ref_is_consumed(&self, key_package_ref: &[u8]) -> bool {
        self.consumed_key_package_refs
            .iter()
            .any(|candidate| candidate.as_slice() == key_package_ref)
            || self.last_consumed_key_package_ref.as_deref() == Some(key_package_ref)
    }

    /// Clear one consumption marker only after the account sweep has handled
    /// the matching current/pending/retained private material.
    pub fn clear_consumed_key_package_ref(&mut self, key_package_ref: &[u8]) {
        self.consumed_key_package_refs
            .retain(|candidate| candidate.as_slice() != key_package_ref);
        if self.last_consumed_key_package_ref.as_deref() == Some(key_package_ref) {
            self.last_consumed_key_package_ref = self.consumed_key_package_refs.last().cloned();
            self.last_consumed_at = None;
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
    use super::{
        KeyPackageLifecycleState, MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP, MaintenancePhase,
    };
    use crate::Timestamp;

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

    #[test]
    fn consumed_key_package_ref_journal_is_serde_defaulted_deduplicated_and_reconciled() {
        let mut legacy_json =
            serde_json::to_value(KeyPackageLifecycleState::slot_only("stable-slot".into()))
                .unwrap();
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("consumed_key_package_refs");
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("cutover_publication_blocked");
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("deletion_overflow_owner_event_id");
        let legacy: KeyPackageLifecycleState = serde_json::from_value(legacy_json).unwrap();
        assert!(legacy.consumed_key_package_refs.is_empty());
        assert!(!legacy.cutover_publication_blocked);
        assert!(legacy.deletion_overflow_owner_event_id.is_none());

        let mut lifecycle = KeyPackageLifecycleState::slot_only("stable-slot".into());
        lifecycle.current_key_package_ref = Some(vec![1]);
        lifecycle
            .record_consumed_key_package_ref(vec![1], Timestamp(10))
            .unwrap();
        lifecycle
            .record_consumed_key_package_ref(vec![1], Timestamp(11))
            .unwrap();
        assert_eq!(lifecycle.consumed_key_package_refs, vec![vec![1]]);
        assert_eq!(lifecycle.last_consumed_at, Some(Timestamp(11)));

        lifecycle.current_key_package_ref = Some(vec![2]);
        lifecycle
            .record_consumed_key_package_ref(vec![2], Timestamp(12))
            .unwrap();
        assert_eq!(
            lifecycle.consumed_key_package_refs,
            vec![vec![1], vec![2]],
            "only the account sweep may clear older unswept evidence"
        );
        lifecycle.clear_consumed_key_package_ref(&[1]);
        assert_eq!(lifecycle.consumed_key_package_refs, vec![vec![2]]);
        lifecycle.current_key_package_ref = None;
        lifecycle.clear_consumed_key_package_ref(&[2]);
        assert!(lifecycle.consumed_key_package_refs.is_empty());
        assert!(lifecycle.last_consumed_key_package_ref.is_none());
        assert!(lifecycle.last_consumed_at.is_none());

        let mut bounded = KeyPackageLifecycleState::slot_only(String::new());
        for index in 0..MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP {
            bounded
                .record_consumed_key_package_ref(
                    u64::try_from(index).unwrap().to_be_bytes().to_vec(),
                    Timestamp(index as u64),
                )
                .unwrap();
        }
        assert!(
            bounded
                .record_consumed_key_package_ref(vec![0xff; 9], Timestamp(u64::MAX))
                .is_err(),
            "the journal fails closed rather than evicting unswept evidence"
        );
    }
}
