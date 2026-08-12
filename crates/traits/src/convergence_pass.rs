//! Durable state for one bounded convergence pass.
//!
//! A pass admits selection-relevant inputs while collecting, freezes an
//! immutable membership set at the earlier cutoff, and resolves only that set.
//! The record is account-device-local engine state, not a wire protocol type.

use crate::{EpochId, GroupId, MessageId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergencePassPhase {
    Collecting,
    Frozen,
    Resolving,
    Completed,
}

impl ConvergencePassPhase {
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::Completed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergenceCutoffCause {
    Quiescence,
    AbsoluteDeadline,
    ClockDiscontinuity,
}

/// Protocol role of one durable convergence-pass member.
///
/// This metadata is derived from the digest-pinned MLS payload at admission
/// and re-verified before frozen resolution. Keeping it in the pass record
/// lets scheduling and outbound gating avoid re-reading every member row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergencePassMemberRole {
    CommitEdge,
    ProposalDependency,
    AppWitnessCandidate,
}

/// One immutable member of a frozen convergence batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergencePassMember {
    pub message_id: MessageId,
    /// SHA-256 of the canonical peeled MLS payload admitted to this pass.
    pub payload_digest: [u8; 32],
    /// Scheduling/selection role derived from the pinned payload.
    pub role: ConvergencePassMemberRole,
    /// MLS source epoch derived from the pinned payload.
    pub source_epoch: u64,
}

/// Durable per-group convergence-pass state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableConvergencePass {
    pub group_id: GroupId,
    pub generation: u64,
    pub phase: ConvergencePassPhase,
    pub base_epoch: EpochId,
    /// Random process-local clock-domain identifier.
    pub clock_instance_id: u64,
    pub opened_monotonic_ms: u64,
    pub quiescence_deadline_monotonic_ms: u64,
    pub absolute_deadline_monotonic_ms: u64,
    pub opened_wall_ms: u64,
    pub quiescence_deadline_wall_ms: u64,
    pub absolute_deadline_wall_ms: u64,
    pub members: Vec<ConvergencePassMember>,
    pub frozen_at_wall_ms: Option<u64>,
    pub cutoff_cause: Option<ConvergenceCutoffCause>,
    /// A completed pass grants one queued user intent before an inbound-only
    /// follow-up pass. Persisting the slot prevents restart from erasing the
    /// fairness edge.
    #[serde(default)]
    pub fairness_slot_available: bool,
}

impl DurableConvergencePass {
    pub const fn is_active(&self) -> bool {
        self.phase.is_active()
    }

    pub fn cutoff_monotonic_ms(&self) -> u64 {
        self.quiescence_deadline_monotonic_ms
            .min(self.absolute_deadline_monotonic_ms)
    }

    pub fn cutoff_wall_ms(&self) -> u64 {
        self.quiescence_deadline_wall_ms
            .min(self.absolute_deadline_wall_ms)
    }
}
