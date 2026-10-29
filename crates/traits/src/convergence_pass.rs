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

/// The step at which an attempt to resolve a frozen pass failed (mdk#2684).
///
/// Aggregate only: it names where the attempt stopped, never what it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergencePassStep {
    /// Searching the frozen batch's candidate branches.
    Select,
    /// Recording the halt for missing retained state.
    Halt,
    /// Completing a pass that selection reported blocked.
    CompleteBlocked,
    /// Reading what the apply needs before it starts.
    PrepareApply,
    /// The atomic apply of the selected result.
    Apply,
}

impl ConvergencePassStep {
    /// Stable low-cardinality label for tracing and audit records.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Halt => "halt",
            Self::CompleteBlocked => "complete_blocked",
            Self::PrepareApply => "prepare_apply",
            Self::Apply => "apply",
        }
    }
}

/// Consecutive failed attempts to resolve one frozen batch (mdk#2684).
///
/// A failed attempt leaves its pass unresolved, so without this record every
/// later advance replays the batch from scratch. The pass backs off between
/// attempts and parks once its failure budget is spent; it stays parked across
/// restarts until new selection input reopens it or the host asks for a retry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergencePassRetry {
    pub failed_attempts: u32,
    pub failed_step: ConvergencePassStep,
    /// The next attempt may start at this process-local instant.
    pub next_attempt_monotonic_ms: u64,
    /// The same instant on the wall clock, which rebases it after a restart.
    pub next_attempt_wall_ms: u64,
    /// When the failure budget ran out. A parked pass makes no attempt on its
    /// own.
    pub parked_at_wall_ms: Option<u64>,
    /// The newest storage insertion position of a commit or proposal already
    /// judged against this batch, so a check for new selection input reads
    /// only rows after it. `None` until the first check, which reads them all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_read_through: Option<u64>,
}

impl ConvergencePassRetry {
    pub const fn is_parked(&self) -> bool {
        self.parked_at_wall_ms.is_some()
    }
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
    /// Failed attempts of this frozen batch; `None` until one fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<ConvergencePassRetry>,
}

impl DurableConvergencePass {
    pub const fn is_active(&self) -> bool {
        self.phase.is_active()
    }

    /// An active pass whose failure budget ran out.
    pub fn is_parked(&self) -> bool {
        self.is_active()
            && self
                .retry
                .as_ref()
                .is_some_and(ConvergencePassRetry::is_parked)
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
