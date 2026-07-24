//! FFI-safe maintenance status and control types.

use cgka_traits::{
    DurableGroupEvolution, DurableTransportFanout, GroupEvolutionPhase, GroupMaintenanceStatus,
    KeyPackageLifecycleState, MaintenanceObligation, MaintenancePhase, MaintenanceTrigger,
    PeriodicMaintenancePolicy, TransportFanoutAttemptState,
};
use marmot_app::MaintenanceRunSummary;

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MaintenanceRunSummaryFfi {
    pub published: u32,
    pub message_ids: Vec<String>,
    pub deferred: u32,
    pub ambiguous_exposure: u32,
    pub failures: u32,
}

impl From<MaintenanceRunSummary> for MaintenanceRunSummaryFfi {
    fn from(value: MaintenanceRunSummary) -> Self {
        Self {
            published: value.published,
            message_ids: value.message_ids,
            deferred: value.deferred,
            ambiguous_exposure: value.ambiguous_exposure,
            failures: value.failures,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MaintenancePhaseFfi {
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
    Complete,
    Failed,
}

impl From<MaintenancePhase> for MaintenancePhaseFfi {
    fn from(value: MaintenancePhase) -> Self {
        match value {
            MaintenancePhase::CatchUp => Self::CatchUp,
            MaintenancePhase::EoseTimeout => Self::EoseTimeout,
            MaintenancePhase::Grace => Self::Grace,
            MaintenancePhase::Quiet => Self::Quiet,
            MaintenancePhase::Jitter => Self::Jitter,
            MaintenancePhase::Overdue => Self::Overdue,
            MaintenancePhase::Paused => Self::Paused,
            MaintenancePhase::ClockSkewBlocked => Self::ClockSkewBlocked,
            MaintenancePhase::PendingPublication => Self::PendingPublication,
            MaintenancePhase::Fanout => Self::Fanout,
            MaintenancePhase::Retry => Self::Retry,
            MaintenancePhase::SupersededByConvergence => Self::SupersededByConvergence,
            MaintenancePhase::Complete => Self::Complete,
            MaintenancePhase::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MaintenanceTriggerFfi {
    PostJoin,
    Periodic,
    Manual,
}

impl From<MaintenanceTrigger> for MaintenanceTriggerFfi {
    fn from(value: MaintenanceTrigger) -> Self {
        match value {
            MaintenanceTrigger::PostJoin => Self::PostJoin,
            MaintenanceTrigger::Periodic => Self::Periodic,
            MaintenanceTrigger::Manual => Self::Manual,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PeriodicMaintenancePolicyFfi {
    EnabledForNewGroups,
    Disabled,
}

impl From<PeriodicMaintenancePolicyFfi> for PeriodicMaintenancePolicy {
    fn from(value: PeriodicMaintenancePolicyFfi) -> Self {
        match value {
            PeriodicMaintenancePolicyFfi::EnabledForNewGroups => Self::EnabledForNewGroups,
            PeriodicMaintenancePolicyFfi::Disabled => Self::Disabled,
        }
    }
}

impl From<PeriodicMaintenancePolicy> for PeriodicMaintenancePolicyFfi {
    fn from(value: PeriodicMaintenancePolicy) -> Self {
        match value {
            PeriodicMaintenancePolicy::EnabledForNewGroups => Self::EnabledForNewGroups,
            PeriodicMaintenancePolicy::Disabled => Self::Disabled,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MaintenanceObligationFfi {
    pub id_hex: String,
    pub trigger: MaintenanceTriggerFfi,
    pub phase: MaintenancePhaseFfi,
    pub created_at: u64,
    pub operational_target_at: Option<u64>,
    pub overdue: bool,
    pub eose_deadline_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub quiet_since: Option<u64>,
    pub sampled_jitter_ms: u64,
    pub not_before: Option<u64>,
    pub attempt_count: u32,
    pub semantic_rearm_count: u32,
    pub last_failure_code: Option<String>,
}

impl From<MaintenanceObligation> for MaintenanceObligationFfi {
    fn from(value: MaintenanceObligation) -> Self {
        Self {
            id_hex: hex::encode(value.id.as_slice()),
            trigger: value.trigger.into(),
            phase: value.phase.into(),
            created_at: value.created_at.0,
            operational_target_at: value.operational_target_at.map(|value| value.0),
            overdue: value.overdue,
            eose_deadline_at: value.eose_deadline_at.map(|value| value.0),
            grace_until: value.grace_until.map(|value| value.0),
            quiet_since: value.quiet_since.map(|value| value.0),
            sampled_jitter_ms: value.sampled_jitter_ms,
            not_before: value.not_before.map(|value| value.0),
            attempt_count: value.attempt_count,
            semantic_rearm_count: value.semantic_rearm_count,
            last_failure_code: value.last_failure_code,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GroupEvolutionStatusFfi {
    pub id_hex: String,
    pub phase: GroupEvolutionPhaseFfi,
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub signed_message_id_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum GroupEvolutionPhaseFfi {
    Preparing,
    Prepared,
    Attempting,
    Confirmed,
    SupersededByConvergence,
}

impl From<GroupEvolutionPhase> for GroupEvolutionPhaseFfi {
    fn from(value: GroupEvolutionPhase) -> Self {
        match value {
            GroupEvolutionPhase::Preparing => Self::Preparing,
            GroupEvolutionPhase::Prepared => Self::Prepared,
            GroupEvolutionPhase::Attempting => Self::Attempting,
            GroupEvolutionPhase::Confirmed => Self::Confirmed,
            GroupEvolutionPhase::SupersededByConvergence => Self::SupersededByConvergence,
        }
    }
}

impl From<DurableGroupEvolution> for GroupEvolutionStatusFfi {
    fn from(value: DurableGroupEvolution) -> Self {
        Self {
            id_hex: hex::encode(value.id.as_slice()),
            phase: value.phase.into(),
            source_epoch: value.source_epoch.0,
            target_epoch: value.target_epoch.0,
            signed_message_id_hex: value
                .signed_message_id
                .map(|message_id| hex::encode(message_id.as_slice())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TransportFanoutStatusFfi {
    pub id_hex: String,
    pub accepted: u32,
    pub unattempted: u32,
    pub attempted_failed: u32,
    pub policy_prohibited: u32,
    pub required_acks: u32,
    pub evolution_confirmed: bool,
    pub bounded_until: Option<u64>,
}

impl From<DurableTransportFanout> for TransportFanoutStatusFfi {
    fn from(value: DurableTransportFanout) -> Self {
        let count = |state| {
            value
                .targets
                .iter()
                .filter(|target| target.state == state)
                .count() as u32
        };
        Self {
            id_hex: hex::encode(value.id.as_slice()),
            accepted: count(TransportFanoutAttemptState::Accepted),
            unattempted: count(TransportFanoutAttemptState::Unattempted),
            attempted_failed: count(TransportFanoutAttemptState::AttemptedFailed),
            policy_prohibited: count(TransportFanoutAttemptState::PolicyProhibited),
            required_acks: value.required_acks as u32,
            evolution_confirmed: value.evolution_confirmed,
            bounded_until: value.bounded_until.map(|value| value.0),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GroupMaintenanceStatusFfi {
    pub group_id_hex: String,
    pub enrolled_at: Option<u64>,
    pub periodic_enrolled: bool,
    pub last_own_leaf_rotation_at: Option<u64>,
    pub next_periodic_rotation_at: Option<u64>,
    pub obligations: Vec<MaintenanceObligationFfi>,
    pub evolutions: Vec<GroupEvolutionStatusFfi>,
    pub fanouts: Vec<TransportFanoutStatusFfi>,
    pub paused: bool,
}

impl From<GroupMaintenanceStatus> for GroupMaintenanceStatusFfi {
    fn from(value: GroupMaintenanceStatus) -> Self {
        let state = value.state;
        Self {
            group_id_hex: hex::encode(value.group_id.as_slice()),
            enrolled_at: state
                .as_ref()
                .and_then(|state| state.enrolled_at)
                .map(|value| value.0),
            periodic_enrolled: state.as_ref().is_some_and(|state| state.periodic_enrolled),
            last_own_leaf_rotation_at: state
                .as_ref()
                .and_then(|state| state.last_own_leaf_rotation_at)
                .map(|value| value.0),
            next_periodic_rotation_at: state
                .as_ref()
                .and_then(|state| state.next_periodic_rotation_at)
                .map(|value| value.0),
            obligations: value.obligations.into_iter().map(Into::into).collect(),
            evolutions: value.evolutions.into_iter().map(Into::into).collect(),
            fanouts: value.fanouts.into_iter().map(Into::into).collect(),
            paused: value.paused,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct KeyPackageMaintenanceStatusFfi {
    pub stable_slot_id: String,
    pub phase: MaintenancePhaseFfi,
    pub current_key_package_ref_hex: Option<String>,
    pub current_not_before: Option<u64>,
    pub current_not_after: Option<u64>,
    pub authored_event_id_hex: Option<String>,
    pub authored_event_created_at: Option<u64>,
    pub accepted_fanout_targets: u32,
    pub unattempted_fanout_targets: u32,
    pub failed_fanout_targets: u32,
    pub policy_prohibited_fanout_targets: u32,
    pub refresh_at: Option<u64>,
    pub last_consumed_key_package_ref_hex: Option<String>,
    pub retained_private_material_count: u32,
    pub pending_event_id_hex: Option<String>,
    pub pending_attempt_count: u32,
    pub pending_last_failure_code: Option<String>,
}

impl From<KeyPackageLifecycleState> for KeyPackageMaintenanceStatusFfi {
    fn from(value: KeyPackageLifecycleState) -> Self {
        let pending = value.pending_replacement.as_ref();
        let count = |state| {
            value
                .publication_targets
                .iter()
                .filter(|target| target.state == state)
                .count() as u32
        };
        Self {
            stable_slot_id: value.stable_slot_id,
            phase: value.phase.into(),
            current_key_package_ref_hex: value.current_key_package_ref.map(hex::encode),
            current_not_before: value.current_not_before.map(|value| value.0),
            current_not_after: value.current_not_after.map(|value| value.0),
            authored_event_id_hex: value
                .authored_event_id
                .map(|message_id| hex::encode(message_id.as_slice())),
            authored_event_created_at: value.authored_event_created_at.map(|value| value.0),
            accepted_fanout_targets: count(TransportFanoutAttemptState::Accepted),
            unattempted_fanout_targets: count(TransportFanoutAttemptState::Unattempted),
            failed_fanout_targets: count(TransportFanoutAttemptState::AttemptedFailed),
            policy_prohibited_fanout_targets: count(TransportFanoutAttemptState::PolicyProhibited),
            refresh_at: value.refresh_at.map(|value| value.0),
            last_consumed_key_package_ref_hex: value.last_consumed_key_package_ref.map(hex::encode),
            retained_private_material_count: value.retained_private_material.len() as u32,
            pending_event_id_hex: pending
                .and_then(|pending| pending.signed_event.as_ref())
                .map(|event| hex::encode(event.id.as_slice())),
            pending_attempt_count: pending.map_or(0, |pending| pending.attempt_count),
            pending_last_failure_code: pending
                .and_then(|pending| pending.last_failure_code.clone()),
        }
    }
}
