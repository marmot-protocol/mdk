//! Agent-control maintenance status and policy handlers.

use agent_control::{
    AgentControlKeyPackageMaintenanceStatus, AgentControlMaintenanceObligation,
    AgentControlMaintenanceStatus, AgentControlResponse, AgentControlSendMaintenanceDisposition,
};
use cgka_traits::{
    GroupEvolutionPhase, GroupId, MaintenanceObligation, MaintenanceTrigger,
    PeriodicMaintenancePolicy, SendMaintenanceDisposition, TransportFanoutAttemptState,
};

use crate::{AgentConnector, ConnectorError};

impl AgentConnector {
    pub(crate) async fn maintenance_status_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let status = self
            .runtime
            .maintenance_status(&account.label, &group_id)
            .await?;
        let state = status.state;
        let evolution_count = |phase| {
            status
                .evolutions
                .iter()
                .filter(|evolution| evolution.phase == phase)
                .count() as u32
        };
        let fanout_count = |attempt_state| {
            status
                .fanouts
                .iter()
                .flat_map(|fanout| &fanout.targets)
                .filter(|target| target.state == attempt_state)
                .count() as u32
        };
        Ok(AgentControlResponse::MaintenanceStatus {
            status: AgentControlMaintenanceStatus {
                group_id_hex: hex::encode(group_id.as_slice()),
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
                obligations: status
                    .obligations
                    .into_iter()
                    .map(agent_obligation)
                    .collect(),
                preparing_evolutions: evolution_count(GroupEvolutionPhase::Preparing),
                prepared_evolutions: evolution_count(GroupEvolutionPhase::Prepared),
                attempting_evolutions: evolution_count(GroupEvolutionPhase::Attempting),
                confirmed_evolutions: evolution_count(GroupEvolutionPhase::Confirmed),
                superseded_evolutions: evolution_count(
                    GroupEvolutionPhase::SupersededByConvergence,
                ),
                accepted_fanout_targets: fanout_count(TransportFanoutAttemptState::Accepted),
                unattempted_fanout_targets: fanout_count(TransportFanoutAttemptState::Unattempted),
                failed_fanout_targets: fanout_count(TransportFanoutAttemptState::AttemptedFailed),
                policy_prohibited_fanout_targets: fanout_count(
                    TransportFanoutAttemptState::PolicyProhibited,
                ),
                paused: status.paused,
            },
        })
    }

    pub(crate) async fn key_package_maintenance_status_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let status = self
            .runtime
            .key_package_maintenance_status(&account.label)
            .await?
            .map(|status| {
                let pending = status.pending_replacement.as_ref();
                AgentControlKeyPackageMaintenanceStatus {
                    stable_slot_id: status.stable_slot_id,
                    phase: status.phase.as_str().to_owned(),
                    current_key_package_ref_hex: status.current_key_package_ref.map(hex::encode),
                    current_not_after: status.current_not_after.map(|value| value.0),
                    refresh_at: status.refresh_at.map(|value| value.0),
                    authored_event_id_hex: status
                        .authored_event_id
                        .map(|message_id| hex::encode(message_id.as_slice())),
                    last_consumed_key_package_ref_hex: status
                        .last_consumed_key_package_ref
                        .map(hex::encode),
                    retained_private_material_count: status.retained_private_material.len() as u32,
                    accepted_fanout_targets: status
                        .publication_targets
                        .iter()
                        .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
                        .count() as u32,
                    unattempted_fanout_targets: status
                        .publication_targets
                        .iter()
                        .filter(|target| target.state == TransportFanoutAttemptState::Unattempted)
                        .count() as u32,
                    failed_fanout_targets: status
                        .publication_targets
                        .iter()
                        .filter(|target| {
                            target.state == TransportFanoutAttemptState::AttemptedFailed
                        })
                        .count() as u32,
                    policy_prohibited_fanout_targets: status
                        .publication_targets
                        .iter()
                        .filter(|target| {
                            target.state == TransportFanoutAttemptState::PolicyProhibited
                        })
                        .count() as u32,
                    pending_event_id_hex: pending
                        .and_then(|pending| pending.signed_event.as_ref())
                        .map(|event| hex::encode(event.id.as_slice())),
                    pending_attempt_count: pending.map_or(0, |pending| pending.attempt_count),
                    pending_last_failure_code: pending
                        .and_then(|pending| pending.last_failure_code.clone()),
                }
            });
        Ok(AgentControlResponse::KeyPackageMaintenanceStatus { status })
    }

    pub(crate) async fn maintenance_schedule_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let obligation_id_hex = self
            .runtime
            .schedule_manual_self_update(&account.label, &group_id)
            .await?;
        Ok(AgentControlResponse::MaintenanceScheduled { obligation_id_hex })
    }

    pub(crate) async fn maintenance_policy_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let policy = self
            .runtime
            .periodic_maintenance_policy(&account.label)
            .await?;
        Ok(AgentControlResponse::MaintenancePolicy {
            enabled_for_new_groups: policy == PeriodicMaintenancePolicy::EnabledForNewGroups,
        })
    }

    pub(crate) async fn set_maintenance_policy_response(
        &self,
        account_id_hex: &str,
        enabled_for_new_groups: bool,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let policy = if enabled_for_new_groups {
            PeriodicMaintenancePolicy::EnabledForNewGroups
        } else {
            PeriodicMaintenancePolicy::Disabled
        };
        self.runtime
            .set_periodic_maintenance_policy(&account.label, policy)
            .await?;
        self.maintenance_policy_response(account_id_hex).await
    }

    pub(crate) async fn pause_maintenance_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        self.runtime.pause_maintenance(&account.label).await?;
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) async fn resume_maintenance_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        self.runtime.resume_maintenance(&account.label).await?;
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) async fn run_maintenance_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let summary = self.runtime.run_due_maintenance(&account.label).await?;
        Ok(AgentControlResponse::MaintenanceRun {
            published: summary.published,
            message_ids_hex: summary.message_ids,
            deferred: summary.deferred,
            ambiguous_exposure: summary.ambiguous_exposure,
            failures: summary.failures,
        })
    }
}

pub(crate) fn agent_maintenance_disposition(
    disposition: SendMaintenanceDisposition,
) -> AgentControlSendMaintenanceDisposition {
    match disposition {
        SendMaintenanceDisposition::Ready => AgentControlSendMaintenanceDisposition::Ready,
        SendMaintenanceDisposition::PostJoinRotationPendingRetryable => {
            AgentControlSendMaintenanceDisposition::PostJoinRotationPendingRetryable
        }
    }
}

fn agent_obligation(value: MaintenanceObligation) -> AgentControlMaintenanceObligation {
    AgentControlMaintenanceObligation {
        id_hex: hex::encode(value.id.as_slice()),
        trigger: match value.trigger {
            MaintenanceTrigger::PostJoin => "post_join",
            MaintenanceTrigger::Periodic => "periodic",
            MaintenanceTrigger::Manual => "manual",
        }
        .to_owned(),
        phase: value.phase.as_str().to_owned(),
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
