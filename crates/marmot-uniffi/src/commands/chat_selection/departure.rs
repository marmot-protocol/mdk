//! Guarded selection steps retain the existing departure/role/journal flows.
use crate::commands::group::{
    ensure_can_promote_admin, ensure_can_request_leave, ensure_can_self_demote_admin,
    group_management_state_for, group_mutation_result_for,
};
use crate::conversions::*;
use crate::subscriptions::ChatSelection;
use crate::{Marmot, MarmotKitError, group_id_from_hex};
use marmot_app::{ChatSelectionDepartureReport, ChatSelectionDepartureStep};
use std::sync::Arc;

fn completed(
    report: ChatSelectionDepartureReport,
) -> Result<ChatSelectionDepartureReport, MarmotKitError> {
    if report.uncertain {
        return Err(MarmotKitError::ChatSelectionUncertain);
    }
    if let Some(error) = &report.refusal {
        return Err(MarmotKitError::from(error.as_ref()));
    }
    if report.skipped {
        return Err(MarmotKitError::ChatSelectionNoLongerEligible);
    }
    Ok(report)
}
async fn retained(
    kit: &Marmot,
    selection: &ChatSelection,
    account: &str,
    action: &ChatSelectionActionFfi,
    id: &str,
    step: &ChatSelectionDepartureStep,
) -> Result<Option<ChatSelectionDepartureReport>, MarmotKitError> {
    selection
        .inner
        .check_runtime_account(&kit.runtime, account)?;
    if let Some(previous) = selection.inner.last_departure().await?
        && previous.operation_id == action.operation_id
        && previous.attempt_id == action.attempt_id
    {
        if previous.group_id_hex != id || &previous.step != step {
            return Err(MarmotKitError::ChatSelectionStale);
        }
        return completed(previous).map(Some);
    }
    Ok(None)
}
async fn execute(
    selection: &ChatSelection,
    action: ChatSelectionActionFfi,
    id: String,
    step: ChatSelectionDepartureStep,
) -> Result<ChatSelectionDepartureReport, MarmotKitError> {
    completed(
        selection
            .inner
            .depart(
                action.operation_id,
                action.attempt_id,
                action.revision,
                id,
                action.context.into(),
                step,
            )
            .await?,
    )
}
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    pub async fn selection_promote_admin_detailed(
        &self,
        selection: Arc<ChatSelection>,
        account_ref: String,
        action: ChatSelectionActionFfi,
        member_ref: String,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group = group_id_from_hex(&action.group_id_hex)?;
        let id = hex::encode(group.as_slice());
        let step = ChatSelectionDepartureStep::Promote {
            member_ref: member_ref.clone(),
        };
        let report = if let Some(report) =
            retained(self, &selection, &account_ref, &action, &id, &step).await?
        {
            report
        } else {
            let state = group_management_state_for(self, &account_ref, &group, &id).await?;
            ensure_can_promote_admin(&state, &id, &member_ref)?;
            execute(&selection, action, id.clone(), step).await?
        };
        let summary = report
            .summary
            .ok_or(MarmotKitError::ChatSelectionUncertain)?;
        group_mutation_result_for(self, &account_ref, &group, &id, summary.into()).await
    }
    pub async fn selection_self_demote_admin_detailed(
        &self,
        selection: Arc<ChatSelection>,
        account_ref: String,
        action: ChatSelectionActionFfi,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group = group_id_from_hex(&action.group_id_hex)?;
        let id = hex::encode(group.as_slice());
        let step = ChatSelectionDepartureStep::SelfDemote;
        let report = if let Some(report) =
            retained(self, &selection, &account_ref, &action, &id, &step).await?
        {
            report
        } else {
            let state = group_management_state_for(self, &account_ref, &group, &id).await?;
            ensure_can_self_demote_admin(&state, &id)?;
            execute(&selection, action, id.clone(), step).await?
        };
        let summary = report
            .summary
            .ok_or(MarmotKitError::ChatSelectionUncertain)?;
        group_mutation_result_for(self, &account_ref, &group, &id, summary.into()).await
    }
    pub async fn selection_leave_group(
        &self,
        selection: Arc<ChatSelection>,
        account_ref: String,
        action: ChatSelectionActionFfi,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group = group_id_from_hex(&action.group_id_hex)?;
        let id = hex::encode(group.as_slice());
        let step = ChatSelectionDepartureStep::Leave;
        let report = if let Some(report) =
            retained(self, &selection, &account_ref, &action, &id, &step).await?
        {
            report
        } else {
            let state = group_management_state_for(self, &account_ref, &group, &id).await?;
            ensure_can_request_leave(&state, &id)?;
            execute(&selection, action, id, step).await?
        };
        Ok(report
            .summary
            .ok_or(MarmotKitError::ChatSelectionUncertain)?
            .into())
    }
    pub async fn selection_forget_group_local(
        &self,
        selection: Arc<ChatSelection>,
        account_ref: String,
        action: ChatSelectionActionFfi,
    ) -> Result<bool, MarmotKitError> {
        let group = group_id_from_hex(&action.group_id_hex)?;
        let id = hex::encode(group.as_slice());
        let step = ChatSelectionDepartureStep::ForgetLocal;
        let report = if let Some(report) =
            retained(self, &selection, &account_ref, &action, &id, &step).await?
        {
            report
        } else {
            execute(&selection, action, id, step).await?
        };
        Ok(report.changed)
    }
    pub async fn selection_delete_group_local(
        &self,
        selection: Arc<ChatSelection>,
        account_ref: String,
        action: ChatSelectionActionFfi,
    ) -> Result<bool, MarmotKitError> {
        let group = group_id_from_hex(&action.group_id_hex)?;
        let id = hex::encode(group.as_slice());
        let step = ChatSelectionDepartureStep::DeleteLocal;
        let report = if let Some(report) =
            retained(self, &selection, &account_ref, &action, &id, &step).await?
        {
            report
        } else {
            execute(&selection, action, id, step).await?
        };
        Ok(report.changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn refused(error: marmot_app::AppError, uncertain: bool) -> ChatSelectionDepartureReport {
        ChatSelectionDepartureReport {
            operation_id: 1,
            attempt_id: 2,
            revision: 3,
            group_id_hex: "private-target-sentinel".into(),
            step: ChatSelectionDepartureStep::Leave,
            summary: None,
            changed: false,
            skipped: false,
            refusal: Some(Arc::new(error)),
            uncertain,
        }
    }
    #[test]
    fn chat_selection_unexpected_departure_refusal_surfaces_uncertainty_before_original_cause() {
        let report = refused(marmot_app::AppError::RuntimeStopping, true);
        assert!(report.refusal.is_some());
        assert!(matches!(
            completed(report),
            Err(MarmotKitError::ChatSelectionUncertain)
        ));
        assert!(matches!(
            completed(refused(
                marmot_app::AppError::GroupCatchingUp("private-target-sentinel".into()),
                false
            )),
            Err(MarmotKitError::GroupCatchingUp { .. })
        ));
        assert!(matches!(
            completed(refused(
                marmot_app::AppError::GroupCommitUndelivered("private-target-sentinel".into()),
                false
            )),
            Err(MarmotKitError::GroupCommitUndelivered { .. })
        ));
    }
}
