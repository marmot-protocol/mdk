//! Per-target continuation of the existing departure dialog/journal. Admission
//! covers one intent; its own committed system messages cannot revoke its later
//! cleanup step. No standalone token or new owner/registry is created.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub enum ChatSelectionDepartureStep {
    Promote { member_ref: String },
    SelfDemote,
    Leave,
    ForgetLocal,
    DeleteLocal,
}
impl ChatSelectionDepartureStep {
    pub(crate) fn kind(&self) -> u8 {
        match self {
            Self::Promote { .. } => 0,
            Self::SelfDemote => 1,
            Self::Leave => 2,
            Self::ForgetLocal => 3,
            Self::DeleteLocal => 4,
        }
    }
    fn final_step(&self) -> bool {
        matches!(self, Self::ForgetLocal | Self::DeleteLocal)
    }
}
impl std::fmt::Debug for ChatSelectionDepartureStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSelectionDepartureStep")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub struct ChatSelectionDepartureReport {
    pub operation_id: u64,
    pub attempt_id: u64,
    pub revision: u64,
    pub group_id_hex: String,
    pub step: ChatSelectionDepartureStep,
    pub summary: Option<crate::SendSummary>,
    pub changed: bool,
    pub skipped: bool,
    /// Existing advisory refusals and explicit worker front guards are known
    /// pre-effect results; errors after invoking a mutator stay conservative.
    pub refusal: Option<Arc<AppError>>,
    pub uncertain: bool,
}
impl std::fmt::Debug for ChatSelectionDepartureReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSelectionDepartureReport")
            .field("step", &self.step)
            .field("changed", &self.changed)
            .field("skipped", &self.skipped)
            .field("has_refusal", &self.refusal.is_some())
            .field("uncertain", &self.uncertain)
            .finish_non_exhaustive()
    }
}
fn known_pre_effect_refusal(error: &AppError) -> bool {
    matches!(
        error,
        AppError::GroupCatchingUp(_) | AppError::GroupCommitUndelivered(_)
    )
}
pub(super) struct DepartureState {
    operation_id: u64,
    group_id: String,
    completed: u8,
    pub(super) admitted: bool,
    pub(super) finished: bool,
    attempt_id: u64,
    step: ChatSelectionDepartureStep,
    pub(super) report: Option<ChatSelectionDepartureReport>,
}
impl RuntimeChatListSelection {
    /// Execute one step of the existing departure flow. A higher attempt is a
    /// new explicit step/retry, never an automatic replay of an uncertain effect.
    pub async fn depart(
        &self,
        operation_id: u64,
        attempt_id: u64,
        revision: u64,
        group_id: String,
        context: ChatSelectionContext,
        step: ChatSelectionDepartureStep,
    ) -> Result<ChatSelectionDepartureReport, ChatListSelectionError> {
        validate_visible_ids(std::slice::from_ref(&group_id))?;
        if let ChatSelectionDepartureStep::Promote { member_ref } = &step {
            let mut budget = crate::chat_selection::presentation::CaptureBudget::default();
            budget.charge(member_ref.len(), 0)?;
        }
        match self
            .send(Action::Departure {
                operation_id,
                attempt_id,
                revision,
                group_id,
                context,
                step,
            })
            .await?
        {
            Response::Departure(value) => Ok(value),
            _ => unreachable!("departure response"),
        }
    }
    pub async fn last_departure(
        &self,
    ) -> Result<Option<ChatSelectionDepartureReport>, ChatListSelectionError> {
        match self.send(Action::LastDeparture).await? {
            Response::LastDeparture(value) => Ok(value),
            _ => unreachable!("departure readback"),
        }
    }
}
impl CompleteState {
    pub(super) async fn depart(
        &mut self,
        operation_id: u64,
        attempt_id: u64,
        revision: u64,
        group_id: String,
        context: ChatSelectionContext,
        step: ChatSelectionDepartureStep,
    ) -> Result<Response, ChatListSelectionError> {
        if self.operation_mutation.is_some() {
            return Err(ChatListSelectionError::UnsupportedScope);
        }
        if let Some(previous) = &self.departure {
            if previous.operation_id != operation_id || attempt_id < previous.attempt_id {
                return Err(ChatListSelectionError::StaleRevision);
            }
            if attempt_id == previous.attempt_id {
                if previous.group_id != group_id || previous.step != step {
                    return Err(ChatListSelectionError::StaleRevision);
                }
                if let Some(report) = &previous.report {
                    return Ok(Response::Departure(report.clone()));
                }
                // An unanswered first admission is the only resumable same
                // attempt without a retained result. No effect started yet.
                if self.mutation_uncertain {
                    return Err(ChatListSelectionError::Closed);
                }
            } else if self.mutation_uncertain || previous.report.is_none() {
                return Err(ChatListSelectionError::IncompletePresentation);
            }
            if !previous.finished && previous.group_id != group_id {
                return Err(ChatListSelectionError::IncompletePresentation);
            }
            if previous.group_id == group_id && previous.finished {
                return Err(ChatListSelectionError::StaleRevision);
            }
            if previous.group_id == group_id && previous.completed & (1 << step.kind()) != 0 {
                return Err(ChatListSelectionError::StaleRevision);
            }
            if previous.group_id == group_id
                && previous.completed & (1 << 2) != 0
                && !step.final_step()
            {
                return Err(ChatListSelectionError::StaleRevision);
            }
        }
        self.require_revision(revision)?;
        if context.host.account_id_hex != self.request.host.account_id_hex {
            return Err(ChatListSelectionError::Closed);
        }
        let previous = self
            .departure
            .as_ref()
            .filter(|state| state.group_id == group_id);
        let admitted = previous.is_some_and(|state| state.admitted);
        if !admitted
            && !self
                .selected
                .as_ref()
                .ok_or(ChatListSelectionError::IncompletePresentation)?
                .binary_search(&group_id)
                .is_ok()
        {
            return Err(ChatListSelectionError::StaleRevision);
        }
        let completed = previous.map_or(0, |state| state.completed);
        let mut request = self.request.clone();
        request.original_ids = Some(vec![owned_text(&group_id)?]);
        request.revision = revision
            .checked_add(1)
            .ok_or(ChatListSelectionError::StaleRevision)?;
        request.host = context.host;
        request.overlays = context.overlays;
        request.capture_now_ms = crate::notifications::unix_now_ms();
        let report_group_id = owned_text(&group_id)?;
        self.departure = Some(DepartureState {
            operation_id,
            group_id: owned_text(&group_id)?,
            completed,
            admitted,
            finished: false,
            attempt_id,
            step: step.clone(),
            report: None,
        });
        self.operation_id = Some(operation_id);
        self.last_attempt = Some(attempt_id);
        self.mutation_uncertain = true;
        let result = self
            .manager
            .depart_selection_context(
                &self.reader.label,
                request.clone(),
                self.proof.clone(),
                self.reader.storage.clone(),
                self.owner_epoch.clone(),
                group_id,
                step.clone(),
                admitted,
            )
            .await;
        let outcome = match result {
            Ok(value) => value,
            Err(error) => {
                // Only source-owned pre-effect capture errors clear uncertainty.
                if error != crate::chat_selection::capture::CaptureError::Closed {
                    self.mutation_uncertain = false;
                }
                return Err(error.into());
            }
        };
        match outcome {
            crate::client::SelectionDepartureOutcome::NeedsPresentation(bound) => {
                // No departure effect ran; follow-up capture failure is known
                // non-effect with a refused follow-up capture.
                self.mutation_uncertain = false;
                let bound = *bound;
                if !bound.owner.shares_connection_with(&self.reader.storage)
                    || bound.owner_epoch != self.owner_epoch
                {
                    return Err(ChatListSelectionError::Closed);
                }
                let selected = self.selected.as_ref().expect("resolved before admission");
                let mut all = Vec::new();
                all.try_reserve_exact(selected.len()).map_err(|_| {
                    crate::chat_selection::presentation::PresentationError::ResourceExhausted
                })?;
                for id in selected {
                    all.push(owned_text(id)?);
                }
                request.original_ids = Some(all);
                let full = self
                    .manager
                    .capture_selection_context(&self.reader.label, request.clone())
                    .await?;
                if !full.owner.shares_connection_with(&self.reader.storage)
                    || full.owner_epoch != self.owner_epoch
                {
                    return Err(ChatListSelectionError::Closed);
                }
                self.request = request;
                self.prepared = full.prepared;
                self.selected = None;
                self.proof = None;
                Err(ChatListSelectionError::IncompletePresentation)
            }
            crate::client::SelectionDepartureOutcome::Effect {
                summary,
                changed,
                skipped,
                error,
                refused_before_effect,
            } => {
                let known_refusal =
                    refused_before_effect || error.as_ref().is_some_and(known_pre_effect_refusal);
                let report = ChatSelectionDepartureReport {
                    operation_id,
                    attempt_id,
                    revision: request.revision,
                    group_id_hex: report_group_id,
                    step: step.clone(),
                    summary,
                    changed,
                    skipped,
                    uncertain: error.is_some() && !known_refusal,
                    refusal: error.map(Arc::new),
                };
                let state = self.departure.as_mut().expect("intent retained");
                if report.refusal.is_none() && !skipped {
                    state.admitted = true;
                    state.completed |= 1 << step.kind();
                }
                state.finished = skipped || (report.refusal.is_none() && step.final_step());
                if state.finished {
                    self.selected
                        .as_mut()
                        .expect("resolved intent")
                        .retain(|id| id != &state.group_id);
                }
                self.request.revision = request.revision;
                self.mutation_uncertain = report.uncertain;
                state.report = Some(report.clone());
                Ok(Response::Departure(report))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_next_change_cautions_permit_acknowledged_step_retry() {
        assert!(known_pre_effect_refusal(&AppError::GroupCatchingUp(
            "private-group-sentinel".into()
        )));
        assert!(known_pre_effect_refusal(&AppError::GroupCommitUndelivered(
            "private-group-sentinel".into()
        )));
        assert!(!known_pre_effect_refusal(&AppError::TransportClosed));
        assert!(!known_pre_effect_refusal(&AppError::RuntimeStopping));
        let report = ChatSelectionDepartureReport {
            operation_id: 1,
            attempt_id: 2,
            revision: 3,
            group_id_hex: "private-group-sentinel".into(),
            step: ChatSelectionDepartureStep::Promote {
                member_ref: "private-member-sentinel".into(),
            },
            summary: None,
            changed: false,
            skipped: false,
            refusal: Some(Arc::new(AppError::GroupCatchingUp(
                "private-error-sentinel".into(),
            ))),
            uncertain: false,
        };
        assert!(!format!("{report:?}").contains("sentinel"));
    }
}
