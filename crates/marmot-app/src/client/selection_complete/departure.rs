//! One existing departure mutator under the existing worker owner. The actor
//! alone supplies whether the target's whole intent was already admitted.
use super::*;
use crate::runtime::ChatSelectionDepartureStep;

pub(crate) enum SelectionDepartureOutcome {
    NeedsPresentation(Box<BoundSelectionCapture>),
    Effect {
        summary: Option<crate::SendSummary>,
        changed: bool,
        skipped: bool,
        error: Option<crate::AppError>,
        refused_before_effect: bool,
    },
}
impl AppClient {
    #[expect(
        clippy::too_many_arguments,
        reason = "Authority, frozen capture proof, action intent and cancellation remain explicit at the account-worker boundary."
    )]
    pub(crate) async fn depart_complete_selection(
        &mut self,
        mut request: CaptureRequest,
        proof: Option<std::sync::Arc<crate::chat_selection::presentation::PresentationProof>>,
        owner: storage_sqlite::SqliteAccountStorage,
        owner_epoch: Vec<u8>,
        group_id: String,
        step: ChatSelectionDepartureStep,
        admitted: bool,
        abandoned: &impl Fn() -> bool,
    ) -> Result<SelectionDepartureOutcome, CaptureError> {
        use crate::chat_selection::presentation::PresentationError;
        if !matches!(
            tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        ) {
            return Err(CaptureError::UnsupportedRuntime);
        }
        let cancelled = request.cancelled.clone();
        let account_id = request.host.account_id_hex.clone();
        if request.original_ids.as_deref() != Some(std::slice::from_ref(&group_id)) {
            return Err(CaptureError::InvalidScope);
        }
        // Decoding and all recoverable result allocation precede the effect.
        let group = cgka_traits::GroupId::new(
            hex::decode(&group_id).map_err(|_| CaptureError::InvalidScope)?,
        );
        if !admitted {
            request.capture_now_ms = crate::notifications::unix_now_ms();
            let mut fresh = tokio::task::block_in_place(|| {
                self.capture_complete_selection(request, abandoned)
            })?;
            if !fresh.owner.shares_connection_with(&owner) || fresh.owner_epoch != owner_epoch {
                return Err(CaptureError::Closed);
            }
            if let Some(pending) = fresh.prepared.presentation.as_mut() {
                match proof.as_ref().map(|proof| pending.reuse_proof(proof)) {
                    Some(Ok(())) => {}
                    Some(Err(PresentationError::ResourceExhausted)) => {
                        return Err(CaptureError::ResourceExhausted);
                    }
                    _ => {
                        return Ok(SelectionDepartureOutcome::NeedsPresentation(Box::new(
                            fresh,
                        )));
                    }
                }
            }
            let ids = fresh.resolved_ids().map_err(|_| CaptureError::NotReady)?;
            if !ids.iter().any(|id| id == &group_id) {
                return Ok(SelectionDepartureOutcome::Effect {
                    summary: None,
                    changed: false,
                    skipped: true,
                    error: None,
                    refused_before_effect: true,
                });
            }
        }
        let live = tokio::task::block_in_place(|| {
            self.app.ensure_storage_open("selection departure").is_ok()
                && self
                    .app
                    .account_storage_is_current(&self.state.label, &owner)
                && owner
                    .app_storage()
                    .chat_presentation_version()
                    .is_ok_and(|version| version.store_epoch == owner_epoch)
                && self
                    .app
                    .account_home()
                    .account(&self.state.label)
                    .is_ok_and(|account| {
                        account.account_id_hex == account_id
                            && account.account_id_hex
                                == hex::encode(self.runtime.session().self_id().as_slice())
                    })
        });
        if !live {
            return Err(CaptureError::Closed);
        }
        // Continuation does not re-filter the admitted intent, but it still
        // binds the ACTUAL dedicated session store to the cached witness epoch.
        // No roster/profile/body read or foreign callback enters this snapshot.
        let session_epoch = tokio::task::block_in_place(|| {
            self.runtime
                .session()
                .with_members_read_snapshot::<_, cgka_traits::StorageError>(|store, _| {
                    store
                        .app_storage()
                        .chat_presentation_version()
                        .map(|version| version.store_epoch)
                })
        })
        .map_err(|_| CaptureError::Closed)?;
        if session_epoch != owner_epoch
            || !self
                .app
                .account_storage_is_current(&self.state.label, &owner)
        {
            return Err(CaptureError::Closed);
        }
        if cancelled.load(std::sync::atomic::Ordering::Acquire) || abandoned() {
            return Err(CaptureError::Cancelled);
        }
        // Actual mutators retain current authoritative engine role/roster,
        // single-attempt acknowledgement and audit behavior. No folder recapture
        // is allowed between effects of this already-admitted target intent.
        if matches!(step, ChatSelectionDepartureStep::DeleteLocal)
            && self
                .runtime
                .disbanding_in_progress(&group)
                .is_ok_and(|disbanding| disbanding)
        {
            return Ok(SelectionDepartureOutcome::Effect {
                summary: None,
                changed: false,
                skipped: false,
                error: Some(crate::AppError::GroupDisbanding(group_id)),
                refused_before_effect: true,
            });
        }
        let result = match step {
            ChatSelectionDepartureStep::Promote { member_ref } => self
                .promote_admin(&group, &member_ref)
                .await
                .map(|summary| (Some(summary), true)),
            ChatSelectionDepartureStep::SelfDemote => self
                .self_demote_admin(&group)
                .await
                .map(|summary| (Some(summary), true)),
            ChatSelectionDepartureStep::Leave => self
                .leave_group(&group)
                .await
                .map(|summary| (Some(summary), true)),
            ChatSelectionDepartureStep::ForgetLocal => self
                .forget_group_local(&group)
                .await
                .map(|changed| (None, changed)),
            ChatSelectionDepartureStep::DeleteLocal => self
                .delete_group_local(&group)
                .await
                .map(|changed| (None, changed)),
        };
        Ok(match result {
            Ok((summary, changed)) => SelectionDepartureOutcome::Effect {
                summary,
                changed,
                skipped: false,
                error: None,
                refused_before_effect: false,
            },
            Err(error) => SelectionDepartureOutcome::Effect {
                summary: None,
                changed: false,
                skipped: false,
                error: Some(error),
                refused_before_effect: false,
            },
        })
    }
}
