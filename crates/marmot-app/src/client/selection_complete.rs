//! Complete-scope capture and action admission through the actual session owner.
use super::AppClient;
mod departure;
use super::selection_context::NativeFolderCaptureError;
use crate::chat_selection::capture::{
    CaptureBuilder, CaptureError, CaptureRequest, PreparedCapture,
};
use crate::chat_selection::scope::{CompiledScope, ScopeError};
pub(crate) use departure::SelectionDepartureOutcome;
use storage_sqlite::{ContextCaptureError, ContextError, SelectedMemberKeys};

/// Exact already-verified cached witness, distinct from the session SQL store.
/// The returned witness must not be replaced by a later cache lookup.
pub(crate) struct BoundSelectionCapture {
    pub prepared: PreparedCapture,
    pub owner: storage_sqlite::SqliteAccountStorage,
    pub owner_epoch: Vec<u8>,
}
impl std::fmt::Debug for BoundSelectionCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.prepared.fmt(f)
    }
}
impl std::ops::Deref for BoundSelectionCapture {
    type Target = PreparedCapture;
    fn deref(&self) -> &Self::Target {
        &self.prepared
    }
}
impl std::ops::DerefMut for BoundSelectionCapture {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.prepared
    }
}
#[cfg(test)]
impl BoundSelectionCapture {
    pub fn complete(
        self,
    ) -> Result<Vec<String>, crate::chat_selection::presentation::PresentationError> {
        self.prepared.complete()
    }
}

pub(crate) enum SelectionApplyOutcome {
    NeedsPresentation(BoundSelectionCapture),
    Applied {
        report: crate::chat_selection::capture::SelectionMutationReport,
        eligible_ids: Vec<String>,
        prepared: PreparedCapture,
        changed: Vec<bool>,
    },
}

impl AppClient {
    pub(crate) fn capture_complete_selection(
        &self,
        request: CaptureRequest,
        abandoned: &impl Fn() -> bool,
    ) -> Result<BoundSelectionCapture, CaptureError> {
        let CaptureRequest {
            scope,
            base,
            original_ids,
            action_hints,
            excluded_cost,
            host,
            overlays,
            revision,
            capture_now_ms,
            cancelled,
        } = request;
        let cancelled = || cancelled.load(std::sync::atomic::Ordering::Acquire) || abandoned();
        if cancelled() {
            return Err(CaptureError::Cancelled);
        }
        let mut compiled = CompiledScope::new(scope).map_err(|error| match error {
            ScopeError::Resources(_) => CaptureError::ResourceExhausted,
            _ => CaptureError::InvalidScope,
        })?;
        compiled
            .budget
            .charge(excluded_cost.0, excluded_cost.1)
            .map_err(|_| CaptureError::ResourceExhausted)?;
        if action_hints {
            compiled
                .require_action_hints()
                .map_err(|_| CaptureError::ResourceExhausted)?;
        }
        let mut builder =
            CaptureBuilder::new(compiled, host.clone(), revision, capture_now_ms, overlays)
                .map_err(|_| CaptureError::ResourceExhausted)?;
        let keys = builder.scope.keys.take();
        let empty = SelectedMemberKeys::for_legacy_catalog(&[])
            .map_err(|_| CaptureError::ResourceExhausted)?;
        let needs_roster = keys.is_some() || builder.needs_roster();
        let storage_request = builder.scope.request;
        let result = self.with_selection_snapshot_bound(&cancelled, |store, check, peer| {
            if peer
                .active
                .is_none_or(|active| hex::encode(active) != host.account_id_hex)
            {
                return Err(crate::AppError::RuntimeStopping.into());
            }
            let prepared = needs_roster.then_some((keys.as_ref().unwrap_or(&empty), peer));
            store.app_storage().visit_selection_scope_context(
                base,
                original_ids.as_deref(),
                storage_request,
                capture_now_ms,
                &cancelled,
                prepared,
                &mut |group| check(group),
                &mut |context| builder.visit(context),
            )?;
            builder.scope.keys = keys;
            builder
                .capture_search_messages(&store.app_storage(), &cancelled)
                .map_err(|error| {
                    NativeFolderCaptureError::Capture(ContextCaptureError::Native(error))
                })?;
            Ok(builder)
        });
        result
            .map_err(|error| match error {
                NativeFolderCaptureError::Capture(ContextCaptureError::Native(
                    ContextError::ResourceExhausted,
                )) => CaptureError::ResourceExhausted,
                NativeFolderCaptureError::Capture(ContextCaptureError::Native(
                    ContextError::Selection(storage_sqlite::ChatListSelectionError::Cancelled),
                )) => CaptureError::Cancelled,
                NativeFolderCaptureError::Capture(ContextCaptureError::Roster(
                    storage_sqlite::RosterReadError::ResourceExhausted,
                )) => CaptureError::ResourceExhausted,
                NativeFolderCaptureError::App(crate::AppError::RuntimeStopping) => {
                    if cancelled() {
                        CaptureError::Cancelled
                    } else {
                        CaptureError::Closed
                    }
                }
                _ => CaptureError::NotReady,
            })
            .and_then(|(mut builder, owner, owner_epoch)| {
                // Local saved-name preparation runs only after account SQL
                // teardown. No directory/profile acquisition or host callback.
                builder.prepare_search_system_names(&self.app)?;
                let prepared = builder
                    .finish()
                    .map_err(|_| CaptureError::ResourceExhausted)?;
                self.app
                    .ensure_storage_open("native selection")
                    .map_err(|_| CaptureError::Closed)?;
                if cancelled() {
                    return Err(CaptureError::Cancelled);
                }
                if !self
                    .app
                    .account_storage_is_current(&self.state.label, &owner)
                    || self
                        .app
                        .account_home()
                        .account(&self.state.label)
                        .map_err(|_| CaptureError::Closed)?
                        .account_id_hex
                        != host.account_id_hex
                    || owner
                        .app_storage()
                        .chat_presentation_version()
                        .map_err(|_| CaptureError::Closed)?
                        .store_epoch
                        != owner_epoch
                {
                    return Err(CaptureError::Closed);
                }
                if cancelled()
                    || !self
                        .app
                        .account_storage_is_current(&self.state.label, &owner)
                {
                    return Err(if cancelled() {
                        CaptureError::Cancelled
                    } else {
                        CaptureError::Closed
                    });
                }
                Ok(BoundSelectionCapture {
                    prepared,
                    owner,
                    owner_epoch,
                })
            })
    }
    /// Recompute in the actual worker immediately before using host answers.
    /// Existing mutators run only after the held snapshot has been released.
    #[expect(
        clippy::too_many_arguments,
        reason = "Authority, frozen capture proof, action intent and cancellation remain explicit at the account-worker boundary."
    )]
    pub(crate) async fn apply_complete_selection(
        &mut self,
        mut request: CaptureRequest,
        proof: Option<std::sync::Arc<crate::chat_selection::presentation::PresentationProof>>,
        owner: storage_sqlite::SqliteAccountStorage,
        owner_epoch: Vec<u8>,
        mutation: crate::chat_selection::capture::SelectionMutation,
        attempt_id: u64,
        operation_id: u64,
        abandoned: &impl Fn() -> bool,
    ) -> Result<SelectionApplyOutcome, CaptureError> {
        use crate::chat_selection::capture::{SelectionMutation, SelectionMutationReport};
        use crate::chat_selection::presentation::PresentationError;
        let cancelled = request.cancelled.clone();
        let revision = request.revision;
        request.capture_now_ms = crate::notifications::unix_now_ms();
        let mut fresh = match tokio::runtime::Handle::try_current()
            .map(|handle| handle.runtime_flavor())
        {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
                tokio::task::block_in_place(|| self.capture_complete_selection(request, abandoned))?
            }
            _ => return Err(CaptureError::UnsupportedRuntime),
        };
        if !fresh.owner.shares_connection_with(&owner) || fresh.owner_epoch != owner_epoch {
            return Err(CaptureError::Closed);
        }
        if let Some(pending) = fresh.prepared.presentation.as_mut() {
            match proof.as_ref().map(|proof| pending.reuse_proof(proof)) {
                Some(Ok(())) => {}
                Some(Err(PresentationError::ResourceExhausted)) => {
                    return Err(CaptureError::ResourceExhausted);
                }
                _ => return Ok(SelectionApplyOutcome::NeedsPresentation(fresh)),
            }
        }
        let eligible_ids = fresh.resolved_ids().map_err(|_| CaptureError::NotReady)?;
        let mut report = SelectionMutationReport {
            mutation,
            attempt_id,
            operation_id,
            revision,
            applied_group_ids: Vec::new(),
            failed_group_id: None,
            uncertain: false,
            remaining: eligible_ids.len(),
        };
        report
            .applied_group_ids
            .try_reserve(eligible_ids.len().min(200))
            .map_err(|_| CaptureError::ResourceExhausted)?;
        let mut changed = Vec::new();
        changed
            .try_reserve(eligible_ids.len().min(200))
            .map_err(|_| CaptureError::ResourceExhausted)?;
        // All fallible output/identity allocations precede the first mutation,
        // so allocation failure cannot erase an already-applied partial result.
        let mut attempts = Vec::new();
        attempts
            .try_reserve(eligible_ids.len().min(200))
            .map_err(|_| CaptureError::ResourceExhausted)?;
        for id in eligible_ids.iter().take(200) {
            let owned = crate::chat_selection::presentation::owned_text(id)
                .map_err(|_| CaptureError::ResourceExhausted)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(id.len() / 2)
                .map_err(|_| CaptureError::ResourceExhausted)?;
            bytes.resize(id.len() / 2, 0);
            hex::decode_to_slice(id, &mut bytes).map_err(|_| CaptureError::NotReady)?;
            attempts.push((owned, cgka_traits::GroupId::new(bytes)));
        }
        for (id, group) in attempts {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) || abandoned() {
                break;
            }
            let owner_ok = tokio::task::block_in_place(|| {
                self.app.ensure_storage_open("selection action").is_ok()
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
                            account.account_id_hex
                                == hex::encode(self.runtime.session().self_id().as_slice())
                        })
            });
            if !owner_ok {
                report.uncertain = true;
                break;
            }
            let result = match mutation {
                SelectionMutation::Archive { archived } => tokio::task::block_in_place(|| {
                    self.set_group_archived(&group, archived).map(|_| true)
                }),
                SelectionMutation::DeleteLocal => self.delete_group_local(&group).await,
            };
            match result {
                Ok(did_change) => {
                    report.applied_group_ids.push(id);
                    changed.push(did_change);
                }
                Err(_) => {
                    report.failed_group_id = Some(id);
                    report.uncertain = true;
                    break;
                }
            }
        }
        report.remaining = eligible_ids
            .len()
            .saturating_sub(report.applied_group_ids.len());
        Ok(SelectionApplyOutcome::Applied {
            report,
            eligible_ids,
            prepared: fresh.prepared,
            changed,
        })
    }
}

#[cfg(test)]
mod tests;
