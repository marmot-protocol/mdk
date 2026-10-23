//! Complete-scope mode of the existing selection owner. Host rendering occurs
//! only through bounded owned pages after the worker's SQL snapshot is released.
use super::*;
mod departure;
use crate::chat_selection::capture::{CaptureRequest, PreparedCapture};
use crate::chat_selection::presentation::owned_text;
pub use departure::{ChatSelectionDepartureReport, ChatSelectionDepartureStep};

#[derive(Clone, Debug)]
pub struct ChatSelectionContext {
    pub host: ChatSelectionHostContext,
    pub overlays: ChatSelectionHostOverlays,
    pub capture_now_ms: i64,
}
#[derive(Clone, Debug)]
pub struct ChatSelectionOpen {
    pub scope: ChatSelectionScope,
    pub base: storage_sqlite::SelectionBaseScope,
    pub context: ChatSelectionContext,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatSelectionStatus {
    pub revision: u64,
    pub count: Option<usize>,
    pub all_archived: Option<bool>,
    pub all_direct: Option<bool>,
    pub all_abandonable: Option<bool>,
    pub presentation_operands: usize,
    pub operation_id: Option<u64>,
    pub last_attempt: Option<u64>,
    pub mutation_uncertain: bool,
}
struct CompleteState {
    reader: Reader,
    owner_epoch: Vec<u8>,
    manager: super::super::AccountManager,
    request: CaptureRequest,
    prepared: PreparedCapture,
    selected: Option<Vec<String>>,
    // Only explicit unchecked native originals, never host-nominated IDs.
    excluded: Vec<String>,
    last_mutation: Option<ChatSelectionMutationReport>,
    mutation_uncertain: bool,
    operation_id: Option<u64>,
    operation_mutation: Option<ChatSelectionMutation>,
    last_attempt: Option<u64>,
    waiting_mutation: Option<ChatSelectionMutation>,
    unresolved_request: Option<CaptureRequest>,
    proof: Option<Arc<crate::chat_selection::presentation::PresentationProof>>,
    departure: Option<departure::DepartureState>,
}
impl RuntimeChatListSelection {
    /// Fresh bounded handoff for the host's idempotent folder-preference union.
    /// `after` is an exclusive original-ID cursor, never candidate authority.
    /// Recheck the frozen host context immediately before writing preferences.
    pub async fn folder_assignment_page(
        &self,
        revision: u64,
        context: ChatSelectionContext,
        after: Option<String>,
        limit: usize,
    ) -> Result<ChatSelectionFolderPage, ChatListSelectionError> {
        match self
            .send(Action::FolderAssignment {
                revision,
                context,
                after,
                limit,
            })
            .await?
        {
            Response::FolderPage(page) => Ok(page),
            _ => unreachable!("folder assignment response"),
        }
    }
    /// Display-only membership for at most 200 visible IDs, in input order.
    /// IDs never add candidates or authorize an action.
    pub async fn membership(
        &self,
        revision: u64,
        group_ids: Vec<String>,
    ) -> Result<Vec<bool>, ChatListSelectionError> {
        validate_visible_ids(&group_ids)?;
        match self
            .send(Action::Membership {
                revision,
                group_ids,
            })
            .await?
        {
            Response::Membership(value) => Ok(value),
            _ => unreachable!("membership response"),
        }
    }
    /// Shrinks the resolved original set. A pending or uncertain mutation must
    /// retain its exact intent; deselection cannot disguise an unresolved retry.
    pub async fn exclude(
        &self,
        revision: u64,
        group_ids: Vec<String>,
    ) -> Result<ChatSelectionStatus, ChatListSelectionError> {
        validate_visible_ids(&group_ids)?;
        match self
            .send(Action::Exclude {
                revision,
                group_ids,
            })
            .await?
        {
            Response::Status(value) => Ok(value),
            _ => unreachable!("exclusion response"),
        }
    }
    /// Restores only explicitly unchecked original IDs, before an operation starts.
    /// Fresh scope/owner/presentation checks still apply; no arrivals are admitted.
    /// A new revision invalidates every previously prepared page or host answer.
    pub async fn reselect(
        &self,
        revision: u64,
        context: ChatSelectionContext,
        group_ids: Vec<String>,
    ) -> Result<ChatSelectionStatus, ChatListSelectionError> {
        validate_visible_ids(&group_ids)?;
        match self
            .send(Action::Reselect {
                revision,
                context,
                group_ids,
            })
            .await?
        {
            Response::Status(value) => Ok(value),
            _ => unreachable!("reselection response"),
        }
    }
    /// Applies at most 200 freshly eligible original IDs. The actor retains a
    /// result for readback if the caller abandons its wait. Uncertain outcomes
    /// are terminal for further mutations on this handle.
    pub async fn apply(
        &self,
        operation_id: u64,
        attempt_id: u64,
        revision: u64,
        context: ChatSelectionContext,
        mutation: ChatSelectionMutation,
    ) -> Result<ChatSelectionMutationReport, ChatListSelectionError> {
        match self
            .send(Action::Apply {
                operation_id,
                attempt_id,
                revision,
                context,
                mutation,
            })
            .await?
        {
            Response::Mutation(value) => Ok(value),
            _ => unreachable!("mutation response"),
        }
    }
    pub async fn last_mutation(
        &self,
    ) -> Result<Option<ChatSelectionMutationReport>, ChatListSelectionError> {
        match self.send(Action::LastMutation).await? {
            Response::LastMutation(value) => Ok(value),
            _ => unreachable!("last mutation response"),
        }
    }
    pub async fn status(&self) -> Result<ChatSelectionStatus, ChatListSelectionError> {
        match self.send(Action::Status).await? {
            Response::Status(value) => Ok(value),
            _ => unreachable!("status response"),
        }
    }
    pub async fn presentation_page(
        &self,
        revision: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ChatSelectionOperand>, ChatListSelectionError> {
        match self
            .send(Action::Presentation {
                revision,
                offset,
                limit,
            })
            .await?
        {
            Response::Operands(value) => Ok(value),
            _ => unreachable!("presentation response"),
        }
    }
    pub async fn submit_presentation(
        &self,
        revision: u64,
        host: ChatSelectionHostContext,
        answers: Vec<ChatSelectionAnswer>,
    ) -> Result<ChatSelectionStatus, ChatListSelectionError> {
        match self
            .send(Action::Answer {
                revision,
                host,
                answers,
            })
            .await?
        {
            Response::Status(value) => Ok(value),
            _ => unreachable!("answer response"),
        }
    }
    pub async fn resolve_presentation(
        &self,
        revision: u64,
    ) -> Result<ChatListSelectionSummary, ChatListSelectionError> {
        match self.send(Action::Resolve { revision }).await? {
            Response::Summary(value) => Ok(value),
            _ => unreachable!("resolve response"),
        }
    }
    /// Explicitly prepare complete-set type/lifecycle display hints before a
    /// confirmation. The configured scope is unchanged; missing optional hints never
    /// force default count/membership to hydrate presentation or roster facts.
    pub async fn prepare_action_hints(
        &self,
        revision: u64,
        context: ChatSelectionContext,
    ) -> Result<ChatSelectionStatus, ChatListSelectionError> {
        match self
            .send(Action::Refresh {
                revision,
                context,
                action_hints: true,
            })
            .await?
        {
            Response::Status(value) => Ok(value),
            _ => unreachable!("action hint response"),
        }
    }
    /// Fresh current host context and native original-ID snapshot are required.
    /// Existing answers are discarded even when the rendered title looks equal.
    pub async fn refresh_scope(
        &self,
        revision: u64,
        context: ChatSelectionContext,
    ) -> Result<ChatSelectionStatus, ChatListSelectionError> {
        match self
            .send(Action::Refresh {
                revision,
                context,
                action_hints: false,
            })
            .await?
        {
            Response::Status(value) => Ok(value),
            _ => unreachable!("refresh response"),
        }
    }
}
impl MarmotAppRuntime {
    pub async fn open_complete_chat_list_selection(
        &self,
        account_ref: &str,
        open: ChatSelectionOpen,
    ) -> Result<RuntimeChatListSelection, ChatListSelectionError> {
        self.shared.lifecycle().ensure_running()?;
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let mut resets = self
            .accounts
            .app
            .presentation_signals
            .account_resets
            .subscribe();
        let account = self
            .accounts
            .resolve(account_ref)
            .map_err(|_| crate::chat_selection::capture::CaptureError::Closed)?;
        if open.context.host.account_id_hex != account.account_id_hex {
            return Err(crate::chat_selection::capture::CaptureError::Closed.into());
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = CancelOnDrop(cancelled.clone());
        let request = CaptureRequest {
            scope: open.scope,
            base: open.base,
            original_ids: None,
            action_hints: false,
            excluded_cost: (0, 0),
            host: open.context.host,
            overlays: open.context.overlays,
            revision: 0,
            capture_now_ms: open.context.capture_now_ms,
            cancelled: cancelled.clone(),
        };
        let prepared = tokio::select! {
            biased;
            _=wait_for_runtime_shutdown(&mut stopping)=>return Err(ChatListSelectionError::Closed),
            _=wait_for_account_reset(&mut resets,&account.label)=>return Err(ChatListSelectionError::Closed),
            capture=self.accounts.capture_selection_context(&account.label,request.clone())=>capture?,
        };
        let app = self.accounts.app.clone();
        let label = account.label.clone();
        let flag = cancelled.clone();
        let crate::client::BoundSelectionCapture {
            prepared,
            owner: storage,
            owner_epoch,
        } = prepared;
        let reader = blocking_app_task(move || {
            let reader = admit_owner_witness(
                app,
                label,
                account.account_id_hex,
                storage,
                &owner_epoch,
                &flag,
            )?;
            Ok((reader, owner_epoch))
        })
        .await
        .map_err(|_| crate::chat_selection::capture::CaptureError::Closed)?;
        let (reader, owner_epoch) = reader;
        let selected = if prepared.presentation.is_none() {
            Some(sorted_resolved_ids(&prepared)?)
        } else {
            None
        };
        let state = CompleteState {
            reader,
            owner_epoch,
            manager: self.accounts.clone(),
            request,
            prepared,
            selected,
            excluded: Vec::new(),
            last_mutation: None,
            mutation_uncertain: false,
            last_attempt: None,
            waiting_mutation: None,
            unresolved_request: None,
            operation_id: None,
            operation_mutation: None,
            proof: None,
            departure: None,
        };
        let owner_account_id = state.reader.account_id.clone();
        let (closed, closing) = watch::channel(false);
        let (commands, command_rx) = mpsc::channel(8);
        tokio::spawn(run_complete(
            state,
            command_rx,
            closing,
            stopping,
            resets,
            cancellation,
        ));
        Ok(RuntimeChatListSelection {
            commands,
            closed,
            cancelled,
            runtime_workers: Arc::downgrade(&self.accounts.workers),
            account_id: owner_account_id,
        })
    }
}
// A single native ID vector remains sorted for bounded visible membership.
// This order is an opaque paging order, not chat-list presentation order.
fn sorted_resolved_ids(prepared: &PreparedCapture) -> Result<Vec<String>, ChatListSelectionError> {
    let mut ids = prepared.resolved_ids()?;
    ids.sort_unstable();
    Ok(ids)
}
fn validate_visible_ids(ids: &[String]) -> Result<(), ChatListSelectionError> {
    if ids.len() > 200 {
        return Err(crate::chat_selection::presentation::PresentationError::InvalidSlots.into());
    }
    let mut budget = crate::chat_selection::presentation::CaptureBudget::default();
    for id in ids {
        budget.charge(id.len(), std::mem::size_of::<String>())?;
    }
    Ok(())
}

fn reserved_ids(capacity: usize) -> Result<Vec<String>, ChatListSelectionError> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(capacity)
        .map_err(|_| crate::chat_selection::presentation::PresentationError::ResourceExhausted)?;
    Ok(ids)
}
fn retained_ids_cost<'a>(
    ids: impl Iterator<Item = &'a String>,
) -> Result<(usize, usize), ChatListSelectionError> {
    let mut text = 0usize;
    let mut headers = 0usize;
    for id in ids {
        text = text
            .checked_add(id.len())
            .ok_or(crate::chat_selection::presentation::PresentationError::ResourceExhausted)?;
        headers = headers
            .checked_add(std::mem::size_of::<String>())
            .ok_or(crate::chat_selection::presentation::PresentationError::ResourceExhausted)?;
    }
    let mut budget = crate::chat_selection::presentation::CaptureBudget::default();
    budget.charge(text, headers)?;
    Ok((text, headers))
}

pub(super) fn admit_owner_witness(
    app: MarmotApp,
    label: String,
    account_id: String,
    storage: SqliteAccountStorage,
    owner_epoch: &[u8],
    cancelled: &AtomicBool,
) -> Result<Reader, AppError> {
    let reader = Reader {
        app,
        label,
        account_id,
        storage,
    };
    reader.check(cancelled)?;
    if reader
        .storage
        .app_storage()
        .chat_presentation_version()?
        .store_epoch
        != owner_epoch
    {
        return Err(AppError::RuntimeStopping);
    }
    reader.check(cancelled)?;
    Ok(reader)
}

impl CompleteState {
    async fn check(&self) -> Result<(), ChatListSelectionError> {
        let reader = self.reader.clone();
        let flag = self.request.cancelled.clone();
        let epoch = self.owner_epoch.clone();
        blocking_app_task(move || {
            reader.check(&flag)?;
            if reader
                .storage
                .app_storage()
                .chat_presentation_version()?
                .store_epoch
                != epoch
            {
                return Err(AppError::RuntimeStopping);
            }
            reader.check(&flag)
        })
        .await
        .map_err(|_| crate::chat_selection::capture::CaptureError::Closed)?;
        Ok(())
    }
    fn require_revision(&self, revision: u64) -> Result<(), ChatListSelectionError> {
        if revision != self.request.revision {
            return Err(ChatListSelectionError::StaleRevision);
        }
        Ok(())
    }
    fn status(&self) -> ChatSelectionStatus {
        let facts = self
            .selected
            .as_deref()
            .and_then(|ids| self.prepared.affordances(ids, self.proof.as_deref()));
        ChatSelectionStatus {
            revision: self.request.revision,
            count: self.selected.as_ref().map(Vec::len),
            all_archived: facts.map(|v| v.0),
            all_direct: facts.and_then(|v| v.1),
            all_abandonable: facts.and_then(|v| v.2),
            operation_id: self.operation_id,
            last_attempt: self.last_attempt,
            mutation_uncertain: self.mutation_uncertain,
            presentation_operands: self
                .prepared
                .presentation
                .as_ref()
                .map_or(0, |p| p.operand_count()),
        }
    }
    async fn read(&mut self, action: Action) -> Result<Response, ChatListSelectionError> {
        match action {
            Action::FolderAssignment {
                revision,
                context,
                after,
                limit,
            } => {
                self.require_revision(revision)?;
                if !(1..=200).contains(&limit) {
                    return Err(storage_sqlite::ChatListSelectionError::InvalidPage.into());
                }
                if self.mutation_uncertain
                    || self.waiting_mutation.is_some()
                    || self
                        .departure
                        .as_ref()
                        .is_some_and(|state| state.admitted && !state.finished)
                {
                    return Err(ChatListSelectionError::IncompletePresentation);
                }
                if context.host.account_id_hex != self.request.host.account_id_hex {
                    return Err(ChatListSelectionError::Closed);
                }
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or(ChatListSelectionError::IncompletePresentation)?;
                let mut original = Vec::new();
                original.try_reserve_exact(limit).map_err(|_| {
                    crate::chat_selection::presentation::PresentationError::ResourceExhausted
                })?;
                for id in selected
                    .iter()
                    .filter(|id| after.as_ref().is_none_or(|after| *id > after))
                    .take(limit)
                {
                    original.push(owned_text(id)?);
                }
                let next_after = original.last().map(|id| owned_text(id)).transpose()?;
                let done = next_after
                    .as_ref()
                    .is_none_or(|last| selected.last().is_none_or(|end| end <= last));
                let mut request = self.request.clone();
                request.original_ids = Some(original);
                let context_changed =
                    context.host != self.request.host || context.overlays != self.request.overlays;
                request.host = context.host;
                request.overlays = context.overlays;
                request.capture_now_ms = crate::notifications::unix_now_ms();
                let mut bound = self
                    .manager
                    .capture_selection_context(&self.reader.label, request.clone())
                    .await?;
                if !bound.owner.shares_connection_with(&self.reader.storage)
                    || bound.owner_epoch != self.owner_epoch
                {
                    return Err(ChatListSelectionError::Closed);
                }
                let reused = match bound.prepared.presentation.as_mut() {
                    None => true,
                    Some(pending) => match self.proof.as_ref().map(|proof| pending.reuse_proof(proof)) {
                        Some(Ok(())) => true,
                        Some(Err(crate::chat_selection::presentation::PresentationError::ResourceExhausted)) => return Err(crate::chat_selection::presentation::PresentationError::ResourceExhausted.into()),
                        _ => false,
                    }
                };
                if !reused || context_changed {
                    // Reissue one complete remaining-original capture; a stale
                    // page never turns into a successful prefix or broad scope.
                    let selected = self.selected.as_ref().expect("resolved folder assignment");
                    let mut all = Vec::new();
                    all.try_reserve_exact(selected.len()).map_err(|_| {
                        crate::chat_selection::presentation::PresentationError::ResourceExhausted
                    })?;
                    for id in selected {
                        all.push(owned_text(id)?);
                    }
                    request.original_ids = Some(all);
                    request.revision = revision
                        .checked_add(1)
                        .ok_or(ChatListSelectionError::StaleRevision)?;
                    let full = self
                        .manager
                        .capture_selection_context(&self.reader.label, request.clone())
                        .await?;
                    if !full.owner.shares_connection_with(&self.reader.storage)
                        || full.owner_epoch != self.owner_epoch
                    {
                        return Err(ChatListSelectionError::Closed);
                    }
                    let prepared = full.prepared;
                    let selected = if prepared.presentation.is_none() {
                        Some(sorted_resolved_ids(&prepared)?)
                    } else {
                        None
                    };
                    // Finish every fallible allocation before replacing any
                    // original owner/revision/proof state, as Refresh does.
                    self.request = request;
                    self.prepared = prepared;
                    self.selected = selected;
                    self.proof = None;
                    return Err(ChatListSelectionError::IncompletePresentation);
                }
                let mut ids = bound.prepared.resolved_ids()?;
                ids.sort_unstable();
                self.check().await?;
                return Ok(Response::FolderPage(ChatSelectionFolderPage {
                    revision,
                    group_ids: ids,
                    next_after,
                    done,
                }));
            }
            Action::Departure {
                operation_id,
                attempt_id,
                revision,
                group_id,
                context,
                step,
            } => {
                return self
                    .depart(operation_id, attempt_id, revision, group_id, context, step)
                    .await;
            }
            Action::LastDeparture => {
                return Ok(Response::LastDeparture(
                    self.departure
                        .as_ref()
                        .and_then(|state| state.report.clone()),
                ));
            }
            Action::Membership {
                revision,
                group_ids,
            } => {
                self.require_revision(revision)?;
                validate_visible_ids(&group_ids)?;
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or(ChatListSelectionError::IncompletePresentation)?;
                let mut membership = Vec::new();
                membership.try_reserve_exact(group_ids.len()).map_err(|_| {
                    crate::chat_selection::presentation::PresentationError::ResourceExhausted
                })?;
                membership.extend(
                    group_ids
                        .iter()
                        .map(|id| selected.binary_search(id).is_ok()),
                );
                return Ok(Response::Membership(membership));
            }
            Action::Exclude {
                revision,
                mut group_ids,
            } => {
                self.require_revision(revision)?;
                validate_visible_ids(&group_ids)?;
                if self.mutation_uncertain
                    || self.waiting_mutation.is_some()
                    || self
                        .departure
                        .as_ref()
                        .is_some_and(|state| state.admitted && !state.finished)
                {
                    return Err(ChatListSelectionError::IncompletePresentation);
                }
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or(ChatListSelectionError::IncompletePresentation)?;
                group_ids.sort_unstable();
                let removed = selected
                    .iter()
                    .filter(|id| group_ids.binary_search(id).is_ok())
                    .count();
                if removed == 0 {
                    return Ok(Response::Status(self.status()));
                }
                let next_revision = revision
                    .checked_add(1)
                    .ok_or(ChatListSelectionError::StaleRevision)?;
                let mut kept = reserved_ids(selected.len() - removed)?;
                let excluded_len = self.excluded.len().checked_add(removed).ok_or(
                    crate::chat_selection::presentation::PresentationError::ResourceExhausted,
                )?;
                let mut excluded = reserved_ids(excluded_len)?;
                // Validate bookkeeping before taking any owned strings/state.
                let cost = retained_ids_cost(
                    self.excluded.iter().chain(
                        selected
                            .iter()
                            .filter(|id| group_ids.binary_search(id).is_ok()),
                    ),
                )?;
                for id in self.selected.take().expect("resolved above") {
                    if group_ids.binary_search(&id).is_ok() {
                        excluded.push(id);
                    } else {
                        kept.push(id);
                    }
                }
                excluded.append(&mut self.excluded);
                excluded.sort_unstable();
                self.selected = Some(kept);
                self.excluded = excluded;
                self.request.excluded_cost = cost;
                self.request.revision = next_revision;
                return Ok(Response::Status(self.status()));
            }
            Action::Reselect {
                revision,
                context,
                mut group_ids,
            } => {
                self.require_revision(revision)?;
                validate_visible_ids(&group_ids)?;
                if self.operation_id.is_some()
                    || self.mutation_uncertain
                    || self.waiting_mutation.is_some()
                    || self
                        .departure
                        .as_ref()
                        .is_some_and(|state| state.admitted && !state.finished)
                {
                    return Err(ChatListSelectionError::IncompletePresentation);
                }
                if context.host.account_id_hex != self.request.host.account_id_hex {
                    return Err(ChatListSelectionError::Closed);
                }
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or(ChatListSelectionError::IncompletePresentation)?;
                group_ids.sort_unstable();
                group_ids.dedup();
                if group_ids.iter().any(|id| {
                    selected.binary_search(id).is_err() && self.excluded.binary_search(id).is_err()
                }) {
                    return Err(ChatListSelectionError::UnsupportedScope);
                }
                let restore_count = group_ids
                    .iter()
                    .filter(|id| self.excluded.binary_search(id).is_ok())
                    .count();
                if restore_count == 0 {
                    return Ok(Response::Status(self.status()));
                }
                let capacity = selected.len().checked_add(restore_count).ok_or(
                    crate::chat_selection::presentation::PresentationError::ResourceExhausted,
                )?;
                let mut originals = reserved_ids(capacity)?;
                for id in selected.iter().chain(
                    self.excluded
                        .iter()
                        .filter(|id| group_ids.binary_search(id).is_ok()),
                ) {
                    originals.push(owned_text(id)?);
                }
                originals.sort_unstable();
                let mut request = self.request.clone();
                request.revision = revision
                    .checked_add(1)
                    .ok_or(ChatListSelectionError::StaleRevision)?;
                request.original_ids = Some(originals);
                request.host = context.host;
                request.overlays = context.overlays;
                request.capture_now_ms = crate::notifications::unix_now_ms();
                let bound = self
                    .manager
                    .capture_selection_context(&self.reader.label, request.clone())
                    .await?;
                if !bound.owner.shares_connection_with(&self.reader.storage)
                    || bound.owner_epoch != self.owner_epoch
                {
                    return Err(crate::chat_selection::capture::CaptureError::Closed.into());
                }
                let prepared = bound.prepared;
                let selected = if prepared.presentation.is_none() {
                    Some(sorted_resolved_ids(&prepared)?)
                } else {
                    None
                };
                // Every fallible step is complete. Missing answers retain the
                // same presentation phase; Resolve removes actual restorations.
                let retained = || {
                    self.excluded.iter().filter(|id| {
                        selected
                            .as_ref()
                            .is_none_or(|ids| ids.binary_search(id).is_err())
                    })
                };
                let cost = retained_ids_cost(retained())?;
                let mut excluded = reserved_ids(retained().count())?;
                for id in self.excluded.drain(..) {
                    if selected
                        .as_ref()
                        .is_none_or(|ids| ids.binary_search(&id).is_err())
                    {
                        excluded.push(id);
                    }
                }
                self.excluded = excluded;
                request.excluded_cost = cost;
                self.request = request;
                self.prepared = prepared;
                self.selected = selected;
                self.proof = None;
                return Ok(Response::Status(self.status()));
            }
            Action::LastMutation => return Ok(Response::LastMutation(self.last_mutation.clone())),
            Action::Apply {
                operation_id,
                attempt_id,
                revision,
                context,
                mutation,
            } => {
                if self.departure.is_some() {
                    return Err(ChatListSelectionError::UnsupportedScope);
                }
                if self
                    .operation_id
                    .is_some_and(|previous| previous != operation_id)
                {
                    return Err(ChatListSelectionError::StaleRevision);
                }
                if self
                    .operation_mutation
                    .is_some_and(|previous| previous != mutation)
                {
                    return Err(ChatListSelectionError::StaleRevision);
                }
                if let Some(previous) = self.last_attempt {
                    if attempt_id < previous {
                        return Err(ChatListSelectionError::StaleRevision);
                    }
                    if attempt_id == previous {
                        if let Some(report) = self
                            .last_mutation
                            .as_ref()
                            .filter(|report| report.attempt_id == attempt_id)
                        {
                            return Ok(Response::Mutation(report.clone()));
                        }
                        if self.mutation_uncertain {
                            return Err(ChatListSelectionError::Closed);
                        }
                        if self.waiting_mutation != Some(mutation) {
                            return Err(ChatListSelectionError::StaleRevision);
                        }
                    } else if self.mutation_uncertain || self.waiting_mutation.is_some() {
                        return Err(ChatListSelectionError::IncompletePresentation);
                    }
                }
                self.require_revision(revision)?;
                if self.mutation_uncertain {
                    return Err(ChatListSelectionError::Closed);
                }
                if context.host.account_id_hex != self.request.host.account_id_hex {
                    return Err(ChatListSelectionError::Closed);
                }
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or(ChatListSelectionError::IncompletePresentation)?;
                let mut original_ids = Vec::new();
                original_ids
                    .try_reserve_exact(selected.len().min(200))
                    .map_err(|_| {
                        crate::chat_selection::presentation::PresentationError::ResourceExhausted
                    })?;
                for id in selected.iter().take(200) {
                    original_ids.push(owned_text(id)?);
                }
                let proof = self.proof.clone();
                let mut request = self.request.clone();
                request.revision = revision
                    .checked_add(1)
                    .ok_or(ChatListSelectionError::StaleRevision)?;
                request.original_ids = Some(original_ids);
                request.host = context.host;
                request.overlays = context.overlays;
                request.capture_now_ms = crate::notifications::unix_now_ms();
                self.operation_id = Some(operation_id);
                self.operation_mutation = Some(mutation);
                self.last_attempt = Some(attempt_id);
                self.waiting_mutation = Some(mutation);
                self.last_mutation = None;
                // A dropped/closed worker response is unresolved, not evidence
                // that no mutation happened. Refresh never clears this flag.
                self.mutation_uncertain = true;
                let result = self
                    .manager
                    .apply_selection_context(
                        &self.reader.label,
                        request.clone(),
                        proof,
                        self.reader.storage.clone(),
                        self.owner_epoch.clone(),
                        mutation,
                        attempt_id,
                        operation_id,
                    )
                    .await;
                let result = match result {
                    Ok(value) => value,
                    Err(error) => {
                        if error != crate::chat_selection::capture::CaptureError::Closed {
                            // Source-owned non-closed errors are returned only
                            // before the first mutation's preallocated loop.
                            self.mutation_uncertain = false;
                        } else {
                            self.unresolved_request = Some(request);
                        }
                        return Err(error.into());
                    }
                };
                match result {
                    crate::client::SelectionApplyOutcome::NeedsPresentation(bound) => {
                        // The worker proved that no mutation was attempted. A
                        // failed follow-up capture cannot make that effect unknown.
                        self.mutation_uncertain = false;
                        if !bound.owner.shares_connection_with(&self.reader.storage)
                            || bound.owner_epoch != self.owner_epoch
                        {
                            return Err(ChatListSelectionError::Closed);
                        }
                        let mut all = Vec::new();
                        let selected = self.selected.as_ref().expect("resolved before action");
                        all.try_reserve_exact(selected.len()).map_err(|_|crate::chat_selection::presentation::PresentationError::ResourceExhausted)?;
                        for id in selected {
                            all.push(owned_text(id)?);
                        }
                        request.original_ids = Some(all);
                        request.capture_now_ms = crate::notifications::unix_now_ms();
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
                        return Err(ChatListSelectionError::IncompletePresentation);
                    }
                    crate::client::SelectionApplyOutcome::Applied {
                        mut report,
                        mut eligible_ids,
                        prepared,
                        ..
                    } => {
                        report.applied_group_ids.sort_unstable();
                        eligible_ids.sort_unstable();
                        let mut prefix = request
                            .original_ids
                            .take()
                            .expect("native bounded action original IDs");
                        prefix.sort_unstable();
                        let selected = self.selected.as_mut().expect("resolved before action");
                        selected.retain(|id| {
                            prefix.binary_search(id).is_err()
                                || (eligible_ids.binary_search(id).is_ok()
                                    && report.applied_group_ids.binary_search(id).is_err())
                        });
                        report.remaining = selected.len();
                        self.request = request;
                        // The old immutable proof still covers the other
                        // original candidates; the fresh small capture is only
                        // this batch's admission evidence, never a new scope.
                        drop(prepared);
                        self.mutation_uncertain = report.uncertain;
                        self.waiting_mutation = None;
                        self.last_mutation = Some(report.clone());
                        return Ok(Response::Mutation(report));
                    }
                }
            }
            Action::Status => return Ok(Response::Status(self.status())),
            Action::Count => {}
            Action::Revalidate { .. } => return Err(ChatListSelectionError::UnsupportedScope),
            Action::Page {
                revision,
                offset,
                limit,
            } => {
                self.require_revision(revision)?;
                let ids = self
                    .selected
                    .as_ref()
                    .ok_or(ChatListSelectionError::IncompletePresentation)?;
                if limit == 0 || limit > 200 || offset > ids.len() {
                    return Err(
                        crate::chat_selection::presentation::PresentationError::InvalidSlots.into(),
                    );
                }
                let slice = &ids[offset..offset.saturating_add(limit).min(ids.len())];
                let mut group_ids = Vec::new();
                group_ids.try_reserve_exact(slice.len()).map_err(|_| {
                    crate::chat_selection::presentation::PresentationError::ResourceExhausted
                })?;
                for id in slice {
                    group_ids.push(owned_text(id)?);
                }
                return Ok(Response::Page(ChatListSelectionPage {
                    revision,
                    group_ids,
                }));
            }
            Action::Presentation {
                revision,
                offset,
                limit,
            } => {
                self.require_revision(revision)?;
                let pending = self
                    .prepared
                    .presentation
                    .as_ref()
                    .ok_or(ChatListSelectionError::UnsupportedScope)?;
                let page = pending.page(offset, limit)?;
                let mut operands = Vec::new();
                operands.try_reserve_exact(page.len()).map_err(|_| {
                    crate::chat_selection::presentation::PresentationError::ResourceExhausted
                })?;
                for operand in page {
                    operands.push(operand.try_owned_copy()?);
                }
                return Ok(Response::Operands(operands));
            }
            Action::Answer {
                revision,
                host,
                answers,
            } => {
                self.require_revision(revision)?;
                if self.selected.is_some() {
                    return Err(ChatListSelectionError::StaleRevision);
                }
                self.prepared.submit(revision, &host, &answers)?;
                return Ok(Response::Status(self.status()));
            }
            Action::Resolve { revision } => {
                self.require_revision(revision)?;
                if self.selected.is_none() {
                    let selected = sorted_resolved_ids(&self.prepared)?;
                    let cost = retained_ids_cost(
                        self.excluded
                            .iter()
                            .filter(|id| selected.binary_search(id).is_err()),
                    )?;
                    let mut excluded = reserved_ids(
                        self.excluded
                            .iter()
                            .filter(|id| selected.binary_search(id).is_err())
                            .count(),
                    )?;
                    let proof = self.prepared.take_proof()?;
                    // Only a reselect capture can contain explicit tombstones.
                    for id in self.excluded.drain(..) {
                        if selected.binary_search(&id).is_err() {
                            excluded.push(id);
                        }
                    }
                    self.excluded = excluded;
                    self.request.excluded_cost = cost;
                    self.selected = Some(selected);
                    self.proof = proof;
                }
            }
            Action::Refresh {
                revision,
                context,
                action_hints,
            } => {
                self.require_revision(revision)?;
                if self
                    .departure
                    .as_ref()
                    .is_some_and(|state| state.admitted && !state.finished)
                {
                    return Err(ChatListSelectionError::IncompletePresentation);
                }
                if context.host.account_id_hex != self.request.host.account_id_hex {
                    return Err(crate::chat_selection::capture::CaptureError::Closed.into());
                }
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or(ChatListSelectionError::IncompletePresentation)?;
                let mut original_ids = Vec::new();
                original_ids
                    .try_reserve_exact(selected.len())
                    .map_err(|_| {
                        crate::chat_selection::presentation::PresentationError::ResourceExhausted
                    })?;
                for id in selected {
                    original_ids.push(owned_text(id)?);
                }
                let mut request = self.request.clone();
                request.revision = revision
                    .checked_add(1)
                    .ok_or(ChatListSelectionError::StaleRevision)?;
                request.original_ids = Some(original_ids);
                request.action_hints |= action_hints;
                request.host = context.host;
                request.overlays = context.overlays;
                request.capture_now_ms = crate::notifications::unix_now_ms();
                let bound = self
                    .manager
                    .capture_selection_context(&self.reader.label, request.clone())
                    .await?;
                if !bound.owner.shares_connection_with(&self.reader.storage)
                    || bound.owner_epoch != self.owner_epoch
                {
                    return Err(crate::chat_selection::capture::CaptureError::Closed.into());
                }
                let prepared = bound.prepared;
                let selected = if prepared.presentation.is_none() {
                    Some(sorted_resolved_ids(&prepared)?)
                } else {
                    None
                };
                // Commit only a complete successful capture; failure leaves the
                // previous revision intact and never publishes a prefix.
                self.request = request;
                self.prepared = prepared;
                self.selected = selected;
                self.proof = None;
                return Ok(Response::Status(self.status()));
            }
        }
        let ids = self
            .selected
            .as_ref()
            .ok_or(ChatListSelectionError::IncompletePresentation)?;
        Ok(Response::Summary(ChatListSelectionSummary {
            revision: self.request.revision,
            count: ids.len(),
        }))
    }
}
async fn run_complete(
    mut state: CompleteState,
    mut commands: mpsc::Receiver<Command>,
    mut closing: watch::Receiver<bool>,
    mut stopping: watch::Receiver<bool>,
    mut resets: broadcast::Receiver<String>,
    cancellation: CancelOnDrop,
) {
    let label = state.reader.label.clone();
    loop {
        let command = tokio::select! { biased;
            _=wait_for_runtime_shutdown(&mut stopping)=>return,
            _=wait_for_account_reset(&mut resets,&label)=>return,
            _=wait_for_close(&mut closing)=>return,
            command=commands.recv()=>match command { Some(value)=>value,None=>return },
        };
        let read = async {
            state.check().await?;
            let result = state.read(command.action).await;
            state.check().await?;
            Ok::<_, ChatListSelectionError>(result)
        };
        let result = tokio::select! { biased;
            _=wait_for_runtime_shutdown(&mut stopping)=>return,
            _=wait_for_account_reset(&mut resets,&label)=>return,
            _=wait_for_close(&mut closing)=>return,
            result=read=>result,
        };
        match result {
            Ok(result) => {
                let _ = command.reply.send(result);
            }
            Err(error) => {
                let _ = command.reply.send(Err(error));
                return;
            }
        }
        if cancellation.0.load(Ordering::Acquire) {
            return;
        }
    }
}
