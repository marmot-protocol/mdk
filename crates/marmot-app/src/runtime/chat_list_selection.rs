//! Compact native-owned selection. Fixed views and closed complete scopes share
//! one command owner; complete actions use fresh worker admission.
use super::{MarmotAppRuntime, blocking_app_task, wait_for_runtime_shutdown};
use crate::{AppError, MarmotApp};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use storage_sqlite::{ChatListSelectionSnapshot, ChatListView, SqliteAccountStorage};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

pub use crate::chat_selection::capture::CaptureError as ChatSelectionCaptureError;
pub use crate::chat_selection::presentation::PresentationError as ChatSelectionPresentationError;
pub use storage_sqlite::{
    ChatListSelectionError as ChatSelectionQueryError, SelectionBaseScope as ChatSelectionBaseScope,
};
mod complete;
pub use crate::chat_selection::capture::{
    HostOverlays as ChatSelectionHostOverlays, OptimisticSending as ChatSelectionSending,
    SelectionMutation as ChatSelectionMutation,
    SelectionMutationReport as ChatSelectionMutationReport,
};
pub use crate::chat_selection::presentation::{
    HostContextIdentity as ChatSelectionHostContext, PresentationAnswer as ChatSelectionAnswer,
    PresentationLeaf as ChatSelectionLeaf, PresentationLeafKind as ChatSelectionLeafKind,
    PresentationOperand as ChatSelectionOperand, SearchMessage as ChatSelectionSearchMessage,
    SearchPresentation as ChatSelectionSearchPresentation,
    SearchPreviewMessage as ChatSelectionSearchPreviewMessage,
    SearchScope as ChatSelectionSearchScope,
};
pub use crate::chat_selection::scope::{
    AutomaticRule as ChatSelectionAutomaticRule, FolderScope as ChatSelectionFolder,
    LegacyRule as ChatSelectionLegacyRule, ScopeRequest as ChatSelectionScope,
};
pub use crate::smart_folder::{
    SmartFolderField as ChatSelectionField, SmartFolderMode as ChatSelectionMode,
    SmartFolderPredicate as ChatSelectionPredicate,
};
pub use complete::{
    ChatSelectionContext, ChatSelectionDepartureReport, ChatSelectionDepartureStep,
    ChatSelectionOpen, ChatSelectionStatus,
};

#[derive(Debug, thiserror::Error)]
pub enum ChatListSelectionError {
    #[error("chat selection is closed")]
    Closed,
    #[error("chat selection changed; use its current revision")]
    StaleRevision,
    #[error("selection requires current host presentation answers")]
    IncompletePresentation,
    #[error("operation is unsupported for this selection mode")]
    UnsupportedScope,
    #[error(transparent)]
    Capture(#[from] crate::chat_selection::capture::CaptureError),
    #[error(transparent)]
    Presentation(#[from] crate::chat_selection::presentation::PresentationError),
    #[error(transparent)]
    Query(#[from] storage_sqlite::ChatListSelectionError),
    #[error(transparent)]
    App(#[from] AppError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatListSelectionSummary {
    pub revision: u64,
    pub count: usize,
}

/// One page of the frozen set; each response has at most 200 IDs. Neither the
/// revision nor offset is a cursor into the moving display window.
#[derive(PartialEq, Eq)]
pub struct ChatListSelectionPage {
    pub revision: u64,
    pub group_ids: Vec<String>,
}
impl std::fmt::Debug for ChatListSelectionPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListSelectionPage")
            .field("revision", &self.revision)
            .field("count", &self.group_ids.len())
            .finish()
    }
}

/// Fresh original-ID page. Progress follows inspected originals, including
/// candidates that became ineligible; an empty result is not end-of-selection.
/// Collect under one original handle/revision and unchanged host context. If a
/// call requires new presentation/revision, discard every prepared old page;
/// never publish a prefix or concatenate pages across revisions.
pub struct ChatSelectionFolderPage {
    pub revision: u64,
    pub group_ids: Vec<String>,
    pub next_after: Option<String>,
    pub done: bool,
}
impl std::fmt::Debug for ChatSelectionFolderPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSelectionFolderPage")
            .field("count", &self.group_ids.len())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

/// Dropping the owner closes it. Cancellation is terminal and does not imply
/// interruption of an already running SQLite step; its result is discarded.
/// Frozen IDs alone never authorize a mutation; complete actions re-admit
/// required current inputs in the account worker.
pub struct RuntimeChatListSelection {
    commands: mpsc::Sender<Command>,
    closed: watch::Sender<bool>,
    cancelled: Arc<AtomicBool>,
    runtime_workers: std::sync::Weak<
        tokio::sync::Mutex<std::collections::HashMap<String, super::ManagedAccountWorker>>,
    >,
    account_id: String,
}
impl RuntimeChatListSelection {
    /// Reject a handle from another runtime/account before global binding
    /// wrappers perform current role checks. This is existing worker-owner
    /// identity, not a new registry or a substitute for per-step native fences.
    pub fn check_runtime_account(
        &self,
        runtime: &MarmotAppRuntime,
        account_ref: &str,
    ) -> Result<(), ChatListSelectionError> {
        if self.cancelled.load(Ordering::Acquire)
            || !self
                .runtime_workers
                .ptr_eq(&Arc::downgrade(&runtime.accounts.workers))
        {
            return Err(ChatListSelectionError::Closed);
        }
        runtime.shared.lifecycle().ensure_running()?;
        if runtime.accounts.resolve(account_ref)?.account_id_hex != self.account_id {
            return Err(ChatListSelectionError::Closed);
        }
        Ok(())
    }
    pub async fn count(&self) -> Result<ChatListSelectionSummary, ChatListSelectionError> {
        match self.send(Action::Count).await? {
            Response::Summary(summary) => Ok(summary),
            _ => unreachable!("count response"),
        }
    }
    pub async fn page(
        &self,
        revision: u64,
        offset: usize,
        limit: usize,
    ) -> Result<ChatListSelectionPage, ChatListSelectionError> {
        match self
            .send(Action::Page {
                revision,
                offset,
                limit,
            })
            .await?
        {
            Response::Page(page) => Ok(page),
            _ => unreachable!("page response"),
        }
    }
    /// Intersect with current native eligibility, never adding new arrivals.
    /// The returned revision invalidates all earlier page requests.
    pub async fn revalidate(
        &self,
        revision: u64,
    ) -> Result<ChatListSelectionSummary, ChatListSelectionError> {
        match self.send(Action::Revalidate { revision }).await? {
            Response::Summary(summary) => Ok(summary),
            _ => unreachable!("revalidation response"),
        }
    }
    pub fn close(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.closed.send_replace(true);
    }
    pub fn cancel(&self) {
        self.close();
    }
    async fn send(&self, action: Action) -> Result<Response, ChatListSelectionError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ChatListSelectionError::Closed);
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command { action, reply })
            .await
            .map_err(|_| ChatListSelectionError::Closed)?;
        let response = result.await.map_err(|_| ChatListSelectionError::Closed)?;
        // A close racing with a completed read must not publish that read.
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ChatListSelectionError::Closed);
        }
        response
    }
}
impl Drop for RuntimeChatListSelection {
    fn drop(&mut self) {
        self.close();
    }
}

enum Action {
    FolderAssignment {
        revision: u64,
        context: ChatSelectionContext,
        after: Option<String>,
        limit: usize,
    },
    Departure {
        operation_id: u64,
        attempt_id: u64,
        revision: u64,
        group_id: String,
        context: ChatSelectionContext,
        step: ChatSelectionDepartureStep,
    },
    LastDeparture,
    Membership {
        revision: u64,
        group_ids: Vec<String>,
    },
    Reselect {
        revision: u64,
        context: ChatSelectionContext,
        group_ids: Vec<String>,
    },
    Exclude {
        revision: u64,
        group_ids: Vec<String>,
    },
    Apply {
        operation_id: u64,
        attempt_id: u64,
        revision: u64,
        context: ChatSelectionContext,
        mutation: ChatSelectionMutation,
    },
    LastMutation,
    Status,
    Presentation {
        revision: u64,
        offset: usize,
        limit: usize,
    },
    Answer {
        revision: u64,
        host: ChatSelectionHostContext,
        answers: Vec<ChatSelectionAnswer>,
    },
    Resolve {
        revision: u64,
    },
    Refresh {
        revision: u64,
        context: ChatSelectionContext,
        action_hints: bool,
    },
    Count,
    Page {
        revision: u64,
        offset: usize,
        limit: usize,
    },
    Revalidate {
        revision: u64,
    },
}
enum Response {
    FolderPage(ChatSelectionFolderPage),
    Departure(ChatSelectionDepartureReport),
    LastDeparture(Option<ChatSelectionDepartureReport>),
    Membership(Vec<bool>),
    Mutation(ChatSelectionMutationReport),
    LastMutation(Option<ChatSelectionMutationReport>),
    Status(ChatSelectionStatus),
    Operands(Vec<ChatSelectionOperand>),
    Summary(ChatListSelectionSummary),
    Page(ChatListSelectionPage),
}
struct Command {
    action: Action,
    reply: oneshot::Sender<Result<Response, ChatListSelectionError>>,
}
#[derive(Clone)]
struct Reader {
    app: MarmotApp,
    label: String,
    account_id: String,
    storage: SqliteAccountStorage,
}
struct State {
    reader: Reader,
    snapshot: ChatListSelectionSnapshot,
    revision: u64,
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Reader {
    fn check(&self, cancelled: &AtomicBool) -> Result<(), AppError> {
        if cancelled.load(Ordering::Acquire)
            || !self
                .app
                .account_storage_is_current(&self.label, &self.storage)
        {
            return Err(AppError::RuntimeStopping);
        }
        let account = self.app.account_home().account(&self.label)?;
        if account.account_id_hex != self.account_id {
            return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
        }
        Ok(())
    }
}
impl MarmotAppRuntime {
    /// Complete fixed native view only. Fails explicitly while base-row
    /// maintenance is incomplete; never hydrates profiles, history or rows.
    pub async fn open_chat_list_selection(
        &self,
        account_ref: &str,
        view: ChatListView,
    ) -> Result<RuntimeChatListSelection, ChatListSelectionError> {
        self.shared.lifecycle().ensure_running()?;
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let mut resets = self
            .accounts
            .app
            .presentation_signals
            .account_resets
            .subscribe();
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        let label = account.label;
        let reset_label = label.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = CancelOnDrop(cancelled.clone());
        let flag = cancelled.clone();
        let state = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return Err(ChatListSelectionError::Closed),
            _ = wait_for_account_reset(&mut resets, &reset_label) => return Err(ChatListSelectionError::Closed),
            state = blocking_app_task(move || {
                let storage = app.account_storage(&label)?;
                let reader = Reader { app, label, account_id: account.account_id_hex, storage };
                reader.check(&flag)?;
                let snapshot = reader.storage.app_storage().chat_list_selection_snapshot_cancellable(view, &|| flag.load(Ordering::Acquire));
                reader.check(&flag)?;
                Ok(snapshot.map(|snapshot| State { reader, snapshot, revision: 0 }))
            }) => state??,
        };
        let owner_account_id = state.reader.account_id.clone();
        let (closed, closing) = watch::channel(false);
        let (commands, command_rx) = mpsc::channel(8);
        tokio::spawn(run(
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

async fn run(
    mut state: State,
    mut commands: mpsc::Receiver<Command>,
    mut closing: watch::Receiver<bool>,
    mut stopping: watch::Receiver<bool>,
    mut resets: broadcast::Receiver<String>,
    cancellation: CancelOnDrop,
) {
    let label = state.reader.label.clone();
    loop {
        let command = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = wait_for_account_reset(&mut resets, &label) => return,
            _ = wait_for_close(&mut closing) => return,
            command = commands.recv() => match command { Some(command) => command, None => return },
        };
        let flag = cancellation.0.clone();
        let read = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = wait_for_account_reset(&mut resets, &label) => return,
            _ = wait_for_close(&mut closing) => return,
            read = blocking_app_task(move || {
                state.reader.check(&flag)?;
                let result = state.read(command.action, &flag);
                state.reader.check(&flag)?;
                Ok((state, result))
            }) => read,
        };
        match read {
            Ok((next, result)) => {
                state = next;
                let _ = command.reply.send(result);
            }
            Err(error) => {
                let _ = command.reply.send(Err(error.into()));
                return;
            }
        }
    }
}
impl State {
    fn read(
        &mut self,
        action: Action,
        cancelled: &AtomicBool,
    ) -> Result<Response, ChatListSelectionError> {
        let storage = self.reader.storage.app_storage();
        match action {
            Action::Status => {
                return Ok(Response::Status(ChatSelectionStatus {
                    revision: self.revision,
                    count: Some(storage.chat_list_selection_count(&self.snapshot)?),
                    all_archived: None,
                    all_direct: None,
                    all_abandonable: None,
                    presentation_operands: 0,
                    operation_id: None,
                    last_attempt: None,
                    mutation_uncertain: false,
                }));
            }
            Action::FolderAssignment { .. }
            | Action::Departure { .. }
            | Action::LastDeparture
            | Action::Membership { .. }
            | Action::Exclude { .. }
            | Action::Reselect { .. }
            | Action::Apply { .. }
            | Action::LastMutation
            | Action::Presentation { .. }
            | Action::Answer { .. }
            | Action::Resolve { .. }
            | Action::Refresh { .. } => return Err(ChatListSelectionError::UnsupportedScope),
            Action::Count => {}
            Action::Page {
                revision,
                offset,
                limit,
            } => {
                if revision != self.revision {
                    return Err(ChatListSelectionError::StaleRevision);
                }
                let group_ids = storage.chat_list_selection_page(&self.snapshot, offset, limit)?;
                return Ok(Response::Page(ChatListSelectionPage {
                    revision,
                    group_ids,
                }));
            }
            Action::Revalidate { revision } => {
                if revision != self.revision {
                    return Err(ChatListSelectionError::StaleRevision);
                }
                let next_revision = self
                    .revision
                    .checked_add(1)
                    .ok_or(ChatListSelectionError::StaleRevision)?;
                self.snapshot = storage
                    .revalidate_chat_list_selection_cancellable(&self.snapshot, &|| {
                        cancelled.load(Ordering::Acquire)
                    })?;
                self.revision = next_revision;
            }
        }
        Ok(Response::Summary(ChatListSelectionSummary {
            revision: self.revision,
            count: storage.chat_list_selection_count(&self.snapshot)?,
        }))
    }
}
/// Borrow the actual ready worker client while yielding its runtime thread.
/// Never run this new operation inline on a current-thread/unknown runtime.
pub(super) fn capture_selection_ready(
    client: &crate::client::AppClient,
    request: crate::chat_selection::capture::CaptureRequest,
    abandoned: &impl Fn() -> bool,
) -> Result<crate::client::BoundSelectionCapture, crate::chat_selection::capture::CaptureError> {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
            tokio::task::block_in_place(|| client.capture_complete_selection(request, abandoned))
        }
        _ => Err(crate::chat_selection::capture::CaptureError::UnsupportedRuntime),
    }
}

async fn wait_for_close(closing: &mut watch::Receiver<bool>) {
    loop {
        if *closing.borrow_and_update() || closing.changed().await.is_err() {
            return;
        }
    }
}
async fn wait_for_account_reset(resets: &mut broadcast::Receiver<String>, label: &str) {
    loop {
        match resets.recv().await {
            Ok(reset) if reset != label => {}
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests;
