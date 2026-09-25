//! Local-first bounded windows with optional coherent live-authority capture.
//! Account-owned fields share a read boundary; directory enrichment is separate.
use super::account_worker::AccountWorkerCommand;
use super::event_routing::{chat_list_event_route, projection_update_from_event};
use super::{AccountManager, MarmotAppRuntime, blocking_app_task, wait_for_runtime_shutdown};
use crate::app_telemetry::runtime::{Observation, Outcome as TelemetryOutcome};
use crate::chat_presentation::signals::PresentationInvalidation;
use crate::conversation_presentation::{
    ConversationAuthority, ConversationHeaderState, ConversationPresentationError,
    ConversationWindowPresentation,
};
use crate::drafts::MessageDraftInvalidation;
use crate::{AppClient, AppError, MarmotApp, MarmotAppEvent, SelectedMessageDraft};
use crate::{AppPerformanceTelemetry, RuntimePerformanceOperation as RuntimeOp};
use cgka_engine::group_authority::GroupAuthoritySnapshot;
use cgka_traits::{GroupId, StorageError};
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use storage_sqlite::{ConversationAccountSnapshot, ConversationOpenError, ConversationWindowQuery};
pub use storage_sqlite::{
    ConversationAnchor, ConversationOpenAnchorOutcome, ConversationOpenQuery,
    ConversationOpenReadState, ConversationOpenTarget,
};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

const RETRY_DELAY: Duration = Duration::from_secs(1);
// Before first authority, a busy worker may enrich the local window later.
// Bound that display wait, not the lifetime of an established window command.
const AUTHORITY_WAIT: Duration = Duration::from_millis(50);
const DRAIN_LIMIT: usize = 1024;
pub const CONVERSATION_WINDOW_MAX_ROWS: usize = 200;

#[derive(Clone, Debug, thiserror::Error)]
pub enum ConversationWindowError {
    #[error("conversation requests must contain 1 to 200 rows")]
    InvalidLimit,
    #[error("conversation window changed; use its current revision")]
    StaleWindow,
    #[error("visible anchor must belong to the retained window")]
    AnchorOutsideWindow,
    #[error("live account capture is temporarily unavailable; retry pending")]
    NotReady,
    #[error("conversation window is closed")]
    Closed,
    #[error(transparent)]
    Query(Arc<ConversationOpenError>),
    #[error(transparent)]
    Presentation(Arc<ConversationPresentationError>),
    #[error(transparent)]
    App(Arc<AppError>),
}
impl From<AppError> for ConversationWindowError {
    fn from(error: AppError) -> Self {
        Self::App(Arc::new(error))
    }
}
impl From<StorageError> for ConversationWindowError {
    fn from(error: StorageError) -> Self {
        AppError::from(error).into()
    }
}
impl From<cgka_session::SessionError> for ConversationWindowError {
    fn from(error: cgka_session::SessionError) -> Self {
        match error {
            cgka_session::SessionError::Storage(error)
            | cgka_session::SessionError::Engine(cgka_traits::EngineError::Storage(error)) => {
                error.into()
            }
            error => AppError::from(error).into(),
        }
    }
}
impl From<ConversationOpenError> for ConversationWindowError {
    fn from(error: ConversationOpenError) -> Self {
        match error {
            ConversationOpenError::ReadStateNotReady => Self::NotReady,
            ConversationOpenError::Storage(error) => error.into(),
            error => Self::Query(Arc::new(error)),
        }
    }
}
impl From<ConversationPresentationError> for ConversationWindowError {
    fn from(error: ConversationPresentationError) -> Self {
        match error {
            ConversationPresentationError::StoreMismatch => Self::Closed,
            ConversationPresentationError::App(error) => error.into(),
            error => Self::Presentation(Arc::new(error)),
        }
    }
}
impl ConversationWindowError {
    fn terminal(&self) -> bool {
        matches!(self, Self::Closed | Self::Presentation(_))
            || matches!(self, Self::Query(error) if !matches!(error.as_ref(), ConversationOpenError::MessageNotFound))
            || matches!(self, Self::App(e) if matches!(e.as_ref(),
                AppError::RuntimeStopping | AppError::TransportClosed | AppError::BlockingTask(_) | AppError::UnknownGroup(_) |
                AppError::Session(cgka_session::SessionError::Engine(cgka_traits::EngineError::UnknownGroup(_))) |
                AppError::AccountHome(marmot_account::AccountHomeError::AccountIdMismatch |
                    marmot_account::AccountHomeError::UnknownAccount(_)) |
                AppError::Storage(StorageError::Closed(_) | StorageError::NotFound)))
    }
}

/// Opaque handle incarnation plus monotonic sequence. Cannot be used after reopening.
#[derive(Clone, PartialEq, Eq)]
pub struct ConversationWindowRevision {
    pub generation: String,
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationPageDirection {
    Older,
    Newer,
}

/// Complete replacement, with one identity sidecar for the retained timeline.
/// Attachment bytes are loaded separately through revision-checked/local media APIs.
#[derive(Clone)]
pub struct ConversationWindowSnapshot {
    pub revision: ConversationWindowRevision,
    pub page: storage_sqlite::ConversationPresentationPage,
    pub presentation: ConversationWindowPresentation,
    /// Raw retained read intent/counters, including pending invitations. Use
    /// header participation for effective display policy; this is not an account badge.
    pub read_state: ConversationOpenReadState,
    pub draft: SelectedMessageDraft,
    pub pending_confirmation: bool,
    pub anchor: ConversationOpenAnchorOutcome,
    /// One canonical token per row, in timeline order. These are local, store-scoped tokens.
    pub anchors: Vec<ConversationAnchor>,
}
impl std::fmt::Debug for ConversationWindowSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationWindowSnapshot")
            .field("sequence", &self.revision.sequence)
            .field("rows", &self.anchors.len())
            .field("anchor", &self.anchor)
            .finish_non_exhaustive()
    }
}
impl ConversationWindowSnapshot {
    fn same_content(&self, other: &Self) -> bool {
        self.page.page() == other.page.page()
            && (0..self.anchors.len()).all(|index| {
                self.page.authenticated_system_content(index).is_some()
                    == other.page.authenticated_system_content(index).is_some()
            })
            && self.presentation == other.presentation
            && self.read_state == other.read_state
            && self.draft.revision == other.draft.revision
            && self.draft.draft == other.draft.draft
            && self.pending_confirmation == other.pending_confirmation
            && self.anchor == other.anchor
            && self.anchors == other.anchors
    }
}

#[derive(Clone)]
pub(crate) struct CapturedConversation {
    account: ConversationAccountSnapshot,
    authority: Option<GroupAuthoritySnapshot>,
}

// A worker-owned send can yield a coherent read before awaiting transport. Each
// open window retains its current-query capture and, while browsing history,
// one exact-query tail capture for a direct return-to-latest. Intermediate
// navigation or a normal worker read invalidates that speculative tail capture.
// The worker holds weak references so closing a window releases its rows.
pub(crate) struct SendCapture {
    group: GroupId,
    epoch: Vec<u8>,
    state: Mutex<SendCaptureState>,
    changed: watch::Sender<()>,
}
struct SendCaptureState {
    query: ConversationWindowQuery,
    generation: u64,
    pending: Option<CapturedConversation>,
    latest: Option<(ConversationWindowQuery, CapturedConversation)>,
}
impl SendCapture {
    fn new(group: GroupId, epoch: Vec<u8>, query: ConversationWindowQuery) -> Self {
        Self {
            group,
            epoch,
            state: Mutex::new(SendCaptureState {
                query,
                generation: 0,
                pending: None,
                latest: None,
            }),
            changed: watch::channel(()).0,
        }
    }
    fn set_query(&self, query: &ConversationWindowQuery) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.query != *query {
            state.query = query.clone();
            state.generation += 1;
            state.pending = state.latest.take().and_then(|(captured_query, capture)| {
                (captured_query == *query).then_some(capture)
            });
        }
    }
    // Keep the source checkpoint until presentation completes. Cancellation
    // drops only this bounded descriptor/row copy, so navigation can retry it.
    fn checkpoint(&self) -> Option<(CapturedConversation, u64)> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .pending
            .clone()
            .map(|capture| (capture, state.generation))
    }
    fn acknowledge(&self, generation: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.generation == generation {
            state.pending = None;
        }
    }
    #[cfg(test)]
    fn take(&self) -> Option<CapturedConversation> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .take()
    }
}
impl AppClient {
    pub(crate) fn register_conversation_capture(&mut self, observer: Option<Weak<SendCapture>>) {
        self.conversation_captures
            .retain(|capture| capture.strong_count() > 0);
        if let Some(observer) = observer
            && let Some(capture) = observer.upgrade()
        {
            // A normal worker read supersedes earlier send checkpoints.
            {
                let mut state = capture.state.lock().unwrap_or_else(|e| e.into_inner());
                state.generation += 1;
                state.pending = None;
                state.latest = None;
            }
            if !self
                .conversation_captures
                .iter()
                .any(|old| old.ptr_eq(&observer))
            {
                self.conversation_captures.push(observer);
            }
        }
    }
    pub(crate) fn publish_conversation_captures(&mut self, group: &GroupId) {
        self.conversation_captures
            .retain(|capture| capture.strong_count() > 0);
        let observers: Vec<_> = self
            .conversation_captures
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|observer| observer.group == *group)
            .collect();
        for observer in observers {
            let (query, generation) = {
                let state = observer.state.lock().unwrap_or_else(|e| e.into_inner());
                (state.query.clone(), state.generation)
            };
            // Use the same live engine/account read boundary as a normal window
            // capture. Never combine frozen permissions with newer account rows.
            // Best effort: the normal read path still owns capture errors.
            let latest_query = ConversationWindowQuery {
                opening: ConversationOpenQuery {
                    target: ConversationOpenTarget::Latest,
                    limit: query.opening.limit,
                },
                before_anchor: None,
            };
            // A history observer costs one extra coherent authority/account
            // capture per send, even if the user never returns to the tail.
            // Bound that speculative work to one same-limit tail viewport;
            // latest observers still require only their current-query capture.
            let latest = if latest_query != query {
                capture_conversation(self, &observer.group, latest_query.clone(), &observer.epoch)
                    .ok()
                    .map(|capture| (latest_query, capture))
            } else {
                None
            };
            if let Ok(captured) =
                capture_conversation(self, &observer.group, query, &observer.epoch)
            {
                let mut state = observer.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.generation == generation {
                    state.generation += 1;
                    state.pending = Some(captured);
                    state.latest = latest;
                    observer.changed.send_replace(());
                }
            }
        }
    }
}
/// Only called with the live client. Frozen startup/recovery snapshots return
/// NotReady at their dispatch sites instead of entering this path.
pub(super) fn capture_conversation(
    client: &mut AppClient,
    group: &GroupId,
    query: ConversationWindowQuery,
    epoch: &[u8],
) -> Result<CapturedConversation, ConversationWindowError> {
    let group_hex = hex::encode(group.as_slice());
    let capture = || {
        client
            .runtime
            .session()
            .with_group_authority_snapshot(group, |storage, authority| {
                if storage.chat_presentation_version()?.store_epoch != epoch {
                    return Err(ConversationWindowError::Closed);
                }
                let mut account =
                    storage.conversation_account_snapshot(&group_hex, query.clone())?;
                // A startup migration can still carry Member until its owner backfills.
                // Use this capture's compact live membership, without loading another roster.
                // Live removal facts do not distinguish voluntary departure from eviction.
                // Removed is the conservative fallback only for stale Member rows; explicit
                // Leaving/Left/Removed/Disbanded projection states remain authoritative.
                let facts = authority.facts;
                if account.presentation_input.self_membership == crate::SelfMembership::Member
                    && (facts.removed
                        || (!facts.is_member && !facts.disbanded && !facts.unrecoverable))
                {
                    account.presentation_input.self_membership = crate::SelfMembership::Removed;
                }
                Ok(CapturedConversation {
                    account,
                    authority: Some(authority),
                })
            })
    };
    match capture() {
        Err(ConversationWindowError::App(error))
            if matches!(
                error.as_ref(),
                AppError::Session(cgka_session::SessionError::Engine(
                    cgka_traits::EngineError::GroupNotHydrated(_)
                ))
            ) =>
        {
            // Background hydration owns recovery; no projection repair or
            // full-history work is needed merely because authority is cold.
            Err(ConversationWindowError::NotReady)
        }
        Err(ConversationWindowError::NotReady) => {
            // Readiness belongs to the existing keyed projection owner. Repair
            // outside the read boundary, only when missing/dirty; never mark read.
            let storage = client.app.account_storage(&client.state.label)?;
            if storage.chat_presentation_version()?.store_epoch != epoch {
                return Err(ConversationWindowError::Closed);
            }
            let local = client
                .app
                .account_home()
                .account(&client.state.label)
                .map_err(AppError::from)?
                .account_id_hex;
            storage.refresh_chat_list_row(
                &local,
                &group_hex,
                &MarmotApp::chat_list_mention_classifier(&local),
            )?;
            capture()
        }
        result => result,
    }
}

/// Commands apply to the current retained viewport. Background replacements (new
/// rows, delivery state, reactions, header, draft) never supersede a revision; once
/// a replacement showing a command's viewport move is published, every earlier
/// revision returns `StaleWindow`. Consume the latest snapshot and reassess the
/// user's intent before retrying. Commands from another handle generation are
/// always rejected.
#[derive(Clone)]
pub struct ConversationWindowHandle {
    commands: mpsc::Sender<Command>,
}
impl ConversationWindowHandle {
    /// Extend context around the retained visible anchor, keeping at most 200 rows.
    /// This never implicitly moves the visible anchor. At the cap, a request may
    /// return the same rows even when `has_more_before`/`has_more_after` is true:
    /// those flags describe stored history, not room around this anchor. Report
    /// the newly visible row with `set_visible_anchor`, then page using the
    /// revision it returns to continue through history without a scroll jump.
    pub async fn page(
        &self,
        revision: &ConversationWindowRevision,
        direction: ConversationPageDirection,
        count: usize,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        self.send(revision, Action::Page(direction, count)).await
    }
    pub async fn set_visible_anchor(
        &self,
        revision: &ConversationWindowRevision,
        message_id_hex: &str,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        self.send(revision, Action::Anchor(message_id_hex.to_owned()))
            .await
    }
    pub async fn return_to_latest(
        &self,
        revision: &ConversationWindowRevision,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        self.send(revision, Action::Latest).await
    }
    pub async fn jump_to_message(
        &self,
        revision: &ConversationWindowRevision,
        message_id_hex: &str,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        self.send(revision, Action::Message(message_id_hex.to_owned()))
            .await
    }
    /// Once accepted, caller cancellation does not cancel the command. On a
    /// transient capture failure its position remains scheduled for timed retry.
    async fn send(
        &self,
        revision: &ConversationWindowRevision,
        action: Action,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command {
                revision: revision.clone(),
                action,
                reply,
            })
            .await
            .map_err(|_| ConversationWindowError::Closed)?;
        rx.await.map_err(|_| ConversationWindowError::Closed)?
    }
}

/// Initial snapshot and an attached stream. Slow receivers coalesce complete
/// replacements; sequence gaps are valid. Dropping this closes surviving handles.
pub struct RuntimeConversationWindowSubscription {
    pub snapshot: ConversationWindowSnapshot,
    handle: ConversationWindowHandle,
    updates: watch::Receiver<Result<ConversationWindowSnapshot, ConversationWindowError>>,
    stopping: watch::Receiver<bool>,
}
impl RuntimeConversationWindowSubscription {
    pub fn window_handle(&self) -> ConversationWindowHandle {
        self.handle.clone()
    }
    /// Cancellation does not consume a notification; no command lock is held.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<ConversationWindowSnapshot>, ConversationWindowError> {
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut self.stopping) => Ok(None),
            result = self.updates.changed() => {
                if result.is_err() { return Ok(None); }
                self.updates.borrow_and_update().clone().map(Some)
            }
        }
    }
}
enum Action {
    Page(ConversationPageDirection, usize),
    Anchor(String),
    Latest,
    Message(String),
}
struct Command {
    revision: ConversationWindowRevision,
    action: Action,
    reply: oneshot::Sender<Result<ConversationWindowSnapshot, ConversationWindowError>>,
}
type WorkerConnection =
    watch::Receiver<Option<Result<mpsc::Sender<AccountWorkerCommand>, ConversationWindowError>>>;

// This future is joined with the window actor, not polled under its display
// timeout. Every admitted reconcile runs to completion, even if the window
// closes, so worker teardown cannot be abandoned inside worker_transactions.
async fn acquire_worker(
    accounts: AccountManager,
    label: String,
    account_id: String,
    ready: watch::Sender<
        Option<Result<mpsc::Sender<AccountWorkerCommand>, ConversationWindowError>>,
    >,
) {
    while !ready.is_closed() {
        let observation = accounts
            .shared
            .app_performance_telemetry()
            .observe(RuntimeOp::ConversationWorkerAcquire);
        let result = async {
            let account = accounts.resolve(&label)?;
            if account.account_id_hex != account_id {
                return Err(
                    AppError::from(marmot_account::AccountHomeError::AccountIdMismatch).into(),
                );
            }
            if account.signed_out {
                return Err(ConversationWindowError::Closed);
            }
            accounts.worker_commands(&label).await.map_err(Into::into)
        }
        .await;
        observation.finish(telemetry_outcome(&result));
        let finished = result.is_ok() || result.as_ref().is_err_and(|error| error.terminal());
        if ready.send(Some(result)).is_err() || finished {
            return;
        }
        // A missing worker during account restart is transient. Retry only
        // after the previous acquisition finished; closing cancels this wait.
        tokio::select! {
            _ = ready.closed() => return,
            _ = tokio::time::sleep(RETRY_DELAY) => {},
        }
    }
}

pub(super) fn telemetry_outcome<T>(
    result: &Result<T, ConversationWindowError>,
) -> TelemetryOutcome {
    match result {
        Ok(_) => TelemetryOutcome::Success,
        Err(ConversationWindowError::NotReady) => TelemetryOutcome::NotReady,
        Err(ConversationWindowError::Closed) => TelemetryOutcome::Cancelled,
        Err(_) => TelemetryOutcome::Failure,
    }
}
async fn measured<T>(
    telemetry: &AppPerformanceTelemetry,
    operation: RuntimeOp,
    work: impl std::future::Future<Output = Result<T, ConversationWindowError>>,
) -> Result<T, ConversationWindowError> {
    let observation = telemetry.observe(operation);
    let result = work.await;
    observation.finish(telemetry_outcome(&result));
    result
}

struct Reader {
    telemetry: AppPerformanceTelemetry,
    authority_ready: Option<Observation>,
    send_ready: Option<Observation>,
    app: MarmotApp,
    label: String,
    account_id: String,
    group: GroupId,
    store_epoch: Vec<u8>,
    worker: WorkerConnection,
    send_capture: Arc<SendCapture>,
}
impl Reader {
    async fn capture_live(
        &mut self,
        query: &ConversationWindowQuery,
        allow_checkpoint: bool,
    ) -> Result<(CapturedConversation, Option<u64>), ConversationWindowError> {
        let worker = match self.worker.borrow().as_ref() {
            Some(Ok(worker)) => worker.clone(),
            Some(Err(error)) if error.terminal() => return Err(error.clone()),
            _ => return Err(ConversationWindowError::NotReady),
        };
        if worker.is_closed() {
            return Err(ConversationWindowError::Closed);
        }
        self.send_capture.set_query(query);
        let mut changed = self.send_capture.changed.subscribe();
        if allow_checkpoint && let Some((captured, generation)) = self.send_capture.checkpoint() {
            return Ok((captured, Some(generation)));
        }
        let (respond, rx) = oneshot::channel();
        let capture = async {
            worker
                .send(AccountWorkerCommand::CaptureConversation {
                    queued: Some(self.telemetry.observe(RuntimeOp::ConversationCaptureQueue)),
                    group_id: self.group.clone(),
                    query: query.clone(),
                    store_epoch: self.store_epoch.clone(),
                    observer: Some(Arc::downgrade(&self.send_capture)),
                    respond,
                })
                .await
                .map_err(|_| ConversationWindowError::Closed)?;
            rx.await.map_err(|_| ConversationWindowError::Closed)?
        };
        tokio::pin!(capture);
        loop {
            tokio::select! {
                biased;
                result = &mut capture => return result.map(|captured| (captured, None)),
                _ = changed.changed(), if allow_checkpoint => {
                    if worker.is_closed() { return Err(ConversationWindowError::Closed); }
                    if let Some((captured, generation)) = self.send_capture.checkpoint() { return Ok((captured, Some(generation))); }
                }
            }
        }
    }

    async fn read(
        &mut self,
        query: &ConversationWindowQuery,
        revision: ConversationWindowRevision,
        allow_local: bool,
        allow_checkpoint: bool,
    ) -> Result<(ConversationWindowSnapshot, bool), ConversationWindowError> {
        if !allow_local {
            // Established windows require a coherent live capture, including
            // checkpoints supplied by an in-flight send. The actor still
            // cancels on close/reset/shutdown; never downgrade to a local read.
            let (captured, checkpoint) = self.capture_live(query, allow_checkpoint).await?;
            return self
                .present_checkpoint(captured, revision, checkpoint)
                .await;
        }
        let observation = self
            .telemetry
            .observe(RuntimeOp::ConversationAuthorityAttempt);
        let captured =
            tokio::time::timeout(AUTHORITY_WAIT, self.capture_live(query, allow_checkpoint)).await;
        observation.finish(match &captured {
            Ok(result) => telemetry_outcome(result),
            Err(_) => TelemetryOutcome::Timeout,
        });
        match captured {
            Ok(Ok((captured, checkpoint))) => {
                self.present_checkpoint(captured, revision, checkpoint)
                    .await
            }
            Ok(Err(ConversationWindowError::NotReady)) | Err(_) => self
                .read_local(query, revision)
                .await
                .map(|snapshot| (snapshot, false)),
            Ok(Err(error)) => Err(error),
        }
    }

    async fn present_checkpoint(
        &self,
        captured: CapturedConversation,
        revision: ConversationWindowRevision,
        checkpoint: Option<u64>,
    ) -> Result<(ConversationWindowSnapshot, bool), ConversationWindowError> {
        let result = self.present(captured, revision).await;
        if let Some(generation) = checkpoint {
            // Do not clear a newer send or a checkpoint for another query.
            self.send_capture.acknowledge(generation);
        }
        result.map(|snapshot| (snapshot, checkpoint.is_some()))
    }

    async fn read_local(
        &self,
        query: &ConversationWindowQuery,
        revision: ConversationWindowRevision,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        let telemetry = self.telemetry.clone();
        measured(&telemetry, RuntimeOp::ConversationLocalRead, async {
            let app = self.app.clone();
            let label = self.label.clone();
            let group = hex::encode(self.group.as_slice());
            let local = self.account_id.clone();
            let query = query.clone();
            let epoch = self.store_epoch.clone();
            let expected_epoch = epoch.clone();
            let captured = blocking_app_task(move || {
                if app.account_home().account(&label)?.account_id_hex != local {
                    return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
                }
                let store = app.account_storage(&label)?;
                if store.chat_presentation_version()?.store_epoch != expected_epoch {
                    return Ok(Err(ConversationOpenError::Storage(StorageError::Closed(
                        "conversation store replaced".into(),
                    ))));
                }
                let read = || store.conversation_account_snapshot(&group, query.clone());
                let account = match read() {
                    Err(ConversationOpenError::ReadStateNotReady) => {
                        // Reuse the keyed durable projection owner. Never hydrate
                        // MLS or mark read merely to render retained local content.
                        store.refresh_chat_list_row(
                            &local,
                            &group,
                            &MarmotApp::chat_list_mention_classifier(&local),
                        )?;
                        read()
                    }
                    result => result,
                };
                Ok(account)
            })
            .await??;
            if captured.page.store_epoch() != epoch {
                return Err(ConversationWindowError::Closed);
            }
            self.present(
                CapturedConversation {
                    account: captured,
                    authority: None,
                },
                revision,
            )
            .await
        })
        .await
    }

    async fn present(
        &self,
        captured: CapturedConversation,
        revision: ConversationWindowRevision,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        let telemetry = self.telemetry.clone();
        measured(&telemetry, RuntimeOp::ConversationPresentation, async {
            let app = self.app.clone();
            let label = self.label.clone();
            let account_id = self.account_id.clone();
            let presentation = blocking_app_task(move || {
                if app.account_home().account(&label)?.account_id_hex != account_id {
                    return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
                }
                let account = captured.account;
                let state = if let Some(authority) = captured.authority {
                    let facts = authority.facts;
                    ConversationHeaderState {
                        archived: account.archived,
                        epoch: Some(facts.epoch.0),
                        authority: ConversationAuthority {
                            is_member: facts.is_member,
                            self_membership: account.presentation_input.self_membership,
                            is_admin: facts.is_admin,
                            admin_count: facts.admin_count,
                            pending_confirmation: account.pending_confirmation,
                            leave_request_pending: account.leave_request_pending,
                            lifecycle: authority.lifecycle.into(),
                            unrecoverable: facts.unrecoverable,
                            disbanding: authority.disbanding,
                            disbanding_enabled: facts.disbanding_enabled,
                            has_disbanding_blockers: facts.has_disbanding_blockers,
                        },
                    }
                } else {
                    // Membership is a durable display fact, not engine authority.
                    // epoch=None explicitly denotes local-only capture; the shared
                    // presenter suppresses every live permission in this state.
                    ConversationHeaderState {
                        archived: account.archived,
                        epoch: None,
                        authority: ConversationAuthority {
                            is_member: account.presentation_input.self_membership
                                == crate::SelfMembership::Member,
                            self_membership: account.presentation_input.self_membership,
                            is_admin: false,
                            admin_count: 0,
                            pending_confirmation: account.pending_confirmation,
                            leave_request_pending: account.leave_request_pending,
                            lifecycle: if account.disbanded {
                                crate::AppGroupLifecycleState::Disbanded
                            } else {
                                crate::AppGroupLifecycleState::Recovering
                            },
                            unrecoverable: false,
                            disbanding: false,
                            disbanding_enabled: false,
                            has_disbanding_blockers: false,
                        },
                    }
                };
                let presentation = app.conversation_window_presentation(
                    &label,
                    &account.presentation_input,
                    state,
                    &account.page,
                );
                Ok(presentation.map(|presentation| ConversationWindowSnapshot {
                    revision,
                    page: account.page,
                    presentation,
                    read_state: account.read_state,
                    draft: account.draft,
                    pending_confirmation: account.pending_confirmation,
                    anchor: account.anchor,
                    anchors: account.anchors,
                }))
            })
            .await?;
            presentation.map_err(Into::into)
        })
        .await
    }
}

impl MarmotAppRuntime {
    /// Open at first unread (accepted conversations) or latest. No read intent
    /// is changed. Native bindings are a separate additive layer over this handle.
    pub async fn open_conversation_window(
        &self,
        account_ref: &str,
        group: &GroupId,
        query: ConversationOpenQuery,
    ) -> Result<RuntimeConversationWindowSubscription, ConversationWindowError> {
        let telemetry = self.shared.app_performance_telemetry();
        measured(&telemetry, RuntimeOp::ConversationOpen, async {
            self.shared.lifecycle().ensure_running()?;
            if !(1..=CONVERSATION_WINDOW_MAX_ROWS).contains(&query.limit) {
                return Err(ConversationWindowError::InvalidLimit);
            }
            let account = self.accounts.resolve(account_ref)?;
            self.accounts.require_onboarding_complete_for(&account)?;
            if !account.can_sign() {
                return Err(
                    AppError::from(marmot_account::AccountHomeError::SecretNotFound(
                        account.account_id_hex,
                    ))
                    .into(),
                );
            }
            if account.signed_out {
                return Err(AppError::RelayDirectory("account is signed out".into()).into());
            }
            let authority_ready = telemetry.observe(RuntimeOp::ConversationAuthorityReady);
            let send_ready = telemetry.observe(RuntimeOp::ConversationSendReady);
            let app = &self.accounts.app;
            let mut sources = Sources {
                avatars: app.presentation_signals.avatars.subscribe(),
                events: self.events.subscribe(),
                profiles: app.presentation_signals.profile_updates.subscribe(),
                presentation: app.presentation_signals.updates.subscribe(),
                drafts: app.presentation_signals.drafts.subscribe(),
                stopping: self.shared.lifecycle().subscribe_shutdown(),
            };
            let mut resets = app.presentation_signals.account_resets.subscribe();
            let position = ConversationWindowQuery {
                opening: query,
                before_anchor: None,
            };
            let revision = ConversationWindowRevision {
                generation: hex::encode(rand::random::<[u8; 16]>()),
                sequence: 0,
            };
            let initialize = async {
                let app = app.clone();
                let label = account.label.clone();
                let epoch = blocking_app_task(move || {
                    Ok(app
                        .account_storage(&label)?
                        .chat_presentation_version()?
                        .store_epoch)
                })
                .await?;
                let (ready, worker) = watch::channel(None);
                let reader = Reader {
                    telemetry: telemetry.clone(),
                    authority_ready: Some(authority_ready),
                    send_ready: Some(send_ready),
                    send_capture: Arc::new(SendCapture::new(
                        group.clone(),
                        epoch.clone(),
                        position.clone(),
                    )),
                    app: self.accounts.app.clone(),
                    label: account.label.clone(),
                    account_id: account.account_id_hex,
                    group: group.clone(),
                    store_epoch: epoch,
                    worker,
                };
                loop {
                    match reader.read_local(&position, revision.clone()).await {
                        Err(ConversationWindowError::NotReady) => tokio::time::sleep(RETRY_DELAY).await,
                        result => return result.map(|snapshot| (reader, snapshot, ready)),
                    }
                }
            };
            let (reader, snapshot, ready) = tokio::select! {
                biased;
                _ = wait_for_runtime_shutdown(&mut sources.stopping) => return Err(ConversationWindowError::Closed),
                _ = wait_for_account_reset(&mut resets, &account.label) => return Err(ConversationWindowError::Closed),
                result = initialize => result?,
            };
            let position = retain_anchor(position, &snapshot);
            let (updates, rx) = watch::channel(Ok(snapshot.clone()));
            let (commands, command_rx) = mpsc::channel(8);
            let snapshot_for_actor = snapshot.clone();
            let accounts = self.accounts.clone();
            let label = reader.label.clone();
            let account_id = reader.account_id.clone();
            tokio::spawn(async move {
                tokio::join!(
                    acquire_worker(accounts, label, account_id, ready),
                    run(
                        reader,
                        position,
                        snapshot_for_actor,
                        sources,
                        resets,
                        command_rx,
                        updates
                    ),
                );
            });
            Ok(RuntimeConversationWindowSubscription {
                snapshot,
                handle: ConversationWindowHandle { commands },
                updates: rx,
                stopping: self.shared.lifecycle().subscribe_shutdown(),
            })
        })
        .await
    }
}

fn anchor_index(anchor: ConversationOpenAnchorOutcome) -> Option<usize> {
    match anchor {
        ConversationOpenAnchorOutcome::Empty => None,
        ConversationOpenAnchorOutcome::Latest { index }
        | ConversationOpenAnchorOutcome::FirstUnread { index }
        | ConversationOpenAnchorOutcome::Message { index }
        | ConversationOpenAnchorOutcome::Retained { index }
        | ConversationOpenAnchorOutcome::RecoveredNext { index }
        | ConversationOpenAnchorOutcome::RecoveredPrevious { index } => Some(index),
    }
}
fn retain_anchor(
    mut position: ConversationWindowQuery,
    snapshot: &ConversationWindowSnapshot,
) -> ConversationWindowQuery {
    if matches!(
        snapshot.anchor,
        ConversationOpenAnchorOutcome::Latest { .. }
    ) && matches!(
        position.opening.target,
        ConversationOpenTarget::Latest | ConversationOpenTarget::Automatic
    ) {
        // Tail mode includes new arrivals. Explicit viewport anchors/history
        // paging leave tail mode until return_to_latest is requested.
        position.opening.target = ConversationOpenTarget::Latest;
        position.before_anchor = None;
    } else if let Some(index) = anchor_index(snapshot.anchor) {
        position.opening.target = ConversationOpenTarget::Anchor(snapshot.anchors[index].clone());
        position.before_anchor = Some(index);
    } else {
        // Empty windows follow the tail when their first row arrives, never reopen unread.
        position.opening.target = ConversationOpenTarget::Latest;
        position.before_anchor = None;
    }
    position
}
fn command_position(
    command: &Command,
    current: &ConversationWindowSnapshot,
    position: &ConversationWindowQuery,
    viewport_sequence: u64,
) -> Result<ConversationWindowQuery, ConversationWindowError> {
    // Background replacements never supersede a revision; only a published
    // command viewport move or another generation does.
    let quoted = &command.revision;
    if quoted.generation != current.revision.generation
        || !(viewport_sequence..=current.revision.sequence).contains(&quoted.sequence)
    {
        return Err(ConversationWindowError::StaleWindow);
    }
    let mut next = position.clone();
    match &command.action {
        Action::Latest => {
            next.opening.target = ConversationOpenTarget::Latest;
            next.before_anchor = None;
        }
        Action::Message(id) => {
            next.opening.target = ConversationOpenTarget::Message(id.clone());
            next.before_anchor = None;
        }
        Action::Anchor(id) => {
            let index = current
                .anchors
                .iter()
                .position(|a| a.message_id_hex().eq_ignore_ascii_case(id))
                .ok_or(ConversationWindowError::AnchorOutsideWindow)?;
            next.opening.target = ConversationOpenTarget::Anchor(current.anchors[index].clone());
            next.before_anchor = Some(index);
        }
        Action::Page(direction, count) => {
            if !(1..=CONVERSATION_WINDOW_MAX_ROWS).contains(count) {
                return Err(ConversationWindowError::InvalidLimit);
            }
            if *direction == ConversationPageDirection::Older
                && matches!(next.opening.target, ConversationOpenTarget::Latest)
                && let Some(anchor) = current.anchors.last()
            {
                next.opening.target = ConversationOpenTarget::Anchor(anchor.clone());
                next.before_anchor = Some(current.anchors.len() - 1);
            }
            let old_limit = next.opening.limit;
            next.opening.limit = (old_limit + count).min(CONVERSATION_WINDOW_MAX_ROWS);
            let before = next.before_anchor.unwrap_or(0);
            next.before_anchor = Some(match direction {
                ConversationPageDirection::Older => (before + count).min(next.opening.limit - 1),
                ConversationPageDirection::Newer => {
                    before.saturating_sub(old_limit + count - next.opening.limit)
                }
            });
        }
    }
    Ok(next)
}
struct Sources {
    avatars: broadcast::Receiver<String>,
    events: broadcast::Receiver<MarmotAppEvent>,
    profiles: broadcast::Receiver<String>,
    presentation: broadcast::Receiver<PresentationInvalidation>,
    drafts: broadcast::Receiver<MessageDraftInvalidation>,
    stopping: watch::Receiver<bool>,
}
impl Sources {
    fn drain(&mut self) {
        for _ in 0..self.avatars.len().min(DRAIN_LIMIT) {
            let _ = self.avatars.try_recv();
        }
        for _ in 0..self.events.len().min(DRAIN_LIMIT) {
            let _ = self.events.try_recv();
        }
        for _ in 0..self.profiles.len().min(DRAIN_LIMIT) {
            let _ = self.profiles.try_recv();
        }
        for _ in 0..self.presentation.len().min(DRAIN_LIMIT) {
            let _ = self.presentation.try_recv();
        }
        for _ in 0..self.drafts.len().min(DRAIN_LIMIT) {
            let _ = self.drafts.try_recv();
        }
    }
    async fn invalidated(&mut self, reader: &Reader, current: &ConversationWindowSnapshot) {
        let group_hex = hex::encode(reader.group.as_slice());
        loop {
            tokio::select! {
                event = self.avatars.recv() => match event { Ok(label) if label == reader.label => return, Err(_) => return, _ => {} },
                event = self.events.recv() => match event {
                    Ok(event) if projection_update_from_event(&event).is_some_and(|u|u.account_id_hex == reader.account_id && u.update.group_id_hex == group_hex)
                        || chat_list_event_route(&event).is_some_and(|(account,group)| account == reader.account_id && group == &reader.group) => return,
                    Err(_) => return, _ => {},
                },
                profile = self.profiles.recv() => match profile {
                    Ok(profile) if current.presentation.depends_on_profile(&profile) => return,
                    Err(_) => return, _ => {},
                },
                event = self.presentation.recv() => match event {
                    Ok(event) if event.account_label == reader.label => return,
                    Err(_) => return, _ => {},
                },
                event = self.drafts.recv() => match event {
                    Ok(event) if event.account_label == reader.label && event.group_id_hex == group_hex => return,
                    Err(_) => return, _ => {},
                },
            }
        }
    }
}
async fn run(
    mut reader: Reader,
    mut position: ConversationWindowQuery,
    mut current: ConversationWindowSnapshot,
    mut sources: Sources,
    mut resets: broadcast::Receiver<String>,
    mut commands: mpsc::Receiver<Command>,
    updates: watch::Sender<Result<ConversationWindowSnapshot, ConversationWindowError>>,
) {
    let mut worker_updates = reader.worker.clone();
    let mut send_updates = reader.send_capture.changed.subscribe();
    reader.send_capture.set_query(&position);
    let mut worker_updates_open = true;
    let mut dirty = true; // enrich the initial local snapshot without delaying it
    let mut authority_pending = false;
    let mut failed = false;
    let mut retry_delayed = false;
    let mut last_good_position = position.clone();
    // First published sequence showing the viewport the latest command moved to.
    // A move kept through a quiet failure takes effect when a retry publishes it.
    let mut viewport_sequence = current.revision.sequence;
    let mut viewport_moved = false;
    let mut deferred_command = None;
    loop {
        let mut stopping = sources.stopping.clone();
        let command = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = wait_for_account_reset(&mut resets, &reader.label) => return,
            _ = updates.closed() => return,
            _ = std::future::ready(()), if deferred_command.is_some() => deferred_command.take(),
            command = commands.recv() => { let Some(command) = command else { return; }; Some(command) },
            _ = send_updates.changed() => { dirty = true; continue; },
            result = worker_updates.changed(), if worker_updates_open => {
                if result.is_err() { worker_updates_open = false; }
                else { dirty = true; }
                continue;
            },
            _ = tokio::time::sleep(if retry_delayed || (authority_pending && !dirty) { RETRY_DELAY } else { Duration::from_millis(10) }), if dirty || authority_pending => None,
            _ = sources.invalidated(&reader, &current), if !dirty => { dirty = true; continue; },
        };
        let next = match command
            .as_ref()
            .map(|c| command_position(c, &current, &position, viewport_sequence))
            .transpose()
        {
            Ok(next) => next.unwrap_or_else(|| position.clone()),
            Err(error) => {
                if let Some(command) = command {
                    let _ = command.reply.send(Err(error));
                }
                continue;
            }
        };
        sources.drain(); // only the queued prefix; mutations during capture remain queued
        // Following the tail may use the send's coherent pre-publication capture.
        // capture_live sets the requested query first, invalidating any capture
        // from a different viewport/generation. Other navigation commands still
        // require a fresh worker read. A checkpoint schedules a fresh follow-up
        // below so invalidations newer than it cannot be lost.
        let allow_checkpoint = command
            .as_ref()
            .is_none_or(|command| matches!(command.action, Action::Latest));
        let reset_label = reader.label.clone();
        let result = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut sources.stopping) => return,
            _ = wait_for_account_reset(&mut resets, &reset_label) => return,
            _ = updates.closed() => return,
            // A fresh background capture can be queued behind publication.
            // Navigation may supersede that read; it must still pass the same
            // revision check on the next iteration. Explicit commands stay FIFO.
            incoming = commands.recv(), if command.is_none() => {
                let Some(incoming) = incoming else { return; };
                deferred_command = Some(incoming);
                dirty = true;
                continue;
            },
            result = reader.read(&next, current.revision.clone(), current.presentation.header.epoch.is_none(), allow_checkpoint) => result,
        };
        match result {
            Ok((mut replacement, checkpoint)) => {
                let changed = command.is_some() || !replacement.same_content(&current);
                if changed {
                    replacement.revision.sequence = current
                        .revision
                        .sequence
                        .checked_add(1)
                        .expect("window sequence exhausted");
                }
                position = retain_anchor(next, &replacement);
                reader.send_capture.set_query(&position);
                last_good_position = position.clone();
                current = replacement;
                if changed && (viewport_moved || command.is_some()) {
                    viewport_sequence = current.revision.sequence;
                }
                viewport_moved = false;
                if current.presentation.header.epoch.is_some()
                    && let Some(observation) = reader.authority_ready.take()
                {
                    observation.finish(TelemetryOutcome::Success);
                }
                if current.presentation.header.epoch.is_some()
                    && let Some(observation) = reader.send_ready.take()
                {
                    observation.finish(if current.presentation.header.capabilities.can_send {
                        TelemetryOutcome::Success
                    } else {
                        TelemetryOutcome::NotReady
                    });
                }
                if changed || failed {
                    let _ = updates.send_replace(Ok(current.clone()));
                }
                if let Some(command) = command {
                    let _ = command.reply.send(Ok(current.clone()));
                }
                authority_pending = current.presentation.header.epoch.is_none();
                // A checkpoint predates sources.drain(), so it may not include
                // invalidations discarded there. Follow it with a fresh capture
                // even when no further event or send completion arrives. This
                // conservative extra read is self-limiting: sends publish only
                // finitely many checkpoints, each before a transport wait.
                dirty = checkpoint;
                failed = false;
                retry_delayed = false;
            }
            Err(error) => {
                let commanded = command.is_some();
                let terminal = error.terminal();
                let terminal_outcome = if matches!(error, ConversationWindowError::Closed) {
                    TelemetryOutcome::Cancelled
                } else {
                    TelemetryOutcome::Failure
                };
                let waiting = matches!(error, ConversationWindowError::NotReady);
                let query_error = matches!(error, ConversationWindowError::Query(_));
                if terminal
                    || (!waiting && !failed && !query_error)
                    || (query_error && command.is_none())
                {
                    let _ = updates.send_replace(Err(error.clone()));
                }
                if let Some(command) = command {
                    let _ = command.reply.send(Err(error));
                } else if query_error {
                    // An explicit jump retained through a transient failure can
                    // disappear before retry. Report it, then resume the last
                    // successful viewport rather than killing the live stream.
                    position = last_good_position.clone();
                    viewport_moved = false;
                    dirty = true;
                    failed = true;
                    retry_delayed = true;
                }
                if terminal {
                    if let Some(observation) = reader.authority_ready.take() {
                        observation.finish(terminal_outcome);
                    }
                    if let Some(observation) = reader.send_ready.take() {
                        observation.finish(terminal_outcome);
                    }
                    return;
                }
                if !query_error {
                    // Preserve accepted viewport commands through a quiet failure.
                    position = next;
                    viewport_moved |= commanded;
                    dirty = true;
                    // Quiet NotReady retries must not suppress a later real
                    // storage error that the receiver has not yet seen.
                    failed |= !waiting;
                    retry_delayed = true;
                }
            }
        }
    }
}
async fn wait_for_account_reset(resets: &mut broadcast::Receiver<String>, label: &str) {
    loop {
        match resets.recv().await {
            Ok(reset) if reset == label => return,
            // A lost teardown signal is terminal, never a reason to rebind a handle.
            Err(_) => return,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
