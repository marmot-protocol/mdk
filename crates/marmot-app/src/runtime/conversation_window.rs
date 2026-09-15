//! One worker capture and one actor per conversation. Account-owned fields share
//! a read boundary; directory enrichment is a separate consistency domain.
use super::account_worker::AccountWorkerCommand;
use super::event_routing::{chat_list_event_route, projection_update_from_event};
use super::{MarmotAppRuntime, blocking_app_task, wait_for_runtime_shutdown};
use crate::chat_presentation::signals::PresentationInvalidation;
use crate::conversation_presentation::{
    ConversationAuthority, ConversationHeaderState, ConversationPresentationError,
    ConversationWindowPresentation,
};
use crate::drafts::MessageDraftInvalidation;
use crate::{AppClient, AppError, MarmotApp, MarmotAppEvent, SelectedMessageDraft};
use cgka_engine::group_authority::GroupAuthoritySnapshot;
use cgka_traits::{GroupId, StorageError};
use std::{sync::Arc, time::Duration};
use storage_sqlite::{ConversationAccountSnapshot, ConversationOpenError, ConversationWindowQuery};
pub use storage_sqlite::{
    ConversationAnchor, ConversationOpenAnchorOutcome, ConversationOpenQuery,
    ConversationOpenReadState, ConversationOpenTarget,
};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

const RETRY_DELAY: Duration = Duration::from_secs(1);
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

pub(crate) struct CapturedConversation {
    account: ConversationAccountSnapshot,
    authority: GroupAuthoritySnapshot,
}
/// Only called with the live client. Frozen startup/recovery snapshots return
/// NotReady at their dispatch sites instead of entering this path.
pub(super) fn capture_conversation(
    client: &mut AppClient,
    group: &GroupId,
    query: ConversationWindowQuery,
    epoch: &[u8],
) -> Result<CapturedConversation, ConversationWindowError> {
    client.runtime.session_mut().ensure_group_hydrated(group)?;
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
                Ok(CapturedConversation { account, authority })
            })
    };
    match capture() {
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

/// Commands apply to the supplied snapshot revision. Every command can return
/// `StaleWindow` if a replacement was published first; consume the latest snapshot
/// and reassess the user's intent before retrying. In particular, paging is relative
/// to that snapshot's retained viewport, not to a newer position changed concurrently.
/// Commands from another handle generation are always rejected.
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
struct Reader {
    app: MarmotApp,
    label: String,
    account_id: String,
    group: GroupId,
    store_epoch: Vec<u8>,
    worker: mpsc::Sender<AccountWorkerCommand>,
}
impl Reader {
    async fn read(
        &self,
        query: &ConversationWindowQuery,
        revision: ConversationWindowRevision,
    ) -> Result<ConversationWindowSnapshot, ConversationWindowError> {
        let (respond, rx) = oneshot::channel();
        self.worker
            .send(AccountWorkerCommand::CaptureConversation {
                group_id: self.group.clone(),
                query: query.clone(),
                store_epoch: self.store_epoch.clone(),
                respond,
            })
            .await
            .map_err(|_| ConversationWindowError::Closed)?;
        let captured = rx.await.map_err(|_| ConversationWindowError::Closed)??;
        let app = self.app.clone();
        let label = self.label.clone();
        let account_id = self.account_id.clone();
        let presentation = blocking_app_task(move || {
            if app.account_home().account(&label)?.account_id_hex != account_id {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            let account = captured.account;
            let authority = captured.authority;
            let facts = authority.facts;
            let state = ConversationHeaderState {
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
        self.shared.lifecycle().ensure_running()?;
        if !(1..=CONVERSATION_WINDOW_MAX_ROWS).contains(&query.limit) {
            return Err(ConversationWindowError::InvalidLimit);
        }
        let account = self.accounts.resolve(account_ref)?;
        let app = &self.accounts.app;
        let mut sources = Sources {
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
            let worker = self.accounts.worker_commands(account_ref).await?;
            let reader = Reader {
                app: self.accounts.app.clone(),
                label: account.label.clone(),
                account_id: account.account_id_hex,
                group: group.clone(),
                store_epoch: epoch,
                worker,
            };
            loop {
                match reader.read(&position, revision.clone()).await {
                    Err(ConversationWindowError::NotReady) => tokio::time::sleep(RETRY_DELAY).await,
                    result => return result.map(|snapshot| (reader, snapshot)),
                }
            }
        };
        let (reader, snapshot) = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut sources.stopping) => return Err(ConversationWindowError::Closed),
            _ = wait_for_account_reset(&mut resets, &account.label) => return Err(ConversationWindowError::Closed),
            result = initialize => result?,
        };
        let position = retain_anchor(position, &snapshot);
        let (updates, rx) = watch::channel(Ok(snapshot.clone()));
        let (commands, command_rx) = mpsc::channel(8);
        tokio::spawn(run(
            reader,
            position,
            snapshot.clone(),
            sources,
            resets,
            command_rx,
            updates,
        ));
        Ok(RuntimeConversationWindowSubscription {
            snapshot,
            handle: ConversationWindowHandle { commands },
            updates: rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
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
) -> Result<ConversationWindowQuery, ConversationWindowError> {
    if command.revision != current.revision {
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
    events: broadcast::Receiver<MarmotAppEvent>,
    profiles: broadcast::Receiver<String>,
    presentation: broadcast::Receiver<PresentationInvalidation>,
    drafts: broadcast::Receiver<MessageDraftInvalidation>,
    stopping: watch::Receiver<bool>,
}
impl Sources {
    fn drain(&mut self) {
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
    reader: Reader,
    mut position: ConversationWindowQuery,
    mut current: ConversationWindowSnapshot,
    mut sources: Sources,
    mut resets: broadcast::Receiver<String>,
    mut commands: mpsc::Receiver<Command>,
    updates: watch::Sender<Result<ConversationWindowSnapshot, ConversationWindowError>>,
) {
    let mut dirty = false;
    let mut failed = false;
    let mut last_good_position = position.clone();
    loop {
        let mut stopping = sources.stopping.clone();
        let command = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = wait_for_account_reset(&mut resets, &reader.label) => return,
            _ = updates.closed() => return,
            command = commands.recv() => { let Some(command) = command else { return; }; Some(command) },
            _ = tokio::time::sleep(if failed { RETRY_DELAY } else { Duration::from_millis(10) }), if dirty => None,
            _ = sources.invalidated(&reader, &current), if !dirty => { dirty = true; continue; },
        };
        let next = match command
            .as_ref()
            .map(|c| command_position(c, &current, &position))
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
        let result = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut sources.stopping) => return,
            _ = wait_for_account_reset(&mut resets, &reader.label) => return,
            _ = updates.closed() => return,
            result = reader.read(&next, current.revision.clone()) => result,
        };
        match result {
            Ok(mut replacement) => {
                let changed = command.is_some() || !replacement.same_content(&current);
                if changed {
                    replacement.revision.sequence = current
                        .revision
                        .sequence
                        .checked_add(1)
                        .expect("window sequence exhausted");
                }
                position = retain_anchor(next, &replacement);
                last_good_position = position.clone();
                current = replacement;
                if changed || failed {
                    let _ = updates.send_replace(Ok(current.clone()));
                }
                if let Some(command) = command {
                    let _ = command.reply.send(Ok(current.clone()));
                }
                dirty = false;
                failed = false;
            }
            Err(error) => {
                let terminal = error.terminal();
                let query_error = matches!(error, ConversationWindowError::Query(_));
                if terminal || (!failed && !query_error) || (query_error && command.is_none()) {
                    let _ = updates.send_replace(Err(error.clone()));
                }
                if let Some(command) = command {
                    let _ = command.reply.send(Err(error));
                } else if query_error {
                    // An explicit jump retained through a transient failure can
                    // disappear before retry. Report it, then resume the last
                    // successful viewport rather than killing the live stream.
                    position = last_good_position.clone();
                    dirty = true;
                    failed = true;
                }
                if terminal {
                    return;
                }
                if !query_error {
                    // Preserve accepted viewport commands through a quiet failure.
                    position = next;
                    dirty = true;
                    failed = true;
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
