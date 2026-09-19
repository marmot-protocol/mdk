//! One actor owns each bounded window. Commands and invalidations never splice
//! independently read pages; every replacement resolves current stable anchors.
use super::event_routing::{chat_list_event_route, projection_update_from_event};
use super::{MarmotAppRuntime, blocking_app_task, wait_for_runtime_shutdown};
use crate::chat_presentation::signals::PresentationInvalidation;
use crate::{AppError, MarmotApp, MarmotAppEvent, PresentedChatRow};
use std::{sync::Arc, time::Duration};
use storage_sqlite::{ChatListCursor, ChatListWindowQuery, ChatListWindowRead};
pub use storage_sqlite::{ChatListPageDirection, ChatListView};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

pub const CHAT_LIST_WINDOW_INITIAL_ROWS: usize = 50;
pub const CHAT_LIST_WINDOW_MAX_ROWS: usize = 200;
// Receiver::len includes messages already overwritten after lag. Bound drain
// attempts even when a paused consumer missed millions of invalidations.
const INVALIDATION_DRAIN_LIMIT: usize = 1024;

#[derive(Clone, Debug, thiserror::Error)]
pub enum ChatListWindowError {
    #[error("chat window requests must contain 1 to 100 rows")]
    InvalidLimit,
    #[error("chat window changed; use the current sequence")]
    StaleWindow,
    #[error("visible anchor must belong to the retained window")]
    AnchorOutsideWindow,
    #[error("chat window is closed")]
    Closed,
    #[error(transparent)]
    Query(Arc<storage_sqlite::ChatListPageError>),
    #[error(transparent)]
    App(Arc<AppError>),
}
impl From<AppError> for ChatListWindowError {
    fn from(value: AppError) -> Self {
        Self::App(Arc::new(value))
    }
}

/// Anchor identity and its current row index. Pixel offsets remain client-owned.
#[derive(Clone, PartialEq, Eq)]
pub enum ChatListAnchorOutcome {
    Top,
    Retained { group_id_hex: String, index: usize },
    Recovered { group_id_hex: String, index: usize },
    Reset,
}
impl std::fmt::Debug for ChatListAnchorOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Top => "Top",
            Self::Retained { .. } => "Retained",
            Self::Recovered { .. } => "Recovered",
            Self::Reset => "Reset",
        })
    }
}

/// Complete replacement; boundaries describe this sequence and are not restart tokens.
/// Effective badge fields suppress invitations and Left; lower-level rows retain raw read intent.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatListWindowSnapshot {
    pub subscription_generation: String,
    pub sequence: u64,
    pub view: ChatListView,
    pub rows: Vec<PresentedChatRow>,
    pub first: Option<ChatListCursor>,
    pub last: Option<ChatListCursor>,
    pub has_more_before: bool,
    pub has_more_after: bool,
    pub anchor: ChatListAnchorOutcome,
}
impl std::fmt::Debug for ChatListWindowSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListWindowSnapshot")
            .field("sequence", &self.sequence)
            .field("view", &self.view)
            .field("rows", &self.rows.len())
            .field("anchor", &self.anchor)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct ChatListWindowHandle {
    commands: mpsc::Sender<Command>,
}
impl ChatListWindowHandle {
    /// Commands stay available while the subscription's recv is waiting. A command
    /// accepted by the actor outlives caller cancellation; its result remains in the stream.
    pub async fn page(
        &self,
        sequence: u64,
        direction: ChatListPageDirection,
        count: usize,
    ) -> Result<ChatListWindowSnapshot, ChatListWindowError> {
        self.send(Action::Page(direction, count), sequence).await
    }
    pub async fn set_visible_anchor(
        &self,
        sequence: u64,
        group_id_hex: &str,
    ) -> Result<ChatListWindowSnapshot, ChatListWindowError> {
        let group = crate::ids::normalize_group_id_hex_app(group_id_hex)?;
        self.send(Action::Anchor(group), sequence).await
    }
    pub async fn return_to_top(
        &self,
        sequence: u64,
    ) -> Result<ChatListWindowSnapshot, ChatListWindowError> {
        self.send(Action::Top, sequence).await
    }
    async fn send(
        &self,
        action: Action,
        sequence: u64,
    ) -> Result<ChatListWindowSnapshot, ChatListWindowError> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command {
                action,
                sequence,
                reply,
            })
            .await
            .map_err(|_| ChatListWindowError::Closed)?;
        rx.await.map_err(|_| ChatListWindowError::Closed)?
    }
}

/// Initial snapshot plus an attached live subscription. Slow receivers coalesce to
/// the latest complete window; sequence gaps are valid. Drop closes the actor even
/// when a separate command handle survives. No lock is held while recv waits.
pub struct RuntimeChatListWindowSubscription {
    pub snapshot: ChatListWindowSnapshot,
    handle: ChatListWindowHandle,
    updates: watch::Receiver<Result<ChatListWindowSnapshot, ChatListWindowError>>,
    stopping: watch::Receiver<bool>,
}
impl RuntimeChatListWindowSubscription {
    pub fn window_handle(&self) -> ChatListWindowHandle {
        self.handle.clone()
    }
    /// Cancellation does not consume a notification. Read failures are explicit and
    /// retried by the actor without another external event.
    pub async fn recv(&mut self) -> Result<Option<ChatListWindowSnapshot>, ChatListWindowError> {
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
    Page(ChatListPageDirection, usize),
    Anchor(String),
    Top,
}
struct Command {
    action: Action,
    sequence: u64,
    reply: oneshot::Sender<Result<ChatListWindowSnapshot, ChatListWindowError>>,
}
#[derive(Clone)]
struct Position {
    limit: usize,
    anchor: Option<String>,
    before: usize,
}
struct Reader {
    app: MarmotApp,
    label: String,
    account_id: String,
    store_epoch: Vec<u8>,
    view: ChatListView,
}

impl MarmotAppRuntime {
    /// Additive four-list API. No legacy full-list subscription or account-wide
    /// selected-presentation preparation is used on this path.
    pub async fn open_chat_list_window(
        &self,
        account_ref: &str,
        view: ChatListView,
        initial_rows: Option<usize>,
    ) -> Result<RuntimeChatListWindowSubscription, ChatListWindowError> {
        self.shared.lifecycle().ensure_running()?;
        let count = initial_rows.unwrap_or(CHAT_LIST_WINDOW_INITIAL_ROWS);
        if !(1..=100).contains(&count) {
            return Err(ChatListWindowError::InvalidLimit);
        }
        let account = self.accounts.resolve(account_ref)?;
        // All invalidations attach BEFORE the first local read.
        let events = self.events.subscribe();
        let profiles = self
            .accounts
            .app
            .presentation_signals
            .profile_updates
            .subscribe();
        let presentation = self.accounts.app.presentation_signals.updates.subscribe();
        let avatars = self.accounts.app.presentation_signals.avatars.subscribe();
        let drafts = self.accounts.app.subscribe_message_draft_changes();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let mut resets = self
            .accounts
            .app
            .presentation_signals
            .account_resets
            .subscribe();
        let mut reader = Reader {
            app: self.accounts.app.clone(),
            label: account.label,
            account_id: account.account_id_hex,
            store_epoch: Vec::new(),
            view,
        };
        let position = Position {
            limit: count,
            anchor: None,
            before: 0,
        };
        let read = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return Err(ChatListWindowError::Closed),
            _ = wait_for_account_reset(&mut resets, &reader.label) => return Err(ChatListWindowError::Closed),
            read = reader.initial_read(&position) => read?,
        };
        reader.store_epoch = read
            .snapshot
            .as_ref()
            .expect("prepared")
            .presentation_version
            .store_epoch
            .clone();
        let generation = hex::encode(rand::random::<[u8; 16]>());
        let snapshot = snapshot(read, &position, generation, 0, view);
        let (updates, rx) = watch::channel(Ok(snapshot.clone()));
        let (commands, command_rx) = mpsc::channel(8);
        tokio::spawn(run(
            reader,
            position,
            snapshot.clone(),
            Sources {
                drafts,
                avatars,
                profiles,
                events,
                presentation,
                stopping,
            },
            resets,
            command_rx,
            updates,
        ));
        Ok(RuntimeChatListWindowSubscription {
            snapshot,
            handle: ChatListWindowHandle { commands },
            updates: rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }
}

impl Reader {
    async fn initial_read(
        &self,
        position: &Position,
    ) -> Result<ChatListWindowRead, ChatListWindowError> {
        loop {
            match self.read(position, &[]).await {
                Err(ChatListWindowError::App(error))
                    if matches!(error.as_ref(), AppError::ChatPresentationNotReady) =>
                {
                    // Each attempt initializes at most one base-row batch. Yield
                    // between batches; the caller owns cancellation/shutdown/reset.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                result => return result,
            }
        }
    }

    async fn read(
        &self,
        position: &Position,
        prior: &[PresentedChatRow],
    ) -> Result<ChatListWindowRead, ChatListWindowError> {
        let mut anchors = Vec::new();
        if let Some(anchor) = &position.anchor {
            anchors.push(anchor.clone());
            if let Some(index) = prior.iter().position(|r| r.row.group_id_hex == *anchor) {
                anchors.extend(
                    prior[index + 1..]
                        .iter()
                        .map(|r| r.row.group_id_hex.clone()),
                );
                anchors.extend(
                    prior[..index]
                        .iter()
                        .rev()
                        .map(|r| r.row.group_id_hex.clone()),
                );
            }
        }
        let query = ChatListWindowQuery {
            view: self.view,
            limit: position.limit,
            anchors,
            before_anchor: position.before,
        };
        let app = self.app.clone();
        let label = self.label.clone();
        let account_id = self.account_id.clone();
        let epoch = self.store_epoch.clone();
        blocking_app_task(move || {
            let account = app.account_home().account(&label)?;
            if account.account_id_hex != account_id {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            let storage = app.account_storage(&label)?;
            if !epoch.is_empty() && storage.chat_presentation_version()?.store_epoch != epoch {
                return Err(AppError::RuntimeStopping);
            }
            // Legacy/imported accounts can lack navigation rows entirely. Repair
            // one bounded batch even without an active account worker; selected
            // preparation below remains limited to the requested window.
            crate::chat_presentation::maintenance::prepare_base_rows(&storage, &account_id)?;
            let read = || storage.read_chat_list_window(query.clone());
            let mut result = match read().inspect_err(|_| app.presentation_signals.wake()) {
                Ok(result) => result,
                Err(error) => return Ok(Err(error)),
            };
            if result.snapshot.is_none() {
                let prepared = crate::chat_presentation::maintenance::prepare_window(
                    &storage,
                    &app.shared_storage()?,
                    &account_id,
                    &result.pending_presentations,
                );
                app.presentation_signals.wake();
                // Notify other windows even when a later selection failed.
                let _ = app
                    .presentation_signals
                    .updates
                    .send(PresentationInvalidation {
                        account_label: label,
                        version: storage.chat_presentation_version()?,
                    });
                prepared?;
                result = match read() {
                    Ok(result) => result,
                    Err(error) => return Ok(Err(error)),
                };
            }
            let Some(snapshot) = result.snapshot.as_mut() else {
                return Err(AppError::ChatPresentationNotReady);
            };
            let mut rows = snapshot
                .rows
                .iter()
                .map(|r| r.row.clone())
                .collect::<Vec<_>>();
            app.hydrate_chat_list_rows(&mut rows)?;
            for (selected, mut row) in snapshot.rows.iter_mut().zip(rows) {
                if row.pending_confirmation || query.view == ChatListView::Left {
                    row.unread_count = 0;
                    row.unread_mention_count = 0;
                    row.has_unread = false;
                    row.has_unread_mention = false;
                    row.manually_marked_unread = false;
                    row.first_unread_message_id_hex = None;
                }
                selected.row = row;
            }
            Ok(Ok(result))
        })
        .await?
        .map_err(|error| match error {
            storage_sqlite::ChatListPageError::Storage(
                cgka_traits::storage::StorageError::NotFound,
            ) => AppError::ChatPresentationNotReady.into(),
            storage_sqlite::ChatListPageError::Storage(error) => AppError::Storage(error).into(),
            error => ChatListWindowError::Query(Arc::new(error)),
        })
    }
}

fn snapshot(
    read: ChatListWindowRead,
    position: &Position,
    generation: String,
    sequence: u64,
    view: ChatListView,
) -> ChatListWindowSnapshot {
    let rows = read.snapshot.expect("prepared window").rows;
    let anchor = match (position.anchor.as_ref(), read.anchor) {
        (None, _) => ChatListAnchorOutcome::Top,
        (Some(wanted), Some(group_id_hex)) => {
            let index = rows
                .iter()
                .position(|r| r.row.group_id_hex == group_id_hex)
                .expect("anchor included");
            if *wanted == group_id_hex {
                ChatListAnchorOutcome::Retained {
                    group_id_hex,
                    index,
                }
            } else {
                ChatListAnchorOutcome::Recovered {
                    group_id_hex,
                    index,
                }
            }
        }
        (Some(_), None) => ChatListAnchorOutcome::Reset,
    };
    ChatListWindowSnapshot {
        subscription_generation: generation,
        sequence,
        view,
        rows,
        first: read.page.first,
        last: read.page.last,
        has_more_before: read.page.has_more_before,
        has_more_after: read.page.has_more_after,
        anchor,
    }
}
struct Sources {
    drafts: broadcast::Receiver<crate::drafts::MessageDraftInvalidation>,
    avatars: broadcast::Receiver<String>,
    profiles: broadcast::Receiver<String>,
    events: broadcast::Receiver<MarmotAppEvent>,
    presentation: broadcast::Receiver<PresentationInvalidation>,
    stopping: watch::Receiver<bool>,
}
impl Sources {
    fn relevant(reader: &Reader, event: &MarmotAppEvent) -> bool {
        projection_update_from_event(event).is_some_and(|u| u.account_id_hex == reader.account_id)
            || chat_list_event_route(event).is_some_and(|(account, _)| account == reader.account_id)
    }
    fn drain(&mut self) {
        for _ in 0..self.drafts.len().min(INVALIDATION_DRAIN_LIMIT) {
            let _ = self.drafts.try_recv();
        }
        for _ in 0..self.avatars.len().min(INVALIDATION_DRAIN_LIMIT) {
            let _ = self.avatars.try_recv();
        }
        // Drain only the bounded queued prefix. Events arriving during a read stay queued.
        for _ in 0..self.events.len().min(INVALIDATION_DRAIN_LIMIT) {
            let _ = self.events.try_recv();
        }
        for _ in 0..self.presentation.len().min(INVALIDATION_DRAIN_LIMIT) {
            let _ = self.presentation.try_recv();
        }
        for _ in 0..self.profiles.len().min(INVALIDATION_DRAIN_LIMIT) {
            let _ = self.profiles.try_recv();
        }
    }
    async fn invalidated(
        &mut self,
        reader: &Reader,
        expiry: Option<i64>,
        rows: &[PresentedChatRow],
    ) {
        loop {
            tokio::select! {
                event = self.drafts.recv() => match event {
                    Ok(event) if event.account_label == reader.label && rows.iter().any(|r| r.row.group_id_hex == event.group_id_hex) => return,
                    Err(_) => return, _ => {}
                },
                event = self.avatars.recv() => match event { Ok(label) if label == reader.label => return, Err(_) => return, _ => {} },
                profile = self.profiles.recv() => match profile {
                    Ok(profile) if rows.iter().any(|r| {
                        r.row.last_message.as_ref().is_some_and(|m| {
                            m.sender.eq_ignore_ascii_case(&profile)
                                || m.group_system.as_ref().is_some_and(|e| {
                                    [e.actor_account_id_hex.as_deref(), e.subject_account_id_hex.as_deref()]
                                        .into_iter().flatten().any(|id| id.eq_ignore_ascii_case(&profile))
                                })
                        })
                    }) => return,
                    Err(_) => return,
                    _ => {},
                },
                event = self.events.recv() => match event {
                    Ok(event) if Self::relevant(reader, &event) => return,
                    Err(_) => return,
                    _ => {},
                },
                event = self.presentation.recv() => match event {
                    Ok(event) if event.account_label == reader.label => return,
                    Err(_) => return,
                    _ => {},
                },
                _ = async {
                    if let Some(at) = expiry { tokio::time::sleep(Duration::from_millis(at.saturating_sub(crate::notifications::unix_now_ms()).max(0) as u64)).await; }
                    else { std::future::pending::<()>().await; }
                } => return,
            }
        }
    }
}

fn command_position(
    command: &Command,
    current: &ChatListWindowSnapshot,
    position: &Position,
) -> Result<Position, ChatListWindowError> {
    if command.sequence != current.sequence {
        return Err(ChatListWindowError::StaleWindow);
    }
    let mut next = position.clone();
    match &command.action {
        Action::Top => {
            next.anchor = None;
            next.before = 0;
        }
        Action::Anchor(group) => {
            let index = current
                .rows
                .iter()
                .position(|r| r.row.group_id_hex.eq_ignore_ascii_case(group))
                .ok_or(ChatListWindowError::AnchorOutsideWindow)?;
            next.anchor = if index == 0 && !current.has_more_before {
                None
            } else {
                Some(current.rows[index].row.group_id_hex.clone())
            };
            next.before = index;
        }
        Action::Page(direction, count) => {
            if !(1..=100).contains(count) {
                return Err(ChatListWindowError::InvalidLimit);
            }
            // Establish an anchor if the client has not yet supplied a viewport.
            if next.anchor.is_none()
                && *direction == ChatListPageDirection::Backward
                && let Some(row) = current.rows.first()
            {
                next.anchor = Some(row.row.group_id_hex.clone());
            }
            let old_limit = next.limit;
            next.limit = (old_limit + count).min(CHAT_LIST_WINDOW_MAX_ROWS);
            match direction {
                ChatListPageDirection::Forward => {
                    next.before = next.before.saturating_sub(old_limit + count - next.limit)
                }
                ChatListPageDirection::Backward => {
                    next.before = (next.before + count).min(next.limit - 1)
                }
            }
        }
    }
    Ok(next)
}

async fn run(
    reader: Reader,
    mut position: Position,
    mut current: ChatListWindowSnapshot,
    mut sources: Sources,
    mut resets: broadcast::Receiver<String>,
    mut commands: mpsc::Receiver<Command>,
    updates: watch::Sender<Result<ChatListWindowSnapshot, ChatListWindowError>>,
) {
    let mut dirty = false;
    let mut failed = false;
    loop {
        let expiry = current
            .rows
            .iter()
            .filter_map(|r| r.row.muted_until_ms)
            .min();
        let command = if dirty {
            tokio::select! {
                biased;
                _ = wait_for_runtime_shutdown(&mut sources.stopping) => return,
                _ = updates.closed() => return,
                _ = wait_for_account_reset(&mut resets, &reader.label) => return,
                command = commands.recv() => { let Some(command) = command else { return; }; Some(command) },
                _ = tokio::time::sleep(if failed { Duration::from_secs(1) } else { Duration::from_millis(10) }) => None,
            }
        } else {
            // Clone the shutdown receiver so waiting for invalidations borrows no command state.
            let mut stopping = sources.stopping.clone();
            tokio::select! {
                biased;
                _ = wait_for_runtime_shutdown(&mut stopping) => return,
                _ = updates.closed() => return,
                _ = wait_for_account_reset(&mut resets, &reader.label) => return,
                command = commands.recv() => { let Some(command) = command else { return; }; Some(command) },
                _ = sources.invalidated(&reader, expiry, &current.rows) => { dirty = true; continue; },
            }
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
        sources.drain();
        let result = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut sources.stopping) => return,
            _ = updates.closed() => return,
            _ = wait_for_account_reset(&mut resets, &reader.label) => return,
            result = reader.read(&next, &current.rows) => result,
        };
        match result {
            Ok(read) => {
                let mut replacement = snapshot(
                    read,
                    &next,
                    current.subscription_generation.clone(),
                    current.sequence,
                    reader.view,
                );
                // Storage revisions also change for activity outside this window.
                // Do not invalidate client commands or redraw unchanged visible content
                // solely because opaque boundary tokens acquired a newer revision.
                let changed = replacement.rows != current.rows
                    || replacement.has_more_before != current.has_more_before
                    || replacement.has_more_after != current.has_more_after
                    || replacement.anchor != current.anchor
                    || command.is_some();
                if changed {
                    replacement.sequence = current
                        .sequence
                        .checked_add(1)
                        .expect("window sequence exhausted");
                }
                position = next;
                match &replacement.anchor {
                    ChatListAnchorOutcome::Retained {
                        group_id_hex,
                        index,
                    }
                    | ChatListAnchorOutcome::Recovered {
                        group_id_hex,
                        index,
                    } => {
                        position.anchor = Some(group_id_hex.clone());
                        position.before = *index;
                    }
                    _ => {
                        position.anchor = None;
                        position.before = 0;
                    }
                }
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
                if matches!(&error, ChatListWindowError::App(e) if matches!(e.as_ref(), AppError::RuntimeStopping | AppError::AccountHome(marmot_account::AccountHomeError::AccountIdMismatch | marmot_account::AccountHomeError::UnknownAccount(_)) | AppError::Storage(cgka_traits::storage::StorageError::Closed(_))))
                {
                    return;
                }
                if !failed {
                    let _ = updates.send_replace(Err(error.clone()));
                }
                let invalid_query = matches!(&error, ChatListWindowError::Query(_));
                if let Some(command) = command {
                    let _ = command.reply.send(Err(error));
                }
                if invalid_query {
                    // Internal query/cursor invariants cannot recover through retries.
                    return;
                }
                dirty = true;
                failed = true;
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
