//! Frozen complete fixed-view intent, never a second display/presentation cache.
use super::{ChatListView, MarmotAppRuntime, wait_for_runtime_shutdown};
use crate::AppError;
use std::sync::Arc;
use storage_sqlite::{ChatListSelectionSnapshot, SqliteAccountStorage};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

#[derive(Debug, thiserror::Error)]
pub enum ChatSelectionError {
    #[error("chat selection is closed")]
    Closed,
    #[error("chat selection changed; use the current revision")]
    StaleRevision,
    #[error(transparent)]
    Selection(#[from] storage_sqlite::ChatListSelectionError),
    #[error(transparent)]
    App(#[from] AppError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatSelectionSummary {
    pub revision: u64,
    pub count: u64,
}

/// IDs are account-local. Debug deliberately reports only aggregate values.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatSelectionPage {
    pub summary: ChatSelectionSummary,
    pub group_ids: Vec<String>,
}
impl std::fmt::Debug for ChatSelectionPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSelectionPage")
            .field("summary", &self.summary)
            .field("page_count", &self.group_ids.len())
            .finish()
    }
}

struct Command {
    revision: Option<u64>,
    action: Action,
    reply: oneshot::Sender<Result<ChatSelectionPage, ChatSelectionError>>,
}
enum Action {
    Count,
    Page { offset: usize, limit: usize },
    Deselect(String),
    Revalidate,
}
struct State {
    snapshot: ChatListSelectionSnapshot,
    revision: u64,
}

/// Drop or close releases intent. All commands serialize; late results after
/// shutdown, account reset or explicit close are discarded, not rebound.
#[derive(Clone)]
pub struct ChatListSelectionHandle {
    commands: mpsc::Sender<Command>,
    closing: Arc<watch::Sender<bool>>,
}
impl ChatListSelectionHandle {
    pub async fn count(&self) -> Result<ChatSelectionSummary, ChatSelectionError> {
        Ok(self.send(None, Action::Count).await?.summary)
    }
    pub async fn page(
        &self,
        revision: u64,
        offset: usize,
        limit: usize,
    ) -> Result<ChatSelectionPage, ChatSelectionError> {
        self.send(Some(revision), Action::Page { offset, limit })
            .await
    }
    pub async fn deselect(
        &self,
        revision: u64,
        group_id_hex: &str,
    ) -> Result<ChatSelectionSummary, ChatSelectionError> {
        let id = crate::ids::normalize_group_id_hex_app(group_id_hex)?;
        Ok(self
            .send(Some(revision), Action::Deselect(id))
            .await?
            .summary)
    }
    /// Remove only IDs no longer in the captured view. Commands still enforce
    /// their own mutation preconditions; this is not an authorization grant.
    pub async fn revalidate(
        &self,
        revision: u64,
    ) -> Result<ChatSelectionSummary, ChatSelectionError> {
        Ok(self.send(Some(revision), Action::Revalidate).await?.summary)
    }
    pub fn close(&self) {
        self.closing.send_replace(true);
    }
    async fn send(
        &self,
        revision: Option<u64>,
        action: Action,
    ) -> Result<ChatSelectionPage, ChatSelectionError> {
        if *self.closing.borrow() {
            return Err(ChatSelectionError::Closed);
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command {
                revision,
                action,
                reply,
            })
            .await
            .map_err(|_| ChatSelectionError::Closed)?;
        let result = result.await.map_err(|_| ChatSelectionError::Closed)?;
        if *self.closing.borrow() {
            return Err(ChatSelectionError::Closed);
        }
        result
    }
}

impl MarmotAppRuntime {
    /// Complete Chats/Unread/Archived/Left selection independent of the screen
    /// window. This entry point does not implement automatic folder predicates.
    pub async fn capture_chat_list_selection(
        &self,
        account_ref: &str,
        view: ChatListView,
    ) -> Result<ChatListSelectionHandle, ChatSelectionError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let mut resets = self
            .accounts
            .app
            .presentation_signals
            .account_resets
            .subscribe();
        let app = self.accounts.app.clone();
        let label = account.label.clone();
        let capture = tokio::task::spawn_blocking(move || {
            let current = app.account_home().account(&label).map_err(AppError::from)?;
            if current.account_id_hex != account.account_id_hex {
                return Err(ChatSelectionError::Closed);
            }
            let store = app.account_storage(&label)?;
            crate::chat_presentation::maintenance::prepare_base_rows(
                &store,
                &account.account_id_hex,
            )?;
            let snapshot = store.chat_list_selection_snapshot(view).inspect_err(|_| {
                app.presentation_signals.wake();
            })?;
            Ok::<_, ChatSelectionError>((store, snapshot))
        });
        let (store, snapshot) = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return Err(ChatSelectionError::Closed),
            _ = wait_for_reset(&mut resets, &account.label) => return Err(ChatSelectionError::Closed),
            result = capture => result.map_err(|e| AppError::BlockingTask(e.to_string()))??,
        };
        // Subscribe before capture, and recheck all terminal signals before publishing.
        self.shared.lifecycle().ensure_running()?;
        if reset_observed(&mut resets, &account.label) {
            return Err(ChatSelectionError::Closed);
        }
        let (commands, receiver) = mpsc::channel(8);
        let (closing, close_rx) = watch::channel(false);
        tokio::spawn(run(
            store,
            State {
                snapshot,
                revision: 0,
            },
            receiver,
            stopping,
            resets,
            account.label,
            close_rx,
        ));
        Ok(ChatListSelectionHandle {
            commands,
            closing: Arc::new(closing),
        })
    }
}

async fn run(
    store: SqliteAccountStorage,
    mut state: State,
    mut commands: mpsc::Receiver<Command>,
    mut stopping: watch::Receiver<bool>,
    mut resets: broadcast::Receiver<String>,
    label: String,
    mut closing: watch::Receiver<bool>,
) {
    loop {
        let command = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut closing) => return,
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = wait_for_reset(&mut resets, &label) => return,
            command = commands.recv() => match command { Some(c) => c, None => return },
        };
        // A caller cancelled while waiting for admission never mutates intent.
        if command.reply.is_closed() {
            continue;
        }
        if command.revision.is_some_and(|r| r != state.revision) {
            let _ = command.reply.send(Err(ChatSelectionError::StaleRevision));
            continue;
        }
        let storage = store.clone();
        let action = command.action;
        let task = tokio::task::spawn_blocking(move || {
            let result = apply(&storage, &mut state, action);
            (state, result)
        });
        let (next, result) = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut closing) => return,
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = wait_for_reset(&mut resets, &label) => return,
            result = task => match result { Ok(value) => value, Err(_) => return },
        };
        state = next;
        // Queued resets cannot be missed when the blocking task wins the wake race.
        if *closing.borrow() || *stopping.borrow() || reset_observed(&mut resets, &label) {
            return;
        }
        let _ = command.reply.send(result);
    }
}

fn apply(
    store: &SqliteAccountStorage,
    state: &mut State,
    action: Action,
) -> Result<ChatSelectionPage, ChatSelectionError> {
    let mut ids = Vec::new();
    match action {
        Action::Count => {}
        Action::Page { offset, limit } => {
            ids = store.chat_list_selection_page(&state.snapshot, offset, limit)?;
        }
        Action::Deselect(id) => {
            if store.deselect_chat_list_selection_id(&mut state.snapshot, &id)? {
                state.revision = state
                    .revision
                    .checked_add(1)
                    .ok_or(ChatSelectionError::Closed)?;
            }
        }
        Action::Revalidate => {
            let next = store.revalidate_chat_list_selection(&state.snapshot)?;
            // Every action-validation result supersedes previously paged action intent,
            // even when the count stayed the same. No old page can be spliced into it.
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(ChatSelectionError::Closed)?;
            state.snapshot = next;
        }
    }
    Ok(ChatSelectionPage {
        summary: ChatSelectionSummary {
            revision: state.revision,
            count: store.chat_list_selection_count(&state.snapshot)? as u64,
        },
        group_ids: ids,
    })
}

fn reset_observed(resets: &mut broadcast::Receiver<String>, label: &str) -> bool {
    loop {
        match resets.try_recv() {
            Ok(reset) if reset == label => return true,
            Ok(_) => {}
            Err(broadcast::error::TryRecvError::Empty) => return false,
            Err(_) => return true,
        }
    }
}
async fn wait_for_reset(resets: &mut broadcast::Receiver<String>, label: &str) {
    loop {
        match resets.recv().await {
            Ok(reset) if reset == label => return,
            Err(_) => return,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
