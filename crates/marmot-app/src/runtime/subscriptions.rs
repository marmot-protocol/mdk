//! Runtime subscription handles, the materialized-timeline window, and the
//! [`MarmotAppRuntime`] builders that spawn their fan-out tasks.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};

use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START;
use cgka_traits::{GroupId, MessageId};
use serde::{Deserialize, Serialize};
use storage_sqlite::AppEventReplayCursor;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use transport_quic_stream::AgentTextStreamCrypto;

use super::event_routing::{
    chat_list_event_route, chat_list_trigger_from_event, projection_update_from_event,
    projection_update_matches_query, runtime_group_event_route, runtime_message_update_from_event,
    timeline_query_can_apply_projection_delta,
};
use super::{
    MESSAGE_SUBSCRIPTION_SEEN_ID_LIMIT, MarmotAppEvent, MarmotAppRuntime,
    MessageSubscriptionSeenIds, RuntimeAgentStreamMessage, RuntimeMessageReceived,
    RuntimeMessageUpdate, RuntimeProjectionUpdate, blocking_app_task, runtime_shutdown_requested,
    wait_for_runtime_shutdown,
};
use crate::ids::normalize_group_id_hex_app;
use crate::notifications;
use crate::{
    APP_RUNTIME_SUBSCRIPTION_BUFFER, AppError, AppGroupRecord, AppMessageQuery, AppMessageRecord,
    AppProjectionUpdate, ChatListRow, MAX_TIMELINE_LIMIT, MarmotApp, NotificationUpdate,
    ReceivedMessage, TimelineMessageChange, TimelineMessageQuery, TimelineMessageRecord,
    TimelinePage, TimelinePagination, TimelineUpdateTrigger,
};

pub struct RuntimeMessagesSubscription {
    pub snapshot: Vec<AppMessageRecord>,
    pub(crate) updates: mpsc::Receiver<RuntimeMessageUpdate>,
    pub(crate) stopping: watch::Receiver<bool>,
}

impl RuntimeMessagesSubscription {
    pub async fn recv(&mut self) -> Option<RuntimeMessageUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

// `Page` carries a fully hydrated `TimelinePage`, so the variant sizes
// differ — boxing either side would change the channel's public type
// and propagate through every consumer.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeTimelineMessageUpdate {
    Page { page: TimelinePage },
    Projection(RuntimeProjectionUpdate),
}

/// Maximum number of messages a timeline subscription keeps materialized at
/// once. Pagination grows the window up to this cap; once exceeded, the edge
/// opposite the one being extended is trimmed (loading older trims the newest,
/// loading newer trims the oldest). This centralizes the per-conversation
/// window the clients previously capped by hand.
///
/// Bounded by the store's single-query cap so the whole window can always be
/// re-materialized in one cursor query (e.g. on a broadcast-lag refresh)
/// without silently dropping rows off the scrolled-back edge.
pub(crate) const TIMELINE_WINDOW_LIMIT: usize = MAX_TIMELINE_LIMIT;

/// Re-materializes the timeline for a fixed account/group from the store.
/// Captures the owning [`MarmotApp`] and account label so the subscription can
/// run cursor queries off the caller thread without threading them through
/// every call site (and so tests can substitute an in-memory store).
pub(crate) type TimelineQueryFn =
    dyn Fn(TimelineMessageQuery) -> Result<TimelinePage, AppError> + Send + Sync;

/// Which side of the window a [`merge_timeline_window`] call extends. The cap
/// is enforced from the opposite edge.
#[derive(Clone, Copy)]
pub(crate) enum TimelineWindowEdge {
    Older,
    Newer,
}

/// Internal signal from a timeline subscription's background task to
/// [`RuntimeTimelineMessagesSubscription::recv`]. `Projection` carries a
/// delta-applicable update; `Refresh` asks the subscription to re-materialize
/// its current window from the store — used on broadcast lag and for queries
/// whose deltas cannot be applied incrementally (e.g. search-scoped windows).
pub(crate) enum TimelineSubscriptionSignal {
    // Boxed so the buffered channel does not reserve the full projection size
    // for every (mostly `Refresh`) slot. This enum is internal, so boxing
    // carries none of the public-type cost noted on `RuntimeTimelineMessageUpdate`.
    Projection(Box<RuntimeProjectionUpdate>),
    Refresh,
}

/// The mutable, materialized window plus everything needed to extend it. Lives
/// behind a `std::sync::Mutex` inside [`TimelineWindowHandle`] so the live
/// receiver and pagination mutate it through brief, non-overlapping critical
/// sections instead of serializing on one long-held lock. The mutex is never
/// held across an `.await`.
pub(crate) struct TimelineWindow {
    pub(crate) query: Arc<TimelineQueryFn>,
    pub(crate) base_query: TimelineMessageQuery,
    pub(crate) page: TimelinePage,
    pub(crate) window_limit: usize,
    /// Bumped on every window mutation (pagination, live apply, refresh install).
    /// A refresh captures this before its store read and re-checks it before
    /// installing, so a pagination that completes during the read is never rolled
    /// back by a stale refresh.
    pub(crate) generation: u64,
}

impl TimelineWindow {
    /// True when the window includes the live head, i.e. no messages exist
    /// after the newest loaded one. Derived from the page so it can never drift
    /// from `has_more_after`.
    fn anchored_to_head(&self) -> bool {
        !self.page.has_more_after
    }

    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// Cursor query that re-materializes the current window from the store.
    /// Anchored windows refresh the head; detached (scrolled-back) windows
    /// refresh the loaded range ending at the current newest message so the
    /// scroll position survives a broadcast lag instead of snapping to the head.
    /// Because the window is capped at the store's single-query limit, one query
    /// always reconstitutes it.
    pub(crate) fn refresh_query(&self) -> TimelineMessageQuery {
        let mut query = self.base_query.clone();
        let limit = self.page.messages.len().max(1);
        query.pagination = match self.page.messages.last() {
            // Detached: re-fetch the loaded range ending exactly at the newest
            // message using an *inclusive* upper-bound cursor. The store applies
            // the descending `LIMIT` against `<= (timeline_at, message_id_hex)`,
            // so newer same-second rows are excluded at the SQL level and can't
            // starve the window — no post-fetch trimming required.
            Some(newest) if !self.anchored_to_head() => TimelinePagination {
                before: Some(newest.timeline_at),
                before_message_id: Some(newest.message_id_hex.clone()),
                before_inclusive: true,
                limit: Some(limit),
                ..TimelinePagination::default()
            },
            // Anchored or empty: refresh the head.
            _ => TimelinePagination {
                limit: Some(limit),
                ..TimelinePagination::default()
            },
        };
        query
    }
}

/// A cloneable handle to a subscription's materialized window. Cloning shares
/// the same underlying window, so a client driving [`recv`] on a background task
/// can paginate through a separately-held clone of this handle without
/// contending on the live-update receiver lock. Window mutations take a brief
/// synchronous lock that is never held across the store read's `.await`.
#[derive(Clone)]
pub struct TimelineWindowHandle {
    pub(crate) inner: Arc<StdMutex<TimelineWindow>>,
}

impl TimelineWindowHandle {
    fn lock(&self) -> std::sync::MutexGuard<'_, TimelineWindow> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The current materialized window: sorted ascending, deduplicated, capped,
    /// with correct `has_more_before` / `has_more_after` flags. Render it
    /// directly — no client-side merging or windowing is required.
    pub fn snapshot(&self) -> TimelinePage {
        self.lock().page.clone()
    }

    /// Extend the window toward older history by up to `count` messages and
    /// return the updated window. A no-op (returns the current window) when no
    /// older messages exist. The store read runs off the caller thread.
    pub async fn paginate_backwards(&self, count: usize) -> Result<TimelinePage, AppError> {
        let (query_fn, query) = {
            let window = self.lock();
            if !window.page.has_more_before {
                return Ok(window.page.clone());
            }
            let Some(oldest) = window.page.messages.first() else {
                return Ok(window.page.clone());
            };
            let mut query = window.base_query.clone();
            query.pagination = TimelinePagination {
                before: Some(oldest.timeline_at),
                before_message_id: Some(oldest.message_id_hex.clone()),
                limit: Some(count),
                ..TimelinePagination::default()
            };
            (window.query.clone(), query)
        };
        let older = blocking_app_task(move || query_fn(query)).await?;
        let mut window = self.lock();
        let limit = window.window_limit;
        merge_timeline_window(&mut window.page, older, TimelineWindowEdge::Older, limit);
        window.bump_generation();
        Ok(window.page.clone())
    }

    /// Extend the window toward the live head by up to `count` messages and
    /// return the updated window. A no-op (returns the current window) when the
    /// window already includes the head. Reaching the head re-anchors the
    /// window (`has_more_after` becomes false).
    pub async fn paginate_forwards(&self, count: usize) -> Result<TimelinePage, AppError> {
        let (query_fn, query) = {
            let window = self.lock();
            if !window.page.has_more_after {
                return Ok(window.page.clone());
            }
            let Some(newest) = window.page.messages.last() else {
                return Ok(window.page.clone());
            };
            let mut query = window.base_query.clone();
            query.pagination = TimelinePagination {
                after: Some(newest.timeline_at),
                after_message_id: Some(newest.message_id_hex.clone()),
                limit: Some(count),
                ..TimelinePagination::default()
            };
            (window.query.clone(), query)
        };
        let newer = blocking_app_task(move || query_fn(query)).await?;
        let mut window = self.lock();
        let limit = window.window_limit;
        merge_timeline_window(&mut window.page, newer, TimelineWindowEdge::Newer, limit);
        window.bump_generation();
        Ok(window.page.clone())
    }

    /// Apply a delta-applicable projection to the window in place (honoring
    /// head-anchoring and the cap).
    fn apply_projection(&self, update: &AppProjectionUpdate) {
        let mut window = self.lock();
        let limit = window.window_limit;
        apply_projection_to_window(&mut window.page, update, limit);
        window.bump_generation();
    }

    /// Read the store handle, the refresh cursor, and the window generation the
    /// refresh is based on (so a stale install can be detected).
    pub(crate) fn refresh_request(&self) -> (Arc<TimelineQueryFn>, TimelineMessageQuery, u64) {
        let window = self.lock();
        (
            window.query.clone(),
            window.refresh_query(),
            window.generation,
        )
    }

    /// Replace the window with a freshly-materialized page and return it —
    /// unless the window changed while the refresh query ran. Pagination uses a
    /// different lock and can complete during the refresh's `.await`; installing
    /// the (now stale) refresh would roll that expansion back, so if the
    /// generation moved we keep the newer window and drop the refresh.
    pub(crate) fn install_refresh(&self, page: TimelinePage, generation: u64) -> TimelinePage {
        let mut window = self.lock();
        if window.generation != generation {
            return window.page.clone();
        }
        window.page = page;
        window.bump_generation();
        window.page.clone()
    }
}

/// A live subscription over one conversation's materialized timeline.
///
/// Holds the loaded window (via a shared [`TimelineWindowHandle`]) and a live
/// update stream. The window can be extended in either direction; live updates
/// and broadcast-lag refreshes mutate the same window through [`recv`](Self::recv).
/// The store remains the durable source of truth; this is the view.
pub struct RuntimeTimelineMessagesSubscription {
    pub(crate) window: TimelineWindowHandle,
    pub(crate) updates: mpsc::Receiver<TimelineSubscriptionSignal>,
    pub(crate) stopping: watch::Receiver<bool>,
}

impl RuntimeTimelineMessagesSubscription {
    /// The current materialized window. See [`TimelineWindowHandle::snapshot`].
    pub fn take_snapshot(&self) -> TimelinePage {
        self.window.snapshot()
    }

    /// A clone of this subscription's window handle. A client that drives
    /// [`recv`](Self::recv) on a background task paginates through this handle
    /// concurrently, without blocking on the live-update receiver.
    pub fn window_handle(&self) -> TimelineWindowHandle {
        self.window.clone()
    }

    /// Extend the window toward older history. See
    /// [`TimelineWindowHandle::paginate_backwards`].
    pub async fn paginate_backwards(&self, count: usize) -> Result<TimelinePage, AppError> {
        self.window.paginate_backwards(count).await
    }

    /// Extend the window toward the live head. See
    /// [`TimelineWindowHandle::paginate_forwards`].
    pub async fn paginate_forwards(&self, count: usize) -> Result<TimelinePage, AppError> {
        self.window.paginate_forwards(count).await
    }

    /// Await the next live update, applying it to the window before returning.
    /// While parked waiting for an update no window lock is held, so concurrent
    /// pagination through [`window_handle`](Self::window_handle) is never blocked.
    pub async fn recv(&mut self) -> Option<RuntimeTimelineMessageUpdate> {
        loop {
            let signal = tokio::select! {
                signal = self.updates.recv() => signal?,
                _ = wait_for_runtime_shutdown(&mut self.stopping) => return None,
            };
            match signal {
                TimelineSubscriptionSignal::Projection(update) => {
                    self.window.apply_projection(&update.update);
                    return Some(RuntimeTimelineMessageUpdate::Projection(*update));
                }
                TimelineSubscriptionSignal::Refresh => {
                    let (query_fn, query, generation) = self.window.refresh_request();
                    match blocking_app_task(move || query_fn(query)).await {
                        Ok(page) => {
                            let page = self.window.install_refresh(page, generation);
                            return Some(RuntimeTimelineMessageUpdate::Page { page });
                        }
                        // Transient store error on refresh: keep the existing
                        // window and wait for the next signal rather than
                        // surfacing a spurious empty page.
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

/// Sort a timeline by the canonical `(timeline_at, message_id_hex)` ascending
/// order the store and clients agree on.
fn sort_timeline_records(messages: &mut [TimelineMessageRecord]) {
    messages.sort_by(|left, right| {
        left.timeline_at
            .cmp(&right.timeline_at)
            .then_with(|| left.message_id_hex.cmp(&right.message_id_hex))
    });
}

/// Merge a freshly-queried page into `window` on the given edge, then enforce
/// the cap from the opposite edge. The single piece of windowing logic shared
/// by both pagination directions.
pub(crate) fn merge_timeline_window(
    window: &mut TimelinePage,
    incoming: TimelinePage,
    edge: TimelineWindowEdge,
    limit: usize,
) {
    let mut messages = std::mem::take(&mut window.messages);
    for message in incoming.messages {
        upsert_window_message(&mut messages, message);
    }
    sort_timeline_records(&mut messages);
    match edge {
        TimelineWindowEdge::Older => {
            // The older side now reflects whatever the store reported. The
            // newer side is unchanged unless the cap forces dropping the newest
            // rows, in which case a gap to the head opens.
            window.has_more_before = incoming.has_more_before;
            if messages.len() > limit {
                messages.truncate(limit);
                window.has_more_after = true;
            }
        }
        TimelineWindowEdge::Newer => {
            window.has_more_after = incoming.has_more_after;
            if messages.len() > limit {
                let overflow = messages.len() - limit;
                messages.drain(0..overflow);
                window.has_more_before = true;
            }
        }
    }
    window.messages = messages;
}

/// Apply a live projection delta to the window, honoring head-anchoring and the
/// cap. Edits/removes to already-loaded messages always apply; brand-new
/// messages append only when the window is anchored to the head (or fall at or
/// below the newest message of a detached window). A new head message arriving
/// while the window is scrolled back is dropped so the window stays put — the
/// client re-anchors via [`RuntimeTimelineMessagesSubscription::paginate_forwards`].
pub(crate) fn apply_projection_to_window(
    window: &mut TimelinePage,
    update: &AppProjectionUpdate,
    limit: usize,
) {
    let anchored = !window.has_more_after;
    // Canonical upper bound of the window is the pair `(timeline_at,
    // message_id_hex)`, not just the timestamp. A detached window must suppress
    // anything sorting strictly after this — including same-second messages with
    // a larger id, which `timeline_at`-only comparison would have admitted.
    let newest_key = window
        .messages
        .last()
        .map(|message| (message.timeline_at, message.message_id_hex.clone()));
    if update.timeline_changes.is_empty() {
        for message in &update.timeline_messages {
            insert_live_message(
                &mut window.messages,
                message.clone(),
                anchored,
                newest_key.as_ref(),
            );
        }
    } else {
        for change in &update.timeline_changes {
            match change {
                TimelineMessageChange::Upsert { message, .. } => {
                    insert_live_message(
                        &mut window.messages,
                        (**message).clone(),
                        anchored,
                        newest_key.as_ref(),
                    );
                }
                TimelineMessageChange::Remove { message_id_hex, .. } => {
                    window
                        .messages
                        .retain(|message| &message.message_id_hex != message_id_hex);
                }
            }
        }
    }
    sort_timeline_records(&mut window.messages);
    // Live growth only ever adds at or below the head, so trim the oldest rows
    // on overflow; the head boundary (`has_more_after`) is preserved.
    if window.messages.len() > limit {
        let overflow = window.messages.len() - limit;
        window.messages.drain(0..overflow);
        window.has_more_before = true;
    }
}

/// Apply one live upsert. Existing messages are replaced in place (edits,
/// reactions, delivery-state changes). A brand-new message is appended only when
/// the window is anchored to the head, or when it sorts at or below the detached
/// window's newest message in canonical `(timeline_at, message_id_hex)` order.
/// `newest_key` is `None` only for an empty window, where a detached window has
/// nothing in range and therefore suppresses (an anchored empty window still
/// appends, as the head).
fn insert_live_message(
    messages: &mut Vec<TimelineMessageRecord>,
    message: TimelineMessageRecord,
    anchored: bool,
    newest_key: Option<&(u64, String)>,
) {
    if let Some(existing) = messages
        .iter_mut()
        .find(|existing| existing.message_id_hex == message.message_id_hex)
    {
        *existing = message;
        return;
    }
    let within_window = newest_key.is_some_and(|(at, id)| {
        (message.timeline_at, message.message_id_hex.as_str()) <= (*at, id.as_str())
    });
    if anchored || within_window {
        messages.push(message);
    }
}

/// Insert or replace a message by id, preserving any others. Used when merging
/// store pages, where dedup matters but ordering is fixed up afterwards.
fn upsert_window_message(
    messages: &mut Vec<TimelineMessageRecord>,
    message: TimelineMessageRecord,
) {
    if let Some(existing) = messages
        .iter_mut()
        .find(|existing| existing.message_id_hex == message.message_id_hex)
    {
        *existing = message;
    } else {
        messages.push(message);
    }
}
pub struct RuntimeChatsSubscription {
    pub snapshot: Vec<AppGroupRecord>,
    updates: mpsc::Receiver<AppGroupRecord>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeChatsSubscription {
    pub async fn recv(&mut self) -> Option<AppGroupRecord> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeChatListSubscription {
    pub snapshot: Vec<ChatListRow>,
    updates: mpsc::Receiver<RuntimeChatListUpdate>,
    stopping: watch::Receiver<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeChatListUpdate {
    Row {
        trigger: ChatListUpdateTrigger,
        row: Box<ChatListRow>,
    },
    RemoveRow {
        trigger: ChatListUpdateTrigger,
        group_id_hex: String,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatListUpdateTrigger {
    NewGroup,
    NewLastMessage,
    LastMessageDeleted,
    ArchiveChanged,
    PendingConfirmationChanged,
    MembershipChanged,
    UnreadChanged,
    #[default]
    SnapshotRefresh,
    Removed,
}

impl ChatListUpdateTrigger {
    pub(crate) fn from_timeline_changes(changes: &[TimelineMessageChange]) -> Self {
        if changes.iter().any(|change| {
            matches!(
                change,
                TimelineMessageChange::Upsert {
                    trigger: TimelineUpdateTrigger::MessageDeleted,
                    ..
                }
            )
        }) {
            return Self::LastMessageDeleted;
        }
        if changes.iter().any(|change| {
            matches!(
                change,
                TimelineMessageChange::Upsert {
                    trigger: TimelineUpdateTrigger::NewMessage
                        | TimelineUpdateTrigger::AgentStreamStarted
                        | TimelineUpdateTrigger::AgentStreamFinished,
                    ..
                }
            )
        }) {
            return Self::NewLastMessage;
        }
        Self::SnapshotRefresh
    }
}

impl RuntimeChatListSubscription {
    pub async fn recv(&mut self) -> Option<RuntimeChatListUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeGroupStateSubscription {
    pub snapshot: AppGroupRecord,
    updates: mpsc::Receiver<AppGroupRecord>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeGroupStateSubscription {
    pub async fn recv(&mut self) -> Option<AppGroupRecord> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeNotificationsSubscription {
    updates: mpsc::Receiver<NotificationUpdate>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeNotificationsSubscription {
    pub async fn recv(&mut self) -> Option<NotificationUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeEventsSubscription {
    pub(crate) events: broadcast::Receiver<MarmotAppEvent>,
    pub(crate) stopping: watch::Receiver<bool>,
}

impl RuntimeEventsSubscription {
    pub async fn recv(&mut self) -> Option<MarmotAppEvent> {
        loop {
            tokio::select! {
                event = self.events.recv() => {
                    match event {
                        Ok(event) => return Some(event),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
                _ = wait_for_runtime_shutdown(&mut self.stopping) => return None,
            }
        }
    }
}

/// One update from watching a live agent text stream over QUIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeAgentStreamUpdate {
    /// An incremental text delta. `text` is the new fragment, not the full text.
    Chunk { seq: u64, text: String },
    /// A provisional stream status label. This is not final-answer text.
    Status { seq: u64, status: String },
    /// A provisional agent progress record. This is not final-answer text.
    Progress { seq: u64, text: String },
    /// A non-text stream record kept for diagnostics/future UI.
    Record {
        seq: u64,
        record_type: u8,
        text: String,
    },
    /// The stream closed cleanly; `text` is the complete transcript.
    Finished {
        text: String,
        transcript_hash_hex: String,
        chunk_count: u64,
    },
    /// The watch failed (connection/broker error).
    Failed { message: String },
}

#[derive(Clone, Debug, Default)]
pub struct AgentStreamWatchOptions {
    /// Watch a specific stream id; `None` watches the latest stream in the group.
    pub stream_id_hex: Option<String>,
    /// DER cert for a self-signed broker; `None` uses platform trust.
    pub server_cert_der: Option<Vec<u8>>,
    /// Loopback-only insecure trust, for local testing.
    pub insecure_local: bool,
}

#[derive(Clone, Debug)]
pub struct AgentTextStreamCryptoContext {
    pub account_id_hex: String,
    pub account_label: String,
    pub group_id: GroupId,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub crypto: AgentTextStreamCrypto,
    pub policy_max_plaintext_frame_len: Option<u32>,
}

/// A live agent-text-stream watch. Drains chunk/finished/failed updates from a
/// background QUIC subscription task.
pub struct RuntimeAgentStreamWatch {
    pub stream_id_hex: String,
    pub(crate) updates: mpsc::Receiver<RuntimeAgentStreamUpdate>,
    pub(crate) terminal: Option<oneshot::Receiver<RuntimeAgentStreamUpdate>>,
    pub(crate) abort: tokio::task::AbortHandle,
    pub(crate) stopping: watch::Receiver<bool>,
}

impl RuntimeAgentStreamWatch {
    pub async fn recv(&mut self) -> Option<RuntimeAgentStreamUpdate> {
        if let Some(mut terminal) = self.terminal.take() {
            return tokio::select! {
                biased;
                terminal = &mut terminal => {
                    self.updates.close();
                    while self.updates.try_recv().is_ok() {}
                    terminal.ok()
                }
                update = self.updates.recv() => {
                    self.terminal = Some(terminal);
                    update
                }
                _ = wait_for_runtime_shutdown(&mut self.stopping) => {
                    self.terminal = Some(terminal);
                    None
                }
            };
        }
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

impl Drop for RuntimeAgentStreamWatch {
    fn drop(&mut self) {
        // Cancel the background QUIC subscriber so dropping the watch handle
        // doesn't leak a task driving a (possibly hung) broker connection.
        self.abort.abort();
    }
}

impl MarmotAppRuntime {
    pub async fn subscribe_messages(
        &self,
        account_ref: &str,
        query: AppMessageQuery,
    ) -> Result<RuntimeMessagesSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let group_id_hex = query.group_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        // Lag recovery must NOT inherit the caller's initial-replay `limit`.
        // That limit caps the *initial* snapshot to the latest N rows; reusing
        // it here would reload only the latest N stored rows on lag, so a slow
        // subscriber with e.g. `limit: Some(1)` could still permanently lose
        // any messages between the last delivered id and that latest row. The
        // live path delivers every post-subscription message, so recovery must
        // reload the full group history (keeping the group filter) and rely on
        // `seen_message_ids` to dedupe what was already delivered. See #180.
        let recovery_query = messages_recovery_query(&query);
        let snapshot_query = query;
        let app_for_snapshot = app.clone();
        let account_label_for_snapshot = account_label.clone();
        let snapshot = blocking_app_task(move || {
            app_for_snapshot.messages_with_query(&account_label_for_snapshot, snapshot_query)
        })
        .await?;
        let mut seen_message_ids = MessageSubscriptionSeenIds::from_ids(
            snapshot
                .iter()
                .map(|message| message.message_id_hex.clone()),
            MESSAGE_SUBSCRIPTION_SEEN_ID_LIMIT,
        );
        // Pre-subscription watermark for lag recovery. `seen_message_ids` is a
        // BOUNDED LRU seeded only from the (possibly `limit`-capped) snapshot,
        // so it cannot, on its own, distinguish "older pre-subscription history
        // the caller never asked for" from "a genuinely new post-subscription
        // message". Without a watermark, the first broadcast lag re-reads the
        // full group history (recovery drops `limit`, see #180) and re-emits
        // every older row that isn't in the limited seen-set — so a mobile
        // caller using `limit: Some(25)` to avoid full-history replay gets the
        // entire back-history dumped as "live" updates on first lag.
        //
        // The store returns rows ascending by `(recorded_at, message_id_hex)`,
        // and a limited snapshot is the latest N of that order, so the snapshot's
        // last row is the newest message that existed at subscription time. Any
        // recovery row at or below this key is pre-existing history and must be
        // suppressed; only strictly-newer rows are genuinely missed live
        // messages worth re-emitting (still deduped via `seen_message_ids`).
        // `None` (empty snapshot) means no pre-existing history, so recovery
        // emits everything as before.
        let recovery_watermark: Option<AppEventReplayCursor> =
            snapshot.last().map(|message| AppEventReplayCursor {
                recorded_at: message.recorded_at,
                message_id_hex: message.message_id_hex.clone(),
                insert_order: message.insert_order,
            });
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => event,
                };
                let event = match event {
                    Ok(event) => event,
                    // On lag the receiver permanently lost any messages that
                    // overflowed the broadcast ring buffer. Re-read the message
                    // snapshot and re-emit anything we have not delivered yet,
                    // matching `subscribe_timeline_messages` / `subscribe_chat_list`,
                    // so a slow consumer cannot silently drop messages.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let app_for_lookup = app.clone();
                        let account_label_for_lookup = account_label.clone();
                        let account_id_for_lookup = account_id_hex.clone();
                        let query_for_lookup = recovery_query.clone();
                        let updates = match blocking_app_task(move || {
                            messages_recovery_updates(
                                &app_for_lookup,
                                &account_id_for_lookup,
                                &account_label_for_lookup,
                                query_for_lookup,
                            )
                        })
                        .await
                        {
                            Ok(updates) => updates,
                            Err(_) => continue,
                        };
                        for (row_cursor, update) in updates {
                            let message = update.message();
                            // Suppress pre-existing history at or below the
                            // subscription watermark. Recovery reloads the full
                            // group history (no `limit`), so without this a
                            // limited subscriber would receive every older row
                            // as a bogus "live" update on the first lag. Only
                            // messages strictly newer than the watermark are
                            // genuinely-missed live messages. The watermark and
                            // `row_cursor` are the SAME `AppEventReplayCursor` the
                            // recovery query ordered by, so the cut is exact.
                            if recovery_row_is_pre_subscription(
                                recovery_watermark.as_ref(),
                                &row_cursor,
                            ) {
                                continue;
                            }
                            let message_id = message.message_id_hex.clone();
                            if !message_id.is_empty() && !seen_message_ids.insert(message_id) {
                                continue;
                            }
                            if updates_tx.send(update).await.is_err() {
                                return;
                            }
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let Some(update) = runtime_message_update_from_event(event) else {
                    continue;
                };
                if update.account_id_hex() != account_id_hex {
                    continue;
                }
                let message = update.message();
                if group_id_hex.as_deref()
                    != Some(hex::encode(message.group_id.as_slice()).as_str())
                    && group_id_hex.is_some()
                {
                    continue;
                }
                if !seen_message_ids.insert(message.message_id_hex.clone()) {
                    continue;
                }
                if updates_tx.send(update).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeMessagesSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_timeline_messages(
        &self,
        account_ref: &str,
        query: TimelineMessageQuery,
    ) -> Result<RuntimeTimelineMessagesSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let group_id_hex = query.group_id_hex.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = {
            let _span = tracing::debug_span!(
                target: "marmot_app::runtime",
                "timeline_subscription_snapshot",
                method = "subscribe_timeline_messages"
            )
            .entered();
            app.timeline_messages_with_query(&account_label, query.clone())?
        };
        // The subscription owns the window, so the re-query base carries only the
        // durable filter (group + search); pagination is supplied per call.
        let base_query = TimelineMessageQuery {
            group_id_hex: query.group_id_hex.clone(),
            search: query.search.clone(),
            pagination: TimelinePagination::default(),
        };
        // Deltas are applicable iff the base query is an unfiltered, unpaginated
        // tail. Search-scoped windows cannot be reconstructed from a projection
        // delta, so they trigger a window refresh instead.
        let deltas_applicable = timeline_query_can_apply_projection_delta(&base_query);
        let query_fn: Arc<TimelineQueryFn> =
            Arc::new(move |query| app.timeline_messages_with_query(&account_label, query));
        let window = TimelineWindowHandle {
            inner: Arc::new(StdMutex::new(TimelineWindow {
                query: query_fn,
                base_query,
                page: snapshot,
                window_limit: TIMELINE_WINDOW_LIMIT,
                generation: 0,
            })),
        };
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => event,
                };
                let event = match event {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // We may have missed projections; ask the subscription to
                        // re-materialize its current window (head or scrolled-back).
                        if updates_tx
                            .send(TimelineSubscriptionSignal::Refresh)
                            .await
                            .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let Some(update) = projection_update_from_event(&event) else {
                    continue;
                };
                if !projection_update_matches_query(
                    update,
                    &account_id_hex,
                    group_id_hex.as_deref(),
                ) {
                    continue;
                }
                let signal = if deltas_applicable {
                    TimelineSubscriptionSignal::Projection(Box::new(update.clone()))
                } else {
                    TimelineSubscriptionSignal::Refresh
                };
                if updates_tx.send(signal).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeTimelineMessagesSubscription {
            window,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_chats(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<RuntimeChatsSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = if include_archived {
            app.groups(&account_label)?
        } else {
            app.visible_groups(&account_label)?
        };
        let mut group_fingerprints = snapshot
            .iter()
            .map(|group| {
                (
                    group.group_id_hex.clone(),
                    app_group_record_fingerprint(group),
                )
            })
            .collect::<HashMap<_, _>>();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => match event {
                        Ok(event) => event,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                };
                let Some((event_account_id_hex, group_id)) = runtime_group_event_route(&event)
                else {
                    continue;
                };
                if event_account_id_hex != account_id_hex {
                    continue;
                }
                let group_id_hex = hex::encode(group_id.as_slice());
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group_id_hex_for_lookup = group_id_hex.clone();
                if runtime_shutdown_requested(&stopping) {
                    return;
                }
                let group = match blocking_app_task(move || {
                    app_for_lookup.group(&account_label_for_lookup, &group_id_hex_for_lookup)
                })
                .await
                {
                    Ok(Some(group)) => group,
                    Ok(None) | Err(_) => {
                        group_fingerprints.remove(&group_id_hex);
                        continue;
                    }
                };
                if !include_archived && group.archived {
                    group_fingerprints.remove(&group_id_hex);
                    if updates_tx.send(group).await.is_err() {
                        return;
                    }
                    continue;
                }
                let fingerprint = app_group_record_fingerprint(&group);
                if group_fingerprints.get(&group.group_id_hex) == Some(&fingerprint) {
                    continue;
                }
                group_fingerprints.insert(group.group_id_hex.clone(), fingerprint);
                if updates_tx.send(group).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeChatsSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_chat_list(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<RuntimeChatListSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = {
            let _span = tracing::debug_span!(
                target: "marmot_app::runtime",
                "chat_list_subscription_snapshot",
                method = "subscribe_chat_list"
            )
            .entered();
            app.chat_list(&account_label, include_archived)?
        };
        let mut row_fingerprints = snapshot
            .iter()
            .map(|row| (row.group_id_hex.clone(), chat_list_row_fingerprint(row)))
            .collect::<HashMap<_, _>>();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => event,
                };
                let event = match event {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let app_for_lookup = app.clone();
                        let account_label_for_lookup = account_label.clone();
                        let rows = match blocking_app_task(move || {
                            app_for_lookup.chat_list(&account_label_for_lookup, include_archived)
                        })
                        .await
                        {
                            Ok(rows) => rows,
                            Err(_) => continue,
                        };
                        if !reconcile_chat_list_snapshot(
                            &updates_tx,
                            &mut row_fingerprints,
                            ChatListUpdateTrigger::SnapshotRefresh,
                            rows,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                if let Some(update) = projection_update_from_event(&event)
                    && update.account_id_hex == account_id_hex
                {
                    let Some(row) = update.update.chat_list_row.clone() else {
                        if !send_chat_list_remove_update(
                            &updates_tx,
                            &mut row_fingerprints,
                            update.update.chat_list_trigger,
                            &update.update.group_id_hex,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    };
                    if !include_archived && row.archived {
                        if !send_chat_list_remove_update(
                            &updates_tx,
                            &mut row_fingerprints,
                            update.update.chat_list_trigger,
                            &row.group_id_hex,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                    if !send_chat_list_row_update(
                        &updates_tx,
                        &mut row_fingerprints,
                        update.update.chat_list_trigger,
                        row,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
                let Some((event_account_id_hex, group_id)) = chat_list_event_route(&event) else {
                    continue;
                };
                if event_account_id_hex != account_id_hex {
                    continue;
                }
                let group_id_hex = hex::encode(group_id.as_slice());
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group_id_hex_for_lookup = group_id_hex.clone();
                if runtime_shutdown_requested(&stopping) {
                    return;
                }
                let row = match blocking_app_task(move || {
                    app_for_lookup
                        .refresh_chat_list_row(&account_label_for_lookup, &group_id_hex_for_lookup)
                })
                .await
                {
                    Ok(row) => row,
                    Err(_) => continue,
                };
                let Some(row) = row else {
                    if !send_chat_list_remove_update(
                        &updates_tx,
                        &mut row_fingerprints,
                        ChatListUpdateTrigger::SnapshotRefresh,
                        &group_id_hex,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                };
                if !include_archived && row.archived {
                    if !send_chat_list_remove_update(
                        &updates_tx,
                        &mut row_fingerprints,
                        ChatListUpdateTrigger::Removed,
                        &row.group_id_hex,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
                if !send_chat_list_row_update(
                    &updates_tx,
                    &mut row_fingerprints,
                    chat_list_trigger_from_event(&event),
                    row,
                )
                .await
                {
                    return;
                }
            }
        });
        Ok(RuntimeChatListSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_group_state(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<RuntimeGroupStateSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let group_id_hex = normalize_group_id_hex_app(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = app
            .group(&account_label, &group_id_hex)?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
        let mut last_fingerprint = app_group_record_fingerprint(&snapshot);
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => match event {
                        Ok(event) => event,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                };
                let Some((event_account_id_hex, event_group_id)) =
                    runtime_group_event_route(&event)
                else {
                    continue;
                };
                if event_account_id_hex != account_id_hex || event_group_id != &group_id {
                    continue;
                }
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group_id_hex_for_lookup = group_id_hex.clone();
                if runtime_shutdown_requested(&stopping) {
                    return;
                }
                let group = match blocking_app_task(move || {
                    app_for_lookup.group(&account_label_for_lookup, &group_id_hex_for_lookup)
                })
                .await
                {
                    Ok(Some(group)) => group,
                    Ok(None) | Err(_) => continue,
                };
                let fingerprint = app_group_record_fingerprint(&group);
                if fingerprint == last_fingerprint {
                    continue;
                }
                last_fingerprint = fingerprint;
                if updates_tx.send(group).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeGroupStateSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_notifications(&self) -> Result<RuntimeNotificationsSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let mut events = self.events.subscribe();
        let app = self.accounts.app.clone();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => event,
                };
                match event {
                    Ok(event) => {
                        match notifications::notification_update_from_event(&app, &event) {
                            Ok(Some(update)) => {
                                if updates_tx.send(update).await.is_err() {
                                    return;
                                }
                            }
                            Ok(None) | Err(AppError::NotificationsDisabled) => {}
                            Err(_) => {
                                tracing::warn!(
                                    target: "marmot_app::notifications",
                                    method = "subscribe_notifications",
                                    error_code = "notification_projection_skipped",
                                    "notification projection skipped",
                                );
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(RuntimeNotificationsSubscription {
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }
}

/// Build the lag-recovery query for `subscribe_messages` from the caller's
/// initial-replay `query`. Recovery keeps the group filter but drops `limit`:
/// the caller's `limit` is an *initial replay* cap on the latest N rows, while
/// recovery must reload the full group history so the existing
/// `seen_message_ids` set can re-emit every message missed during broadcast
/// lag — not just the latest N. Reusing the limit here would reintroduce #180
/// for any limited subscriber. See `subscribe_messages`.
pub(crate) fn messages_recovery_query(query: &AppMessageQuery) -> AppMessageQuery {
    AppMessageQuery {
        group_id_hex: query.group_id_hex.clone(),
        limit: None,
    }
}

/// True when a lag-recovery row is at or below the subscription's pre-existing
/// watermark — i.e. it existed at subscription time and must NOT be re-emitted
/// as a live update.
///
/// `watermark` is the [`AppEventReplayCursor`] of the newest message that
/// existed when the subscription was created (the last row of the ascending
/// snapshot; `None` for an empty snapshot). Because lag recovery drops the
/// caller's initial-replay `limit` and reloads the full group history (see
/// #180), a limited subscriber would otherwise receive every older row as a
/// bogus live update on the first lag. Both the watermark and the compared row
/// are the SAME `AppEventReplayCursor` the store orders by (#630, #736 boundary
/// contract 2), so the suppression boundary can never disagree with the recovery
/// query order — even for an unscoped (all-groups) subscription, where the
/// `insert_order` tiebreak distinguishes two groups' rows that share
/// `(recorded_at, message_id_hex)`. A row at or below the watermark is
/// pre-existing history (suppress); strictly-greater rows are genuinely-new
/// (emit). An empty watermark means there was no pre-existing history, so
/// nothing is suppressed.
pub(crate) fn recovery_row_is_pre_subscription(
    watermark: Option<&AppEventReplayCursor>,
    row: &AppEventReplayCursor,
) -> bool {
    match watermark {
        Some(watermark) => row <= watermark,
        None => false,
    }
}

/// Re-read the message projection on broadcast lag and rebuild the runtime
/// message updates a subscriber would have received. The caller filters these
/// through its `seen_message_ids` set so only genuinely-missed messages are
/// re-emitted. Kind-1200 agent-stream starts are reclassified as
/// `AgentStreamStarted`, matching the live forwarding path.
fn messages_recovery_updates(
    app: &MarmotApp,
    account_id_hex: &str,
    account_label: &str,
    query: AppMessageQuery,
) -> Result<Vec<(AppEventReplayCursor, RuntimeMessageUpdate)>, AppError> {
    let records = app.messages_with_query(account_label, query)?;
    let senders = records
        .iter()
        .map(|record| record.sender.clone())
        .collect::<Vec<_>>();
    let display_names = app
        .display_names_for_account_ids(&senders)
        .unwrap_or_default();
    let updates = records
        .into_iter()
        .filter_map(|record| {
            // Capture the replay cursor (incl. the LOCAL `insert_order`) before
            // the record is consumed into a `RuntimeMessageUpdate`, so the
            // watermark suppression compares the exact order the recovery query
            // produced (#630). `insert_order` is deliberately not carried on the
            // FFI-facing `ReceivedMessage`.
            let cursor = AppEventReplayCursor {
                recorded_at: record.recorded_at,
                message_id_hex: record.message_id_hex.clone(),
                insert_order: record.insert_order,
            };
            received_message_update_from_record(
                account_id_hex,
                account_label,
                record,
                &display_names,
            )
            .map(|update| (cursor, update))
        })
        .collect();
    Ok(updates)
}

/// Rebuild a `RuntimeMessageUpdate` from a stored projection row. Returns
/// `None` when the row carries an undecodable group id (it cannot be routed).
pub(crate) fn received_message_update_from_record(
    account_id_hex: &str,
    account_label: &str,
    record: AppMessageRecord,
    display_names: &HashMap<String, String>,
) -> Option<RuntimeMessageUpdate> {
    let group_id = GroupId::new(hex::decode(&record.group_id_hex).ok()?);
    let sender_display_name = display_names.get(&record.sender).cloned();
    let message = ReceivedMessage {
        message_id_hex: record.message_id_hex,
        // The projection does not retain the transport (outer-event) id; the
        // canonical app-message id above is what subscribers dedupe on.
        source_message_id_hex: String::new(),
        sender: record.sender,
        sender_display_name,
        group_id,
        source_epoch: record.source_epoch.unwrap_or(0),
        plaintext: record.plaintext,
        kind: record.kind,
        tags: record.tags,
        recorded_at: record.recorded_at,
    };
    let received = RuntimeMessageReceived {
        account_id_hex: account_id_hex.to_owned(),
        account_label: account_label.to_owned(),
        message,
    };
    if received.message.kind == MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
        Some(RuntimeMessageUpdate::AgentStreamStarted(
            RuntimeAgentStreamMessage {
                account_id_hex: received.account_id_hex,
                account_label: received.account_label,
                message: received.message,
            },
        ))
    } else {
        Some(RuntimeMessageUpdate::Message(received))
    }
}

fn app_group_record_fingerprint(group: &AppGroupRecord) -> String {
    serde_json::to_string(group).unwrap_or_else(|_| group.group_id_hex.clone())
}

pub(crate) fn chat_list_row_fingerprint(row: &ChatListRow) -> String {
    let mut stable = row.clone();
    stable.updated_at = 0;
    serde_json::to_string(&stable).unwrap_or_else(|_| row.group_id_hex.clone())
}

async fn send_chat_list_row_update(
    updates_tx: &mpsc::Sender<RuntimeChatListUpdate>,
    row_fingerprints: &mut HashMap<String, String>,
    trigger: ChatListUpdateTrigger,
    row: ChatListRow,
) -> bool {
    let fingerprint = chat_list_row_fingerprint(&row);
    if row_fingerprints.get(&row.group_id_hex) == Some(&fingerprint) {
        return true;
    }
    row_fingerprints.insert(row.group_id_hex.clone(), fingerprint);
    updates_tx
        .send(RuntimeChatListUpdate::Row {
            trigger,
            row: Box::new(row),
        })
        .await
        .is_ok()
}

pub(crate) async fn send_chat_list_remove_update(
    updates_tx: &mpsc::Sender<RuntimeChatListUpdate>,
    row_fingerprints: &mut HashMap<String, String>,
    trigger: ChatListUpdateTrigger,
    group_id_hex: &str,
) -> bool {
    if row_fingerprints.remove(group_id_hex).is_none() {
        return true;
    }
    updates_tx
        .send(RuntimeChatListUpdate::RemoveRow {
            trigger,
            group_id_hex: group_id_hex.to_owned(),
        })
        .await
        .is_ok()
}

pub(crate) async fn reconcile_chat_list_snapshot(
    updates_tx: &mpsc::Sender<RuntimeChatListUpdate>,
    row_fingerprints: &mut HashMap<String, String>,
    trigger: ChatListUpdateTrigger,
    rows: Vec<ChatListRow>,
) -> bool {
    let visible_group_ids = rows
        .iter()
        .map(|row| row.group_id_hex.clone())
        .collect::<HashSet<_>>();
    let removed_group_ids = row_fingerprints
        .keys()
        .filter(|group_id_hex| !visible_group_ids.contains(*group_id_hex))
        .cloned()
        .collect::<Vec<_>>();
    for group_id_hex in removed_group_ids {
        if !send_chat_list_remove_update(updates_tx, row_fingerprints, trigger, &group_id_hex).await
        {
            return false;
        }
    }
    for row in rows {
        if !send_chat_list_row_update(updates_tx, row_fingerprints, trigger, row).await {
            return false;
        }
    }
    true
}
