//! Opaque C handles over the `marmot-uniffi` subscription objects.
//!
//! Each `marmot_subscribe_*` function returns an opaque handle wrapping the
//! `Arc`'d uniffi subscription plus a handle to the client's tokio runtime.
//! Consumers drive it one of two ways:
//!
//! - **Blocking:** `marmot_*_subscription_next(sub, timeout_ms, out)`
//!   blocks the calling thread. `timeout_ms == 0` waits indefinitely; a
//!   nonzero timeout that elapses returns `MARMOT_STATUS_TIMEOUT` (out is
//!   NULL). A closed stream (runtime shutdown / sender dropped) returns
//!   `MARMOT_STATUS_CLOSED`; no further items will ever be produced.
//! - **Callbacks:** `marmot_*_subscription_set_callback(sub, cb, user_data)`
//!   spawns a runtime task that invokes `cb` with a *borrowed* item pointer
//!   valid only for the duration of the call, then a final NULL item when
//!   the stream closes. Callbacks run on runtime worker threads; `user_data`
//!   must be safe to touch from another thread. Clearing the callback (or
//!   freeing the handle) cancels the task at its next await point — an
//!   in-flight callback always runs to completion first.
//!
//! Do not mix blocking reads and an installed callback on the same handle:
//! both compete for the same inner receiver and items go to whichever wins.
//!
//! Lifetime rule (documented in the header): free every subscription handle
//! before freeing the `MarmotClient` that created it.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use marmot_uniffi::subscriptions::{
    AgentStreamSubscription, ChatListSubscription, ChatsSubscription, EventsSubscription,
    GroupStateSubscription, MessagesSubscription, NotificationsSubscription,
    TimelineMessagesSubscription,
};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::MarmotStatus;
use crate::commands::deliver;
use crate::memory::{
    CFree, boxed, free_boxed, free_c_string, optional_str, owned_c_string, required_str,
};
use crate::status::{set_last_error, status_from_error};
use crate::types::agent_stream::MarmotAgentStreamUpdate;
use crate::types::chat_list::{
    MarmotChatListRow, MarmotChatListRowList, MarmotChatListSubscriptionUpdate,
};
use crate::types::event::MarmotEvent;
use crate::types::group::{MarmotAppGroupRecord, MarmotAppGroupRecordList};
use crate::types::message::{MarmotAppMessageRecordList, MarmotMessageUpdate};
use crate::types::notification::MarmotNotificationUpdate;
use crate::types::timeline::{MarmotTimelinePage, MarmotTimelineSubscriptionUpdate};
use crate::{MarmotClient, client_ref, ffi_guard, write_out};

/// `user_data` travels into a tokio task; the C caller owns its thread
/// safety (documented on every `set_callback`).
struct CallbackCtx {
    user_data: *mut c_void,
}
unsafe impl Send for CallbackCtx {}

impl CallbackCtx {
    /// Accessor (rather than a direct field read) so the callback pump's
    /// async block captures the whole `CallbackCtx` — which carries the
    /// `Send` justification — instead of precise-capturing the bare
    /// `*mut c_void` field, which is not `Send`.
    fn user_data(&self) -> *mut c_void {
        self.user_data
    }
}

// The callback pump moves each mirror item into a runtime worker task
// before handing C a borrowed pointer. Mirror types contain raw pointers
// only to allocations the value exclusively owns, so moving one across
// threads is sound. (`MarmotEvent` carries the same impl in its own
// module.)
unsafe impl Send for MarmotTimelinePage {}
unsafe impl Send for MarmotNotificationUpdate {}
unsafe impl Send for MarmotAppGroupRecord {}
unsafe impl Send for MarmotChatListRow {}
unsafe impl Send for MarmotMessageUpdate {}
unsafe impl Send for MarmotAgentStreamUpdate {}

/// Shared body of every subscription handle: the runtime that drives it
/// and the slot holding an installed callback task.
struct SubscriptionCore {
    runtime: Handle,
    callback_task: StdMutex<Option<JoinHandle<()>>>,
}

impl SubscriptionCore {
    fn new(runtime: Handle) -> Self {
        Self {
            runtime,
            callback_task: StdMutex::new(None),
        }
    }

    /// Block on `fut` with the subscription timeout convention:
    /// `Ok(Some(item))` on data, `Err(Timeout)` on elapse, `Ok(None)` on
    /// closed stream.
    fn block_next<T>(
        &self,
        timeout_ms: u32,
        fut: impl Future<Output = Option<T>>,
    ) -> Result<Option<T>, MarmotStatus> {
        if timeout_ms == 0 {
            return Ok(self.runtime.block_on(fut));
        }
        let duration = Duration::from_millis(u64::from(timeout_ms));
        match self
            .runtime
            .block_on(async { tokio::time::timeout(duration, fut).await })
        {
            Ok(item) => Ok(item),
            Err(_elapsed) => Err(MarmotStatus::Timeout),
        }
    }

    /// Reserve the callback slot, then spawn the pump under the lock. Taking
    /// the slot before spawning means a rejected second install never starts
    /// a pump that races the receiver (and immediately gets aborted). The
    /// `spawn` closure receives the runtime handle to spawn onto.
    fn install(&self, spawn: impl FnOnce(&Handle) -> JoinHandle<()>) -> MarmotStatus {
        let mut slot = self
            .callback_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.as_ref().is_some_and(|t| !t.is_finished()) {
            set_last_error("a callback is already installed on this subscription");
            return MarmotStatus::Runtime;
        }
        *slot = Some(spawn(&self.runtime));
        MarmotStatus::Ok
    }

    /// Cancel the callback task, if any, at its next await point.
    fn clear(&self) {
        let task = self
            .callback_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.abort();
        }
    }
}

impl Drop for SubscriptionCore {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Deliver one blocking-next result through an out-pointer using the
/// OK / TIMEOUT / CLOSED convention. `out` receives NULL on both
/// non-item outcomes.
unsafe fn deliver_next<TFfi, TMirror>(
    result: Result<Option<TFfi>, MarmotStatus>,
    out: *mut *mut TMirror,
) -> MarmotStatus
where
    TMirror: From<TFfi> + CFree,
{
    if out.is_null() {
        set_last_error("out-pointer argument was NULL");
        return MarmotStatus::NullPointer;
    }
    match result {
        Ok(Some(item)) => {
            unsafe { out.write(boxed(TMirror::from(item))) };
            MarmotStatus::Ok
        }
        Ok(None) => {
            unsafe { out.write(std::ptr::null_mut()) };
            MarmotStatus::Closed
        }
        Err(status) => {
            unsafe { out.write(std::ptr::null_mut()) };
            status
        }
    }
}

/// Spawn the callback pump: convert each item to its mirror, hand the C
/// callback a borrowed pointer, deep-free after it returns, and finish
/// with a NULL-item terminal call when the stream closes.
fn spawn_callback_pump<TFfi, TMirror, F, Fut>(
    runtime: &Handle,
    ctx: CallbackCtx,
    callback: unsafe extern "C" fn(item: *const TMirror, user_data: *mut c_void),
    mut next: F,
) -> JoinHandle<()>
where
    TFfi: Send + 'static,
    TMirror: From<TFfi> + CFree + Send + 'static,
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Option<TFfi>> + Send,
{
    runtime.spawn(async move {
        loop {
            match next().await {
                Some(item) => {
                    let mut mirror = TMirror::from(item);
                    // Borrowed for the duration of the call only.
                    unsafe { callback(&raw const mirror, ctx.user_data()) };
                    unsafe { mirror.free_in_place() };
                }
                None => {
                    unsafe { callback(std::ptr::null(), ctx.user_data()) };
                    break;
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Events subscription (top-level firehose)
// ---------------------------------------------------------------------------

/// Opaque handle to the top-level event firehose: one subscription, every
/// account, every event type. Broadcast lag is skipped silently — catch
/// back up via the per-account subscriptions.
pub struct MarmotEventsSubscription {
    core: SubscriptionCore,
    inner: Arc<EventsSubscription>,
}

/// Callback invoked with each event (borrowed; valid only during the
/// call) and finally with NULL when the stream closes.
pub type MarmotEventCallback =
    Option<unsafe extern "C" fn(event: *const MarmotEvent, user_data: *mut c_void)>;

/// Subscribe to the event firehose. Free with
/// `marmot_events_subscription_free` (before freeing the client).
///
/// # Safety
/// `client` must be a live handle; `out_sub` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_events(
    client: *const MarmotClient,
    out_sub: *mut *mut MarmotEventsSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let handle = MarmotEventsSubscription {
            core: SubscriptionCore::new(client.runtime.handle().clone()),
            inner: client.marmot.subscribe_events(),
        };
        let raw = boxed(handle);
        match unsafe { write_out(out_sub, raw) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                unsafe { free_plain(raw) };
                status
            }
        }
    })
}

/// Block until the next event, the timeout, or stream close.
/// `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out
/// set; free with `marmot_event_free`), `MARMOT_STATUS_TIMEOUT`, or
/// `MARMOT_STATUS_CLOSED` (out NULL for both).
///
/// # Safety
/// `sub` must be a live handle from `marmot_subscribe_events`;
/// `out_event` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_events_subscription_next(
    sub: *const MarmotEventsSubscription,
    timeout_ms: u32,
    out_event: *mut *mut MarmotEvent,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_event) }
    })
}

/// Install a callback pump for this subscription. `callback` runs on a
/// runtime worker thread with a borrowed event pointer (valid only during
/// the call; do not store or free it) and a final NULL event on close.
/// `user_data` must be safe to use from another thread. Fails if a
/// callback is already installed.
///
/// # Safety
/// `sub` must be a live handle; `callback` must be a valid function
/// pointer; `user_data` must remain valid until the callback is cleared
/// or the handle freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_events_subscription_set_callback(
    sub: *const MarmotEventsSubscription,
    callback: MarmotEventCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any. An in-flight
/// callback completes before the pump stops; no further calls follow.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_events_subscription_clear_callback(
    sub: *const MarmotEventsSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_subscribe_events`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_events_subscription_free(sub: *mut MarmotEventsSubscription) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Timeline messages subscription (snapshot + next + next_update + paginate)
// ---------------------------------------------------------------------------

/// Opaque handle to one conversation's materialized timeline window.
/// `next` returns the full authoritative window after each update;
/// `next_update` returns the raw delta; pagination extends the window
/// without blocking a concurrent `next`.
pub struct MarmotTimelineSubscription {
    core: SubscriptionCore,
    inner: Arc<TimelineMessagesSubscription>,
}

/// Callback invoked with each full timeline window (borrowed) and a final
/// NULL page on close.
pub type MarmotTimelinePageCallback =
    Option<unsafe extern "C" fn(page: *const MarmotTimelinePage, user_data: *mut c_void)>;

/// Subscribe to live materialized timeline updates for a group
/// (`group_id_hex` non-NULL) or the account-wide tail (NULL). `has_limit`
/// plus `limit` cap the initial window. Free with
/// `marmot_timeline_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `group_id_hex` NULL or a valid string; `out_sub` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_timeline_messages(
    client: *const MarmotClient,
    account_ref: *const std::ffi::c_char,
    group_id_hex: *const std::ffi::c_char,
    has_limit: bool,
    limit: u32,
    out_sub: *mut *mut MarmotTimelineSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let account_ref = match unsafe { required_str(account_ref) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let group_id_hex = match unsafe { optional_str(group_id_hex) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let limit = has_limit.then_some(limit);
        match client.block_on(client.marmot.subscribe_timeline_messages(
            account_ref,
            group_id_hex,
            limit,
        )) {
            Ok(inner) => {
                let handle = MarmotTimelineSubscription {
                    core: SubscriptionCore::new(client.runtime.handle().clone()),
                    inner,
                };
                let raw = boxed(handle);
                match unsafe { write_out(out_sub, raw) } {
                    Ok(()) => MarmotStatus::Ok,
                    Err(status) => {
                        unsafe { free_plain(raw) };
                        status
                    }
                }
            }
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial window snapshot. Yields the page exactly once: later
/// calls (or a snapshot already consumed by this handle) write NULL with
/// `MARMOT_STATUS_OK`. Free the page with `marmot_timeline_page_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_page` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_snapshot(
    sub: *const MarmotTimelineSubscription,
    out_page: *mut *mut MarmotTimelinePage,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let page = sub
            .inner
            .snapshot()
            .map_or(std::ptr::null_mut(), |p| boxed(MarmotTimelinePage::from(p)));
        match unsafe { write_out(out_page, page) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                unsafe { free_boxed(page) };
                status
            }
        }
    })
}

/// Block until the next live update and return the resulting full window
/// (already sorted, deduplicated, and capped — render directly). Same
/// OK / TIMEOUT / CLOSED convention as every subscription `next`. Free
/// with `marmot_timeline_page_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_page` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_next(
    sub: *const MarmotTimelineSubscription,
    timeout_ms: u32,
    out_page: *mut *mut MarmotTimelinePage,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_page) }
    })
}

/// Block until the next raw delta (page replacement or projection
/// update). Free with `marmot_timeline_subscription_update_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_update` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_next_update(
    sub: *const MarmotTimelineSubscription,
    timeout_ms: u32,
    out_update: *mut *mut MarmotTimelineSubscriptionUpdate,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next_update());
        unsafe { deliver_next(result, out_update) }
    })
}

/// Extend the window toward older history by up to `count` messages and
/// return the new window. Runs on the runtime off the caller's lock, so a
/// concurrent blocking `next` on another thread is not blocked. Free with
/// `marmot_timeline_page_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_page` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_paginate_backwards(
    sub: *const MarmotTimelineSubscription,
    count: u32,
    out_page: *mut *mut MarmotTimelinePage,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub
            .core
            .runtime
            .block_on(async move { inner.paginate_backwards(count).await });
        unsafe { deliver(result, out_page) }
    })
}

/// Extend the window toward the live head by up to `count` messages and
/// return the new window. Reaching the head re-anchors the window. Free
/// with `marmot_timeline_page_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_page` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_paginate_forwards(
    sub: *const MarmotTimelineSubscription,
    count: u32,
    out_page: *mut *mut MarmotTimelinePage,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub
            .core
            .runtime
            .block_on(async move { inner.paginate_forwards(count).await });
        unsafe { deliver(result, out_page) }
    })
}

/// Install a full-window callback pump (each call receives the borrowed
/// authoritative window; final NULL page on close). Same rules as
/// `marmot_events_subscription_set_callback`.
///
/// # Safety
/// Same as `marmot_events_subscription_set_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_set_callback(
    sub: *const MarmotTimelineSubscription,
    callback: MarmotTimelinePageCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_clear_callback(
    sub: *const MarmotTimelineSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_subscribe_timeline_messages`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_free(sub: *mut MarmotTimelineSubscription) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Notifications subscription
// ---------------------------------------------------------------------------

/// Opaque handle to the notification pipeline: local-notification updates
/// produced by the runtime (foreground receipt, background collection, …).
pub struct MarmotNotificationsSubscription {
    core: SubscriptionCore,
    inner: Arc<NotificationsSubscription>,
}

/// Callback invoked with each notification update (borrowed; valid only
/// during the call) and finally with NULL when the stream closes.
pub type MarmotNotificationUpdateCallback =
    Option<unsafe extern "C" fn(update: *const MarmotNotificationUpdate, user_data: *mut c_void)>;

/// Subscribe to notification updates. Free with
/// `marmot_notifications_subscription_free` (before freeing the client).
///
/// # Safety
/// `client` must be a live handle; `out_sub` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_notifications(
    client: *const MarmotClient,
    out_sub: *mut *mut MarmotNotificationsSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        match client.block_on(client.marmot.subscribe_notifications()) {
            Ok(inner) => {
                let handle = MarmotNotificationsSubscription {
                    core: SubscriptionCore::new(client.runtime.handle().clone()),
                    inner,
                };
                let raw = boxed(handle);
                match unsafe { write_out(out_sub, raw) } {
                    Ok(()) => MarmotStatus::Ok,
                    Err(status) => {
                        unsafe { free_plain(raw) };
                        status
                    }
                }
            }
            Err(err) => status_from_error(&err),
        }
    })
}

/// Block until the next notification update, the timeout, or stream
/// close. `timeout_ms == 0` waits indefinitely. Returns
/// `MARMOT_STATUS_OK` (out set; free with
/// `marmot_notification_update_free`), `MARMOT_STATUS_TIMEOUT`, or
/// `MARMOT_STATUS_CLOSED` (out NULL for both).
///
/// # Safety
/// `sub` must be a live handle from `marmot_subscribe_notifications`;
/// `out_update` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_notifications_subscription_next(
    sub: *const MarmotNotificationsSubscription,
    timeout_ms: u32,
    out_update: *mut *mut MarmotNotificationUpdate,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_update) }
    })
}

/// Install a callback pump for this subscription. Same rules as
/// `marmot_events_subscription_set_callback`: borrowed item pointer,
/// runtime worker thread, final NULL on close, one callback at a time.
///
/// # Safety
/// Same as `marmot_events_subscription_set_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_notifications_subscription_set_callback(
    sub: *const MarmotNotificationsSubscription,
    callback: MarmotNotificationUpdateCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_notifications_subscription_clear_callback(
    sub: *const MarmotNotificationsSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_subscribe_notifications`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_notifications_subscription_free(
    sub: *mut MarmotNotificationsSubscription,
) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Chats subscription (per-account group projections)
// ---------------------------------------------------------------------------

/// Opaque handle to one account's chats list: an initial snapshot of every
/// group projection, then one record per projection change.
pub struct MarmotChatsSubscription {
    core: SubscriptionCore,
    inner: Arc<ChatsSubscription>,
}

/// Callback invoked with each group record (borrowed; valid only during
/// the call) and finally with NULL when the stream closes. Shared by the
/// chats and group-state subscriptions.
pub type MarmotAppGroupRecordCallback =
    Option<unsafe extern "C" fn(record: *const MarmotAppGroupRecord, user_data: *mut c_void)>;

/// Subscribe to one account's chats list. Emits whenever a group's
/// projection changes; `include_archived` widens the filter. Free with
/// `marmot_chats_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_sub` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_chats(
    client: *const MarmotClient,
    account_ref: *const std::ffi::c_char,
    include_archived: bool,
    out_sub: *mut *mut MarmotChatsSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let account_ref = match unsafe { required_str(account_ref) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        match client.block_on(client.marmot.subscribe_chats(account_ref, include_archived)) {
            Ok(inner) => {
                let handle = MarmotChatsSubscription {
                    core: SubscriptionCore::new(client.runtime.handle().clone()),
                    inner,
                };
                let raw = boxed(handle);
                match unsafe { write_out(out_sub, raw) } {
                    Ok(()) => MarmotStatus::Ok,
                    Err(status) => {
                        unsafe { free_plain(raw) };
                        status
                    }
                }
            }
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial chats snapshot. Yields the populated list exactly
/// once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`.
/// Free the list with `marmot_app_group_record_list_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_list` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chats_subscription_snapshot(
    sub: *const MarmotChatsSubscription,
    out_list: *mut *mut MarmotAppGroupRecordList,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let list = boxed(MarmotAppGroupRecordList::from(sub.inner.snapshot()));
        match unsafe { write_out(out_list, list) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                unsafe { free_boxed(list) };
                status
            }
        }
    })
}

/// Block until the next changed group record, the timeout, or stream
/// close. Same OK / TIMEOUT / CLOSED convention as every subscription
/// `next`. Free with `marmot_app_group_record_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_record` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chats_subscription_next(
    sub: *const MarmotChatsSubscription,
    timeout_ms: u32,
    out_record: *mut *mut MarmotAppGroupRecord,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_record) }
    })
}

/// Install a callback pump for this subscription. Same rules as
/// `marmot_events_subscription_set_callback`.
///
/// # Safety
/// Same as `marmot_events_subscription_set_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chats_subscription_set_callback(
    sub: *const MarmotChatsSubscription,
    callback: MarmotAppGroupRecordCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chats_subscription_clear_callback(
    sub: *const MarmotChatsSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_subscribe_chats`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chats_subscription_free(sub: *mut MarmotChatsSubscription) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Chat-list subscription (durable chat-list projection)
// ---------------------------------------------------------------------------

/// Opaque handle to one account's durable chat-list projection: an initial
/// row snapshot, then row upserts (`next`) or raw deltas including row
/// removals (`next_update`).
pub struct MarmotChatListSubscription {
    core: SubscriptionCore,
    inner: Arc<ChatListSubscription>,
}

/// Callback invoked with each upserted chat-list row (borrowed; valid only
/// during the call) and finally with NULL when the stream closes. Row
/// removals are skipped — use `marmot_chat_list_subscription_next_update`
/// polling to observe them.
pub type MarmotChatListRowCallback =
    Option<unsafe extern "C" fn(row: *const MarmotChatListRow, user_data: *mut c_void)>;

/// Subscribe to one account's durable chat-list projection. Free with
/// `marmot_chat_list_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_sub` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_chat_list(
    client: *const MarmotClient,
    account_ref: *const std::ffi::c_char,
    include_archived: bool,
    out_sub: *mut *mut MarmotChatListSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let account_ref = match unsafe { required_str(account_ref) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        match client.block_on(
            client
                .marmot
                .subscribe_chat_list(account_ref, include_archived),
        ) {
            Ok(inner) => {
                let handle = MarmotChatListSubscription {
                    core: SubscriptionCore::new(client.runtime.handle().clone()),
                    inner,
                };
                let raw = boxed(handle);
                match unsafe { write_out(out_sub, raw) } {
                    Ok(()) => MarmotStatus::Ok,
                    Err(status) => {
                        unsafe { free_plain(raw) };
                        status
                    }
                }
            }
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial chat-list snapshot. Yields the populated list exactly
/// once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`.
/// Free the list with `marmot_chat_list_row_list_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_list` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_snapshot(
    sub: *const MarmotChatListSubscription,
    out_list: *mut *mut MarmotChatListRowList,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let list = boxed(MarmotChatListRowList::from(sub.inner.snapshot()));
        match unsafe { write_out(out_list, list) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                unsafe { free_boxed(list) };
                status
            }
        }
    })
}

/// Block until the next upserted row, the timeout, or stream close.
/// Row-removal deltas are skipped internally — receive them via
/// `marmot_chat_list_subscription_next_update` instead. Free with
/// `marmot_chat_list_row_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_row` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_next(
    sub: *const MarmotChatListSubscription,
    timeout_ms: u32,
    out_row: *mut *mut MarmotChatListRow,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_row) }
    })
}

/// Block until the next raw chat-list delta (row upsert or removal). Free
/// with `marmot_chat_list_subscription_update_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_update` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_next_update(
    sub: *const MarmotChatListSubscription,
    timeout_ms: u32,
    out_update: *mut *mut MarmotChatListSubscriptionUpdate,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next_update());
        unsafe { deliver_next(result, out_update) }
    })
}

/// Install an upserted-row callback pump for this subscription. Same
/// rules as `marmot_events_subscription_set_callback`.
///
/// # Safety
/// Same as `marmot_events_subscription_set_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_set_callback(
    sub: *const MarmotChatListSubscription,
    callback: MarmotChatListRowCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_clear_callback(
    sub: *const MarmotChatListSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_subscribe_chat_list`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_free(sub: *mut MarmotChatListSubscription) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Messages subscription (per-group or account-wide)
// ---------------------------------------------------------------------------

/// Opaque handle to a message stream: an initial record snapshot, then one
/// message update per store change.
pub struct MarmotMessagesSubscription {
    core: SubscriptionCore,
    inner: Arc<MessagesSubscription>,
}

/// Callback invoked with each message update (borrowed; valid only during
/// the call) and finally with NULL when the stream closes.
pub type MarmotMessageUpdateCallback =
    Option<unsafe extern "C" fn(update: *const MarmotMessageUpdate, user_data: *mut c_void)>;

/// Subscribe to messages for a specific group (`group_id_hex` non-NULL)
/// or every message across the account (NULL). `has_limit` + `limit` cap
/// the initial snapshot to the latest N rows; live updates continue after
/// the snapshot. Free with `marmot_messages_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `group_id_hex` NULL or a valid string; `out_sub` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_messages(
    client: *const MarmotClient,
    account_ref: *const std::ffi::c_char,
    group_id_hex: *const std::ffi::c_char,
    has_limit: bool,
    limit: u32,
    out_sub: *mut *mut MarmotMessagesSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let account_ref = match unsafe { required_str(account_ref) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let group_id_hex = match unsafe { optional_str(group_id_hex) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let limit = has_limit.then_some(limit);
        match client.block_on(
            client
                .marmot
                .subscribe_messages(account_ref, group_id_hex, limit),
        ) {
            Ok(inner) => {
                let handle = MarmotMessagesSubscription {
                    core: SubscriptionCore::new(client.runtime.handle().clone()),
                    inner,
                };
                let raw = boxed(handle);
                match unsafe { write_out(out_sub, raw) } {
                    Ok(()) => MarmotStatus::Ok,
                    Err(status) => {
                        unsafe { free_plain(raw) };
                        status
                    }
                }
            }
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial message-record snapshot. Yields the populated list
/// exactly once: later calls write an EMPTY list, still with
/// `MARMOT_STATUS_OK`. Free the list with
/// `marmot_app_message_record_list_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_list` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_messages_subscription_snapshot(
    sub: *const MarmotMessagesSubscription,
    out_list: *mut *mut MarmotAppMessageRecordList,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let list = boxed(MarmotAppMessageRecordList::from(sub.inner.snapshot()));
        match unsafe { write_out(out_list, list) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                unsafe { free_boxed(list) };
                status
            }
        }
    })
}

/// Block until the next message update, the timeout, or stream close.
/// Same OK / TIMEOUT / CLOSED convention as every subscription `next`.
/// Free with `marmot_message_update_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_update` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_messages_subscription_next(
    sub: *const MarmotMessagesSubscription,
    timeout_ms: u32,
    out_update: *mut *mut MarmotMessageUpdate,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_update) }
    })
}

/// Install a callback pump for this subscription. Same rules as
/// `marmot_events_subscription_set_callback`.
///
/// # Safety
/// Same as `marmot_events_subscription_set_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_messages_subscription_set_callback(
    sub: *const MarmotMessagesSubscription,
    callback: MarmotMessageUpdateCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_messages_subscription_clear_callback(
    sub: *const MarmotMessagesSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_subscribe_messages`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_messages_subscription_free(sub: *mut MarmotMessagesSubscription) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Group-state subscription (one group's roster/profile/member changes)
// ---------------------------------------------------------------------------

/// Opaque handle to one group's state: an initial record snapshot, then
/// the full record after each member/profile/roster change.
pub struct MarmotGroupStateSubscription {
    core: SubscriptionCore,
    inner: Arc<GroupStateSubscription>,
}

/// Subscribe to member/profile/roster changes for one group. Free with
/// `marmot_group_state_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_sub` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_group_state(
    client: *const MarmotClient,
    account_ref: *const std::ffi::c_char,
    group_id_hex: *const std::ffi::c_char,
    out_sub: *mut *mut MarmotGroupStateSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let account_ref = match unsafe { required_str(account_ref) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let group_id_hex = match unsafe { required_str(group_id_hex) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        match client.block_on(
            client
                .marmot
                .subscribe_group_state(account_ref, group_id_hex),
        ) {
            Ok(inner) => {
                let handle = MarmotGroupStateSubscription {
                    core: SubscriptionCore::new(client.runtime.handle().clone()),
                    inner,
                };
                let raw = boxed(handle);
                match unsafe { write_out(out_sub, raw) } {
                    Ok(()) => MarmotStatus::Ok,
                    Err(status) => {
                        unsafe { free_plain(raw) };
                        status
                    }
                }
            }
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial group-record snapshot. Yields the record exactly
/// once: later calls (or a snapshot already consumed by this handle)
/// write NULL with `MARMOT_STATUS_OK`. Free the record with
/// `marmot_app_group_record_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_record` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_state_subscription_snapshot(
    sub: *const MarmotGroupStateSubscription,
    out_record: *mut *mut MarmotAppGroupRecord,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let record = sub.inner.snapshot().map_or(std::ptr::null_mut(), |r| {
            boxed(MarmotAppGroupRecord::from(r))
        });
        match unsafe { write_out(out_record, record) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                unsafe { free_boxed(record) };
                status
            }
        }
    })
}

/// Block until the group's next full record, the timeout, or stream
/// close. Same OK / TIMEOUT / CLOSED convention as every subscription
/// `next`. Free with `marmot_app_group_record_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_record` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_state_subscription_next(
    sub: *const MarmotGroupStateSubscription,
    timeout_ms: u32,
    out_record: *mut *mut MarmotAppGroupRecord,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_record) }
    })
}

/// Install a callback pump for this subscription. Same rules as
/// `marmot_events_subscription_set_callback`.
///
/// # Safety
/// Same as `marmot_events_subscription_set_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_state_subscription_set_callback(
    sub: *const MarmotGroupStateSubscription,
    callback: MarmotAppGroupRecordCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_state_subscription_clear_callback(
    sub: *const MarmotGroupStateSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_subscribe_group_state`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_state_subscription_free(
    sub: *mut MarmotGroupStateSubscription,
) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Agent stream subscription (live brokered QUIC text stream watch)
// ---------------------------------------------------------------------------

/// Opaque handle to a live agent-text-stream watch: incremental `Chunk`s,
/// then a terminal `Finished` / `Failed`, after which the stream closes.
/// Created by `marmot_watch_agent_text_stream`; the matching anchor/start
/// command is `marmot_start_agent_text_stream` in the commands layer.
pub struct MarmotAgentStreamSubscription {
    core: SubscriptionCore,
    inner: Arc<AgentStreamSubscription>,
}

/// Callback invoked with each agent-stream update (borrowed; valid only
/// during the call) and finally with NULL when the stream closes.
pub type MarmotAgentStreamUpdateCallback =
    Option<unsafe extern "C" fn(update: *const MarmotAgentStreamUpdate, user_data: *mut c_void)>;

/// Watch a live agent text stream over the brokered QUIC channel. Pass
/// `stream_id_hex = NULL` to follow the latest stream in the group (the
/// common case when reacting to an AgentStreamStarted event).
/// `server_cert_der` (+ `server_cert_der_len`) pins a self-signed broker
/// certificate; pass NULL with length 0 to use platform trust. The bytes
/// are copied — the caller keeps ownership. `insecure_local` is
/// loopback-only for testing. Free with
/// `marmot_agent_stream_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `stream_id_hex` NULL or a valid string; `server_cert_der`
/// NULL with length 0, or a pointer to `server_cert_der_len` valid bytes;
/// `out_sub` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_watch_agent_text_stream(
    client: *const MarmotClient,
    account_ref: *const std::ffi::c_char,
    group_id_hex: *const std::ffi::c_char,
    stream_id_hex: *const std::ffi::c_char,
    server_cert_der: *const u8,
    server_cert_der_len: usize,
    insecure_local: bool,
    out_sub: *mut *mut MarmotAgentStreamSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let account_ref = match unsafe { required_str(account_ref) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let group_id_hex = match unsafe { required_str(group_id_hex) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let stream_id_hex = match unsafe { optional_str(stream_id_hex) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let server_cert_der = if server_cert_der.is_null() {
            if server_cert_der_len != 0 {
                set_last_error("server_cert_der was NULL with nonzero length");
                return MarmotStatus::NullPointer;
            }
            None
        } else {
            Some(
                unsafe { std::slice::from_raw_parts(server_cert_der, server_cert_der_len) }
                    .to_vec(),
            )
        };
        match client.block_on(client.marmot.watch_agent_text_stream(
            account_ref,
            group_id_hex,
            stream_id_hex,
            server_cert_der,
            insecure_local,
        )) {
            Ok(inner) => {
                let handle = MarmotAgentStreamSubscription {
                    core: SubscriptionCore::new(client.runtime.handle().clone()),
                    inner,
                };
                let raw = boxed(handle);
                match unsafe { write_out(out_sub, raw) } {
                    Ok(()) => MarmotStatus::Ok,
                    Err(status) => {
                        unsafe { free_plain(raw) };
                        status
                    }
                }
            }
            Err(err) => status_from_error(&err),
        }
    })
}

/// The resolved stream id this watch is following (hex). Writes an owned
/// copy: free it with `marmot_string_free`.
///
/// # Safety
/// `sub` must be a live handle from `marmot_watch_agent_text_stream`;
/// `out_stream_id_hex` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_subscription_stream_id_hex(
    sub: *const MarmotAgentStreamSubscription,
    out_stream_id_hex: *mut *mut std::ffi::c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let ptr = owned_c_string(sub.inner.stream_id_hex());
        match unsafe { write_out(out_stream_id_hex, ptr) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                unsafe { free_c_string(ptr) };
                status
            }
        }
    })
}

/// Block until the next agent-stream update, the timeout, or stream
/// close. `Chunk`s arrive incrementally; a terminal `Finished` / `Failed`
/// precedes `MARMOT_STATUS_CLOSED`. Free with
/// `marmot_agent_stream_update_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_update` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_subscription_next(
    sub: *const MarmotAgentStreamSubscription,
    timeout_ms: u32,
    out_update: *mut *mut MarmotAgentStreamUpdate,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next());
        unsafe { deliver_next(result, out_update) }
    })
}

/// Install a callback pump for this subscription. Same rules as
/// `marmot_events_subscription_set_callback`.
///
/// # Safety
/// Same as `marmot_events_subscription_set_callback`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_subscription_set_callback(
    sub: *const MarmotAgentStreamSubscription,
    callback: MarmotAgentStreamUpdateCallback,
    user_data: *mut c_void,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        let Some(callback) = callback else {
            set_last_error("callback function pointer was NULL");
            return MarmotStatus::NullPointer;
        };
        let inner = sub.inner.clone();
        sub.core.install(|runtime| {
            spawn_callback_pump(runtime, CallbackCtx { user_data }, callback, move || {
                let inner = inner.clone();
                async move { inner.next().await }
            })
        })
    })
}

/// Cancel this subscription's callback pump, if any.
///
/// # Safety
/// `sub` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_subscription_clear_callback(
    sub: *const MarmotAgentStreamSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = match unsafe { sub_ref(sub) } {
            Ok(s) => s,
            Err(status) => return status,
        };
        sub.core.clear();
        MarmotStatus::Ok
    })
}

/// Free the subscription handle (cancels any callback pump). NULL is a
/// no-op. Must be freed before the client.
///
/// # Safety
/// `sub` must be NULL or an unfreed pointer from
/// `marmot_watch_agent_text_stream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_subscription_free(
    sub: *mut MarmotAgentStreamSubscription,
) {
    let _ = ffi_guard(|| {
        unsafe { free_plain(sub) };
        MarmotStatus::Ok
    });
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

/// Borrow-check a subscription handle argument.
pub(crate) unsafe fn sub_ref<'a, T>(sub: *const T) -> Result<&'a T, MarmotStatus> {
    if sub.is_null() {
        set_last_error("subscription handle was NULL");
        return Err(MarmotStatus::NullPointer);
    }
    Ok(unsafe { &*sub })
}

/// Free a handle allocated with `memory::boxed` whose type has no
/// `CFree` (opaque handles drop their contents via `Drop`).
pub(crate) unsafe fn free_plain<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }
    #[cfg(feature = "alloc-audit")]
    crate::memory::audit::on_free();
    drop(unsafe { Box::from_raw(ptr) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("build test runtime")
    }

    #[test]
    fn block_next_returns_data() {
        let rt = runtime();
        let core = SubscriptionCore::new(rt.handle().clone());
        assert_eq!(core.block_next(0, async { Some(42u32) }), Ok(Some(42)));
    }

    #[test]
    fn block_next_reports_closed_stream() {
        let rt = runtime();
        let core = SubscriptionCore::new(rt.handle().clone());
        let result: Result<Option<u32>, _> = core.block_next(0, async { None });
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn block_next_times_out() {
        let rt = runtime();
        let core = SubscriptionCore::new(rt.handle().clone());
        let result: Result<Option<u32>, _> = core.block_next(10, std::future::pending());
        assert_eq!(result, Err(MarmotStatus::Timeout));
    }

    #[test]
    fn install_reserves_slot_before_spawning() {
        let rt = runtime();
        let core = SubscriptionCore::new(rt.handle().clone());

        // First install occupies the slot with a task that never finishes.
        let first = core.install(|handle| handle.spawn(std::future::pending::<()>()));
        assert_eq!(first, MarmotStatus::Ok);

        // A second install must be rejected AND must not run its spawn
        // closure (the whole point of reserving before spawning).
        let spawned = AtomicBool::new(false);
        let second = core.install(|handle| {
            spawned.store(true, Ordering::SeqCst);
            handle.spawn(async {})
        });
        assert_eq!(second, MarmotStatus::Runtime);
        assert!(
            !spawned.load(Ordering::SeqCst),
            "spawn closure must not run when a callback is already installed"
        );

        core.clear();
    }

    #[test]
    fn install_accepts_again_after_clear() {
        let rt = runtime();
        let core = SubscriptionCore::new(rt.handle().clone());
        assert_eq!(
            core.install(|handle| handle.spawn(std::future::pending::<()>())),
            MarmotStatus::Ok
        );
        core.clear();
        assert_eq!(
            core.install(|handle| handle.spawn(std::future::pending::<()>())),
            MarmotStatus::Ok
        );
        core.clear();
    }
}
