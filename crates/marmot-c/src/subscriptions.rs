//! Opaque C handles over the `marmot-uniffi` subscription objects.
//!
//! Each `marmot_subscribe_*` function returns an opaque handle wrapping
//! the `Arc`'d uniffi subscription plus a handle to the client's tokio
//! runtime. Consumers drive it one of two ways:
//!
//! - **Blocking:** `marmot_*_subscription_next(sub, timeout_ms, out)`
//!   blocks the calling thread. `timeout_ms == 0` waits indefinitely; a
//!   nonzero timeout that elapses returns `MARMOT_STATUS_TIMEOUT` (out is
//!   NULL). A closed stream (runtime shutdown / sender dropped) returns
//!   `MARMOT_STATUS_CLOSED`; no further items will ever be produced.
//! - **Callbacks:** `marmot_*_subscription_set_callback(sub, cb,
//!   user_data)` spawns a runtime task that invokes `cb` with a
//!   *borrowed* item pointer valid only for the duration of the call,
//!   then a final NULL item when the stream closes. Callbacks run on
//!   runtime worker threads, so `cb` and any access to `user_data` must
//!   be thread-safe.
//!
//!   **`user_data` lifetime — read carefully.** `clear_callback` and
//!   `*_subscription_free` only *request* cancellation: internally they
//!   call tokio's `JoinHandle::abort`, which is non-blocking. A callback
//!   already executing keeps running and can return after the clear/free
//!   call has returned. So clearing or freeing is **not** a
//!   synchronization point — `user_data` must outlive every possible
//!   callback invocation. To reclaim it safely, use your own
//!   synchronization: e.g. observe the terminal NULL-item call (or a
//!   quiescent flag) before freeing, or only free at process teardown.
//!
//!   The terminal NULL item arrives only when the stream closes on its
//!   own. `clear_callback` and `*_subscription_free` abort the pump, so
//!   after either call the terminal NULL item is never delivered. Do
//!   not wait for it on that path; use a quiescent flag or free at
//!   process teardown instead.
//!
//! Do not mix blocking reads and an installed callback on the same
//! handle: both compete for the same inner receiver.
//!
//! Lifetime rule: free every subscription handle before freeing the
//! `MarmotClient` that created it.

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
use crate::commands::{deliver, try_arg};
use crate::memory::{
    CFree, boxed, free_boxed, free_c_string, optional_str, owned_c_string, required_str,
};
use crate::status::{set_last_error, status_from_error};
use crate::types::agent_stream::MarmotAgentStreamUpdate;
use crate::types::chat_list::{
    MarmotChatListRow, MarmotChatListRowList, MarmotChatListSubscriptionUpdate,
};
use crate::types::event::MarmotEvent;
use crate::types::group::MarmotAppGroupRecord;
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
// threads is sound.
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

    /// Reserve the callback slot, then spawn the pump under the lock, so
    /// a rejected second install never starts a pump that races the
    /// receiver.
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

/// Write a freshly created handle through an out-pointer, reclaiming it
/// when the out-pointer is NULL.
unsafe fn write_handle<T>(handle: T, out: *mut *mut T) -> MarmotStatus {
    let raw = boxed(handle);
    match unsafe { write_out(out, raw) } {
        Ok(()) => MarmotStatus::Ok,
        Err(status) => {
            unsafe { free_plain(raw) };
            status
        }
    }
}

/// Generate one subscription handle's shared surface: the opaque handle
/// struct, callback type alias, and `next` / `set_callback` /
/// `clear_callback` / `free` entry points. Subscribe functions, snapshot
/// flavors, and extra methods stay hand-written per subscription.
macro_rules! c_subscription {
    (
        $(#[$m:meta])* $handle:ident($inner:ty),
        item $mirror:ident from $ffi:ty, item_free $item_free:literal,
        callback $cb:ident,
        next $next:ident,
        set_callback $set:ident,
        clear_callback $clear:ident,
        free $free:ident
    ) => {
        $(#[$m])*
        pub struct $handle {
            core: SubscriptionCore,
            inner: Arc<$inner>,
        }

        /// Callback invoked with each item (borrowed; valid only during
        /// the call) and finally with NULL when the stream closes.
        pub type $cb =
            Option<unsafe extern "C" fn(item: *const $mirror, user_data: *mut c_void)>;

        #[doc = concat!("Block until the next item, the timeout, or stream close. \
`timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `",
            $item_free, "`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).")]
        ///
        /// # Safety
        /// `sub` must be a live handle; `out` must be a valid pointer.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $next(
            sub: *const $handle,
            timeout_ms: u32,
            out: *mut *mut $mirror,
        ) -> MarmotStatus {
            ffi_guard(|| {
                let sub = try_arg!(unsafe { sub_ref(sub) });
                let inner = sub.inner.clone();
                let result = sub.core.block_next(timeout_ms, inner.next());
                unsafe { deliver_next(result, out) }
            })
        }

        /// Install a callback pump for this subscription. `callback` runs
        /// on a runtime worker thread with a borrowed item pointer (valid
        /// only during the call; do not store or free it) and a final
        /// NULL item on close. `callback` and `user_data` access must be
        /// thread-safe. Fails if a callback is already installed.
        ///
        /// # Safety
        /// `sub` must be a live handle; `callback` a valid function
        /// pointer. `user_data` must outlive every callback invocation —
        /// clear/free only *request* cancellation without waiting (see
        /// the module docs).
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $set(
            sub: *const $handle,
            callback: $cb,
            user_data: *mut c_void,
        ) -> MarmotStatus {
            ffi_guard(|| {
                let sub = try_arg!(unsafe { sub_ref(sub) });
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

        /// Request cancellation of this subscription's callback pump, if
        /// any. Non-blocking: a callback already running keeps executing
        /// after this returns (see the module docs).
        ///
        /// # Safety
        /// `sub` must be a live handle.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $clear(sub: *const $handle) -> MarmotStatus {
            ffi_guard(|| {
                let sub = try_arg!(unsafe { sub_ref(sub) });
                sub.core.clear();
                MarmotStatus::Ok
            })
        }

        /// Free the subscription handle. Requests callback-pump
        /// cancellation without waiting (a callback may still be running
        /// after this returns — do not free `user_data` on that basis).
        /// NULL is a no-op. Free every handle before the client that
        /// created it.
        ///
        /// # Safety
        /// `sub` must be NULL or an unfreed handle pointer.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $free(sub: *mut $handle) {
            let _ = ffi_guard(|| {
                unsafe { free_plain(sub) };
                MarmotStatus::Ok
            });
        }
    };
}

c_subscription! {
    /// Opaque handle to the top-level event firehose: one subscription,
    /// every account, every event type. Broadcast lag is skipped
    /// silently — catch back up via the per-account subscriptions.
    MarmotEventsSubscription(EventsSubscription),
    item MarmotEvent from marmot_uniffi::conversions::MarmotEventFfi,
    item_free "marmot_event_free",
    callback MarmotEventCallback,
    next marmot_events_subscription_next,
    set_callback marmot_events_subscription_set_callback,
    clear_callback marmot_events_subscription_clear_callback,
    free marmot_events_subscription_free
}

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
        let client = try_arg!(unsafe { client_ref(client) });
        let handle = MarmotEventsSubscription {
            core: SubscriptionCore::new(client.runtime.handle().clone()),
            inner: client.marmot.subscribe_events(),
        };
        unsafe { write_handle(handle, out_sub) }
    })
}

c_subscription! {
    /// Opaque handle to one conversation's materialized timeline window.
    /// `next` returns the full authoritative window after each update;
    /// `next_update` returns the raw delta; pagination extends the
    /// window without blocking a concurrent `next`.
    MarmotTimelineSubscription(TimelineMessagesSubscription),
    item MarmotTimelinePage from marmot_uniffi::conversions::TimelinePageFfi,
    item_free "marmot_timeline_page_free",
    callback MarmotTimelinePageCallback,
    next marmot_timeline_subscription_next,
    set_callback marmot_timeline_subscription_set_callback,
    clear_callback marmot_timeline_subscription_clear_callback,
    free marmot_timeline_subscription_free
}

/// Subscribe to live materialized timeline updates for a group
/// (`group_id_hex` non-NULL) or the account-wide tail (NULL).
/// `has_limit` plus `limit` cap the initial window. Free with
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
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { optional_str(group_id_hex) });
        let limit = has_limit.then_some(limit);
        match client.block_on(client.marmot.subscribe_timeline_messages(
            account_ref,
            group_id_hex,
            limit,
        )) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotTimelineSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial window snapshot. Yields the page exactly once: later
/// calls write NULL with `MARMOT_STATUS_OK`. Free the page with
/// `marmot_timeline_page_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_page` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_snapshot(
    sub: *const MarmotTimelineSubscription,
    out_page: *mut *mut MarmotTimelinePage,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
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
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next_update());
        unsafe { deliver_next(result, out_update) }
    })
}

/// Extend the window toward older history by up to `count` messages and
/// return the new window. Runs on the runtime off the caller's lock, so
/// a concurrent blocking `next` on another thread is not blocked. Free
/// with `marmot_timeline_page_free`.
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
        let sub = try_arg!(unsafe { sub_ref(sub) });
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
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let inner = sub.inner.clone();
        let result = sub
            .core
            .runtime
            .block_on(async move { inner.paginate_forwards(count).await });
        unsafe { deliver(result, out_page) }
    })
}

c_subscription! {
    /// Opaque handle to the notification pipeline: local-notification
    /// updates produced by the runtime.
    MarmotNotificationsSubscription(NotificationsSubscription),
    item MarmotNotificationUpdate from marmot_uniffi::conversions::NotificationUpdateFfi,
    item_free "marmot_notification_update_free",
    callback MarmotNotificationUpdateCallback,
    next marmot_notifications_subscription_next,
    set_callback marmot_notifications_subscription_set_callback,
    clear_callback marmot_notifications_subscription_clear_callback,
    free marmot_notifications_subscription_free
}

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
        let client = try_arg!(unsafe { client_ref(client) });
        match client.block_on(client.marmot.subscribe_notifications()) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotNotificationsSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(err) => status_from_error(&err),
        }
    })
}

c_subscription! {
    /// Opaque handle to one account's chats list: an initial snapshot of
    /// every group projection, then one record per projection change.
    MarmotChatsSubscription(ChatsSubscription),
    item MarmotAppGroupRecord from marmot_uniffi::conversions::AppGroupRecordFfi,
    item_free "marmot_app_group_record_free",
    callback MarmotAppGroupRecordCallback,
    next marmot_chats_subscription_next,
    set_callback marmot_chats_subscription_set_callback,
    clear_callback marmot_chats_subscription_clear_callback,
    free marmot_chats_subscription_free
}

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
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        match client.block_on(client.marmot.subscribe_chats(account_ref, include_archived)) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotChatsSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
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
    out_list: *mut *mut crate::types::group::MarmotAppGroupRecordList,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
        unsafe {
            deliver(
                Ok::<_, marmot_uniffi::MarmotKitError>(sub.inner.snapshot()),
                out_list,
            )
        }
    })
}

c_subscription! {
    /// Opaque handle to one account's durable chat-list projection: an
    /// initial row snapshot, then row upserts (`next`) or raw deltas
    /// including row removals (`next_update`).
    MarmotChatListSubscription(ChatListSubscription),
    item MarmotChatListRow from marmot_uniffi::conversions::ChatListRowFfi,
    item_free "marmot_chat_list_row_free",
    callback MarmotChatListRowCallback,
    next marmot_chat_list_subscription_next,
    set_callback marmot_chat_list_subscription_set_callback,
    clear_callback marmot_chat_list_subscription_clear_callback,
    free marmot_chat_list_subscription_free
}

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
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        match client.block_on(
            client
                .marmot
                .subscribe_chat_list(account_ref, include_archived),
        ) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotChatListSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial chat-list snapshot. Yields the populated list
/// exactly once: later calls write an EMPTY list, still with
/// `MARMOT_STATUS_OK`. Free with `marmot_chat_list_row_list_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_list` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_snapshot(
    sub: *const MarmotChatListSubscription,
    out_list: *mut *mut MarmotChatListRowList,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
        unsafe {
            deliver(
                Ok::<_, marmot_uniffi::MarmotKitError>(sub.inner.snapshot()),
                out_list,
            )
        }
    })
}

/// Block until the next raw chat-list delta (row upsert or removal).
/// Free with `marmot_chat_list_subscription_update_free`.
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
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let inner = sub.inner.clone();
        let result = sub.core.block_next(timeout_ms, inner.next_update());
        unsafe { deliver_next(result, out_update) }
    })
}

c_subscription! {
    /// Opaque handle to a message stream: an initial record snapshot,
    /// then one message update per store change.
    MarmotMessagesSubscription(MessagesSubscription),
    item MarmotMessageUpdate from marmot_uniffi::conversions::MessageUpdateFfi,
    item_free "marmot_message_update_free",
    callback MarmotMessageUpdateCallback,
    next marmot_messages_subscription_next,
    set_callback marmot_messages_subscription_set_callback,
    clear_callback marmot_messages_subscription_clear_callback,
    free marmot_messages_subscription_free
}

/// Subscribe to messages for a specific group (`group_id_hex` non-NULL)
/// or every message across the account (NULL). `has_limit` + `limit` cap
/// the initial snapshot to the latest N rows. Free with
/// `marmot_messages_subscription_free`.
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
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { optional_str(group_id_hex) });
        let limit = has_limit.then_some(limit);
        match client.block_on(
            client
                .marmot
                .subscribe_messages(account_ref, group_id_hex, limit),
        ) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotMessagesSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial message-record snapshot. Yields the populated list
/// exactly once: later calls write an EMPTY list, still with
/// `MARMOT_STATUS_OK`. Free with `marmot_app_message_record_list_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_list` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_messages_subscription_snapshot(
    sub: *const MarmotMessagesSubscription,
    out_list: *mut *mut MarmotAppMessageRecordList,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
        unsafe {
            deliver(
                Ok::<_, marmot_uniffi::MarmotKitError>(sub.inner.snapshot()),
                out_list,
            )
        }
    })
}

c_subscription! {
    /// Opaque handle to one group's state: an initial record snapshot,
    /// then the full record after each member/profile/roster change.
    MarmotGroupStateSubscription(GroupStateSubscription),
    item MarmotAppGroupRecord from marmot_uniffi::conversions::AppGroupRecordFfi,
    item_free "marmot_app_group_record_free",
    callback MarmotGroupStateRecordCallback,
    next marmot_group_state_subscription_next,
    set_callback marmot_group_state_subscription_set_callback,
    clear_callback marmot_group_state_subscription_clear_callback,
    free marmot_group_state_subscription_free
}

/// Subscribe to member/profile/roster changes for one group. Free with
/// `marmot_group_state_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex`
/// valid strings; `out_sub` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_group_state(
    client: *const MarmotClient,
    account_ref: *const std::ffi::c_char,
    group_id_hex: *const std::ffi::c_char,
    out_sub: *mut *mut MarmotGroupStateSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        match client.block_on(
            client
                .marmot
                .subscribe_group_state(account_ref, group_id_hex),
        ) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotGroupStateSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(err) => status_from_error(&err),
        }
    })
}

/// Take the initial group-record snapshot. Yields the record exactly
/// once: later calls write NULL with `MARMOT_STATUS_OK`. Free with
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
        let sub = try_arg!(unsafe { sub_ref(sub) });
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

c_subscription! {
    /// Opaque handle to a live agent-text-stream watch: incremental
    /// `Chunk`s, then a terminal `Finished` / `Failed`, after which the
    /// stream closes. Created by `marmot_watch_agent_text_stream`; the
    /// matching anchor/start command is `marmot_start_agent_text_stream`.
    MarmotAgentStreamSubscription(AgentStreamSubscription),
    item MarmotAgentStreamUpdate from marmot_uniffi::conversions::AgentStreamUpdateFfi,
    item_free "marmot_agent_stream_update_free",
    callback MarmotAgentStreamUpdateCallback,
    next marmot_agent_stream_subscription_next,
    set_callback marmot_agent_stream_subscription_set_callback,
    clear_callback marmot_agent_stream_subscription_clear_callback,
    free marmot_agent_stream_subscription_free
}

/// Watch a live agent text stream over the brokered QUIC channel. Pass
/// `stream_id_hex = NULL` to follow the latest stream in the group.
/// `server_cert_der` (+ `server_cert_der_len`) pins a self-signed broker
/// certificate; pass NULL with length 0 to use platform trust. The bytes
/// are copied — the caller keeps ownership. `insecure_local` is
/// loopback-only for testing. Free with
/// `marmot_agent_stream_subscription_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex`
/// valid strings; `stream_id_hex` NULL or a valid string;
/// `server_cert_der` NULL with length 0, or a pointer to
/// `server_cert_der_len` valid bytes; `out_sub` valid.
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
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let stream_id_hex = try_arg!(unsafe { optional_str(stream_id_hex) });
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
            Ok(inner) => unsafe {
                write_handle(
                    MarmotAgentStreamSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(err) => status_from_error(&err),
        }
    })
}

/// The resolved stream id this watch is following (hex). Writes an owned
/// copy: free it with `marmot_string_free`.
///
/// # Safety
/// `sub` must be a live handle; `out_stream_id_hex` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_agent_stream_subscription_stream_id_hex(
    sub: *const MarmotAgentStreamSubscription,
    out_stream_id_hex: *mut *mut std::ffi::c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
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
    fn block_next_ok_closed_and_timeout() {
        let rt = runtime();
        let core = SubscriptionCore::new(rt.handle().clone());
        assert_eq!(core.block_next(0, async { Some(42u32) }), Ok(Some(42)));
        assert_eq!(core.block_next::<u32>(0, async { None }), Ok(None));
        assert_eq!(
            core.block_next::<u32>(10, std::future::pending()),
            Err(MarmotStatus::Timeout)
        );
    }

    #[test]
    fn install_reserves_slot_before_spawning() {
        let rt = runtime();
        let core = SubscriptionCore::new(rt.handle().clone());

        assert_eq!(
            core.install(|handle| handle.spawn(std::future::pending::<()>())),
            MarmotStatus::Ok
        );

        // A second install must be rejected AND must not run its spawn
        // closure (the whole point of reserving before spawning).
        let spawned = AtomicBool::new(false);
        let second = core.install(|handle| {
            spawned.store(true, Ordering::SeqCst);
            handle.spawn(async {})
        });
        assert_eq!(second, MarmotStatus::Runtime);
        assert!(!spawned.load(Ordering::SeqCst));

        core.clear();
        assert_eq!(
            core.install(|handle| handle.spawn(std::future::pending::<()>())),
            MarmotStatus::Ok
        );
        core.clear();
    }
}
