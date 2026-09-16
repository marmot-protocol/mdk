//! Fallible replacement streams use blocking next; paging has independent ownership.
use super::*;
use crate::types::chat_window::*;

/// Free before its client. Concurrent next and commands are supported; never free during a call.
pub struct MarmotChatListWindowSubscription {
    core: SubscriptionCore,
    inner: Arc<marmot_uniffi::ChatListWindowSubscription>,
}
/// Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed.
/// # Safety
/// sub must be live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_window_subscription_snapshot(
    sub: *const MarmotChatListWindowSubscription,
    out: *mut *mut MarmotChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        unsafe { deliver_next(Ok(sub.inner.snapshot()), out) }
    })
}
/// Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves
/// out NULL. Timeout does not consume an update. Free results with the matching snapshot_free.
/// # Safety
/// sub must remain live throughout the call; out must be writable. Use one receiver per handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_window_subscription_next(
    sub: *const MarmotChatListWindowSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let result = match sub
            .core
            .block_next(timeout_ms, async { Some(sub.inner.next().await) })
        {
            Ok(Some(Ok(item))) => Ok(item),
            Ok(Some(Err(e))) => Err(status_from_error(&e)),
            Ok(None) => Ok(None),
            Err(status) => Err(status),
        };
        unsafe { deliver_next(result, out) }
    })
}
/// Cancel and free. NULL is a no-op; does not free previously returned snapshots.
/// # Safety
/// sub must be NULL or a library-owned handle with no active calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_window_subscription_free(
    sub: *mut MarmotChatListWindowSubscription,
) {
    crate::memory::free_guard(|| unsafe { free_plain(sub) });
}
/// Free before its client. Concurrent next and commands are supported; never free during a call.
pub struct MarmotAccountAttentionSubscription {
    core: SubscriptionCore,
    inner: Arc<marmot_uniffi::AccountAttentionSubscription>,
}
/// Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed.
/// # Safety
/// sub must be live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attention_subscription_snapshot(
    sub: *const MarmotAccountAttentionSubscription,
    out: *mut *mut MarmotAccountAttentionSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        unsafe { deliver_next(Ok(sub.inner.snapshot()), out) }
    })
}
/// Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves
/// out NULL. Timeout does not consume an update. Free results with the matching snapshot_free.
/// # Safety
/// sub must remain live throughout the call; out must be writable. Use one receiver per handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attention_subscription_next(
    sub: *const MarmotAccountAttentionSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotAccountAttentionSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let result = match sub
            .core
            .block_next(timeout_ms, async { Some(sub.inner.next().await) })
        {
            Ok(Some(Ok(item))) => Ok(item),
            Ok(Some(Err(e))) => Err(status_from_error(&e)),
            Ok(None) => Ok(None),
            Err(status) => Err(status),
        };
        unsafe { deliver_next(result, out) }
    })
}
/// Cancel and free. NULL is a no-op; does not free previously returned snapshots.
/// # Safety
/// sub must be NULL or a library-owned handle with no active calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_attention_subscription_free(
    sub: *mut MarmotAccountAttentionSubscription,
) {
    crate::memory::free_guard(|| unsafe { free_plain(sub) });
}

/// Open one account/view. A NULL initial_rows uses 50; otherwise requires 1–100.
/// View is a MarmotChatListView discriminant. Take snapshot once, then receive replacements.
/// # Safety
/// client/string must be valid; initial_rows must be NULL or readable, out_sub writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_open_chat_list_window(
    client: *const MarmotClient,
    account_ref: *const c_char,
    view: u32,
    initial_rows: *const u32,
    out_sub: *mut *mut MarmotChatListWindowSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out_sub) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let view = try_arg!(MarmotChatListView::from_c(view)).to_ffi();
        let initial_rows = unsafe { initial_rows.as_ref() }.copied();
        match client.block_on(
            client
                .marmot
                .open_chat_list_window(account_ref, view, initial_rows),
        ) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotChatListWindowSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(e) => status_from_error(&e),
        }
    })
}
/// Open independent signed-in account summaries; requires no active chat-list handle.
/// # Safety
/// client must be valid; out_sub writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_subscribe_account_attention(
    client: *const MarmotClient,
    out_sub: *mut *mut MarmotAccountAttentionSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out_sub) });
        let client = try_arg!(unsafe { client_ref(client) });
        match client.block_on(client.marmot.subscribe_account_attention()) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotAccountAttentionSubscription {
                        core: SubscriptionCore::new(client.runtime.handle().clone()),
                        inner,
                    },
                    out_sub,
                )
            },
            Err(e) => status_from_error(&e),
        }
    })
}

/// Apply a window command against the installed sequence, returning a complete replacement.
/// May run while next waits. Stale sequence returns CHAT_WINDOW_STALE; refresh before retrying.
/// The same completion also arrives through next; deduplicate by generation/sequence.
/// # Safety
/// sub must be live, any input string valid, and out writable. Never free during a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_window_subscription_page(
    sub: *const MarmotChatListWindowSubscription,
    sequence: u64,
    direction: u32,
    count: u32,
    out: *mut *mut MarmotChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let direction = try_arg!(MarmotChatListPageDirection::from_c(direction)).to_ffi();
        let result = block_on_handle(
            &sub.core.runtime,
            sub.inner.page(sequence, direction, count),
        );
        match result {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(e) => status_from_error(&e),
        }
    })
}

/// Apply a window command against the installed sequence, returning a complete replacement.
/// May run while next waits. Stale sequence returns CHAT_WINDOW_STALE; refresh before retrying.
/// The same completion also arrives through next; deduplicate by generation/sequence.
/// # Safety
/// sub must be live, any input string valid, and out writable. Never free during a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_window_subscription_set_visible_anchor(
    sub: *const MarmotChatListWindowSubscription,
    sequence: u64,
    group_id_hex: *const c_char,
    out: *mut *mut MarmotChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let result = block_on_handle(
            &sub.core.runtime,
            sub.inner.set_visible_anchor(sequence, group_id_hex),
        );
        match result {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(e) => status_from_error(&e),
        }
    })
}

/// Apply a window command against the installed sequence, returning a complete replacement.
/// May run while next waits. Stale sequence returns CHAT_WINDOW_STALE; refresh before retrying.
/// The same completion also arrives through next; deduplicate by generation/sequence.
/// # Safety
/// sub must be live, any input string valid, and out writable. Never free during a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_window_subscription_return_to_top(
    sub: *const MarmotChatListWindowSubscription,
    sequence: u64,
    out: *mut *mut MarmotChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });

        let result = block_on_handle(&sub.core.runtime, sub.inner.return_to_top(sequence));
        match result {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(e) => status_from_error(&e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_uniffi::{Marmot, MarmotKitError, SecretStore};
    use std::{collections::HashMap, ffi::CString, ptr};
    #[derive(Default)]
    struct Store(StdMutex<HashMap<String, String>>);
    impl SecretStore for Store {
        fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError> {
            Ok(self.0.lock().unwrap().contains_key(&label))
        }
        fn has_secret_for_account_id(&self, _: String) -> Result<bool, MarmotKitError> {
            Ok(false)
        }
        fn write_secret(
            &self,
            label: String,
            _: String,
            secret: String,
        ) -> Result<(), MarmotKitError> {
            self.0.lock().unwrap().insert(label, secret);
            Ok(())
        }
        fn load_secret(&self, label: String, _: String) -> Result<String, MarmotKitError> {
            self.0
                .lock()
                .unwrap()
                .get(&label)
                .cloned()
                .ok_or(MarmotKitError::SecretNotFound {
                    details: "test".into(),
                })
        }
        fn remove_secret(&self, label: String, _: String) -> Result<(), MarmotKitError> {
            self.0.lock().unwrap().remove(&label);
            Ok(())
        }
    }
    #[test]
    fn c_screen_handles_preflight_timeout_concurrent_commands_and_close() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
        let url = rt.block_on(relay.url()).to_string();
        let kit = Marmot::new_with_options(
            dir.path().to_str().unwrap().into(),
            vec![url.clone()],
            marmot_uniffi::RelayPolicyFfi::AllowLoopback,
            Some(Arc::new(Store::default())),
        )
        .unwrap();
        let client = MarmotClient {
            runtime: rt,
            marmot: kit,
        };
        let account = client
            .block_on(client.marmot.create_identity(vec![url.clone()], vec![url]))
            .unwrap()
            .account_id_hex;
        for name in ["One", "Two"] {
            client
                .block_on(
                    client
                        .marmot
                        .create_group(account.clone(), name.into(), vec![], None),
                )
                .unwrap();
        }
        let account = CString::new(account).unwrap();
        unsafe {
            let mut summary = ptr::null_mut();
            assert_eq!(
                marmot_subscribe_account_attention(&client, &mut summary),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_account_attention_subscription_snapshot(summary, ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            let mut totals = ptr::null_mut();
            assert_eq!(
                marmot_account_attention_subscription_snapshot(summary, &mut totals),
                MarmotStatus::Ok
            );
            assert_eq!((*totals).accounts_len, 1);
            marmot_account_attention_snapshot_free(totals);
            assert_eq!(
                marmot_account_attention_subscription_snapshot(summary, &mut totals),
                MarmotStatus::Closed
            );
            assert!(totals.is_null());
            assert_eq!(
                marmot_account_attention_subscription_next(summary, 5, &mut totals),
                MarmotStatus::Timeout
            );
            assert!(totals.is_null());
            let mut window = ptr::null_mut();
            assert_eq!(
                marmot_open_chat_list_window(
                    &client,
                    account.as_ptr(),
                    99,
                    ptr::null(),
                    &mut window
                ),
                MarmotStatus::InvalidArgument
            );
            assert!(window.is_null());
            assert_eq!(
                marmot_open_chat_list_window(&client, account.as_ptr(), 0, &0, &mut window),
                MarmotStatus::ChatWindowInvalidLimit
            );
            assert!(window.is_null());
            assert_eq!(
                marmot_open_chat_list_window(&client, account.as_ptr(), 0, &1, &mut window),
                MarmotStatus::Ok
            );
            let mut snapshot = ptr::null_mut();
            assert_eq!(
                marmot_chat_list_window_subscription_snapshot(window, ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_chat_list_window_subscription_snapshot(window, &mut snapshot),
                MarmotStatus::Ok
            );
            assert_eq!((*snapshot).rows_len, 1);
            let sequence = (*snapshot).sequence;
            marmot_chat_list_window_snapshot_free(snapshot);
            assert_eq!(
                marmot_chat_list_window_subscription_next(window, 5, &mut snapshot),
                MarmotStatus::Timeout
            );
            assert!(snapshot.is_null());
            assert_eq!(
                marmot_chat_list_window_subscription_page(window, sequence, 0, 1, ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            let sub = &*window;
            std::thread::scope(|scope| {
                let waiter = scope.spawn(|| {
                    let mut update = ptr::null_mut();
                    let status = marmot_chat_list_window_subscription_next(sub, 5_000, &mut update);
                    assert_eq!(status, MarmotStatus::Ok);
                    let sequence = (*update).sequence;
                    marmot_chat_list_window_snapshot_free(update);
                    sequence
                });
                assert_eq!(
                    marmot_chat_list_window_subscription_page(sub, sequence, 0, 1, &mut snapshot),
                    MarmotStatus::Ok
                );
                assert_eq!((*snapshot).rows_len, 2);
                assert_eq!(waiter.join().unwrap(), (*snapshot).sequence);
            });
            marmot_chat_list_window_snapshot_free(snapshot);
            assert_eq!(
                marmot_chat_list_window_subscription_page(window, sequence, 0, 1, &mut snapshot),
                MarmotStatus::ChatWindowStale
            );
            assert!(snapshot.is_null());
            client.block_on(client.marmot.shutdown_and_close()).unwrap();
            assert_eq!(
                marmot_chat_list_window_subscription_next(window, 100, &mut snapshot),
                MarmotStatus::Closed
            );
            assert_eq!(
                marmot_account_attention_subscription_next(summary, 100, &mut totals),
                MarmotStatus::Closed
            );
            marmot_chat_list_window_subscription_free(window);
            marmot_account_attention_subscription_free(summary);
            marmot_chat_list_window_subscription_free(ptr::null_mut());
            marmot_account_attention_subscription_free(ptr::null_mut());
        }
        drop(relay);
        drop(client);
        // Clear owned error-detail storage used by these deliberate rejection tests.
        let _ = crate::status::take_last_error();
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
    #[test]
    fn c_conversation_window_ownership_timeout_and_revision_operations() {
        use crate::subscriptions::conversation_window::*;
        use crate::types::conversation_window::*;
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
        let url = rt.block_on(relay.url()).to_string();
        let kit = Marmot::new_with_options(
            dir.path().to_str().unwrap().into(),
            vec![url.clone()],
            marmot_uniffi::RelayPolicyFfi::AllowLoopback,
            Some(Arc::new(Store::default())),
        )
        .unwrap();
        let client = MarmotClient {
            runtime: rt,
            marmot: kit,
        };
        let account = client
            .block_on(client.marmot.create_identity(vec![url.clone()], vec![url]))
            .unwrap()
            .account_id_hex;
        let group = client
            .block_on(client.marmot.create_group(
                account.clone(),
                "C conversation".into(),
                vec![],
                None,
            ))
            .unwrap();
        for i in 0..3 {
            client
                .block_on(client.marmot.send_text(
                    account.clone(),
                    group.clone(),
                    format!("message {i}"),
                ))
                .unwrap();
        }
        let account = CString::new(account).unwrap();
        let group = CString::new(group).unwrap();
        unsafe {
            let mut window = ptr::null_mut();
            assert_eq!(
                marmot_open_conversation_window(
                    &client,
                    account.as_ptr(),
                    group.as_ptr(),
                    99,
                    ptr::null(),
                    ptr::null(),
                    0,
                    &mut window
                ),
                MarmotStatus::InvalidArgument
            );
            assert!(window.is_null());
            assert_eq!(
                marmot_open_conversation_window(
                    &client,
                    account.as_ptr(),
                    group.as_ptr(),
                    1,
                    ptr::null(),
                    &2,
                    0,
                    &mut window
                ),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_conversation_window_subscription_snapshot(window, ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            let mut initial = ptr::null_mut();
            assert_eq!(
                marmot_conversation_window_subscription_snapshot(window, &mut initial),
                MarmotStatus::Ok
            );
            assert_eq!((*initial).messages_len, 2);
            let mut update = ptr::null_mut();
            // The initial local snapshot may precede the authority upgrade.
            // Install that replacement before asserting quiet command/revision
            // behavior, as a native consumer must do for any live update.
            while !(*initial).header.has_epoch {
                assert!(!(*initial).header.capabilities.can_send);
                assert_eq!(
                    marmot_conversation_window_subscription_next(window, 5000, &mut update),
                    MarmotStatus::Ok
                );
                marmot_conversation_window_snapshot_free(initial);
                initial = update;
                update = ptr::null_mut();
            }
            assert!((*initial).header.capabilities.can_send);
            let missing = CString::new("00".repeat(32)).unwrap();
            assert_eq!(
                marmot_conversation_window_subscription_jump_to_message(
                    window,
                    &(*initial).revision,
                    missing.as_ptr(),
                    0,
                    &mut update,
                ),
                MarmotStatus::ConversationWindowMessageNotRetained
            );
            assert!(update.is_null());
            // The failed jump neither closes nor advances this window: same-revision
            // paging below still succeeds and its stream echo remains available.
            assert_eq!(
                marmot_conversation_window_subscription_next(window, 10, &mut update),
                MarmotStatus::Timeout
            );
            assert!(update.is_null());
            assert_eq!(
                marmot_conversation_window_subscription_page(
                    window,
                    &(*initial).revision,
                    0,
                    1,
                    0,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_conversation_window_subscription_page(
                    window,
                    &(*initial).revision,
                    99,
                    1,
                    0,
                    &mut update
                ),
                MarmotStatus::InvalidArgument
            );
            let sub = &*window;
            std::thread::scope(|scope| {
                let waiter = scope.spawn(|| {
                    let mut received = ptr::null_mut();
                    assert_eq!(
                        marmot_conversation_window_subscription_next(sub, 5000, &mut received),
                        MarmotStatus::Ok
                    );
                    let sequence = (*received).revision.sequence;
                    marmot_conversation_window_snapshot_free(received);
                    sequence
                });
                assert_eq!(
                    marmot_conversation_window_subscription_page(
                        sub,
                        &(*initial).revision,
                        0,
                        1,
                        0,
                        &mut update
                    ),
                    MarmotStatus::Ok
                );
                assert_eq!((*update).messages_len, 3);
                assert_eq!(waiter.join().unwrap(), (*update).revision.sequence);
            });
            marmot_conversation_window_snapshot_free(update);
            assert_eq!(
                marmot_conversation_window_subscription_return_to_latest(
                    window,
                    &(*initial).revision,
                    0,
                    &mut update
                ),
                MarmotStatus::ConversationWindowStale
            );
            assert!(update.is_null());
            // Borrow a token from the still-owned snapshot; free returned drafts independently.
            let attachment_id = c"missing";
            let mut found = 99;
            let mut bytes = ptr::dangling_mut();
            let mut bytes_len = 99;
            assert_eq!(
                marmot_message_draft_attachment_if_revision(
                    &client,
                    account.as_ptr(),
                    (*initial).draft.revision,
                    attachment_id.as_ptr(),
                    &mut found,
                    &mut bytes,
                    &mut bytes_len,
                ),
                MarmotStatus::Ok
            );
            assert_eq!((found, bytes.is_null(), bytes_len), (0, true, 0));
            assert_eq!(
                marmot_message_draft_attachment_if_revision(
                    &client,
                    account.as_ptr(),
                    (*initial).draft.revision,
                    attachment_id.as_ptr(),
                    &mut found,
                    &mut bytes,
                    ptr::null_mut(),
                ),
                MarmotStatus::NullPointer
            );
            let attachment = crate::types::draft::MarmotMessageDraftAttachmentInput {
                id: c"empty".as_ptr(),
                file_name: c"empty.txt".as_ptr(),
                media_type: c"text/plain".as_ptr(),
                plaintext: ptr::null(),
                plaintext_len: 0,
                dim: ptr::null(),
                thumbhash: ptr::null(),
                has_duration_seconds: 0,
                duration_seconds: 0.0,
                waveform_samples: ptr::null(),
                waveform_samples_len: 0,
            };
            let mut edited = ptr::null_mut();
            assert_eq!(
                marmot_save_message_draft_if_revision(
                    &client,
                    account.as_ptr(),
                    (*initial).draft.revision,
                    c"edited".as_ptr(),
                    ptr::null(),
                    &attachment,
                    1,
                    &mut edited,
                ),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_message_draft_attachment_if_revision(
                    &client,
                    account.as_ptr(),
                    (*edited).revision,
                    c"empty".as_ptr(),
                    &mut found,
                    &mut bytes,
                    &mut bytes_len,
                ),
                MarmotStatus::Ok
            );
            assert_eq!((found, bytes_len), (1, 0));
            crate::marmot_bytes_free(bytes, bytes_len);
            found = 99;
            bytes = ptr::dangling_mut();
            bytes_len = 99;
            assert_eq!(
                marmot_message_draft_attachment_if_revision(
                    &client,
                    account.as_ptr(),
                    (*initial).draft.revision,
                    c"empty".as_ptr(),
                    &mut found,
                    &mut bytes,
                    &mut bytes_len,
                ),
                MarmotStatus::MessageDraftRevisionConflict
            );
            assert_eq!((found, bytes.is_null(), bytes_len), (0, true, 0));
            let mut selected = ptr::null_mut();
            assert_eq!(
                marmot_clear_message_draft_if_revision(
                    &client,
                    account.as_ptr(),
                    (*edited).revision,
                    &mut selected
                ),
                MarmotStatus::Ok
            );
            marmot_selected_message_draft_free(selected);
            marmot_selected_message_draft_free(edited);
            marmot_conversation_window_snapshot_free(initial);
            assert_eq!(
                marmot_conversation_window_subscription_cancel(window),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_conversation_window_subscription_next(window, 100, &mut update),
                MarmotStatus::Closed
            );
            marmot_conversation_window_subscription_free(window);
            marmot_conversation_window_subscription_free(ptr::null_mut());
            marmot_conversation_window_snapshot_free(ptr::null_mut());
            marmot_selected_message_draft_free(ptr::null_mut());
        }
        client.block_on(client.marmot.shutdown_and_close()).unwrap();
        drop(relay);
        drop(client);
        let _ = crate::status::take_last_error();
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
