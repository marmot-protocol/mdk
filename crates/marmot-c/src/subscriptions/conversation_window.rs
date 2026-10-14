//! Fallible replacement streams use blocking next; paging has independent ownership.
use super::*;
use crate::types::conversation_window::*;
use crate::types::presentation::MarmotChatListDraftVersion;

/// Free before its client. Concurrent next and commands are supported; never free during a call.
pub struct MarmotConversationWindowSubscription {
    core: SubscriptionCore,
    inner: Arc<marmot_uniffi::ConversationWindowSubscription>,
}
/// Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed.
/// # Safety
/// sub must be live and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_conversation_window_subscription_snapshot(
    sub: *const MarmotConversationWindowSubscription,
    out: *mut *mut MarmotConversationWindowSnapshot,
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
pub unsafe extern "C" fn marmot_conversation_window_subscription_next(
    sub: *const MarmotConversationWindowSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotConversationWindowSnapshot,
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
pub unsafe extern "C" fn marmot_conversation_window_subscription_free(
    sub: *mut MarmotConversationWindowSubscription,
) {
    crate::memory::free_guard(|| unsafe { free_plain(sub) });
}

/// Close and wake pending receivers/commands. Idempotent; does not free this handle or snapshots.
/// # Safety
/// sub must remain live throughout all calls; free only after active calls return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_conversation_window_subscription_cancel(
    sub: *const MarmotConversationWindowSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
        block_on_handle(&sub.core.runtime, sub.inner.cancel());
        MarmotStatus::Ok
    })
}
/// Open one account/group. mode is a MarmotConversationOpenMode discriminant.
/// Message mode requires message_id_hex; other modes require NULL. initial_rows NULL uses 50.
/// Zero timeout uses 30 seconds; opening timeout abandons the opening. No mark-read occurs.
/// # Safety
/// client/strings must be valid; optional pointers readable or NULL, out_sub writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_open_conversation_window(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    mode: u32,
    message_id_hex: *const c_char,
    initial_rows: *const u32,
    timeout_ms: u32,
    out_sub: *mut *mut MarmotConversationWindowSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out_sub) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let mode = try_arg!(MarmotConversationOpenMode::from_c(mode)).to_ffi();
        let message = try_arg!(unsafe { optional_str(message_id_hex) });
        let rows = unsafe { initial_rows.as_ref() }.copied();
        match client.block_on(
            client
                .marmot
                .open_conversation_window(account, group, mode, message, rows, timeout_ms),
        ) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotConversationWindowSubscription {
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
unsafe fn read_revision(
    p: *const MarmotConversationWindowRevision,
) -> Result<marmot_uniffi::ConversationWindowRevisionFfi, MarmotStatus> {
    let v = unsafe { p.as_ref() }.ok_or(MarmotStatus::NullPointer)?;
    Ok(marmot_uniffi::ConversationWindowRevisionFfi {
        generation: unsafe { required_str(v.generation) }?,
        sequence: v.sequence,
    })
}

/// Apply against the installed revision. May run while next waits; deduplicate completions by
/// generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after
/// timeout through next; refresh before retrying. Extend history around the visible anchor;
/// paging preserves that anchor at the retained-row cap.
/// # Safety
/// sub and borrowed revision/strings must remain live; out writable. Never free during a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_conversation_window_subscription_page(
    sub: *const MarmotConversationWindowSubscription,
    revision: *const MarmotConversationWindowRevision,
    direction: u32,
    count: u32,
    timeout_ms: u32,
    out: *mut *mut MarmotConversationWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let revision = try_arg!(unsafe { read_revision(revision) });
        let direction = try_arg!(MarmotConversationPageDirection::from_c(direction)).to_ffi();
        let result = block_on_handle(
            &sub.core.runtime,
            sub.inner.page(revision, direction, count, timeout_ms),
        );
        match result {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(e) => status_from_error(&e),
        }
    })
}

/// Apply against the installed revision. May run while next waits; deduplicate completions by
/// generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after
/// timeout through next; refresh before retrying. Report a row in the installed window as
/// the visible anchor; this does not acknowledge reads or encode pixel offsets.
/// # Safety
/// sub and borrowed revision/strings must remain live; out writable. Never free during a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_conversation_window_subscription_set_visible_anchor(
    sub: *const MarmotConversationWindowSubscription,
    revision: *const MarmotConversationWindowRevision,
    message_id_hex: *const c_char,
    timeout_ms: u32,
    out: *mut *mut MarmotConversationWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let revision = try_arg!(unsafe { read_revision(revision) });
        let message = try_arg!(unsafe { required_str(message_id_hex) });
        let result = block_on_handle(
            &sub.core.runtime,
            sub.inner.set_visible_anchor(revision, message, timeout_ms),
        );
        match result {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(e) => status_from_error(&e),
        }
    })
}

/// Apply against the installed revision. May run while next waits; deduplicate completions by
/// generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after
/// timeout through next; refresh before retrying. Center the window on a retained message;
/// a missing target fails explicitly.
/// # Safety
/// sub and borrowed revision/strings must remain live; out writable. Never free during a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_conversation_window_subscription_jump_to_message(
    sub: *const MarmotConversationWindowSubscription,
    revision: *const MarmotConversationWindowRevision,
    message_id_hex: *const c_char,
    timeout_ms: u32,
    out: *mut *mut MarmotConversationWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let revision = try_arg!(unsafe { read_revision(revision) });
        let message = try_arg!(unsafe { required_str(message_id_hex) });
        let result = block_on_handle(
            &sub.core.runtime,
            sub.inner.jump_to_message(revision, message, timeout_ms),
        );
        match result {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(e) => status_from_error(&e),
        }
    })
}

/// Apply against the installed revision. May run while next waits; deduplicate completions by
/// generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after
/// timeout through next; refresh before retrying. Move to the latest message and resume
/// following arrivals, retaining the current row budget.
/// # Safety
/// sub and borrowed revision/strings must remain live; out writable. Never free during a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_conversation_window_subscription_return_to_latest(
    sub: *const MarmotConversationWindowSubscription,
    revision: *const MarmotConversationWindowRevision,
    timeout_ms: u32,
    out: *mut *mut MarmotConversationWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let revision = try_arg!(unsafe { read_revision(revision) });

        let result = block_on_handle(
            &sub.core.runtime,
            sub.inner.return_to_latest(revision, timeout_ms),
        );
        match result {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(e) => status_from_error(&e),
        }
    })
}

/// Descriptor-only draft; result owns the revision handle and must be deep-freed.
/// # Safety
/// client and strings valid; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_message_draft(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out: *mut *mut MarmotSelectedMessageDraft,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe { deliver(client.marmot.selected_message_draft(account, group), out) }
    })
}
/// Compare an opaque chat-list draft version with a selected revision.
/// Returns zero for a foreign store/group or a newer draft.
/// # Safety
/// revision's owning draft/snapshot and version's owning row remain live;
/// out is writable. Inputs are borrowed for this call only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_message_draft_revision_includes_chat_list_version(
    revision: *const MarmotMessageDraftRevision,
    version: *const MarmotChatListDraftVersion,
    out: *mut u8,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { crate::preflight_out(out) });
        let revision = try_arg!(unsafe { revision.as_ref() }.ok_or(MarmotStatus::NullPointer));
        let version = try_arg!(unsafe { version.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            *out = u8::from(
                revision
                    .inner
                    .includes_chat_list_version(version.inner.clone()),
            )
        };
        MarmotStatus::Ok
    })
}
/// Clear only this selected revision; later edits are preserved.
/// # Safety
/// client, account and revision valid; revision's owning snapshot/draft must remain live; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_clear_message_draft_if_revision(
    client: *const MarmotClient,
    account_ref: *const c_char,
    revision: *const MarmotMessageDraftRevision,
    out: *mut *mut MarmotSelectedMessageDraft,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let revision = try_arg!(unsafe { revision.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            deliver(
                client
                    .marmot
                    .clear_message_draft_if_revision(account, revision.inner.clone()),
                out,
            )
        }
    })
}
/// Save only if the selected revision still matches. Attachment inputs are copied, never retained.
/// # Safety
/// client, account, content and revision valid; reply nullable; attachments points to len readable
/// items (or NULL with zero len). Revision's owner stays live; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_save_message_draft_if_revision(
    client: *const MarmotClient,
    account_ref: *const c_char,
    revision: *const MarmotMessageDraftRevision,
    content: *const c_char,
    reply: *const c_char,
    attachments: *const crate::types::draft::MarmotMessageDraftAttachmentInput,
    attachments_len: usize,
    out: *mut *mut MarmotSelectedMessageDraft,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let content = try_arg!(unsafe { required_str(content) });
        let reply = try_arg!(unsafe { optional_str(reply) });
        let revision = try_arg!(unsafe { revision.as_ref() }.ok_or(MarmotStatus::NullPointer));
        let attachments = try_arg!(unsafe {
            crate::commands::struct_array(attachments, attachments_len, |a| a.to_ffi())
        });
        unsafe {
            deliver(
                client.marmot.save_message_draft_if_revision(
                    account,
                    revision.inner.clone(),
                    content,
                    reply,
                    attachments,
                ),
                out,
            )
        }
    })
}
/// Read one selected attachment. found=0 distinguishes absence from an empty acquired attachment.
/// Free returned bytes with marmot_bytes_free; revision conflicts return an error.
/// # Safety
/// client, strings, revision valid; revision's owning draft stays live; all out pointers writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_message_draft_attachment_if_revision(
    client: *const MarmotClient,
    account_ref: *const c_char,
    revision: *const MarmotMessageDraftRevision,
    attachment_id: *const c_char,
    out_found: *mut u8,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { crate::preflight_out(out_found) });
        try_arg!(unsafe { preflight_out_ptr(out_data) });
        try_arg!(unsafe { crate::preflight_out(out_len) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let attachment = try_arg!(unsafe { required_str(attachment_id) });
        let revision = try_arg!(unsafe { revision.as_ref() }.ok_or(MarmotStatus::NullPointer));
        match client.marmot.message_draft_attachment_if_revision(
            account,
            revision.inner.clone(),
            attachment,
        ) {
            Ok(Some(bytes)) => unsafe {
                out_found.write(1);
                crate::commands::deliver_bytes(Ok(bytes), out_data, out_len)
            },
            Ok(None) => MarmotStatus::Ok,
            Err(e) => status_from_error(&e),
        }
    })
}

/// Send the exact selected revision; successful durable acceptance clears it atomically.
/// Hosts must not independently delete the draft on delivery. Prepared media must match descriptors.
/// # Safety
/// client, account, revision valid; revision owner stays live; attachments readable for length,
/// or NULL with zero length; out writable. Free result with marmot_send_summary_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_send_message_draft(
    client: *const MarmotClient,
    account_ref: *const c_char,
    revision: *const MarmotMessageDraftRevision,
    attachments: *const crate::types::media::MarmotMediaAttachmentReference,
    attachments_len: usize,
    out: *mut *mut crate::types::account::MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let revision = try_arg!(unsafe { revision.as_ref() }.ok_or(MarmotStatus::NullPointer));
        let attachments = try_arg!(unsafe {
            crate::commands::struct_array(attachments, attachments_len, |a| a.to_ffi())
        });
        unsafe {
            deliver(
                client.block_on(client.marmot.send_message_draft(
                    account,
                    revision.inner.clone(),
                    attachments,
                )),
                out,
            )
        }
    })
}

/// Atomically consume a draft and admit its token-bound message locally.
/// # Safety
/// Client, account, token and revision must be valid; attachments readable for
/// length (NULL allowed at zero); out writable. Free with marmot_local_send_acceptance_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_send_message_draft_with_client_token(
    client: *const MarmotClient,
    account_ref: *const c_char,
    revision: *const MarmotMessageDraftRevision,
    attachments: *const crate::types::media::MarmotMediaAttachmentReference,
    attachments_len: usize,
    client_token: *const c_char,
    out: *mut *mut crate::types::local_submissions::MarmotLocalSendAcceptance,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let token = try_arg!(unsafe { required_str(client_token) });
        let revision = try_arg!(unsafe { revision.as_ref() }.ok_or(MarmotStatus::NullPointer));
        let attachments = try_arg!(unsafe {
            crate::commands::struct_array(attachments, attachments_len, |a| a.to_ffi())
        });
        unsafe {
            deliver(
                client.block_on(client.marmot.send_message_draft_with_client_token(
                    account,
                    revision.inner.clone(),
                    attachments,
                    token,
                )),
                out,
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{
        marmot_create_group, marmot_create_identity, marmot_presented_chat_list_row,
        marmot_save_message_draft,
    };
    use crate::memory::audit;
    use crate::types::account::marmot_account_summary_free;
    use crate::types::draft::marmot_message_draft_free;
    use crate::types::presentation::marmot_presented_chat_row_free;
    use crate::{
        MarmotRelayPolicy, marmot_client_free, marmot_client_new_with_options,
        marmot_client_shutdown, marmot_client_start, marmot_string_free,
    };
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn draft_version_comparison_preflights_output_and_both_borrows() {
        let mut covered = 9;
        unsafe {
            assert_eq!(
                marmot_message_draft_revision_includes_chat_list_version(
                    ptr::null(),
                    ptr::null(),
                    &raw mut covered
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(covered, 0);
            // A NULL output must be refused before either input is dereferenced.
            assert_eq!(
                marmot_message_draft_revision_includes_chat_list_version(
                    ptr::dangling(),
                    ptr::dangling(),
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
        }
    }

    #[test]
    fn row_owned_draft_version_compares_and_deep_frees() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let relay = runtime
            .block_on(nostr_relay_builder::MockRelay::run())
            .unwrap();
        let relay_url = CString::new(runtime.block_on(relay.url()).to_string()).unwrap();
        let relays = [relay_url.as_ptr()];
        let home = tempfile::tempdir().unwrap();
        let root = CString::new(home.path().to_str().unwrap()).unwrap();
        unsafe {
            let mut client = ptr::null_mut();
            assert_eq!(
                marmot_client_new_with_options(
                    root.as_ptr(),
                    relays.as_ptr(),
                    1,
                    MarmotRelayPolicy::AllowLoopback as u32,
                    ptr::null(),
                    &mut client
                ),
                MarmotStatus::Ok
            );
            assert_eq!(marmot_client_start(client), MarmotStatus::Ok);
            let mut account = ptr::null_mut();
            assert_eq!(
                marmot_create_identity(
                    client,
                    relays.as_ptr(),
                    1,
                    relays.as_ptr(),
                    1,
                    ptr::null(),
                    0,
                    &mut account
                ),
                MarmotStatus::Ok
            );
            let mut group = ptr::null_mut();
            assert_eq!(
                marmot_create_group(
                    client,
                    (*account).account_id_hex,
                    c"draft version test".as_ptr(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut group
                ),
                MarmotStatus::Ok
            );
            let mut draft = ptr::null_mut();
            assert_eq!(
                marmot_save_message_draft(
                    client,
                    (*account).account_id_hex,
                    group,
                    c"same".as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    &mut draft
                ),
                MarmotStatus::Ok
            );
            marmot_message_draft_free(draft);
            let mut selected = ptr::null_mut();
            assert_eq!(
                marmot_selected_message_draft(
                    client,
                    (*account).account_id_hex,
                    group,
                    &mut selected
                ),
                MarmotStatus::Ok
            );
            let mut row = ptr::null_mut();
            assert_eq!(
                marmot_presented_chat_list_row(client, (*account).account_id_hex, group, &mut row),
                MarmotStatus::Ok
            );
            assert!(!row.is_null() && !(*row).draft_version.is_null());
            let mut covered = 9;
            assert_eq!(
                marmot_message_draft_revision_includes_chat_list_version(
                    (*selected).revision,
                    (*row).draft_version,
                    &mut covered
                ),
                MarmotStatus::Ok
            );
            assert_eq!(covered, 1);
            assert_eq!(
                marmot_message_draft_revision_includes_chat_list_version(
                    (*selected).revision,
                    ptr::null(),
                    &mut covered
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(covered, 0);
            covered = 9;
            assert_eq!(
                marmot_message_draft_revision_includes_chat_list_version(
                    ptr::null(),
                    (*row).draft_version,
                    &mut covered
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(covered, 0);
            marmot_presented_chat_row_free(row);
            // Same text saved again must not be covered by the older captured revision.
            assert_eq!(
                marmot_save_message_draft(
                    client,
                    (*account).account_id_hex,
                    group,
                    c"same".as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    &mut draft
                ),
                MarmotStatus::Ok
            );
            marmot_message_draft_free(draft);
            assert_eq!(
                marmot_presented_chat_list_row(client, (*account).account_id_hex, group, &mut row),
                MarmotStatus::Ok
            );
            assert!(!row.is_null() && !(*row).draft_version.is_null());
            assert_eq!(
                marmot_message_draft_revision_includes_chat_list_version(
                    (*selected).revision,
                    (*row).draft_version,
                    &mut covered
                ),
                MarmotStatus::Ok
            );
            assert_eq!(covered, 0);
            marmot_presented_chat_row_free(row);
            crate::types::conversation_window::marmot_selected_message_draft_free(selected);
            marmot_string_free(group);
            marmot_account_summary_free(account);
            assert_eq!(marmot_client_shutdown(client), MarmotStatus::Ok);
            marmot_client_free(client);
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(audit::live_allocations(), before);
    }
}
