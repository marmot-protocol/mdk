//! Manage storage (mdk#2314 step 5): usage, largest-first listings with
//! borrowed opaque cursors, and bulk removal. Calls block: use off the UI
//! thread.
use crate::commands::{deliver, deliver_scalar, try_arg};
use crate::macros::{c_enum, c_mirror};
use crate::memory::{
    CFree, boxed_opt, free_boxed, free_c_string, free_guard, free_vec, optional_str,
    owned_c_string, owned_vec, required_str,
};
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out, preflight_out_ptr};
use marmot_uniffi::conversions::*;
use std::{ffi::c_char, sync::Arc};

c_mirror! {
    /// Account-wide attachment storage across both body layouts.
    MarmotAttachmentStorageUsage from AttachmentStorageUsageFfi,
    free marmot_attachment_storage_usage_free {
        copy media_bytes: u64,
        copy legacy_bytes: u64,
        copy attachment_count: u64,
        copy database_bytes: u64,
        copy database_free_bytes: u64,
        copy migration: MarmotAttachmentMigrationState,
        copy migration_bytes: u64,
        copy cache_bytes: u64,
        /// Composer-draft attachments staged as media-store files.
        copy draft_bytes: u64,
    }
}

c_enum! {
    /// Where moving legacy attachment bodies into the media store stands.
    MarmotAttachmentMigrationState from AttachmentMigrationStateFfi {
        NotNeeded,
        Running,
        Paused,
        Complete,
        Compacting,
    }
}

c_enum! {
    /// How long retained attachments are kept on this device, per account
    /// ("Keep media"). Forever is the default.
    MarmotAttachmentKeepMedia from AttachmentKeepMediaFfi {
        Forever,
        OneYear,
        SixMonths,
        ThirtyDays,
    }
}

/// Where the next page of chats starts. Borrowed from its page.
pub struct MarmotChatStorageCursor {
    inner: Arc<ChatStorageCursor>,
}
impl From<Arc<ChatStorageCursor>> for MarmotChatStorageCursor {
    fn from(inner: Arc<ChatStorageCursor>) -> Self {
        Self { inner }
    }
}
impl CFree for MarmotChatStorageCursor {
    unsafe fn free_in_place(&mut self) {}
}

/// Where the next page of attachments starts. Borrowed from its page.
pub struct MarmotRetainedAttachmentsCursor {
    inner: Arc<RetainedAttachmentsCursor>,
}
impl From<Arc<RetainedAttachmentsCursor>> for MarmotRetainedAttachmentsCursor {
    fn from(inner: Arc<RetainedAttachmentsCursor>) -> Self {
        Self { inner }
    }
}
impl CFree for MarmotRetainedAttachmentsCursor {
    unsafe fn free_in_place(&mut self) {}
}

c_mirror! {
    /// One chat's retained attachment storage; a stored file counts once.
    MarmotChatAttachmentUsage from ChatAttachmentUsageFfi {
        str group_id_hex,
        copy bytes: u64,
        copy attachment_count: u64,
    }
}

/// Chats by storage, largest first. Continue with next_cursor while it is not
/// NULL; it is borrowed from this page.
#[repr(C)]
pub struct MarmotChatStoragePage {
    pub chats: *mut MarmotChatAttachmentUsage,
    pub chats_len: usize,
    pub next_cursor: *mut MarmotChatStorageCursor,
}
impl From<ChatStoragePageFfi> for MarmotChatStoragePage {
    fn from(v: ChatStoragePageFfi) -> Self {
        let (chats, chats_len) = owned_vec(v.chats.into_iter().map(Into::into).collect());
        Self {
            chats,
            chats_len,
            next_cursor: boxed_opt(v.next_cursor.map(Into::into)),
        }
    }
}
impl CFree for MarmotChatStoragePage {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.chats, self.chats_len);
            free_boxed(self.next_cursor);
        }
    }
}

/// One retained attachment. message_id_hex, source_message_id_hex and
/// attachment_index form the target for marmot_attachment_local_assets,
/// marmot_open_attachment_handoff and removal.
#[repr(C)]
pub struct MarmotRetainedAttachmentSummary {
    pub group_id_hex: *mut c_char,
    pub message_id_hex: *mut c_char,
    pub source_message_id_hex: *mut c_char,
    pub attachment_index: u32,
    pub byte_count: u64,
    pub media_type: *mut c_char,
    pub file_name: *mut c_char,
    pub received_at: u64,
}
impl From<RetainedAttachmentSummaryFfi> for MarmotRetainedAttachmentSummary {
    fn from(v: RetainedAttachmentSummaryFfi) -> Self {
        Self {
            group_id_hex: owned_c_string(v.group_id_hex),
            message_id_hex: owned_c_string(v.target.message_id_hex),
            source_message_id_hex: owned_c_string(v.target.source_message_id_hex),
            attachment_index: v.target.attachment_index,
            byte_count: v.byte_count,
            media_type: owned_c_string(v.media_type),
            file_name: owned_c_string(v.file_name),
            received_at: v.received_at,
        }
    }
}
impl CFree for MarmotRetainedAttachmentSummary {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            free_c_string(self.message_id_hex);
            free_c_string(self.source_message_id_hex);
            free_c_string(self.media_type);
            free_c_string(self.file_name);
        }
    }
}

/// Retained attachments, largest first. Continue with next_cursor while it is
/// not NULL; it is borrowed from this page.
#[repr(C)]
pub struct MarmotRetainedAttachmentsPage {
    pub attachments: *mut MarmotRetainedAttachmentSummary,
    pub attachments_len: usize,
    pub next_cursor: *mut MarmotRetainedAttachmentsCursor,
}
impl From<RetainedAttachmentsPageFfi> for MarmotRetainedAttachmentsPage {
    fn from(v: RetainedAttachmentsPageFfi) -> Self {
        let (attachments, attachments_len) =
            owned_vec(v.attachments.into_iter().map(Into::into).collect());
        Self {
            attachments,
            attachments_len,
            next_cursor: boxed_opt(v.next_cursor.map(Into::into)),
        }
    }
}
impl CFree for MarmotRetainedAttachmentsPage {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.attachments, self.attachments_len);
            free_boxed(self.next_cursor);
        }
    }
}

/// Deep-free a chat storage page, including its cursor. NULL is a no-op.
/// # Safety
/// Value must be NULL or an owned, unfreed page with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_storage_page_free(value: *mut MarmotChatStoragePage) {
    free_guard(|| unsafe { free_boxed(value) });
}

/// Deep-free a retained attachments page, including its cursor. NULL is a
/// no-op.
/// # Safety
/// Value must be NULL or an owned, unfreed page with no outstanding borrows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_retained_attachments_page_free(
    value: *mut MarmotRetainedAttachmentsPage,
) {
    free_guard(|| unsafe { free_boxed(value) });
}

/// Account-wide attachment storage. Blocking local read; reads no bodies.
/// # Safety
/// Client and string must be live; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_storage_usage(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out: *mut *mut MarmotAttachmentStorageUsage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.attachment_storage_usage(account)),
                out,
            )
        }
    })
}

/// Chats by retained attachment bytes, largest first; limit is 1..=256.
/// Cursor is NULL for the first page, else a page's borrowed next_cursor
/// (keep that page alive for the call). Blocking local read.
/// # Safety
/// Client and string must be live, cursor NULL or live, out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_storage_by_chat(
    client: *const MarmotClient,
    account_ref: *const c_char,
    limit: u32,
    cursor: *const MarmotChatStorageCursor,
    out: *mut *mut MarmotChatStoragePage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let cursor = unsafe { cursor.as_ref() }.map(|cursor| cursor.inner.clone());
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .attachment_storage_by_chat(account, limit, cursor),
                ),
                out,
            )
        }
    })
}

/// Retained attachments, largest first; limit is 1..=256. group_id_hex NULL
/// lists the whole account. Cursor as for marmot_attachment_storage_by_chat.
/// Blocking local read.
/// # Safety
/// Client and strings must be live (group may be NULL), cursor NULL or live,
/// out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_largest_retained_attachments(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    limit: u32,
    cursor: *const MarmotRetainedAttachmentsCursor,
    out: *mut *mut MarmotRetainedAttachmentsPage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { optional_str(group_id_hex) });
        let cursor = unsafe { cursor.as_ref() }.map(|cursor| cursor.inner.clone());
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .largest_retained_attachments(account, group, limit, cursor),
                ),
                out,
            )
        }
    })
}

/// Removes every retained attachment in one chat, as Remove does, writing
/// how many it removed. Media-store space is freed before this returns.
/// Blocking.
/// # Safety
/// Client and strings must be live; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_remove_chat_attachments(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_removed: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out_removed) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.remove_chat_attachments(account, group)),
                out_removed,
            )
        }
    })
}

/// Removes retained attachments of messages received before
/// received_before (Unix seconds), across the account (group_id_hex NULL) or
/// within one chat, as Remove does, writing how many it removed. Blocking.
/// # Safety
/// Client and strings must be live (group may be NULL); out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_remove_attachments_older_than(
    client: *const MarmotClient,
    account_ref: *const c_char,
    received_before: u64,
    group_id_hex: *const c_char,
    out_removed: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out_removed) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { optional_str(group_id_hex) });
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.remove_attachments_older_than(
                    account,
                    received_before,
                    group,
                )),
                out_removed,
            )
        }
    })
}

/// Writes the account's "Keep media" setting as a MarmotAttachmentKeepMedia
/// discriminant. Blocking.
/// # Safety
/// Client and string must be live; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_keep_media(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_keep: *mut u32,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out_keep) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver_scalar(
                client
                    .block_on(client.marmot.attachment_keep_media(account))
                    .map(|keep| MarmotAttachmentKeepMedia::from(keep) as u32),
                out_keep,
            )
        }
    })
}

/// Sets the account's "Keep media" setting (a MarmotAttachmentKeepMedia
/// discriminant), then removes every retained attachment already past the
/// new window, writing how many it removed. They show as CleanedBySetting
/// (download again allowed); media-store space is freed before this returns.
/// Forever removes nothing. Blocking.
/// # Safety
/// Client and string must be live; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_attachment_keep_media(
    client: *const MarmotClient,
    account_ref: *const c_char,
    keep: u32,
    out_removed: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out_removed) });
        let keep = try_arg!(MarmotAttachmentKeepMedia::from_c(keep));
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let keep = match keep {
            MarmotAttachmentKeepMedia::Forever => AttachmentKeepMediaFfi::Forever,
            MarmotAttachmentKeepMedia::OneYear => AttachmentKeepMediaFfi::OneYear,
            MarmotAttachmentKeepMedia::SixMonths => AttachmentKeepMediaFfi::SixMonths,
            MarmotAttachmentKeepMedia::ThirtyDays => AttachmentKeepMediaFfi::ThirtyDays,
        };
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.set_attachment_keep_media(account, keep)),
                out_removed,
            )
        }
    })
}

c_enum! {
    /// Historical body-loss reason, not current byte-read authorization.
    MarmotAttachmentBodyRemovalState from AttachmentBodyRemovalStateFfi {
        CleanedBySetting,
        Removed,
        CompletedUnretained,
        Unavailable,
    }
}

c_mirror! {
    /// Source-slot identity borrowed from its containing removal page.
    MarmotAttachmentBodyRemoval from AttachmentBodyRemovalFfi {
        str group_id_hex,
        str message_id_hex,
        str source_message_id_hex,
        copy attachment_index: u32,
        copy state: MarmotAttachmentBodyRemovalState,
    }
}

impl std::fmt::Debug for MarmotAttachmentBodyRemoval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarmotAttachmentBodyRemoval")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

c_mirror! {
    /// Owned durable removal page; free only with
    /// marmot_body_removal_page_free, including its strings and array.
    /// Copy next_cursor before freeing if it will be persisted or reused.
    MarmotAttachmentBodyRemovalPage from AttachmentBodyRemovalPageFfi,
    free marmot_body_removal_page_free {
        vec removals/removals_len: MarmotAttachmentBodyRemoval,
        str next_cursor,
        copy reset_required: bool,
        copy has_more: bool,
    }
}

impl std::fmt::Debug for MarmotAttachmentBodyRemovalPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarmotAttachmentBodyRemovalPage")
            .field("removal_count", &self.removals_len)
            .field("reset_required", &self.reset_required)
            .field("has_more", &self.has_more)
            .finish_non_exhaustive()
    }
}

/// Local durable body-removal journal; limit is 1..=256. Cursor is a
/// borrowed nullable string. NULL captures the current high water with
/// reset_required=true and no records. Reconcile the derivative cache before
/// persisting that captured cursor. Invalidated cursors also require reset.
/// Otherwise evict returned identities idempotently, persist next_cursor,
/// and continue while has_more. Historical states never authorize byte reads.
/// Blocking; call off the UI thread. Free with
/// marmot_body_removal_page_free.
/// # Safety
/// Client and account string must be live, cursor NULL or a live string,
/// and out writable. Inputs are borrowed only for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_attachment_removals(
    client: *const MarmotClient,
    account_ref: *const c_char,
    cursor: *const c_char,
    limit: u32,
    out: *mut *mut MarmotAttachmentBodyRemovalPage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let cursor = try_arg!(unsafe { optional_str(cursor) });
        unsafe {
            deliver(
                client.block_on(client.marmot.attachment_removals(account, cursor, limit)),
                out,
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    use std::ptr;

    #[test]
    fn body_removal_page_owns_fields() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        let states = [
            AttachmentBodyRemovalStateFfi::CleanedBySetting,
            AttachmentBodyRemovalStateFfi::Removed,
            AttachmentBodyRemovalStateFfi::CompletedUnretained,
            AttachmentBodyRemovalStateFfi::Unavailable,
        ];
        let page: MarmotAttachmentBodyRemovalPage = AttachmentBodyRemovalPageFfi {
            removals: states
                .into_iter()
                .map(|state| AttachmentBodyRemovalFfi {
                    group_id_hex: "ab".repeat(16),
                    message_id_hex: "cd".repeat(32),
                    source_message_id_hex: "ef".repeat(32),
                    attachment_index: 7,
                    state,
                })
                .collect(),
            next_cursor: "durable-cursor".into(),
            reset_required: false,
            has_more: true,
        }
        .into();
        assert_eq!(page.removals_len, 4);
        assert!(!page.reset_required && page.has_more);
        assert_eq!(
            format!("{page:?}"),
            "MarmotAttachmentBodyRemovalPage { removal_count: 4, reset_required: false, has_more: true, .. }"
        );
        unsafe {
            assert_eq!(
                std::ffi::CStr::from_ptr(page.next_cursor).to_str().unwrap(),
                "durable-cursor"
            );
            for (index, removal) in std::slice::from_raw_parts(page.removals, page.removals_len)
                .iter()
                .enumerate()
            {
                assert_eq!(removal.state as u32, index as u32);
                assert_eq!(
                    std::ffi::CStr::from_ptr(removal.group_id_hex)
                        .to_str()
                        .unwrap(),
                    "ab".repeat(16)
                );
                assert_eq!(
                    std::ffi::CStr::from_ptr(removal.message_id_hex)
                        .to_str()
                        .unwrap(),
                    "cd".repeat(32)
                );
                assert_eq!(
                    std::ffi::CStr::from_ptr(removal.source_message_id_hex)
                        .to_str()
                        .unwrap(),
                    "ef".repeat(32)
                );
                assert_eq!(removal.attachment_index, 7);
                assert_eq!(
                    format!("{removal:?}"),
                    format!(
                        "MarmotAttachmentBodyRemoval {{ state: {:?}, .. }}",
                        removal.state
                    )
                );
            }
            marmot_body_removal_page_free(boxed(page));
            let reset: MarmotAttachmentBodyRemovalPage = AttachmentBodyRemovalPageFfi {
                removals: Vec::new(),
                next_cursor: "captured-high-water".into(),
                reset_required: true,
                has_more: false,
            }
            .into();
            assert!(reset.removals.is_null());
            assert_eq!(reset.removals_len, 0);
            assert!(reset.reset_required && !reset.has_more);
            assert_eq!(
                std::ffi::CStr::from_ptr(reset.next_cursor)
                    .to_str()
                    .unwrap(),
                "captured-high-water"
            );
            marmot_body_removal_page_free(boxed(reset));
            marmot_body_removal_page_free(ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(audit::live_allocations(), before);
    }

    /// NULL inputs are refused before any work; pages and their borrowed
    /// cursors deep-free; a live client reads an empty account.
    #[test]
    fn attachment_storage_c_validates_frees_and_reads() {
        let _guard = audit::test_lock();
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        unsafe {
            let mut usage = ptr::dangling_mut();
            assert_eq!(
                marmot_attachment_storage_usage(ptr::null(), ptr::null(), &mut usage),
                MarmotStatus::NullPointer
            );
            assert!(usage.is_null());
            let mut removed = 7u64;
            assert_eq!(
                marmot_remove_chat_attachments(ptr::null(), ptr::null(), ptr::null(), &mut removed),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_remove_attachments_older_than(
                    ptr::null(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );

            let page: MarmotChatStoragePage = ChatStoragePageFfi {
                chats: vec![ChatAttachmentUsageFfi {
                    group_id_hex: "ab".repeat(16),
                    bytes: 9,
                    attachment_count: 1,
                }],
                next_cursor: None,
            }
            .into();
            assert_eq!(page.chats_len, 1);
            assert!(page.next_cursor.is_null());
            marmot_chat_storage_page_free(boxed(page));
            let attachments: MarmotRetainedAttachmentsPage = RetainedAttachmentsPageFfi {
                attachments: vec![RetainedAttachmentSummaryFfi {
                    group_id_hex: "ab".repeat(16),
                    target: AttachmentLocalTargetFfi {
                        message_id_hex: "aa".repeat(32),
                        source_message_id_hex: "bb".repeat(32),
                        attachment_index: 2,
                    },
                    byte_count: 7,
                    media_type: "image/png".into(),
                    file_name: "photo.png".into(),
                    received_at: 5,
                }],
                next_cursor: None,
            }
            .into();
            assert_eq!((*attachments.attachments).attachment_index, 2);
            marmot_retained_attachments_page_free(boxed(attachments));
            marmot_chat_storage_page_free(ptr::null_mut());
            marmot_retained_attachments_page_free(ptr::null_mut());
            marmot_attachment_storage_usage_free(ptr::null_mut());

            let home = tempfile::tempdir().unwrap();
            let root = std::ffi::CString::new(home.path().to_str().unwrap()).unwrap();
            let relays = [c"wss://relay.example".as_ptr()];
            let mut client = ptr::null_mut();
            assert_eq!(
                crate::marmot_client_new(
                    root.as_ptr(),
                    relays.as_ptr(),
                    1,
                    crate::deployment::OwnedDeployment::white_noise().as_ptr(),
                    &mut client,
                ),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_attachment_storage_usage(client, c"absent".as_ptr(), &mut usage),
                MarmotStatus::UnknownAccount,
                "an unknown account is an error"
            );
            assert!(usage.is_null());
            let mut removed = 9u64;
            assert_eq!(
                marmot_remove_chat_attachments(
                    client,
                    c"absent".as_ptr(),
                    c"abababababababababababababababab".as_ptr(),
                    &mut removed
                ),
                MarmotStatus::UnknownAccount
            );
            assert_eq!(removed, 0, "a failed call clears a stale count");
            removed = 9;
            assert_eq!(
                marmot_remove_attachments_older_than(
                    client,
                    c"absent".as_ptr(),
                    1,
                    ptr::null(),
                    &mut removed
                ),
                MarmotStatus::UnknownAccount
            );
            assert_eq!(removed, 0);
            let mut keep = 9u32;
            assert_eq!(
                marmot_attachment_keep_media(client, ptr::null(), &mut keep),
                MarmotStatus::NullPointer
            );
            assert_eq!(keep, 0, "cleared before the call");
            assert_eq!(
                marmot_attachment_keep_media(client, c"absent".as_ptr(), &mut keep),
                MarmotStatus::UnknownAccount
            );
            removed = 9;
            assert_eq!(
                marmot_set_attachment_keep_media(client, c"absent".as_ptr(), 4, &mut removed),
                MarmotStatus::InvalidArgument,
                "an out-of-range setting is refused before any work"
            );
            assert_eq!(removed, 0);
            assert_eq!(
                marmot_set_attachment_keep_media(
                    client,
                    c"absent".as_ptr(),
                    MarmotAttachmentKeepMedia::ThirtyDays as u32,
                    &mut removed
                ),
                MarmotStatus::UnknownAccount
            );
            assert_eq!(crate::marmot_client_shutdown(client), MarmotStatus::Ok);
            crate::marmot_client_free(client);
        }
    }
}
