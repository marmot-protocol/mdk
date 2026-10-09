//! Opaque account-local fixed-view intent. Free only when no call is in flight.
use super::*;
use crate::types::chat_window::{
    MarmotChatListView, MarmotChatSelectionPage, MarmotChatSelectionSummary,
};

pub struct MarmotChatListSelection {
    inner: Arc<marmot_uniffi::ChatListSelection>,
    runtime: Handle,
}
impl Drop for MarmotChatListSelection {
    fn drop(&mut self) {
        self.inner.close();
    }
}

/// Capture all eligible IDs in one fixed native view; no display-row hydration.
/// # Safety
/// client and account_ref must be live; out must be writable. View is a validated
/// MarmotChatListView discriminant. Free the returned handle before its client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_capture_chat_list_selection(
    client: *const MarmotClient,
    account_ref: *const c_char,
    view: u32,
    out: *mut *mut MarmotChatListSelection,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let view = try_arg!(MarmotChatListView::from_c(view)).to_ffi();
        match client.block_on(client.marmot.capture_chat_list_selection(account, view)) {
            Ok(inner) => unsafe {
                write_handle(
                    MarmotChatListSelection {
                        inner,
                        runtime: client.runtime.handle().clone(),
                    },
                    out,
                )
            },
            Err(error) => status_from_error(&error),
        }
    })
}

/// Complete count and revision; deep-free with marmot_chat_selection_summary_free.
/// # Safety
/// selection must be live for the call and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_selection_count(
    selection: *const MarmotChatListSelection,
    out: *mut *mut MarmotChatSelectionSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        unsafe {
            deliver(
                block_on_handle(&selection.runtime, selection.inner.count()),
                out,
            )
        }
    })
}

/// At most 200 frozen IDs; revision must match the current selection.
/// Deep-free the page with marmot_chat_selection_page_free.
/// # Safety
/// selection must be live for the call and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_selection_page(
    selection: *const MarmotChatListSelection,
    revision: u64,
    offset: u64,
    limit: u32,
    out: *mut *mut MarmotChatSelectionPage,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        unsafe {
            deliver(
                block_on_handle(
                    &selection.runtime,
                    selection.inner.page(revision, offset, limit),
                ),
                out,
            )
        }
    })
}

/// Remove one frozen ID, never add an externally supplied ID. Returns new count/revision.
/// # Safety
/// selection and borrowed group_id_hex must be live; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_selection_deselect(
    selection: *const MarmotChatListSelection,
    revision: u64,
    group_id_hex: *const c_char,
    out: *mut *mut MarmotChatSelectionSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        let id = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                block_on_handle(&selection.runtime, selection.inner.deselect(revision, id)),
                out,
            )
        }
    })
}

/// Remove no-longer-eligible IDs before an action. All old pages become stale;
/// each command still enforces its own authorization and mutation preconditions.
/// # Safety
/// selection must be live for the call and out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_selection_revalidate(
    selection: *const MarmotChatListSelection,
    revision: u64,
    out: *mut *mut MarmotChatSelectionSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let selection = try_arg!(unsafe { sub_ref(selection) });
        unsafe {
            deliver(
                block_on_handle(&selection.runtime, selection.inner.revalidate(revision)),
                out,
            )
        }
    })
}

/// Idempotent close, without freeing the handle. Pending operations return closed.
/// # Safety
/// selection must be live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_selection_close(
    selection: *const MarmotChatListSelection,
) -> MarmotStatus {
    ffi_guard(|| {
        let selection = try_arg!(unsafe { sub_ref(selection) });
        selection.inner.close();
        MarmotStatus::Ok
    })
}

/// Close and free; NULL is a no-op. Previously returned results remain caller-owned.
/// # Safety
/// selection must be NULL or a library-owned handle with no active calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_selection_free(selection: *mut MarmotChatListSelection) {
    crate::memory::free_guard(|| unsafe { free_plain(selection) });
}
