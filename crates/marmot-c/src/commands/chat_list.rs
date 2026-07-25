//! Durable chat-list and chat read-state commands.

use std::ffi::c_char;

use crate::memory::required_str;
use crate::status::MarmotStatus;
use crate::types::chat_list::{MarmotChatListRow, MarmotChatListRowList};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::{deliver, deliver_opt};

/// Durable chat-list rows for fast app launch. Rows include the group
/// title/avatar, last kind-9 preview, unread count, and read anchors.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_list` a valid pointer. Free the result with
/// `marmot_chat_list_row_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list(
    client: *const MarmotClient,
    account_ref: *const c_char,
    include_archived: bool,
    out_list: *mut *mut MarmotChatListRowList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.marmot.chat_list(account_ref, include_archived),
                out_list,
            )
        }
    })
}

/// Establish the unread baseline the first time a user opens a group.
/// Existing kind-9 history remains read; later remote kind-9 messages count
/// until marked visible via `marmot_mark_timeline_message_read`. Writes NULL
/// with `MARMOT_STATUS_OK` when the group has no chat-list row.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_row` a valid pointer. Free the result with
/// `marmot_chat_list_row_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_initialize_chat_read_state(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_row: *mut *mut MarmotChatListRow,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver_opt(
                client
                    .marmot
                    .initialize_chat_read_state(account_ref, group_id_hex),
                out_row,
            )
        }
    })
}

/// Mark a kind-9 timeline message visible/read. Own kind-9 messages can
/// advance the marker too, which clears any earlier unread messages. Writes
/// NULL with `MARMOT_STATUS_OK` when the group has no chat-list row.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`, and
/// `message_id_hex` valid strings; `out_row` a valid pointer. Free the
/// result with `marmot_chat_list_row_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_mark_timeline_message_read(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    message_id_hex: *const c_char,
    out_row: *mut *mut MarmotChatListRow,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let message_id_hex = try_arg!(unsafe { required_str(message_id_hex) });
        unsafe {
            deliver_opt(
                client
                    .marmot
                    .mark_timeline_message_read(account_ref, group_id_hex, message_id_hex),
                out_row,
            )
        }
    })
}
