//! Message history read plus send/react/reply/edit/delete commands.

use std::ffi::c_char;

use crate::memory::{optional_str, required_str};
use crate::status::MarmotStatus;
use crate::types::account::MarmotSendSummary;
use crate::types::message::{MarmotAppMessageRecordList, MarmotSecureDeleteExpiredResult};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::deliver;

/// Send a plain UTF-8 text message. Structured payloads (reactions,
/// replies, deletes, media) go through dedicated methods.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`, and
/// `text` valid strings; `out_summary` a valid pointer. Free the result
/// with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_send_text(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    text: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let text = try_arg!(unsafe { required_str(text) });
        unsafe {
            deliver(
                client.block_on(client.marmot.send_text(account_ref, group_id_hex, text)),
                out_summary,
            )
        }
    })
}

/// Re-attempt publishing a group's pending (committed-but-undelivered)
/// commit(s) without minting a new event.
///
/// An own send commits and projects locally *before* it publishes, so a
/// message sent while offline (or when the relay was unreachable) lands in
/// the timeline with `source_message_id_hex == NULL` — committed, not yet
/// delivered. Re-sending the same text would mint a fresh commit and event
/// id, duplicating the bubble. This drives the existing pending commit to
/// the relays via convergence instead, so the original timeline row flips
/// to delivered (`source_message_id_hex != NULL`) on success and no new
/// event is created. Returns the delivery summary; `published == 0` means
/// nothing was pending or publishing is still failing.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_summary` a valid pointer. Free the result with
/// `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_retry_group_convergence(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .retry_group_convergence(account_ref, group_id_hex),
                ),
                out_summary,
            )
        }
    })
}

/// React to `target_message_id` with `emoji` (an "add" reaction).
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`,
/// `target_message_id`, and `emoji` valid strings; `out_summary` a valid
/// pointer. Free the result with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_react_to_message(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target_message_id: *const c_char,
    emoji: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let target_message_id = try_arg!(unsafe { required_str(target_message_id) });
        let emoji = try_arg!(unsafe { required_str(emoji) });
        unsafe {
            deliver(
                client.block_on(client.marmot.react_to_message(
                    account_ref,
                    group_id_hex,
                    target_message_id,
                    emoji,
                )),
                out_summary,
            )
        }
    })
}

/// Remove this account's reaction from `target_message_id`.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`, and
/// `target_message_id` valid strings; `out_summary` a valid pointer. Free
/// the result with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_unreact_from_message(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target_message_id: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let target_message_id = try_arg!(unsafe { required_str(target_message_id) });
        unsafe {
            deliver(
                client.block_on(client.marmot.unreact_from_message(
                    account_ref,
                    group_id_hex,
                    target_message_id,
                )),
                out_summary,
            )
        }
    })
}

/// Send `text` as a reply that quotes `target_message_id`.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`,
/// `target_message_id`, and `text` valid strings; `out_summary` a valid
/// pointer. Free the result with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_reply_to_message(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target_message_id: *const c_char,
    text: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let target_message_id = try_arg!(unsafe { required_str(target_message_id) });
        let text = try_arg!(unsafe { required_str(text) });
        unsafe {
            deliver(
                client.block_on(client.marmot.reply_to_message(
                    account_ref,
                    group_id_hex,
                    target_message_id,
                    text,
                )),
                out_summary,
            )
        }
    })
}

/// Mark `target_message_id` deleted for the whole group. This is a
/// tombstone — the original stays in everyone's store; clients render a
/// "message deleted" placeholder.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`, and
/// `target_message_id` valid strings; `out_summary` a valid pointer. Free
/// the result with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_delete_message(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target_message_id: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let target_message_id = try_arg!(unsafe { required_str(target_message_id) });
        unsafe {
            deliver(
                client.block_on(client.marmot.delete_message(
                    account_ref,
                    group_id_hex,
                    target_message_id,
                )),
                out_summary,
            )
        }
    })
}

/// Securely scrub and prune expired disappearing-message plaintext for a
/// group according to its active retention component. The media hash list
/// identifies pruned encrypted-media blobs so host apps can purge their own
/// decrypted-media disk caches keyed by ciphertext hash.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_result` a valid pointer. Free the result with
/// `marmot_secure_delete_expired_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_secure_delete_expired(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_result: *mut *mut MarmotSecureDeleteExpiredResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .secure_delete_expired(account_ref, group_id_hex),
                ),
                out_result,
            )
        }
    })
}

/// Edit `target_message_id` by publishing a kind-1009 event that
/// references it and carries the replacement plaintext in `content`.
/// Recipients honour the edit only when its authenticated author matches
/// the target's author; mismatched edits are ignored client-side.
///
/// The chat-list preview deliberately does not bump on an edit — an edit
/// to a stale message must not reorder a conversation back to the top of
/// the list. Host apps that aggregate edit history (e.g. an "(edited · N)"
/// affordance) read the kind-1009 versions back from the timeline
/// projection and resolve the latest text per target message id.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`,
/// `target_message_id`, and `content` valid strings; `out_summary` a valid
/// pointer. Free the result with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_edit_message(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    target_message_id: *const c_char,
    content: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let target_message_id = try_arg!(unsafe { required_str(target_message_id) });
        let content = try_arg!(unsafe { required_str(content) });
        unsafe {
            deliver(
                client.block_on(client.marmot.edit_message(
                    account_ref,
                    group_id_hex,
                    target_message_id,
                    content,
                )),
                out_summary,
            )
        }
    })
}

/// Initial history fetch for a group (or, when `group_id_hex` is NULL,
/// the account-wide tail). Used to populate the conversation view before
/// the subscription stream takes over. When `has_limit` is false, `limit`
/// is ignored and no row cap is applied.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `group_id_hex` NULL or a valid string; `out_list` a valid pointer.
/// Free the result with `marmot_app_message_record_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_messages(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    has_limit: bool,
    limit: u32,
    out_list: *mut *mut MarmotAppMessageRecordList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { optional_str(group_id_hex) });
        let limit = has_limit.then_some(limit);
        unsafe {
            deliver(
                client.marmot.messages(account_ref, group_id_hex, limit),
                out_list,
            )
        }
    })
}
