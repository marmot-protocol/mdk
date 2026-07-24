//! Encrypted-media upload/download/send/list commands.

use std::ffi::c_char;

use crate::memory::{optional_str, required_str};
use crate::status::MarmotStatus;
use crate::types::account::MarmotSendSummary;
use crate::types::media::{
    MarmotMediaAttachmentReference, MarmotMediaDownloadResult, MarmotMediaRecordList,
    MarmotMediaUploadRequest, MarmotMediaUploadResult,
};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::deliver;

/// Send already-uploaded encrypted media attachments as a kind-9 chat
/// carrying ordered NIP-92 `imeta` tags.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `attachments` must point to `attachments_len` valid borrowed
/// attachment references (or be NULL with len 0); `caption` NULL or a valid
/// string; `out_summary` valid. Input structs are never freed by the
/// library. Free the result with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_send_media_attachments(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    attachments: *const MarmotMediaAttachmentReference,
    attachments_len: usize,
    caption: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let attachments = if attachments.is_null() {
            if attachments_len != 0 {
                crate::status::set_last_error(
                    "media attachment array was NULL with nonzero length",
                );
                return MarmotStatus::NullPointer;
            }
            Vec::new()
        } else {
            let borrowed = unsafe { std::slice::from_raw_parts(attachments, attachments_len) };
            let mut converted = Vec::with_capacity(attachments_len);
            for attachment in borrowed {
                converted.push(try_arg!(unsafe { attachment.to_ffi() }));
            }
            converted
        };
        let caption = try_arg!(unsafe { optional_str(caption) });
        unsafe {
            deliver(
                client.block_on(client.marmot.send_media_attachments(
                    account_ref,
                    group_id_hex,
                    attachments,
                    caption,
                )),
                out_summary,
            )
        }
    })
}

/// Backward-compatible single-attachment send helper. Prefer
/// `marmot_send_media_attachments` for new callers so one chat can carry
/// ordered mixed media attachments.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `reference` a valid borrowed attachment reference (never freed
/// by the library); `caption` NULL or a valid string; `out_summary` valid.
/// Free the result with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_send_media_reference(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    reference: *const MarmotMediaAttachmentReference,
    caption: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        if reference.is_null() {
            crate::status::set_last_error("reference argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let reference = try_arg!(unsafe { (*reference).to_ffi() });
        let caption = try_arg!(unsafe { optional_str(caption) });
        unsafe {
            deliver(
                client.block_on(client.marmot.send_media_reference(
                    account_ref,
                    group_id_hex,
                    reference,
                    caption,
                )),
                out_summary,
            )
        }
    })
}

/// Encrypt plaintext attachments, upload the ciphertext blobs, and
/// optionally send the resulting media references into the group.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `request` a valid borrowed upload request (never freed by the
/// library); `out_result` valid. Free the result with
/// `marmot_media_upload_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_upload_media(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    request: *const MarmotMediaUploadRequest,
    out_result: *mut *mut MarmotMediaUploadResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        if request.is_null() {
            crate::status::set_last_error("request argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let request = try_arg!(unsafe { (*request).to_ffi() });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .upload_media(account_ref, group_id_hex, request),
                ),
                out_result,
            )
        }
    })
}

/// Fetch an encrypted media blob and decrypt it using the group's
/// encrypted media component secret.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `reference` a valid borrowed attachment reference (never freed
/// by the library); `out_result` valid. Free the result with
/// `marmot_media_download_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_download_media(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    reference: *const MarmotMediaAttachmentReference,
    out_result: *mut *mut MarmotMediaDownloadResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        if reference.is_null() {
            crate::status::set_last_error("reference argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let reference = try_arg!(unsafe { (*reference).to_ffi() });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .download_media(account_ref, group_id_hex, reference),
                ),
                out_result,
            )
        }
    })
}

/// Typed media references projected from group message history. Each
/// record's embedded `reference` can be passed back to
/// `marmot_download_media`. When `has_limit` is false, `limit` is ignored
/// and the full history is projected.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_list` valid. Free the result with
/// `marmot_media_record_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_list_media(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    has_limit: bool,
    limit: u32,
    out_list: *mut *mut MarmotMediaRecordList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let limit = has_limit.then_some(limit);
        unsafe {
            deliver::<_, MarmotMediaRecordList>(
                client.marmot.list_media(account_ref, group_id_hex, limit),
                out_list,
            )
        }
    })
}
