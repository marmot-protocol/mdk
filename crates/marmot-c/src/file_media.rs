//! File-backed media inputs and thread-safe operation control. No payload arrays cross the ABI.
use crate::commands::{deliver, try_arg};
use crate::memory::{CFree, boxed, c_bool, free_boxed, optional_str, required_str};
use crate::status::set_last_error;
use crate::types::common::MarmotStringArray;
use crate::types::local_submissions::MarmotMediaUploadSubmission;
use crate::types::media::MarmotMediaUploadResult;
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out, preflight_out_ptr};
use marmot_uniffi::conversions::{
    MediaFileTransferControlFfi, MediaFileUploadAttachmentRequestFfi, MediaFileUploadRequestFfi,
};
use std::{ffi::c_char, sync::Arc};

/// Borrowed private input. Its path is local only and is never published.
#[repr(C)]
pub struct MarmotMediaFileUploadAttachmentRequest {
    pub source_path: *const c_char,
    /// Nonzero requires the immutable snapshot to contain exactly expected_size bytes.
    pub has_expected_size: u8,
    pub expected_size: u64,
    pub file_name: *const c_char,
    pub media_type: *const c_char,
    pub dim: *const c_char,
    pub thumbhash: *const c_char,
}

/// Borrowed input batch. Snapshots are copied before the first network side effect.
#[repr(C)]
pub struct MarmotMediaFileUploadRequest {
    pub attachments: *const MarmotMediaFileUploadAttachmentRequest,
    pub attachments_len: usize,
    pub caption: *const c_char,
    pub send: u8,
    pub blossom_server: *const c_char,
    pub message_tags: *const MarmotStringArray,
    pub message_tags_len: usize,
}

impl MarmotMediaFileUploadRequest {
    unsafe fn to_ffi(&self) -> Result<MediaFileUploadRequestFfi, MarmotStatus> {
        if self.attachments_len == 0 || self.attachments_len > 64 {
            set_last_error("invalid file attachment count");
            return Err(MarmotStatus::InvalidArgument);
        }
        if self.attachments.is_null() {
            return Err(MarmotStatus::NullPointer);
        }
        let mut attachments = Vec::with_capacity(self.attachments_len);
        for item in unsafe { std::slice::from_raw_parts(self.attachments, self.attachments_len) } {
            attachments.push(MediaFileUploadAttachmentRequestFfi {
                source_path: unsafe { required_str(item.source_path) }?,
                expected_size: c_bool(item.has_expected_size).then_some(item.expected_size),
                file_name: unsafe { required_str(item.file_name) }?,
                media_type: unsafe { required_str(item.media_type) }?,
                dim: unsafe { optional_str(item.dim) }?,
                thumbhash: unsafe { optional_str(item.thumbhash) }?,
            });
        }
        Ok(MediaFileUploadRequestFfi {
            attachments,
            caption: unsafe { optional_str(self.caption) }?,
            send: c_bool(self.send),
            blossom_server: unsafe { optional_str(self.blossom_server) }?,
            message_tags: unsafe {
                crate::commands::struct_array(self.message_tags, self.message_tags_len, |row| {
                    crate::memory::str_array(row.values, row.values_len)
                })
            }?,
        })
    }
}

/// One operation's control. Query/cancel concurrently; never free during any call on the handle.
pub struct MarmotMediaFileTransferControl {
    inner: Arc<MediaFileTransferControlFfi>,
}
impl CFree for MarmotMediaFileTransferControl {
    unsafe fn free_in_place(&mut self) {}
}

/// Create a control; free it with marmot_media_file_transfer_control_free after upload returns.
/// # Safety
/// out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_file_transfer_control_new(
    out: *mut *mut MarmotMediaFileTransferControl,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        unsafe {
            out.write(boxed(MarmotMediaFileTransferControl {
                inner: MediaFileTransferControlFfi::new(),
            }))
        };
        MarmotStatus::Ok
    })
}
/// Cancel before durable admission; already admitted delivery stays owned by the local-send queue.
/// # Safety
/// control must be live; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_file_transfer_control_cancel(
    control: *const MarmotMediaFileTransferControl,
) -> MarmotStatus {
    ffi_guard(|| {
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        control.inner.cancel();
        MarmotStatus::Ok
    })
}
/// Read cancellation as uint8_t (0 or 1).
/// # Safety
/// control must be live; out writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_file_transfer_control_is_cancelled(
    control: *const MarmotMediaFileTransferControl,
    out: *mut u8,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe { out.write(u8::from(control.inner.is_cancelled())) };
        MarmotStatus::Ok
    })
}
/// Read monotonic processed bytes, not a percentage (preparation and retries can exceed file length).
/// # Safety
/// control must be live; out writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_file_transfer_control_processed_bytes(
    control: *const MarmotMediaFileTransferControl,
    out: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe { out.write(control.inner.processed_bytes()) };
        MarmotStatus::Ok
    })
}
/// Free a control; NULL is accepted.
/// # Safety
/// control must be NULL or live, with all calls on it finished.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_media_file_transfer_control_free(
    control: *mut MarmotMediaFileTransferControl,
) {
    ffi_guard(|| {
        unsafe { free_boxed(control) };
        MarmotStatus::Ok
    });
}
/// Return the per-batch ciphertext implementation bound, including each attachment's AEAD tag.
#[unsafe(no_mangle)]
pub extern "C" fn marmot_max_file_media_ciphertext_bytes() -> u64 {
    let mut limit = 0;
    ffi_guard(|| {
        limit = marmot_uniffi::conversions::max_file_media_ciphertext_bytes();
        MarmotStatus::Ok
    });
    limit
}
/// Blocking file-backed upload. Results use marmot_media_upload_result_free; inputs remain borrowed.
/// # Safety
/// client/control must be live; strings/request valid until return; out writable. No concurrent frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_upload_media_files(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    request: *const MarmotMediaFileUploadRequest,
    control: *const MarmotMediaFileTransferControl,
    out: *mut *mut MarmotMediaUploadResult,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let Some(request) = (unsafe { request.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let request = try_arg!(unsafe { request.to_ffi() });
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe {
            deliver(
                client.block_on(client.marmot.upload_media_files(
                    account,
                    group,
                    request,
                    control.inner.clone(),
                )),
                out,
            )
        }
    })
}
/// Blocking token-aware twin. Keep one token for the logical submission; probe local-send status after interruption.
/// Results use marmot_media_upload_submission_free; input paths are copied, never published.
/// # Safety
/// Same input/lifetime requirements as marmot_upload_media_files, plus a valid client_token string.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)] // Borrowed C ABI inputs and required out-pointer.
pub unsafe extern "C" fn marmot_upload_media_files_with_client_token(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    request: *const MarmotMediaFileUploadRequest,
    control: *const MarmotMediaFileTransferControl,
    client_token: *const c_char,
    out: *mut *mut MarmotMediaUploadSubmission,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let token = try_arg!(unsafe { required_str(client_token) });
        let Some(request) = (unsafe { request.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        let request = try_arg!(unsafe { request.to_ffi() });
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe {
            deliver(
                client.block_on(client.marmot.upload_media_files_with_client_token(
                    account,
                    group,
                    request,
                    control.inner.clone(),
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
    #[test]
    fn file_control_and_upload_out_preflight_are_null_safe() {
        unsafe {
            assert_eq!(
                marmot_media_file_transfer_control_new(std::ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            let mut handle = std::ptr::null_mut();
            assert_eq!(
                marmot_media_file_transfer_control_new(&mut handle),
                MarmotStatus::Ok
            );
            let mut cancelled = 42;
            let mut bytes = 42;
            assert_eq!(
                marmot_media_file_transfer_control_is_cancelled(handle, &mut cancelled),
                MarmotStatus::Ok
            );
            assert_eq!(cancelled, 0);
            assert_eq!(
                marmot_media_file_transfer_control_processed_bytes(handle, &mut bytes),
                MarmotStatus::Ok
            );
            assert_eq!(bytes, 0);
            assert_eq!(
                marmot_media_file_transfer_control_cancel(handle),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_media_file_transfer_control_is_cancelled(handle, &mut cancelled),
                MarmotStatus::Ok
            );
            assert_eq!(cancelled, 1);
            marmot_media_file_transfer_control_free(handle);
            marmot_media_file_transfer_control_free(std::ptr::null_mut());
            let dangling = std::ptr::dangling();
            assert_eq!(
                marmot_upload_media_files(
                    dangling,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_upload_media_files_with_client_token(
                    dangling,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
        }
        assert!(marmot_max_file_media_ciphertext_bytes() > 758_000_000);
    }
}
