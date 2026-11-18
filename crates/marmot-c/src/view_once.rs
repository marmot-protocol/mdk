//! Blocking view-once commands and revocable viewer ownership.
use crate::commands::{deliver, try_arg};
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, boxed, free_boxed, free_vec, optional_str, owned_vec, required_str};
use crate::status::{set_last_error, status_from_error};
use crate::types::account::MarmotSendSummary;
use crate::{
    MarmotClient, MarmotStatus, block_on_handle, client_ref, ffi_guard, preflight_out,
    preflight_out_ptr,
};
use marmot_uniffi::{
    ViewOnceActivationRefusalFfi, ViewOnceConsumeOutcomeFfi, ViewOnceMediaRequestFfi,
    ViewOncePresentationFfi, ViewOnceStateFfi, ViewOnceViewerFfi,
};
use std::{ffi::c_char, sync::Arc};
use zeroize::Zeroize;

c_enum! {
    /// Local account-device state; no consumption receipt is broadcast.
    MarmotViewOnceState from ViewOnceStateFfi { Unopened, Consumed, Expired, Sent, Unavailable, }
}
c_enum! {
    /// Reason explicit group activation cannot proceed.
    MarmotViewOnceActivationRefusal from ViewOnceActivationRefusalFfi { NotAdmin, AlreadyRequired, LegacyProfile, UnsupportedLeaf, EncryptedMediaV2NotRequired, CarriesData, }
}
c_mirror! {
    /// Content-free timeline placeholder. No usable media reference is included.
    MarmotViewOncePresentation from ViewOncePresentationFfi {
        copy state: MarmotViewOnceState,
        copy unopened_expires_at: u64,
    }
}

/// Borrowed input, copied before send. MDK cannot erase the caller's original bytes.
#[repr(C)]
pub struct MarmotViewOnceMediaRequest {
    pub plaintext: *const u8,
    pub plaintext_len: usize,
    pub media_type: *const c_char,
    pub unopened_expires_at: u64,
    /// Nullable endpoint override.
    pub blossom_server: *const c_char,
}
impl MarmotViewOnceMediaRequest {
    unsafe fn to_ffi(&self) -> Result<ViewOnceMediaRequestFfi, MarmotStatus> {
        if self.plaintext_len == 0 || self.plaintext_len > 64 * 1024 * 1024 {
            set_last_error("view-once input must contain 1..=67108864 bytes");
            return Err(MarmotStatus::InvalidArgument);
        }
        if self.plaintext.is_null() {
            return Err(MarmotStatus::NullPointer);
        }
        let media_type = unsafe { required_str(self.media_type) }?;
        let blossom_server = unsafe { optional_str(self.blossom_server) }?;
        Ok(ViewOnceMediaRequestFfi {
            plaintext: unsafe { std::slice::from_raw_parts(self.plaintext, self.plaintext_len) }
                .to_vec(),
            media_type,
            unopened_expires_at: self.unopened_expires_at,
            blossom_server,
        })
    }
}

/// Opaque viewer. Never free concurrently with any call using this handle.
pub struct MarmotViewOnceViewer {
    inner: Arc<ViewOnceViewerFfi>,
    runtime: tokio::runtime::Handle,
}
impl CFree for MarmotViewOnceViewer {
    unsafe fn free_in_place(&mut self) {
        self.inner.revoke();
    }
}
/// Result of an irreversible local claim. Opened transfers an independently owned viewer.
#[repr(C)]
pub enum MarmotViewOnceConsumeOutcome {
    Opened { viewer: *mut MarmotViewOnceViewer },
    Consumed,
    Expired,
    Unavailable,
}
/// One bounded plaintext chunk. Freed bytes are erased in MDK's allocation, not host copies.
#[repr(C)]
pub struct MarmotViewOnceBytes {
    pub data: *mut u8,
    pub len: usize,
}
impl CFree for MarmotViewOnceBytes {
    unsafe fn free_in_place(&mut self) {
        if !self.data.is_null() {
            unsafe { std::slice::from_raw_parts_mut(self.data, self.len) }.zeroize();
            unsafe { free_vec(self.data, self.len) };
        }
    }
}

/// Activate negotiated view-once support; out uses marmot_send_summary_free.
/// # Safety
/// Client and strings must be live; out writable. No concurrent frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_enable_view_once(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.enable_view_once(account, group)),
                out,
            )
        }
    })
}
/// Return has_refusal=0 when activation is allowed. refusal is meaningful only when set.
/// # Safety
/// Client and strings must be live; both outputs writable. No concurrent frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_refusal(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    has_refusal: *mut u8,
    refusal: *mut MarmotViewOnceActivationRefusal,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(has_refusal) });
        try_arg!(unsafe { crate::check_out(refusal) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        match client.block_on(client.marmot.view_once_activation_refusal(account, group)) {
            Ok(value) => {
                if let Some(value) = value {
                    unsafe {
                        refusal.write(value.into());
                        has_refusal.write(1);
                    }
                }
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Send one image/video, without returning a reusable media reference.
/// # Safety
/// Client, strings, request and input bytes valid until return; out writable. No concurrent frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_send_view_once_media(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    request: *const MarmotViewOnceMediaRequest,
    out: *mut *mut MarmotSendSummary,
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
        unsafe {
            deliver(
                client.block_on(client.marmot.send_view_once_media(account, group, request)),
                out,
            )
        }
    })
}
/// Claim before decrypting. Failure after claim remains consumed. Opened viewer uses marmot_view_once_viewer_free.
/// # Safety
/// Client and strings must be live; out writable. No concurrent frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_consume_view_once(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    message_id: *const c_char,
    attachment_index: u32,
    out: *mut MarmotViewOnceConsumeOutcome,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { crate::write_out(out, MarmotViewOnceConsumeOutcome::Unavailable) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let message = try_arg!(unsafe { required_str(message_id) });
        match client.block_on(client.marmot.consume_view_once(
            account,
            group,
            message,
            attachment_index,
        )) {
            Ok(value) => {
                let value = match value {
                    ViewOnceConsumeOutcomeFfi::Opened { viewer } => {
                        MarmotViewOnceConsumeOutcome::Opened {
                            viewer: boxed(MarmotViewOnceViewer {
                                inner: viewer,
                                runtime: client.runtime.handle().clone(),
                            }),
                        }
                    }
                    ViewOnceConsumeOutcomeFfi::Consumed => MarmotViewOnceConsumeOutcome::Consumed,
                    ViewOnceConsumeOutcomeFfi::Expired => MarmotViewOnceConsumeOutcome::Expired,
                    ViewOnceConsumeOutcomeFfi::Unavailable => {
                        MarmotViewOnceConsumeOutcome::Unavailable
                    }
                };
                unsafe { out.write(value) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Read local state without decrypting or claiming.
/// # Safety
/// Client and strings must be live; out writable. No concurrent frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_state(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    message_id: *const c_char,
    attachment_index: u32,
    out: *mut MarmotViewOnceState,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { crate::check_out(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let group = try_arg!(unsafe { required_str(group_id_hex) });
        let message = try_arg!(unsafe { required_str(message_id) });
        match client.block_on(client.marmot.view_once_state(
            account,
            group,
            message,
            attachment_index,
        )) {
            Ok(value) => {
                unsafe { out.write(value.into()) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Read at most 1 MiB. NULL out on success means closed, expired, revoked, or end of input.
/// # Safety
/// Viewer must be live, its client runtime alive, and out writable. No concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_viewer_read(
    viewer: *const MarmotViewOnceViewer,
    offset: u64,
    limit: u32,
    out: *mut *mut MarmotViewOnceBytes,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let Some(viewer) = (unsafe { viewer.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        match block_on_handle(&viewer.runtime, viewer.inner.read(offset, limit)) {
            Ok(value) => {
                if let Some(bytes) = value {
                    let (data, len) = owned_vec(bytes);
                    unsafe { out.write(boxed(MarmotViewOnceBytes { data, len })) };
                }
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Revoke plaintext immediately without freeing the handle.
/// # Safety
/// Viewer must be live. No concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_viewer_close(
    viewer: *const MarmotViewOnceViewer,
) -> MarmotStatus {
    ffi_guard(|| {
        let Some(viewer) = (unsafe { viewer.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        viewer.inner.revoke();
        MarmotStatus::Ok
    })
}
/// Return the original plaintext length.
/// # Safety
/// Viewer must be live; out writable. No concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_viewer_size(
    viewer: *const MarmotViewOnceViewer,
    out: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out) });
        let Some(viewer) = (unsafe { viewer.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe { out.write(viewer.inner.size_bytes()) };
        MarmotStatus::Ok
    })
}
/// Return an owned MIME string, freed with marmot_string_free.
/// # Safety
/// Viewer must be live; out writable. No concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_viewer_type(
    viewer: *const MarmotViewOnceViewer,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let Some(viewer) = (unsafe { viewer.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe { out.write(crate::memory::owned_c_string(viewer.inner.media_type())) };
        MarmotStatus::Ok
    })
}
/// Close and free an opened viewer. NULL is accepted.
/// # Safety
/// Viewer must be NULL or returned by consume, not freed, and all viewer calls finished.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_viewer_free(viewer: *mut MarmotViewOnceViewer) {
    ffi_guard(|| {
        unsafe { free_boxed(viewer) };
        MarmotStatus::Ok
    });
}
/// Erase and free an MDK-returned chunk. NULL is accepted; host copies are unaffected.
/// # Safety
/// Bytes must be NULL or returned by read, and not previously freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_view_once_bytes_free(bytes: *mut MarmotViewOnceBytes) {
    ffi_guard(|| {
        unsafe { free_boxed(bytes) };
        MarmotStatus::Ok
    });
}
