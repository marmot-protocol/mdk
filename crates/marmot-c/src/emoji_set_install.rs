//! Emoji set install with a thread-safe progress and cancellation control.
use crate::commands::{deliver, try_arg};
use crate::memory::{CFree, boxed, free_boxed, required_str};
use crate::types::emoji_set::{MarmotEmojiSetInstallProgress, MarmotEmojiSetInstallResult};
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out, preflight_out_ptr};
use marmot_uniffi::conversions::EmojiSetInstallControlFfi;
use std::{ffi::c_char, sync::Arc};

/// One install's control. Query or cancel from any thread while the install
/// runs; never free during any call on the handle.
pub struct MarmotEmojiSetInstallControl {
    pub(crate) inner: Arc<EmojiSetInstallControlFfi>,
}
impl CFree for MarmotEmojiSetInstallControl {
    unsafe fn free_in_place(&mut self) {}
}

/// Create a control for one install; free it with
/// marmot_emoji_set_install_control_free after the install returns.
/// # Safety
/// out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_emoji_set_install_control_new(
    out: *mut *mut MarmotEmojiSetInstallControl,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        unsafe {
            out.write(boxed(MarmotEmojiSetInstallControl {
                inner: EmojiSetInstallControlFfi::new(),
            }))
        };
        MarmotStatus::Ok
    })
}
/// Cancel the install: no new downloads start, those in flight are dropped,
/// nothing is stored, and the install returns
/// MARMOT_STATUS_EMOJI_SET_INSTALL_CANCELLED. Too late once the final write
/// has started.
/// # Safety
/// control must be live; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_emoji_set_install_control_cancel(
    control: *const MarmotEmojiSetInstallControl,
) -> MarmotStatus {
    ffi_guard(|| {
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        control.inner.cancel();
        MarmotStatus::Ok
    })
}
/// Read cancellation as uint8_t (0 or 1). Runtime shutdown or close also sets it.
/// # Safety
/// control must be live; out writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_emoji_set_install_control_is_cancelled(
    control: *const MarmotEmojiSetInstallControl,
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
/// Read progress: entries finished, entries to try (0 until the install has
/// read the stored version) and response bytes received. Nothing to free.
/// # Safety
/// control must be live; out writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_emoji_set_install_control_progress(
    control: *const MarmotEmojiSetInstallControl,
    out: *mut MarmotEmojiSetInstallProgress,
) -> MarmotStatus {
    ffi_guard(|| {
        if out.is_null() {
            return MarmotStatus::NullPointer;
        }
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe { out.write(control.inner.progress().into()) };
        MarmotStatus::Ok
    })
}
/// Free a control; NULL is accepted.
/// # Safety
/// control must be NULL or live, with all calls on it finished.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_emoji_set_install_control_free(
    control: *mut MarmotEmojiSetInstallControl,
) {
    ffi_guard(|| {
        unsafe { free_boxed(control) };
        MarmotStatus::Ok
    });
}
/// Blocking install of the stored set version: download each emoji once,
/// validate it and store its bytes and SHA-256. Reveals the user's IP
/// address to the set's image hosts: call only after the user taps Install.
/// `expected_event_id_hex` is the version the user was shown: another stored
/// version fails with MARMOT_STATUS_EMOJI_SET_CHANGED before any download,
/// and nothing stored fails with MARMOT_STATUS_EMOJI_SET_NOT_FOUND. Free the
/// result with marmot_emoji_set_install_result_free; inputs stay borrowed.
/// # Safety
/// client/control must be live; strings NUL-terminated; out writable. No concurrent frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_install_emoji_set(
    client: *const MarmotClient,
    account_ref: *const c_char,
    coordinate: *const c_char,
    expected_event_id_hex: *const c_char,
    control: *const MarmotEmojiSetInstallControl,
    out: *mut *mut MarmotEmojiSetInstallResult,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let coordinate = try_arg!(unsafe { required_str(coordinate) });
        let expected = try_arg!(unsafe { required_str(expected_event_id_hex) });
        let Some(control) = (unsafe { control.as_ref() }) else {
            return MarmotStatus::NullPointer;
        };
        unsafe {
            deliver(
                client.block_on(client.marmot.install_emoji_set(
                    account,
                    coordinate,
                    expected,
                    control.inner.clone(),
                )),
                out,
            )
        }
    })
}
