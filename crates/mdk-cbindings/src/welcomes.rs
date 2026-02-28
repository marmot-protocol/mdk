//! Welcome functions.

use std::os::raw::c_char;

use nostr::UnsignedEvent;

use mdk_storage_traits::welcomes::{Pagination as WelcomePagination, types as welcome_types};

use crate::error::{self, MdkError};
use crate::types::{
    MdkHandle, cstr_to_str, ffi_try_unwind_safe, lock_handle, parse_event_id, parse_json, to_json,
    write_cstring_to,
};

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Get pending welcomes with optional pagination.
///
/// # Parameters
///
/// * `limit`  — Maximum number of welcomes (0 = no limit / default 1000).
/// * `offset` — Number of welcomes to skip (0 = none).
///
/// On success, `*out_json` receives a JSON array of welcome objects.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_pending_welcomes(
    h: *mut MdkHandle,
    limit: u32,
    offset: u32,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };

        let limit_opt = match limit {
            0 => None,
            n => Some(n as usize),
        };
        let offset_opt = match offset {
            0 => None,
            n => Some(n as usize),
        };
        let pagination = match (limit_opt, offset_opt) {
            (None, None) => None,
            _ => Some(WelcomePagination::new(limit_opt, offset_opt)),
        };

        let welcomes = lock_handle(handle)?
            .get_pending_welcomes(pagination)
            .map_err(error::from_mdk_error)?;
        let json = to_json(&welcomes)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Get a welcome by event ID.
///
/// On success, `*out_json` receives the welcome JSON or `"null"`.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_welcome(
    h: *mut MdkHandle,
    event_id: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let eid = parse_event_id(unsafe { cstr_to_str(event_id) }?)?;

        let welcome = lock_handle(handle)?
            .get_welcome(&eid)
            .map_err(error::from_mdk_error)?;
        let json = to_json(&welcome)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Process a welcome message.
///
/// # Parameters
///
/// * `wrapper_event_id` — Hex-encoded event ID of the 1059 wrapper event.
/// * `rumor_json`       — JSON of the rumor (kind 444) unsigned event.
///
/// On success, `*out_json` receives the processed welcome as JSON.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_process_welcome(
    h: *mut MdkHandle,
    wrapper_event_id: *const c_char,
    rumor_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let wrapper_id = parse_event_id(unsafe { cstr_to_str(wrapper_event_id) }?)?;
        let rumor: UnsignedEvent =
            parse_json(unsafe { cstr_to_str(rumor_json) }?, "rumor event JSON")?;

        let welcome = lock_handle(handle)?
            .process_welcome(&wrapper_id, &rumor)
            .map_err(error::from_mdk_error)?;
        let json = to_json(&welcome)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Accept a welcome message.
///
/// # Parameters
///
/// * `welcome_json` — JSON representation of the welcome (as returned by
///   [`mdk_process_welcome`] or [`mdk_get_welcome`]).
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_accept_welcome(
    h: *mut MdkHandle,
    welcome_json: *const c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        let handle = unsafe { &*h };
        let welcome: welcome_types::Welcome =
            parse_json(unsafe { cstr_to_str(welcome_json) }?, "welcome JSON")?;
        lock_handle(handle)?
            .accept_welcome(&welcome)
            .map_err(error::from_mdk_error)
    })
}

/// Decline a welcome message.
///
/// # Parameters
///
/// * `welcome_json` — JSON representation of the welcome.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_decline_welcome(
    h: *mut MdkHandle,
    welcome_json: *const c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        let handle = unsafe { &*h };
        let welcome: welcome_types::Welcome =
            parse_json(unsafe { cstr_to_str(welcome_json) }?, "welcome JSON")?;
        lock_handle(handle)?
            .decline_welcome(&welcome)
            .map_err(error::from_mdk_error)
    })
}
