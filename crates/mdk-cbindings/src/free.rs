//! Memory-management functions for strings and byte arrays returned by the C API.

use std::ffi::CString;
use std::os::raw::c_char;

/// Free a string previously returned by any `mdk_*` function.
///
/// # Safety
///
/// `s` must be a pointer previously returned by an `mdk_*` function, or null
/// (in which case this is a no-op). Passing any other pointer is undefined
/// behaviour. Do **not** call this more than once on the same pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Free a byte array previously returned by an `mdk_*` function.
///
/// # Safety
///
/// `data` must be a pointer previously returned by an `mdk_*` function (paired
/// with the correct `len`), or null (no-op). Passing any other pointer or an
/// incorrect length is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_bytes_free(data: *mut u8, len: usize) {
    if !data.is_null() && len > 0 {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, len)) });
    }
}
